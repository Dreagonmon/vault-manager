/**
 * Host half of the credential vault bundle.
 *
 * Stores secret entries encrypted with a single master password
 * (scrypt-derived key, per-entry AES-256-GCM). Entry names and notes stay
 * plaintext so list/delete need no password. Whenever a secret must be read
 * or written, a prompt is queued for the browser UI (prefix route
 * `/vault-api`); the popup collects the master password over this local
 * channel only — it never enters the session log or the agent context.
 */
import { randomBytes, scryptSync, createCipheriv, createDecipheriv } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync, chmodSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawn } from 'node:child_process'

export const inject = ['tools', 'webServer', 'workingDirectory']

const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 32, maxmem: 64 * 1024 * 1024 }
const PLACEHOLDER_RE = /\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}/g
const NAME_RE = /^[A-Za-z0-9_.-]+$/
const OUTPUT_CAP = 256 * 1024

export function apply(ctx, config = {}) {
  const vaultPath = config.path
    || path.join(process.env.DSH_HOME || path.join(os.homedir(), '.dsh'), 'vault.json')
  const redactOutput = config.redactOutput !== false
  const commandTimeoutMs = Number(config.commandTimeoutMs) > 0 ? Number(config.commandTimeoutMs) : 120000
  const promptTimeoutMs = Number(config.promptTimeoutMs) > 0 ? Number(config.promptTimeoutMs) : 30 * 60 * 1000

  /* ---------------- crypto ---------------- */

  const deriveKey = (password, saltHex) => scryptSync(
    Buffer.from(String(password), 'utf8'), Buffer.from(saltHex, 'hex'), SCRYPT.keylen,
    { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: SCRYPT.maxmem },
  )

  const encryptValue = (key, value) => {
    const iv = randomBytes(12)
    const c = createCipheriv('aes-256-gcm', key, iv)
    const data = Buffer.concat([c.update(Buffer.from(value, 'utf8')), c.final()])
    return { iv: iv.toString('hex'), tag: c.getAuthTag().toString('hex'), ciphertext: data.toString('hex') }
  }

  const decryptValue = (key, entry) => {
    const d = createDecipheriv('aes-256-gcm', key, Buffer.from(entry.iv, 'hex'))
    d.setAuthTag(Buffer.from(entry.tag, 'hex'))
    return Buffer.concat([d.update(Buffer.from(entry.ciphertext, 'hex')), d.final()]).toString('utf8')
  }

  /** A master password is valid for the vault iff it decrypts any stored entry. */
  const probeKey = (key, vault) => {
    for (const entry of Object.values(vault.entries)) {
      try { decryptValue(key, entry); return true } catch { /* try next */ }
    }
    return Object.keys(vault.entries).length === 0
  }

  /* ---------------- vault file ---------------- */

  const loadVault = () => {
    if (!existsSync(vaultPath)) return null
    const doc = JSON.parse(readFileSync(vaultPath, 'utf8'))
    if (!doc || doc.version !== 1 || !doc.kdf?.salt || typeof doc.entries !== 'object') {
      throw new Error(`保险库文件格式异常: ${vaultPath}`)
    }
    return doc
  }

  const saveVault = (doc) => {
    mkdirSync(path.dirname(vaultPath), { recursive: true, mode: 0o700 })
    const tmp = `${vaultPath}.tmp-${process.pid}-${Date.now()}`
    writeFileSync(tmp, JSON.stringify(doc, null, 2), { mode: 0o600 })
    chmodSync(tmp, 0o600)
    renameSync(tmp, vaultPath)
  }

  /** Serialize every read-modify-write on the vault file. */
  let queue = Promise.resolve()
  const withVault = (fn) => {
    const run = queue.then(fn, fn)
    queue = run.then(() => {}, () => {})
    return run
  }

  const freshVault = () => ({ version: 1, kdf: { algo: 'scrypt', ...SCRYPT, salt: randomBytes(16).toString('hex') }, entries: {} })

  /* ---------------- popup prompts ---------------- */

  const pending = []
  let promptSeq = 0

  /** Queue a prompt for the browser UI; resolves with the user's outcome. */
  const ask = (kind, payload, signal) => new Promise((resolve) => {
    const prompt = { id: `vp-${++promptSeq}`, kind, payload, settle: () => {} }
    const finish = (outcome) => {
      const index = pending.indexOf(prompt)
      if (index < 0) return
      pending.splice(index, 1)
      clearTimeout(timer)
      if (signal) signal.removeEventListener('abort', onAbort)
      resolve(outcome)
    }
    const timer = setTimeout(() => finish({ action: 'timeout' }), promptTimeoutMs)
    const onAbort = () => finish({ action: 'aborted' })
    prompt.settle = finish
    pending.push(prompt)
    if (signal?.aborted) onAbort()
    else if (signal) signal.addEventListener('abort', onAbort, { once: true })
  })

  /** Validate a submit against the vault before consuming the prompt; a
   * rejected submit keeps the prompt open so the popup can retry in place. */
  const handleAnswer = (body) => {
    const prompt = pending.find(p => p.id === body.id)
    if (!prompt) return { ok: false, error: 'gone' }
    if (body.action === 'cancel') {
      prompt.settle({ action: 'cancel' })
      return { ok: true }
    }
    if (body.action !== 'submit') return { ok: false, error: 'bad-request' }
    const vault = (() => { try { return loadVault() } catch { return null } })()
    const hasEntries = !!vault && Object.keys(vault.entries).length > 0
    if (prompt.kind === 'save') {
      const password = String(body.password || '')
      if (hasEntries) {
        if (!probeKey(deriveKey(password, vault.kdf.salt), vault)) return { ok: false, error: 'mismatch' }
      } else if (password !== String(body.confirm || '') || !password) {
        return { ok: false, error: 'confirm' }
      }
      prompt.settle({ action: 'submit', password, secret: String(body.secret || '') })
      return { ok: true }
    }
    if (prompt.kind === 'use') {
      prompt.settle({ action: 'submit', password: String(body.password || '') })
      return { ok: true }
    }
    if (prompt.kind === 'rekey') {
      if (!hasEntries) {
        prompt.settle({ action: 'submit' })
        return { ok: true }
      }
      const oldPassword = String(body.oldPassword || '')
      if (!probeKey(deriveKey(oldPassword, vault.kdf.salt), vault)) return { ok: false, error: 'old' }
      const newPassword = String(body.newPassword || '')
      if (!newPassword || newPassword !== String(body.confirm || '')) return { ok: false, error: 'confirm' }
      prompt.settle({ action: 'submit', oldPassword, newPassword })
      return { ok: true }
    }
    return { ok: false, error: 'bad-request' }
  }

  /* ---------------- HTTP channel ---------------- */

  const readBody = (req) => new Promise((resolve, reject) => {
    let size = 0
    const chunks = []
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > 65536) { reject(new Error('body too large')); req.destroy(); return }
      chunks.push(chunk)
    })
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')) }
      catch { reject(new Error('invalid JSON')) }
    })
    req.on('error', reject)
  })

  const sendJson = (res, code, value) => {
    res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' })
    res.end(JSON.stringify(value))
  }

  /* ---------------- command execution ---------------- */

  const runCommand = (command, cwd, signal) => new Promise((resolve) => {
    const win = process.platform === 'win32'
    const shell = win ? (process.env.COMSPEC || 'cmd.exe') : (process.env.SHELL || '/bin/sh')
    const argv = win ? ['/d', '/s', '/c', command] : ['-c', command]
    const child = spawn(shell, argv, { cwd, env: process.env })
    let stdout = ''
    let stderr = ''
    let timedOut = false
    const kill = () => { try { child.kill('SIGKILL') } catch {} }
    const timer = setTimeout(() => { timedOut = true; kill() }, commandTimeoutMs)
    const onAbort = () => kill()
    if (signal) signal.addEventListener('abort', onAbort, { once: true })
    child.stdout.on('data', (d) => { stdout += d; if (stdout.length > OUTPUT_CAP) kill() })
    child.stderr.on('data', (d) => { stderr += d; if (stderr.length > OUTPUT_CAP) kill() })
    child.on('error', (error) => {
      clearTimeout(timer)
      if (signal) signal.removeEventListener('abort', onAbort)
      resolve({ exitCode: -1, stdout, stderr: stderr + String(error?.message || error), timedOut })
    })
    child.on('close', (code) => {
      clearTimeout(timer)
      if (signal) signal.removeEventListener('abort', onAbort)
      resolve({ exitCode: timedOut ? -1 : code, stdout, stderr, timedOut })
    })
  })

  const redact = (text, secrets) => {
    let out = text
    for (const secret of secrets) if (secret) out = out.split(secret).join('***')
    return out
  }

  const cwdOf = (exec) => {
    try {
      const agent = exec?.agent
      if (agent) return ctx.workingDirectory.get(agent.session)
    } catch {}
    return process.cwd()
  }

  /* ---------------- tools ---------------- */

  const messageSchema = (extra = {}) => ({
    type: 'object',
    properties: { message: { type: 'string' }, ...extra },
    required: ['message'],
    additionalProperties: true,
  })
  const output = (schema) => ({
    schema,
    render: (args, value) => [{
      type: 'text',
      text: Object.keys(value).length === 1 && typeof value.message === 'string'
        ? value.message
        : JSON.stringify(value, null, 2),
    }],
  })
  const fail = (message) => { const error = new Error(message); error.code = 'VAULT'; throw error }

  const toolDefs = [
    {
      name: 'vault_save',
      description: 'Save a new secret (or replace one) in the encrypted credential vault. The secret VALUE is typed by the user into a popup dialog together with the master password, so never pass or echo the secret here; the popup verifies the master password against existing vault entries (one master password for all entries). Returns only after the user finishes or cancels.',
      parameters: {
        type: 'object',
        properties: {
          name: { type: 'string', description: 'Entry name, e.g. "github-token". [A-Za-z0-9_.-]+' },
          note: { type: 'string', description: 'Optional plaintext description of what this secret is for.' },
        },
        required: ['name'],
        additionalProperties: false,
      },
      output: output(messageSchema()),
      async execute(args, exec) {
        const name = String(args?.name || '')
        if (!NAME_RE.test(name)) fail(`条目名不合法: ${JSON.stringify(name)}（仅允许字母数字与 _ . -）`)
        const note = typeof args?.note === 'string' ? args.note : undefined
        const isNew = await withVault(() => {
          const vault = loadVault()
          return !vault || Object.keys(vault.entries).length === 0
        })
        const outcome = await ask('save', { name, note, isNew }, exec.signal)
        if (outcome.action === 'cancel') return { message: '用户取消了保存。' }
        if (outcome.action === 'timeout') fail('等待用户输入超时，未保存。')
        if (outcome.action === 'aborted') fail('调用已取消，未保存。')
        return await withVault(() => {
          const vault = loadVault() || freshVault()
          const hasEntries = Object.keys(vault.entries).length > 0
          const key = deriveKey(outcome.password, vault.kdf.salt)
          if (hasEntries && !probeKey(key, vault)) fail('主密码与现有条目不一致，未保存。')
          const now = new Date().toISOString()
          const replaced = !!vault.entries[name]
          vault.entries[name] = {
            ...(note !== undefined ? { note } : vault.entries[name]?.note !== undefined ? { note: vault.entries[name].note } : {}),
            createdAt: vault.entries[name]?.createdAt || now,
            updatedAt: now,
            ...encryptValue(key, outcome.secret),
          }
          saveVault(vault)
          return { message: `已${replaced ? '更新' : '保存'}密钥条目 ${name}（值未进入对话上下文）。` }
        })
      },
    },
    {
      name: 'vault_list',
      description: 'List credential vault entries (names, notes, timestamps only — never the secret values). No master password needed.',
      parameters: { type: 'object', properties: {}, additionalProperties: false },
      output: output(messageSchema({
        entries: { type: 'array', items: { type: 'object', properties: {
          name: { type: 'string' }, note: { type: 'string' },
          createdAt: { type: 'string' }, updatedAt: { type: 'string' },
        }, required: ['name'] } },
      })),
      async execute() {
        return await withVault(() => {
          const vault = loadVault()
          if (!vault) return { message: '保险库尚未创建（还没有任何密钥条目）。', entries: [] }
          const entries = Object.entries(vault.entries).map(([name, e]) => ({
            name, ...(e.note ? { note: e.note } : {}), createdAt: e.createdAt, updatedAt: e.updatedAt,
          }))
          return { message: `保险库共有 ${entries.length} 个条目。`, entries }
        })
      },
    },
    {
      name: 'vault_use',
      description: 'Run a shell command that needs vault secrets. Write the command with {{entry-name}} placeholders instead of real secrets and pass the same names in entries. A popup shows the command to the user, who approves it by typing the master password; the plugin decrypts the secrets in memory, substitutes them, runs the command, and returns exit code plus output (secret occurrences redacted). Secrets never appear in the conversation. A wrong master password fails the call.',
      parameters: {
        type: 'object',
        properties: {
          command: { type: 'string', description: 'Shell command containing {{entry-name}} placeholders for every secret used.' },
          entries: { type: 'array', items: { type: 'string' }, description: 'Vault entry names substituted into the command.' },
        },
        required: ['command', 'entries'],
        additionalProperties: false,
      },
      output: output(messageSchema({
        exitCode: { type: 'number' }, stdout: { type: 'string' }, stderr: { type: 'string' },
      })),
      async execute(args, exec) {
        const command = String(args?.command || '')
        const names = Array.isArray(args?.entries) ? args.entries.map(String) : []
        if (!command) fail('command 不能为空。')
        if (!names.length || names.some(n => !NAME_RE.test(n))) fail('entries 必须是非空的合法条目名数组。')
        const used = [...new Set([...command.matchAll(PLACEHOLDER_RE)].map(m => m[1]))]
        const missing = used.filter(n => !names.includes(n))
        const unused = names.filter(n => !used.includes(n))
        if (missing.length) fail(`命令中的占位符 ${missing.map(n => `{{${n}}}`).join(', ')} 未全部列在 entries 中。`)
        if (unused.length) fail(`entries 中的 ${unused.join(', ')} 未出现在命令占位符中。`)
        const exists = await withVault(() => {
          const vault = loadVault()
          return vault ? names.filter(n => !vault.entries[n]) : names
        })
        if (exists.length) fail(`条目不存在: ${exists.join(', ')}（可先用 vault_list 查看）。`)
        const outcome = await ask('use', { command, entries: names }, exec.signal)
        if (outcome.action === 'cancel') return { message: '用户拒绝执行该命令。' }
        if (outcome.action === 'timeout') fail('等待用户确认超时，未执行。')
        if (outcome.action === 'aborted') fail('调用已取消，未执行。')
        const { secrets, filled } = await withVault(() => {
          const vault = loadVault()
          if (!vault) fail('保险库尚未创建。')
          const key = deriveKey(outcome.password, vault.kdf.salt)
          const secrets = names.map(n => {
            try { return decryptValue(key, vault.entries[n]) }
            catch { fail('主密码错误。') }
          })
          let i = 0
          const filled = command.replace(PLACEHOLDER_RE, () => secrets[i++])
          return { secrets, filled }
        })
        const result = await runCommand(filled, cwdOf(exec), exec.signal)
        if (result.timedOut) fail(`命令执行超过 ${commandTimeoutMs} ms 被终止。`)
        return {
          message: `命令执行完成，退出码 ${result.exitCode}。`,
          exitCode: result.exitCode,
          stdout: redactOutput ? redact(result.stdout, secrets) : result.stdout,
          stderr: redactOutput ? redact(result.stderr, secrets) : result.stderr,
        }
      },
    },
    {
      name: 'vault_delete',
      description: 'Delete a credential vault entry by name. No master password needed. Returns whether an entry was removed.',
      parameters: {
        type: 'object',
        properties: { name: { type: 'string', description: 'Entry name to delete.' } },
        required: ['name'],
        additionalProperties: false,
      },
      output: output(messageSchema()),
      async execute(args) {
        const name = String(args?.name || '')
        if (!NAME_RE.test(name)) fail(`条目名不合法: ${JSON.stringify(name)}`)
        return await withVault(() => {
          const vault = loadVault()
          if (!vault || !vault.entries[name]) return { message: `条目 ${name} 不存在，未做修改。` }
          delete vault.entries[name]
          saveVault(vault)
          return { message: `已删除条目 ${name}。` }
        })
      },
    },
    {
      name: 'vault_change_password',
      description: 'Open the master-password change dialog for the user (old password, new password, confirmation, all typed in the popup; every entry is re-encrypted on success). The result is visible only to the user: this call returns the same neutral message whether the user changed the password or cancelled.',
      parameters: { type: 'object', properties: {}, additionalProperties: false },
      output: output(messageSchema()),
      async execute(args, exec) {
        const empty = await withVault(() => {
          const vault = loadVault()
          return !vault || Object.keys(vault.entries).length === 0
        })
        if (empty) return { message: '保险库尚未创建，无需修改主密码。' }
        const outcome = await ask('rekey', {}, exec.signal)
        if (outcome.action !== 'submit') return { message: '主密码管理流程已结束，结果仅用户可见。' }
        await withVault(() => {
          const vault = loadVault()
          if (!vault) return
          const oldKey = deriveKey(outcome.oldPassword, vault.kdf.salt)
          const newSalt = randomBytes(16).toString('hex')
          const newKey = deriveKey(outcome.newPassword, newSalt)
          for (const entry of Object.values(vault.entries)) {
            const plain = decryptValue(oldKey, entry) // throws -> abort, file untouched
            Object.assign(entry, encryptValue(newKey, plain))
          }
          vault.kdf.salt = newSalt
          saveVault(vault)
        })
        return { message: '主密码管理流程已结束，结果仅用户可见。' }
      },
    },
  ]

  /* ---------------- registration ---------------- */

  ctx.effect(() => {
    const disposers = toolDefs.map(def => ctx.tools.register(def))
    disposers.push(ctx.webServer.register({
      kind: 'prefix',
      path: '/vault-api',
      async handler(req, res) {
        const origin = req.headers.origin
        if (origin && origin !== ctx.webServer.getOrigin()) return sendJson(res, 403, { ok: false, error: 'origin' })
        const route = (req.url || '').split('?')[0]
        if (req.method === 'GET' && route === '/vault-api/pending') {
          const prompt = pending[0]
          return sendJson(res, 200, prompt
            ? { prompt: { id: prompt.id, kind: prompt.kind, ...prompt.payload } }
            : { prompt: null })
        }
        if (req.method === 'POST' && route === '/vault-api/answer') {
          let body
          try { body = await readBody(req) } catch { return sendJson(res, 400, { ok: false, error: 'bad-body' }) }
          return sendJson(res, 200, handleAnswer(body))
        }
        return sendJson(res, 404, { ok: false, error: 'not-found' })
      },
    }))
    return () => disposers.forEach(off => off())
  })
}
