/**
 * Client half: a frame-wide modal that answers vault prompts queued by the
 * Host half via the local /vault-api route. The master password and secret
 * values travel only over this local HTTP exchange, never into the session.
 */
window.__ModuleLoader__.load({
  id: '@dreagonmon/vault-manager',
  factory(require) {
    const React = require('react')
    const h = React.createElement

    const STRINGS = {
      zh: {
        saveTitle: '保存密钥',
        newVaultHint: '首次使用：请设置主密码（两次输入需一致）',
        masterHint: '输入主密码；将与现有条目校验一致（整个保险库共用一个主密码）',
        master: '主密码',
        confirm: '确认主密码',
        secret: '密钥值',
        noteLabel: '备注',
        useTitle: '执行命令',
        useHint: '确认以下命令后输入主密码解密执行；密钥值不会出现在对话中',
        entriesLabel: '使用条目',
        rekeyTitle: '修改主密码',
        rekeyHint: '所有条目将用新主密码重新加密；结果仅你可见',
        old: '旧主密码',
        newPassword: '新主密码',
        confirmNew: '确认新密码',
        submit: '确认',
        cancel: '取消',
        show: '显示',
        errMismatch: '主密码与现有条目不一致，请重新输入',
        errConfirm: '两次输入不一致',
        errOld: '旧主密码错误，请重新输入',
        errGone: '该请求已结束',
      },
      en: {
        saveTitle: 'Save secret',
        newVaultHint: 'First use: set a master password (both fields must match)',
        masterHint: 'Enter the master password; it is verified against existing entries (one master password per vault)',
        master: 'Master password',
        confirm: 'Confirm master password',
        secret: 'Secret value',
        noteLabel: 'Note',
        useTitle: 'Run command',
        useHint: 'Review the command, then type the master password to decrypt and run it; secrets never enter the conversation',
        entriesLabel: 'Entries',
        rekeyTitle: 'Change master password',
        rekeyHint: 'All entries are re-encrypted with the new password; the result is visible only to you',
        old: 'Old master password',
        newPassword: 'New master password',
        confirmNew: 'Confirm new password',
        submit: 'Confirm',
        cancel: 'Cancel',
        show: 'Show',
        errMismatch: 'Master password does not match existing entries',
        errConfirm: 'The two entries do not match',
        errOld: 'Wrong old master password',
        errGone: 'This request has ended',
      },
    }

    const STYLES = `
      .vlt-mask { position: fixed; inset: 0; z-index: 1000; background: rgba(0,0,0,0.45);
        display: flex; align-items: center; justify-content: center; pointer-events: auto; }
      .vlt-panel { width: min(560px, calc(100vw - 48px)); max-height: calc(100vh - 96px); overflow: auto;
        background: var(--dsw-alias-bg-overlay); color: var(--dsw-alias-label-primary);
        border: 1px solid var(--dsw-alias-border-l2); border-radius: 12px; padding: 20px 22px;
        box-shadow: 0 16px 48px rgba(0,0,0,0.35); font-size: 14px; }
      .vlt-title { font-size: 16px; font-weight: 600; margin: 0 0 4px; }
      .vlt-sub { color: var(--dsw-alias-label-secondary); margin: 0 0 14px; font-size: 13px; }
      .vlt-cmd { background: var(--dsw-alias-bg-layer-2); border: 1px solid var(--dsw-alias-border-l1);
        border-radius: 8px; padding: 10px 12px; white-space: pre-wrap; word-break: break-all;
        font-family: ui-monospace, monospace; font-size: 13px; margin: 0 0 12px; }
      .vlt-chips { display: flex; flex-wrap: wrap; gap: 6px; margin: 0 0 12px; }
      .vlt-chip { background: var(--dsw-alias-bg-layer-2); border: 1px solid var(--dsw-alias-border-l1);
        border-radius: 999px; padding: 2px 10px; font-size: 12px; }
      .vlt-field { display: block; margin: 0 0 10px; }
      .vlt-field > span { display: block; color: var(--dsw-alias-label-secondary); font-size: 12px; margin-bottom: 4px; }
      .vlt-field input { width: 100%; box-sizing: border-box; background: var(--dsw-alias-bg-layer-1);
        color: var(--dsw-alias-label-primary); border: 1px solid var(--dsw-alias-border-l1);
        border-radius: 8px; padding: 8px 10px; font-size: 14px; outline: none; }
      .vlt-field input:focus { border-color: var(--dsw-alias-brand-primary); }
      .vlt-error { color: var(--dsw-alias-state-error-primary); font-size: 13px; margin: 2px 0 10px; min-height: 1em; }
      .vlt-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 6px; }
      .vlt-btn { border-radius: 8px; padding: 7px 16px; font-size: 14px; cursor: pointer;
        border: 1px solid var(--dsw-alias-border-l1); background: transparent;
        color: var(--dsw-alias-label-primary); }
      .vlt-btn--primary { background: var(--dsw-alias-brand-primary); border-color: var(--dsw-alias-brand-primary); color: #fff; }
      .vlt-show { display: flex; align-items: center; gap: 6px; color: var(--dsw-alias-label-secondary);
        font-size: 12px; margin: -4px 0 10px; user-select: none; }
    `

    function VaultModal({ prompt, t, onClose }) {
      const [values, setValues] = React.useState({})
      const [error, setError] = React.useState('')
      const [showSecret, setShowSecret] = React.useState(false)
      const firstRef = React.useRef(null)
      React.useEffect(() => { if (firstRef.current) firstRef.current.focus() }, [])

      const set = (key) => (e) => setValues(v => ({ ...v, [key]: e.target.value }))
      const fields = []
      if (prompt.kind === 'save') {
        if (prompt.isNew) {
          fields.push(['password', t.master, true], ['confirm', t.confirm, true])
        } else {
          fields.push(['password', t.master, true])
        }
        fields.push(['secret', t.secret, !showSecret])
      } else if (prompt.kind === 'use') {
        fields.push(['password', t.master, true])
      } else if (prompt.kind === 'rekey') {
        fields.push(['password', t.old, true], ['newPassword', t.newPassword, true], ['confirm', t.confirmNew, true])
      }

      const answer = async (body) => {
        try {
          const r = await fetch('/vault-api/answer', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ id: prompt.id, ...body }),
          })
          const json = await r.json()
          if (json.ok) { onClose(); return }
          setError(t['err' + json.error[0].toUpperCase() + json.error.slice(1)] || json.error || 'Error')
        } catch { /* host unreachable; the poller will close the modal */ }
      }

      const submit = (e) => {
        e.preventDefault()
        setError('')
        answer({ action: 'submit', ...values })
      }
      const cancel = () => answer({ action: 'cancel' })

      React.useEffect(() => {
        const onKey = (e) => { if (e.key === 'Escape') cancel() }
        window.addEventListener('keydown', onKey)
        return () => window.removeEventListener('keydown', onKey)
      })

      return h('div', { className: 'vlt-mask', role: 'dialog', 'aria-modal': true, 'aria-label': t.useTitle },
        h('style', null, STYLES),
        h('form', {
          className: 'vlt-panel',
          onSubmit: submit,
          onKeyDown: (e) => { if (e.key === 'Escape') { e.preventDefault(); cancel() } },
        },
          h('h2', { className: 'vlt-title' },
            prompt.kind === 'save' ? `${t.saveTitle} · ${prompt.name}`
              : prompt.kind === 'rekey' ? t.rekeyTitle : t.useTitle),
          h('p', { className: 'vlt-sub' },
            prompt.kind === 'save' ? (prompt.isNew ? t.newVaultHint : t.masterHint)
              : prompt.kind === 'rekey' ? t.rekeyHint : t.useHint),
          prompt.kind === 'use' && h('pre', { className: 'vlt-cmd' }, prompt.command),
          prompt.kind === 'use' && prompt.entries?.length
            ? h('div', { className: 'vlt-chips' },
                h('span', { className: 'vlt-chip' }, t.entriesLabel),
                ...prompt.entries.map(n => h('span', { key: n, className: 'vlt-chip' }, n)))
            : null,
          prompt.kind === 'save' && prompt.note ? h('p', { className: 'vlt-sub' }, `${t.noteLabel}: ${prompt.note}`) : null,
          ...fields.map(([key, label, password], i) => h('label', { key, className: 'vlt-field' },
            h('span', null, label),
            h('input', {
              ref: i === 0 ? firstRef : null,
              type: password ? 'password' : 'text',
              value: values[key] || '',
              onChange: set(key),
              autoComplete: 'off',
            }))),
          prompt.kind === 'save'
            ? h('label', { className: 'vlt-show' },
                h('input', { type: 'checkbox', checked: showSecret, onChange: (e) => setShowSecret(e.target.checked) }),
                t.show)
            : null,
          error ? h('div', { className: 'vlt-error' }, error) : null,
          h('div', { className: 'vlt-actions' },
            h('button', { type: 'button', className: 'vlt-btn', onClick: cancel }, t.cancel),
            h('button', { type: 'submit', className: 'vlt-btn vlt-btn--primary' }, t.submit)),
        ))
    }

    function VaultDialogHost() {
      const t = STRINGS[localeOf()]
      const [prompt, setPrompt] = React.useState(null)
      React.useEffect(() => {
        let alive = true
        const tick = async () => {
          try {
            const r = await fetch('/vault-api/pending', { cache: 'no-store' })
            const json = await r.json()
            if (alive) setPrompt(json.prompt || null)
          } catch { if (alive) setPrompt(null) }
        }
        tick()
        const timer = setInterval(tick, 1000)
        return () => { alive = false; clearInterval(timer) }
      }, [])
      if (!prompt) return null
      return h(VaultModal, { key: prompt.id, prompt, t, onClose: () => setPrompt(null) })
    }

    let localeOf = () => 'en'

    return {
      inject: ['slots', 'locale'],
      apply(ctx) {
        localeOf = () => {
          let id = ''
          try { id = ctx.locale?.getLocale?.()?.locale || '' } catch {}
          return String(id || (typeof navigator !== 'undefined' && navigator.language) || 'en')
            .toLowerCase().startsWith('zh') ? 'zh' : 'en'
        }
        ctx.slots.inject('shell.overlay', () => ctx.slots.register({
          name: 'shell.overlay', id: 'vault-manager', order: 10,
        }, VaultDialogHost))
      },
    }
  },
})
