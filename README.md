# Credential Vault

Stores secrets in a local encrypted file behind a single master password, and runs
shell commands with those secrets injected — while the secret values and the master
password never enter the agent's conversation context or the session log.

English | [中文](README.zh.md)

## Why

An agent that needs a credential (a Git hosting token, an API key) normally sees it in
tool arguments or command output, which writes it into the session log and the model
context. This plugin keeps the whole secret lifecycle out of the conversation:

- Secrets are **typed by the user into a popup dialog**, never passed as tool arguments.
- Every command that consumes a secret is **shown to the user for approval** — with
  `{{placeholder}}` syntax instead of real values — before it runs.
- Command **output is redacted**: any occurrence of a used secret is replaced with `***`
  before the result reaches the agent.
- The master password travels only over a local HTTP exchange between the browser page
  and the Host process. It is never persisted and never logged.

## Tools

| Tool | Parameters | Popup | Description |
|---|---|---|---|
| `vault_save` | `name`, `note?` | yes | Save or replace an entry. The user types the master password (or sets one, on first use) and the secret value in the popup. For an existing vault the password is verified against the stored entries — one master password covers the whole vault. |
| `vault_list` | — | no | List entry names, notes and timestamps. Never returns secret values. |
| `vault_use` | `command`, `entries` | yes | Run a shell command containing `{{entry-name}}` placeholders. The popup shows the exact command for audit; on approval the plugin decrypts the entries in memory, substitutes every placeholder, runs the command, and returns exit code plus redacted output. |
| `vault_delete` | `name` | no | Remove an entry. |
| `vault_change_password` | — | yes | Open the change dialog (old password, new password, confirmation). All entries are re-encrypted with a fresh salt on success. The tool always returns the same neutral message — the agent cannot tell whether the password was changed, and never learns the new one. |

## Security model

- **Encryption**: the master password is stretched with scrypt (N=16384, r=8, p=1) into a
  256-bit key; each secret value is encrypted individually with AES-256-GCM. The GCM
  authentication tag doubles as the password check — a wrong password fails to decrypt.
- **Layout**: entry names, notes and timestamps stay plaintext (so `vault_list` and
  `vault_delete` need no password); only the values are ciphertext.
- **File**: `~/.dsh/vault.json` by default, written with mode `0600` through a temporary
  file and an atomic rename. Reads and writes are serialized in-process.
- **Memory only**: decrypted values live in process memory for the duration of one tool
  call. Nothing is cached on disk; by default every save/use/change asks for the master
  password again.
- **Approval gate**: the popup is the human decision point. A command such as
  `curl -d {{token}} https://untrusted.example` is visible, in placeholder form, before
  the password unlocks it.
- **Channel**: the popup talks to the Host over a local `/vault-api` HTTP route on the
  Harness web origin; requests carrying a foreign `Origin` header are refused.

### Known limitations

- During execution the substituted command is passed to the shell, so the secret is
  briefly visible in the process command line (`ps`) on multi-user hosts.
- Redaction covers exact occurrences of the secret in stdout/stderr; transformed output
  (hashes, partial echoes) cannot be redacted.
- If no browser page is connected, or nobody answers within the prompt timeout, the tool
  call fails with a clear error — nothing is saved or executed.
- The vault file protects secrets at rest; anyone who can read the Host process memory
  while a call runs is inside the trust boundary.

## Configuration

The patch row accepts an optional `config` object:

| Field | Default | Meaning |
|---|---|---|
| `path` | `~/.dsh/vault.json` (`$DSH_HOME/vault.json`) | Vault file location. |
| `redactOutput` | `true` | Replace secret occurrences in command output with `***`. |
| `commandTimeoutMs` | `120000` | Kill the command after this long. |
| `promptTimeoutMs` | `1800000` | Fail the call when the popup goes unanswered this long (30 minutes). |

```yaml
- insert:
    - id: vault-manager
      name: '@dreagonmon/vault-manager'
      config:
        redactOutput: true
```

## Install

From the npm registry, use the plugin manager (`install_bundle` with
`@dreagonmon/vault-manager`). From a local checkout, pass the package directory instead.
Or add the patch row above to a profile that can resolve the package. The
bundle carries both halves: the Host plugin (`index.js`) and the Web dialog
(`client.js`, rendered in the `shell.overlay` slot). No third-party runtime dependencies.

## Usage examples

```text
agent: vault_save { name: "github-token", note: "PAT for HTTPS git operations" }
user:  [popup] master password + secret value

agent: vault_use {
  command: "git push https://{{github-token}}@github.com/me/repo.git main",
  entries: ["github-token"]
}
user:  [popup] reviews the command, types the master password
agent: { exitCode: 0, stdout: "...", stderr: "..." }   # secrets redacted
```

## Privacy contract

What the agent can ever observe: entry names, notes, timestamps, exit codes, and output
with secret occurrences removed. What it can never observe through this plugin: the
secret values, the master password, and the outcome of a password change.
