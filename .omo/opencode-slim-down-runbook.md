# opencode 瘦身 Runbook（2026-10-28）

目的：把每次请求的固定上下文开销从 ~65–75k tokens 压到 ~12–15k。
影响范围：仅 opencode 配置与本机技能目录；**不改任何项目代码**。全部可逆（移动而非删除，配置有备份）。

---

## 0. 前置说明

- 配置**不热加载**：改完必须退出并重启 opencode。
- 若项目配置校验失败导致 opencode 起不来，用逃生阀启动：
  `set OPENCODE_DISABLE_PROJECT_CONFIG=1`（在该项目目录下启动，改好配置后再去掉）。
- 执行位置：任意 PowerShell（建议管理员不必需，用户级即可）。

---

## 1. 项目级 MCP 瘦身（只对 cipherbox 生效，不动全局）

创建 `C:\code\cipherbox\opencode.json`：

```powershell
@'
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "rea": { "enabled": false },
    "oracle": { "enabled": false },
    "codegraph": { "enabled": false }
  }
}
'@ | Set-Content -LiteralPath 'C:\code\cipherbox\opencode.json' -Encoding UTF8
```

说明：
- `rea`（约 168 个工具，~45–55k tokens/请求）——逆向工程专用，本项目零用途，**收益最大**。
- `oracle`（5 工具）——本项目用 SQLite；保留在全局，其他项目仍可用。
- `codegraph`（1 工具，~1.8k）——本仓库仅约 2k 行，grep 足够；需要时删掉此行即可恢复。
- 已验证的禁用写法来自 opencode 官方 skill 文档（`"name": { "enabled": false }` 用于禁用从父级配置继承的 MCP）。

---

## 2. 归档外部技能（可逆；不删除）

把两个自动扫描目录里的技能**移动**到扫描路径之外的归档区（注意：必须移出 `.agents\skills` / `.claude\skills` 目录树，放在其子目录里仍会被递归扫描）。

```powershell
$archive = 'C:\Users\22419\skill-archive'
New-Item -ItemType Directory -Force -Path $archive,
  "$archive\claude-skills", "$archive\agents-skills" | Out-Null

Get-ChildItem 'C:\Users\22419\.claude\skills' -Force |
  Move-Item -Destination "$archive\claude-skills" -Force
Get-ChildItem 'C:\Users\22419\.agents\skills' -Force |
  Move-Item -Destination "$archive\agents-skills" -Force

# 验证：源目录应为 0，归档区应为 35（17 + 18）
(Get-ChildItem 'C:\Users\22419\.claude\skills','C:\Users\22419\.agents\skills' `
  -Recurse -Filter SKILL.md -ErrorAction SilentlyContinue | Measure-Object).Count
(Get-ChildItem $archive -Recurse -Filter SKILL.md | Measure-Object).Count
```

内容：16 个 `dingtalk-*`（两处重复）+ `developing-with-streamlit`（两处重复）+ `reverse-engineer-anything`。

**恢复方式**：在需要钉钉/Streamlit 的项目 `opencode.json` 里加：
```json
{ "skills": { "paths": ["C:/Users/22419/skill-archive/agents-skills"] } }
```
或把目录直接移回原处。

---

## 3. 写归档说明

`C:\Users\22419\skill-archive\README.md`：

```markdown
# Archived opencode skills (2026-10-28)

归档原因：减少 opencode 每次请求的固定上下文开销。
内容：16 个 dingtalk-*（.agents 与 .claude 两处重复）、developing-with-streamlit（重复）、
reverse-engineer-anything（配套已禁用的 rea MCP）。

恢复：在目标项目 opencode.json 增加
  "skills": { "paths": ["C:/Users/22419/skill-archive/agents-skills"] }
或把目录移回 C:\Users\22419\.agents\skills\ 。
```

---

## 4. Oracle 口令外置（安全项）

全局配置 `C:\Users\22419\.config\opencode\opencode.jsonc` 里目前有**明文生产库口令**（且用户名字符串包含口令子串，**不可**用简单字符串替换）。

```powershell
$cfg = 'C:\Users\22419\.config\opencode\opencode.jsonc'
Copy-Item $cfg "$cfg.bak-20261028" -Force

$j      = Get-Content $cfg -Raw | ConvertFrom-Json
$secret = $j.mcp.oracle.environment.ORACLE_RCPQ_PASSWORD

if ([string]::IsNullOrEmpty($secret)) {
  'skip: 已是外部引用或缺失'
} else {
  setx ORACLE_RCPQ_PASSWORD $secret | Out-Null   # 用户级持久化，不回显
  $raw = Get-Content $cfg -Raw
  # 精确替换该 JSON 属性值，避免误伤同名前缀的用户名
  $raw = [regex]::Replace($raw,
    '("ORACLE_RCPQ_PASSWORD"\s*:\s*")[^"]*(")',
    '${1}{env:ORACLE_RCPQ_PASSWORD}${2}')
  Set-Content -LiteralPath $cfg -Value $raw -Encoding UTF8
  'migrated'
}

# 验证：可解析 + 不再含明文（不打印口令）
(Get-Content $cfg -Raw | ConvertFrom-Json) | Out-Null; 'parse OK'
Select-String -LiteralPath $cfg -Pattern 'ORACLE_RCPQ_PASSWORD"\s*:\s*"\{env:ORACLE_RCPQ_PASSWORD\}"' |
  ForEach-Object { 'env-ref OK' }
```

注意：`setx` 只对**新启动**的进程生效，重启 opencode 后才生效。

---

## 5. 未处理项（收益小/机制不支持，暂缓）

- `websearch` 与其 `web_search_exa` 重复（~300 tokens）：来自插件/内置，无法按单个工具禁用，忽略。
- OMO 内置中本项目用不到的 `playwright / frontend / visual-qa / ultimate-browsing / ast-grep / coding-agent-sessions / lsp-setup / init-deep / hyperplan / ulw-research / security-research(别名)`（合计 ~2k）：由 `oh-my-openagent` 插件托管，升级会覆盖，建议不动。

---

## 6. 验收清单

- [ ] `C:\code\cipherbox\opencode.json` 存在且为合法 JSON
- [ ] 两个源技能目录 `SKILL.md` 计数 = 0；归档区 = 35
- [ ] 全局配置 `ConvertFrom-Json` 通过；`ORACLE_RCPQ_PASSWORD` 值为 `{env:ORACLE_RCPQ_PASSWORD}`
- [ ] `echo %ORACLE_RCPQ_PASSWORD%` 在新终端非空
- [ ] 重启 opencode 后：工具列表里 `rea_*`/`oracle_*`/`codegraph_*` 消失；技能列表里不再有 `dingtalk-*`
- [ ] 预计固定开销：~65–75k → ~12–15k tokens/请求（约 -75~80%）
