# CipherBox — 办公文件透明加密（防外发）

员工在 `S:` 保密盘（VeraCrypt 卷）里用 LibreOffice 无感编辑 docx/xlsx/pptx，文件**静态落盘即密文**（`.cbx` 容器）；从磁盘拿走文件发出去的就是密文，对方打不开；密钥由局域网服务器统一签发/轮换，加解密与外发事件全部审计落库（HMAC 链防篡改）。

```
员工双击 a.docx.cbx
   │
   ▼
Agent 常驻程序 (agent/)  ──取钥/上报──▶  服务器 (server/, FastAPI+SQLite, HTTPS 8443)
   │ 解密→临时明文(卷内)                    密钥签发·轮换·审计·令牌TTL/吊销
   ▼
受控 LibreOffice 打开（专用 profile + Job 绑定）
   │ 关闭后
   ▼
重新加密回 a.docx.cbx，删临时明文
```

## 仓库结构

| 目录 | 内容 |
|---|---|
| `server/` | FastAPI 服务器：令牌认证（TTL/续期/吊销）、密钥签发/轮换（全量版本集）、审计事件（HMAC 链 + 链头锚点）、`verify_audit` 校验命令 |
| `agent/` | 客户端常驻程序：`.cbx` 容器解析/加解密、密钥 DPAPI 缓存、文件夹监控自动加密、受控打开闭环、审计上报、崩溃恢复清理 |
| `lo-encryption-demo/` | LibreOffice 加密引擎（`CipherBoxDataSpace`）+ 拦截器 + spike 脚本 |
| `deploy/` | 部署脚本（服务器一键/启动/证书/种子/安装/验收） |
| `docs/` | 部署与实测文档 |
| `test/` | OOXML E2E |

## 快速开始

1. **部署服务器（一键，uv 虚拟环境）**：`docs/服务器部署指南.md`
   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File deploy\server_setup_uv.ps1
   powershell -NoProfile -ExecutionPolicy Bypass -File deploy\server_start.ps1
   ```
2. **单机实测全链路**（起 Agent → 放明文自动加密 → 双击受控打开 → 查审计）：`docs/部署实测指南.md`
3. **真实环境**：双机部署 + VeraCrypt 卷引导（卷引导脚本 todo 23 未完成，见下）。

## 测试

```powershell
python -m pytest server/tests agent/tests -q      # 201 passed（单元+集成）
# LO 引擎侧（需 S: 卷 + 常驻服务，见实测指南第 1 节）
& 'C:\Program Files\LibreOffice\program\python.exe' test\e2e_full.py
```

## 当前状态（诚实版）

- **可用**：服务器全部功能、加密引擎与 `.cbx` 容器、Agent 主程序（监控自动加密 + 双击受控打开 + 审计 + 崩溃恢复）、审计防篡改校验。
- **已知缺口**（详见 `.omo/handoff-session-summary.md` v2）：受控会话内"另存为明文"强制拦截**尚未接入**（拦截器本体已修复并冒烟通过）；`deploy/veracrypt_bootstrap.ps1`（todo 23）缺失；拦截器专项测试（todo 19）缺失；部署脚本的自启/ACL/LO 加固为简化版；主密钥明文存 DB（DPAPI 包裹待补）。
- **明确不做**：内核驱动、审批流、doc/xls/ppt 主密钥加密、移动端（计划 Scope 声明）。

## 文档

| 文档 | 内容 |
|---|---|
| `docs/服务器部署指南.md` | 服务器一键部署（uv）/手动步骤/运维/防火墙/自启/排障 |
| `docs/部署实测指南.md` | 单机实测全流程（服务器→Agent→加密→受控打开→审计） |
| `.omo/plans/cipherbox-transparent-encryption.md` | 权威计划（27 todo + 验收标准） |
| `.omo/handoff-session-summary.md` | 最新进度与缺口清单 |
