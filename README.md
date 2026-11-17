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

1. **部署服务器（一键，uv 虚拟环境）**：
   ```powershell
   # Windows
   powershell -NoProfile -ExecutionPolicy Bypass -File deploy\server_setup_uv.ps1
   powershell -NoProfile -ExecutionPolicy Bypass -File deploy\server_start.ps1
   ```
   ```bash
   # Ubuntu（国内镜像内置，WSL Ubuntu-24.04 真机验证）
   bash deploy/server_setup_uv.sh --install-uv
   bash deploy/server_start.sh
   ```
2. **客户端部署（Windows 10/11 员工机器）**：`docs/客户端部署指南.md`
3. **单机实测全链路**（起 Agent → 放明文自动加密 → 双击受控打开 → 查审计）：`docs/部署实测指南.md`
4. **真实环境**：双机部署 + VeraCrypt 卷引导（卷引导脚本 todo 23 未完成，见下）。

## 测试

```powershell
python -m pytest server/tests agent/tests -q      # 265 passed（单元+集成）
# LO 实机冒烟（需本机装有 LibreOffice；专用 headless 实例，不碰 S: 卷）
powershell -NoProfile -ExecutionPolicy Bypass -File lo-encryption-demo/test/run_smoke_link.ps1
# LO 引擎侧 e2e（需 S: 卷 + 常驻服务，见实测指南第 1 节）
& 'C:\Program Files\LibreOffice\program\python.exe' test/e2e_full.py
```

## 当前状态（诚实版）

- **可用**：服务器全部功能、加密引擎与 `.cbx` 容器、Agent 主程序（监控自动加密 + 双击受控打开 + 审计 + 崩溃恢复）、审计防篡改校验。
- **本次新接入（2026-11-16，单测 265 全绿 + LO 26 实机冒烟 6/6）**：受控会话"另存为明文"强制拦截已接入装配链（todo 17 ①）——每会话链接工作进程（LO 自带 Python）注册拦截器**先于文档加载**（硬顺序），按保存会话密钥（取不到即拒存）、审计经链接管道回流 Agent（断连落卷内 JSONL 队列、启动重放）；`.uno:Save/.uno:SaveAll` 永不注入（堵住"Ctrl+S 把临时明文写成密文、会话收尾回灌坏 `.cbx`"的数据损坏隐患）；会话 temp 目录内目标一律拒存（fail-closed）。实机冒烟（`lo-encryption-demo/test/run_smoke_link.ps1`，6 phase）覆盖：另存→CFB+引擎回读、Ctrl+S 明文、对话框流 fail-closed、temp 守卫、LinkWorker 硬顺序，并实证三条 LO 事实——`queryFrames` 每轮询返回全新代理（帧去重改走拦截器链 impl-name 探测）、pyuno 代理只暴露 UNO 声明成员、`close(False)` 连发 notifyClosing+disposing（关闭分类按"先通知后处置"定序）。
- **已知缺口**（详见 `.omo/handoff-session-summary.md`）：拦截器驻留 LO 进内（pythonloader 部署）与心跳监控未做；对话框流 with-key 分支待 GUI 真窗口验证；`deploy/veracrypt_bootstrap.ps1`（todo 23）缺失；部署脚本的自启/ACL/LO 加固为简化版（受控 profile 应预设 `WarnAlienFormat=false`——headless 实证其交互路径会杀 URP 桥）；主密钥明文存 DB（DPAPI 包裹待补）。
- **管理控制台（2026-11-17 新增）**：浏览器访问 `https://<服务器>:8443/admin/ui` —— 单文件页面（`server/static/admin.html`，无外部依赖，内网可用），支持审计事件过滤/分页查询、一键 HMAC 审计链校验、密钥轮换（双击确认）、员工令牌吊销；概览不含密钥 material（可投屏），页面可匿名加载但所有数据请求需 admin Bearer 令牌（仅存 sessionStorage）。新增端点 `GET /admin/summary`、`POST /admin/verify_chain`（admin-only），单测 10 项 + 本机真机 HTTPS 实测通过。
- **明确不做**：内核驱动、审批流、doc/xls/ppt 主密钥加密、移动端（计划 Scope 声明）。

## 文档

| 文档 | 内容 |
|---|---|
| `docs/服务器部署指南.md` | Windows 服务器一键部署（uv）/手动步骤/运维/防火墙/自启/排障 |
| `docs/服务器部署指南-Ubuntu.md` | Ubuntu 服务器部署（一键/systemd/ufw/双机 SAN/排障） |
| `docs/客户端部署指南.md` | Win10/11 员工机器部署（一键/令牌分发/.cbx 关联/验证清单） |
| `docs/部署实测指南.md` | 单机实测全流程（服务器→Agent→加密→受控打开→审计→管理界面） |
| `.omo/plans/cipherbox-transparent-encryption.md` | 权威计划（27 todo + 验收标准） |
| `.omo/handoff-session-summary.md` | 最新进度与缺口清单 |
