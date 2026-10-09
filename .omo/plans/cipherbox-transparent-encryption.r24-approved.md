# cipherbox-transparent-encryption - Work Plan

## TL;DR (For humans)

给一家小公司做"办公文件防外发"工具：员工在 `S:` 保密盘（VeraCrypt 卷）里用 LibreOffice 无感编辑 Word/Excel 等文件，文件**静态落盘即密文**；从磁盘拿文件发邮件/微信/拷 U 盘，发出去的就是密文（对方打不开）；非 LibreOffice 直接打开密文 = 打不开；员工想"另存为明文/导出"会被**强制审计记录（仅记录不审批）**；密钥由局域网服务器统一签发，加解密/外发事件都上传审计。

**格式范围（重要）**：现有 `lo-encryption-demo` 的自定义引擎 `CipherBoxDataSpace` 只覆盖 **OOXML 三格式（docx/xlsx/pptx）**。老二进制格式 **doc/xls/ppt 不走自定义引擎**（`test_documents.py` L33-35 中 `use_hook=False`，走 LO 内置加密）——本期将 doc/xls/ppt 主密钥文件级加密列为 **out-of-scope**，避免"单主密钥统一签发六格式"的虚假承诺。Wave 0 会再实测确认这一边界。

**安全边界（诚实声明）**："落盘即密文"仅指静态 `.cbx` 文件。受控打开会话期间存在**受控明文临时副本**（落在 VeraCrypt 卷内 `S:\.cipherbox-tmp\`）；LO 的服务/受控专用 profile 也落在卷内 `S:\.cipherbox-profile\`（AutoRecovery/备份副本关闭，避免明文泄卷外）。该窗口不在"防外发"承诺内；防"复制内容/拍屏/恶意规避/会话期临时明文"需内核 minifilter（采购），超出本项目。

**为什么这么做**：复用已跑通的加密内核（AES-256-CBC + PBKDF2 + 口令校验），只补"无感注入 + 受控打开 + 中心密钥/审计 + 部署"这一层。VeraCrypt 用**原版**只做物理隔离（防介质被偷/取证），不做文件/进程审计（磁盘级驱动做不到）。

**它会做什么**：① 局域网密钥/审计服务器（HTTPS，含部署引导）；② 客户端 Agent（独立解密/加密模块 + 监控受保护文件夹自动加密 + 串行化双击受控打开 + 密钥缓存 + 审计上报）；③ LibreOffice 内"强制加密保存"拦截器（驻留 LO 进程、经 UNO 直传密钥、覆盖全部 frame，堵"另存为明文/导出/发送"）；④ 服务器+客户端安装/部署脚本 + VeraCrypt 卷引导。

**它不会做（明确边界）**：复制内容粘贴/拍屏/员工恶意规避、非受控打开时"主动提示+留痕"、doc/xls/ppt 的主密钥文件级加密——均需内核 minifilter 或超出本期范围。

**工作量**：约 27 个实现任务 + 4 个最终验证，分 6 个 wave。

**风险（已识别并内置缓解）**：① Spike（Wave 0）是真风险闸门，含二进制格式能否路由、LO 单实例（默认 profile 转交 + 同 profile 并发）、拦截器可行性（含新 frame）三项实测；② 单主密钥 + 每文件内嵌口令 verifier = 共享口令的离线爆破面，依赖 ≥256bit 高熵口令缓解；③ 会话期明文临时副本是已声明残余风险（落卷内 + 关闭清理 + profile 落卷内关 AutoRecovery + **Agent 退出时 Job Object 终止受控 GUI**）；④ 拦截器密钥经命名管道 UNO 直传、受控 profile 禁宏（详见 todo 17/21），残余=同用户进程调试器读内存属恶意规避已声明；⑤ 局域网明文 HTTP 会被嗅探 token，缓解=自签 HTTPS；⑥ 防抖窗口（明文落盘→加密之间）是可复制走明文的小窗口；**且文件被任一 LO 实例打开期间（锁文件存在）明文窗口持续整个会话，此期间在非受控 profile 的另存/导出不产生审计**，均已声明；⑦ **密钥轮换为 forward-only**：存量 `.cbx` 不自动 re-key（仅打开/保存触碰时用当前密钥重加密），历史密钥集缓存在每客户端 DPAPI——单客户端被攻破可离线解其缓存版本对应的全部历史文件，此单点暴露已声明；**离线期间新加密可能用缓存中的旧版本密钥（key_version 落后），服务器对该类 encrypt 事件仅记录不拒绝，审计查询可按 key_version 过滤**；⑧ 审计 HMAC 链防"行级篡改+尾部删除"，**不防"整库文件级回滚"**（events+meta 同时被旧快照替换则校验通过），此残余已声明；⑨ **令牌吊销语义**：吊销仅阻断服务器交互（`/key` 刷新、`/events` 上报）与后续版本获取，**不回收客户端已 DPAPI 缓存的历史密钥**——离职员工离线仍可解其缓存版本对应的存量文件（仅轮换后新文件受保护），此残余已声明。

**决策**：已与用户逐项确认（文件级加密复用引擎 / 被动防外发 / 仅记录不审批 / 单主密钥 / 原版 VeraCrypt / TDD）。

## Scope

### In scope
- 中心服务器：主密钥签发/轮换（**返回全量版本集**）+ 加解密/外发审计记录 + 每员工令牌认证（**带 TTL/续期/吊销**）（Python + SQLite，局域网，**HTTPS**）。
- **服务器部署引导**：装服务器 + 生成 HMAC 密钥 + 种子 admin/员工令牌 + 自签 CA/证书下发。
- 客户端 Agent（Windows，Python）：**独立 .cbx 容器解析与加解密模块**、密钥获取与 DPAPI 缓存（含历史密钥集）、受保护文件夹监控自动加密、**串行化**双击受控打开（解密→LO 打开→关闭重加密，**UNO 文档级关闭检测 + Job Object 绑定**）、审计上报。
- LibreOffice 内"强制加密保存"拦截器：堵"另存为明文/导出/发送"，并对明文导出/发送强制审计记录；**驻留 LO 进程、经 UNO 由 Agent 直传密钥、覆盖全部 frame、缺密钥 fail-closed**。
- 部署脚本：安装 LibreOffice 扩展 + Agent + 配置（服务器地址/令牌/CA pin）、`.cbx` 文件关联、VeraCrypt 卷引导、**服务/受控专用 profile 落卷内 + 宏安全设置 + 关 AutoRecovery/备份副本**。
- 测试（TDD）：服务器单测/集成、Agent 单测/集成、拦截器测试、E2E 端到端、安全加固测试。
- **格式范围**：OOXML（docx/xlsx/pptx）走主密钥文件级加密。文件级加密复用现有 `lo-encryption-demo/src/cipherbox.py`（**抽离纯密码学函数复用 + encrypt() 加 fail-closed 门禁，不改加密算法**）。

### Out of scope（Must-NOT-Have）
- 内核 minifilter 驱动 / 主动提示+留痕（需采购透明加密/DLP 产品）。
- VeraCrypt 二次开发（用原版）。
- 审批流（涉密分级审批留作后续可选增强；本期仅记录）。
- 复制内容粘贴/拍屏/恶意规避的防护；会话期明文临时副本的防外发。
- **二进制格式 doc/xls/ppt 的主密钥文件级加密**（自定义引擎不覆盖，`test_documents.py` 已证 `use_hook=False`；如需支持改用 LO 内置加密 + 独立口令，作后续可选）。
- **密钥轮换的存量文件全量 re-key 扫描**（forward-only，触碰时才迁移；全量重加密扫描作后续可选）。
- **审计整库文件级回滚的检测**（需 chain_head 外送至独立载体，本期仅行级+尾部删除防护）。
- 移动端 / 非 Windows 平台。
- ODF 格式（现有引擎已明确排除）。

## Verification strategy

- **TDD**：每个功能先写测试（沿用现有 pytest 风格），再实现；`pytest` 通过是每个 todo 完成的硬前提。
- **分层验证**：
  - 纯逻辑（密钥派生、容器格式、CFB 解析、服务器路由、审计 HMAC 链 + 链头锚点）→ 单测，无外部依赖。
  - Agent 监控/加密/受控打开 → 需要常驻 soffice（`soffice --headless -env:UserInstallation=<服务专用profile> --accept="pipe,name=cipherbox-service;urp;"`），沿用现有 `test_documents.py` / `test_e2e.py` 的 UNO 驱动方式（**生产与测试统一走命名管道**；仓库既有 socket URL 仅作历史基线参考）。
  - 服务器 → 单测（FastAPI TestClient + 内存/临时 SQLite）+ 集成（起真实进程，HTTPS，requests 打端点）。
  - E2E → 真实文档 docx/xlsx/pptx（OOXML）加解密 + 外发密文 + 审计落库全链路。
- **验收证据路径**：每条 QA 都写明"运行命令 + 断言 + 输出到哪里（日志/DB/文件）"，执行者零判断。
- **最终验证 wave**（F1–F4）在全部 todo 后并行跑，全部 APPROVE 才交付。

## Execution strategy

**顺序依赖**：服务器（Wave 1）先于 Agent（Wave 2，Agent 依赖 `/key`、`/events`）；Agent 先于部署（Wave 4）；强制加密保存（Wave 3）与 Agent 可并行但依赖同一 LO 环境；E2E（Wave 5）最后。**启动顺序：挂载 VeraCrypt 卷 → 启动常驻服务（profile 落卷内）→ 启动 Agent。**

**Wave 划分**：
- Wave 0（Spike，4 todo）：验证方案 B 三要素 + 拦截器可行性（含新 frame）+ 实测格式边界。**这是唯一的真风险闸门**。
- Wave 1（服务器，5 todo）：令牌认证（含 TTL/吊销）+ 密钥签发/轮换（全量版本集）+ 审计事件 + 测试。
- Wave 2（Agent 核心，7 todo）：容器解析/加解密模块（含 fail-closed 门禁）+ 密钥管理 + 文件夹监控加密 + 串行化受控打开（含 Job Object + 文档级关闭检测）+ 审计上报 + 测试。
- Wave 3（强制加密保存，3 todo）：LO 拦截器（全 frame 注册 + LO 驻留 fail-closed）+ 外发审计 + 测试。
- Wave 4（部署，5 todo）：服务器部署引导 + 客户端安装 + `.cbx` 关联 + VeraCrypt 卷引导 + 验证。
- Wave 5（E2E + 加固，3 todo）：E2E + 明文临时清理 + 审计完整性（链头锚点）。

**回退判据**（Wave 0 任一失败则切换 A 方案）：(1) UNO 重加密已有明文文件不可靠/过慢；(2) `.cbx` 关联或"打开→关闭→重加密"闭环无法稳定（含 LO 单实例无法用专用 profile + 串行化解决）；(3) 明文临时生命周期有致命竞态；(4) 二进制格式（doc/xls/ppt）实测确无法路由自定义引擎（此情况不切 A，而是确认格式边界并按 out-of-scope 处理）。切换时 A = LO 内部拦截器（`XDispatchProviderInterceptor` 注入 `EncryptionData{CryptoType,Password}`），其"强制加密保存"同时承担防外发——**A 的可行性已在 todo 4 spike 验证过**，因此回退有安全网。

**全局命名约定**：密文一律 `<原全名>.cbx`（如 `a.docx.cbx`，保留原始扩展名）；解密时剥尾部 `.cbx` 还原临时文件名；受控会话临时目录用 `S:\.cipherbox-tmp\<会话UUID>\` 防同名冲突；**隔离区统一用 `S:\.cipherbox-quarantine\`（todo 12/13/26 的"隔离"一律落此，watcher 排除规则点名之）**。

**运行环境前提**（执行者需确认，若缺失则先补）：Windows + LibreOffice + 现有 `lo-encryption-demo` 可构建可跑；**Wave 0 前需已挂载 S: 卷（卷引导脚本在 Wave 4 todo 23，早期可用 subst 替代盘符或先手动建卷）**；`start_soffice.ps1`（test 注释引用但仓库未见，需确认/创建）；Python 3.11+（现有 `.pyc` 显示 3.11/3.13 均运行过）；OpenSSL 用于自签 HTTPS 证书；`olefile` 用于 CFB 解析（**必选**）。

## Todos

### Wave 0 — Spike：方案 B 可行性验证（真风险闸门）

- [ ] 1. 确认常驻 soffice 可启动并注册 CipherBoxDataSpace 服务（服务专用 profile 落卷内）
  - References: `lo-encryption-demo/test/check_service.py`、`test/test_e2e.py`（URL `uno:socket,host=127.0.0.1,port=2002`）；`lo-encryption-demo/src/cipherbox.py`（服务名 `com.sun.star.comp.oox.crypto.CipherBoxDataSpace`）。
  - Acceptance: 创建 `start_soffice.ps1`，启动命令为 `soffice --headless -env:UserInstallation=<服务专用profile, 落 S:\.cipherbox-profile\service\> --accept="pipe,name=cipherbox-service;urp;"`（**UNO 走命名管道而非 TCP socket——loopback TCP 跨用户无认证，命名管道受 NT DACL 限定当前用户**；服务专用 profile 落卷内且规避与员工正常 LO 实例的单实例转交冲突；**并设 `TMP=TEMP=S:\.cipherbox-tmp\service\` 卷内临时目录**），运行后 `check_service.py` 输出 `RESULT: OK service instantiated`（**同步把 `check_service.py`、`test_documents.py`、`test_e2e.py` 三处连接 URL 迁移到 `uno:pipe,name=cipherbox-service;urp;StarOffice.ComponentContext`——否则它们按 socket 连接必然 `could not connect`（todo 2 spike 与 todo 25 E2E 均沿用 `test_documents.py` 驱动，不迁移则必失败）**）。启动顺序：先挂卷再起服务。
  - QA happy: 运行 `check_service.py` → 断言 `XPackageEncryption` 与 `XServiceInfo` 均非空、`encrypt()` 返回 5 个命名流（DataSpaceMap/Version/DataSpaceInfo/TransformInfo/EncryptedPackage；**`check_service.py` 需传一个测试口令——todo 10 ③ 加 fail-closed 门禁后无口令调 `encrypt()` 会抛错**）。
  - QA failure: 停掉 soffice → `check_service.py` 超时/`could not connect`；**且在员工正常启动 LO 时，服务进程仍存活不退出**（服务 profile 隔离生效）。
  - Commit: `git init`（若用户同意）后首个提交：补齐 `start_soffice.ps1` 与 `check_service.py` 基线。

- [ ] 2. 验证"UNO 重加密已有明文文件"可行 + 实测二进制格式边界
  - References: `lo-encryption-demo/test/test_documents.py`（`storeToURL` + `EncryptionData` 触发加密；L33-35 `use_hook=False` 表明 doc/xls/ppt 走内置加密）、`test/probe_encrypt.py`（媒体描述符触发矩阵）。
  - Acceptance: 写脚本：`loadComponentFromURL(明文.docx)` → `storeToURL(目标, [FilterName, Password, EncryptionData{CryptoType:"CipherBoxDataSpace", Password:主密钥}])` → 生成 CFB 容器（OLE_MAGIC `\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1`）含 `EncryptedPackage` 与 `CipherBoxDataSpace` 标记（**引擎实际返回 5 流 DataSpaceMap/Version/DataSpaceInfo/TransformInfo/EncryptedPackage，无 `EncryptionInfo` 流——那是 LO 内置 agile 加密的流名，切勿断言它**）；用 `Password:主密钥` 重新 `loadComponentFromURL` 能读回原文。**并对 .doc/.xls/.ppt 实测：带 `EncryptionData{CryptoType}` 保存后，产物是否含 `CipherBoxDataSpace` 标记，据此固化格式边界结论。**
  - QA happy: docx/xlsx/pptx 三格式重加密+重载，内容标记（`CipherBox round trip marker 4711`）一致；doc/xls/ppt 输出明确结论（走自定义引擎 or 内置加密）。
  - QA failure: 传错密码重载 → 断言返回 None/拒绝（复用 `test_password_verify.py` 已验证的 verifier 行为）。
  - Commit: spike 脚本 + 格式边界结论记录到 `lo-encryption-demo/test/spike_reencrypt.py`。

- [ ] 3. 验证"双击受控打开闭环 + `.cbx` 文件关联 + LO 单实例两态 + 文档级关闭检测"可行（受控 profile 落卷内）
  - References: `lo-encryption-demo/src/cipherbox.py`（`decrypt` 返回 XSeekable TempFile 流）、`test/test_e2e.py`（`read_stream` 读解密流）。
  - Acceptance: 写 spike：把密文 `.cbx` 解密到临时明文 → 启动**独立 GUI soffice 进程**（`-env:UserInstallation=<受控专用profile, 落 S:\.cipherbox-profile\controlled\>`）打开 → **文档关闭后（持有打开文档返回的 XModel 对象，以其 dispose/close 事件为结束信号，与 todo 14 实现机制一致——而非等进程退出，LO 关文档后回 Start Center 进程不退出）Agent 主动终止受控进程** → 重加密回 `.cbx` → 删临时明文；Windows 注册表写一次 `.cbx` 关联指向启动器后，双击能触发该启动器。spike 必须实测：**(a) 默认 profile 已有运行中 soffice 时，受控进程仍独立可等待退出；(b) 受控专用 profile 已有实例时再次受控打开——验证"同 profile 单实例转交"发生，据此确认需 Agent 侧串行化；(c) 仅关文档窗口（Start Center 仍开）时，文档级关闭检测能正确判定"编辑结束"**。
  - QA happy: 端到端脚本验证：密文→明文→LO 打开→保存→关闭→重加密→密文，全程无明文残留；且 (a) 态 `waitpid` 正确等待、(c) 态文档级检测正确触发重加密；**(d) 实测活动 LO 会话对锁文件/文档的 Restart Manager 句柄可枚举性，结论写入 spike 记录（供 todo 12 陈旧锁判活）**。
  - QA failure: 启动器被杀/崩溃 → 验证有清理路径（残留临时明文可被下次启动回收），无静默丢失；(b) 态确认转交发生、记录为需串行化的证据。
  - Commit: spike 脚本 + 关联注册脚本草稿；若此步失败，触发"B→A 回退"并在草稿记录切换点。

- [ ] 4. 验证 XDispatchProviderInterceptor 拦截 SaveAs/ExportTo/Send 可行性（回退方案 A 的安全网 + 覆盖与新 frame 探测）
  - References: LO `com.sun.star.frame.XDispatchProviderInterceptor`；`lo-encryption-demo/src/cipherbox.py`（服务注入方式）。
  - Acceptance: 写最小 spike：经 UNO 连接注册一个拦截器，拦截 `.uno:SaveAs` 时改写 media descriptor（注入 `EncryptionData{CryptoType:"CipherBoxDataSpace", Password:<测试口令>}`）并委托原 dispatch；验证保存产物是 CFB 密文且用该口令可解。**同时实测：`Window > New Window` 开第二 frame 后，从新 frame 执行 SaveAs 是否仍被拦截（若否，记录为"需 per-frame 注册"证据）；新 frame 的自动发现机制（轮询 `Desktop.Components` 差集 / GlobalEventBroadcaster `OnNewView` / 每 frame `COMPONENT_ATTACHED`）哪个可用；拦截器进程内对象回调 Agent 取钥/上报的反向 UNO 通道是否可行；`.uno:SaveACopy`（另存副本）是否可拦截；SaveAs 强制改写为 `.cbx` 后，紧接着 `.uno:Save` 是否仍携带 EncryptionData（若否则 `.cbx` 目标会被明文覆盖）**。同时探明：`.uno:ExportTo`/`.uno:ExportToPDF`/`.uno:ExportDirectToPDF`（PDF 导出）、**`.uno:Print`/`.uno:PrintDefault`（含 print-to-file/Print-to-PDF 变体）**、`.uno:SendMail`/`.uno:SendDocAsPDF` 等"发送"族 dispatch 是否可拦截、可否注入（预期：PDF/打印/发送无法用 EncryptionData 加密，只能放行+审计）；**`.uno:SaveAll` 的 frame/desktop 路由方式（决定 temp 文档逐文档判定放行的实现路径）**。
  - QA happy: 拦截 SaveAs 后产物为密文、可解；输出 ExportTo/SendMail 可拦截性结论；第二 frame 下 SaveAs 拦截结论。
  - QA failure: 拦截器注册失败/未生效 → 记录为"方案 A 不可行"结论，不进入回退依赖。
  - Commit: `lo-encryption-demo/test/spike_interceptor.py` + 结论记录。

### Wave 1 — 中心服务器（Python + SQLite + HTTPS）

- [ ] 5. 服务器骨架 + 每员工令牌认证（含 TTL/续期/吊销）+ 健康检查（HTTPS）
  - References: 无既有代码（新增）。技术栈 FastAPI + SQLite（`sqlite3` 或 SQLAlchemy），按 `programming` 约定（类型标注、结构化错误）；HTTPS 用自签证书（OpenSSL 生成，随部署下发，客户端 pin 证书）。
  - Acceptance: `GET /health` 返回 200；受保护端点缺/错 `Authorization: Bearer <token>` 返回 401；令牌存 DB 表 `employees(token_hash, employee, level, issued_at, expires_at, revoked)`（**`employee` 为员工标识列，审计事件的 employee 字段由此解析**），**TTL=90 天**，`POST /token/renew`（认证后且未吊销）续期，`POST /admin/revoke`（管理员）吊销；过期或吊销 token → 401；`/key`/`/events` 均检查吊销态；服务只监听 HTTPS（8443），**不监听 HTTP 端口（连接直接拒绝）**——不做"仅跳转"（跳转会令客户端先发一次带 Bearer 的明文请求）。
  - QA happy: TestClient 断言 health 200、带正确 token 的 `/key` 200、错 token 401；HTTPS 握手成功、HTTP 明文被拒；续期后 expires_at 顺延；吊销后该 token 调 `/key` → 401。
  - QA failure: 无 token / 过期 / 已吊销 / 错误格式 → 全部 401 且不泄露信息；明文 HTTP 访问受保护端点 → 拒绝。
  - Commit: `server/` 骨架 + `server/tests/test_auth.py` + 自签证书生成脚本。

- [ ] 6. 主密钥签发与轮换端点（≥256bit 高熵口令 + 全量版本集返回）
  - References: `lo-encryption-demo/src/cipherbox.py`（`derive_key`/PBKDF2 用"口令"派生 AES 密钥）；口令用 `secrets.token_hex(32)`（64 hex，256bit）生成，杜绝弱口令。
  - Acceptance: `POST /key`（认证后）返回**全量版本集** `{"versions": [{"version": n, "key": <64-hex>}, ...], "current": n}`（客户端整体同步，消除"按号索取不知 n"的盲区）；`POST /admin/rotate`（管理员）生成新版本追加进版本集，旧版本**保留**供解旧文件；密钥只存 DB（**key 列用 todo 20 ⑥ 指定的专用运行账户上下文 DPAPI 包裹存储，内存中解密使用，防 DB 文件级外泄即得全量主密钥**）。
  - QA happy: 两次 `/key` 返回同一 current 且版本集稳定；轮换后 current +1、新 key 不同、版本集含全部历史。
  - QA failure: 非管理员 token 调 `/admin/rotate` → 403；未认证 → 401。
  - Commit: 密钥签发/轮换 + `server/tests/test_key.py`。

- [ ] 7. 审计事件记录端点 + SQLite schema（employee 由 token 解析，file_hash=明文内容 sha256）
  - References: `hashlib.sha256`（`cipherbox.py` 已依赖）；字段统一：`file_hash` = **明文内容** sha256（加密前原文），decrypt/export 事件同用明文 hash。
  - Acceptance: `POST /events`（认证后）落库 `events(id, ts, employee, file_hash, action, key_version, machine, ok, prev_hash, mac)`；**`employee` 由服务端从 Bearer token 解析（查 `employees` 表的 `employee` 列；请求体同名字段一律拒绝 422，杜绝冒名）**，`machine`/`ts` 客户端自报可接受；`GET /events`（管理员）分页查回，**支持按 `key_version`/`action`/`employee` 过滤参数**；**服务器不接收/不存储文件内容**（端点只收元数据 JSON）。
  - QA happy: 发一条 encrypt 事件 → DB 可查回字段一致（含 key_version），且 `employee` 与 token 所属员工一致（即使请求体伪造了不同 employee）；**按 key_version 过滤能正确筛出该事件**。
  - QA failure: 缺必填字段 → 422；未认证 → 401；超长/非法 hash → 422。
  - Commit: 审计事件端点 + schema + `server/tests/test_events.py`。

- [ ] 8. 服务器单元测试（TDD 补齐覆盖）
  - References: 上面 5–7 的测试文件。
  - Acceptance: `pytest server/tests/` 全绿，覆盖 auth/key/events 三组 happy+failure 路径。
  - QA happy: `pytest -q` 退出码 0，报告测试数 > 15。
  - QA failure: 人为改坏一处（如错 token 校验）→ 对应测试红。
  - Commit: 测试补漏后的提交。

- [ ] 9. 服务器集成测试（起真实进程打端点，HTTPS）
  - References: FastAPI 应用入口 `server/app.py`。
  - Acceptance: 启动真实 uvicorn（HTTPS）→ 用 `requests`（verify=自签 CA）走完 `health→key→events→(admin)rotate→events` 全链路，DB 落库可查。
  - QA happy: 脚本断言每步 HTTP 状态码与返回体。
  - QA failure: 停掉 DB 文件写权限 → 端点返回 5xx 且不崩进程、日志有原因。
  - Commit: `server/tests/test_integration.py` + 启动说明。

### Wave 2 — 客户端 Agent（Python，Windows）

- [ ] 10. Agent 侧 .cbx 容器解析与独立加解密模块（复用纯密码学函数 + encrypt() 加 fail-closed 门禁）
  - References: `lo-encryption-demo/src/cipherbox.py` 的 `aes_cbc`/`derive_key`/`derive_verifier`/`verifier_matches`/`_parse_verifier`/`_i64`/`_pkcs7_*`（纯函数，L240-291、L299-379 等）**及 `aes_cbc` 的 CNG 依赖链 `_cbc_raw`/`_load_bcrypt`/`_as_pbuf`（L100-237，随 `aes_cbc` 一并抽离，否则 `cipherbox_crypto.py` 不可导入）**；`setupEncryption` 的空口令兜底（L645-647）与 `_require_key` 的 demo key 兜底（L769-773）。
  - Acceptance: ① 把上述纯密码学函数抽离到新模块 `lo-encryption-demo/src/cipherbox_crypto.py`（**无 `uno` 依赖**），`cipherbox.py` 改为从它 import（**只抽离不改加密算法，现有 LO 内引擎行为不变**）。② 新增 `agent/container.py`：用 `olefile`（只读 CFB）解析 `.cbx`，提取 `EncryptedPackage` 载荷与 `DataSpaceInfo` 的 verifier trailer；载荷按 `_i64(len) + iv + cipher` 用 `aes_cbc(derive_key(口令), iv, ct)` 解密；verifier 试探复用 `_parse_verifier` + `verifier_matches`，**verifier 缺失（旧文件向后兼容）时按"未知"处理，对全部缓存版本逐个尝试解密，成功判据 = padding 合法 且 明文以 `PK\x03\x04` 开头（OOXML 恒为 ZIP），不满足则继续下一版本直至穷尽报错**。③ **给 `cipherbox.py` 的 `encrypt()` 加 fail-closed 门禁**：仅当 key 来源于 `NV_KEY`、**非空** `Password`、或经 verifier 验证的 `generateEncryptionKey` 路径时才允许加密，空/缺失口令一律抛错拒绝保存（堵"伪密文"）；load/decrypt 路径不改。
  - QA happy: 用 UNO 加密出的真实 `.cbx`（todo 2 产物）作为输入，`agent/container.py` 解密结果与原文逐字节一致；verifier 试探能对错口令返回 False、对正确口令返回 True；**无口令调 `encrypt()` → 抛错而非产出空口令密文**。
  - QA failure: 损坏的 `.cbx`（截断/错 magic）→ 抛明确错误而非静默返回空；错口令解密 → 抛"密钥错误"。
  - Commit: `lo-encryption-demo/src/cipherbox_crypto.py` + `agent/container.py` + `agent/tests/test_container.py`。

- [ ] 11. Agent 密钥管理：取全量版本集 + DPAPI 本地缓存（含历史密钥集，加密前刷新）
  - References: Windows DPAPI 用 `ctypes` 调 `CryptProtectData`/`CryptUnprotectData`（与 `cipherbox.py` 现有 CNG `ctypes` 风格一致）。
  - Acceptance: Agent 启动 → `POST /key` 取**全量版本集** → DPAPI 加密写本地缓存（**统一位置 `%APPDATA%\CipherBox\keycache.dat`，放卷外以保证卷未挂载/离线可用**）；缓存**全量历史版本集**（version→口令），打开旧文件时用 todo 10 的 verifier 试探逐版本判定正确口令（纯 Python，不反复 UNO 加载）；**加密前若在线则先刷新版本集**；离线用缓存。
  - QA happy: 首次在线取版本集→缓存文件存在且非明文；断网重启→能用缓存解密文件；轮换后用旧口令打开旧 `.cbx` 成功（逐版本试探命中）；在线加密前版本集已刷新。
  - QA failure: 服务器返回 401（token 失效）→ Agent 明确报错并提示重配，不用空密钥；无匹配版本 → 明确"密钥缺失"而非静默失败。
  - Commit: `agent/key_manager.py` + `agent/tests/test_key_manager.py`。

- [ ] 12. 受保护文件夹监控（watchdog）+ 防抖 + 排除自身输出/受控临时目录/带锁文件
  - References: `watchdog` 库（`Observer`/`FileSystemEventHandler`）；受保护文件夹默认 = VeraCrypt 卷挂载盘 `S:\` 或配置指定目录。
  - Acceptance: 监控目录出现新/改动的明文 office 文件（.docx/.xlsx/.pptx）→ 防抖（文件稳定 N 秒无写入）后触发加密；**排除 `.cbx`、`.cbx.tmp`、受保护目录下的 `.cipherbox-tmp`、`.cipherbox-profile`、`.cipherbox-quarantine` 子目录、LO 锁文件 `.~lock.*#` 及 encryptor 输出路径**；**候选文件存在同伴锁文件 `.~lock.<名>#` 时跳过并延迟重试（避免加密 LO 正在编辑的文件）；重试超阈值（如 2 小时）时用 **Restart Manager（RmStartSession/RmGetList）查询该文件是否被任何进程持有句柄**判定陈旧（LO 锁文件不含 PID，无法直接判活）——**但需先实测（此实测项并入 todo 3 spike）：活动 LO 会话对锁文件/文档通常不持有可枚举句柄，故"RM 返回 0 进程"一律归入"无法判定"分支（不删锁、仅告警重试），除非实测证明活动会话有可枚举句柄**（堵 RM 假阳性误删活动锁、加密编辑中文件）；判陈旧才清除后继续加密并产出审计/告警事件（堵崩溃遗留陈旧锁致明文静默滞留）；**连续"无法判定"超阈值（如 24 小时）→ 发一次性 `lock_stuck` 告警事件并隔离明文文件（移入隔离区，隔离区在排除规则内防自触发），停止无限告警重试****（排除规则相对受保护目录解析，不硬编码盘符）；**Agent 启动时对受保护目录做一次存量扫描**，对存量明文 office 文件走同一 ZIP-magic 预检/锁文件跳过/加密管线（堵停机/首装期间落入的明文）。
  - QA happy: 复制一个明文 .docx 进目录 → N 秒后触发加密（日志可见）；**预置明文文件在 Agent 启动后（存量扫描）被加密**。
  - QA failure: 快速连续写文件 → 只触发一次（防抖）；非 office 文件（.txt）不触发；`.cbx.tmp` 落盘不触发；**受保护目录下 `.cipherbox-tmp\` 或 `.cipherbox-profile\` 内的明文不触发**；**存在 `.~lock.*#` 同伴锁的明文不触发加密（待锁消失后再加密）**。
  - Commit: `agent/watcher.py` + `agent/tests/test_watcher.py`（用临时目录 + fake 回调）。

- [ ] 13. 明文文件加密：ZIP magic 预检 → UNO 重加密 → `.cbx.tmp` 原子改名 → `.cbx` + 审计上报
  - References: Wave 0 todo 2 的 spike（`spike_reencrypt.py`）；`test_documents.py` 的 `EncryptionData` 触发。
  - Acceptance: 对监控到的文件：**先做 OOXML ZIP magic（`PK\x03\x04`）预检，非明文（如已是 CFB 密文容器、或伪装成 office 扩展名的非 ZIP 文件）跳过并 `POST /events`（action=encrypt_skip, ok=false）审计告警**；明文文件（docx/xlsx/pptx）→ UNO `loadComponentFromURL`（**带 `UpdateDocMode=NO_UPDATE` 属性，禁外部链接/DDE/OLE 自动更新——堵投递含 `\\host\share` 链接文档触发 SMB/HTTP 外联**）→`storeToURL`（带 `EncryptionData{CryptoType, Password:当前主密钥}`）→ **密文先写 `<原全名>.cbx.tmp` 再原子改名为 `<原全名>.cbx`**（保留原扩展名，如 `a.docx.cbx`；防 watchdog 自触发；**此 superseded 拒绝分支仅适用于 watcher 驱动的无跟踪明文加密——todo 14 会话收尾与 todo 26 崩溃恢复对自身 session 记录指向的 `cbx_path` 重加密时绕过此分支（其自身 mtime 守卫：todo 14 收尾见 todo 14、todo 26 崩溃恢复见 todo 26）**；**改名前若目标 `.cbx` 已存在 且（源明文路径在清单 `source_path` 中 或 目标 `.cbx` 在清单 `cbx_path` 中）→ 不覆盖，隔离明文（不删除）并审计 `encrypt_superseded`；否则仅当源明文 mtime 新于目标 `.cbx` mtime 才覆盖（堵跨谱系 SaveAs 后陈旧明文覆盖新 `.cbx` 的数据丢失；时钟回拨时相等视为可覆盖）；**mtime 不新于目标（不满足覆盖条件）时：不覆盖、隔离明文并审计 `encrypt_stale`（不原样保留、不删除）**；路径比对前统一 `GetFullPathName` + 大小写折叠规范化（堵 Windows 大小写/8.3 短名/尾斜杠绕过）**）→ 删除明文 → `POST /events`（action=encrypt, file_hash=明文 sha256, key_version=当前版本）。
  - QA happy: docx/xlsx/pptx 各一 → 落盘只剩 `.cbx` 密文 + 审计事件落库（含 key_version）；**一个 CFB 密文容器（非 ZIP）落盘 → 被跳过不触发加密**。
  - QA failure: UNO 加密失败（如文件被独占）→ 明文保留 + 重试（**最多 5 次、指数退避**）+ 事件 action=encrypt, ok=false；**超限则隔离文件并告警一次（不再无限重试刷审计）**；不静默删明文。
  - Commit: `agent/encryptor.py` + `agent/tests/test_encryptor.py`（需要 soffice）。

- [ ] 14. 受控打开闭环：`.cbx` 解密 → 独立 GUI LO 打开（专用 profile + Job Object + 文档级关闭检测，串行化）→ 重加密
  - References: Wave 0 todo 3 spike；`agent/container.py`（todo 10）；`cipherbox.py` `decrypt` 返回 XSeekable 流。
  - Acceptance: 双击 `.cbx`（或启动器参数）→ **Agent 用 todo 10 的 `container.py` 自行解密 `.cbx` 到临时明文**（剥尾部 `.cbx` 还原原始扩展名，落 `S:\.cipherbox-tmp\<会话UUID>\`，如 `a.docx.cbx` → `a.docx`；不经过 LO 引擎 decrypt，规避 `_seekable_output_stream` 的卷外 TempFile 泄漏）→ **解密成功后先持久化 session 记录 `{会话UUID: {cbx_path, tmp_path, orig_sha256, key_version, ts}}`（`ts`=记录写入时间戳，供 todo 26 崩溃恢复守卫比对）到 `%APPDATA%\CipherBox\sessions\<uuid>.json`（**DPAPI 加密落盘——含文件名/内容哈希元数据，防泄卷外**；会话正常关闭后删除，供 todo 26 崩溃恢复用），再 `POST /events`（action=decrypt, file_hash=原始明文 sha256, key_version=实际解密版本）**（先落记录再落事件，堵"事件已记、记录未落"的孤儿窗口；也堵会话中途崩溃→解密无痕）→ 启动**独立 GUI soffice 进程**（设 `TMP=TEMP=S:\.cipherbox-tmp\<会话>\` 环境变量；`-env:UserInstallation=<受控专用profile, 落 S:\.cipherbox-profile\controlled\> --accept="pipe,name=cipherbox-controlled-<会话>;urp;" --norestore`），**并加入 Windows Job Object（KILL_ON_JOB_CLOSE）绑定到 Agent 生命周期** → **Agent 接管管道、枚举全部 frame 注册拦截器（todo 17），收到注册确认后才 `loadComponentFromURL` 临时明文**（硬顺序"先注册、后加载"，注册失败则不打开文档、删临时明文、清 session 记录、**立即 Job 强杀本次启动的受控 GUI 进程**、报错退出——堵会话开启的 fail-open 窗口，也防孤儿受控实例占用同 profile 致后续单实例转交、注册永远失败）→ **持有打开文档时返回的 XModel 对象引用，以其 dispose/close 事件为结束信号（URL 会在 SaveAs 强制改写 `.cbx` 时改变，不能按 URL 字符串跟踪；也不按 desktop `Components` 计数——避免再开文档卡死检测）判定编辑结束** → Agent 主动终止受控进程 → 用临时明文内容 sha256 对比原明文判定是否有改动 → 有改动则**复用 todo 13 的 UNO encryptor 用当前主密钥重加密**回 `.cbx`（**绕开 todo 13 的 superseded 拒绝分支——这是对自身 session 记录 `cbx_path` 的重加密**；**重加密前先比 mtime：若目标 `.cbx` 的 mtime 新于 temp 文件 mtime，视为拦截器已直写更新版（会话内 SaveAs 到 `.cbx` 后 `.uno:Save` 直写 `.cbx`、temp 停留旧态）→ 跳过重加密、删 temp、保留 `.cbx` 并记日志/审计，仅 temp 较新才重加密**）并 `POST /events`（action=encrypt, key_version=当前版本）→ 删除临时明文（**删除临时明文时，同步清除 superseded.json 中 `source_path` 指向该会话 temp 的条目——受控会话内 SaveAs 产生的条目由会话收尾负责清，防条目永久残留致后续同名明文被误杀**）。**进程退出（含崩溃）与心跳超时 Job 强杀均走同一收尾：Agent 经进程句柄/Job 通知即时检测受控进程退出，立即执行上述"hash 对比→有改动重加密→删 temp→删 session 记录→释放串行槽"（不留孤儿到下次启动）**。**受控打开必须串行化：Agent 用全局命名互斥体保证单实例，启动器作为瘦客户端经命名管道把打开请求转发给常驻 Agent 排队（进程内锁无效——每次双击都新起进程；管道连接失败时启动器尝试启动 Agent 并重试一次，仍失败则明确报错退出，绝不在本地自行解密）；同一时刻只允许一个受控会话（规避同 profile 单实例转交），后续打开排队并提示"等待上一个文档关闭"。**
  - QA happy: 打开→编辑→保存→**关文档窗口（Start Center 仍开）**→ Agent 文档级检测触发重加密 → 落盘密文含新内容，临时明文已删；重加密使用当前 key_version 且有 encrypt 审计事件；同时双击两个 `.cbx` → 第二个排队而非并发打开；**Agent 进程被 kill → 受控 soffice 被 Job Object 连带终止**。
  - QA failure: 打开后不改直接关 → 不重加密（保持原密文）；**LO 崩溃 → Agent 经进程句柄/Job 通知即时检测退出，立即执行与正常 doc-close 相同收尾（temp hash 对比 orig_sha256→有改动则以当前主密钥重加密并上报 encrypt 事件→删 temp→删 session 记录→释放串行槽，不留孤儿到下次启动）**；**会话中途 kill Agent → decrypt 事件已落库/已入本地队列（解密有痕）**；**注入注册失败 → 文档绝不打开、临时明文已清、无受控 soffice 残留，且下一次受控打开可正常执行（fail-open 窗口关闭、无孤儿楔死）**。
  - Commit: `agent/opener.py` + `agent/tests/test_opener.py`。

- [ ] 15. Agent 审计上报封装 + 机器标识
  - References: 服务器 `/events` 契约（todo 7）；机器标识用 `socket.gethostname()` 或 Windows `GetComputerNameEx`。
  - Acceptance: 统一的 `report(action, file_hash, key_version, ok)` 封装，含员工令牌、机器名、时间戳；**employee 由服务端从 token 解析（客户端不伪造）**；失败时本地暂存队列、联网后重放——**队列落 `%APPDATA%\CipherBox\audit-queue.json`（DPAPI 加密，含文件名/哈希元数据不得卷外明文）**；**设容量上限（如 10000 条），满时丢弃最旧条目，恢复联网后补报一条 `ok=false` 的元事件（记录"离线期溢出丢弃 N 条"）**。
  - QA happy: 上报成功落库字段一致。
  - QA failure: 服务器不可达 → 事件进本地队列不丢，恢复后重放成功。
  - Commit: `agent/audit.py` + `agent/tests/test_audit.py`。

- [ ] 16. Agent 单测/集成测试
  - References: 10–15 的测试文件。
  - Acceptance: `pytest agent/tests/` 全绿（纯逻辑部分不依赖 soffice；依赖 soffice 的部分标记/跳过或走集成）。
  - QA happy: `pytest -q` 退出码 0。
  - QA failure: 改坏防抖逻辑 → 对应测试红。
  - Commit: 测试补漏后提交。

### Wave 3 — LibreOffice"强制加密保存"拦截器（A 补强）

- [ ] 17. LO 强制加密保存拦截器 + LO 驻留 + 全 frame 注册 + 密钥直传 + 判定范围 + 目标格式分流
  - References: `lo-encryption-demo/src/cipherbox.py`；LO 拦截器用 `com.sun.star.frame.XDispatchProviderInterceptor` 拦截 `.uno:Save`/`.uno:SaveAs`/`.uno:SaveACopy`/`.uno:SaveAll`/`.uno:ExportTo`/`.uno:SendMail` 等（todo 4 spike 已验证可行性）。
  - Acceptance: ① **驻留、密钥生命周期与上报通道**：拦截器实现**驻留 LO 进程内**（受控 profile 加载，不依赖 Agent 连接存活）；受控 GUI soffice 以 `-env:UserInstallation=<受控专用profile> --accept="pipe,name=cipherbox-controlled-<会话>;urp;"` 启动；Agent 经 UNO 连接，**枚举 Desktop 全部现有 frame 逐一注册拦截器，且监听新 frame 出现并补注册（机制以 todo 4 spike 结论为准：轮询 `Desktop.Components` 差集 或 GlobalEventBroadcaster `OnNewView`，勿用不存在的 `FRAME_CREATED` 枚举）**（堵新窗口逃逸）。**密钥生命周期**：拦截器**不持久持钥**，每次强制加密保存时经 UNO 向 Agent 取当前主密钥（**Agent 应答取钥请求时适用 todo 11 同一规则——在线先刷新版本集再返回 current，离线用缓存，key_version 滞后已声明**），取不到即 fail-closed 拒存（这样"Agent 被杀→拒存"才成立）。**上报通道**：export_plaintext 审计经 UNO 回调 Agent，由 Agent 持令牌上报+暂存队列；Agent 不可达时拦截器把事件落 **`S:\.cipherbox-tmp\audit-queue\`（独立子目录，豁免 todo 14 会话收尾删除与 todo 26 陈旧会话目录清扫）**，Agent 启动时及恢复在线时重放（堵"Agent 死后审计丢失"）；**该队列明文 jsonl 落卷内可接受（卷内已声明边界），容量不设上限（心跳 15 秒超时即终止会话，窗口内有界），Agent 启动时逐行重放后删除**；**拦截器每次强制加密保存（OOXML→`.cbx`）同时向 Agent 上报 `{target_path, 明文sha256, key_version, 源明文路径}`，Agent 记 `action=encrypt` 审计事件并把源明文标记为 superseded，且以追加式 JSON（DPAPI）持久化到 `%APPDATA%\CipherBox\superseded.json`（条目 `{source_path, cbx_path, sha256, key_version, ts}`，**条目在其 `source_path` 被任一路径删除/隔离时即清除——含 todo 14 会话收尾删 temp；若上报时 `source_path` 从未落盘（拦截器直写 `.cbx` 无中间明文），条目仍登记，于首次命中（watcher 隔离该同名明文）或对应 `cbx_path` 被删除时清除（新建文档无 URL 时 `source_path` 取 `cbx_path` 剥尾部 `.cbx` 的路径）**——Agent 重启后清单仍生效，堵 watcher 以旧明文覆盖新 `.cbx` 的数据丢失 + 补上拦截器强制加密的审计缺口）**。**该 encrypt/superseded 上报回调失败（Agent 取钥后、上报前被杀/连接重置）时，拦截器以独立行类型落同一 `audit-queue\` 队列，Agent 重放时补记 `action=encrypt` 审计并补登 superseded（堵盘上已有新 `.cbx` 却无审计、无清单保护）**。**心跳确认**：拦截器注册成功后向 Agent 发注册确认，之后每 5 秒经 UNO 回调心跳（**由拦截器内独立 Python 线程发出，不经 LO UI 线程——避免模态对话框/长操作造成假超时**）；Agent 连续 3 次未收到 → 先尝试 `XCloseable.close(false)` 优雅关文档（保住最后已保存状态），失败再 Job 强杀终止受控会话（决策写死，不留"可选"）。密钥不用环境变量（规避同会话宏/PEB 读取）。② **判定范围**：**拦截器仅在受控 profile 激活——服务专用 profile 与默认 profile 一律不加载拦截器**（`force_encrypt.py` 仅部署/激活于受控 profile，见 todo 21 ①；否则服务 profile 的加密管线会把 todo 13 的 `.cbx.tmp` 输出改写并重复注入 EncryptionData，默认 profile 的员工正常 OOXML 保存会被全部强制 `.cbx`+审计，违背 TL;DR 风险⑥已声明边界）；**受控 profile 内全部文档适用③，无范围豁免**（受控 profile 专用于受控会话、会话结束即被杀，无误伤面——堵"受控会话内 File>Open 打开 S:\ 明文窗口期文件后 SaveAs-OOXML 到卷外逃逸且无审计"）。③ **目标格式分流（按目标过滤器判定，不按 dispatch 名族）**：拦截**所有写盘 dispatch（`.uno:Save`/`.uno:SaveAs`/`.uno:SaveACopy`/`.uno:SaveAll`/`.uno:ExportTo`/`.uno:ExportToPDF`/`.uno:ExportDirectToPDF`/`.uno:Print`/`.uno:PrintDefault`）**——temp 目录文档的保存类 dispatch（`.uno:Save` 及 `.uno:SaveAll` 中指向 temp 文档者）一律放行写回临时明文（卷内已声明风险；SaveAll 须逐文档判定目标，堵"temp 文档被 SaveAll 强制改 `.cbx` 致会话编辑丢失"；**优先级：目标 URL 已为 `.cbx` 的 `.uno:Save` 一律强制加密，优先于本 temp 放行例外——堵 temp 内 SaveAs 产出 `.cbx` 后 Save 明文覆盖之**）；**任何写盘 dispatch 目标位于会话 temp 目录 `S:\.cipherbox-tmp\<uuid>\` 内 → 拒绝并提示改选位置（fail-closed；唯一例外=指向 temp 文档自身的 `.uno:Save`/`.uno:SaveAll` 放行；Print 族维持"若 spike 证可拦截"条件前缀）——堵 LO SaveAs/Export 对话框默认目录=temp 致用户另存/导出副本落 scratch 目录、收尾清理时蒸发（副本生命周期无定义）**；**任何写盘 dispatch 的目标过滤器为 OOXML → 强制加密且目标扩展名改写为 `.cbx`**（含 SaveAs 后文档 URL 已变 `.cbx` 时，后续 `.uno:Save` 仍强制加密，堵"明文覆盖 .cbx"；堵 `ExportTo` 选 OOXML 过滤器的落空）；**任何写盘 dispatch 的目标过滤器为非 OOXML（odt/pdf/txt 等）、以及 `.uno:SendMail` 等发送族（若 spike 证可拦截）→ 放行 + 强制 `export_plaintext` 审计**（本期仅记录）；**不可拦截的发送/导出/打印 dispatch 写入安全边界声明并同步修订 TL;DR 承诺④与成功标准 4**。
  - QA happy: 另存为到桌面（OOXML）→ 桌面产物为 `.cbx` 密文（OLE_MAGIC 校验），用主密钥可解；生成日志**不含** `using empty-password key` **且不含** `using fixed demo key`；另存为 .odt/.pdf → 明文 + 审计落库 export_plaintext；**开第二窗口后 SaveAs 仍被强制加密**；**Agent 被杀后，缺密钥状态拒绝 OOXML 保存（fail-closed）**；**服务 profile 加密管线（todo 13）产出的 `.cbx.tmp` 不被拦截器改写——服务 profile 不加载拦截器**。
  - QA failure: 拦截器未拿到密钥 → 明确报错拒绝保存，不静默空口令加密。**（受控 profile 内无"普通新建文档"豁免——任何文档 OOXML 保存都强制 `.cbx`，非 OOXML 导出都审计）**
  - Commit: `lo-encryption-demo/src/force_encrypt.py`（或扩展）+ 对应测试。

- [ ] 18. 明文导出/外发 → 强制审计记录（明确触发操作）
  - References: 服务器 `/events`（action=export_plaintext）。
  - Acceptance: 明文导出触发操作**明确为**：`.uno:ExportTo`/`.uno:ExportToPDF`/`.uno:ExportDirectToPDF`（PDF 导出）、"另存为/导出为非 OOXML 格式"（odt/pdf/txt 等）、**`.uno:Print`/`.uno:PrintDefault` 打印到文件/Print-to-PDF（若 todo 4 实测可拦截）**、以及可拦截的 `.uno:SendMail` 等发送族（若 todo 4 实测可拦截）→ 强制 `POST /events`（action=export_plaintext, ok=true），记录"谁、哪个文件、何时、key_version"；**file_hash = 导出时刻经 UNO 取当前文档内容的 sha256（与 temp 明文 hash 可能因未保存编辑而不同，供与 encrypt/decrypt 事件关联查询时据此甄别）**；本期仅记录不审批。
  - QA happy: 执行一次 `.uno:ExportTo` PDF 导出 → 审计落库含 export_plaintext。
  - QA failure: 上报失败 → 本地队列暂存（复用 todo 15），不阻断放行但留痕。
  - Commit: 拦截器内联审计调用 + 测试。

- [ ] 19. 拦截器测试
  - References: 17–18。
  - Acceptance: `pytest` 覆盖"另存为 OOXML 被强制加密且改 .cbx"、"SaveACopy/另存副本被强制加密"、"SaveAs 后 .cbx 文档的 .uno:Save 仍强制加密（不明文覆盖）"、"非 OOXML 导出被审计（export_plaintext）"、"**受控 profile 内新建/非 temp 文档 OOXML 保存同样强制 .cbx（无豁免）**"、"第二 frame SaveAs 仍被拦截"、"缺密钥 fail-closed 拒存"、"**拦截器强制保存后 watcher 不覆盖新 .cbx（superseded 防碰撞）**"、"**SaveAll 对 temp 文档放行写回临时明文（不被强制改 .cbx）**"、"**SaveAs-to-`.cbx` 后再 `.uno:Save`，会话收尾不得以陈旧 temp 回退 `.cbx` 内容（temp 停留旧态时跳过重加密）**"、"**ExportToPDF/ExportDirectToPDF 目标落会话 temp 被拒（fail-closed，不落 scratch 蒸发）**"十一条路径。
  - QA happy: 断言另存为产物是 .cbx 密文、非 OOXML 导出审计落库、**受控 profile 内新建文档 OOXML 保存也强制 .cbx（无明文豁免）**、第二 frame 拦截生效、缺密钥拒存。
  - QA failure: 受控会话建立后 Agent 与拦截器做注册/心跳确认，确认失败 → Agent 告警并终止受控会话（与 todo 17 一致，不可选）；拦截器缺密钥 → 拒绝保存（不静默明文）。
  - Commit: 拦截器测试补漏提交。

### Wave 4 — 部署与物理隔离

- [ ] 20. 服务器部署引导（装服务器 + HMAC 密钥 + 种子令牌 + CA/证书下发）
  - References: `server/app.py`（todo 5-9）；自签 CA 用 OpenSSL。
  - Acceptance: 一个脚本在局域网服务器主机完成：① 安装 server 依赖 + 启动 uvicorn（HTTPS，监听 8443）；② **生成 HMAC 审计密钥**（存配置文件，**ACL=运行账户+管理员可读**，不入 DB/日志/仓库）；③ **生成自签 CA/服务器证书 + 导出一份供客户端 pin 的 CA 文件**（**CA/服务器私钥文件与 HMAC 密钥同等 ACL 保护（运行账户+管理员可读），不入 DB/日志/仓库**）；④ **种子 admin 令牌与首个员工令牌入库**（用 `secrets.token_urlsafe(32)` 生成、哈希存储，**并写入对应的 employee 标识列**，打印一次性明文令牌供分发）；⑤ 注册开机自启；**⑥ 明确服务器运行账户为专用服务账户（如专用本地账户）——todo 6 的 DPAPI 包裹必须以该运行账户上下文执行（否则自启后解不开主密钥），HMAC/CA 私钥 ACL 同步授予该运行账户**。
  - QA happy: 脚本跑完 → `/health` 200（HTTPS）；admin 令牌可调 `/admin/rotate`、`/admin/revoke`；首个员工令牌可调 `/key`；HMAC 密钥文件存在且仅管理员可读；导出的 CA 文件可被客户端 `requests(verify=)` 使用。
  - QA failure: 缺 OpenSSL/Python → 报错给指引；种子令牌泄露（明文打印后）→ 提示立即轮换。
  - Commit: `deploy/server_bootstrap.ps1` + 说明。

- [ ] 21. 客户端安装/部署脚本（LibreOffice 扩展 + Agent + 配置 + 多 profile 落卷内 + 宏安全 + 关 AutoRecovery + CA pin）
  - References: `lo-encryption-demo/build.ps1`（Java 扩展打包模式可参考）；`test_password_verify.py` 的 DEPLOYED 路径 `%APPDATA%/LibreOffice/4/user/Scripts/python/cipherbox.py`。
  - Acceptance: 一个 PowerShell 脚本完成：① 部署 `cipherbox.py`、`cipherbox_crypto.py`（引擎）到 LO 用户 Scripts（**默认 profile + 服务专用 profile + 受控专用 profile 三处**）；`force_encrypt.py`（拦截器）**仅部署并激活于受控专用 profile**（服务/默认 profile 不加载拦截器，见 todo 17 ②，堵服务加密管线 `.cbx.tmp` 被改写、员工正常保存被误强制 `.cbx`）；② 安装 Agent 到程序目录；③ 写入配置（服务器地址、员工令牌、**CA pin 证书指纹/文件**、受保护目录 `S:\`、临时目录 `S:\.cipherbox-tmp\`；**员工令牌同密钥缓存一样用 DPAPI 加密落盘**）；④ 注册开机启动（**顺序：挂卷→起服务→起 Agent**；服务/Agent 启动包装**轮询等待 S: 就绪**，未挂载期间禁用加密管线并明示，不静默失败）；⑤ **受控专用 profile 与服务专用 profile 均设宏安全最高级（禁用宏）**（服务 profile 自动摄取监控目录内不可信文件，不应依赖 LO 默认 High），**并禁用 DDE 与外部链接自动更新**（同类外联面，投递含外链文档不应自动触发 SMB/HTTP 外联）；⑥ **服务/受控专用 profile 均落 `S:\.cipherbox-profile\{service,controlled}\`（卷内），服务与受控 profile 均关闭 AutoRecovery 与"总是创建备份副本"**（**服务 profile 是 todo 13 加密管线 loadComponentFromURL 明文的进程，崩溃时 AutoRecovery 会把明文快照泄卷内 backup 目录，必须关**）；**默认 profile 同样关闭 AutoRecovery 与"总是创建备份副本"**（员工正常 LO 打开 S:\ 明文窗口期文件时，防明文快照泄卷外 `%APPDATA%\...\backup`），堵明文备份泄卷外。
  - QA happy: 干净环境跑脚本 → 组件被 LO 识别（`check_service.py` 通过）+ Agent 能取密钥（走 HTTPS 且 CA 校验通过）；受控 profile 宏安全最高级、DDE 与外部链接自动更新禁用、AutoRecovery 关闭；服务专用 profile 的常驻服务与员工正常 LO 实例并存；profile 目录落在 `S:` 卷内。
  - QA failure: 缺 LibreOffice → 脚本报错并给出安装指引，不半途崩溃。
  - Commit: `deploy/install.ps1` + 配置样例。

- [ ] 22. `.cbx` 文件关联注册
  - References: Wave 0 todo 3 spike；Windows 注册表 `HKEY_CLASSES_ROOT\.cbx` → `CipherBox.Document` → shell open 命令指向 Agent 启动器。
  - Acceptance: 脚本写一次关联；双击 `.cbx` 触发 Agent 受控打开（todo 14）。
  - QA happy: 双击 `.cbx` → LO 打开明文、关闭后重加密。
  - QA failure: 未关联时双击 → 系统提示选择程序（不静默失败）。
  - Commit: 关联注册脚本（并入 install.ps1 或独立）。

- [ ] 23. VeraCrypt 卷引导（原版，零二次开发）
  - References: 原版 VeraCrypt CLI（`VeraCrypt.exe /q /v <卷文件> /l S /p <卷口令> /s`，卷口令避免明文上命令行：仅交互输入（"用后清理"不可靠，进程列表/WMI 已留痕））；决策：VeraCrypt=物理隔离层。
  - Acceptance: 部署脚本引导管理员创建 VeraCrypt 卷文件并挂载到 `S:`；Agent 的受保护目录默认 `S:\`、**明文临时副本默认 `S:\.cipherbox-tmp\`、profile 落 `S:\.cipherbox-profile\`**；密钥缓存在卷外 `%APPDATA%\CipherBox`（与 todo 11 一致）。
  - QA happy: 挂载 `S:` → Agent 监控 `S:\` 正常加密；卸载 `S:` → 卷文件为密文 blob（无明文 office magic 扫描），盘符消失。
  - QA failure: 卷口令错误 → 挂载失败并明确报错，Agent 不误写错误盘符。
  - Commit: `deploy/veracrypt_bootstrap.ps1` + 说明。

- [ ] 24. 部署验证
  - References: 20–23。
  - Acceptance: 一条验收脚本串起"服务器引导→客户端安装→关联→挂卷→取密钥→加密→受控打开→审计落库"。
  - QA happy: 全新 Windows 虚拟机跑通全流程（含服务器与客户端两台）。
  - QA failure: 任一步失败有清晰错误码与回滚说明。
  - Commit: `deploy/verify.ps1`。

### Wave 5 — 端到端 + 安全加固

- [ ] 25. E2E 端到端测试（OOXML 三格式）
  - References: `lo-encryption-demo/test/test_documents.py`（驱动方式）、`test_e2e.py`。
  - Acceptance: 一条 E2E 脚本覆盖：docx/xlsx/pptx"保存→加密→受控打开→编辑→重加密" + "从磁盘拿密文发邮件/微信/U盘场景=拿到密文" + "非 LO 打开=打不开" + "另存为明文(OOXML)被加密为 .cbx/非 OOXML 导出与发送被审计" + "审计落库可查（含 key_version）" + "**受控流程不经过引擎 decrypt（扫描 %TEMP% 无明文残留）**"。
  - QA happy: 全链路断言全过，输出 `RESULT: PASS`。
  - QA failure: 任一环节失败 → 打印环节名 + 日志位置，退出码非 0。
  - Commit: `test/e2e_full.py`。

- [ ] 26. 明文临时文件安全清理（覆盖卷外 TempFile 泄漏 + profile backup 目录 + 孤儿 GUI）
  - References: `lo-encryption-demo/src/cipherbox.py` 的 `_seekable_output_stream`（当前 `RemoveFile=False`，明文 TempFile 可能残留在 %TEMP%——需评估并处置）。
  - Acceptance: 受控打开/关闭后 `S:\.cipherbox-tmp\` 无明文残留；**Agent 重启时（在任何受控打开请求受理之前、且 watcher 启动（含存量扫描与防抖事件处理）之前同步完成恢复——先重放 `S:\.cipherbox-tmp\audit-queue\`（补记 `action=encrypt` 审计+补登 superseded）再执行孤儿恢复，确保崩溃会话的 superseded 条目已入清单后孤儿恢复与 watcher 判 `encrypt_superseded` 才查清单，堵恢复误判/扫描误覆盖）遍历 `%APPDATA%\CipherBox\sessions\*.json`，对孤儿临时明文先校验完整性（`PK\x03\x04` magic + 可解析），再查 Agent superseded 清单（源明文已被拦截器强制保存的更新 `.cbx` 取代 → 隔离临时明文+审计告警，不覆盖），且仅在临时明文 sha256 ≠ session `orig_sha256` 时才按其 session 记录 `cbx_path` 重加密回 `.cbx`（**密钥用当前主密钥、经 todo 11 在线刷新规则，审计 key_version=当前版本**；有改动才重加密）；**重加密前若目标 `.cbx` 的 mtime 新于 session 记录 `ts` → 隔离孤儿 temp+审计告警，禁止覆盖（堵"S1 崩溃后 S2 已更新 `.cbx`，恢复却用 S1 孤儿明文覆盖"的静默数据丢失）**；随后清理；损坏则保留原 `.cbx`、隔离临时文件并审计告警，先杀孤儿受控 GUI；同时扫描 `S:\.cipherbox-tmp\` 下无对应 session 记录的会话目录（**会话目录=UUID 命名目录；`service` 与 `audit-queue` 子目录豁免此清扫**），按陈旧时间隔离/清理并审计告警（堵"解密后、记录落盘前崩溃"的孤儿）**；**受控流程用 todo 10 的 `container.py` 自行解密（不经过引擎 decrypt），因此引擎的 %TEMP% TempFile 不产生**；**受控 GUI 启动时无条件设 `TMP=TEMP=S:\.cipherbox-tmp\<会话>\`**（即使不经引擎 decrypt 也消除卷外明文残留），`%TEMP%` 扫描保留为回归断言；**扫描范围含受控与服务 profile 的 backup/AutoRecovery 目录（断言无明文 office 文件）**。
  - QA happy: 打开→关闭后扫描 `S:\.cipherbox-tmp\`、`%TEMP%`、受控与服务 profile backup 目录均无明文 office 文件。
  - QA failure: 崩溃场景 → 重启 Agent 先对孤儿临时明文重加密回 `.cbx`（有改动时）再清理（含杀孤儿 GUI）并记录；**Agent 重启后 superseded 清单仍生效（watcher 不覆盖新 `.cbx`、恢复不误判）**。
  - Commit: 清理逻辑 + 测试。

- [ ] 27. 审计完整性（HMAC 哈希链 + 链头锚点，防篡改+防尾部删除）
  - References: 服务器 `/events`；`cipherbox.py` 已有 `hmac` 依赖。
  - Acceptance: 每条审计事件附行级 HMAC（密钥=服务器密钥，不出库，`SHA-256`）**+ 前一行哈希链（`prev_hash` = 前一行事件的 `mac`，首行填 `HMAC(key,"genesis")`）+ 单调 `id`**；服务器只追加不覆盖（无 UPDATE/DELETE 暴露）；**在 events 表外维护链头锚点 `meta(chain_head, chain_count)`**（每追加一行更新为运行式密钥链 `chain_head_n = HMAC(key, chain_head_{n-1} || mac_n)`，初值 `HMAC(key, "genesis")`——**不可从表内数据重放**，锚点与事件分离存储，同一事务更新）；提供校验命令 `python -m server.verify_audit`（校验每行 HMAC + 哈希链连续 + id 无缺口 + **重放运行链比对 chain_head 且行数==chain_count**）。**HMAC 密钥由 todo 20 部署时生成、存于仅管理员可读的配置文件，不入 DB/日志/仓库。**（整库文件级回滚的检测超出本期，已在 Scope Out 声明。）
  - QA happy: 运行 `python -m server.verify_audit` → 全部通过；`sqlite3` 篡改一条 → 非零退出并定位到行；`sqlite3` 删除末尾 N 行 → 校验命令检出；**`sqlite3` 删除末尾 N 行并把新末行的 mac 抄入 meta.chain_head、chain_count 改为剩余行数 → 校验命令仍必须检出（运行链无法从表内数据重放）**。
  - QA failure: 审计写入失败 → 客户端本地队列兜底不丢。
  - Commit: 审计完整性增强 + `server/verify_audit.py` + 测试。

## Final verification wave

- [ ] F1. 计划符合性审计：逐条核对 27 个 todo 是否都完成、验收是否满足、是否有超出 Scope 的擅自新增。
- [ ] F2. 代码质量审查：`cipherbox.py` 抽离后复用不破坏现有测试；新代码类型/风格/日志规范（参考 `programming` 约定）；无明文口令/密钥落日志。
- [ ] F3. 可脚本化验收：编写并运行 `deploy/verify.ps1` + 一个故障注入脚本（停服务器进程断言离线可用；kill LO 进程断言崩溃清理+审计重放；kill Agent 断言孤儿 GUI 被 Job Object 终止；篡改/删除审计行断言 HMAC 链 + 链头锚点检出），全断言通过。
- [ ] F4. Scope 保真度：确认未实现 Out-of-scope 项（内核驱动/主动提示/审批流/doc-xls-ppt 主密钥加密/存量全量 re-key 扫描/整库回滚检测），且未遗漏 In-scope 项。

## Commit strategy

- 项目当前**非 git 仓库**（`Is directory a git repo: no`）。执行前先 `git init`（推荐，便于 atomic commit 与回滚）；若用户不同意，则退化为"每完成一个 wave 做一次目录快照/检查点"。
- 提交粒度：一个 todo（实现+测试）一个提交，提交信息形如 `feat(server): key issue/rotate endpoints`。
- 每提交前跑相关测试，`pytest` 绿才提交；Spike 结论与回退切换点单独提交并写明。
- 密钥/令牌/卷口令/自签 CA 私钥/HMAC 密钥**绝不入库**，用 `.gitignore` + 样例配置（`config.example`）替代真实配置。

## Success criteria

1. 员工在 `S:` 保密盘用 LibreOffice 无感打开/保存 docx/xlsx/pptx，全程不输入口令。
2. `.cbx` 文件静态落盘始终为密文；从磁盘拿 `.cbx` 发邮件/微信/拷 U 盘 → 对方拿到的是密文/打不开（会话期明文临时副本为已声明残余风险，不在本承诺内）。
3. 非 LibreOffice 直接打开密文 → 打不开（被动防）。
4. "另存为明文(OOXML)" 被强制加密为 `.cbx`、"非 OOXML 导出/发送"被强制审计记录（仅记录，不审批），审计在服务器可查、可追溯、防篡改+防尾部删除（HMAC 链 + 链头锚点校验）；employee 由 token 解析不可伪造。
5. 主密钥由服务器统一签发/轮换（≥256bit 高熵，返回全量版本集），客户端 DPAPI 缓存（含历史密钥集，逐版本试探），断网可开已缓存文件；令牌带 TTL/续期/吊销；轮换 forward-only 语义已声明。
6. docx/xlsx/pptx（OOXML 三格式）全链路测试通过；`pytest`（服务器+Agent+拦截器）与 E2E 全绿。
7. 部署脚本可在干净 Windows 一键安装并验证（含服务器引导）；VeraCrypt 卷引导可用；**受控与服务专用 profile 宏安全最高级、AutoRecovery 关闭**、profile 落卷内、服务器走 HTTPS、常驻服务用专用 profile 与员工正常 LO 并存。
8. 明确不越界：未实现内核驱动/主动提示/审批流/doc-xls-ppt 主密钥加密/存量全量 re-key 扫描/整库回滚检测等 Out-of-scope 项。
