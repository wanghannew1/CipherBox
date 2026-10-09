# cipherbox-transparent-encryption — Planning Draft (resume point)

- intent: clear
- review_required: true
- classification: architecture
- status: review-in-progress
- slug: cipherbox-transparent-encryption

## Request
无感加密 Word/Excel 等办公文件，用于小公司商业信息保密。
之前策略：LibreOffice 加密模块加解密 + 中心服务器记录加解密 + 统一密钥管理。
要求：最简单的实现方式；先评估现有项目进展。
核心目标（补充）：防止明文外发——发邮件/微信/拷U盘时，拿到/发出去的是密文（对方打不开）。

## Existing state (lo-encryption-demo)
- 已跑通：LibreOffice 自定义加密引擎 CipherBoxDataSpace（XPackageEncryption），
  Python(PyUNO) + Java 两版；MS-OFFCRYPTO DataSpaces 容器字节级对齐；AES-256-CBC +
  PBKDF2；口令校验器 trailer；6 格式(docx/xlsx/pptx/doc/xls/ppt)真实文档回环测试。
- 未做：中心服务器 / 加解密审计 / 统一密钥管理 / "无感"（当前需显式传口令）/ 部署安装器。

## Topology (components ledger)
- C1 客户端无感加密层：员工机器 LibreOffice + 扩展，本机加解密，无口令。
- C2 中心密钥+审计服务器：下发密钥、记录加解密事件。
- C3 密钥管理模型：统一密钥的粒度与轮换。
- C4 部署/打包：扩展安装器 + 指向服务器的配置。
- C5 传输与认证：客户端鉴权取密钥、上报事件。

## Decisions (owner + adopted defaults)
- 架构方向：客户端方案（复用现有引擎）。加解密在本机 LibreOffice 内完成，服务器只管密钥下发+审计。
- 密钥粒度：全公司一把主密钥（强随机口令串）。
- 离线：主密钥本地缓存（DPAPI 加密存储），断网可开已缓存密钥的文件。
- 测试策略：TDD（延续现有 pytest 风格套件）。
- 外发管控：员工"另存为明文/导出"= 不安全操作，强制审计记录（仅记录，不审批）。
- 非受控打开：被动防——非 LibreOffice 打开密文拿到的是密文/打不开；不做主动提示+留痕
  （需 minifilter/采购，超出范围）。审计由客户端在受控打开/保存时上传。
- 关键设计洞察：主密钥直接当"口令"喂给现有组件（复用已验证的口令路径 + verifier），
  保存时注入 EncryptionData{CryptoType,Password}，打开时注入 Password。
  依据：MediaDescriptor.EncryptionData 文档 + oox DocumentEncryption.cxx 按 CryptoType
  解析服务；test_documents.py 已证明"打开时传 Password"可正确解密并拒绝错口令。

## 无感触发机制（已选定）
- 选定：方案 B —— 受保护文件夹 + 后台守护进程（Agent）。先做 B；B 验证失败才回退 A。
- B 的核心工作流：
  1. 保存（加密）：员工正常用 LO 存明文 .docx 到受保护文件夹 -> Agent(watchdog) 检测 ->
     防抖等文件写完 -> 经 UNO 用主密钥重加密 -> 原地替换为密文、改扩展名 .cbx -> 上报加密事件。
  2. 打开（解密）：双击 .cbx -> 启动器解密到 %TEMP% 临时明文 -> 启动 GUI LO 打开 ->
     等关闭 -> 重加密回受保护文件夹(.cbx) -> 删临时明文 -> 上报解密事件。

## B 方案落地设计决策（adopted defaults）
- Agent：Python（复用 cipherbox.py 纯函数 + UNO），watchdog 监控文件夹，Windows。
- 加密实现：经常驻 headless soffice --accept=socket（UNO），loadComponentFromURL 明文 ->
  storeToURL 带 EncryptionData{CryptoType,Password} 加密（test_documents.py 已验证该路径）。
- 密文命名：加密后改扩展名 .cbx 并注册文件关联到启动器（最简、双击即开）。
  备选：保留扩展名+右键"用 CipherBox 打开"（需 shell extension，升级项）。
- 密钥：主密钥=强随机口令串，服务器签发；Agent 启动时获取，DPAPI 加密缓存，定期轮换。
- 服务器：Python + SQLite（FastAPI）；端点 /key /events /health + admin 轮换；每员工令牌；
  只存密钥+审计元数据，绝不存明文文件。
- 审计：加密/解密事件（用户、文件 hash、动作、时间戳、机器）上报。

## 最终方案（收敛，防外发）
- 防外发语义：磁盘上 office 文件始终密文 + 员工编辑走受控客户端 -> 从磁盘拿文件
  发邮件/微信/拷U盘天然就是密文（对方打不开）。
- 方案构成：B（受保护文件夹+Agent 磁盘密文+受控打开）打底，叠加 A 的关键补强——
  LO 内"强制加密保存"（拦截另存为/导出，默认带加密），堵住"另存为明文到别处再发"这个主漏洞。
- 外发管控：员工"另存为明文/导出"= 不安全操作，强制产生审计记录（仅记录，不做审批放行；
  涉密分级审批留作后续可选增强）。
- 物理隔离（VeraCrypt，采纳用户诉求）：受保护文件夹放在 VeraCrypt 加密卷内（如挂载 S: 盘）。
  职责分工——VeraCrypt=物理层（卷卸载后整体密文，防硬盘/U盘/卷文件被拿走或取证，
  并保护明文临时副本+密钥缓存）；LibreOffice 引擎=文件层（文件落盘密文，发出去是密文）。
  直接用原版 VeraCrypt，无需二次开发；卷由 Agent 引导挂载/卸载。
- 补强手段（低成本物理管控，可选）：组策略禁可移动存储写入。
- 服务器：主密钥签发/轮换 + 加解密审计（SQLite）。
- 明确不覆盖（需内核透明加密/采购才能做，超出本项目范围）：
  复制内容粘贴到聊天框/记事本、手机拍屏、员工恶意规避（把密文+偷取的密钥一起带出）。
- 阶段策略：先做 B（受控打开+文件夹加密+服务器+审计）跑通并验证，
  再叠加 A 的"强制加密保存"补强；任一步验证失败，按对应回退判据调整。

## B->A 回退判据
- B 不可行的信号（任一出现则回退 A）：(1) UNO 重加密已有明文文件不可靠/过慢；
  (2) .cbx 关联或"打开->关闭->重加密"闭环无法稳定实现；(3) 临时明文生命周期管理有致命竞态。
- 回退时 A = LO 内部拦截器（XDispatchProviderInterceptor 注入 EncryptionData/Password），
  且 A 的"强制加密保存"同时承担防"另存为明文"外发的作用。

## Approval gate
- status: approved（用户已批准，计划已生成 .omo/plans/cipherbox-transparent-encryption.md）
- 用户要求高精度双评审 → review_required=true，round_id=cb-review-r1-20261008
- approach: 文件级加密（复用现有引擎）+ B 受控打开打底 + A 强制加密保存补强 +
  外发仅记录审计 + VeraCrypt 卷作物理隔离层 + 主密钥即口令 + 中心密钥/审计服务器；
  不覆盖复制内容/拍屏/恶意规避。
- next: 双评审（momus + oracle）全 OKAY 后交付；有 issue 则修订重评。

## Review progress
- r1–r17：momus 持续 OKAY；oracle 逐轮 CHANGES_REQUESTED，缺陷已全部折入计划。
- r18：momus OKAY；oracle CHANGES_REQUESTED（4 项）——已修复并重新派发 r19。
  - r18#1[高] superseded 守卫作用域/条目生命周期/路径规范化 → todo 13 限定守卫仅适用 watcher 驱动、todo 14 绕开+会话收尾清条目、todo 17 条目任一路径删除即清、路径 GetFullPathName+大小写折叠。
  - r18#2[中] 拦截器 profile 范围 → todo 21① 引擎三处/force_encrypt.py 仅受控、todo 17② 服务/默认 profile 不加载拦截器、todo 17 QA 增"服务管线 .cbx.tmp 不被改写"断言。
  - r18#3[中低] 测试 URL 迁移无归属 → todo 1 增"check_service.py/test_documents.py/test_e2e.py 三处迁命名管道"。
  - r18#4[低] 审计队列位置/保护/容量 → todo 15 明确 %APPDATA%\CipherBox\audit-queue.json（DPAPI）+ 10000 条上限+满时弃最旧+恢复补报 ok=false 元事件。
- r19：已派发双评审（oracle bg_4ffc2952 / momus bg_e2a4cdcb），round_identity=cb-review-r19-20261008。
- r19 结果：momus CHANGES_REQUESTED（2 项）+ oracle CHANGES_REQUESTED（3 中 + 2 低，其一为无需改计划的验证缺口）——已全部修复并重派发 r20。
  - r19 合并 7 处修复：todo 13「删除/隔离」写死为「隔离不删除」+ mtime 否定分支（`encrypt_stale` 隔离审计）；todo 17 superseded 条目「source_path 从未落盘」生命周期 + 兜底队列明文 jsonl/无上限/逐行重放 + ③ 规则优先级（`.cbx` URL 的 Save 优先于 temp 放行）；todo 14 session 记录增 `ts` 字段；todo 26 守卫改用 `mtime vs ts`（删「内容 hash」）+ `service`/`audit-queue` 子目录豁免陈旧清扫。
- r20：已派发双评审（round_identity=cb-review-r20-20261008）。
- r20 结果：momus OKAY + oracle CHANGES_REQUESTED（1 高 + 1 中 + 1 低）——已修复并重派发 r21。
  - r20#1[高] todo 14 正常收尾用陈旧 temp 覆盖更新 `.cbx`（r19 优先级规则新开的洞）→ todo 14 收尾加重加密前 mtime 比对（`.cbx` 新于 temp 则跳过重加密保留 `.cbx`）、todo 13 括号备注改「todo 14 收尾守卫见 todo 14、todo 26 仅崩溃恢复」、todo 19 增第十条测试路径。
  - r20#2[中] 会话 temp 目录内拦截器产出的 `.cbx` 生命周期未定义（SaveAs 默认目录=temp 致副本蒸发）→ todo 17 ③ SaveAs/SaveACopy/ExportTo 目标位于会话 temp 目录内即拒绝保存并提示改选位置（fail-closed）。
  - r20#3[低] 新建文档 superseded 条目 `source_path` 取值未定义 → todo 17 ① 写死「新建文档无 URL 时 `source_path` = `cbx_path` 剥尾部 `.cbx`」。
- r21：已派发双评审（round_identity=cb-review-r21-20261008）。
- r21 结果：momus OKAY + oracle CHANGES_REQUESTED（1 中 + 2 低）——已修复并重派发 r22。
  - r21#1[中] todo 17 ③ in-temp 拒绝只覆盖 SaveAs/SaveACopy/ExportTo，漏 ExportToPDF/ExportDirectToPDF/Print-to-file（同"副本蒸发"洞对另一半写盘 dispatch 仍开）→ 改写为「任何写盘 dispatch 目标位于会话 temp 目录内→拒绝，唯一例外=指向 temp 文档自身的 .uno:Save/.uno:SaveAll 放行」+ todo 19 增第十一条测试路径。
  - r21#2[低] todo 17 ① encrypt/superseded 上报无 Agent 不可达兜底 → 回调失败时以独立行类型落同一 audit-queue 队列，重放时补记审计+补登 superseded。
  - r21#3[低] 隔离区无规范路径 → 全局命名约定（L70）定义 `S:\.cipherbox-quarantine\`，todo 12 排除清单点名之。
- r22：已派发双评审（round_identity=cb-review-r22-20261008）。
- r22 结果：momus OKAY + oracle CHANGES_REQUESTED（1 低）——已修复并重派发 r23。
  - r22#1[低] todo 17 ① fallback 队列制造未钉死的启动顺序依赖（孤儿恢复查 superseded 清单时崩溃会话条目可能还在未重放的 audit-queue 里）→ todo 26 钉死顺序「先重放 audit-queue（补记审计+补登 superseded）再执行孤儿恢复」。
- r23：已派发双评审（round_identity=cb-review-r23-20261008）。
- r23 结果：momus OKAY + oracle CHANGES_REQUESTED（1 中）——已修复并重派发 r24。
  - r23#1[中] round-22 顺序修复只约束了受控打开受理，未约束 watcher 启动（存量扫描+防抖事件处理也消费 superseded 清单）→ todo 26 顺序子句扩为「重放+孤儿恢复同步完成前，不受理受控打开、且不启动 watcher」。
- r24：已派发双评审（round_identity=cb-review-r24-20261008）。
- r24 结果：momus OKAY + oracle OKAY —— **双评审全部通过，计划定稿**。26 轮（r1-r24，含 r18/r19/r20/r21/r22/r23 多轮修订）收敛完毕，可交付执行。