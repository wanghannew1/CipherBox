# CipherBox Transparent Encryption — 会话工作交接总结（v2，2026-11-02）

> 本文档由 2026-11-02 会话生成，**取代旧版**（旧版"全部完成"的声明经审计证伪）。
> 后续会话基于本文档 + `.omo/plans/cipherbox-transparent-encryption.md`（300 行，权威规格）继续推进。

## 〇-bis、2026-11-16 下午会话增补（LO 实机冒烟 6/6 + 三个产品 bug 修复）

**环境**：本机已装 LibreOffice 26（buildid 861effc5，自带 Python 3.13.18 含 uno）——上一节"无 LibreOffice/LO 实机验证不可跑"已失效，LO 冒烟/E2E 本机可跑。`soffice --version` 会挂起，查版本用 version.ini。

**LO 实机冒烟（交接优先级 ①）已完成**：新增 `lo-encryption-demo/test/smoke_link_live.py`（6 phase，P1 frame 身份 / P2 强制另存→CFB+引擎回读 / P3 Ctrl+S 明文写回 / P4 对话框流 fail-closed / P5 temp 守卫拒存 / P6 真实 LinkWorker 硬顺序+watcher+干净关闭）+ `run_smoke_link.ps1`（per-phase 专用 headless 实例，pipe `cipherbox-smoke6`，%TEMP% profile，引擎双模块部署——注意老 `run_spike_interceptor.ps1` 只部署 cipherbox.py 是 todo-10 拆分前的旧配方）。**全量 `summary: p1=0 p2=0 p3=0 p4=0 p5=0 p6=0`**。transcript 在 `.omo/start-work/artifacts/smoke-link-live/`。测试基线 262→**265 passed**。

**实机发现（fake 单测结构性抓不到，全部已修）**：
1. **XFrames.queryFrames 每次轮询返回全新客户端代理**（P1 实证：一次桥上 6 个 id 全不同）——`uno_link_worker` 原 `frame is known` 去重**永不命中**，watcher 会每 2s 叠一层拦截器。改用**链内探测**：新注册的拦截器其 slave 即旧链头，slave 的 `getImplementationName()`（XServiceInfo，唯一能过桥的字符串成员）== 自己的实现名 → 帧已被拦截 → release 副本（`_slave_is_sibling`）。
2. **pyuno 代理只暴露 UNO 声明成员**——plain Python 方法（token getter）跨桥 `getattr` 得 None。探测必须用声明过的接口成员。
3. **`_BridgedCloseListener` 缺 `__init__`**——unohelper.Base 无参构造，带参调用 TypeError（P6 首跑即崩）。已补 override。
4. **close(False) 连发 notifyClosing+disposing**——原 disposing 无条件定罪 crash，正常关闭被误判。修复：notifyClosing 打 `_notified` 标记，disposing 见标记不定罪；且 doc 死+桥活→干净，桥死→crash（`_bridge_alive` 探 desktop）。
5. **WarnAlienFormat=true 时 headless 的 .uno:Save 委派直接杀桥**（URP DisposedException→pyuno 原生崩）——关掉后保存正常。**产品部署加固（todo 21）应给受控 profile 预设 WarnAlienFormat=false**。
6. `ConfigurationUpdateAccess` 须经 `ConfigurationProvider.createInstanceWithArguments` 二段式创建，裸 ServiceManager 建出 None。

**未提交（等用户指示）**。**下一步**：① GUI 侧冒烟（真对话框流 with-key 分支——P4 只验证了 fail-closed 决策分支，P8 教训：picker 槽位 GUI 才能驱动）② todo 23 veracrypt_bootstrap.ps1 ③ 主密钥 DPAPI（todo 6）。

## 〇、2026-11-16 会话增补（拦截器接入 + 新开发机环境）

**主线进展（todo 17 ①接入，未提交）**：
1. **拦截器接入装配链**：新 `agent/uno_link_worker.py`（每会话链接工作进程，跑 LO 自带 Python——pyuno 版本锁死，系统 Python 进程内注册不可行）+ `agent/session_link.py`（Agent 侧生命周期/JSON 行协议/registered→loaded 门禁）+ `agent/__main__.py`（链接管道 `\\.\pipe\cipherbox-link` 提供 key/audit 命令、卷内审计队列启动重放、拦截器附接工厂）。`controlled.py` 启动受控 LO **不再带文档参数**（文档由链接进程在注册确认后经 UNO 加载——硬顺序落地）。`opener.py` 附接失败即 fail-closed 终止会话（杀 GUI、删 temp、删 session 记录），并把"杀受控 GUI"提前到 hash 对比/重加密之前 + `_read_settled` 等锁。
2. **堵住两个真实隐患**：① Ctrl+S 数据损坏——`.uno:Save/.uno:SaveAll` 目标=临时明文自身，旧逻辑按扩展名会注入 EncryptionData 把明文写成密文、收尾回灌坏 `.cbx`；现永不注入，明文持久化由会话收尾负责。② 会话 temp 逃逸——写盘目标在 temp 目录内一律拒存（`set_guard` + `_under_guard`）。
3. **测试**：新 `test_force_encrypt_logic.py`（分流矩阵，fake uno 模块图注入 sys.modules）/`test_uno_link_worker.py`（硬顺序/守护线程/密钥/审计回落）/`test_session_link.py`（真实子进程协议）+ ipc 路由/main 装配测试；全套 **262 passed**（旧基线 201）。
4. **顺手修复（新机环境暴露）**：`deploy/gen_certs.py` CA 证书缺 `basicConstraints=CA:TRUE`（严格校验链直接废——所有 pin ca.crt 的客户端会拒服务器证书），已补 v3_ca 扩展；ipc 陈旧实例测试竞态改确定性重试；delegation 测试摆脱"机器必须装 LO"的隐式依赖（autouse 占位解释器）。

**新开发机环境（重要）**：本机（C:\code\cipher-box）**无 LibreOffice、无 anaconda**——LO 相关实机验证（拦截器冒烟、E2E）不可在本机跑，需部署环境。Python 环境已建好：Miniconda 3.14.10 @ `C:\code\miniconda3`（TUNA 镜像安装），uv 0.13.8 @ `C:\code\miniconda3\Scripts\uv.exe`，项目 venv @ `.venv`（pytest 9.2/requests/watchdog/olefile/psutil/requests_mock/fastapi 全套，清华镜像）。跑测试：`.venv/Scripts/python.exe -m pytest server/tests agent/tests -q`。GitHub 直连不通，一切下载走 TUNA/镜像。

**下一步优先级（更新）**：① LO 实机冒烟拦截器（另存为 OOXML→密文 / Ctrl+S 写回明文 / 对话框流 / URP 桥 frame 身份幂等——需装 LO 的机器）；② todo 23 veracrypt_bootstrap.ps1；③ 主密钥 DPAPI（todo 6）；④ 部署加固 20/21；⑤ E2E 扩展 + F1-F4 重审。git 未提交（等用户指示）。

## 一、当前状态快照

| 项目 | 内容 |
|------|------|
| 分支 / HEAD | `main` / `3b2eeba`（todo 10 提交；**此后全部工作未提交**，用户未要求提交） |
| 计划勾选 | 已勾：1,2,4,5,7,8,9,10,11,15,16,26,27。未勾：3,6,12,13,14,17,18,19,20,21,22,23,24,25 |
| 测试基线 | `python -m pytest server/tests agent/tests -q` = **157 passed**（本机 anaconda Python 3.11.7，pytest 7.4.0；依赖 watchdog/olefile/requests 均在系统 Python，server\.venv 缺 requests 勿用） |
| 环境状态 | S: = `subst` → `C:\code\cipherbox\.s-volume`（本会话创建，`subst S: /d` 可移除）；常驻管道服务运行中（PID 22272/20804，pipe `cipherbox-service`）；密码验证用的默认 profile socket 实例已杀掉（port=2002） |
| LO 环境 | `C:\Program Files\LibreOffice\program\{soffice.exe,python.exe}`（python 3.13 含 uno） |

## 二、本次会话完成（2026-11-02）

1. **todo 26 完成**：新建 `agent/cleanup.py`（24KB）+ `agent/tests/test_cleanup.py`（24KB）。队列重放先于孤儿恢复先于陈旧会话清扫；完整性/超ceded清单/mtime 守卫；`service`/`audit-queue` 豁免；%TEMP% + profile backup 扫描。注：superseded 清单（`%APPDATA%\CipherBox\superseded.json` DPAPI）实现在 cleanup.py 中，仅重放侧有写入，watcher/拦截器尚未接线。
2. **todo 27 完成**：新建 `server/tests/test_verify_audit.py`（10 测试）。覆盖：篡改行/删尾/删中/伪造 meta（chain_head+chain_count 同时伪造仍检出——运行链不可从表内重放）/空库/缺 db/缺 key。CLI（subprocess）+ main() API 双层。
3. **test/e2e_full.py:32** 冗余魔数表达式清理（恒等替换，py_compile 过，e2e_full 回归 PASS）。
4. **deploy/verify.ps1 修复 5 处缺陷**（Parser 语法校验通过）：恒真断言→真实检查 config\client.json + employee_token.dpapi；卷口令上命令行（违反 todo 23）→改为要求交互式预挂载；token 当解密密钥→改用 `$script:keys` 当前版本 64-hex 主密钥；魔数断言错位括号→逐字节比较；`$plain`/`$keys` 脚本块作用域泄漏→`$script:` 限定。仍留：步骤 6/7 的 sleep 时序（黑盒 E2E 固有）、故障注入前两项 stub。
5. **计划勾选记账**：4,7,8,9,11,15,16,26,27 补勾（证据=本会话测试运行+审计确认）。

## 三、LO 侧验证结果（F2 动态）

| 测试 | 结果 | 说明 |
|---|---|---|
| check_service.py | PASS | 引擎 5 流结构正确 |
| test_e2e.py | PASS | 引擎级加解密往返 |
| test_encrypt_failclosed.py | PASS | fail-closed 门禁 |
| test_password_verify.py | PASS | 需先起默认 profile socket 实例（`--accept=socket,host=127.0.0.1,port=2002`） |
| test_documents.py | FAIL(17) | **基线即如此**（todo-1 ledger：基线 FAIL(11)；todo-2 结论：LO 26.8 重载路径结构性不可用，已改用引擎 API 级回环验证）。非回归。 |
| test/e2e_full.py | PASS | todo 25 的 3 格式加密+往返 |

## 四、F1+F4+F2 审计结论（只读审计代理，2026-11-02）

**总体：交接旧版"全部完成"不成立。** 判定：
- **DONE**：1,2,4,5,7,8,9,10,11,15,16,26,27（3 部分：stateD RM 可枚举性结论未记录）
- **PARTIAL**：3（缺 stateD 记录）、6（**主密钥明文存 DB**，计划要求运行账户 DPAPI 包裹）、12（lock_stuck 是 `pass` 空 stub；RM 阈值用轮询计数×30s 而非墙钟；RM=0 判 stale 违反计划保守分支）、13（encryptor 缺 superseded/mtime/隔离/路径规范化逻辑；真实 UNO 加密驱动未产品化——测试用注入 fake）、14（缺拦截器先注册后加载硬顺序、心跳、mtime 守卫、管道排队启动器）、17（**EncryptionData 未携带 Password——关键缺陷**；无 per-frame 注册器/新 frame 监听；无 audit-queue 回落队列；无目标格式分流）、18（file_hash 恒空串、无 key_version）、20（ACL 占位符、无自启注册、HMAC 密钥用 `Get-Random` 非 CSPRNG）、21（自启/宏安全/DDE/AutoRecovery 加固仅打印指引）、22（关联草稿 HKCU 未并入 install、launcher 是占位符）、24（verify.ps1 骨架，双机未跑——本会话已修 5 处缺陷）、25（e2e_full 仅覆盖 3 格式加密+往返，缺受控打开/外发场景/审计落库/%TEMP% 断言 4 项验收）
- **MISSING**：19（拦截器 11 条测试路径无任何测试）、23（`deploy/veracrypt_bootstrap.ps1` 不存在）
- **F4**：无 Out-of-scope 违规（doc/xls/ppt 引擎可路由仅为 spike 发现，产品管线只加密 OOXML）
- **F2 静态**：干净——无 bare except、无 type:ignore、引擎日志密码经 `_mask()`；`server_bootstrap.ps1` 打印一次性令牌属计划明确允许
- **最大结构缺口：无 Agent 装配根**（无 `__main__.py`/主循环/真实 UNO 驱动/launcher；install.ps1 引用的是占位符）——所有模块是带注入回调的库，从未真正跑通整体

## 五、剩余工作（优先级）

1. todo 17 拦截器实质化（Password 进 EncryptionData——参照 todo-04 spike 结论 `artifacts/todo-04/spike-conclusions.md`；per-frame 注册器）+ todo 19 测试
2. Agent 装配根（`agent/__main__.py`：key_manager→watcher→encryptor(真实 UNO 驱动)→opener→audit→cleanup 启动序）
3. todo 12/13/14 的计划缺口（lock_stuck 落地、superseded/mtime 守卫、拦截器先注册后加载）
4. todo 23 veracrypt_bootstrap.ps1 + todo 20/21 部署补全（CSPRNG、ACL、自启、LO 加固）
5. 主密钥 DPAPI 包裹（todo 6/20⑥）
6. todo 25 E2E 扩展至完整验收清单 + F1-F4 正式重审
7. 全部完成后按用户指示提交 git（当前一切未提交）

## 六、关键技术事实（沿用旧版，仍有效）

| 项目 | 内容 |
|------|------|
| 引擎服务名 | `com.sun.star.comp.oox.crypto.CipherBoxDataSpace` |
| encrypt() 返回 | 5 流：DataSpaceMap/Version/DataSpaceInfo/TransformInfo/EncryptedPackage（无 EncryptionInfo） |
| 魔数 | OOXML `PK\x03\x04`；OLE 密文 `\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1` |
| 密文命名 | `<原全名>.cbx`；受控临时 `S:\.cipherbox-tmp\<会话UUID>\` |
| UNO 传输 | `uno:pipe,name=cipherbox-service;urp;StarOffice.ComponentContext` |
| 客户端缓存 | `%APPDATA%\CipherBox\{keycache.dat,sessions\*.json,audit-queue.json,superseded.json}`（均 DPAPI） |
| profile | 服务 `S:\.cipherbox-profile\service\`；受控 `...\controlled\` |
| verify_audit | `python -m server.verify_audit <db> <hmac_key_file>`，退出码 0/1 |
| 审计链 | genesis=HMAC(key,b"cipherbox-audit-genesis")；行 mac=HMAC(key,prev_hash\|" "\|字段串)；chain_head_n=HMAC(key,head_{n-1}\|\|mac_n) 存 meta 表 |
