# Wave 0 执行经验（所有 spike worker 必读）

## 1. 环境
- `S:` 是 subst 映射 → `C:\code\cipherbox\.s-volume`。**机器/终端会话变化后映射会丢失**；脚本报 `FileNotFoundError: 'S:\\'` 就是这个原因。恢复：`subst S: C:\code\cipherbox\.s-volume`。
- 常驻服务：`powershell -NoProfile -ExecutionPolicy Bypass -File C:\code\cipherbox\lo-encryption-demo\start_soffice.ps1`（幂等，约 3–5s）。管道 `cipherbox-service`，URL `uno:pipe,name=cipherbox-service;urp;StarOffice.ComponentContext`。
- **禁止 kill/restart 共享服务**；自己的实例自起自清。
- 引擎组件日志：`S:\.cipherbox-tmp\service\cipherbox-encryption.log`（服务进程 TMP）。要读它的脚本需把自身 TMP/TEMP 设为同一目录。
- 测试脚本必须用 bundled python：`C:\Program Files\LibreOffice\program\python.exe`（PATH python 无 `uno`）。
- LO 26.8 的 `uno` 模块**没有**模块级 `queryInterface`；用对象方法：`obj.queryInterface(uno.getTypeByName(...))`。

## 2. 运行器（血泪教训）
- **绝对不要**用 .NET Process + `RedirectStandardOutput`（管道）跑输出 >4KB 的脚本：管道缓冲满 → WaitForExit 死锁（表现为"挂死"，实际是死锁）。
- 唯一正确姿势：`Start-Process -FilePath $py -ArgumentList '"<script>"' -RedirectStandardOutput <file> -RedirectStandardError <file> -Wait -PassThru`（直写文件，无管道）。
- 每个外部调用加看门狗（超时 kill）；单条命令显式 timeout ≤120s；不允许开放式等待。
- 易崩路径（错口令重载等）用**逐次子进程隔离**（每次一个 python 子进程 + 20s cap）。

## 3. 已实证事实（不要重新推导）
- 保存/重加密全绿：明文 `loadComponentFromURL` + `storeToURL(FilterName, Password, EncryptionData{CryptoType,Password})` → CFB（OLE magic）+ `EncryptedPackage` + **无** `EncryptionInfo` 流。
- 引擎 API 级 `decrypt()` 回环逐字节一致；verifier 拒绝错口令/近似口令/空口令。
- **LO 26.8 用 `loadComponentFromURL` 打开自定义数据空间容器不可用**（检测返回空类型 / 显式过滤器 None / 自动回退 Text）。源码级原因：`decrypt()` 的 `[out]` 参数 + filterdetect 自嗅探。**任何设计都不得依赖它**：解密走引擎 API，LO 只打开解密后的明文。
- 格式边界：`doc/xls/ppt` 带 `EncryptionData{CryptoType}` 时**同样走自定义引擎**（原计划判断有误，那只是 Password-only 路径的现象）。
- 错口令重载：快速抛 `IllegalArgumentException`（"Unsupported URL ... type detection aborted"），不返回 None、不挂起。

## 4. 交付纪律
- 每完成一步向 `.omo/start-work/artifacts/<todo-XX>/PROGRESS.md` 追加 `[HH:mm:ss] 步骤 — 结论`。
- 真实 transcript 存同目录（不得重建/编造）。
- 只提交自己范围内的文件；`.omo/` 不提交；git index.lock 冲突等 2s 重试。
- 结束核实：无残留进程（共享服务除外）、无明文残留、worktree 干净。
