# Wave 0 todo 2 — spike conclusions (UNO re-encrypt + format boundary + reload root cause)

Date: 2026-10-09. LibreOffice 26.8.0.3, persistent pipe service (`cipherbox-service`,
PIDs 19336/16524, profile `S:\.cipherbox-profile\service`), bundled python
`C:\Program Files\LibreOffice\program\python.exe`, engine `CipherBoxDataSpace` as deployed.
All evidence transcripts live in this directory; products under
`S:\.cipherbox-tmp\spike-todo-02\<timestamp>\`.

Committed spike scripts (lo-encryption-demo/test/):
`spike_reencrypt.py` (A), `spike_format_boundary.py` (B),
`spike_wrongpassword.py` (C), `spike_reload_rootcause.py` (D).

## A. UNO 重加密已有明文文件 — PROVEN（回退判据 1 绿）

`loadComponentFromURL(明文)` → `storeToURL(目标, [FilterName, Password,
EncryptionData{CryptoType:"CipherBoxDataSpace", Password}])` for docx/xlsx/pptx:

- Product is a CFB container (OLE magic `d0cf11e0a1b11ae1`) with `EncryptedPackage`
  and CipherBoxDataSpace marks, and **no** `EncryptionInfo` stream (that is LO's
  built-in agile stream name; the engine writes the 5 DataSpaces streams).
- Engine `encrypt()` ran on save (component log).
- Round trip verified through the **ENGINE's decrypt over UNO** (oox-style:
  readEncryptionInfo → generateEncryptionKey → decrypt), NOT via
  loadComponentFromURL: recovered payload is the OOXML ZIP (PK magic) and the
  marker `CipherBox round trip marker 4711` survives byte-consistently
  (zip entries are DEFLATED — the check scans entries decompressed via zipfile).
- generateEncryptionKey rejects the wrong password on the real product (verifier
  works end-to-end through the container).
- 45 checks green, 0 FAIL, ~2 s per run. Transcript: `spike-reencrypt-run.txt`.

**结论：todo 13 的生产加密路径（明文 load + 加密 storeToURL）在 LO 26.8 上完全可靠。**

## B. 格式边界结论 — 计划预期被实测证伪（FALSIFIED）

Plan premise (TL;DR + out-of-scope): "doc/xls/ppt 不走自定义引擎
（test_documents.py L33-35 use_hook=False，走 LO 内置加密）".

**实测（byte inspection + engine log + engine-decrypt round trip，非假设）：**
doc/xls/ppt with the SAME `EncryptionData{CryptoType}` media descriptor DO route
the custom CipherBoxDataSpace engine:

| format | product | OLE magic | EncryptedPackage | CipherBoxDataSpace marks | EncryptionInfo | engine encrypt() ran | engine-decrypt round trip |
|---|---|---|---|---|---|---|---|
| doc  | 14336 B | yes | yes | yes | no | yes | inner .doc OLE file 9216 B recovered, marker survives |
| xls  | 10752 B | yes | yes | yes | no | yes | inner .xls OLE file 5632 B recovered, marker survives |
| ppt  | 469504 B | yes | yes | yes | no | yes | inner .ppt OLE file 460800 B recovered, marker survives |

Mechanism: the storage-level encryption layer (oox DocumentEncryption path) is
**format-agnostic** — the binary filters export the whole inner office file and
the encryption layer wraps it into the CipherBox container. The `use_hook=False`
premise in test_documents.py L33-35 describes the **Password-only** path (LO
built-in crypto), not the `EncryptionData{CryptoType}` path.

**真正的格式边界是重载路径（见 D），它对所有 custom-dataspace 容器（OOXML 与二进制
同罪）都断——而生产路径不用它。doc/xls/ppt 的 out-of-scope 决策所依据的技术前提
已被证伪，是否扩scope（保存路径已实测可用）是 orchestrator 的计划决策，不是技术障碍。**
Transcript: `spike-format-boundary-run.txt`.

## C. 错误密码重载 — 实际行为（供计划 QA 措辞）

On LO 26.8 headless, `loadComponentFromURL(产品, [Password=错])`:

- **RAISES `com.sun.star.lang.IllegalArgumentException: Unsupported URL <...>:
  "type detection aborted"`** — quickly (<1 s), does NOT return None.
  (todo-01 baseline observed the same raise; this spike re-confirmed with
  per-load child-process isolation, 20 s kill cap, docx + xlsx.)
- The engine-side verifier rejects the wrong password FIRST (component log:
  `generateEncryptionKey(): verifier mismatch -> rejecting password` — both for
  LO's "VelvetSweatshop" default probe and the supplied wrong password).
- 计划 QA 措辞应断言"拒绝打开（raise 'type detection aborted'）"，而非"返回 None"。
Transcript: `spike-wrongpassword-run.txt`.

## D. 重载断点根因（todo 1 遗留，本 todo 深挖）— 结构性，非 26.8 回归，非引擎 bug

### 隔离实验（a）：一般加密重载在 26.8 上是好的

Password-only（无 EncryptionData → LO 内置 agile）docx：产物为内置 agile 容器
（EncryptionInfo 存在、无 CipherBoxDataSpace 标记、引擎日志静默），用密码重载
**成功且内容标记完好**。→ 断裂仅限 custom-dataspace 容器，不是"加密重载"这一类。

### 发散点定位（b）：字节从未到达 oox

- 外部 `TypeDetection.queryTypeByDescriptor(Url+Password, deep)` → 返回 **空类型**，
  且**完全不触发引擎**（日志零行——该查询根本没走到 crypto）。
- `loadComponentFromURL(Password=正确)` → **引擎全链路跑完**（readEncryptionInfo →
  generateEncryptionKey(VelvetSweatshop→拒) → generateEncryptionKey(正确→过) →
  createEncryptionData → decrypt → checkDataIntegrity()=True，日志逐行可证），
  却仍回退 Text 滤镜，加载出的"文档"内容是**原始 CFB 字节**（标记不在其中）。
- `createEncryptionData` 的返回值**不是**断点：oox 的 PasswordVerifier 只检查
  `hasElements()`，引擎返回的 [CryptoType, CipherBoxKey] 满足它。

### 根因（LO 26.8 oox 源码级，逐文件可证）

1. `oox/source/crypto/DocumentDecryption.cxx` `decrypt()`：先把调用方
   UNOMemoryStream 的输出流（`xDocumentStream->getOutputStream()`）赋给局部变量，
   再作为第二参传给引擎——期望引擎**把解密字节写进这个预置的流对象**。
2. `oox/source/core/filterdetect.cxx` `extractUnencryptedPackage()`：解密后**只嗅探
  它自己 new 的那个 UNOMemoryStream**（`xTempStream->getInputStream()` →
   `lclIsZipPackage`）——不读引擎经 [out] 参数交回的任何流。
3. `offapi/com/sun/star/packages/XPackageEncryption.idl`：`decrypt()` 第二参声明为
   **[out]** → PyUNO 给 Python 引擎投递 **None**，Python 引擎永远拿不到调用方的流。
4. 内置 C++ 引擎（`oox/source/crypto/StrongEncryptionDataSpace.cxx`）能工作是因为
   进程内 C++ 调用传的是引用，其当前值恰是调用方预置的流，C++ 直接往里写
   （`BinaryXOutputStream aOutputStream(rxOutputStream, true)`）。Python 引擎唯一的
   交回通道——返回 `(True, own_stream)`——只会把调用方变量**替换成另一个流对象**，
   而 filterdetect 从不读它。
5. 结果链：UNOMemoryStream 空 → `lclIsZipPackage` false →
   `extractUnencryptedPackage` 返回空 → `detect()` 的 `UNO_SET_THROW` 抛出 →
   catch（ABORTED 未置）→ 返回空 filter 名 → 类型检测链继续 → Text 滤镜兜底。
   错误密码时：两次 verifier 拒绝 → `requestAndVerifyDocPassword` 空 →
   PROP_ABORTED → detect 返回 flat 类型名 + Aborted 标志 → 加载代码抛
   "type detection aborted"（与 C 观测一致）。

该 API 自 LO 7.0 引入起即此结构（filterdetect 读自己的 UNOMemoryStream 的形状早于
自定义引擎支持），**不是 26.8 回归，不是 cipherbox.py 的密码学错误，纯 Python 不可修**。

### 生产影响评估

- **todo 13（加密）**：明文 load + 加密 storeToURL —— 本 spike A **实测绿**，不受影响。
- **todo 14（受控打开）**：Agent 侧用 container.py 自行解密（不经 LO 引擎 decrypt），
  不走 LO 重载路径，不受影响。
- **LO 侧 custom-engine 重载不在生产路径上**——它只影响"直接用 LO 打开 .cbx"这一
  本期不存在的使用方式。
- **B 的证伪影响计划决策**：doc/xls/ppt 的保存路径加密实测可用；是否将其纳入
  主密钥统一加密是 scope 决策（计划当前列为 out-of-scope 的技术依据已不成立），
  由 orchestrator 裁决（若扩 scope：todo 13 的 ZIP-magic 预检需加 OLE-magic 分支
  （二进制明文也是 OLE 容器，不能只认 PK），todo 10 的 container.py 解密判据
  "明文以 PK 开头"对二进制格式需改为 OLE magic——这是真实的后续工作量）。

### 选项（供 orchestrator 裁决）

1. **接受现状（推荐）**：记录"LO 侧 custom-engine 重载结构性不可用"为已声明边界；
   生产路径（13 加密 / 14 Agent 解密）不受影响；不改 cipherbox.py。
2. **引擎侧适配：纯 Python 不可行**——[out] 参数无通道把字节送进调用方的
   UNOMemoryStream；只有改 LO C++（filterdetect 改读引擎交回的 out-param 流）或
   OLE-storage 层 workaround 才可能修，均超出本项目。
3. **若扩 doc/xls/ppt scope**：保存路径已实测可用（B 证据）；重载边界与 OOXML 相同
   （同样不走 LO 重载）；需按上表补 todo 10/13 的格式判据工作量。

## 运维级发现（供后续 todo 复用）

- **.NET 重定向管道死锁**：子进程 stdout 走 .NET `Process.RedirectStandardOutput`
  管道且父端 `WaitForExit` 先于读取时，输出 >4KB（Windows 匿名管道缓冲）即死锁
  （本 wave 三次"挂死"全是它，不是脚本挂）。**测试 runner 一律用
  `Start-Process -RedirectStandardOutput <file>`（子进程直写文件，无管道）**。
  todo 25 E2E 的 runner 必须沿用。
- **bundled python 的 sys.executable 是目录**：`...\program\python-core-3.13.15`
  （非 exe），`subprocess.run([sys.executable, ...])` → WinError 5。可 spawn 的启动器
  是 `os.path.dirname(sys.executable)\python.exe`（见 spike_wrongpassword.py 的
  `bundled_python_exe()`）。**todo 13 的 Agent（PATH python）驱动 bundled-python
  UNO worker 时必须用 `C:\Program Files\LibreOffice\program\python.exe`。**
- **CFB 目录项名是 UTF-16LE**：字节检查标记要查 `ascii OR utf-16-le` 两种形式。
- **OOXML zip 条目是 DEFLATED**：内容标记的字节级校验必须解压后扫（zipfile）。
- **LO 26.8 uno 模块无模块级 queryInterface**：一律用对象方法 `obj.queryInterface(...)`
  （todo-01 已知，本 wave 全部沿用）。

## 证据索引

- `spike-reencrypt-run.txt` — A：45 checks PASS，RESULT: PASS（含 run1 挂死诊断
  `spike-reencrypt-run1-hang-diagnosis.txt` 与管道死锁根因）。
- `spike-format-boundary-run.txt` — B：边界证伪 + 引擎往返证据。
- `spike-wrongpassword-run.txt` — C：实际 raise 行为 + 引擎 verifier 拒绝。
- `spike-reload-rootcause-run.txt` — D：agile 隔离 + 发散点探针 + 根因打印。
- `probe-spawn.txt` — sys.executable 目录问题的 traceback 证据。
- 引擎日志：`S:\.cipherbox-tmp\service\cipherbox-encryption.log`（服务进程持续追加）。
- LO 26.8 源码引用：libreoffice-26-8 分支 `oox/source/core/filterdetect.cxx`、
  `oox/source/crypto/DocumentDecryption.cxx`、`oox/source/crypto/StrongEncryptionDataSpace.cxx`、
  `offapi/com/sun/star/packages/XPackageEncryption.idl`。
