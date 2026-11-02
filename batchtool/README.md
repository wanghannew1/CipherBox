# 批量文档加密工具

Word / Excel / PowerPoint 批量加密,基于 LibreOffice 原生文档密码(ECMA-376 Agile)。
图形界面,同时输出 TXT 与 XLSX 报告。

---

## ⚠️ 最重要的一件事

**加密后密码一旦遗忘,文件将永久无法恢复。**

本工具不保存任何密钥副本,没有后门,没有找回通道。密码一旦丢失,
文件就只能从原始数据重新生成。加密前请务必把密码记录到密码管理器
或纸质备份 —— 报告文件本身就是一份密码清单。

---

## 快速开始

### Windows

1. 安装 [LibreOffice](https://www.libreoffice.org/download/)(默认装到 `C:\Program Files\LibreOffice`)
2. 安装 Python 3(安装时勾选 **Add Python to PATH**)
3. 双击 `run.bat`,或在命令行:

```bat
run.bat
```

### Linux / macOS

```bash
python3 batchtool/gui.py
```

依赖:

| 组件 | 要求 |
|---|---|
| Python | 3.8+,需 `tkinter`(标准库自带) |
| LibreOffice | **必须**,且需包含 Writer / Calc / **Impress** 三个模块 |

Debian / Ubuntu:

```bash
sudo apt install libreoffice-writer libreoffice-calc libreoffice-impress python3-uno
```

> 只加密 PPT 就必须装 `libreoffice-impress`。缺模块时 PPT 会在报告里
> 显示为失败,Word/Excel 不受影响。

### 关于「用哪个 Python 跑」

GUI 需要 `tkinter`,加密需要 `uno`,而这两个通常不在同一个解释器里:

- **Windows**:LibreOffice 自带的 `program\python.exe` 有 `uno` 但**没有 tkinter**
- **Linux**:系统 `python3` 两个都有

所以 `encryptor.py` 会在缺少 `uno` 时**自动**改用 LibreOffice 自带的 python
以 worker 模式重新执行自身。你不需要手动处理,直接跑 GUI 即可。

---

## 使用

| 步骤 | 说明 |
|---|---|
| 1. 添加文件 | 「添加文件」可多选;「添加文件夹」可加目录。两者可混合 |
| 2. 范围 | 「全部子目录」递归 / 「仅当前层」不进子目录 |
| 3. 类型 | 勾选 Word / Excel / PowerPoint,支持 `.docx/.docm/.xlsx/.xlsm/.pptx/.pptm` 及 ODF |
| 4. 密码 | 手填或「随机生成」,需输入两次确认 |
| 5. 输出 | 见下方两种模式 |
| 6. 执行 | 「扫描预览」可先看命中数量,再点「开始加密」 |

### 两种输出模式

**复制并加密** — 保留明文原件,密文写入指定输出目录(保持子目录结构)。
适合归档、备份、外发。

> ⚠️ LibreOffice 加密**不会删除明文原件**。此模式下源文件仍是明文,
> 需你自行删除或妥善保管。不删等于没加密。

**⚠ 原地覆盖源文件** — 源文件被密文直接替换,原始明文不再存在。
实现上先写同目录临时文件、验证确实是密文后才原子替换,中途失败不会损坏源文件。

### 关于「先备份」

原地覆盖前建议先备份。工具不会替你备份。

---

## 报告

每次执行生成两份(可在界面勾选):

- `加密报告-YYYYMMDD-HHMMSS.txt` — 人类可读,带表头汇总
- `加密报告-YYYYMMDD-HHMMSS.xlsx` — 可直接用 Excel/WPS 打开

字段:序号、文件名、源路径、目标路径、扩展名、**密码**、模式、原始大小、
加密后大小、含宏、结果、错误信息、时间。

单个文件失败不会中断整批,失败原因逐条记入报告。

> 报告含明文密码,等同一份密码清单。请与密文分开保管,勿随文档外发。
> 勾选「报告中隐藏密码」可只留 `S*************7` 形式的掩码。

---

## 命令行用法

不用界面也能跑:

```bash
# 复制模式,递归全部子目录
python3 batchtool/encryptor.py \
  --input /path/to/docs \
  --password "Your-Password" \
  --mode copy --out /path/to/encrypted \
  --report-dir /path/to/reports

# 原地覆盖,仅当前层
python3 batchtool/encryptor.py \
  --input /path/to/docs \
  --password "Your-Password" \
  --flat --mode overwrite

# 只加密 Excel,报告中隐藏密码
python3 batchtool/encryptor.py \
  --input /path/to/docs --password "PW" \
  --kinds excel --mask-password
```

退出码 `0` = 全部成功,`1` = 有失败项,`2` = 环境问题。可用于 CI。

主要参数:

| 参数 | 说明 |
|---|---|
| `--input` | 文件或目录,可多个 |
| `--password` | 加密密码 |
| `--mode copy\|overwrite` | 复制加密 / 原地覆盖 |
| `--flat` | 仅当前层,不递归 |
| `--out DIR` | 复制模式的输出目录 |
| `--report-dir DIR` | 报告保存目录 |
| `--kinds word excel ppt` | 文件类型筛选 |
| `--no-txt` / `--no-xlsx` | 关闭某种报告 |
| `--mask-password` | 报告密码打码 |
| `--port N` | UNO 端口(默认 2095) |

---

## 实现要点

加密靠 UNO 的 `storeToURL`,**密码必须放在 MediaDescriptor 顶层**:

```python
doc.storeToURL(out_url, (
    pv("FilterName", "MS Word 2007 XML"),
    pv("Overwrite", True),
    pv("Password", password),   # ← 必须顶层
))
```

放进 `FilterData.Password` 或 `FilterData.EncryptionData` 会被 LibreOffice
**静默忽略** —— 不报错、不警告、文件照旧落成明文。这是最容易误判
「LO 不支持格式级加密」的地方。

XLSX 报告用手写 zip+XML 实现,**不依赖 openpyxl**,因为用户的系统
Python 未必装了它。

整批共用一个 soffice 实例 —— 逐个文件启动 LibreOffice 会慢到不可用。

### 加密后是什么

OLE2 / CFB 复合文档(与旧版 `.doc` 同容器),内含 `EncryptedPackage`
密文流。这是标准 ECMA-376 Agile 加密。

---

## 已知限制

- **会重写整个文件。** LibreOffice 往返可能引起排版偏移、字体替换、
  修订批注损坏。**加密成功 ≠ 内容保真。** 重要文档请先拿副本试。
- **VBA 宏有风险。** `.docm` / `.xlsm` / `.pptm` 的宏经往返可能丢失或失效。
  报告的「含宏」列会标出这些文件,建议加密后逐个验证。
- **不能远程撤销密码。** 格式级密码只防「拿到文件但没有密码」,
  不防拥有密码的人,也不控制打印、复制粘贴、截图。
- **需要本机装 LibreOffice**,不是纯 Python 实现。

---

## 文件

```
batchtool/
├── gui.py         图形界面
├── encryptor.py   引擎 + 命令行
├── run.bat        Windows 启动器
└── README.md
```
