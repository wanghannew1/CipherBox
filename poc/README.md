# lo_password_probe — LibreOffice 格式级加密验证程序

验证一个技术问题：**把 `.docx` / `.xlsx` 的密文封装在文件格式内部，能否穿透到 FAT32 / exFAT / U 盘。**

这是 EFS 的两个已知痛点的候选解法：

| EFS 痛点 | 格式级密文是否解决 |
|---|---|
| 证书 / 用户配置文件丢失 → 文件永久不可读 | ✅ 不依赖证书，密码可服务端托管 |
| 授权用户拷到 FAT32/exFAT → 副本落成明文 | ✅ 密文在文件内部，介质无从解密 |

程序会生成带唯一哨兵明文的文档，走 LibreOffice 原生「设密码保存」，
嗅探容器魔数，复制到目标介质，再做三态开箱测试，输出 JSON 报告。

---

## 它证明了什么 / 没证明什么

**已实测证明（本机 22/22 通过）**

- LO 原生设密码保存产出 **OLE2/CFB 容器**（`d0cf11e0`），而非明文 ZIP
- 哨兵明文**不出现在密文原始字节**中
- 复制到 FAT32 后**逐字节一致**（SHA-256 相同），仍为 OLE2，哨兵仍不泄漏
- 无密码、错密码均被拒绝；正确密码可打开且哨兵完整还原

**没有证明（别当成已解决）**

- ❌ **Microsoft Word / WPS 能否打开这些文件** —— 本测试是 LibreOffice 读自己写的文件，跨应用互操作属未知
- ❌ **「无感打开」** —— 这是文件口令，用户仍需输密码，不是策略透明解密
- ❌ **远程吊销** —— 对方拿到文件 + 密码即永久可解。EFS 可以吊销证书做到即时失效，文件密码**做不到**
- ❌ **exFAT / 真实 U 盘** —— 仅测了 FAT32
- ❌ **禁打印 / 禁复制粘贴 / 禁截图** —— 文件密码一概不管

> 路线判断请先看 `evidence/lo-password-probe-report.json` 与本文件末节。

---

## 环境要求

| 依赖 | 验证命令 | 本机实测版本 |
|---|---|---|
| LibreOffice | `soffice --version` | 24.2.7.2 |
| python3-uno | `python3 -c "import uno"` | 4:24.2.7-0ubuntu0.24.04.6 |
| Python | `python3 --version` | 3.12 |

安装（Ubuntu/Debian）：

```bash
sudo apt install libreoffice-writer libreoffice-calc python3-uno
```

必须装 `python3-uno` —— 只有 `libreoffice-core` 时 `import uno` 会失败。
注意 `libreoffice-writer` / `libreoffice-calc` 用于创建文档，缺了会失败。

---

## 快速开始

```bash
# 在项目根目录
python3 poc/lo_password_probe.py --workdir /tmp/loprobe --fat32 /mnt/m
```

退出码 **0 = 全部检查通过**，**1 = 至少一项失败**（可直接用于 CI 判定）。

带 FAT32 介质与 JSON 报告的完整用法：

```bash
python3 poc/lo_password_probe.py \
    --workdir /tmp/loprobe \
    --fat32   /mnt/m \
    --json    evidence/lo-password-probe-report.json
```

只验证容器级加密、不测跨介质（不需要挂载可移动盘）：

```bash
python3 poc/lo_password_probe.py --fat32 "" --workdir /tmp/loprobe
```

---

## 命令行参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--workdir` | `/tmp/loprobe` | 中间文件与 soffice profile 目录 |
| `--fat32` | `/mnt/m` | 跨介质测试目标挂载点；传空字符串 `""` 则跳过 |
| `--password` | `Pr0be-Passw0rd!2026` | 加密口令。**仅测试用，勿用于生产** |
| `--port` | `2083` | soffice UNP 端口。若该端口已有 soffice 实例会直接复用 |
| `--keep` | 关 | 保留明文/密文中间文件，便于手工取证 |
| `--json` | 空 | 报告写入路径；不指定则只打印到 stdout |

### 清理行为

不加 `--keep` 时会自动删除：

- `<workdir>/probe-*`（明文与密文样本）
- `<fat32>/lo-probe/`（跨介质副本）

**不会**删除 `<workdir>/loprofile/`（soffice profile，体积较大）。手动清理：

```bash
rm -rf /tmp/loprobe
```

---

## 读懂输出

```jsonc
{
  "verdict": {
    "all_checks_passed": true,
    "headline": "PASS: 格式级密文可穿透 FAT32 ...",
    "checks": { "docx_enc_is_ole": true, ... }   // docx 11 + xlsx 11
  },
  "results": [ { "format": "docx", "plain": {...}, "enc": {...}, "fat32": {...},
                 "open_no_password": {...}, ... } ]
}
```

`checks` 的条数取决于是否测跨介质：**含 FAT32 时 22 项**（docx 11 + xlsx 11），
**`--fat32 ""` 跳过时 16 项**（每格式去掉 3 项 `*_fat32_*`）。

关键字段：

| 字段 | 含义 |
|---|---|
| `plain.container` | 应为 `ZIP`（明文 OOXML 就是普通 zip） |
| `plain.canary_found_in_zip` | **阳性对照**。解压后必须能找到哨兵 —— 用来证明检测器本身有效 |
| `enc.container` | 应为 `OLE2`，`encrypted: true` |
| `enc.canary_leaked` | 必须为 `false` |
| `fat32.byte_identical` | 副本 SHA-256 与源文件相同 |
| `open_no_password.opened` | 必须为 `false` |
| `open_wrong_password.opened` | 必须为 `false` |
| `open_correct_password.recovered_canary` | 必须为 `true` |

> `plain.canary_found_in_zip` 是**阳性对照**，不是泄漏检查。明文 zip 内文本被 deflate
> 压缩，哨兵本就不在原始字节里；直接对明文做原始字节搜索会得到「未找到」的假阴性，
> 从而掩盖真正的检测器故障。

---

## 踩过的坑（供二次开发参考）

### 1. OOXML 加密只认顶层 `Password` 属性

这是最容易把人带进沟里的地方。实测 5 个变体：

| 变体 | 结果 |
|---|---|
| `storeToURL` + 顶层 `Password` | ✅ OLE2 / 加密 |
| `storeToURL` + `FilterData.Password` | ❌ 明文 ZIP |
| `storeToURL` + `FilterData.EncryptionData` | ❌ 明文 ZIP |
| `storeAsURL` + 顶层 `Password` | ✅ OLE2 / 加密 |
| `storeAsURL` + `FilterData.EncryptionData` | ❌ 明文 ZIP |

**失败路径不报错、不警告，文件照旧落成明文 ZIP。** 网上流传的
`FilterData` / `EncryptionData` 写法在 OOXML 导出上无效 —— 用它会得出
「LibreOffice 做不了格式级加密」的错误结论。

正确写法：

```python
doc.storeToURL(out_url, (
    pv("FilterName", "MS Word 2007 XML"),
    pv("Overwrite", True),
    pv("Password", password),      # ← 顶层，不是 FilterData
))
```

### 2. 自研加密（`XPackageEncryption`）是另一条路

若要实现**策略透明解密**（无感打开），得走 `com.sun.star.packages::XPackageEncryption`。
但它的 IDL 方法是 `generateEncryptionKey(password)` / `createEncryptionData(password)` ——
**口令形，不是密钥注入**。想自己实现就必须自己写 ECMA-376 Agile 密码学，
LO 内部的 `oox::crypto::AgileEngine` 不在公开 SDK 里。本 PoC 走的是**原生另存为**路径，
与之无关，两者不可混谈。

### 3. WSL 下看不到 EFS 密文

`/mnt/c` 是 9p/drvfs 桥接，会透明返回明文，**不能**用它验证盘上原始字节。
判 EFS 是否生效只能靠 `cipher /c` 和文件属性。格式级密文则不受此限制，
因为密文就在文件内部，`/mnt/m` 读到的就是真密文（本 PoC 依赖这一点）。

---

## 在 Windows 上复跑

本机 Windows 侧**未安装 LibreOffice**，所以这份报告的 Word/WPS 互操作性是空白。
要验证 Windows 原生行为：

1. Windows 装 LibreOffice（含 `python.exe` 与 UNO 桥接）
2. 用 Windows 的 python 执行本脚本，或在 WSL 里装 `libreoffice-writer libreoffice-calc python3-uno`
3. 拿一份 Windows 生成的加密 docx 交给 Word / WPS 打开，验证是否提示密码、能否正常读取

```bash
# Windows 侧路径写法（WSL 下的等价形式）
python3 poc/lo_password_probe.py --workdir /tmp/loprobe --fat32 /mnt/e
```

---

## 结论边界

这个 PoC 回答的是「**密文能否穿透 FAT32**」，答案是**能**。

它没有回答、也回答不了的是「**能否远程撤销外发的文档**」—— 答案明确是**不能**。

EFS 与文件口令加密属于同一档：都是被动落盘加密，都不执行策略，都管不了打印和复制。
格式级密文相对 EFS 是**横向平移**（用密码换证书，丢掉可吊销性），不是能力升级。

若「远程撤销 / 外发审批」是硬需求，能同时满足「无感打开 + 可吊销」的路径是
**Microsoft Office 原生 RMS**（`IrmsProtector`，Word/Excel 原生支持），或采购持牌 DRM 厂商。
