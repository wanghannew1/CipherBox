#!/usr/bin/env python3
"""
lo_password_probe.py — 验证 LibreOffice 原生口令加密的 .docx/.xlsx
能否作为「格式级密文」穿透到 FAT32 / exFAT / U 盘。

要回答的唯一问题：
    EFS 的两个痛点（证书丢失、拷贝到 FAT32 落明文）
    能否被「密文封装在文件格式内部」这一做法同时绕开？

方法（6 步）：
    1. 生成带唯一哨兵明文的 .docx / .xlsx
    2. 用 LO 原生「另存为 + 设密码」重新保存为密文
    3. 嗅探容器魔数：明文 OOXML = PK(ZIP)；密文 OOXML = D0CF11E0(OLE2/CFB)
    4. 原样复制到 FAT32 介质
    5. 对 FAT32 副本做三态开箱：无密码 / 错密码 / 正确密码
    6. 输出 JSON 报告并清理

用法：
    python3 lo_password_probe.py --workdir /tmp/loprobe --fat32 /mnt/m
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import uuid
import zipfile
from pathlib import Path

import uno
from com.sun.star.beans import PropertyValue

# ---------------------------------------------------------------- 常量

IS_WINDOWS = os.name == "nt"

# Windows 下 soffice 不在 PATH，需回退到默认安装路径
_WINDOWS_SOFFICE_CANDIDATES = [
    r"C:\Program Files\LibreOffice\program\soffice.exe",
    r"C:\Program Files (x86)\LibreOffice\program\soffice.exe",
]


def _find_soffice() -> str:
    found = shutil.which("soffice") or shutil.which("soffice.exe")
    if found:
        return found
    if IS_WINDOWS:
        for cand in _WINDOWS_SOFFICE_CANDIDATES:
            if Path(cand).exists():
                return cand
    return "/usr/bin/soffice"


SOFFICE = _find_soffice()
PORT = int(os.environ.get("LOPROBE_PORT", "2083"))

DEFAULT_WORKDIR = r"C:\loprobe" if IS_WINDOWS else "/tmp/loprobe"

# OOXML 容器魔数
MAGIC_ZIP = b"PK\x03\x04"          # 明文 .docx/.xlsx = 普通 ZIP
MAGIC_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # 加密 .docx/.xlsx = OLE2/CFB

TARGETS = [
    {"key": "docx", "filter": "MS Word 2007 XML", "ext": ".docx"},
    {"key": "xlsx", "filter": "Calc MS Excel 2007 XML", "ext": ".xlsx"},
]


def pv(name, value):
    p = PropertyValue()
    p.Name = name
    p.Value = value
    return p


# ---------------------------------------------------------------- soffice 生命周期


def port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        return s.connect_ex(("127.0.0.1", port)) == 0


def start_soffice(profile: Path):
    """以独立 profile 启动 headless soffice 并挂 UNP socket。"""
    if port_open(PORT):
        return None  # 复用已在运行的实例

    profile_url = uno.systemPathToFileUrl(str(profile))
    cmd = [
        SOFFICE,
        f"-env:UserInstallation={profile_url}",
        "--headless", "--invisible", "--nologo", "--nodefault",
        "--norestore", "--nolockcheck",
        f"--accept=socket,host=127.0.0.1,port={PORT};urp;",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    for _ in range(60):  # 最多等 30s
        if port_open(PORT):
            return proc
        # Windows 下 soffice.exe 会派生 soffice.bin 后立即退出，
        # 因此进程结束不等于启动失败，只在未监听端口时才报错。
        if proc.poll() is not None and not IS_WINDOWS:
            err = (proc.stderr.read() or b"").decode(errors="replace")
            raise RuntimeError(f"soffice 启动失败: {err[:500]}")
        time.sleep(0.5)
    raise RuntimeError("soffice 30s 内未监听 UNP 端口")


def connect():
    local = uno.getComponentContext()
    resolver = local.ServiceManager.createInstanceWithContext(
        "com.sun.star.bridge.UnoUrlResolver", local
    )
    last = None
    for _ in range(40):
        try:
            ctx = resolver.resolve(
                f"uno:socket,host=127.0.0.1,port={PORT};urp;StarOffice.ComponentContext"
            )
            smgr = ctx.ServiceManager
            return smgr, smgr.createInstanceWithContext(
                "com.sun.star.frame.Desktop", ctx
            )
        except Exception as e:  # noqa: BLE001 - 重试竞态
            last = e
            time.sleep(0.5)
    raise RuntimeError(f"无法连接 UNO: {last}")


# ---------------------------------------------------------------- 容器嗅探


def sniff(path: Path) -> dict:
    raw = path.read_bytes()
    magic = raw[:8]
    if raw.startswith(MAGIC_ZIP):
        kind = "ZIP"
    elif raw.startswith(MAGIC_OLE):
        kind = "OLE2"
    else:
        kind = "UNKNOWN"
    return {
        "magic_hex": magic.hex(),
        "container": kind,
        "encrypted": kind == "OLE2",
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def contains(path: Path, needle: bytes) -> bool:
    """在**原始字节**里找哨兵。仅对 OLE2(密文)容器有效：
    ZIP 内文本被 deflate 压缩，明文不在原始字节中。"""
    return needle in path.read_bytes()


def zip_contains(path: Path, needle: bytes) -> bool:
    """解压 ZIP 后找哨兵。用作**阳性对照**：证明检测器本身有效，
    否则「密文里找不到哨兵」可能只是检测器坏了。"""
    try:
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                try:
                    if needle in z.read(name):
                        return True
                except Exception:  # noqa: BLE001 - 跳过无法解压的条目
                    continue
    except zipfile.BadZipFile:
        return False
    return False


# ---------------------------------------------------------------- 文档构造


def build_plain_doc(desktop, out_url: str, target: dict, sentinel: str):
    """生成明文文档并写入哨兵。"""
    if target["key"] == "docx":
        doc = desktop.loadComponentFromURL(
            "private:factory/swriter", "_blank", 0,
            (pv("Hidden", True),)
        )
        doc.Text.setString(sentinel)
    else:
        doc = desktop.loadComponentFromURL(
            "private:factory/scalc", "_blank", 0,
            (pv("Hidden", True),)
        )
        doc.Sheets.getByIndex(0).getCellByPosition(0, 0).setString(sentinel)

    doc.storeToURL(out_url, (
        pv("FilterName", target["filter"]),
        pv("Overwrite", True),
    ))
    doc.close(True)
    return out_url


def build_encrypted_doc(desktop, src_url: str, out_url: str,
                        target: dict, password: str):
    """走 LO 原生「另存为 + 设密码」路径。

    实测结论（5 变体对照，见报告）：OOXML 导出**只认 MediaDescriptor 顶层的
    `Password` 属性**。放进 `FilterData.Password` 或 `FilterData.EncryptionData`
    会被**静默忽略**，产出仍是明文 ZIP —— 这是本脚本第一版的真实 bug。
    """
    doc = desktop.loadComponentFromURL(src_url, "_blank", 0, (pv("Hidden", True),))
    try:
        doc.storeToURL(out_url, (
            pv("FilterName", target["filter"]),
            pv("Overwrite", True),
            pv("Password", password),
        ))
    finally:
        doc.close(True)
    return out_url


def extract_text(doc) -> str:
    """兼容 Writer / Calc 取回哨兵文本。"""
    try:
        if doc.supportsService("com.sun.star.text.TextDocument"):
            return str(doc.Text.getString())
    except Exception:  # noqa: BLE001
        pass
    try:
        return str(doc.Sheets.getByIndex(0).getCellByPosition(0, 0).getString())
    except Exception:  # noqa: BLE001
        return ""


def try_open(desktop, url: str, password: str | None) -> dict:
    """尝试打开受保护文档。

    密码错误/缺失时 LibreOffice 可能抛异常，也可能返回一个「打不开内容」的
    骨架文档。因此「打不开」判定为：抛异常，或取回的文本里没有内容。
    """
    props = [pv("Hidden", True), pv("ReadOnly", True)]
    if password is not None:
        props.append(pv("Password", password))

    doc = None
    try:
        doc = desktop.loadComponentFromURL(url, "_blank", 0, tuple(props))
        text = extract_text(doc)
        return {"opened": True, "error": None, "text": text}
    except Exception as e:  # noqa: BLE001 - 预期内的密码错误
        return {"opened": False, "error": type(e).__name__, "text": None}
    finally:
        if doc is not None:
            try:
                doc.close(True)
            except Exception:  # noqa: BLE001
                pass


# ---------------------------------------------------------------- 主流程


def probe(desktop, workdir: Path, fat32: Path | None, password: str) -> dict:
    sentinel = f"CANARY-{uuid.uuid4().hex[:12]}-DO-NOT-LEAK"
    needle = sentinel.encode("ascii")
    results = []

    for target in TARGETS:
        key = target["key"]
        stem = f"probe-{key}"
        plain_p = workdir / f"{stem}-plain{target['ext']}"
        enc_p = workdir / f"{stem}-enc{target['ext']}"
        rec: dict = {"format": key, "sentinel": sentinel}

        # 1 + 2: 明文 → 密文
        build_plain_doc(desktop, uno.systemPathToFileUrl(str(plain_p)), target, sentinel)
        build_encrypted_doc(
            desktop,
            uno.systemPathToFileUrl(str(plain_p)),
            uno.systemPathToFileUrl(str(enc_p)),
            target, password,
        )

        # 3: 容器嗅探 + 哨兵泄漏检查
        # 明文 ZIP 必须用 zip_contains 做**阳性对照**（证明检测器有效），
        # 因为文本被 deflate 压缩，原始字节里本来就没有哨兵。
        rec["plain"] = sniff(plain_p)
        rec["plain"]["canary_found_in_zip"] = zip_contains(plain_p, needle)
        rec["plain"]["canary_leaked"] = contains(plain_p, needle)
        # 密文 OLE2：EncryptedPackage 内是真密文，原始字节里绝不该有哨兵
        rec["enc"] = sniff(enc_p)
        rec["enc"]["canary_leaked"] = contains(enc_p, needle)

        # 4: 复制到 FAT32
        if fat32 and fat32.is_dir():
            dst_dir = fat32 / "lo-probe"
            dst_dir.mkdir(exist_ok=True)
            dst = dst_dir / enc_p.name
            shutil.copy2(enc_p, dst)
            rec["fat32"] = sniff(dst)
            rec["fat32"]["canary_leaked"] = contains(dst, needle)
            rec["fat32"]["path"] = str(dst)
            rec["fat32"]["byte_identical"] = (
                rec["fat32"]["sha256"] == rec["enc"]["sha256"]
            )
            probe_file = dst
        else:
            rec["fat32"] = None
            probe_file = enc_p

        # 5: 三态开箱（针对 FAT32 副本）
        url = uno.systemPathToFileUrl(str(probe_file))
        rec["open_no_password"] = try_open(desktop, url, None)
        rec["open_wrong_password"] = try_open(desktop, url, password + "-WRONG")
        ok = try_open(desktop, url, password)
        rec["open_correct_password"] = {
            "opened": ok["opened"],
            "error": ok["error"],
            "recovered_canary": (ok["text"] or "").find(sentinel) >= 0,
        }
        results.append(rec)

    verdict = decide(results, fat32)
    return {
        "verdict": verdict,
        "password_length": len(password),
        "results": results,
    }


def cleanup(workdir: Path, fat32: Path | None) -> list[str]:
    """删除样本。必须在 soffice 退出之后调用，否则 Windows 上文件被句柄锁住，
    rmtree 会静默失败，导致密文残留在可移动介质上。返回失败项描述。"""
    problems: list[str] = []

    for p in workdir.glob("probe-*"):
        try:
            p.unlink()
        except OSError as e:
            problems.append(f"未删除 {p}: {e}")

    if fat32 and (fat32 / "lo-probe").is_dir():
        try:
            shutil.rmtree(fat32 / "lo-probe")
        except OSError as e:
            problems.append(
                f"未删除 {fat32 / 'lo-probe'}: {e} —— "
                f"密文可能残留在可移动介质上，请手动删除"
            )

    return problems


def decide(results: list[dict], fat32: Path | None) -> dict:
    """把观测收敛成结论。"""
    checks = {}

    for r in results:
        k = r["format"]
        checks[f"{k}_plain_is_zip"] = not r["plain"]["encrypted"]
        checks[f"{k}_detector_works"] = r["plain"]["canary_found_in_zip"]
        checks[f"{k}_enc_is_ole"] = r["enc"]["encrypted"]
        checks[f"{k}_enc_no_canary"] = not r["enc"]["canary_leaked"]
        if r["fat32"]:
            checks[f"{k}_fat32_is_ole"] = r["fat32"]["encrypted"]
            checks[f"{k}_fat32_no_canary"] = not r["fat32"]["canary_leaked"]
            checks[f"{k}_fat32_byte_identical"] = r["fat32"]["byte_identical"]
        checks[f"{k}_blocked_without_pw"] = not r["open_no_password"]["opened"]
        checks[f"{k}_blocked_wrong_pw"] = not r["open_wrong_password"]["opened"]
        checks[f"{k}_opens_with_pw"] = r["open_correct_password"]["opened"]
        checks[f"{k}_recovers_canary"] = r["open_correct_password"]["recovered_canary"]

    all_ok = all(checks.values())

    if fat32:
        survived = all(
            r["fat32"] and r["fat32"]["encrypted"] and not r["fat32"]["canary_leaked"]
            and r["fat32"]["byte_identical"]
            for r in results
        )
        headline = (
            "PASS: 格式级密文可穿透 FAT32 —— EFS 的两项痛点均可被此机制绕开"
            if (all_ok and survived)
            else "PARTIAL/FAIL: 见下方逐项检查"
        )
    else:
        headline = "PASS(仅容器级): 密文成立，但未测跨介质" if all_ok else "FAIL"

    return {"all_checks_passed": all_ok, "headline": headline, "checks": checks}


# ---------------------------------------------------------------- CLI


def main() -> int:
    global PORT

    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir", default=DEFAULT_WORKDIR)
    ap.add_argument("--fat32", default="/mnt/m", help="FAT32 挂载点；空字符串则跳过")
    ap.add_argument("--password", default="Pr0be-Passw0rd!2026")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--keep", action="store_true", help="保留中间文件")
    ap.add_argument("--json", default="", help="报告写入路径")
    args = ap.parse_args()

    PORT = args.port

    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    profile = workdir / "loprofile"
    profile.mkdir(exist_ok=True)
    fat32 = Path(args.fat32) if args.fat32 else None

    proc = start_soffice(profile)
    try:
        _, desktop = connect()
        report = probe(desktop, workdir, fat32, args.password)
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()

    if not args.keep:
        problems = cleanup(workdir, fat32)
        if problems:
            report["cleanup_problems"] = problems
            for msg in problems:
                print(f"清理失败: {msg}", file=sys.stderr)

    text = json.dumps(report, indent=2, ensure_ascii=False)
    if args.json:
        Path(args.json).write_text(text, encoding="utf-8")
    print(text)

    return 0 if report["verdict"]["all_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
