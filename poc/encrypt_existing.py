#!/usr/bin/env python3
"""
encrypt_existing.py — 用 LibreOffice 原生口令加密现有 .docx/.xlsx 文件。

与 lo_password_probe.py 同一条技术路径：LO 打开文档 → storeToURL 带顶层
Password → OOXML 导出过滤器施加 ECMA-376 Agile 加密 → 产出 OLE2/CFB 容器。

⚠️ 重要风险：LO 会**重写整个文件**。复杂文档经往返后排版可能偏移、字体替换、
   VBA 宏丢失、修订/批注损坏。加密成功 ≠ 内容保真，务必人工比对。
   另：原文件**不会被修改**，新密文另存。明文原件需自行删除。

用法：
    python3 encrypt_existing.py 输入文件 -o 输出文件 -p 密码
    python3 encrypt_existing.py 输入文件 -o 输出文件 -p 密码 --keep-open
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import uno
from com.sun.star.beans import PropertyValue

IS_WINDOWS = os.name == "nt"
PORT = int(os.environ.get("ENCRYPT_PORT", "2091"))

_WINDOWS_SOFFICE = [
    r"C:\Program Files\LibreOffice\program\soffice.exe",
    r"C:\Program Files (x86)\LibreOffice\program\soffice.exe",
]

MAGIC_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

FILTERS = {
    ".docx": "MS Word 2007 XML",
    ".docm": "MS Word 2007 VBA XML",
    ".xlsx": "Calc MS Excel 2007 XML",
    ".xlsm": "Calc MS Excel 2007 VBA XML",
    ".pptx": "Impress MS PowerPoint 2007 XML",
    ".odt": "writer8",
    ".ods": "calc8",
    ".odp": "impress8",
}


def _find_soffice() -> str:
    found = shutil.which("soffice") or shutil.which("soffice.exe")
    if found:
        return found
    if IS_WINDOWS:
        for c in _WINDOWS_SOFFICE:
            if Path(c).exists():
                return c
    return "/usr/bin/soffice"


SOFFICE = _find_soffice()


def pv(name, value):
    p = PropertyValue()
    p.Name = name
    p.Value = value
    return p


def _port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        return s.connect_ex(("127.0.0.1", port)) == 0


def start_soffice(profile: Path):
    if _port_open(PORT):
        return None
    cmd = [
        SOFFICE,
        f"-env:UserInstallation={uno.systemPathToFileUrl(str(profile))}",
        "--headless", "--invisible", "--nologo", "--nodefault",
        "--norestore", "--nolockcheck",
        f"--accept=socket,host=127.0.0.1,port={PORT};urp;",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(60):
        if _port_open(PORT):
            return proc
        if proc.poll() is not None and not IS_WINDOWS:
            err = (proc.stderr.read() or b"").decode(errors="replace")
            raise RuntimeError(f"soffice 启动失败: {err[:400]}")
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
            return smgr.createInstanceWithContext("com.sun.star.frame.Desktop", ctx)
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(0.5)
    raise RuntimeError(f"无法连接 UNO: {last}")


def main() -> int:
    global PORT

    ap = argparse.ArgumentParser()
    ap.add_argument("input", help="待加密的源文件")
    ap.add_argument("-o", "--output", required=True, help="密文输出路径")
    ap.add_argument("-p", "--password", required=True, help="加密口令")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--workdir", default="", help="soffice profile 目录")
    args = ap.parse_args()

    PORT = args.port

    src = Path(args.input).resolve()
    dst = Path(args.output).resolve()

    if not src.is_file():
        print(f"错误：源文件不存在 -> {src}", file=sys.stderr)
        return 2

    ext = src.suffix.lower()
    if ext not in FILTERS:
        print(f"错误：不支持的扩展名 {ext}", file=sys.stderr)
        print(f"支持：{', '.join(sorted(FILTERS))}", file=sys.stderr)
        return 2

    if src.read_bytes()[:8] == MAGIC_OLE:
        print("错误：源文件已是 OLE2 容器，可能已加密，请先解密。", file=sys.stderr)
        return 2

    if dst == src:
        print("错误：输出路径不能与源文件相同（原文件不会被覆盖）。", file=sys.stderr)
        return 2

    dst.parent.mkdir(parents=True, exist_ok=True)
    workdir = Path(args.workdir) if args.workdir else (
        (Path(r"C:\loenc") if IS_WINDOWS else Path("/tmp/loenc"))
    )
    workdir.mkdir(parents=True, exist_ok=True)
    profile = workdir / "profile"
    profile.mkdir(exist_ok=True)

    print(f"源文件  : {src}  ({src.stat().st_size} B)")
    print(f"输出    : {dst}")
    print(f"格式    : {ext} -> {FILTERS[ext]}")
    print(f"过滤器  : {SOFFICE}")
    print()

    proc = start_soffice(profile)
    try:
        desktop = connect()
        doc = desktop.loadComponentFromURL(
            uno.systemPathToFileUrl(str(src)), "_blank", 0, (pv("Hidden", True),)
        )
        if doc is None:
            print("错误：LibreOffice 无法打开该文件（可能已损坏或格式不受支持）。", file=sys.stderr)
            return 3
        try:
            doc.storeToURL(uno.systemPathToFileUrl(str(dst)), (
                pv("FilterName", FILTERS[ext]),
                pv("Overwrite", True),
                pv("Password", args.password),
            ))
        finally:
            doc.close(True)
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()

    if not dst.is_file():
        print("错误：未生成输出文件。", file=sys.stderr)
        return 3

    raw = dst.read_bytes()
    ok = raw[:8] == MAGIC_OLE

    print("=" * 60)
    if ok:
        print("✅ 加密成功：输出为 OLE2/CFB 加密容器")
    else:
        print("❌ 加密未生效：输出仍是明文容器，请检查 UNO Password 属性位置")
    print(f"   大小      : {src.stat().st_size} B -> {len(raw)} B")
    print(f"   魔数      : {raw[:8].hex()}")
    print()
    print("⚠️  请人工确认以下事项（本工具无法自动判定）：")
    print("   1. 用 Word/Excel 打开密文，验证内容与排版和原文件一致")
    print("   2. 字体、图片、表格、公式、页眉页脚是否错位")
    print("   3. VBA 宏 / 修订 / 批注 / 嵌入对象是否丢失")
    print(f"   4. 删除明文原件：{src}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
