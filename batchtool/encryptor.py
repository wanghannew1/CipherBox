#!/usr/bin/env python3
"""
encryptor.py — 批量文档加密引擎（LibreOffice 原生 ECMA-376 Agile 加密）

支持 Word / Excel / PowerPoint（以及 ODF）。核心机制与 encrypt_existing.py 相同：
LO 打开文档 → storeToURL 带**顶层** Password → OOXML 导出过滤器施加加密 → 写出 OLE2/CFB。

⚠️ 关键：Password 必须放在 MediaDescriptor 顶层。放进 FilterData.Password 或
   FilterData.EncryptionData 会被 LibreOffice 静默忽略，产出仍是明文容器。

跨平台：GUI 通常跑在系统 Python（有 tkinter 但通常无 uno），而加密需要 uno。
   本模块检测到缺 uno 时，会自动用 LibreOffice 自带的 python 以 worker 模式
   重新执行自身，因此对调用方透明。

命令行（无需 GUI）：
    python3 encryptor.py --input DIR --password PW [--flat] [--mode copy|overwrite]
    python3 encryptor.py --input FILE1 FILE2 --password PW --mode copy --out OUTDIR
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import datetime
from pathlib import Path

MAGIC_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

# 扩展名 -> LO 导出过滤器。顺序无关。
FILTERS: dict[str, str] = {
    ".docx": "MS Word 2007 XML",
    ".docm": "MS Word 2007 VBA XML",
    ".xlsx": "Calc MS Excel 2007 XML",
    ".xlsm": "Calc MS Excel 2007 VBA XML",
    ".pptx": "Impress MS PowerPoint 2007 XML",
    ".pptm": "Impress MS PowerPoint 2007 VBA XML",
    ".odt": "writer8",
    ".ods": "calc8",
    ".odp": "impress8",
}

EXT_LABEL = {
    "word": [".docx", ".docm", ".odt"],
    "excel": [".xlsx", ".xlsm", ".ods"],
    "ppt": [".pptx", ".pptm", ".odp"],
}

IS_WINDOWS = os.name == "nt"
PORT = int(os.environ.get("BATCHENC_PORT", "2095"))

_WINDOWS_SOFFICE_CANDIDATES = [
    r"C:\Program Files\LibreOffice\program\soffice.exe",
    r"C:\Program Files (x86)\LibreOffice\program\soffice.exe",
]

_WINDOWS_LO_PYTHON_CANDIDATES = [
    r"C:\Program Files\LibreOffice\program\python.exe",
    r"C:\Program Files (x86)\LibreOffice\program\python.exe",
]

# VBA 宏格式——往返极可能丢宏，报告中需特别标注
MACRO_EXTS = {".docm", ".xlsm", ".pptm"}


def log(msg: str) -> None:
    print(msg, flush=True)


# ---------------------------------------------------------------- LibreOffice 定位


def find_soffice() -> str | None:
    found = shutil.which("soffice") or shutil.which("soffice.exe")
    if found:
        return found
    for cand in _WINDOWS_SOFFICE_CANDIDATES:
        if IS_WINDOWS and Path(cand).exists():
            return cand
    for cand in ("/usr/bin/soffice", "/usr/lib/libreoffice/program/soffice",
                 "/snap/bin/libreoffice"):
        if Path(cand).exists():
            return cand
    return None


def find_lo_python() -> str | None:
    """LibreOffice 自带的 python——Windows 上它才有 uno。"""
    if IS_WINDOWS:
        for cand in _WINDOWS_LO_PYTHON_CANDIDATES:
            if Path(cand).exists():
                return cand
    for cand in ("/usr/lib/libreoffice/program/python",
                 "/usr/lib/libreoffice/program/python.bin"):
        if Path(cand).exists() and os.access(cand, os.X_OK):
            return cand
    return None


def have_uno() -> bool:
    try:
        import uno  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------- 文件发现


def discover(inputs: list[Path], flat: bool, kinds: list[str]) -> list[Path]:
    """收集待加密文件。

    flat=False -> inputs 下**全部**子目录递归
    flat=True  -> 仅 inputs 所在**当前层**，不进入子目录
    """
    wanted: set[str] = set()
    for k in kinds:
        wanted.update(EXT_LABEL.get(k, []))

    found: list[Path] = []
    seen: set[Path] = set()

    for src in inputs:
        if src.is_file():
            if src.suffix.lower() in wanted and src.resolve() not in seen:
                seen.add(src.resolve())
                found.append(src)
            continue
        if not src.is_dir():
            log(f"跳过（不存在）: {src}")
            continue
        walker = src.iterdir() if flat else src.rglob("*")
        for p in walker:
            if not p.is_file():
                continue
            if p.suffix.lower() not in wanted:
                continue
            # 加密后的产物是 OLE2，不再重复处理
            if p.suffix.lower() in wanted and _is_encrypted(p):
                continue
            r = p.resolve()
            if r not in seen:
                seen.add(r)
                found.append(p)

    return sorted(found, key=lambda x: str(x).lower())


def _is_encrypted(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(8) == MAGIC_OLE
    except OSError:
        return False


# ---------------------------------------------------------------- soffice 会话


class Office:
    """单个 soffice 实例，整批复用（批量场景下逐个启动会非常慢）。"""

    def __init__(self, port: int, profile: Path | None = None):
        self.port = port
        self.profile = profile
        self.proc: subprocess.Popen | None = None
        self.desktop = None

    def _port_open(self) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            return s.connect_ex(("127.0.0.1", self.port)) == 0

    def __enter__(self):
        soffice = find_soffice()
        if not soffice:
            raise RuntimeError(
                "未找到 LibreOffice。请先安装：\n"
                "  Windows: https://www.libreoffice.org/download/\n"
                "  Debian/Ubuntu: sudo apt install libreoffice-writer libreoffice-calc libreoffice-impress"
            )

        import uno  # 仅在确认有 uno 的解释器里执行到这里

        if not self._port_open():
            if self.profile is None:
                self.profile = Path(tempfile.mkdtemp(prefix="batchenc-prof-"))
            cmd = [
                soffice,
                f"-env:UserInstallation={uno.systemPathToFileUrl(str(self.profile))}",
                "--headless", "--invisible", "--nologo", "--nodefault",
                "--norestore", "--nolockcheck",
                f"--accept=socket,host=127.0.0.1,port={self.port};urp;",
            ]
            self.proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
            )

        local = uno.getComponentContext()
        resolver = local.ServiceManager.createInstanceWithContext(
            "com.sun.star.bridge.UnoUrlResolver", local
        )
        last = None
        for _ in range(80):  # 40s
            if self._port_open():
                try:
                    ctx = resolver.resolve(
                        f"uno:socket,host=127.0.0.1,port={self.port};urp;"
                        f"StarOffice.ComponentContext"
                    )
                    self.desktop = ctx.ServiceManager.createInstanceWithContext(
                        "com.sun.star.frame.Desktop", ctx
                    )
                    return self
                except Exception as e:  # noqa: BLE001
                    last = e
            time.sleep(0.5)
        raise RuntimeError(f"无法连接 LibreOffice UNO: {last}")

    def __exit__(self, *exc):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self.profile and self.profile.name.startswith("batchenc-prof-"):
            shutil.rmtree(self.profile, ignore_errors=True)
        return False


def _pv(name, value):
    from com.sun.star.beans import PropertyValue
    p = PropertyValue()
    p.Name = name
    p.Value = value
    return p


# ---------------------------------------------------------------- 单文件加密


def encrypt_one(desktop, src: Path, dst: Path, password: str) -> dict:
    """把 src 加密后写到 dst。调用前需确保 dst 不存在。"""
    import uno

    filt = FILTERS.get(src.suffix.lower())
    if not filt:
        raise ValueError(f"不支持的扩展名: {src.suffix}")

    doc = desktop.loadComponentFromURL(
        uno.systemPathToFileUrl(str(src)), "_blank", 0, (_pv("Hidden", True),)
    )
    if doc is None:
        raise RuntimeError("LibreOffice 无法打开该文件（可能已损坏或受密码保护）")
    try:
        doc.storeToURL(uno.systemPathToFileUrl(str(dst)), (
            _pv("FilterName", filt),
            _pv("Overwrite", True),
            _pv("Password", password),
        ))
    finally:
        try:
            doc.close(True)
        except Exception:  # noqa: BLE001
            pass

    if not dst.is_file():
        raise RuntimeError("未生成输出文件")

    raw = dst.read_bytes()[:8]
    if raw != MAGIC_OLE:
        dst.unlink(missing_ok=True)
        raise RuntimeError(
            "加密未生效：输出不是 OLE2 容器。"
            "通常是 UNO 的 Password 属性位置不对（本工具不应出现此问题）"
        )
    return {"filter": filt}


# ---------------------------------------------------------------- 批处理


def plan_outputs(files: list[Path], inputs: list[Path], mode: str,
                 outdir: Path | None) -> list[tuple[Path, Path]]:
    """产出 (源, 目标) 配对。copy 模式保持相对目录结构。"""
    pairs: list[tuple[Path, Path]] = []
    for f in files:
        if mode == "overwrite":
            pairs.append((f, f))
            continue
        if outdir is None:
            raise ValueError("复制模式必须指定输出目录")
        # 相对哪个**目录** input 决定层级。input 本身是文件时不能当基准，
        # 否则 relative_to 返回 "."，目标会退化成输出目录本身。
        base = None
        for ins in inputs:
            if not ins.is_dir():
                continue
            try:
                f.relative_to(ins)
                base = ins
                break
            except ValueError:
                continue
        rel = f.name if base is None else f.relative_to(base)
        pairs.append((f, outdir / rel))
    return pairs


def run_batch(files: list[Path], inputs: list[Path], password: str, mode: str,
              outdir: Path | None, port: int) -> list[dict]:
    pairs = plan_outputs(files, inputs, mode, outdir)
    results: list[dict] = []
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for idx, (src, dst) in enumerate(pairs, 1):
        rec: dict = {
            "序号": idx,
            "文件名": src.name,
            "源路径": str(src),
            "目标路径": str(dst) if dst != src else "(原地覆盖)",
            "扩展名": src.suffix.lower(),
            "密码": password,
            "模式": "覆盖源文件" if mode == "overwrite" else "复制并加密",
            "原始大小": src.stat().st_size if src.is_file() else 0,
            "加密后大小": 0,
            "含宏": "是" if src.suffix.lower() in MACRO_EXTS else "否",
            "结果": "失败",
            "错误信息": "",
            "时间": ts,
        }

        # 覆盖模式：先写同目录临时文件，验证为密文后再原子替换，
        # 避免中途失败把源文件搞坏。
        staging: Path | None = None
        try:
            if mode == "overwrite":
                fd, tmpname = tempfile.mkstemp(
                    prefix=src.stem + ".enc-", suffix=src.suffix,
                    dir=str(src.parent),
                )
                os.close(fd)
                staging = Path(tmpname)
                staging.unlink(missing_ok=True)  # 交给 LO 创建
                real_dst = staging
            else:
                real_dst = dst
                real_dst.parent.mkdir(parents=True, exist_ok=True)
                real_dst.unlink(missing_ok=True)

            with Office(port) as office:
                encrypt_one(office.desktop, src, real_dst, password)

            rec["加密后大小"] = real_dst.stat().st_size

            if mode == "overwrite":
                os.replace(real_dst, src)
                rec["目标路径"] = "(原地覆盖)"
            else:
                rec["目标路径"] = str(dst)

            rec["结果"] = "成功"
            log(f"[{idx}/{len(pairs)}] ✅ {src.name}  "
                f"{rec['原始大小']} → {rec['加密后大小']} B")

        except Exception as e:  # noqa: BLE001 - 单个失败不中断整批
            rec["错误信息"] = f"{type(e).__name__}: {e}"[:300]
            log(f"[{idx}/{len(pairs)}] ❌ {src.name}  {rec['错误信息']}")
            if staging is not None:
                staging.unlink(missing_ok=True)
        finally:
            if staging is not None and staging.exists():
                staging.unlink(missing_ok=True)

        results.append(rec)

    return results


# ---------------------------------------------------------------- 报告输出


REPORT_COLUMNS = [
    "序号", "文件名", "源路径", "目标路径", "扩展名", "密码",
    "模式", "原始大小", "加密后大小", "含宏", "结果", "错误信息", "时间",
]


def write_txt_report(path: Path, results: list[dict], meta: dict, mask: bool) -> None:
    L: list[str] = []
    L.append("=" * 78)
    L.append("批量文档加密报告")
    L.append("=" * 78)
    L.append(f"生成时间   : {meta['ts']}")
    L.append(f"加密密码   : {meta['password_display']}")
    L.append(f"处理模式   : {meta['mode']}")
    L.append(f"扫描范围   : {meta['scope']}")
    L.append(f"输入路径   : {meta['inputs']}")
    if meta.get("outdir"):
        L.append(f"输出目录   : {meta['outdir']}")
    L.append(f"LibreOffice: {meta['soffice']}")
    L.append("")

    ok = sum(1 for r in results if r["结果"] == "成功")
    bad = len(results) - ok
    L.append(f"合计 {len(results)} 个文件：成功 {ok}，失败 {bad}")
    L.append("")
    L.append("-" * 78)
    L.append("")

    for r in results:
        L.append(f"[{r['序号']}] {r['文件名']}")
        L.append(f"    源路径     : {r['源路径']}")
        L.append(f"    目标路径   : {r['目标路径']}")
        L.append(f"    密码       : {r['密码']}")
        L.append(f"    模式       : {r['模式']}    含宏: {r['含宏']}")
        L.append(f"    大小       : {r['原始大小']} B → {r['加密后大小']} B")
        L.append(f"    结果       : {r['结果']}")
        if r["错误信息"]:
            L.append(f"    错误       : {r['错误信息']}")
        L.append("")

    L.append("-" * 78)
    L.append("警告：本报告若含明文密码，等同于一份密码清单。任何拿到本文件的人")
    L.append("      都可打开所有已加密的文档。请与密文分开保管，勿随文档外发。")
    L.append("提醒：LibreOffice 加密不会删除明文原件。复制模式下源文件仍是明文，")
    L.append("      需你自行删除或妥善保管。")
    L.append("=" * 78)

    path.write_text("\n".join(L), encoding="utf-8")


def _xesc(s: str) -> str:
    return (
        str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def write_xlsx_report(path: Path, results: list[dict], meta: dict) -> None:
    """零依赖写 .xlsx（openpyxl 未必存在于用户的系统 Python）。"""
    ok = sum(1 for r in results if r["结果"] == "成功")
    bad = len(results) - ok

    def ref(c_i: int, r_i: int) -> str:
        return f"{chr(ord('A') + c_i)}{r_i}"

    def cell(r_i: int, c_i: int, val, bold: bool = False) -> str:
        style = ' s="1"' if bold else ""
        return (f'<c r="{ref(c_i, r_i)}"{style} t="inlineStr">'
                f'<is><t xml:space="preserve">{_xesc(val)}</t></is></c>')

    summary = (
        f"批量文档加密报告    生成时间 {meta['ts']}    密码 {meta['password_display']}    "
        f"模式 {meta['mode']}    范围 {meta['scope']}    成功 {ok} 失败 {bad}"
    )
    # 行号必须自洽：1=汇总 2=表头 3..=数据
    rows = [f'<row r="1">{cell(1, 0, summary, bold=True)}</row>',
            '<row r="2">' + "".join(
                cell(2, i, c, bold=True) for i, c in enumerate(REPORT_COLUMNS)
            ) + "</row>"]
    for i, r in enumerate(results, start=3):
        rows.append(
            f'<row r="{i}">' + "".join(
                cell(i, j, r.get(c, "")) for j, c in enumerate(REPORT_COLUMNS)
            ) + "</row>"
        )
    # 提醒行置于末尾
    tip = i + 1
    rows.append(
        f'<row r="{tip}">'
        + cell(tip, 0,
               "警告：本表若含明文密码即等同密码清单，请与密文分开保管；"
               "LibreOffice 加密不会删除明文原件，复制模式下源文件仍是明文。")
        + "</row>"
    )

    sheet = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        + "".join(rows) + "</worksheet>"
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
        ' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="加密报告" sheetId="1" r:id="rId1"/></sheets></workbook>'
    )
    wb_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1"'
        ' Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"'
        ' Target="worksheets/sheet1.xml"/></Relationships>'
    )
    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1"'
        ' Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"'
        ' Target="xl/workbook.xml"/></Relationships>'
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels"'
        ' ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '</Types>'
    )
    # CT_Stylesheet 要求子元素按 numFmts→fonts→fills→borders→cellStyleXfs→
    # cellXfs→cellStyles 顺序出现。xf 里的 fillId/borderId 必须指向真实存在的
    # 集合，否则解析器会在展开命名样式时索引越界。
    styles = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
        '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
        '<fills count="2">'
        '<fill><patternFill patternType="none"/></fill>'
        '<fill><patternFill patternType="gray125"/></fill>'
        '</fills>'
        '<borders count="1">'
        '<border><left/><right/><top/><bottom/><diagonal/></border>'
        '</borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
        '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>'
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
        '</styleSheet>'
    )

    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", root_rels)
        z.writestr("xl/workbook.xml", workbook)
        z.writestr("xl/_rels/workbook.xml.rels", wb_rels)
        z.writestr("xl/styles.xml", styles)
        z.writestr("xl/worksheets/sheet1.xml", sheet)


# ---------------------------------------------------------------- worker / 入口


def _mask(pw: str) -> str:
    if not pw:
        return "(空)"
    return pw[0] + "*" * (len(pw) - 2) + pw[-1] if len(pw) > 2 else "*" * len(pw)


def build_meta(inputs, mode, scope, outdir, password, mask) -> dict:
    return {
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "password_display": _mask(password) if mask else password,
        "mode": "覆盖源文件" if mode == "overwrite" else "复制并加密",
        "scope": scope,
        "inputs": "; ".join(str(p) for p in inputs),
        "outdir": str(outdir) if outdir else "",
        "soffice": find_soffice() or "(未找到)",
    }


def do_work(job: dict) -> int:
    """实际执行加密。由具备 uno 的解释器运行。"""
    inputs = [Path(p) for p in job["inputs"]]
    password = job["password"]
    mode = job["mode"]
    outdir = Path(job["outdir"]) if job.get("outdir") else None
    port = int(job.get("port") or PORT)
    mask = bool(job.get("mask"))

    files = discover(inputs, bool(job.get("flat")), job.get("kinds") or ["word", "excel", "ppt"])
    scope = "仅当前层" if job.get("flat") else "全部子目录"
    log(f"扫描到 {len(files)} 个待加密文件（{scope}）")

    if not files:
        log("没有符合条件的文件，未做任何改动。")
        results: list[dict] = []
    else:
        results = run_batch(files, inputs, password, mode, outdir, port)

    report_dir = Path(job.get("report_dir") or ".")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    meta = build_meta(inputs, mode, scope, outdir, password, mask)

    ok = sum(1 for r in results if r["结果"] == "成功")
    bad = len(results) - ok

    if job.get("txt", True):
        p = report_dir / f"加密报告-{stamp}.txt"
        write_txt_report(p, results, meta, mask)
        log(f"报告(TXT) : {p}")
    if job.get("xlsx", True):
        p = report_dir / f"加密报告-{stamp}.xlsx"
        try:
            write_xlsx_report(p, results, meta)
            log(f"报告(XLSX): {p}")
        except Exception as e:  # noqa: BLE001
            log(f"报告(XLSX) 生成失败: {type(e).__name__}: {e}")

    log(f"完成：成功 {ok}，失败 {bad}")
    return 0 if bad == 0 else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="批量文档加密（LibreOffice 原生加密）")
    ap.add_argument("--input", nargs="+", required=True, help="文件或目录，可多个")
    ap.add_argument("--password", required=True)
    ap.add_argument("--flat", action="store_true",
                    help="只处理当前层，不递归子目录")
    ap.add_argument("--mode", choices=["copy", "overwrite"], default="copy")
    ap.add_argument("--out", default="", help="复制模式的输出目录")
    ap.add_argument("--report-dir", default="")
    ap.add_argument("--kinds", nargs="*", default=["word", "excel", "ppt"],
                    choices=["word", "excel", "ppt"])
    ap.add_argument("--no-txt", action="store_true",
                    help="不生成 TXT 报告")
    ap.add_argument("--no-xlsx", action="store_true",
                    help="不生成 XLSX 报告")
    ap.add_argument("--mask-password", action="store_true",
                    help="报告中把密码打码")
    ap.add_argument("--port", type=int, default=PORT)
    # worker 内部使用
    ap.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--job", default="", help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.worker:
        return do_work(json.loads(args.job))

    inputs = [Path(p).expanduser() for p in args.input]
    outdir = Path(args.out).expanduser() if args.out else None
    report_dir = Path(args.report_dir).expanduser() if args.report_dir else Path.cwd()
    report_dir.mkdir(parents=True, exist_ok=True)
    if outdir is not None and args.mode == "copy":
        outdir.mkdir(parents=True, exist_ok=True)

    job = {
        "inputs": [str(p) for p in inputs],
        "password": args.password,
        "flat": args.flat,
        "mode": args.mode,
        "outdir": str(outdir) if outdir else "",
        "report_dir": str(report_dir),
        "kinds": args.kinds,
        "txt": not args.no_txt,
        "xlsx": not args.no_xlsx,
        "mask": args.mask_password,
        "port": args.port,
    }

    # 有 uno 就地执行；没有则改用 LibreOffice 的 python 以 worker 重启自身。
    if have_uno():
        return do_work(job)

    lo_py = find_lo_python()
    if not lo_py:
        log("错误：当前 Python 没有 uno 模块，且未找到 LibreOffice 自带的 python。\n"
            "  Windows: 确认已安装 LibreOffice（默认 C:\\Program Files\\LibreOffice）\n"
            "  Debian/Ubuntu: sudo apt install python3-uno")
        return 2

    log(f"当前解释器无 uno，改用 {lo_py} 以 worker 模式执行…")
    r = subprocess.run(
        [lo_py, str(Path(__file__).resolve()), "--worker",
         "--job", json.dumps(job)],
        cwd=str(Path(__file__).resolve().parent),
    )
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
