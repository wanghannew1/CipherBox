#!/usr/bin/env python3
"""
gui.py — 批量文档加密工具（图形界面）

Word / Excel / PowerPoint 批量加密，支持：
  · 选择文件或文件夹（可混合）
  · 全部子目录递归 / 仅当前层
  · 复制并加密（保留明文原件）/ 原地覆盖
  · 自设密码或随机生成
  · 同时输出 TXT 与 XLSX 报告（含文件名、路径、密码、大小、结果）

⚠️ 加密后的文档若遗忘密码将**永久无法恢复**——没有找回通道、没有后门。
   本工具不保存任何密钥副本。因此界面在开始前强制用户确认该风险。
"""

from __future__ import annotations

import os
import queue
import secrets
import string
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

sys.path.insert(0, str(Path(__file__).resolve().parent))
from encryptor import (  # noqa: E402
    EXT_LABEL, discover, find_soffice,
)

APP_TITLE = "批量文档加密工具 — LibreOffice 原生加密"
KIND_LABEL = {"word": "Word", "excel": "Excel", "ppt": "PowerPoint"}


def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} GB"


def gen_password(length: int = 20) -> str:
    """生成高强度密码。避免易混淆字符 (O/0, l/1, I)。"""
    pool = string.ascii_letters.replace("O", "").replace("o", "")
    pool += string.digits.replace("0", "").replace("1", "")
    pool += "!@#$%^&*-_=+?"
    while True:
        pw = "".join(secrets.choice(pool) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw)
                and any(c in "!@#$%^&*-_=+?" for c in pw)):
            return pw


class EncryptorApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("940x800")
        self.root.minsize(860, 720)
        self.proc: subprocess.Popen | None = None
        self.q: queue.Queue = queue.Queue()
        self._build_style()
        self._build_ui()
        self._check_env()

    # ---------------------------------------------------------------- 样式
    def _build_style(self) -> None:
        s = ttk.Style()
        try:
            s.theme_use("vista" if os.name == "nt" else "clam")
        except tk.TclError:
            pass
        s.configure("Warn.TLabel", background="#FFF4E5", foreground="#8A2B06",
                    font=("Microsoft YaHei UI", 10, "bold"), padding=8)
        s.configure("Head.TLabelframe.Label", font=("Microsoft YaHei UI", 10, "bold"))
        s.configure("Run.TButton", font=("Microsoft YaHei UI", 11, "bold"), padding=(10, 8))

    # ---------------------------------------------------------------- 界面
    def _build_ui(self) -> None:
        pad = {"padx": 10, "pady": 4}

        warn = tk.Label(
            self.root,
            text="⚠  加密后密码一旦遗忘，文件将永久无法恢复。"
                 "本工具不保存密钥副本，也没有找回通道。请务必先记录密码。",
            wraplength=900, justify="left", anchor="w",
            bg="#FFF4E5", fg="#8A2B06", relief="solid", bd=1,
            font=("Microsoft YaHei UI", 10, "bold"), padx=10, pady=8,
        )
        warn.pack(fill="x", padx=10, pady=(10, 6), anchor="w")

        body = ttk.Frame(self.root)
        body.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # ---- 1 选择文件 ----
        f1 = ttk.LabelFrame(body, text=" 1. 选择要加密的文件 ", style="Head.TLabelframe")
        f1.pack(fill="both", expand=True, **pad)

        lb_wrap = ttk.Frame(f1)
        lb_wrap.pack(fill="both", expand=True, padx=8, pady=6)
        self.listbox = tk.Listbox(lb_wrap, height=8, selectmode="extended",
                                  font=("Consolas", 9))
        sb = ttk.Scrollbar(lb_wrap, orient="vertical", command=self.listbox.yview)
        self.listbox.config(yscrollcommand=sb.set)
        self.listbox.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        btns = ttk.Frame(f1)
        btns.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(btns, text="添加文件…", command=self.add_files).pack(side="left")
        ttk.Button(btns, text="添加文件夹…", command=self.add_folder).pack(side="left", padx=4)
        ttk.Button(btns, text="移除选中", command=self.remove_selected).pack(side="left")
        ttk.Button(btns, text="清空", command=self.clear_list).pack(side="left", padx=4)
        ttk.Button(btns, text="扫描预览", command=self.preview).pack(side="left")

        self.count_lbl = ttk.Label(btns, text="尚未扫描", foreground="#555")
        self.count_lbl.pack(side="right")

        # ---- 2 范围与格式 ----
        f2 = ttk.LabelFrame(body, text=" 2. 扫描范围与文件类型 ", style="Head.TLabelframe")
        f2.pack(fill="x", **pad)

        row1 = ttk.Frame(f2)
        row1.pack(fill="x", padx=8, pady=6)
        ttk.Label(row1, text="文件夹范围：").pack(side="left")
        self.scope = tk.StringVar(value="recursive")
        ttk.Radiobutton(row1, text="全部子目录（递归）", value="recursive",
                        variable=self.scope).pack(side="left")
        ttk.Radiobutton(row1, text="仅当前层（不进入子目录）", value="flat",
                        variable=self.scope).pack(side="left", padx=(12, 0))

        row2 = ttk.Frame(f2)
        row2.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Label(row2, text="文件类型：").pack(side="left")
        self.kinds: dict[str, tk.BooleanVar] = {}
        for k in ("word", "excel", "ppt"):
            v = tk.BooleanVar(value=True)
            self.kinds[k] = v
            ttk.Checkbutton(row2, text=KIND_LABEL[k], variable=v).pack(side="left", padx=4)
        ttk.Label(row2, text="（含 .docx/.xlsx/.pptx 及 .docm/.xlsm/.pptm、ODF）",
                  foreground="#666").pack(side="left", padx=(10, 0))

        # ---- 3 密码 ----
        f3 = ttk.LabelFrame(body, text=" 3. 密码 ", style="Head.TLabelframe")
        f3.pack(fill="x", **pad)

        p1 = ttk.Frame(f3)
        p1.pack(fill="x", padx=8, pady=6)
        ttk.Label(p1, text="密码：").pack(side="left")
        self.pw = tk.StringVar()
        self.pw_entry = ttk.Entry(p1, textvariable=self.pw, width=34, show="●")
        self.pw_entry.pack(side="left")
        self.show_pw = tk.BooleanVar(value=False)
        ttk.Checkbutton(p1, text="显示", variable=self.show_pw,
                        command=self._toggle_pw).pack(side="left", padx=6)
        ttk.Button(p1, text="随机生成", command=self.gen_pw).pack(side="left")

        p2 = ttk.Frame(f3)
        p2.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Label(p2, text="确认：").pack(side="left")
        self.pw2 = tk.StringVar()
        self.pw2_entry = ttk.Entry(p2, textvariable=self.pw2, width=34, show="●")
        self.pw2_entry.pack(side="left")
        self.pw_match = ttk.Label(p2, text="", foreground="#1A7F37")
        self.pw_match.pack(side="left", padx=8)
        self.pw2.trace_add("write", lambda *_: self._check_pw_match())

        # ---- 4 输出方式 ----
        f4 = ttk.LabelFrame(body, text=" 4. 输出方式 ", style="Head.TLabelframe")
        f4.pack(fill="x", **pad)

        self.fmt_txt = tk.BooleanVar(value=True)
        self.fmt_xlsx = tk.BooleanVar(value=True)

        m1 = ttk.Frame(f4)
        m1.pack(fill="x", padx=8, pady=6)
        self.mode = tk.StringVar(value="copy")
        ttk.Radiobutton(m1, text="复制并加密（保留明文原件）", value="copy",
                        variable=self.mode, command=self._sync_mode).pack(side="left")
        ttk.Radiobutton(m1, text="⚠ 原地覆盖源文件（明文将被替换，不可用密码找回）",
                        value="overwrite", command=self._sync_mode).pack(side="left", padx=(12, 0))

        m2 = ttk.Frame(f4)
        m2.pack(fill="x", padx=8, pady=(0, 6))
        ttk.Label(m2, text="输出目录：").pack(side="left")
        self.outdir = tk.StringVar()
        self.out_entry = ttk.Entry(m2, textvariable=self.outdir, width=52)
        self.out_entry.pack(side="left")
        self.outdir_buttons: list[ttk.Button] = []
        b = ttk.Button(m2, text="选择…", command=self.pick_outdir)
        b.pack(side="left", padx=4)
        self.outdir_buttons.append(b)

        m3 = ttk.Frame(f4)
        m3.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Label(m3, text="报告目录：").pack(side="left")
        self.reportdir = tk.StringVar(value=str(Path.cwd()))
        self.rep_entry = ttk.Entry(m3, textvariable=self.reportdir, width=52)
        self.rep_entry.pack(side="left")
        ttk.Button(m3, text="选择…", command=self.pick_reportdir).pack(side="left", padx=4)
        ttk.Checkbutton(m3, text="TXT", variable=self.fmt_txt).pack(side="left", padx=(10, 0))
        ttk.Checkbutton(m3, text="XLSX", variable=self.fmt_xlsx).pack(side="left")
        self.mask_pw = tk.BooleanVar(value=False)
        ttk.Checkbutton(m3, text="报告中隐藏密码", variable=self.mask_pw).pack(
            side="left", padx=(10, 0))

        # ---- 5 执行 ----
        f5 = ttk.LabelFrame(body, text=" 5. 执行 ", style="Head.TLabelframe")
        f5.pack(fill="both", expand=True, **pad)

        self.run_btn = ttk.Button(f5, text="🔒  开始加密", style="Run.TButton",
                                  command=self.start)
        self.run_btn.pack(anchor="w", padx=8, pady=6)
        self.stop_btn = ttk.Button(f5, text="中止", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=4)

        self.progress = ttk.Progressbar(f5, mode="determinate")
        self.progress.pack(fill="x", padx=8, pady=(0, 4))
        self.status = ttk.Label(f5, text="就绪", foreground="#555")
        self.status.pack(anchor="w", padx=8)

        self.log = ScrolledText(f5, height=9, font=("Consolas", 9), state="disabled")
        self.log.pack(fill="both", expand=True, padx=8, pady=(4, 8))

    def _check_env(self) -> None:
        if not find_soffice():
            self._log("❌ 未检测到 LibreOffice。请先安装后重启本工具。")
            self.status.config(text="缺少 LibreOffice", foreground="#B42318")
            self.run_btn.config(state="disabled")
        else:
            self._log(f"LibreOffice: {find_soffice()}")

    # ---------------------------------------------------------------- 小工具
    def _log(self, msg: str) -> None:
        self.log.config(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.config(state="disabled")

    def _toggle_pw(self) -> None:
        c = "" if self.show_pw.get() else "●"
        self.pw_entry.config(show=c)
        self.pw2_entry.config(show=c)

    def _check_pw_match(self) -> None:
        a, b = self.pw.get(), self.pw2.get()
        if not a and not b:
            self.pw_match.config(text="")
        elif a == b:
            self.pw_match.config(text="✓ 一致", foreground="#1A7F37")
        else:
            self.pw_match.config(text="✗ 不一致", foreground="#B42318")

    def _sync_mode(self) -> None:
        st = "disabled" if self.mode.get() == "overwrite" else "normal"
        self.out_entry.config(state=st)
        self.pick_btn_state(st)

    def pick_btn_state(self, st: str) -> None:
        for w in self.outdir_buttons:
            w.config(state=st)

    def gen_pw(self) -> None:
        self.pw.set(gen_password())
        self.pw2.set(self.pw.get())
        self._check_pw_match()

    def add_files(self) -> None:
        exts = []
        for k, v in self.kinds.items():
            if v.get():
                exts += EXT_LABEL[k]
        types = [("Office 文档", " ".join(f"*{e}" for e in sorted(set(exts)))),
                 ("所有文件", "*.*")]
        paths = filedialog.askopenfilenames(title="选择要加密的文件", filetypes=types)
        for p in paths:
            self.listbox.insert("end", f"[文件] {p}")

    def add_folder(self) -> None:
        d = filedialog.askdirectory(title="选择要加密的文件夹")
        if d:
            self.listbox.insert("end", f"[目录] {d}")

    def remove_selected(self) -> None:
        for i in reversed(self.listbox.curselection()):
            self.listbox.delete(i)

    def clear_list(self) -> None:
        self.listbox.delete(0, "end")
        self.count_lbl.config(text="尚未扫描")

    def pick_outdir(self) -> None:
        d = filedialog.askdirectory(title="选择输出目录")
        if d:
            self.outdir.set(d)

    def pick_reportdir(self) -> None:
        d = filedialog.askdirectory(title="选择报告保存目录")
        if d:
            self.reportdir.set(d)

    # ---------------------------------------------------------------- 扫描
    def _entries(self) -> tuple[list[Path], list[Path]]:
        files, dirs = [], []
        for line in self.listbox.get(0, "end"):
            kind, _, path = line.partition(" ")
            (dirs if kind == "[目录]" else files).append(Path(path))
        return files, dirs

    def _selected_kinds(self) -> list[str]:
        return [k for k, v in self.kinds.items() if v.get()]

    def preview(self) -> None:
        files, dirs = self._entries()
        if not files and not dirs:
            messagebox.showinfo("扫描预览", "请先添加文件或文件夹。")
            return
        kinds = self._selected_kinds()
        if not kinds:
            messagebox.showwarning("扫描预览", "请至少勾选一种文件类型。")
            return
        try:
            hits = discover(files + dirs, self.scope.get() == "flat", kinds)
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("扫描预览", f"扫描失败：{e}")
            return
        total = sum(f.stat().st_size for f in hits if f.is_file())
        self.count_lbl.config(
            text=f"匹配 {len(hits)} 个文件，合计 {human_size(total)}")
        self._log(f"预览：{'仅当前层' if self.scope.get() == 'flat' else '全部子目录'}"
                  f" → {len(hits)} 个文件，合计 {human_size(total)}")
        if not hits:
            messagebox.showinfo("扫描预览", "没有匹配到符合条件的文件。")

    # ---------------------------------------------------------------- 风险确认
    def _confirm_risk(self, n_files: int, mode: str) -> bool:
        """强制确认弹窗。必须勾选复选框才能继续——这是本工具的核心风险闸门。"""
        dlg = tk.Toplevel(self.root)
        dlg.title("请确认加密风险")
        dlg.transient(self.root)
        dlg.resizable(False, False)
        dlg.configure(bg="#FFF4E5")

        body = tk.Frame(dlg, bg="#FFF4E5", padx=22, pady=18)
        body.pack(fill="both", expand=True)

        tk.Label(
            body,
            text="⚠  密码遗忘 = 文件永久无法恢复",
            font=("Microsoft YaHei UI", 14, "bold"), bg="#FFF4E5", fg="#8A2B06",
        ).pack(anchor="w")
        tk.Label(
            body,
            text=(
                f"即将加密 {n_files} 个文件。\n\n"
                "加密使用的是文档内嵌密码，本工具不保存任何密钥副本，\n"
                "也没有后门或找回通道。一旦密码丢失，文件将永远无法打开，\n"
                "只能重新从原始数据生成。\n\n"
                "请确认你已安全记录密码（密码管理器、纸质记录、\n"
                "或下方勾选的“报告中保存密码”）。"
            ),
            justify="left", anchor="w", bg="#FFF4E5", wraplength=520,
        ).pack(anchor="w", pady=(10, 0))

        if mode == "overwrite":
            tk.Label(
                body,
                text="⚠  本次为原地覆盖：源文件将被密文替换，原始明文不再存在。",
                justify="left", anchor="w", bg="#FFF4E5", fg="#B42318",
                font=("Microsoft YaHei UI", 10, "bold"), wraplength=520,
            ).pack(anchor="w", pady=(12, 0))

        ack = tk.BooleanVar(value=False)
        cb = ttk.Checkbutton(body, text="我已阅读并理解上述风险",
                             variable=ack, command=lambda: ok_btn.config(
                                 state="normal" if ack.get() else "disabled"))
        cb.pack(anchor="w", pady=(16, 0))

        btns = ttk.Frame(body)
        btns.pack(anchor="e", pady=(14, 0))
        ok_btn = ttk.Button(btns, text="继续加密", state="disabled", command=dlg.destroy)
        ok_btn.pack(side="left", padx=4)
        ttk.Button(btns, text="取消", command=dlg.destroy).pack(side="left", padx=4)

        self.root.wait_window(dlg)
        return bool(ack.get())

    # ---------------------------------------------------------------- 执行
    def start(self) -> None:
        if self.proc is not None:
            return
        files, dirs = self._entries()
        if not files and not dirs:
            messagebox.showinfo("提示", "请先添加文件或文件夹。")
            return
        kinds = self._selected_kinds()
        if not kinds:
            messagebox.showwarning("提示", "请至少勾选一种文件类型。")
            return
        pw = self.pw.get()
        if not pw:
            messagebox.showwarning("提示", "请设置密码。")
            return
        if pw != self.pw2.get():
            messagebox.showerror("提示", "两次输入的密码不一致。")
            return

        mode = self.mode.get()
        if mode == "copy" and not self.outdir.get().strip():
            messagebox.showwarning("提示", "复制模式必须指定输出目录。")
            return
        if not (self.fmt_txt.get() or self.fmt_xlsx.get()):
            messagebox.showwarning("提示", "请至少选择一种报告格式（TXT / XLSX）。")
            return

        try:
            hits = discover(files + dirs, self.scope.get() == "flat", kinds)
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("错误", f"扫描失败：{e}")
            return
        if not hits:
            messagebox.showinfo("提示", "没有匹配到符合条件的文件。")
            return

        if not self._confirm_risk(len(hits), mode):
            self._log("已取消。")
            return

        cmd = [sys.executable, str(Path(__file__).parent / "encryptor.py"),
               "--input", *[str(p) for p in files + dirs],
               "--password", pw, "--mode", mode,
               "--report-dir", self.reportdir.get().strip() or str(Path.cwd()),
               "--kinds", *kinds,
               "--port", "2095"]
        if self.scope.get() == "flat":
            cmd.append("--flat")
        if mode == "copy":
            cmd += ["--out", self.outdir.get().strip()]
        if not self.fmt_txt.get():
            cmd.append("--no-txt")
        if not self.fmt_xlsx.get():
            cmd.append("--no-xlsx")
        if self.mask_pw.get():
            cmd.append("--mask-password")

        self.run_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.progress.config(maximum=len(hits), value=0)
        self.status.config(text="正在加密…", foreground="#1A7F37")
        self._log(f"开始：{len(hits)} 个文件，模式 "
                  f"{'覆盖源文件' if mode == 'overwrite' else '复制并加密'}")
        self.proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", bufsize=1)
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        """子进程输出线程 → 队列 → 主线程刷新。UNO 不可跨线程，故隔离到子进程。"""
        assert self.proc is not None
        for line in self.proc.stdout:  # type: ignore[union-attr]
            self.q.put(line.rstrip())
        self.proc.wait()
        self.q.put(("__DONE__", self.proc.returncode))

    def _drain(self) -> None:
        total = self.progress["maximum"] or 1
        while True:
            try:
                item = self.q.get_nowait()
            except queue.Empty:
                break
            if isinstance(item, tuple) and item and item[0] == "__DONE__":
                self._finish(item[1])
                return
            line = item
            self._log(line)
            if line.startswith("["):
                done = line.split("/", 1)[0].lstrip("[")
                if done.isdigit():
                    self.progress.config(value=int(done))
            if line.startswith("扫描到"):
                self.status.config(text=line, foreground="#1A7F37")

    def _finish(self, code: int | None) -> None:
        self.proc = None
        self.run_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        if code == 0:
            self.status.config(text="✅ 全部成功，报告已生成", foreground="#1A7F37")
            self.progress.config(value=self.progress["maximum"])
        else:
            self.status.config(
                text=f"⚠ 已结束（退出码 {code}），请查看日志与报告中的失败项",
                foreground="#B42318")
        if messagebox.askyesno("完成", self.status.cget("text") + "\n\n是否打开报告目录？"):
            target = self.reportdir.get().strip() or str(Path.cwd())
            try:
                if sys.platform == "win32":
                    os.startfile(target)  # noqa: S606
                elif sys.platform == "darwin":
                    subprocess.Popen(["open", target])
                else:
                    subprocess.Popen(["xdg-open", target],
                                     stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
            except Exception as e:  # noqa: BLE001
                self._log(f"打开目录失败：{e}")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            if messagebox.askyesno("中止", "确定要中止加密吗？\n已完成的文件不会回滚。"):
                self.proc.terminate()
                self.status.config(text="正在中止…", foreground="#B42318")

    def poll_queue(self) -> None:
        self._drain()
        self.root.after(150, self.poll_queue)


def main() -> None:
    root = tk.Tk()
    app = EncryptorApp(root)
    root.after(150, app.poll_queue)
    root.mainloop()


if __name__ == "__main__":
    main()
