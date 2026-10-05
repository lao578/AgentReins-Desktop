#!/usr/bin/env python3
"""Cross-platform Tk desktop shell for the AgentReins portable collector.

The collector remains dependency-free and runs on a worker thread. This
module is presentation-only so it can be packaged by PyInstaller on Windows
and run from source on Linux. ``pystray`` and Pillow are detected at runtime
for an optional real system tray; the standard-library fallback minimizes the
window to the taskbar.
"""

from __future__ import annotations

import json
import locale
import queue
import sys
import threading
import time
import tkinter as tk
from dataclasses import asdict
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Optional

try:
    from agent_adapters import NativeSessionReader
except ImportError:
    from .agent_adapters import NativeSessionReader

try:  # Running as ``python portable/agentreins_desktop.py``.
    from agentreins_portable import (
        EvidenceStore,
        WebEvidenceReader,
        create_file_watcher,
        platform_paths,
        snapshot,
        write_snapshot,
    )
except ImportError:  # Running as an installed package (or a test harness).
    from .agentreins_portable import (
        EvidenceStore,
        WebEvidenceReader,
        create_file_watcher,
        platform_paths,
        snapshot,
        write_snapshot,
    )


class AgentReinsDesktop(tk.Tk):
    """Responsive desktop monitoring console around the portable collector."""

    def __init__(self, start_background: bool = False, start_watch: bool = False, use_etw: bool = False) -> None:
        super().__init__()
        self._language = self._initial_language()
        self._localized: list[tuple[Any, str]] = []
        self._localized_headings: list[tuple[Any, str, str]] = []
        self._notebook_tabs: list[tuple[Any, str, str]] = []
        self.title("AgentReins")
        self.minsize(900, 620)
        self.geometry("1120x760")
        self.protocol("WM_DELETE_WINDOW", self._close)

        resolved_paths = platform_paths()
        default_path = Path(resolved_paths["evidence"])
        self.output_var = tk.StringVar(value=str(default_path))
        self.database_var = tk.StringVar(value=str(resolved_paths["database"]))
        self.interval_var = tk.StringVar(value="2")
        self.status_var = tk.StringVar(value=self._t("Ready"))
        self.filter_var = tk.StringVar()
        self.auto_refresh_var = tk.BooleanVar(value=True)
        self._auto_refresh_enabled = True
        self._events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self._stop = threading.Event()
        self._watch_thread: Optional[threading.Thread] = None
        self._closed = False
        self._last_record: Optional[dict[str, Any]] = None
        self._process_rows: list[dict[str, Any]] = []
        self._network_rows: list[dict[str, Any]] = []
        self._tray_icon: Any = None
        self._tray_supported = False
        self._tray_thread: Optional[threading.Thread] = None
        self._use_etw = use_etw
        self.language_var = tk.StringVar(value="中文" if self._language == "zh_CN" else "English")

        self._build_widgets()
        self.filter_var.trace_add("write", self._filter_changed)
        self._prepare_optional_tray()
        self.after(100, self._drain_events)
        if start_watch:
            self.after(250, self.toggle_watch)
        if start_background:
            self.after(400, self._enter_background)

    @staticmethod
    def _initial_language() -> str:
        """Choose Chinese for Chinese system locales; English otherwise."""
        try:
            language = locale.getlocale()[0] or ""
        except (ValueError, TypeError):
            language = ""
        return "zh_CN" if language.lower().startswith("zh") else "en"

    _ZH = {
        "Evidence JSONL:": "证据 JSONL：", "Browse...": "浏览…", "Evidence SQLite:": "证据 SQLite：",
        "Refresh (seconds):": "刷新间隔（秒）：", "Capture snapshot": "采集快照", "Start watch": "开始监控",
        "Stop watch": "停止监控", "Auto refresh": "自动刷新", "Background": "后台运行",
        "Platform": "平台", "Agents": "Agent 数量", "Processes": "进程", "Connections": "网络连接",
        "File changes": "文件变更", "Web events": "网页事件", "Native session events": "本地会话事件", "Detected agents": "检测到的 Agent",
        "No known Agent processes detected": "未检测到已知 Agent 进程", "Processes tab": "进程列表",
        "Connections tab": "网络连接", "Raw JSON": "原始 JSON", "Filter:": "筛选：", "Clear": "清除",
        "PID": "进程 ID", "Agent": "Agent", "Parent": "父进程", "Executable": "可执行文件",
        "Command": "命令行", "State": "状态", "Local": "本地地址", "Remote": "远端地址", "Protocol": "协议",
        "Ready": "就绪", "Collecting snapshot...": "正在采集快照…", "Watching...": "正在监控…",
        "Stopping watch...": "正在停止监控…", "Watch stopped": "监控已停止", "Running in the system tray": "正在系统托盘中运行",
        "Minimized to the taskbar (install pystray and Pillow for a tray icon)": "已最小化到任务栏（安装 pystray 和 Pillow 可启用托盘图标）",
        "Invalid interval": "刷新间隔无效", "Enter a number of at least 0.25 seconds.": "请输入不小于 0.25 秒的数字。",
        "Evidence JSONL destination": "证据 JSONL 保存位置", "Evidence SQLite database": "证据 SQLite 数据库",
        "JSON Lines": "JSON Lines 文件", "SQLite database": "SQLite 数据库", "All files": "所有文件",
        "Show AgentReins": "显示 AgentReins", "Start/stop watch": "开始/停止监控", "Quit": "退出",
        "Check for updates": "检查更新", "Checking for updates...": "正在检查更新…", "Language": "语言", "English": "English", "中文": "中文",
        "Update check": "更新检查", "{count} instance(s)": "{count} 个实例", "PID: {ids}": "进程 ID：{ids}",
        "You are using the latest version ({version}).": "当前已是最新版本（{version}）。",
        "Version {version} is available. Open the release page to download it?": "发现新版本 {version}。要打开发布页面下载吗？",
        "Could not check for updates: {error}": "检查更新失败：{error}", "Snapshot failed: {error}": "快照采集失败：{error}",
        "Watch failed: {error}": "监控失败：{error}", "Last snapshot: {timestamp}  |  Saved to {path}": "最近快照：{timestamp}  |  已保存到 {path}",
    }

    def _t(self, value: str, **format_values: Any) -> str:
        translated = self._ZH.get(value, value) if self._language == "zh_CN" else value
        return translated.format(**format_values) if format_values else translated

    def _text(self, widget: Any, text: str) -> Any:
        widget.configure(text=self._t(text))
        self._localized.append((widget, text))
        return widget

    def _text_format(self, widget: Any, text: str, **values: Any) -> Any:
        widget.configure(text=self._t(text, **values))
        self._localized.append((widget, text))
        return widget

    def _set_language(self, selection: str) -> None:
        self._language = "zh_CN" if selection == "中文" else "en"
        for widget, source_text in self._localized:
            try:
                widget.configure(text=self._t(source_text))
            except tk.TclError:
                pass
        for tree, column, source_text in self._localized_headings:
            tree.heading(column, text=self._t(source_text))
        for notebook, child, source_text in self._notebook_tabs:
            notebook.tab(child, text=self._t(source_text))
        for widget, source_text in self.summary_cards:
            widget.configure(text=self._t(source_text))
        self.language_var.set("中文" if self._language == "zh_CN" else "English")

    def _build_widgets(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(4, weight=0)

        controls = ttk.Frame(self, padding=12)
        controls.grid(row=0, column=0, sticky="ew")
        controls.columnconfigure(1, weight=1)
        self._text(ttk.Label(controls), "Evidence JSONL:").grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(controls, textvariable=self.output_var).grid(row=0, column=1, columnspan=4, sticky="ew")
        self._text(ttk.Button(controls, command=self._browse), "Browse...").grid(row=0, column=5, padx=(8, 0))

        self._text(ttk.Label(controls), "Evidence SQLite:").grid(row=1, column=0, sticky="w", pady=(8, 0), padx=(0, 8))
        ttk.Entry(controls, textvariable=self.database_var).grid(row=1, column=1, columnspan=4, sticky="ew", pady=(8, 0))
        self._text(ttk.Button(controls, command=self._browse_database), "Browse...").grid(row=1, column=5, padx=(8, 0), pady=(8, 0))

        self._text(ttk.Label(controls), "Refresh (seconds):").grid(row=2, column=0, sticky="w", pady=(8, 0), padx=(0, 8))
        ttk.Entry(controls, width=10, textvariable=self.interval_var).grid(row=2, column=1, sticky="w", pady=(8, 0))
        self.snapshot_button = self._text(ttk.Button(controls, command=self.capture_snapshot), "Capture snapshot")
        self.snapshot_button.grid(row=2, column=2, pady=(8, 0), padx=(8, 0))
        self.watch_button = self._text(ttk.Button(controls, command=self.toggle_watch), "Start watch")
        self.watch_button.grid(row=2, column=3, pady=(8, 0), padx=(8, 0))
        self._text(ttk.Checkbutton(controls, variable=self.auto_refresh_var, command=self._set_auto_refresh), "Auto refresh").grid(
            row=2, column=4, pady=(8, 0), padx=(8, 0), sticky="w"
        )
        self._text(ttk.Button(controls, command=self._enter_background), "Background").grid(
            row=2, column=5, pady=(8, 0), padx=(8, 0)
        )

        self._text(ttk.Label(controls), "Language").grid(row=3, column=0, sticky="w", pady=(8, 0), padx=(0, 8))
        language_picker = ttk.Combobox(controls, textvariable=self.language_var, values=("English", "中文"), state="readonly", width=12)
        language_picker.grid(row=3, column=1, sticky="w", pady=(8, 0))
        language_picker.bind("<<ComboboxSelected>>", lambda _event: self._set_language(self.language_var.get()))
        self.update_button = self._text(ttk.Button(controls, command=self.check_updates), "Check for updates")
        self.update_button.grid(row=3, column=2, columnspan=2, sticky="w", pady=(8, 0), padx=(8, 0))

        ttk.Separator(self, orient="horizontal").grid(row=3, column=0, sticky="ew")
        self.summary_frame = ttk.Frame(self, padding=(12, 10, 12, 4))
        self.summary_frame.grid(row=4, column=0, sticky="ew")
        for index in range(7):
            self.summary_frame.columnconfigure(index, weight=1)
        self.summary_values: dict[str, ttk.Label] = {}
        self.summary_cards: list[tuple[ttk.LabelFrame, str]] = []
        for index, (key, title, value) in enumerate(
            (
                ("platform", "Platform", "-"),
                ("agents", "Agents", "0"),
                ("processes", "Processes", "0"),
                ("connections", "Connections", "0"),
                ("fileEvents", "File changes", "0"),
                ("webEvents", "Web events", "0"),
                ("nativeEvents", "Native session events", "0"),
            )
        ):
            card = ttk.LabelFrame(self.summary_frame, text=self._t(title), padding=(12, 6))
            self.summary_cards.append((card, title))
            card.grid(row=0, column=index, sticky="ew", padx=(0 if index == 0 else 6, 0))
            label = ttk.Label(card, text=value, font=("TkDefaultFont", 16, "bold"))
            label.pack(anchor="w")
            self.summary_values[key] = label

        content = ttk.Frame(self, padding=(12, 4, 12, 0))
        content.grid(row=5, column=0, sticky="nsew")
        content.columnconfigure(0, weight=1)
        content.rowconfigure(2, weight=1)
        self.rowconfigure(5, weight=1)

        agent_header = ttk.Frame(content)
        agent_header.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        self._text(ttk.Label(agent_header, font=("TkDefaultFont", 11, "bold")), "Detected agents").grid(row=0, column=0, sticky="w")
        self.agent_cards = ttk.Frame(content)
        self.agent_cards.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        self.agent_cards.columnconfigure(0, weight=1)

        self.notebook = ttk.Notebook(content)
        self.notebook.grid(row=2, column=0, sticky="nsew")
        self.process_tab = ttk.Frame(self.notebook, padding=8)
        self.network_tab = ttk.Frame(self.notebook, padding=8)
        self.raw_tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.process_tab, text=self._t("Processes tab"))
        self.notebook.add(self.network_tab, text=self._t("Connections tab"))
        self.notebook.add(self.raw_tab, text=self._t("Raw JSON"))
        self._notebook_tabs.extend(((self.notebook, self.process_tab, "Processes tab"), (self.notebook, self.network_tab, "Connections tab"), (self.notebook, self.raw_tab, "Raw JSON")))
        self._build_tables()

        self.output = tk.Text(self.raw_tab, wrap="none", undo=False, font=("Consolas", 10), state="disabled")
        self.output.pack(side="left", fill="both", expand=True)
        raw_y = ttk.Scrollbar(self.raw_tab, orient="vertical", command=self.output.yview)
        raw_y.pack(side="right", fill="y")
        raw_x = ttk.Scrollbar(self.raw_tab, orient="horizontal", command=self.output.xview)
        raw_x.pack(side="bottom", fill="x")
        self.output.configure(yscrollcommand=raw_y.set, xscrollcommand=raw_x.set)

        status = ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w", padding=(8, 4))
        status.grid(row=6, column=0, sticky="ew", padx=12, pady=(8, 12))

    def _build_tables(self) -> None:
        for parent, columns, headings in (
            (self.process_tab, ("pid", "agent", "ppid", "executable", "command"), ("PID", "Agent", "Parent", "Executable", "Command")),
            (self.network_tab, ("pid", "state", "local", "remote", "protocol"), ("PID", "State", "Local", "Remote", "Protocol")),
        ):
            parent.columnconfigure(0, weight=1)
            parent.rowconfigure(1, weight=1)
            top = ttk.Frame(parent)
            top.grid(row=0, column=0, sticky="ew", pady=(0, 6))
            top.columnconfigure(1, weight=1)
            self._text(ttk.Label(top), "Filter:").grid(row=0, column=0, padx=(0, 6))
            ttk.Entry(top, textvariable=self.filter_var).grid(row=0, column=1, sticky="ew")
            self._text(ttk.Button(top, command=lambda: self.filter_var.set("")), "Clear").grid(row=0, column=2, padx=(6, 0))
            tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")
            tree.grid(row=1, column=0, sticky="nsew")
            scroll = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
            scroll.grid(row=1, column=1, sticky="ns")
            tree.configure(yscrollcommand=scroll.set)
            for column, heading in zip(columns, headings):
                tree.heading(column, text=self._t(heading), command=lambda c=column, t=tree: self._sort_tree(t, c, False))
                self._localized_headings.append((tree, column, heading))
                tree.column(column, width=110 if column != "command" else 360, anchor="w", stretch=column in {"command", "remote", "executable"})
            if parent is self.process_tab:
                self.process_tree = tree
            else:
                self.network_tree = tree

    def _prepare_optional_tray(self) -> None:
        """Load tray support only when optional pystray/Pillow are installed."""
        try:
            import pystray  # type: ignore
            from PIL import Image, ImageDraw  # type: ignore

            image = Image.new("RGBA", (32, 32), (27, 94, 122, 255))
            draw = ImageDraw.Draw(image)
            draw.rectangle((7, 7, 25, 25), outline=(255, 255, 255, 255), width=2)
            draw.line((10, 16, 22, 16), fill=(255, 255, 255, 255), width=2)

            def show(_icon: Any, _item: Any) -> None:
                self.after(0, self._restore_from_background)

            def quit_app(_icon: Any, _item: Any) -> None:
                self.after(0, self._close)

            def snapshot(_icon: Any, _item: Any) -> None:
                self.after(0, self.capture_snapshot)

            def watch(_icon: Any, _item: Any) -> None:
                self.after(0, self.toggle_watch)

            self._tray_icon = pystray.Icon(
                "AgentReins", image, "AgentReins", pystray.Menu(
                    pystray.MenuItem(lambda _icon: self._t("Show AgentReins"), show, default=True),
                    pystray.MenuItem(lambda _icon: self._t("Capture snapshot"), snapshot),
                    pystray.MenuItem(lambda _icon: self._t("Start/stop watch"), watch),
                    pystray.MenuItem(lambda _icon: self._t("Quit"), quit_app),
                )
            )
            self._tray_supported = True
        except (ImportError, OSError):
            self._tray_icon = None
            self._tray_supported = False

    def _enter_background(self) -> None:
        if self._tray_supported and self._tray_icon is not None:
            self.withdraw()
            if self._tray_thread is None or not self._tray_thread.is_alive():
                self._tray_thread = threading.Thread(target=self._tray_icon.run, daemon=True, name="agentreins-tray")
                self._tray_thread.start()
            self.status_var.set("Running in the system tray")
        else:
            self.iconify()
            self.status_var.set("Minimized to the taskbar (install pystray and Pillow for a tray icon)")

    def _restore_from_background(self) -> None:
        self.deiconify()
        self.state("normal")
        self.lift()
        self.focus_force()
        self.status_var.set("Ready")

    def _browse(self) -> None:
        selected = filedialog.asksaveasfilename(
            title="Evidence JSONL destination",
            initialfile=Path(self.output_var.get()).name or "evidence.jsonl",
            initialdir=str(Path(self.output_var.get()).expanduser().parent),
            defaultextension=".jsonl",
            filetypes=[("JSON Lines", "*.jsonl"), ("All files", "*.*")],
        )
        if selected:
            self.output_var.set(selected)

    def _browse_database(self) -> None:
        selected = filedialog.asksaveasfilename(
            title="Evidence SQLite database",
            initialfile=Path(self.database_var.get()).name or "evidence.sqlite3",
            initialdir=str(Path(self.database_var.get()).expanduser().parent),
            defaultextension=".sqlite3",
            filetypes=[("SQLite database", "*.sqlite3"), ("All files", "*.*")],
        )
        if selected:
            self.database_var.set(selected)

    def _set_output(self, text: str) -> None:
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("1.0", text)
        self.output.configure(state="disabled")

    def _render_snapshot(self, record: dict[str, Any]) -> str:
        return json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True)

    def _filter_changed(self, *_args: Any) -> None:
        self._apply_filter()

    def _set_auto_refresh(self) -> None:
        # Keep the worker thread independent from Tk's Tcl interpreter.
        self._auto_refresh_enabled = bool(self.auto_refresh_var.get())

    def _apply_filter(self) -> None:
        query = self.filter_var.get().strip().lower()
        for tree, rows in ((self.process_tree, self._process_rows), (self.network_tree, self._network_rows)):
            tree.delete(*tree.get_children())
            for row in rows:
                values = tuple(str(row.get(column, "")) for column in tree["columns"])
                if query and query not in " ".join(values).lower():
                    continue
                tree.insert("", "end", values=values)

    def _sort_tree(self, tree: ttk.Treeview, column: str, reverse: bool) -> None:
        items = [(tree.set(item, column), item) for item in tree.get_children("")]
        try:
            items.sort(key=lambda pair: float(pair[0]), reverse=reverse)
        except ValueError:
            items.sort(key=lambda pair: pair[0].lower(), reverse=reverse)
        for index, (_value, item) in enumerate(items):
            tree.move(item, "", index)
        tree.heading(column, command=lambda: self._sort_tree(tree, column, not reverse))

    def _populate_record(self, record: dict[str, Any]) -> None:
        self._last_record = record
        agents = record.get("agents") or []
        self._process_rows = list(record.get("processes") or [])
        self._network_rows = list(record.get("connections") or [])
        self.summary_values["platform"].configure(text=str(record.get("platform", "unknown")).title())
        self.summary_values["agents"].configure(text=str(len(agents)))
        self.summary_values["processes"].configure(text=str(len(self._process_rows)))
        self.summary_values["connections"].configure(text=str(len(self._network_rows)))
        self.summary_values["fileEvents"].configure(text=str(len(record.get("fileEvents") or [])))
        self.summary_values["webEvents"].configure(text=str(len(record.get("webEvents") or [])))
        self.summary_values["nativeEvents"].configure(text=str(len(record.get("nativeEvents") or [])))
        for child in self.agent_cards.winfo_children():
            child.destroy()
        if not agents:
            self._text(ttk.Label(self.agent_cards, foreground="#666666"), "No known Agent processes detected").grid(row=0, column=0, sticky="w")
        else:
            for index, agent in enumerate(agents):
                card = ttk.LabelFrame(self.agent_cards, text=str(agent.get("id", "unknown")).title(), padding=(10, 5))
                card.grid(row=0, column=index, sticky="ew", padx=(0 if index == 0 else 6, 0))
                self.agent_cards.columnconfigure(index, weight=1)
                self._text_format(ttk.Label(card), "{count} instance(s)", count=agent.get("instances", 0)).pack(anchor="w")
                self._text_format(ttk.Label(card), "PID: {ids}", ids=", ".join(str(pid) for pid in agent.get("processIds", [])) or "-").pack(anchor="w")
        self._apply_filter()
        self._set_output(self._render_snapshot(record))

    def capture_snapshot(self) -> None:
        if self._closed:
            return
        self.snapshot_button.configure(state="disabled")
        self.status_var.set(self._t("Collecting snapshot..."))
        destination = Path(self.output_var.get()).expanduser()
        database = Path(self.database_var.get()).expanduser()
        threading.Thread(target=self._snapshot_worker, args=(destination, database), daemon=True, name="agentreins-snapshot").start()

    def _snapshot_worker(self, destination: Path, database: Path) -> None:
        store: Optional[EvidenceStore] = None
        try:
            record = snapshot()
            store = EvidenceStore(database)
            web_events = WebEvidenceReader(Path(platform_paths()["webEvidence"])).poll()
            native_events = NativeSessionReader().poll()
            record["webEvents"] = web_events
            record["nativeEvents"] = native_events
            write_snapshot(record, destination)
            store.append_web_events([*web_events, *native_events])
            store.append_snapshot(record)
            self._events.put(("snapshot", record))
        except Exception as exc:  # Keep UI alive when an OS collector is unavailable.
            self._events.put(("error", f"Snapshot failed: {exc}"))
        finally:
            if store is not None:
                store.close()

    def check_updates(self) -> None:
        """Check GitHub asynchronously; never replace the running app."""
        if self._closed:
            return
        self.update_button.configure(state="disabled")
        self.status_var.set(self._t("Checking for updates..."))
        threading.Thread(target=self._update_worker, daemon=True, name="agentreins-update-check").start()

    def _update_worker(self) -> None:
        try:
            try:
                from update_checker import check_for_updates
                from agentreins_portable import VERSION
            except ImportError:
                from .update_checker import check_for_updates
                from .agentreins_portable import VERSION
            self._events.put(("update-result", check_for_updates(VERSION)))
        except Exception as exc:
            self._events.put(("update-error", str(exc)))

    def toggle_watch(self) -> None:
        if self._watch_thread and self._watch_thread.is_alive():
            self._stop.set()
            self.watch_button.configure(state="disabled")
            self.status_var.set(self._t("Stopping watch..."))
            return
        try:
            interval = max(0.25, float(self.interval_var.get()))
        except ValueError:
            messagebox.showerror(self._t("Invalid interval"), self._t("Enter a number of at least 0.25 seconds."))
            return
        self._stop.clear()
        self.watch_button.configure(text=self._t("Stop watch"))
        self.status_var.set(self._t("Watching..."))
        destination = Path(self.output_var.get()).expanduser()
        database = Path(self.database_var.get()).expanduser()
        self._watch_thread = threading.Thread(target=self._watch_worker, args=(interval, destination, database), daemon=True, name="agentreins-watch")
        self._watch_thread.start()

    def _watch_worker(self, interval: float, destination: Path, database: Path) -> None:
        store: Optional[EvidenceStore] = None
        file_watcher = None
        try:
            paths = platform_paths()
            store = EvidenceStore(database)
            file_watcher = create_file_watcher([Path(paths["data"])], use_etw=self._use_etw)
            web_reader = WebEvidenceReader(Path(paths["webEvidence"]))
            native_reader = NativeSessionReader()
            while not self._stop.is_set():
                started = time.monotonic()
                try:
                    record = snapshot()
                    file_events = file_watcher.poll() if file_watcher is not None else []
                    web_events = web_reader.poll()
                    native_events = native_reader.poll()
                    record["fileEvents"] = [asdict(event) for event in file_events]
                    record["webEvents"] = web_events
                    record["nativeEvents"] = native_events
                    if hasattr(file_watcher, "mode"):
                        record["fileWatcher"] = file_watcher.mode
                    write_snapshot(record, destination)
                    store.append_web_events([*web_events, *native_events])
                    store.append_snapshot(record)
                    store.append_file_events(file_events, store.latest_context())
                    if self._auto_refresh_enabled:
                        self._events.put(("snapshot", record))
                except Exception as exc:
                    self._events.put(("error", f"Watch failed: {exc}"))
                self._stop.wait(max(0.0, interval - (time.monotonic() - started)))
        finally:
            if file_watcher is not None:
                file_watcher.close()
            if store is not None:
                store.close()
            self._events.put(("watch-stopped", None))

    def _drain_events(self) -> None:
        try:
            while True:
                kind, value = self._events.get_nowait()
                if kind == "snapshot":
                    self._populate_record(value)
                    self.status_var.set(self._t("Last snapshot: {timestamp}  |  Saved to {path}", timestamp=value.get("timestamp", "unknown"), path=self.output_var.get()))
                    self.snapshot_button.configure(state="normal")
                elif kind == "error":
                    message = str(value)
                    if message.startswith("Snapshot failed: "):
                        message = self._t("Snapshot failed: {error}", error=message.partition(": ")[2])
                    elif message.startswith("Watch failed: "):
                        message = self._t("Watch failed: {error}", error=message.partition(": ")[2])
                    self.status_var.set(message)
                    if not (self._watch_thread and self._watch_thread.is_alive()):
                        self.snapshot_button.configure(state="normal")
                elif kind == "watch-stopped":
                    self.watch_button.configure(text=self._t("Start watch"), state="normal")
                    if not self._closed:
                        self.status_var.set(self._t("Watch stopped"))
                elif kind == "update-result":
                    self.update_button.configure(state="normal")
                    result = value
                    if result.error:
                        self.status_var.set(self._t("Could not check for updates: {error}", error=result.error))
                    elif result.available:
                        prompt = self._t("Version {version} is available. Open the release page to download it?", version=result.latest_version)
                        self.status_var.set(prompt)
                        if messagebox.askyesno(self._t("Update check"), prompt):
                            import webbrowser
                            webbrowser.open(result.release_url)
                    else:
                        self.status_var.set(self._t("You are using the latest version ({version}).", version=result.current_version))
                elif kind == "update-error":
                    self.update_button.configure(state="normal")
                    self.status_var.set(self._t("Could not check for updates: {error}", error=value))
        except queue.Empty:
            pass
        if not self._closed:
            self.after(100, self._drain_events)

    def _close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        if self._tray_icon is not None:
            try:
                self._tray_icon.stop()
            except Exception:
                pass
        self.destroy()


def main(argv: Optional[list[str]] = None) -> int:
    arguments = set(argv if argv is not None else sys.argv[1:])
    app = AgentReinsDesktop(start_background="--background" in arguments, start_watch="--start-watch" in arguments,
                            use_etw="--etw" in arguments)
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
