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
import queue
import threading
import time
import tkinter as tk
from dataclasses import asdict
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Optional

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

    def __init__(self) -> None:
        super().__init__()
        self.title("AgentReins")
        self.minsize(900, 620)
        self.geometry("1120x760")
        self.protocol("WM_DELETE_WINDOW", self._close)

        resolved_paths = platform_paths()
        default_path = Path(resolved_paths["evidence"])
        self.output_var = tk.StringVar(value=str(default_path))
        self.database_var = tk.StringVar(value=str(resolved_paths["database"]))
        self.interval_var = tk.StringVar(value="2")
        self.status_var = tk.StringVar(value="Ready")
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

        self._build_widgets()
        self.filter_var.trace_add("write", self._filter_changed)
        self._prepare_optional_tray()
        self.after(100, self._drain_events)

    def _build_widgets(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(4, weight=0)

        controls = ttk.Frame(self, padding=12)
        controls.grid(row=0, column=0, sticky="ew")
        controls.columnconfigure(1, weight=1)
        ttk.Label(controls, text="Evidence JSONL:").grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(controls, textvariable=self.output_var).grid(row=0, column=1, columnspan=4, sticky="ew")
        ttk.Button(controls, text="Browse...", command=self._browse).grid(row=0, column=5, padx=(8, 0))

        ttk.Label(controls, text="Evidence SQLite:").grid(row=1, column=0, sticky="w", pady=(8, 0), padx=(0, 8))
        ttk.Entry(controls, textvariable=self.database_var).grid(row=1, column=1, columnspan=4, sticky="ew", pady=(8, 0))
        ttk.Button(controls, text="Browse...", command=self._browse_database).grid(row=1, column=5, padx=(8, 0), pady=(8, 0))

        ttk.Label(controls, text="Refresh (seconds):").grid(row=2, column=0, sticky="w", pady=(8, 0), padx=(0, 8))
        ttk.Entry(controls, width=10, textvariable=self.interval_var).grid(row=2, column=1, sticky="w", pady=(8, 0))
        self.snapshot_button = ttk.Button(controls, text="Capture snapshot", command=self.capture_snapshot)
        self.snapshot_button.grid(row=2, column=2, pady=(8, 0), padx=(8, 0))
        self.watch_button = ttk.Button(controls, text="Start watch", command=self.toggle_watch)
        self.watch_button.grid(row=2, column=3, pady=(8, 0), padx=(8, 0))
        ttk.Checkbutton(controls, text="Auto refresh", variable=self.auto_refresh_var, command=self._set_auto_refresh).grid(
            row=2, column=4, pady=(8, 0), padx=(8, 0), sticky="w"
        )
        ttk.Button(controls, text="Background", command=self._enter_background).grid(
            row=2, column=5, pady=(8, 0), padx=(8, 0)
        )

        ttk.Separator(self, orient="horizontal").grid(row=3, column=0, sticky="ew")
        self.summary_frame = ttk.Frame(self, padding=(12, 10, 12, 4))
        self.summary_frame.grid(row=4, column=0, sticky="ew")
        for index in range(6):
            self.summary_frame.columnconfigure(index, weight=1)
        self.summary_values: dict[str, ttk.Label] = {}
        for index, (key, title, value) in enumerate(
            (
                ("platform", "Platform", "-"),
                ("agents", "Agents", "0"),
                ("processes", "Processes", "0"),
                ("connections", "Connections", "0"),
                ("fileEvents", "File changes", "0"),
                ("webEvents", "Web events", "0"),
            )
        ):
            card = ttk.LabelFrame(self.summary_frame, text=title, padding=(12, 6))
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
        ttk.Label(agent_header, text="Detected agents", font=("TkDefaultFont", 11, "bold")).grid(row=0, column=0, sticky="w")
        self.agent_cards = ttk.Frame(content)
        self.agent_cards.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        self.agent_cards.columnconfigure(0, weight=1)

        self.notebook = ttk.Notebook(content)
        self.notebook.grid(row=2, column=0, sticky="nsew")
        self.process_tab = ttk.Frame(self.notebook, padding=8)
        self.network_tab = ttk.Frame(self.notebook, padding=8)
        self.raw_tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.process_tab, text="Processes")
        self.notebook.add(self.network_tab, text="Connections")
        self.notebook.add(self.raw_tab, text="Raw JSON")
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
            ttk.Label(top, text="Filter:").grid(row=0, column=0, padx=(0, 6))
            ttk.Entry(top, textvariable=self.filter_var).grid(row=0, column=1, sticky="ew")
            ttk.Button(top, text="Clear", command=lambda: self.filter_var.set("")).grid(row=0, column=2, padx=(6, 0))
            tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")
            tree.grid(row=1, column=0, sticky="nsew")
            scroll = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
            scroll.grid(row=1, column=1, sticky="ns")
            tree.configure(yscrollcommand=scroll.set)
            for column, heading in zip(columns, headings):
                tree.heading(column, text=heading, command=lambda c=column, t=tree: self._sort_tree(t, c, False))
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

            self._tray_icon = pystray.Icon(
                "AgentReins", image, "AgentReins", pystray.Menu(
                    pystray.MenuItem("Show AgentReins", show, default=True),
                    pystray.MenuItem("Quit", quit_app),
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
        for child in self.agent_cards.winfo_children():
            child.destroy()
        if not agents:
            ttk.Label(self.agent_cards, text="No known Agent processes detected", foreground="#666666").grid(row=0, column=0, sticky="w")
        else:
            for index, agent in enumerate(agents):
                card = ttk.LabelFrame(self.agent_cards, text=str(agent.get("id", "unknown")).title(), padding=(10, 5))
                card.grid(row=0, column=index, sticky="ew", padx=(0 if index == 0 else 6, 0))
                self.agent_cards.columnconfigure(index, weight=1)
                ttk.Label(card, text=f"{agent.get('instances', 0)} instance(s)").pack(anchor="w")
                ttk.Label(card, text=f"PID: {', '.join(str(pid) for pid in agent.get('processIds', [])) or '-'}").pack(anchor="w")
        self._apply_filter()
        self._set_output(self._render_snapshot(record))

    def capture_snapshot(self) -> None:
        if self._closed:
            return
        self.snapshot_button.configure(state="disabled")
        self.status_var.set("Collecting snapshot...")
        destination = Path(self.output_var.get()).expanduser()
        database = Path(self.database_var.get()).expanduser()
        threading.Thread(target=self._snapshot_worker, args=(destination, database), daemon=True, name="agentreins-snapshot").start()

    def _snapshot_worker(self, destination: Path, database: Path) -> None:
        store: Optional[EvidenceStore] = None
        try:
            record = snapshot()
            store = EvidenceStore(database)
            web_events = WebEvidenceReader(Path(platform_paths()["webEvidence"])).poll()
            record["webEvents"] = web_events
            write_snapshot(record, destination)
            store.append_web_events(web_events)
            store.append_snapshot(record)
            self._events.put(("snapshot", record))
        except Exception as exc:  # Keep UI alive when an OS collector is unavailable.
            self._events.put(("error", f"Snapshot failed: {exc}"))
        finally:
            if store is not None:
                store.close()

    def toggle_watch(self) -> None:
        if self._watch_thread and self._watch_thread.is_alive():
            self._stop.set()
            self.watch_button.configure(state="disabled")
            self.status_var.set("Stopping watch...")
            return
        try:
            interval = max(0.25, float(self.interval_var.get()))
        except ValueError:
            messagebox.showerror("Invalid interval", "Enter a number of at least 0.25 seconds.")
            return
        self._stop.clear()
        self.watch_button.configure(text="Stop watch")
        self.status_var.set("Watching...")
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
            file_watcher = create_file_watcher([Path(paths["data"])])
            web_reader = WebEvidenceReader(Path(paths["webEvidence"]))
            while not self._stop.is_set():
                started = time.monotonic()
                try:
                    record = snapshot()
                    file_events = file_watcher.poll() if file_watcher is not None else []
                    web_events = web_reader.poll()
                    record["fileEvents"] = [asdict(event) for event in file_events]
                    record["webEvents"] = web_events
                    write_snapshot(record, destination)
                    store.append_web_events(web_events)
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
                    self.status_var.set(f"Last snapshot: {value.get('timestamp', 'unknown')}  |  Saved to {self.output_var.get()}")
                    self.snapshot_button.configure(state="normal")
                elif kind == "error":
                    self.status_var.set(str(value))
                    if not (self._watch_thread and self._watch_thread.is_alive()):
                        self.snapshot_button.configure(state="normal")
                elif kind == "watch-stopped":
                    self.watch_button.configure(text="Start watch", state="normal")
                    if not self._closed:
                        self.status_var.set("Watch stopped")
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


def main() -> int:
    app = AgentReinsDesktop()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
