#!/usr/bin/env python3
"""Small Windows/Linux desktop shell for the AgentReins portable collector.

The collector deliberately remains a separate, dependency-free module. This
file only provides a Tkinter presentation layer, so the same executable can
be packaged by PyInstaller on Windows and run from source on Linux. Collection
is performed on worker threads because CIM/ss can take a few seconds on a busy
machine and must not freeze the Tk event loop.
"""

from __future__ import annotations

import json
import queue
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Optional

try:  # Running as ``python portable/agentreins_desktop.py``.
    from agentreins_portable import platform_paths, snapshot, write_snapshot
except ImportError:  # Running as an installed package (or a test harness).
    from .agentreins_portable import platform_paths, snapshot, write_snapshot


class AgentReinsDesktop(tk.Tk):
    """A minimal, responsive desktop UI around the portable collector."""

    def __init__(self) -> None:
        super().__init__()
        self.title("AgentReins")
        self.minsize(760, 520)
        self.geometry("920x650")
        self.protocol("WM_DELETE_WINDOW", self._close)

        default_path = Path(platform_paths()["evidence"])
        self.output_var = tk.StringVar(value=str(default_path))
        self.interval_var = tk.StringVar(value="2")
        self.status_var = tk.StringVar(value="Ready")
        self._events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self._stop = threading.Event()
        self._watch_thread: Optional[threading.Thread] = None
        self._closed = False

        self._build_widgets()
        self.after(100, self._drain_events)

    def _build_widgets(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        controls = ttk.Frame(self, padding=12)
        controls.grid(row=0, column=0, sticky="ew")
        controls.columnconfigure(1, weight=1)

        ttk.Label(controls, text="Evidence JSONL:").grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(controls, textvariable=self.output_var).grid(row=0, column=1, columnspan=2, sticky="ew")
        ttk.Button(controls, text="Browse…", command=self._browse).grid(row=0, column=3, padx=(8, 0))

        ttk.Label(controls, text="Watch interval (seconds):").grid(row=1, column=0, sticky="w", pady=(8, 0), padx=(0, 8))
        ttk.Entry(controls, width=10, textvariable=self.interval_var).grid(row=1, column=1, sticky="w", pady=(8, 0))
        self.snapshot_button = ttk.Button(controls, text="Capture snapshot", command=self.capture_snapshot)
        self.snapshot_button.grid(row=1, column=2, pady=(8, 0), padx=(8, 0))
        self.watch_button = ttk.Button(controls, text="Start watch", command=self.toggle_watch)
        self.watch_button.grid(row=1, column=3, pady=(8, 0), padx=(8, 0))

        ttk.Separator(self, orient="horizontal").grid(row=1, column=0, sticky="ew")
        self.output = tk.Text(self, wrap="none", undo=False, font=("Consolas", 10), state="disabled")
        self.output.grid(row=2, column=0, sticky="nsew", padx=12, pady=12)
        yscroll = ttk.Scrollbar(self, orient="vertical", command=self.output.yview)
        yscroll.grid(row=2, column=1, sticky="ns", pady=12)
        xscroll = ttk.Scrollbar(self, orient="horizontal", command=self.output.xview)
        xscroll.grid(row=3, column=0, sticky="ew", padx=12)
        self.output.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)

        status = ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w", padding=(8, 4))
        status.grid(row=4, column=0, columnspan=2, sticky="ew", padx=12, pady=(8, 12))

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

    def _set_output(self, text: str) -> None:
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("1.0", text)
        self.output.configure(state="disabled")

    def _render_snapshot(self, record: dict[str, Any]) -> str:
        agents = record.get("agents") or []
        connections = record.get("connections") or []
        heading = (
            f"Platform: {record.get('platform', 'unknown')}    "
            f"Processes: {len(record.get('processes') or [])}    "
            f"Connections: {len(connections)}    "
            f"Agents: {len(agents)}\n\n"
        )
        return heading + json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True)

    def capture_snapshot(self) -> None:
        if self._closed:
            return
        self.snapshot_button.configure(state="disabled")
        self.status_var.set("Collecting snapshot…")
        threading.Thread(target=self._snapshot_worker, daemon=True, name="agentreins-snapshot").start()

    def _snapshot_worker(self) -> None:
        try:
            record = snapshot()
            write_snapshot(record, Path(self.output_var.get()).expanduser())
            self._events.put(("snapshot", record))
        except Exception as exc:  # Keep UI alive when an OS collector is unavailable.
            self._events.put(("error", f"Snapshot failed: {exc}"))

    def toggle_watch(self) -> None:
        if self._watch_thread and self._watch_thread.is_alive():
            self._stop.set()
            self.watch_button.configure(state="disabled")
            self.status_var.set("Stopping watch…")
            return
        try:
            interval = max(0.25, float(self.interval_var.get()))
        except ValueError:
            messagebox.showerror("Invalid interval", "Enter a number of at least 0.25 seconds.")
            return
        self._stop.clear()
        self.watch_button.configure(text="Stop watch")
        self.status_var.set("Watching…")
        self._watch_thread = threading.Thread(target=self._watch_worker, args=(interval,), daemon=True, name="agentreins-watch")
        self._watch_thread.start()

    def _watch_worker(self, interval: float) -> None:
        destination = Path(self.output_var.get()).expanduser()
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                record = snapshot()
                write_snapshot(record, destination)
                self._events.put(("snapshot", record))
            except Exception as exc:
                self._events.put(("error", f"Watch failed: {exc}"))
            elapsed = time.monotonic() - started
            self._stop.wait(max(0.0, interval - elapsed))
        self._events.put(("watch-stopped", None))

    def _drain_events(self) -> None:
        try:
            while True:
                kind, value = self._events.get_nowait()
                if kind == "snapshot":
                    self._set_output(self._render_snapshot(value))
                    self.status_var.set(f"Snapshot saved to {self.output_var.get()}")
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
        self._closed = True
        self._stop.set()
        self.destroy()


def main() -> int:
    app = AgentReinsDesktop()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
