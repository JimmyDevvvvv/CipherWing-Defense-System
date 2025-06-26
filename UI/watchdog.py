import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess, sys, os, psutil, threading, time, signal

BASE_DIR   = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
AGENT_PATH = os.path.join(BASE_DIR, "agent", "main_agent.py")

class WatchdogTab(tk.Frame):
    REFRESH_INTERVAL = 2000  # ms

    def __init__(self, parent):
        super().__init__(parent, bg="#1e1e1e")
        self.proc = None
        self.mode_manual = tk.BooleanVar(value=False)
        self._init_ui()
        self._start_status_loop()

    # ───────────────────────────────────────────────── UI
    def _init_ui(self):
        tk.Label(self, text="🐶 CipherWing Watchdog",
                 font=("Helvetica", 18, "bold"),
                 fg="white", bg="#1e1e1e").pack(pady=10)

        self.status_lbl = tk.Label(self, text="Status: ❌ Stopped",
                                   fg="#ff5252", bg="#1e1e1e",
                                   font=("Helvetica", 12, "bold"))
        self.status_lbl.pack(pady=5)

        btns = tk.Frame(self, bg="#1e1e1e"); btns.pack(pady=5)

        ttk.Checkbutton(btns, text="Manual Mode", variable=self.mode_manual)\
            .pack(side=tk.LEFT, padx=5)

        ttk.Button(btns, text="▶️ Start", command=self.start_watchdog)\
            .pack(side=tk.LEFT, padx=5)

        ttk.Button(btns, text="⏹️ Stop", command=self.stop_watchdog)\
            .pack(side=tk.LEFT, padx=5)

        self.console = scrolledtext.ScrolledText(self, height=15, state=tk.DISABLED,
                                                 bg="#000", fg="#0f0", font=("Courier", 9))
        self.console.pack(fill="both", expand=True, padx=10, pady=10)

    # ───────────────────────────────────── Process control
    def start_watchdog(self):
        if self.proc and self.proc.poll() is None:
            messagebox.showinfo("Running", "Watchdog is already running.")
            return
        if not os.path.exists(AGENT_PATH):
            messagebox.showerror("Error", f"main_agent.py not found:\n{AGENT_PATH}")
            return

        cmd = [sys.executable, "-u", AGENT_PATH]  # ← Unbuffered
        if self.mode_manual.get():
            cmd.append("--manual")

        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1  # ← Line-buffered
        )

        threading.Thread(target=self._pipe_output, daemon=True).start()
        self._update_status(True)

    def stop_watchdog(self):
        if self.proc and self.proc.poll() is None:
            try:
                os.kill(self.proc.pid, signal.SIGINT)
            except Exception:
                self.proc.terminate()
        else:
            messagebox.showinfo("Not running", "Watchdog is not running.")

    # ───────────────────────────────────── Console piping
    def _pipe_output(self):
        for line in iter(self.proc.stdout.readline, ''):
            self.console.configure(state=tk.NORMAL)
            self.console.insert(tk.END, line)
            self.console.see(tk.END)
            self.console.configure(state=tk.DISABLED)

    # ───────────────────────────────────── Status updater
    def _start_status_loop(self):
        self._refresh_status()
        self.after(self.REFRESH_INTERVAL, self._start_status_loop)

    def _refresh_status(self):
        running = self.proc and self.proc.poll() is None
        self._update_status(running)

    def _update_status(self, running: bool):
        if running:
            self.status_lbl.config(text=f"Status: ✅ Running (PID {self.proc.pid})",
                                   fg="#00e676")
        else:
            self.status_lbl.config(text="Status: ❌ Stopped",
                                   fg="#ff5252")
