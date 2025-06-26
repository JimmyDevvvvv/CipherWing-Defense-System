import tkinter as tk
from tkinter import ttk, messagebox
import os
import sys
import subprocess
import shlex
import json

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR       = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
SCRIPT_DIR     = BASE_DIR            # same level as agent/
INTERCEPTOR_SO = os.path.join(BASE_DIR, "agent", "interceptor.so")
LOG_FILE_PATH  = os.path.join(BASE_DIR, "logs", "interceptor_events.json")

# ---------------------------------------------------------------------------
# Shell Tab
# ---------------------------------------------------------------------------
class ShellTab(tk.Frame):
    """
    A GUI wrapper around cipherwing_shell.py functionality:
    - Built-ins: cd, ls, pwd, clear, exit, help
    - External commands executed with LD_PRELOAD=interceptor.so
    """
    def __init__(self, parent):
        super().__init__(parent, bg="#1e1e1e")

        self.current_dir = BASE_DIR
        self.init_ui()

    # ----------------------------------------------------------------------
    # UI Setup
    # ----------------------------------------------------------------------
    def init_ui(self):
        tk.Label(self, text="🐚 CipherWing Shell",
                 font=("Helvetica", 18, "bold"),
                 fg="white", bg="#1e1e1e").pack(pady=10)

        # Terminal display
        self.terminal = tk.Text(self, height=20, bg="#000", fg="#00FF00",
                                insertbackground="white",
                                font=("Courier", 10))
        self.terminal.pack(fill="both", expand=True, padx=10, pady=5)
        self.terminal.config(state=tk.DISABLED)

        # Command entry
        self.cmd_entry = tk.Entry(self, bg="#222", fg="white",
                                  insertbackground="white",
                                  font=("Courier", 10))
        self.cmd_entry.pack(fill="x", padx=10, pady=5)
        self.cmd_entry.bind("<Return>", self.on_enter)

        self.history = []
        self.hist_pos = -1
        self.cmd_entry.bind("<Up>",   self.history_up)
        self.cmd_entry.bind("<Down>", self.history_down)

        # Banner
        self.append("\n🛡️  Welcome to CipherWing Shell — GUI Edition\n"
                    "Built-ins: cd, ls, pwd, clear, exit, help\n\n")
        self.prompt()

    # ----------------------------------------------------------------------
    # History navigation
    # ----------------------------------------------------------------------
    def history_up(self, event):
        if not self.history: return
        self.hist_pos = max(0, self.hist_pos - 1)
        self.cmd_entry.delete(0, tk.END)
        self.cmd_entry.insert(0, self.history[self.hist_pos])

    def history_down(self, event):
        if not self.history: return
        self.hist_pos = min(len(self.history) - 1, self.hist_pos + 1)
        self.cmd_entry.delete(0, tk.END)
        self.cmd_entry.insert(0, self.history[self.hist_pos])

    # ----------------------------------------------------------------------
    # Core helpers
    # ----------------------------------------------------------------------
    def append(self, text, newline=True):
        self.terminal.config(state=tk.NORMAL)
        self.terminal.insert(tk.END, text + ("\n" if newline else ""))
        self.terminal.see(tk.END)
        self.terminal.config(state=tk.DISABLED)

    def prompt(self):
        cwd_name = os.path.basename(self.current_dir) or "/"
        self.append(f"💀 cipherwing ({cwd_name})> ", newline=False)

    # ----------------------------------------------------------------------
    # Command handler
    # ----------------------------------------------------------------------
    def on_enter(self, event=None):
        cmd = self.cmd_entry.get().strip()
        self.cmd_entry.delete(0, tk.END)

        # Store history
        if cmd:
            self.history.append(cmd)
            self.hist_pos = len(self.history)

        self.append(cmd)  # echo command
        self.execute(cmd)
        self.prompt()

    def execute(self, user_input: str):
        if not user_input:
            return

        # === Built-ins ===
        if user_input in {"exit", "quit"}:
            messagebox.showinfo("Exit", "Use the main window controls to quit the app.")
            return
        if user_input == "clear":
            self.terminal.config(state=tk.NORMAL)
            self.terminal.delete("1.0", tk.END)
            self.terminal.config(state=tk.DISABLED)
            return
        if user_input == "help":
            self.append("Built-ins: cd, ls, pwd, clear, exit, help")
            return
        if user_input == "pwd":
            self.append(self.current_dir)
            return
        if user_input.startswith("cd"):
            parts = user_input.split(maxsplit=1)
            target = parts[1] if len(parts) > 1 else os.path.expanduser("~")
            new_path = os.path.abspath(os.path.join(self.current_dir, target))
            if os.path.isdir(new_path):
                self.current_dir = new_path
            else:
                self.append(f"[!] No such directory: {new_path}")
            return
        if user_input == "ls":
            try:
                self.append("  ".join(os.listdir(self.current_dir)))
            except Exception as e:
                self.append(f"[!] ls failed: {e}")
            return
        if user_input == "list":                          # extra helper
            self.list_recent()
            return

        # === External command ===
        if not os.path.exists(INTERCEPTOR_SO):
            self.append(f"[!] interceptor.so not found at {INTERCEPTOR_SO}")
            return

        try:
            command_parts = shlex.split(user_input)
        except ValueError as ve:
            self.append(f"[!] Parse error: {ve}")
            return

        env = os.environ.copy()
        env["LD_PRELOAD"] = INTERCEPTOR_SO

        try:
            proc = subprocess.Popen(command_parts,
                                    cwd=self.current_dir,
                                    env=env,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    text=True)
            out, err = proc.communicate()
            if out:
                self.append(out.rstrip())
            if err:
                self.append(err.rstrip())
        except FileNotFoundError:
            self.append(f"[!] Command not found: {command_parts[0]}")
        except Exception as e:
            self.append(f"[!] Error running command: {e}")

    # ----------------------------------------------------------------------
    # Helper: show last 5 detections
    # ----------------------------------------------------------------------
    def list_recent(self):
        if not os.path.exists(LOG_FILE_PATH):
            self.append("[!] No log file found.")
            return
        try:
            with open(LOG_FILE_PATH, "r") as f:
                lines = f.readlines()[-5:]
            self.append("\nRecent Interceptions:")
            for ln in lines:
                try:
                    entry = json.loads(ln)
                    ts   = entry.get("timestamp", "?")
                    path = os.path.basename(entry.get("file", entry.get("file_path", '')))
                    stat = entry.get("status", "unknown").upper()
                    self.append(f" - [{ts}] {stat} - {path}")
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            self.append(f"[!] Could not read log: {e}")
