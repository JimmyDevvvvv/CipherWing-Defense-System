import tkinter as tk
from tkinter import ttk
import subprocess
import os
import sys

# Import all tabs
from dashboard import DashboardTab
from scan_tab import ScanTab
from soar_tab import SoarTab
from logs_tab import LogsTab
from settings_tab import SettingsTab
from shell_tab import ShellTab
from watchdog import WatchdogTab

# Get base project directory
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

 
# ──────────────────────────────────────────────────────────────
# GUI Class
# ──────────────────────────────────────────────────────────────
class CipherWingUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🛡️ CipherWing — AI-Powered Malware Defense")
        self.geometry("1200x720")
        self.configure(bg="#1e1e1e")

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill='both', expand=True)

        self.tabs = {
            "Analytics": DashboardTab(self.notebook),
            "Scan": ScanTab(self.notebook),
            "SOAR Actions": SoarTab(self.notebook),
            "Logs": LogsTab(self.notebook),
            "Shell": ShellTab(self.notebook),
            "Settings": SettingsTab(self.notebook),
            "Watchdog": WatchdogTab(self.notebook),
        }

        for tab_name, frame in self.tabs.items():
            self.notebook.add(frame, text=tab_name)

# ──────────────────────────────────────────────────────────────
# Entrypoint
# ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = CipherWingUI()
    app.mainloop()
