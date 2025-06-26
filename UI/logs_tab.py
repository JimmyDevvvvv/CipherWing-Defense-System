import tkinter as tk
from tkinter import ttk, messagebox
import json
import os

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
LOG_FILE_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', 'logs', 'interceptor_events.json'))

HEADER_TEXT = (
    f"{'STATUS':<10} | "
    f"{'FAMILY':<12} | "
    f"{'CONF':>6} | "
    f"{'ACTION':<20} | "
    f"PATH\n"
    + "-" * 90 + "\n"
)


class LogsTab(tk.Frame):
    """Scrollable viewer for interceptor_events.json"""

    def __init__(self, parent):
        super().__init__(parent, bg="#1e1e1e")

        # ------------------------------------------------------------------
        # Title
        # ------------------------------------------------------------------
        title = tk.Label(
            self,
            text="📜 Log Viewer – Interceptor Events",
            font=("Helvetica", 18, "bold"),
            fg="white",
            bg="#1e1e1e",
        )
        title.pack(pady=10)

        # ------------------------------------------------------------------
        # Text widget + scrollbar
        # ------------------------------------------------------------------
        self.text_area = tk.Text(
            self,
            wrap="none",
            bg="#111",
            fg="#0f0",
            insertbackground="white",
            font=("Courier New", 10),
        )
        self.text_area.pack(fill="both", expand=True, padx=10, pady=10)

        scrollbar_y = tk.Scrollbar(self, command=self.text_area.yview)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.text_area.config(yscrollcommand=scrollbar_y.set)

        # Color tags
        self.text_area.tag_config("malicious", foreground="#ff5252")  # red
        self.text_area.tag_config("clean", foreground="#00e676")      # green
        self.text_area.tag_config("header", foreground="#00b0ff")     # cyan

        # ------------------------------------------------------------------
        # Buttons
        # ------------------------------------------------------------------
        btn_frame = tk.Frame(self, bg="#1e1e1e")
        btn_frame.pack(pady=5)

        ttk.Button(btn_frame, text="🔁 Refresh", command=self.load_logs)\
           .pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="🧼 Clear Logs", command=self.clear_logs)\
           .pack(side=tk.LEFT, padx=5)

        # Initial population
        self.load_logs()

    # ----------------------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------------------
    def load_logs(self):
        """Read the JSONL file and display formatted entries."""
        self.text_area.config(state=tk.NORMAL)
        self.text_area.delete("1.0", tk.END)

        # Header
        self.text_area.insert(tk.END, HEADER_TEXT, ("header",))

        if not os.path.exists(LOG_FILE_PATH):
            self.text_area.insert(tk.END, "[!] No log file found.\n", ("malicious",))
            self.text_area.config(state=tk.DISABLED)
            return

        try:
            with open(LOG_FILE_PATH, "r") as f:
                for raw_line in f:
                    raw_line = raw_line.strip()
                    if not raw_line:
                        continue

                    try:
                        log = json.loads(raw_line)
                    except json.JSONDecodeError:
                        # show raw if json malformed
                        self.text_area.insert(
                            tk.END, f"[RAW] {raw_line}\n", ("malicious",)
                        )
                        continue

                    status     = log.get("status", log.get("verdict", "N/A")).upper()
                    family     = log.get("family", "Unknown")
                    confidence = (
                        f"{log.get('ml_confidence', 0):.2f}"
                        if "ml_confidence" in log
                        else "--"
                    )
                    action     = log.get("action", "-")
                    file_path  = log.get("file", log.get("file_path", ""))

                    line = (
                        f"{status:<10} | "
                        f"{family:<12} | "
                        f"{confidence:>6} | "
                        f"{action:<20} | "
                        f"{file_path}\n"
                    )

                    tag = "malicious" if status == "MALICIOUS" else "clean"
                    self.text_area.insert(tk.END, line, (tag,))

        except Exception as e:
            self.text_area.insert(
                tk.END, f"[ERROR] Failed to load log: {e}\n", ("malicious",)
            )

        self.text_area.config(state=tk.DISABLED)

    def clear_logs(self):
        """Wipe the log file after confirmation."""
        if not os.path.exists(LOG_FILE_PATH):
            messagebox.showinfo("Info", "Log file does not exist.")
            return

        if messagebox.askyesno("Confirm", "Clear interceptor_events.json?"):
            try:
                with open(LOG_FILE_PATH, "w"):
                    pass  # truncate
                self.load_logs()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear logs: {e}")
