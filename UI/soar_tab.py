import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
import os
import sys
import json

# === Add CipherWing paths ===
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from soar.soar_engine import execute_soar_response

LOG_FILE_PATH = os.path.join(BASE_DIR, "logs", "interceptor_events.json")

class SoarTab(tk.Frame):
    """Manual SOAR response tab with SHAP forensics overlay."""
    def __init__(self, parent):
        super().__init__(parent, bg="#1e1e1e")
        self.threats = []
        self.selected_idx = None
        self.shap_images = []             # hold refs for popup
        self.init_ui()
        self.load_threats()

    # ------------------------------------------------------------------ UI
    def init_ui(self):
        tk.Label(self, text="🧠 SOAR Manual Response",
                 font=("Helvetica", 18, "bold"),
                 fg="white", bg="#1e1e1e").pack(pady=10)

        # === Threat table ===
        self.tree = ttk.Treeview(
            self,
            columns=("Timestamp", "Family", "Confidence", "Path"),
            show="headings",
            height=12
        )
        for col in ("Timestamp", "Family", "Confidence", "Path"):
            self.tree.heading(col, text=col)
        self.tree.column("Confidence", width=100, anchor="center")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.pack(fill="both", expand=True, padx=10, pady=5)

        # === Action buttons ===
        btns = tk.Frame(self, bg="#1e1e1e")
        btns.pack(pady=10)

        for label, action in [
            ("🧼 Quarantine", "quarantine"),
            ("🗑️ Delete",    "delete"),
            ("💀 Kill",      "kill"),
            ("❌ Ignore",    "log")
        ]:
            ttk.Button(btns, text=label,
                       command=lambda act=action: self.apply_action(act))\
                .pack(side=tk.LEFT, padx=5)

        # View details button
        ttk.Button(btns, text="🔍 View Details", command=self.view_details)\
            .pack(side=tk.LEFT, padx=5)

        # Refresh button
        ttk.Button(self, text="🔄 Refresh", command=self.load_threats)\
           .pack(pady=10)

    # --------------------------------------------------------- Load threats
    def load_threats(self):
        self.tree.delete(*self.tree.get_children())
        self.threats.clear()

        if not os.path.exists(LOG_FILE_PATH):
            return

        try:
            with open(LOG_FILE_PATH, "r") as f:
                for line in reversed(f.readlines()):
                    try:
                        data = json.loads(line)
                        if data.get("status") == "malicious":
                            self.threats.append(data)
                            self.tree.insert(
                                "", tk.END,
                                values=(
                                    data.get("timestamp", "?"),
                                    data.get("family",    "?"),
                                    f"{data.get('ml_confidence', 0):.2f}",
                                    os.path.basename(data.get("file",
                                                data.get("file_path", '???')))
                                )
                            )
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load threats: {e}")

    # ---------------------------------------------------- Selection handler
    def on_select(self, _event):
        sel = self.tree.selection()
        self.selected_idx = self.tree.index(sel[0]) if sel else None

    # ------------------------------------------------------- SOAR actions
    def apply_action(self, action: str):
        if self.selected_idx is None:
            messagebox.showwarning("No Selection", "Please select a threat first.")
            return

        scan = self.threats[self.selected_idx]
        scan["action"] = action

        try:
            result = execute_soar_response(scan, source="manual")
            messagebox.showinfo(
                "SOAR Response",
                f"{result['action'].upper()} executed for:\n{scan['file']}"
            )
        except Exception as e:
            messagebox.showerror("SOAR Error", f"Failed to apply action:\n{e}")

    # --------------------------------------------------- SHAP / forensics
    def view_details(self):
        if self.selected_idx is None:
            messagebox.showwarning("No Selection", "Select a threat first.")
            return

        scan = self.threats[self.selected_idx]

        popup = tk.Toplevel(self)
        popup.title("🧬 Threat Details")
        popup.configure(bg="#1e1e1e")
        popup.geometry("820x620")

        # ---- Metadata ----
        info = (
            f"🧾 File: {scan.get('file', 'N/A')}\n"
            f"🧠 Family: {scan.get('family', 'N/A')}\n"
            f"🎯 Confidence: {scan.get('ml_confidence', 0):.2f}\n"
            f"🚩 Flags: {', '.join(scan.get('flags', [])) or 'None'}"
        )
        tk.Label(
            popup, text=info, justify="left",
            font=("Courier", 10), fg="white", bg="#1e1e1e"
        ).pack(padx=10, pady=10, anchor="w")

        # ---- SHAP images ----
        frame = tk.Frame(popup, bg="#1e1e1e")
        frame.pack(pady=5)

        self.shap_images.clear()
        for label, k in [("Malware SHAP", "shap_malware"),
                         ("Family SHAP",  "shap_family")]:
            path = scan.get(k)
            if path and os.path.exists(path):
                try:
                    img   = Image.open(path).resize((380, 280))
                    photo = ImageTk.PhotoImage(img)

                    tk.Label(frame, text=label, fg="white",
                             bg="#1e1e1e").pack()
                    panel = tk.Label(frame, image=photo, bg="#1e1e1e")
                    panel.image = photo           # keep reference
                    self.shap_images.append(panel)
                    panel.pack(padx=10, pady=5)
                except Exception:
                    tk.Label(frame, text=f"[!] Failed to load {label}",
                             fg="red", bg="#1e1e1e").pack()
            else:
                tk.Label(frame, text=f"[No {label}]", fg="#888",
                         bg="#1e1e1e").pack()
