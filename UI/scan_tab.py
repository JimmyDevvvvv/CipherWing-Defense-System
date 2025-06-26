import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import os
import sys

# === Import your core scanner backend ===
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.scanner_core import run_full_scan

class ScanTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#1e1e1e")

        self.file_path = None
        self.scan_result = None
        self.shap_img_refs = []

        # === Title ===
        title = tk.Label(self, text="🛡️ Manual File Scan",
                         font=("Helvetica", 18, "bold"),
                         fg="white", bg="#1e1e1e")
        title.pack(pady=10)

        # === File Picker ===
        picker_frame = tk.Frame(self, bg="#1e1e1e")
        picker_frame.pack(pady=5)

        ttk.Button(picker_frame, text="📂 Choose File", command=self.pick_file)\
           .pack(side=tk.LEFT, padx=5)

        self.path_label = tk.Label(picker_frame, text="No file selected.",
                                   fg="gray", bg="#1e1e1e", font=("Courier", 9))
        self.path_label.pack(side=tk.LEFT, padx=10)

        # === Scan Button ===
        ttk.Button(self, text="🔍 Scan File", command=self.run_scan)\
           .pack(pady=10)

        # === Result Output ===
        self.result_label = tk.Label(self, text="", fg="white", bg="#1e1e1e",
                                     font=("Helvetica", 12))
        self.result_label.pack(pady=10)

        # === SHAP Visual Container ===
        self.shap_frame = tk.Frame(self, bg="#1e1e1e")
        self.shap_frame.pack(pady=5)

    # ----------------------------------------------------------------------
    # File Picker
    # ----------------------------------------------------------------------
    def pick_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path = file_path
            self.path_label.config(text=file_path, fg="#0f0")
            self.result_label.config(text="", fg="white")
            self.clear_shap()

    # ----------------------------------------------------------------------
    # Scan Runner
    # ----------------------------------------------------------------------
    def run_scan(self):
        if not self.file_path:
            messagebox.showwarning("No File", "Please select a file to scan.")
            return

        self.result_label.config(text="🧠 Scanning… please wait.", fg="#FFD700")
        self.update_idletasks()

        try:
            result = run_full_scan(self.file_path)
            self.scan_result = result
            self.show_result()
        except Exception as e:
            self.result_label.config(text=f"[ERROR] {e}", fg="#ff5252")

    # ----------------------------------------------------------------------
    # Scan Result Display
    # ----------------------------------------------------------------------
    def show_result(self):
        verdict = self.scan_result.get("verdict", "unknown").upper()
        family  = self.scan_result.get("family", "unknown")
        conf    = self.scan_result.get("confidence", 0)

        if verdict in ("CLEAN", "BENIGN", "SAFE"):
            color = "#00e676"  # Green
        elif verdict in ("MALICIOUS", "DANGEROUS", "INFECTED"):
            color = "#ff5252"  # Red
        else:
            color = "#FFD700"  # Yellow (unknown or ambiguous)

        msg = f"🔎 Verdict: {verdict}\n🧬 Family: {family}\n🎯 Confidence: {conf:.2f}"
        self.result_label.config(text=msg, fg=color)

        self.show_shap_images()

    # ----------------------------------------------------------------------
    # SHAP Visualizer
    # ----------------------------------------------------------------------
    def show_shap_images(self):
        self.clear_shap()

        malware_path = self.scan_result.get("shap_malware")
        family_path  = self.scan_result.get("shap_family")

        for label, path in [("Malware SHAP", malware_path), ("Family SHAP", family_path)]:
            if path and os.path.exists(path):
                try:
                    img = Image.open(path)
                    img = img.resize((320, 240))
                    img_tk = ImageTk.PhotoImage(img)

                    panel = tk.Label(self.shap_frame, image=img_tk, bg="#1e1e1e")
                    caption = tk.Label(self.shap_frame, text=label, fg="white", bg="#1e1e1e")

                    panel.image = img_tk  # retain reference
                    self.shap_img_refs.append(panel)

                    caption.pack()
                    panel.pack(padx=10, pady=5)
                except Exception as e:
                    print(f"Error loading SHAP image {path}: {e}")

    # ----------------------------------------------------------------------
    # Clear SHAP Display
    # ----------------------------------------------------------------------
    def clear_shap(self):
        for widget in self.shap_frame.winfo_children():
            widget.destroy()
        self.shap_img_refs.clear()
