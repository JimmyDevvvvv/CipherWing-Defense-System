import tkinter as tk
from tkinter import ttk, messagebox
import yaml
import os

CONFIG_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', 'config.yaml'))

class SettingsTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#1e1e1e")

        self.config_data = {}
        self.vars = {}
        self.init_ui()
        self.load_config()

    def init_ui(self):
        tk.Label(self, text="⚙️ CipherWing Settings",
                 font=("Helvetica", 18, "bold"),
                 fg="white", bg="#1e1e1e").pack(pady=10)

        form = tk.Frame(self, bg="#1e1e1e")
        form.pack(pady=10)

        # === Checkboxes ===
        for key, label in [
            ("auto_respond", "Auto Respond to Threats"),
            ("enable_ml", "Enable ML Detection"),
            ("enable_yara", "Enable YARA Engine")
        ]:
            var = tk.BooleanVar()
            chk = ttk.Checkbutton(form, text=label, variable=var)
            chk.pack(anchor="w", pady=5)
            self.vars[key] = var

        # === Threshold Entry ===
        tk.Label(form, text="Auto-Quarantine Threshold (0.0 - 1.0)",
                 fg="white", bg="#1e1e1e").pack(anchor="w", pady=(20, 0))
        self.threshold_entry = ttk.Entry(form)
        self.threshold_entry.pack(anchor="w", pady=5)

        # === Log path (readonly display) ===
        self.log_path_label = tk.Label(form, text="Log Path: N/A",
                                       fg="#ccc", bg="#1e1e1e", font=("Courier", 9))
        self.log_path_label.pack(anchor="w", pady=(10, 0))

        # === Save button ===
        ttk.Button(self, text="💾 Save Settings", command=self.save_config)\
           .pack(pady=15)

    def load_config(self):
        if not os.path.exists(CONFIG_PATH):
            messagebox.showerror("Error", f"config.yaml not found:\n{CONFIG_PATH}")
            return

        with open(CONFIG_PATH, "r") as f:
            self.config_data = yaml.safe_load(f)

        # Set checkboxes
        for key in ["auto_respond", "enable_ml", "enable_yara"]:
            if key in self.config_data:
                self.vars[key].set(bool(self.config_data.get(key, False)))

        # Set threshold
        thresh = self.config_data.get("auto_quarantine_threshold", 0.85)
        self.threshold_entry.delete(0, tk.END)
        self.threshold_entry.insert(0, str(thresh))

        # Show log path
        log_path = self.config_data.get("log_path", "./logs")
        self.log_path_label.config(text=f"Log Path: {log_path}")

    def save_config(self):
        try:
            for key in self.vars:
                self.config_data[key] = self.vars[key].get()

            try:
                threshold = float(self.threshold_entry.get())
                if not 0 <= threshold <= 1:
                    raise ValueError
                self.config_data["auto_quarantine_threshold"] = threshold
            except ValueError:
                messagebox.showerror("Error", "Threshold must be a float between 0.0 and 1.0")
                return

            with open(CONFIG_PATH, "w") as f:
                yaml.dump(self.config_data, f)

            messagebox.showinfo("Success", "Configuration saved.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save config:\n{str(e)}")
