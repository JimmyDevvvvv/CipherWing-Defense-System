import tkinter as tk, tkinter.ttk as ttk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from backend_connector import load_events, family_distribution, scans_over_time


REFRESH_SECS = 5        # auto-refresh interval


class DashboardTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#1e1e1e")

        title = tk.Label(
            self, text="📊 Analytics Dashboard",
            font=("Helvetica", 18, "bold"),
            fg="white", bg="#1e1e1e")
        title.pack(pady=10)

        # matplotlib figure / axes holders
        self.fig, self.axs = plt.subplots(1, 2, figsize=(10, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, master=self)
        self.canvas.get_tk_widget().pack(pady=20)

        self.refresh_charts()       # initial draw
        self.after(REFRESH_SECS * 1000, self.auto_refresh)

    # --------------------------------------------------------
    def refresh_charts(self):
        events = load_events()

        # -- LEFT ::: Pie chart (families)
        fam_counter = family_distribution(events)
        labels, sizes = zip(*fam_counter.items()) if fam_counter else (["No data"], [1])

        self.axs[0].clear()
        self.axs[0].pie(sizes, labels=labels, autopct="%1.1f%%", startangle=140)
        self.axs[0].set_title("Threat Type Distribution")

        # -- RIGHT ::: Line chart (scans over time)
        bucket = scans_over_time(events)
        dates, counts = zip(*bucket.items()) if bucket else (["No data"], [0])

        self.axs[1].clear()
        self.axs[1].plot(dates, counts, marker='o')
        self.axs[1].set_title("Scans Over Time")
        self.axs[1].set_xlabel("Date")
        self.axs[1].set_ylabel("Files Scanned")
        self.axs[1].tick_params(axis='x', rotation=45)

        self.fig.tight_layout(pad=3)
        self.canvas.draw()

    # --------------------------------------------------------
    def auto_refresh(self):
        self.refresh_charts()
        self.after(REFRESH_SECS * 1000, self.auto_refresh)
