# 🛡️ CipherWing: AI-Powered Linux Malware Defense

**CipherWing** is a modular, real-time malware detection and response system for Linux.  
It combines static machine learning, YARA signature scanning, SHAP-based explainability, and SOAR-style real-time responses — all wrapped in a clean Tkinter-based GUI. Ideal for blue teamers, researchers, and cybersecurity enthusiasts.

---

## 📸 Demo & Architecture

- ▶️ **Video Demo** – See CipherWing in action



https://github.com/user-attachments/assets/899bf7b7-5f75-4e58-860f-b1bfbbc776f0





 
- 🧭 **Architecture Diagram**
![Diagram](https://github.com/user-attachments/assets/6c41df20-6184-4bb0-9385-55bbc86a017a)

  

---

## 🚀 Features

- 📂 **Watchdog**: Monitors sensitive directories in real time
- 🧠 **ML Scanner**: Detects malware using trained binary & family classifiers
- 🧬 **YARA Engine**: Signature-based rule scanning
- 🧾 **SHAP Explainability**: Visual breakdowns of why a file was flagged
- ⚡ **SOAR Engine**: Automatic responses (quarantine, kill, shutdown, delete)
- 🖥️ **GUI Panel**: Tkinter dashboard to control and monitor detections
- 🐚 **LD_PRELOAD Shell**: Intercepts and blocks real-time file executions

---

## 🧠 Tech Stack

- Python 3.11  
- `scikit-learn`, `joblib` – Static ML  
- `SHAP` – Explainability  
- `watchdog` – Directory monitoring  
- `tkinter`, `psutil` – GUI & system interactions  
- `yara-python` – Signature detection

---

## 📦 Directory Structure

```
CipherWing/
├── agent/             → Watchdog + interceptor
├── ML_scanner/        → Static ML models, SHAP, scanner logic
├── yara_scanner/      → YARA rule compiler and runner
├── soar/              → SOAR response logic
├── UI/                → Tkinter-based GUI dashboard
├── models/            → Pretrained ML model files (.pkl)
├── logs/              → Logged JSON events
├── quarantine/        → Quarantined malware samples
├── shap/              → SHAP plots for explainability
├── scanner_core.py    → Orchestrator for full scan
├── README.md
└── requirements.txt
```

---

## 🛠️ Setup Instructions

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/CipherWing.git
cd CipherWing

# 2. Create a virtual environment
python3 -m venv env
source env/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch the GUI (recommended)
python UI/main.py


```

---

## 🐾 How It Works

1. **Watchdog** detects file creation/modification in critical directories.
2. File is passed to the **ML Scanner** and **YARA Engine**.
3. **SHAP** plots explain why the file was flagged.
4. If malicious, the **SOAR Engine** can:
   - 🔒 Quarantine
   - 💀 Kill the Process
   - ⚠️ Shutdown the System
   - 🗑️ Delete the File
5. All events are logged and visualized in the **GUI**.

---

## 🧪 Want to Test?

Drop a file in one of the following directories:

- `~/Downloads`  
- `~/Desktop`  
- `/tmp`

Use the GUI to observe real-time detection, SHAP explanations, and SOAR actions.  
You can also launch a benign file inside the interceptor shell to see CipherWing in action — safely.

---

## 🧾 Legal Disclaimer

> This project is for educational and research purposes only.  
> **Do not upload real malware to GitHub**.  
> Always test in isolated environments.

---

## 👨‍💻 Author

**Mohamed Gamal**  
Built with 🖤

---

## 🔗 License

**MIT License** – See [`LICENSE`](./LICENSE) file for more details.
