# 🛡️ CipherWing: AI-Powered Linux Malware Defense

**CipherWing** is a modular, real-time malware detection and response system for Linux. It combines static machine learning, YARA signature scanning, SHAP-based explainability, and SOAR-style real-time responses — all wrapped in a clean Tkinter-based GUI. Ideal for blue teamers, researchers, and cybersecurity enthusiasts.

CipherWing is not just a tool — it's a solo learning journey inspired by platforms like CrowdStrike Falcon and Plato Networks. Built from scratch, it's a love letter to modern EDR systems, aiming to explore how detections are made, how real-time responses are triggered, and how explainability strengthens visibility.

---

## 📸 Demo

* ▶️ **Video Demo** – See CipherWing in action


https://github.com/user-attachments/assets/aa514ac2-7b20-423b-82dc-737ed535cd5f


![Diagram](https://github.com/user-attachments/assets/0f3bb330-5105-4263-9111-f46ae4a63de0)

---

## 🚀 Features

* 📂 **Watchdog**: Monitors sensitive directories in real time
* 🧠 **ML Scanner**: Detects malware using trained binary & family classifiers
* 🧬 **YARA Engine**: Signature-based rule scanning
* 🧾 **SHAP Explainability**: Visual breakdowns of why a file was flagged
* ⚡ **SOAR Engine**: Automatic responses (quarantine, kill, shutdown, delete)
* 🖥️ **GUI Panel**: Tkinter dashboard to control and monitor detections
* 🐚 **LD\_PRELOAD Shell**: Intercepts and blocks real-time file executions

---

## 🧠 Tech Stack

* Python 3.11
* `scikit-learn`, `joblib` – Static ML
* `SHAP` – Explainability
* `watchdog` – Directory monitoring
* `tkinter`, `psutil` – GUI & system interactions
* `yara-python` – Signature detection

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

# 5. Or launch the watchdog manually (optional)
python agent/main_agent.py
```

---

## 🐾 How It Works

1. **Watchdog** detects file creation/modification in critical directories.
2. File is passed to the **ML Scanner** and **YARA Engine**.
3. **SHAP** plots explain why the file was flagged.
4. If malicious, the **SOAR Engine** can:

   * 🔒 Quarantine
   * 💀 Kill the Process
   * ⚠️ Shutdown the System
   * 🗑️ Delete the File
5. All events are logged and visualized in the **GUI**.
6. **LD\_PRELOAD-based Interceptor** actively blocks execution of flagged files.

---

## 🧪 Data Engineering & Training

Instead of relying on public datasets, CipherWing’s dataset was manually engineered from scratch:

* Real malware samples from trusted sources
* Manual family labels based on behavior and structure
* Clean files from open-source repositories
* Extracted features: entropy, PE headers, suspicious strings
* Trained with k-fold validation
* Benchmarked vs. YARA-only baseline

This project taught me how to move across data engineering, ML pipeline design, and security logic — not just to detect, but to explain and act.

---

## 📈 Performance

* ML Classifier FPR: \~3.5%
* YARA-only FPR: \~6%
* SHAP explanations help interpret results and reduce false positives

---

## ⚠️ Limitations

In security, acknowledging limitations isn’t just a formality — it’s a sign of maturity. No system is bulletproof, and CipherWing is no exception. Being honest about where things stand is crucial for responsible development.

* No cloud sync or centralized backend
* Local-only GUI and logs
* Family classification (e.g., RAT vs. Trojan) can be inconsistent
* YARA may miss packed or heavily obfuscated binaries

---

## 👨‍💻 Author

**Mohamed "Jimmy" Gamal**
Built with 🖤 and fire for Linux defenders.

---

## 🔗 License

**MIT License** – See [`LICENSE`](./LICENSE) file for more details.


