# 🛡️ CipherWing: AI-Powered Linux Malware Defense
# CipherWing: Linux Malware Detection System

**CipherWing** is a modular, real-time malware detection and response system for Linux. It combines static machine learning, YARA signature scanning, SHAP-based explainability, and SOAR-style real-time responses — all wrapped in a clean Tkinter-based GUI.
CipherWing is a real-time malware detection and response system for Linux that combines machine learning classification, YARA signature scanning, and automated response capabilities through a Tkinter GUI.

CipherWing is not just a tool — it's a solo learning journey inspired by platforms like CrowdStrike Falcon and Plato Networks. Built entirely in userspace (ring 3), it uses LD_PRELOAD-based syscall interception (e.g., open, execve, etc.) to monitor and respond in real time — no kernel modules, no root required. It's a love letter to modern EDR systems, exploring how detections are made, how responses are triggered, and how explainability strengthens visibility, all without touching ring 0.
The system operates entirely in userspace using LD_PRELOAD-based syscall interception to monitor file operations without requiring kernel modules or root privileges.

---
## Demo

## 📸 Demo
[Video Demo](https://github.com/user-attachments/assets/aa514ac2-7b20-423b-82dc-737ed535cd5f)

* ▶️ **Video Demo** – See CipherWing in action
![System Diagram](https://github.com/user-attachments/assets/0f3bb330-5105-4263-9111-f46ae4a63de0)

## Components

https://github.com/user-attachments/assets/aa514ac2-7b20-423b-82dc-737ed535cd5f
- **Watchdog**: Real-time directory monitoring
- **ML Scanner**: Binary classification using trained models
- **YARA Engine**: Signature-based detection
- **SHAP Integration**: Model explainability and visualization
- **SOAR Engine**: Automated response actions (quarantine, process termination, file deletion)
- **GUI Dashboard**: Tkinter-based control interface
- **LD_PRELOAD Shell**: Runtime file execution interception

## Technical Stack

![Diagram](https://github.com/user-attachments/assets/0f3bb330-5105-4263-9111-f46ae4a63de0)
- Python 3.11
- scikit-learn, joblib for machine learning
- SHAP for model explainability
- watchdog for filesystem monitoring
- tkinter and psutil for GUI and system operations
- yara-python for signature detection

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
## Directory Structure

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
├── agent/             # Watchdog and interceptor components
├── ML_scanner/        # ML models, SHAP integration, scanner logic
├── yara_scanner/      # YARA rule management
├── soar/              # Response automation
├── UI/                # GUI dashboard
├── models/            # Trained model files (.pkl)
├── logs/              # Event logs (JSON)
├── quarantine/        # Isolated malware samples
├── shap/              # Explainability visualizations
├── scanner_core.py    # Main orchestration logic
└── requirements.txt
```

---

## 🛠️ Setup Instructions
## Installation

```bash
# 1. Clone the repo
# Clone repository
git clone https://github.com/YOUR_USERNAME/CipherWing.git
cd CipherWing

# 2. Create a virtual environment
# Set up virtual environment
python3 -m venv env
source env/bin/activate

# 3. Install dependencies
# Install dependencies
pip install -r requirements.txt

# 4. Launch the GUI (recommended)
# Launch GUI
python UI/main.py

# 5. Or launch the watchdog and cipherwing shell manually (optional)
# Alternative: Manual component startup
python agent/main_agent.py
python agent/cipherwing_shell.py
ipc_listener.py

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
* Check the eval folder for more info!
---

## ⚠️ Limitations
## Operation

In security, acknowledging limitations isn’t just a formality — it’s a sign of maturity. No system is bulletproof, and CipherWing is no exception. Being honest about where things stand is crucial for responsible development.
1. Watchdog monitors specified directories for file changes
2. New/modified files are analyzed by ML classifier and YARA engine
3. SHAP generates explanations for ML predictions
4. Detected threats trigger configurable responses:
   - File quarantine
   - Process termination
   - System shutdown
   - File deletion
5. All events are logged and displayed in the GUI
6. LD_PRELOAD interceptor blocks execution of flagged files

* No cloud sync or centralized backend
* Local-only GUI and logs
* Family classification (e.g., RAT vs. Trojan) can be inconsistent
* YARA may miss packed or heavily obfuscated binaries
## Dataset and Training

---
The ML models were trained on a custom dataset including:
- Malware samples from established sources
- Clean binaries from open-source projects
- Manual family classification based on behavioral analysis
- Feature extraction covering entropy, PE structure, and string analysis
- K-fold cross-validation for model evaluation

## 👨‍💻 Author
## Performance Metrics

**Mohamed Gamal**
- ML Classifier False Positive Rate: ~3.5%
- YARA-only False Positive Rate: ~6%
- SHAP explanations provide interpretability for predictions
- Detailed evaluation results available in `/eval` directory

Built with love for security
## Known Limitations

---
- No remote management or centralized logging
- Local-only operation and data storage
- Family classification accuracy varies between malware types
- Detection may be limited against heavily packed or obfuscated samples
- Userspace operation provides less visibility than kernel-level solutions

## 🔗 License
## License

**MIT License** – See [`LICENSE`](./LICENSE) file for more details.
MIT License - see LICENSE file for details.

## Author

Mohamed Gamal
