# CipherWing: AI-Powered Linux Malware Defense

CipherWing is a modular, real-time malware detection and response system for Linux. It combines static machine learning, YARA signature scanning, SHAP-based explainability, and SOAR-style automated responses, all wrapped in a clean Tkinter-based GUI.

Built entirely in userspace (ring 3), CipherWing uses LD_PRELOAD-based syscall interception to monitor and respond in real time without requiring kernel modules or root privileges. It's a solo learning project inspired by platforms like CrowdStrike Falcon, exploring how detections are made, how responses are triggered, and how explainability strengthens visibility.

## Demo

[Video Demo](https://github.com/user-attachments/assets/aa514ac2-7b20-423b-82dc-737ed535cd5f)

![System Diagram](https://github.com/user-attachments/assets/0f3bb330-5105-4263-9111-f46ae4a63de0)

## Components

**Watchdog**: Real-time directory monitoring  
**ML Scanner**: Binary classification using trained models  
**YARA Engine**: Signature-based detection  
**SHAP Integration**: Model explainability and visualization  
**SOAR Engine**: Automated response actions (quarantine, process termination, file deletion)  
**GUI Dashboard**: Tkinter-based control interface  
**LD_PRELOAD Shell**: Runtime file execution interception

## Technical Stack

Python 3.11  
scikit-learn, joblib for machine learning  
SHAP for model explainability  
watchdog for filesystem monitoring  
tkinter and psutil for GUI and system operations  
yara-python for signature detection

## Directory Structure

```
CipherWing/
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

## Installation

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/CipherWing.git
cd CipherWing

# Set up virtual environment
python3 -m venv env
source env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Launch GUI
python UI/main.py

# Alternative: Manual component startup
python agent/main_agent.py
python agent/cipherwing_shell.py
```

## How It Works

1. Watchdog detects file creation/modification in critical directories
2. File is passed to the ML Scanner and YARA Engine
3. SHAP plots explain why the file was flagged
4. If malicious, the SOAR Engine can quarantine, kill the process, shutdown the system, or delete the file
5. All events are logged and visualized in the GUI
6. LD_PRELOAD-based interceptor actively blocks execution of flagged files

## Dataset and Training

The ML models were trained on a custom dataset including:

Real malware samples from established sources  
Clean binaries from open-source projects  
Manual family classification based on behavioral analysis  
Feature extraction covering entropy, PE structure, and string analysis  
K-fold cross-validation for model evaluation

This project taught me how to move across data engineering, ML pipeline design, and security logic, not just to detect, but to explain and act.

## Performance Metrics

ML Classifier False Positive Rate: ~3.5%  
YARA-only False Positive Rate: ~6%  
SHAP explanations provide interpretability for predictions  
Detailed evaluation results available in `/eval` directory

## Known Limitations

In security, acknowledging limitations isn't just a formality; it's a sign of maturity. No system is bulletproof, and CipherWing is no exception.

No remote management or centralized logging  
Local-only operation and data storage  
Family classification accuracy varies between malware types  
Detection may be limited against heavily packed or obfuscated samples  
Userspace operation provides less visibility than kernel-level solutions

## License

MIT License. See LICENSE file for details.

## Author

Mohamed Gamal  
Built with love for security
