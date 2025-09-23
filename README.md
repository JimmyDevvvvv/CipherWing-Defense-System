# CipherWing: Linux Malware Detection System

A student project built out of curiosity and passion for cybersecurity research. CipherWing is a proof-of-concept malware detection system that combines machine learning classification, YARA signature scanning, and basic automated response capabilities through a Tkinter GUI.

## Demo
[Video Demo](https://github.com/user-attachments/assets/aa514ac2-7b20-423b-82dc-737ed535cd5f)
![System Diagram](https://github.com/user-attachments/assets/0f3bb330-5105-4263-9111-f46ae4a63de0)

## Components
- **Watchdog**: Real-time directory monitoring using Python's watchdog library
- **ML Scanner**: Binary classification using trained scikit-learn models
- **YARA Engine**: Signature-based detection with custom rules
- **SHAP Integration**: Model explainability and visualization
- **Response System**: Basic automated actions (quarantine, process termination, file deletion)
- **GUI Dashboard**: Tkinter-based control interface

## Technical Stack
- Python 3.11
- scikit-learn, joblib for machine learning
- SHAP for model explainability
- watchdog for filesystem monitoring
- tkinter and psutil for GUI and system operations
- yara-python for signature detection

## Directory Structure
```
CipherWing/
├── agent/             # Watchdog and monitoring components
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
```

## Operation
1. Watchdog monitors specified directories for file changes
2. New/modified files are analyzed by ML classifier and YARA engine
3. SHAP generates explanations for ML predictions
4. Detected threats trigger configurable responses:
   - File quarantine
   - Process termination
   - System shutdown
   - File deletion
5. All events are logged and displayed in the GUI

## Dataset and Training
The ML models were trained on a custom dataset including:
- Malware samples from established public sources
- Clean binaries from open-source projects
- Manual family classification based on behavioral analysis
- Feature extraction covering entropy, PE structure, and string analysis
- K-fold cross-validation for model evaluation

## Performance Metrics
- ML Classifier False Positive Rate: ~3.5%
- YARA-only False Positive Rate: ~6%
- SHAP explanations provide interpretability for predictions
- Detailed evaluation results available in `/eval` directory

## Known Limitations
This is a student learning project with several limitations:
- No remote management or centralized logging
- Local-only operation and data storage
- Family classification accuracy varies between malware types
- Detection may be limited against heavily packed or obfuscated samples
- Userspace monitoring has visibility constraints compared to kernel-level solutions
- No production-level hardening or enterprise features

## License
MIT License - see LICENSE file for details.

## Author
Mohamed Gamal

---
*Built as a learning exercise in malware analysis and detection systems*
