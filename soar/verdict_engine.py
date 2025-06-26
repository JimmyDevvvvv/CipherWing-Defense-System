import os
import yaml

# === Load config from project root, not relative path ===
def load_config():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    path = os.path.join(base_dir, "config.yaml")
    with open(path, "r") as f:
        return yaml.safe_load(f)

config = load_config()

def get_verdict(file_path, yara_result, ml_result, ml_confidence, family="unknown"):
    reason = []
    final_verdict = "benign"
    action = "none"

    if config["enable_yara"] and yara_result:
        reason.append("YARA matched")

    if config["enable_ml"] and ml_result:
        reason.append(f"ML flagged with confidence {ml_confidence:.2f}")

    if reason:
        final_verdict = "malicious"

    if final_verdict == "malicious":
        if config["enable_ml"] and ml_result and ml_confidence >= config["auto_quarantine_threshold"]:
            action = "quarantine"
        elif yara_result:
            action = "quarantine"

    return {
        "file_path": file_path,
        "verdict": final_verdict,
        "confidence": ml_confidence,
        "family": family,
        "reason": ", ".join(reason),
        "action": action
    }
