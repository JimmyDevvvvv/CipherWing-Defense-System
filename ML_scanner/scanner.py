import sys
import os
import joblib
import shap
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import json
from datetime import datetime

# === Setup project root ===
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from analyzer.analyzer import analyze

# === Absolute paths ===
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "..", "models")
LOGS_DIR = os.path.join(BASE_DIR, "..", "logs")
SHAP_DIR = os.path.join(BASE_DIR, "..", "shap")

os.makedirs(SHAP_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

MALWARE_MODEL_PATH = os.path.join(MODELS_DIR, "malware_detector2.pkl")
FAMILY_MODEL_PATH = os.path.join(MODELS_DIR, "family_model2.pkl")
FAMILY_ENCODER_PATH = os.path.join(MODELS_DIR, "family_label_encoder2.pkl")
LOG_PATH = os.path.join(LOGS_DIR, "interceptor_events.json")  # NDJSON format for backend compatibility


def scan_file(file_path):
    result = {
        "is_malware": False,
        "confidence": 0.0,
        "family": "N/A",
        "shap_malware_path": None,
        "shap_family_path": None
    }

    print(f"[+] Scanning file: {file_path}")
    features = analyze(file_path)
    if not features:
        print("[!] Failed to extract features.")
        return result

    features.pop("filename", None)
    df = pd.DataFrame([features])

    # === Load Malware Model
    if not os.path.exists(MALWARE_MODEL_PATH):
        print("[!] Malware model not found.")
        return result

    malware_model = joblib.load(MALWARE_MODEL_PATH)
    pred = malware_model.predict(df)[0]
    proba = malware_model.predict_proba(df)[0][pred]

    result["is_malware"] = bool(pred)
    result["confidence"] = float(proba)

    # === SHAP for malware model
    try:
        explainer = shap.Explainer(malware_model)
        shap_values = explainer(df)
        shap_filename = f"shap_malware_{os.path.basename(file_path)}.png"
        shap_path = os.path.join(SHAP_DIR, shap_filename)
        shap.plots.bar(shap_values[0], show=False)
        plt.title("SHAP - Malware Detection")
        plt.tight_layout()
        plt.savefig(shap_path)
        result["shap_malware_path"] = shap_path
        print(f"[✓] SHAP Malware plot saved: {shap_path}")
    except Exception as e:
        print(f"[!] SHAP Malware Error: {e}")

    # === Predict family if malware
    if pred == 1 and os.path.exists(FAMILY_MODEL_PATH) and os.path.exists(FAMILY_ENCODER_PATH):
        try:
            family_model = joblib.load(FAMILY_MODEL_PATH)
            encoder = joblib.load(FAMILY_ENCODER_PATH)
            family_pred = family_model.predict(df)[0]
            family_label = encoder.inverse_transform([family_pred])[0]
            result["family"] = str(family_label)

            family_explainer = shap.Explainer(family_model)
            family_shap_values = family_explainer(df)

            shap_filename_family = f"shap_family_{os.path.basename(file_path)}.png"
            shap_path_family = os.path.join(SHAP_DIR, shap_filename_family)

            try:
                shap.plots.bar(family_shap_values[0], show=False)
            except Exception:
                raw_values = family_shap_values.values
                if raw_values.ndim == 3:
                    raw_values = raw_values[0, :, family_pred]
                elif raw_values.ndim == 2:
                    raw_values = raw_values[0]
                shap_expl = shap.Explanation(
                    values=raw_values,
                    base_values=family_shap_values.base_values[0] if hasattr(family_shap_values, 'base_values') else 0,
                    data=df.iloc[0].values,
                    feature_names=df.columns.tolist()
                )
                shap.plots.bar(shap_expl, show=False)

            plt.title("SHAP - Malware Family Classification")
            plt.tight_layout()
            plt.savefig(shap_path_family)
            result["shap_family_path"] = shap_path_family
            print(f"[✓] SHAP Family plot saved: {shap_path_family}")
        except Exception as e:
            print(f"[!] Family Classification Error: {e}")

    # === NDJSON Logging for ALL files (Compatible with backend_connector)
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "file": file_path,
        "status": "malicious" if result["is_malware"] else "clean",
        "ml_confidence": result["confidence"],  # Keep as float, not string
        "family": result["family"] if result["is_malware"] else "N/A"
    }

    if result["is_malware"]:
        log_entry.update({
            "action": "blocked_by_interceptor",
            "flags": ["ml_detected"],
            "shap_malware": result["shap_malware_path"] or "N/A",
            "shap_family": result["shap_family_path"] or "N/A"
        })

    try:
        # NDJSON: Just append one JSON object per line - compatible with backend_connector!
        with open(LOG_PATH, "a") as f:
            json.dump(log_entry, f, separators=(',', ':'))  # Compact format
            f.write('\n')
        print(f"[✓] Logged scan to: {LOG_PATH}")
    except Exception as e:
        print(f"[!] Failed to write NDJSON log: {e}")

    return result


# === CLI for testing ===
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 scanner.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    print(scan_file(file_path))