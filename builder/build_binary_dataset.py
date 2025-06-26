import sys
import os
import pandas as pd
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from analyzer.analyzer import analyze
from tqdm import tqdm

BENIGN_DIR = "data/benign"
MALWARE_DIR = "data/malware_balanced"
OUTPUT_FILE = "data/features_binary.csv"

def collect_files(directory, limit=None):
    files = []
    for root, _, filenames in os.walk(directory):
        for filename in filenames:
            if filename.endswith(".exe"):
                files.append(os.path.join(root, filename))
    if limit:
        return files[:limit]
    return files

def extract_features(file_list, label):
    data = []
    for path in tqdm(file_list, desc=f"Extracting label {label}"):
        try:
            features = analyze(path)
            if features:
                features["label"] = label
                data.append(features)
        except Exception as e:
            print(f"[!] Failed on {path}: {e}")
    return data

if __name__ == "__main__":
    print("[*] Collecting benign and malware files...")

    benign_files = collect_files(BENIGN_DIR)
    malware_files = collect_files(MALWARE_DIR)

    limit = min(len(benign_files), len(malware_files), 500)  # Keep it balanced and capped
    print(f"[~] Using {limit} benign and {limit} malware samples.")

    benign_features = extract_features(benign_files[:limit], label=0)
    malware_features = extract_features(malware_files[:limit], label=1)

    all_data = benign_features + malware_features
    df = pd.DataFrame(all_data)
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"[✓] Dataset saved to: {OUTPUT_FILE}")
