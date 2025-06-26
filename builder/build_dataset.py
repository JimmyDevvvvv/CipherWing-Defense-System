import sys
import os
import csv
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.analyzer import analyze
BENIGN_DIR = "data/benign"
MALWARE_BASE_DIR = "data/malware_samples"
OUTPUT_FILE = "data/family.csv"

def process_directory(path, label, family=""):
    rows = []
    for filename in os.listdir(path):
        full_path = os.path.join(path, filename)
        if os.path.isfile(full_path):
            try:
                features = analyze(full_path)
                if features:
                    features["label"] = label
                    features["family"] = family
                    features["filename"] = filename
                    rows.append(features)
            except Exception as e:
                print(f"[!] Error processing {filename}: {e}")
    return rows

def main():
    all_data = []

    print("[+] Processing benign files...")
    all_data.extend(process_directory(BENIGN_DIR, label=0, family=""))

    print("[+] Processing malware families...")
    for family_name in os.listdir(MALWARE_BASE_DIR):
        family_path = os.path.join(MALWARE_BASE_DIR, family_name)
        if os.path.isdir(family_path):
            print(f"  └─▶ Family: {family_name}")
            all_data.extend(process_directory(family_path, label=1, family=family_name))

    if not all_data:
        print("[!] No data collected. Exiting.")
        return

    keys = list(all_data[0].keys())

    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(all_data)

    print(f"[✓] Dataset saved to: {OUTPUT_FILE} ({len(all_data)} samples)")

if __name__ == "__main__":
    main()
