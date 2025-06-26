# scanner_core.py

import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
YARA_DIR = os.path.join(BASE_DIR, 'yara_rules')  # 🔥 Absolute path now
sys.path.insert(0, BASE_DIR)

from ML_scanner.scanner import scan_file
from yara_scanner.scanner import scan_file_with_yara, compile_yara_rules
from soar.verdict_engine import get_verdict

print(f"[*] Compiling YARA rules from: {YARA_DIR}")
if not os.path.exists(YARA_DIR):
    print("[!] YARA rules directory not found!")
    yara_rules = {}
else:
    yara_rules = compile_yara_rules(YARA_DIR)

def run_full_scan(file_path: str):
    if not os.path.exists(file_path):
        return {"error": "File does not exist", "file_path": file_path}

    print(f"[SCAN] Running full scan on: {file_path}")

    ml_result = scan_file(file_path)
    print("[DEBUG] ML Scan done.")

    ml_is_malware = ml_result.get("is_malware", False)
    ml_confidence = ml_result.get("confidence", 0.0)
    family = ml_result.get("family", "unknown")

    yara_result_raw = scan_file_with_yara(file_path, yara_rules)
    print("[DEBUG] YARA Scan done.")

    yara_is_malware = yara_result_raw.get("is_malware", False)

    verdict = get_verdict(
        file_path=file_path,
        yara_result=yara_is_malware,
        ml_result=ml_is_malware,
        ml_confidence=ml_confidence,
        family=family
    )

    verdict["ml_result"] = ml_result
    verdict["yara_result"] = yara_result_raw

    return verdict

if __name__ == "__main__":
    print("[DEBUG] scanner_core.py started")

    if len(sys.argv) != 2:
        print("Usage: python scanner_core.py <file_path>")
        sys.exit(1)

    path = sys.argv[1]
    print(f"[DEBUG] Argument received: {path}")
    print(f"[DEBUG] Absolute path check: {os.path.exists(path)}")

    result = run_full_scan(path)

    print("\n[VERDICT]")
    if result:
        for k, v in result.items():
            print(f"{k}: {v}")
    else:
        print("[!] No result returned by run_full_scan.")
