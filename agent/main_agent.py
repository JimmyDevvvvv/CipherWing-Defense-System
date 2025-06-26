
"""
CipherWing Watchdog – targeted directories, extension filtering, SOAR autopilot.
"""

import time
import os
import sys
import argparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ────────────────────────────────────────────────────────────────────────────
# Project paths
# ────────────────────────────────────────────────────────────────────────────
AGENT_DIR    = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(AGENT_DIR, '..'))
sys.path.insert(0, PROJECT_ROOT)

# ────────────────────────────────────────────────────────────────────────────
# Imports from CipherWing
# ────────────────────────────────────────────────────────────────────────────
from entropy_checker import check_entropy
from soar.soar_engine import execute_soar_response, alert_terminal
from core.scanner_core import run_full_scan

# ────────────────────────────────────────────────────────────────────────────
# Config – targeted folders & extensions can add more or less just for a demo
# ────────────────────────────────────────────────────────────────────────────
USER = os.getenv("USER") or os.getenv("USERNAME") or "user"

WATCH_DIRS = [
    f"/home/{USER}/Downloads",
    f"/home/{USER}/Desktop",
    f"/home/{USER}/Documents",
    "/tmp",
    "/var/tmp",
    "/usr/local/bin",
    "/opt",
]

MONITORED_EXTS = (".exe", ".dll", ".scr", ".bat", ".sh", ".py", ".bin", ".elf")

def handle_family_response(family: str):
    fam = (family or "unknown").lower()
    mapping = {
        "ransomware": "⚠️ high-threat protocol",
        "keylogger":  "📝 forensic logging mode",
        "worm":       "🧬 lateral-movement check",
        "rat":        "📡 remote-access alert",
        "trojan":     "🛑 quarantine enforced",
    }
    print(f"[TACTICAL] {fam.title()} detected → {mapping.get(fam, 'default response.')}")

def prompt_manual_action(scan: dict) -> str:
    print("\n🚨  Detected MALICIOUS file")
    for k in ("file_path", "family", "confidence"):
        print(f"• {k.replace('_', ' ').title():<10}: {scan.get(k)}")
    print("Choose an action: [1] Quarantine  [2] Kill  [3] Delete  [4] Shutdown  [5] Ignore")
    return {
        "1": "quarantine",
        "2": "kill",
        "3": "delete",
        "4": "shutdown",
        "5": "log",
    }.get(input(">> ").strip(), "log")

# ────────────────────────────────────────────────────────────────────────────
# Watchdog event handler
# ────────────────────────────────────────────────────────────────────────────
class TargetedEventHandler(FileSystemEventHandler):
    def __init__(self, manual_mode: bool):
        super().__init__()
        self.manual_mode = manual_mode

    # Central processing
    def process(self, path: str):
        if not path.lower().endswith(MONITORED_EXTS):
            return
        if not os.path.isfile(path) or os.path.getsize(path) == 0:
            return

        entropy = check_entropy(path)
        scan = run_full_scan(path)
        scan.update({
            "entropy": entropy,
            "flags": ["high_entropy"] if entropy > 7.5 else [],
        })

        if scan.get("verdict") == "malicious":
            if self.manual_mode:
                scan["action"] = prompt_manual_action(scan)
            result = execute_soar_response(scan, source="watchdog")
            alert_terminal(f"[WATCHDOG] {path} → action={result.get('action')}")
            handle_family_response(scan.get("family"))
        else:
            print(f"[SAFE] {path}")

    # Trigger hooks
    def on_created(self, event):  # noqa
        if not event.is_directory:
            self.process(event.src_path)

    def on_modified(self, event):  # noqa
        if not event.is_directory:
            self.process(event.src_path)

# ────────────────────────────────────────────────────────────────────────────
# Entrypoint
# ────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="CipherWing Targeted Watchdog")
    parser.add_argument("--manual", action="store_true",
                        help="Prompt before SOAR action")
    args = parser.parse_args()

    os.makedirs(os.path.join(PROJECT_ROOT, "logs"), exist_ok=True)
    os.makedirs(os.path.join(PROJECT_ROOT, "quarantine"), exist_ok=True)

    observer = Observer()
    handler  = TargetedEventHandler(manual_mode=args.manual)

    for d in WATCH_DIRS:
        if os.path.exists(d):
            observer.schedule(handler, d, recursive=True)
            print(f"[+] Watching: {d}")
        else:
            print(f"[!] Skipping (missing): {d}")

    observer.start()
    mode = "MANUAL" if args.manual else "AUTO"
    print(f"[*] Watchdog active ({mode} mode). Monitoring {len(WATCH_DIRS)} dirs.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Stopping Watchdog…")
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
