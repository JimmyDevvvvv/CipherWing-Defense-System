#!/usr/bin/env python3
"""
IPC listener for LD_PRELOAD interceptor → runs full scan → hands off to SOAR
Adds de-duplication to avoid infinite re-scan loops.
"""

import os
import sys
import time
import argparse

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# ── Project imports ───────────────────────────────────────────
from core.scanner_core  import run_full_scan
from core.config_loader import load_config
from soar.soar_engine   import execute_soar_response, alert_terminal

PIPE_PATH = "/tmp/cipherwing_pipe"
cfg       = load_config()                      # reads config.yaml

# ── De-duplication cache ──────────────────────────────────────
TTL_SECONDS  = 5           # ignore the same path if seen within N seconds
recent_paths = {}          # { path: last_seen_timestamp }

def is_duplicate(path: str) -> bool:
    """Return True if path seen less than TTL_SECONDS ago."""
    now = time.time()
    last = recent_paths.get(path)
    recent_paths[path] = now           # update each time we see it
    return last is not None and (now - last) < TTL_SECONDS

# ── Pipe helper ───────────────────────────────────────────────
def setup_pipe():
    if not os.path.exists(PIPE_PATH):
        os.mkfifo(PIPE_PATH)
        print(f"[*] Created named pipe at: {PIPE_PATH}")
    else:
        print(f"[*] Listening on existing pipe: {PIPE_PATH}")

# ── Manual prompt (same UX as Watchdog) ───────────────────────
def prompt_manual_action(scan: dict) -> str:
    print("\n🚨  Interceptor caught MALICIOUS file")
    print(f"• Path      : {scan['file_path']}")
    print(f"• Family    : {scan['family']}")
    print(f"• Confidence: {scan['confidence']:.2f}")
    print("Choose an action:")
    print("  [1] Quarantine")
    print("  [2] Kill Process")
    print("  [3] Delete File")
    print("  [4] Shutdown System")
    print("  [5] Log Only / Ignore")

    choice = input(">> ").strip()
    return {
        "1": "quarantine",
        "2": "kill",
        "3": "delete",
        "4": "shutdown",
        "5": "log"
    }.get(choice, "log")

# ── Main listener loop ────────────────────────────────────────
def listen(auto_mode: bool):
    print(f"[*] IPC Listener running ({'AUTO' if auto_mode else 'MANUAL'} mode)…")

    while True:
        try:
            with open(PIPE_PATH, "r") as pipe:
                for raw in pipe:
                    file_path = raw.strip()
                    if not file_path or not os.path.exists(file_path):
                        continue
                    if is_duplicate(file_path):
                        # Skip bursts caused by the same handle being opened repeatedly
                        continue

                    print(f"\n[🔌] Interceptor sent: {file_path}")
                    scan = run_full_scan(file_path)

                    # Only bother if malicious
                    if scan.get("verdict") == "malicious":
                        if not auto_mode:                    # manual prompt
                            scan["action"] = prompt_manual_action(scan)

                        result = execute_soar_response(scan, source="interceptor")
                        alert_terminal(f"[INTERCEPT] action={result['action']} → {file_path}")
                    else:
                        print("[SAFE] Interceptor scan clean")
        except Exception as e:
            print(f"[ERROR] IPC listener error: {e}")
            time.sleep(1)

# ── Entrypoint ────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="CipherWing Interceptor IPC listener")
    parser.add_argument("--manual", action="store_true",
                        help="Prompt before taking SOAR action")
    args = parser.parse_args()

    auto_mode = not args.manual and cfg.get("auto_respond", True)

    setup_pipe()
    try:
        listen(auto_mode)
    except KeyboardInterrupt:
        print("\n[!] IPC listener terminated.")

if __name__ == "__main__":
    main()
