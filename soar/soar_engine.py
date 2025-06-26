"""
CipherWing SOAR Engine
– Executes response actions (quarantine / kill / delete / shutdown)
– Simplified version with logging removed
"""

import os
import shutil
import psutil
import time
import hashlib
from datetime import datetime, timezone

# ──────────────────────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────────────────────
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
QUARANTINE_DIR = os.path.join(PROJECT_ROOT, "quarantine")

os.makedirs(QUARANTINE_DIR, exist_ok=True)

# ──────────────────────────────────────────────────────────────
# Internal utils
# ──────────────────────────────────────────────────────────────
def _timestamp() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def _file_hash(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

def _is_quarantined_file(file_path):
    """Check if file is in quarantine directory"""
    try:
        return os.path.abspath(file_path).startswith(os.path.abspath(QUARANTINE_DIR))
    except Exception:
        return False

# ──────────────────────────────────────────────────────────────
# Atomic actions
# ──────────────────────────────────────────────────────────────
def quarantine_file(path, *, reason="unspecified", source="manual"):
    base = os.path.basename(path)
    target = os.path.join(QUARANTINE_DIR, base)
    if os.path.exists(target):
        root, ext = os.path.splitext(base)
        target = os.path.join(QUARANTINE_DIR, f"{root}_{int(time.time())}{ext}")

    try:
        shutil.move(path, target)
        return True, target
    except Exception:
        return False, None

def kill_process(pid, *, reason="unspecified", source="manual"):
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        return True
    except Exception:
        return False

def kill_process_by_path(path, *, reason="unspecified", source="manual"):
    killed = []
    for p in psutil.process_iter(["pid", "exe"]):
        try:
            if p.info["exe"] and os.path.samefile(p.info["exe"], path):
                if kill_process(p.pid, reason=reason, source=source):
                    killed.append(p.pid)
        except Exception:
            continue
    return killed

def delete_file(path, *, reason="unspecified", source="manual"):
    try:
        os.remove(path)
        return True
    except Exception:
        return False

def shutdown_now(*, reason="unspecified", source="manual"):
    os.system("shutdown -h now")

def alert_terminal(msg):
    print(f"\n[!! ALERT !!] {msg}\n")

# ──────────────────────────────────────────────────────────────
# SOAR Dispatcher
# ──────────────────────────────────────────────────────────────
def execute_soar_response(scan: dict, *, source="scanner_core"):
    """
    scan must include:
      • file_path or file
      • family
      • confidence  (0-1 float) – optional
      • action      (quarantine|kill|delete|shutdown|log)
      • flags       (list) – optional
      • shap_malware / shap_family – optional
    """
    file_path = scan.get("file_path") or scan.get("file")
    if not file_path:
        return {"error": "Missing file path"}

    # Avoid recursive re-scanning of already quarantined files
    if _is_quarantined_file(file_path):
        print(f"[!] Skipping scan of quarantined file: {file_path}")
        return {"ignored": True, "reason": "inside_quarantine_dir"}

    family = scan.get("family", "unknown")
    action = scan.get("action", "log").lower()
    flags = scan.get("flags", [])

    try:
        confidence = float(scan.get("confidence", 0.0))
    except (ValueError, TypeError):
        confidence = 0.0

    reason = f"ML flagged with confidence {confidence:.2f}"

    result = {
        "timestamp": _timestamp(),
        "file": file_path,
        "action": action,
        "confidence": confidence,
        "family": family,
        "flags": flags,
        "source": source,
    }

    # ── Route action ───────────────────────────────────────────
    if action == "quarantine":
        ok, target = quarantine_file(file_path, reason=reason, source=source)
        if ok:
            result["target"] = target
            result["hash"] = _file_hash(target)
            result["success"] = True
        else:
            result["success"] = False
            result["error"] = "Failed to quarantine file"
        
        # Kill any running processes for this file
        kill_pids = kill_process_by_path(file_path, reason="quarantined file", source=source)
        if kill_pids:
            result["killed_pids"] = kill_pids
            result["action"] = "quarantine+kill"

    elif action == "kill":
        pid = scan.get("pid")
        if pid:
            ok = kill_process(pid, reason=reason, source=source)
            result["success"] = ok
            if not ok:
                result["error"] = "Failed to kill process"
        else:
            # Kill by file path if no PID specified
            kill_pids = kill_process_by_path(file_path, reason=reason, source=source)
            if kill_pids:
                result["killed_pids"] = kill_pids
                result["success"] = True
            else:
                result["success"] = False
                result["error"] = "No processes found for file"

    elif action == "delete":
        file_hash = _file_hash(file_path) if os.path.exists(file_path) else None
        ok = delete_file(file_path, reason=reason, source=source)
        result["success"] = ok
        if ok:
            result["hash"] = file_hash
        else:
            result["error"] = "Failed to delete file"

    elif action == "shutdown":
        shutdown_now(reason=reason, source=source)
        return {"shutdown": True, "timestamp": _timestamp()}

    else:
        result["action"] = "log_only"
        result["success"] = True

    return result