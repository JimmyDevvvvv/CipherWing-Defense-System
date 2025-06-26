"""
Backend helper: read SOAR / interceptor logs and give handy
aggregations for the GUI.

All log files are JSON *one-object-per-line*.
"""

import os, json, itertools
from collections import Counter, defaultdict
from datetime import datetime

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
LOG_PATH     = os.path.join(PROJECT_ROOT, "logs", "interceptor_events.json")   # <- adjust if needed

# ------------------------------------------------------------
def load_events(max_rows: int | None = None) -> list[dict]:
    """Return newest events first (most recent line == newest)."""
    if not os.path.exists(LOG_PATH):
        return []

    with open(LOG_PATH, "r") as f:
        lines = f.readlines()

    if max_rows:
        lines = lines[-max_rows:]

    events = [json.loads(line) for line in lines]
    # sort by timestamp (assuming ISO string) newest→oldest
    events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return events


# ------------------------------------------------------------
def family_distribution(events: list[dict]) -> Counter:
    """Return Counter of malware family names."""
    fams = [e.get("family", "unknown") or "unknown" for e in events if e.get("is_malware", True)]
    return Counter(fams)


# ------------------------------------------------------------
def scans_over_time(events: list[dict], time_unit="day") -> dict[str,int]:
    """
    Group scans per day (default) or hour.
    Key: 'YYYY-MM-DD'  or  'YYYY-MM-DD HH'
    """
    bucket = defaultdict(int)
    for e in events:
        ts = e.get("timestamp")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            continue

        key = dt.strftime("%Y-%m-%d") if time_unit == "day" else dt.strftime("%Y-%m-%d %H")
        bucket[key] += 1
    return dict(sorted(bucket.items()))
