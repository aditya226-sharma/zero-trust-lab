#!/usr/bin/env python3
"""
posture_check.py — runs on each client VM, queries osquery, writes a
verdict keyed by that VM's IP into a shared posture store (a JSON file on
a volume authz-bridge also mounts, for lab simplicity — see the fail-open
warning in authz-bridge/app.py's get_posture()).

Run on a schedule via systemd timer, e.g. every 60 seconds.

CRITICAL: this script fails CLOSED. Any osquery query that errors out
results in "unhealthy", never a silent default to "healthy". This is the
single most important property of this file — do not "fix" a flaky query
by defaulting it to pass.
"""
import json
import socket
import subprocess
import sys
import time

POSTURE_STORE_PATH = "/shared/posture.json"  # shared volume with authz-bridge
MAX_PATCH_AGE_DAYS = 30
BLOCKLISTED_PROCESSES = ["nc", "ncat", "mimikatz"]  # example only — extend as needed


def run_osquery(sql: str):
    """Runs an osqueryi query, returns parsed JSON rows or None on failure."""
    try:
        result = subprocess.run(
            ["osqueryi", "--json", sql],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        return json.loads(result.stdout)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
            json.JSONDecodeError, FileNotFoundError) as e:
        print(f"osquery query failed, treating as unhealthy signal: {e}", file=sys.stderr)
        return None  # caller must treat None as a failed/unhealthy signal


def check_disk_encryption() -> bool:
    rows = run_osquery("SELECT * FROM disk_encryption WHERE encrypted = 1;")
    if rows is None:
        return False  # fail closed
    return len(rows) > 0


def check_patch_age() -> bool:
    # Simplified proxy: days since last apt upgrade, via a marker file
    # updated by your patch process. Real deployments should query actual
    # package manager state — this is a lab-simplicity placeholder,
    # flagged deliberately.
    try:
        result = subprocess.run(
            ["stat", "-c", "%Y", "/var/log/apt/history.log"],
            capture_output=True, text=True, timeout=5, check=True,
        )
        last_modified = int(result.stdout.strip())
        age_days = (time.time() - last_modified) / 86400
        return age_days <= MAX_PATCH_AGE_DAYS
    except Exception as e:
        print(f"patch age check failed, treating as unhealthy: {e}", file=sys.stderr)
        return False  # fail closed


def check_blocklisted_processes() -> bool:
    rows = run_osquery("SELECT name FROM processes;")
    if rows is None:
        return False  # fail closed
    running = {row.get("name", "").lower() for row in rows}
    hits = running.intersection({p.lower() for p in BLOCKLISTED_PROCESSES})
    return len(hits) == 0  # True = clean, no blocklisted process found


def main():
    disk_ok = check_disk_encryption()
    patch_ok = check_patch_age()
    process_ok = check_blocklisted_processes()

    healthy = disk_ok and patch_ok and process_ok

    verdict = {
        "healthy": healthy,
        "signals": {
            "disk_encrypted": disk_ok,
            "patch_within_window": patch_ok,
            "no_blocklisted_process": process_ok,
        },
        "checked_at": int(time.time()),
    }

    try:
        with open(POSTURE_STORE_PATH, "r") as f:
            store = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        store = {}

    my_ip = socket.gethostbyname(socket.gethostname())
    store[my_ip] = {
        "posture": "healthy" if healthy else "unhealthy",
        **verdict,
    }

    with open(POSTURE_STORE_PATH, "w") as f:
        json.dump(store, f, indent=2)

    print(json.dumps(verdict, indent=2))


if __name__ == "__main__":
    main()
