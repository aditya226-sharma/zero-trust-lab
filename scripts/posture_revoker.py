#!/usr/bin/env python3
"""
Phase 6 — Automatic Posture-Based Revocation Script

Monitors the posture log file on gateway. On detecting an unhealthy device:
1. Removes the WireGuard peer for that device
2. Revokes the associated user's Authentik sessions via API

Run as a systemd service (see posture-revoker.service).

Usage:
  python3 posture_revoker.py
"""

import json
import logging
import os
import subprocess
import time
import urllib.request
import urllib.error

POSTURE_LOG = "/var/log/device_posture.log"
WG_INTERFACE = "wg0"
AUTHENTIK_API_BASE = "https://10.10.1.10/api/v3"
AUTHENTIK_TOKEN = os.environ.get("AUTHENTIK_TOKEN", "")
CHECK_INTERVAL = 5  # seconds

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s posture-revoker %(message)s"
)
log = logging.getLogger("posture-revoker")

# Track last known state per device_id
device_state: dict[str, bool] = {}
user_device_map: dict[str, str] = {}  # device_id -> user_email


def get_wireguard_peers():
    """Return dict of {public_key: device_id} from wg show."""
    try:
        result = subprocess.run(
            ["wg", "show", WG_INTERFACE, "dump"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # First line is interface info, rest are peers
        lines = result.stdout.strip().split("\n")[1:]
        peers = {}
        for line in lines:
            parts = line.split("\t")
            if len(parts) >= 5:
                pubkey = parts[0]
                allowed_ips = parts[3] if len(parts) > 3 else ""
                peers[pubkey] = allowed_ips
        return peers
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, IndexError) as e:
        log.error("Failed to get WireGuard peers: %s", e)
        return {}


def remove_wireguard_peer(pubkey):
    """Remove a peer from WireGuard by public key."""
    try:
        subprocess.run(
            ["wg", "set", WG_INTERFACE, "peer", pubkey, "remove"],
            check=True,
            timeout=10,
        )
        log.info("Removed WireGuard peer: %s", pubkey)
        return True
    except subprocess.CalledProcessError as e:
        log.error("Failed to remove WireGuard peer %s: %s", pubkey, e)
        return False


def revoke_authentik_sessions(user_email):
    """Revoke all Authentik sessions for a user."""
    if not AUTHENTIK_TOKEN:
        log.warning("AUTHENTIK_TOKEN not set — skipping Authentik session revocation")
        return False

    try:
        # 1. Look up user by email
        req = urllib.request.Request(
            f"{AUTHENTIK_API_BASE}/users/?search={urllib.request.quote(user_email)}",
            headers={"Authorization": f"Bearer {AUTHENTIK_TOKEN}"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            users = data.get("results", [])
            if not users:
                log.warning("User not found in Authentik: %s", user_email)
                return False
            user_pk = users[0]["pk"]

        # 2. Terminate all sessions for that user
        req = urllib.request.Request(
            f"{AUTHENTIK_API_BASE}/users/{user_pk}/sessions/terminate/",
            method="POST",
            headers={"Authorization": f"Bearer {AUTHENTIK_TOKEN}"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 204:
                log.info(
                    "Revoked Authentik sessions for %s (user pk: %s)",
                    user_email,
                    user_pk,
                )
                return True
            else:
                log.warning("Unexpected response revoking sessions: %s", resp.status)
                return False

    except urllib.error.HTTPError as e:
        log.error("Authentik API error: %s %s", e.code, e.reason)
        return False
    except urllib.error.URLError as e:
        log.error("Authentik unreachable: %s", e.reason)
        return False
    except Exception as e:
        log.error("Authentik revocation error: %s", e)
        return False


def process_posture_log():
    """Read latest entries from posture log and act on failures."""
    try:
        with open(POSTURE_LOG, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        device_id = entry.get("device_id", "unknown")
        healthy = entry.get("healthy", False)
        user_email = entry.get("user_email", "")

        # Check if state changed from healthy to unhealthy
        prev = device_state.get(device_id)
        if prev is True and healthy is False:
            log.warning(
                "Posture degraded for device=%s user=%s — triggering revocation",
                device_id,
                user_email,
            )

            # Find and remove WireGuard peer
            for pubkey, allowed_ips in get_wireguard_peers().items():
                # Match by allowed IP (which contains the device ID range)
                if device_id in allowed_ips:
                    remove_wireguard_peer(pubkey)
                    log.info(
                        "Revoked WireGuard peer %s for device %s", pubkey, device_id
                    )
                    break

            # Revoke Authentik sessions
            if user_email:
                revoke_authentik_sessions(user_email)

            # Log the revocation event for the dashboard
            log_event = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "event": "automatic_revocation",
                "device_id": device_id,
                "user_email": user_email,
                "trigger": "posture_failure",
                "posture_entry": entry,
            }
            revocation_log = "/var/log/posture_revoker.log"
            with open(revocation_log, "a") as f:
                f.write(json.dumps(log_event) + "\n")

        device_state[device_id] = healthy
        if user_email:
            user_device_map[device_id] = user_email


def main():
    log.info("Posture revoker started (interval=%ds)", CHECK_INTERVAL)
    while True:
        try:
            process_posture_log()
        except Exception as e:
            log.error("Unexpected error: %s", e)
        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
