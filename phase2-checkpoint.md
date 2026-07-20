# Phase 2 — Device Posture Pillar (v2, shared-file store)

## Pre-reqs (verify before starting)
- [ ] `osqueryi --version` works on each client VM
- [ ] Docker Compose stack from Phase 4 has the `shared-posture` directory created: `mkdir -p /opt/ztlab/gateway/shared-posture && echo '{}' > /opt/ztlab/gateway/shared-posture/posture.json`
- [ ] Python 3 available on all client VMs: `python3 --version`
- [ ] Client VMs can write to the shared-posture directory on the gateway (via NFS, scp, or direct mount — in this lab, the file is bind-mounted into the Docker container, and the posture_check.py runs on the gateway itself for simplicity, or on client VMs with write access)

## Architecture Change (from v1)

**Old approach:** Each client VM POSTed posture JSON to a webhook on the gateway.

**New approach:** Each client VM writes directly to a shared JSON file (`shared-posture/posture.json`) keyed by source IP. The authz-bridge reads this file synchronously on every request. This is a lab simplification — in production this would be a proper store (Redis, DB) with authenticated writes.

## Files Created

| File | Purpose |
|------|---------|
| `scripts/posture_check.py` | osquery-based posture check, writes to shared JSON store |
| `scripts/ztlab-posture.service` | systemd oneshot unit |
| `scripts/ztlab-posture.timer` | systemd timer (every 60s) |

## Setup Steps

### On gateway VM (or wherever the shared-posture directory lives):
```bash
# 1. Create the shared posture store
mkdir -p /opt/ztlab/gateway/shared-posture
echo '{}' > /opt/ztlab/gateway/shared-posture/posture.json
```

### On each client VM (or gateway if running locally):
```bash
# 2. Install osquery
curl -L https://github.com/osquery/osquery/releases/download/5.15.0/osquery_5.15.0-1.linux_amd64.deb -o /tmp/osquery.deb
sudo dpkg -i /tmp/osquery.deb; sudo apt install -f -y

# 3. Deploy the posture check script
sudo cp scripts/posture_check.py /usr/local/bin/posture_check.py
sudo chmod +x /usr/local/bin/posture_check.py

# 4. Edit the script to set POSTURE_STORE_PATH to the actual shared path
#    If running on the gateway itself: /opt/ztlab/gateway/shared-posture/posture.json
#    If running remotely: adjust to the mount path

# 5. Test manually
sudo python3 /usr/local/bin/posture_check.py
```

### Schedule (systemd timer):
```bash
sudo cp scripts/ztlab-posture.service /etc/systemd/system/ztlab-posture.service
sudo cp scripts/ztlab-posture.timer /etc/systemd/system/ztlab-posture.timer
sudo systemctl daemon-reload
sudo systemctl enable --now ztlab-posture.timer
```

## Common Failure Modes

### 1. osquery returns empty results on some VMs
**What it looks like:** `disk_encryption` table returns no rows, or `processes` table returns empty.
**How to check:** `osqueryi ".tables" | grep -E "disk|encrypt"` — if the table isn't available, the query returns empty.
**Fix:** Adjust `check_disk_encryption()` in the script. On non-encrypted VMs, the check correctly returns `False` (fail-closed). If you want to test on a non-encrypted VM, you'll get "unhealthy" which is correct behavior for the zero-trust model.

### 2. Script reports "healthy": true by default when a query fails (FAIL-OPEN bug)
**What it looks like:** A broken osquery still produces `"healthy": true`.
**Why:** This is the most common posture-script bug. If error handling defaults to pass, the check is meaningless.
**How to check:** Stop osquery (`sudo systemctl stop osqueryd`), run the script. If it says `"healthy": true`, the script has a fail-open bug.
**Fix:** The script in this repo fails CLOSED — every query error returns `False`. Verify by reading `posture_check.py`: every `except` block returns `None` (which the caller treats as failure) or directly returns `False`.

### 3. Posture file not writable
**What it looks like:** Script runs but the shared store file is not updated.
**How to check:** `cat /opt/ztlab/gateway/shared-posture/posture.json` — if it's still `{}` after running the script, the path is wrong or permissions are bad.
**Fix:** `sudo chmod 666 /opt/ztlab/gateway/shared-posture/posture.json` or run the script as root.

## Forcing Specific States (for testing Phase 4)

```bash
# Force HEALTHY:
python3 /usr/local/bin/posture_check.py
# OR write directly:
echo '{"10.10.1.1":{"posture":"healthy","healthy":true,"signals":{"disk_encrypted":true,"patch_within_window":true,"no_blocklisted_process":true},"checked_at":9999999999}}' > /opt/ztlab/gateway/shared-posture/posture.json

# Force UNHEALTHY:
echo '{"10.10.1.1":{"posture":"unhealthy","healthy":false,"signals":{"disk_encrypted":false,"patch_within_window":false,"no_blocklisted_process":false},"checked_at":1}}' > /opt/ztlab/gateway/shared-posture/posture.json
```

## Definition of Done

- [ ] Running on 2+ VMs gives believable pass/fail verdicts matching their actual state
- [ ] You've confirmed the script fails CLOSED (broken osquery query results in "unhealthy", not a silent default-true)
- [ ] You can manually force both states for testing Phase 4 later
- [ ] Posture JSON is actually landing in the shared store, readable by authz-bridge

## Lab Shortcuts Flagged

1. **Store is a bind-mounted JSON file** — keyed by source IP, trivially spoofable. Production needs Redis/database with authenticated writes.
2. **Patch age via apt history log mtime** — imprecise. Production queries package manager directly.
3. **No attestation** — pure software reporting. A compromised client can lie. Production needs TPM.
4. **fail-closed verified?** — verify by running with osquery disabled and confirming `"healthy": false`.
