# Phase 6 — Visibility + Automation (v2)

## Pre-reqs (verify before starting)
- [ ] Docker Compose stack from Phase 4 is running and producing logs: `docker compose logs --tail=20`
- [ ] Phase 2 posture agent is running on at least one client VM and writing to the shared posture store

## Log Aggregation Approach

With Docker Compose, each service's stdout/stderr is automatically collected by Docker's logging driver. For a single-VM lab, the simplest approach that serves the learning purpose:

**Option A: `docker compose logs` + structured JSON** (recommended for this lab)
Each service logs structured JSON lines to stdout. `docker compose logs --follow --tail=50` gives real-time visibility. Combine with a simple log viewer like `lnav` for filtering.

**Option B: Loki + Grafana** (if you want deeper dashboarding)
Run Loki and Grafana as additional services in `docker-compose.yml`. This is the same approach documented in v1, but the log sources are now Docker containers instead of system files.

For this lab, Option A is sufficient to prove visibility. **Recommend Loki/Grafana only if you specifically want the dashboarding practice** — the v1 docs for that are still in this repo if you want them.

### Minimal log viewer setup:
```bash
sudo apt install -y lnav
# Watch all docker logs in real-time
docker compose logs --follow --tail=50
# Or with lnav for colorized, filterable view
docker compose logs --follow --tail=50 | lnav
```

### Structured log format required per service:
Each service already logs structured JSON:
- `authz-bridge`: `{"decision": "allow"/"deny", "path": "...", "email": "...", "reason": "..."}`
- `opa`: OPA decision logs (JSON)
- `oauth2-proxy`: Auth request logs (JSON)
- `nginx`: Access logs (JSON if configured)

## Automation: Posture-Based Revocation Script

The revocation script (`scripts/posture_revoker.py`) monitors the shared posture JSON file. When a device transitions from `healthy: true` to `healthy: false`, it:

1. Removes the device's WireGuard peer from the gateway
2. Revokes the associated user's Authentik sessions via API

### Setup
```bash
# Copy the revoker script
sudo cp scripts/posture_revoker.py /usr/local/bin/posture_revoker.py
sudo chmod +x /usr/local/bin/posture_revoker.py

# Generate Authentik API token (Admin Interface → API Tokens → Create)
echo 'AUTHENTIK_TOKEN="ak-xxxxx-your-token-here"' | sudo tee /etc/ztlab/authentik.env

# Create the systemd service
sudo cp scripts/posture-revoker.service /etc/systemd/system/posture-revoker.service
sudo systemctl daemon-reload
sudo systemctl enable --now posture-revoker
```

The revoker watches the posture store file (same one mounted in docker-compose) and reacts to state changes within 5 seconds.

## Common Failure Modes

### 1. Log timestamps across services not in the same timezone
**What it looks like:** Events appear in wrong order when correlating across services.
**How to check:** `docker compose logs --tail=10 authz-bridge` and `docker compose logs --tail=10 opa` — compare timestamp formats.
**Fix:** Set `TZ=UTC` environment variable in `docker-compose.yml` for all services, or ensure host system timezone is UTC.

### 2. Revoker can't find the posture file
**What it looks like:** Revoker logs show `posture store missing or unreadable`.
**Why:** The revoker runs as a host process (not in Docker) but needs access to the same file the Docker services use.
**How to check:** The shared-posture volume is at `/opt/ztlab/gateway/shared-posture/posture.json` on the host. Verify the revoker's `POSTURE_STORE_PATH` env var or hardcoded path matches.
**Fix:** Update the revoker to point to the same file path, or change the docker-compose volume mount to a path the revoker can read.

## Definition of Done

- [ ] `docker compose logs --follow` shows live allow/deny events within seconds of requests
- [ ] Forcing a posture failure (writing `"posture": "unhealthy"` to the shared file) triggers automatic revocation within seconds
- [ ] You can correlate a single request across nginx, authz-bridge, oauth2-proxy, and OPA logs using a shared request ID or timestamp

## Lab Shortcuts Flagged

1. **No persistent log storage** — Docker's default logging driver loses logs on container restart. Add `json-file` with rotation or Loki for persistence.
2. **Revoker runs as host process** — not containerized. Fine for lab, production would run in the same orchestration.
3. **No log correlation ID** — correlating across services relies on timestamps, not a trace ID. Real deployments use structured logging with a shared request ID header.
