# Phase 4 — PEP + PDP Integration (v2, nginx + OPA stack)

## Architectural Change Note

**Correction from earlier prompts:** Pomerium Community does NOT support custom Rego policies — that's an Enterprise-only feature. The free version only supports PPL (their own YAML policy language). Building on Pomerium Community would mean either paying for Enterprise or not actually using OPA at all — a fake PDP.

This phase instead uses the **fully open-source** stack:
- **nginx** — PEP transport layer, handles TLS and `auth_request` to the decision point
- **oauth2-proxy** — OIDC authentication front-end against Authentik
- **authz-bridge** — PEP glue logic: validates session via oauth2-proxy, reads posture, calls OPA
- **OPA** — PDP, evaluates Rego policy and returns allow/deny

## Pre-reqs (verify before starting)
- [ ] Phase 1's "ztlab-app" OIDC entry exists, client ID and secret are saved
- [ ] Phase 2's posture store mechanism works (shared JSON file on docker-compose volume)
- [ ] Phase 3's WireGuard tunnel is active, app VM reachable from gateway over wg0
- [ ] Docker + Docker Compose installed on gateway VM: `docker --version && docker compose version`
- [ ] (This version uses JWT payload decoding — no header name guessing needed — but still verify oauth2-proxy's `--set-authorization-header` actually passes the ID token)

## Architecture

```
Client -> nginx:443 (PEP transport) -> authz-bridge:9191/validate (PEP logic)
                                          |
                                          +-> oauth2-proxy:4180/oauth2/auth (authn)
                                          +-> OPA:8181/v1/data/ztlab/authz (authz)
                                          +-> shared-posture/posture.json (device state)
                                          |
                                   nginx proxies to demo-app:8080 on 200
                                   nginx returns 403 on non-200
```

**Data flow:**
1. Client hits `https://app.ztlab.local/public`
2. nginx intercepts, calls `/validate` (internal location)
3. authz-bridge receives the request, forwards session cookie to oauth2-proxy's `/oauth2/auth`
4. oauth2-proxy validates the OIDC session against Authentik, returns identity claims as headers
5. authz-bridge reads device posture from shared JSON file (keyed by source IP)
6. authz-bridge assembles input `{user, device, path}` and POSTs to OPA's `/allow` and `/reason`
7. OPA evaluates Rego policy — checks `authenticated`, `mfa_verified`, `posture`, and `auth_time` freshness for `/sensitive`
8. authz-bridge returns 200 (nginx proxies to demo-app) or 403 (nginx returns denial)

## Setup Steps

### 1. Create directory structure on gateway VM
```bash
mkdir -p /opt/ztlab/gateway/{nginx/{conf.d,certs},oauth2-proxy,opa,authz-bridge,shared-posture}
cd /opt/ztlab/gateway
```

### 2. Copy all files from this repo's `gateway/` directory

### 3. Generate secrets
```bash
# Cookie secret for oauth2-proxy
python3 -c "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
# PASTE this into gateway/oauth2-proxy/oauth2-proxy.cfg as cookie_secret

# Self-signed TLS cert for lab
openssl req -x509 -newkey rsa:2048 -keyout /opt/ztlab/gateway/nginx/certs/ztlab.key \
  -out /opt/ztlab/gateway/nginx/certs/ztlab.crt -days 365 -nodes \
  -subj "/CN=app.ztlab.local"

# Authentik client secret — copy from Phase 1's "ztlab-app" OIDC provider
# PASTE into gateway/oauth2-proxy/oauth2-proxy.cfg as client_secret

# Initialize posture store
echo '{}' > /opt/ztlab/gateway/shared-posture/posture.json
```

### 4. Update /etc/hosts on gateway
```bash
echo "10.10.1.10 idp.ztlab.local" | sudo tee -a /etc/hosts
# The idp hostname must resolve for oauth2-proxy to reach Authentik
```

### 5. Start the stack
```bash
cd /opt/ztlab/gateway
docker compose up --build -d

# Verify all services are running
docker compose ps

# Check logs
docker compose logs --tail=20
```

## Common Failure Modes

### 1. ID token / Authorization header not being passed through
**What it looks like:** Authentication succeeds (user can log in) but authz-bridge reports `"authenticated": True` while `mfa_verified` stays `False` and `auth_time` is `0`. The `/validate` log shows `id_token claims: email=... auth_time=0 amr=[]`.
**Why:** oauth2-proxy's `--set-authorization-header` flag is missing or not set correctly. Without it, the ID token (which contains `auth_time` and `amr` claims) is not included in the `/oauth2/auth` response, and authz-bridge's JWT decoder returns an empty payload.
**How to check:** Simulate what authz-bridge sends:
```bash
# On gateway, after a successful browser login, extract your cookie and test:
curl -v http://oauth2-proxy:4180/oauth2/auth -H "Cookie: _oauth2_proxy=<your-cookie>" 2>&1 | grep -i authorization
```
Expected output: `Authorization: Bearer <jwt>` — if missing, `set_authorization_header` isn't working.
**Fix:** Ensure `oauth2-proxy.cfg` contains `set_authorization_header = true`. If it does and the header still doesn't appear, check if your oauth2-proxy version renamed or removed this flag — the 7.x docs confirm it exists.

### 2. OPA input schema mismatch (silent always-deny)
**What it looks like:** Every request is denied, even when logged in with MFA + healthy device.
**Why:** The Rego policy references `input.user.authenticated`, `input.device.posture`, etc., but authz-bridge sends slightly different key names.
**How to check:** Add a debug print to authz-bridge or check its logs:
```bash
docker compose logs authz-bridge
```
Look for the "decision" log line — it shows what authz-bridge sent. Compare against the Rego policy's expected input schema.
**Fix:** The policy expects `input.user.authenticated`, `input.user.mfa_verified`, `input.user.auth_time`, `input.device.posture`, `input.path`. Authz-bridge sends exactly these keys. If they don't match, edit `authz-bridge/app.py`'s `opa_input` dict.

### 3. Clock skew between VMs breaking OIDC token validation
**What it looks like:** Intermittent login failures — tokens work for a few minutes then get rejected as expired, or are immediately rejected with "iat in the future."
**How to check:** Compare times across gateway, idp, and any client:
```bash
date -u
```
**Fix:** Install NTP on all VMs: `sudo apt install -y ntp && sudo systemctl enable --now ntp`

## Minimal curl-based test (before browser flow)

```bash
# 1. Test OPA directly with known-good input
curl -X POST http://127.0.0.1:8181/v1/data/ztlab/authz/allow \
  -H "Content-Type: application/json" \
  -d '{"input":{"user":{"authenticated":true,"mfa_verified":true,"auth_time":1000000000},"device":{"posture":"healthy"},"path":"/public"}}'
# Expected: {"result":true}

# 2. Test OPA with unhealthy device (should deny)
curl -X POST http://127.0.0.1:8181/v1/data/ztlab/authz/allow \
  -H "Content-Type: application/json" \
  -d '{"input":{"user":{"authenticated":true,"mfa_verified":true,"auth_time":1000000000},"device":{"posture":"unhealthy"},"path":"/public"}}'
# Expected: {"result":false}

# 3. Test the nginx -> auth_request -> authz-bridge path
# (Requires a valid session cookie; after browser login:)
curl -vk -o /dev/null -w "%{http_code}" \
  -H "Cookie: _oauth2_proxy=<your-cookie>" \
  https://app.ztlab.local/public 2>&1
# Expected: 200

# 4. Check deny reason header
curl -vk -o /dev/null -w "%{http_code}\n" -D - \
  -H "Cookie: _oauth2_proxy=<your-cookie>" \
  https://app.ztlab.local/sensitive 2>&1 | grep -E "HTTP/|X-ZTLab-Reason"
```

## Definition of Done

- [ ] Valid Authentik session + healthy posture → request allowed (200)
- [ ] Valid Authentik session + posture forced unhealthy → request DENIED (403 with `X-ZTLab-Reason: denied: device posture unhealthy`)
- [ ] No valid session at all → request denied before even reaching OPA (401 redirect or 403)
- [ ] You can explain, without looking at notes, the full data flow: nginx → auth_request → authz-bridge → oauth2-proxy + OPA + posture store → decision → nginx → app
- [ ] You've hit at least one real failure and fixed it (likely the oauth2-proxy header name issue) — if this phase went smoothly, you skipped something

## Lab Shortcuts Flagged

1. **Posture store is a bind-mounted JSON file** — keyed by source IP, trivially spoofable. Production needs Redis/database keyed by real device identity.
2. **Self-signed TLS cert** — fine for lab, not for anything real.
3. **oauth2-proxy `--set-authorization-header` flag name is version-consistent** (it's existed since 7.x) but still verify it works in your installed version before trusting the config.
4. **OPA port 8181 exposed** — open for direct curl testing in the lab. Production would remove this exposure.
