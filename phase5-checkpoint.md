# Phase 5 — Data Pillar / Demo App (v2, Flask)

## Pre-reqs (verify before starting)
- [ ] Phase 4's nginx + authz-bridge + OPA layer is proven working with a denial case, not just an allow case
- [ ] `docker compose ps` shows all gateway services running
- [ ] You've tested a curl against `/public` with a valid session and gotten 200

## Architecture Change

The demo app has NO auth logic of its own. Every request reaching it has already passed nginx's `auth_request` → authz-bridge → OPA check. This is deliberate: the app trusts the enforcement layer completely and stays dumb, which is the point of putting the PEP in front of it rather than inside it.

The app is a Flask app (simpler than FastAPI for this purpose) that renders two HTML pages from inline templates:
- `/public` — green banner "PUBLIC ZONE"
- `/sensitive` — red banner "SENSITIVE ZONE — RE-AUTH REQUIRED"

The re-authentication enforcement is handled by OPA's Rego policy (checking `input.user.auth_time`), not by the app.

## Files

| File | Purpose |
|------|---------|
| `app/app.py` | Flask app with /public, /sensitive, /healthz |
| `app/Dockerfile` | Python container build |
| `app/requirements.txt` | flask, gunicorn |

## Setup Steps

The app is defined as a service in `gateway/docker-compose.yml` and will be built and started with the rest of the stack:

```bash
cd /opt/ztlab/gateway
docker compose up --build -d demo-app
```

No separate deployment steps are needed — the Docker Compose setup handles it.

## Rego Policy (enforces re-auth for /sensitive)

From `gateway/opa/policy.rego`:

```rego
# Freshness window for /sensitive re-auth requirement
sensitive_reauth_window_seconds := 300  # 5 minutes

seconds_since_auth := result if {
	now := time.now_ns() / 1000000000
	result := now - input.user.auth_time
}

fresh_auth if {
	seconds_since_auth <= sensitive_reauth_window_seconds
}

# Allow rule: public paths just need base identity+posture
allow if {
	base_ok
	input.path != "/sensitive"
}

# Allow rule: /sensitive additionally needs a fresh re-auth
allow if {
	base_ok
	input.path == "/sensitive"
	fresh_auth
}
```

**Critical:** The check uses `input.user.auth_time` — the timestamp of the user's last authentication event, NOT the session creation time. This is what makes the re-auth requirement real: even with a valid session, if the last auth was more than 5 minutes ago, /sensitive is denied.

## Common Failure Modes

### 1. Re-auth checked against session creation time instead of auth_time
**What it looks like:** Once a user authenticates, they can access /sensitive indefinitely without re-authenticating.
**Why:** The OPA policy checks `input.user.auth_time` but the authz-bridge is populating it with session start time instead of last-auth time.
**How to check:** Authenticate, wait 6 minutes, access /sensitive. If it works, the timestamp is wrong.
**Fix:** authz-bridge now decodes the ID token JWT payload (via `--set-authorization-header` in oauth2-proxy) to extract the real `auth_time` claim from the OIDC token. Verify the `id_token claims` log line in authz-bridge shows a non-zero `auth_time` value. If `auth_time=0`, the ID token isn't being passed through or doesn't contain the claim.

## Definition of Done

- [ ] /public renders normally with green "PUBLIC ZONE" banner on any valid session
- [ ] /sensitive shows red "SENSITIVE ZONE — RE-AUTH REQUIRED" banner when accessed >5 minutes since last auth
- [ ] You've confirmed the check uses last-auth time (`input.user.auth_time`), not session-start time

## Lab Shortcuts Flagged

1. **No actual WebAuthn in the app** — the app doesn't perform WebAuthn itself. The "re-auth" is enforced by OPA verifying that the `auth_time` claim from Authentik is recent. This works for the lab but the actual re-authentication happens at the Authentik level, not in the app.
2. **Inline HTML templates** — minimal styling, but no separate template files. Fine for a demo.
3. **App is completely trustless** — it has no auth logic at all. This is correct per architecture (PEP is in front), but means if someone bypasses nginx they hit an unprotected app.
