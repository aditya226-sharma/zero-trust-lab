# Phase 1 — Identity Pillar (Authentik) (v2)

## Pre-reqs (verify before starting)
- [ ] Docker + Docker Compose installed on `idp` VM: `docker --version && docker compose version`
- [ ] Ports 80/443 (or 9000/9443) free on idp: `ss -tlnp | grep -E ':(80|443|9000|9443) '`
- [ ] idp has a resolvable hostname OR you're prepared to use its IP directly in redirect URIs
- [ ] Phase 0 networking verified: `idp` can reach gateway, gateway can reach idp

## Setup Steps (run on idp VM: 10.10.1.10)

### 1. Deploy Authentik
```bash
# Install Docker + Compose if not present
sudo apt update && sudo apt install -y docker.io docker-compose-plugin
sudo systemctl enable --now docker

# Create project directory
mkdir -p /opt/authentik && cd /opt/authentik

# Create .env with secrets (use the template from idp/.env.template)
echo "PG_PASS=$(openssl rand -base64 36 | tr -d '\n')" >> .env
echo "AUTHENTIK_SECRET_KEY=$(openssl rand -base64 60 | tr -d '\n')" >> .env

# Deploy compose file
cp /path/to/idp/docker-compose.yml ./
sudo docker compose up -d

# Wait for healthy — this takes 30-60s on first start
sudo docker compose ps
# Both server and worker should show "Up" and "healthy"
```

### 2. Initial Admin Setup
Access https://10.10.1.10 (accept self-signed cert warning).
1. Set the admin password on first login — **set this to a strong password + WebAuthn immediately**
2. Log in as admin

### 3. Create OIDC Application "ztlab-app"
1. **Admin Interface** → **Applications** → **Applications** → **Create with Provider**
2. Name: `ZTLab App`, Slug: `ztlab-app`
3. Provider Type: **OAuth2/OIDC**
4. Redirect URIs/Origins: `https://app.ztlab.local/oauth2/callback` (oauth2-proxy's callback URL, proxied through nginx)
5. Client Type: **Confidential**
6. Scopes: check `openid`, `profile`, `email`, `offline_access`
7. **WRITE DOWN** the Client ID and Client Secret — they appear once and you'll need them in Phase 4

### 4. Enforce WebAuthn as Required Second Factor
1. **Admin Interface** → **Flows & Stages** → **Stages** → **Create**
2. Create a **WebAuthn Authenticator Setup Stage**: name `webauthn-setup`
3. Create an **Authenticator Validation Stage**: name `webauthn-validate`, Device classes: only **WebAuthn** (uncheck TOTP, SMS), Not configured action: **Configure**, Configuration stages: select `webauthn-setup`
4. **Flows** → `default-authentication-flow` → **Stage Bindings** → **Bind existing stage** → select `webauthn-validate`
5. Order: Password stage → **webauthn-validate** → User Login stage

### 5. Set Session Lifetime to 20 Minutes
1. **Flows & Stages** → **Stages** → find the `User Login` stage in `default-authentication-flow`
2. Edit → set **Session duration** to `minutes=20`
3. Save

## Common Failure Modes

### 1. Redirect URI mismatch
**What it looks like:** Authentik shows "Invalid redirect URI" after OIDC login attempt.
**How to check:** Look at the error URL in the browser — it will include the redirect_uri that Authentik rejected. Compare against what you configured in the OIDC provider.
**Fix:** The redirect URI must match **exactly** (including trailing slash if present, protocol, port). For oauth2-proxy it's `https://app.ztlab.local/oauth2/callback`.

### 2. PostgreSQL not healthy before Authentik starts
**What it looks like:** `docker compose ps` shows `server` restarting in a loop. `docker compose logs server` shows database connection errors.
**How to check:** `docker compose logs postgresql | tail -20` — look for "ready to accept connections" or "database system is ready".
**Fix:** The docker-compose.yml has `depends_on: condition: service_healthy` which should handle this, but on slow storage the postgres healthcheck can time out. Increase `start_period` in the healthcheck or restart with `docker compose restart`.

### 3. WebAuthn fails on HTTP (not HTTPS)
**What it looks like:** WebAuthn prompt never appears, or browser console shows "PublicKeyCredential creation requires a secure context".
**How to check:** Browser dev tools → Console tab during login attempt. Also check URL starts with `https://`.
**Fix:** Authentik's docker-compose exposes port 9443 for HTTPS. Access https://10.10.1.10:9443 instead of port 80/9000. Or set up a reverse proxy with a valid cert. For this lab, use the self-signed HTTPS endpoint.

## Rollback

```bash
# Reset Authentik completely (keeps database, loses config)
cd /opt/authentik
sudo docker compose down
sudo rm -rf data/custom-templates/*  # optional: remove customizations

# Full reset (wipes everything including database)
sudo docker compose down -v
sudo rm -rf data/

# Re-deploy from scratch
sudo docker compose up -d
```

If you lock yourself out of the admin account during MFA setup:
```bash
# Reset admin MFA via the shell:
sudo docker compose run --rm server manage createsuperuser
# Then log in with a fresh MFA enrollment
```

## Definition of Done

- [ ] Admin UI reachable and admin account secured with its own MFA
- [ ] "ztlab-app" OIDC provider entry exists with a redirect URI you've actually written down
- [ ] Login with password + WebAuthn succeeds
- [ ] Login with password alone (no key) explicitly fails — you've tested this, not assumed it
- [ ] You can verify a session actually expires at 20 minutes by waiting and retrying, not just trusting the config value

## Lab Shortcuts Flagged

1. **Self-signed cert on idp** — Authentik's default self-signed cert is fine for this lab. Production requires Let's Encrypt or proper CA.
2. **Single admin user** — Real deployments need proper user provisioning and role management.
3. **No backup factors** — If the WebAuthn key is lost, the user is locked out. Real deployments should provide backup WebAuthn keys (not fallback to OTP).
