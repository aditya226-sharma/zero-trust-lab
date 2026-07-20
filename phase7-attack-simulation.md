# Phase 7 — Attack Simulation (v2, nginx + OPA stack)

## Pre-reqs (verify before starting)
- [ ] All Phases 0-6 services running: nginx, oauth2-proxy, authz-bridge, OPA, demo-app
- [ ] Docker Compose stack healthy: `docker compose ps` shows all services "Up"
- [ ] Attacker VM (10.10.2.10) booted with curl, nmap, nc installed
- [ ] You have a valid `_oauth2_proxy` session cookie from a legitimate browser login

## Architecture Under Test

```
Attacker (10.10.2.10)
    │
    ├── gateway:443 (only reachable port from untrusted-net)
    │       nginx ──auth_request──► authz-bridge ──► oauth2-proxy ──► Authentik
    │                                           ──► OPA
    │                                           ──► posture store
    │
    ├── app:443 (should NOT be reachable directly)
    ├── idp:443 (should NOT be reachable directly)
    └── any other port on gateway (should NOT be reachable except 443)
```

---

## Attempt 1: Direct Network Access to App VM (Bypassing Gateway)

**What this tests:** Network segmentation — can an attacker on untrusted-net reach the app's internal IP directly?

### Commands (from attacker VM)
```bash
# 1.1 — Port scan app's internal IP
nmap -Pn -p 1-65535 10.10.1.20

# 1.2 — Attempt direct HTTP(S)
curl -v --connect-timeout 5 http://10.10.1.20:8000 2>&1
curl -v --connect-timeout 5 https://10.10.1.20:443 2>&1

# 1.3 — ICMP
ping -c 3 -W 3 10.10.1.20

# 1.4 — Verify gateway:443 IS reachable (expected — the designed ingress)
curl -vk --connect-timeout 5 https://10.10.2.1:443 2>&1 | head -5
```

### Interpretation

| Result | Meaning | Verdict |
|--------|---------|---------|
| All ports filtered/timed out on 10.10.1.20 | Network segmentation holds | **PASS** |
| curl to app times out | No route from untrusted-net to trusted-net | **PASS** |
| Gateway:443 returns any response | Gateway's external interface reachable as designed | Expected |
| Any direct connection succeeds | Network segmentation failed | **FAIL** |

### FALSE-PASS alert
If gateway:443 is also unreachable (test 1.4 times out too), the network is down entirely — the "denial" is not a policy, it's a coincidence. Fix the network first.

---

## Attempt 2: Replaying Expired oauth2-proxy Session Cookie

**What this tests:** Session lifetime enforcement — can a captured cookie be reused after it expires?

### Commands
```bash
# 2.1 — Capture a valid _oauth2_proxy cookie from browser dev tools
OAUTH_COOKIE="_oauth2_proxy=eyJhbGciOiJ...<full-cookie-value>"

# 2.2 — Replay immediately (should work)
curl -vk -w "\nHTTP %{http_code}\n" \
  -H "Cookie: $OAUTH_COOKIE" \
  https://10.10.2.1/public 2>&1 | tail -5

# 2.3 — Wait for session to expire
# oauth2-proxy session lifetime is set by cookie_expire in cfg
# For testing, temporarily set cookie_expire = 1m in oauth2-proxy.cfg
# then: docker compose restart oauth2-proxy

# After waiting past expiry:
curl -vk -w "\nHTTP %{http_code}\n" \
  -H "Cookie: $OAUTH_COOKIE" \
  https://10.10.2.1/public 2>&1 | tail -5
```

### Interpretation

| Result | Meaning | Verdict |
|--------|---------|---------|
| 302 redirect to Authentik login | Session expired, cookie rejected | **PASS** |
| 200 with page content | Session not invalidated after expiry | **FAIL** |
| 403 from authz-bridge | Session may still be valid but OPA denied | Check X-ZTLab-Reason |

### FALSE-PASS alert
A 403 could come from OPA denying for other reasons (device unhealthy, no MFA). Check the `X-ZTLab-Reason` response header — if it says `denied: user not authenticated`, the session was invalid. If it says anything else, the session is still valid.

---

## Attempt 3: Submitting Spoofed Healthy Posture Data

**What this tests:** Posture integrity — can an attacker inject a false "healthy" verdict?

### Commands
```bash
# 3.1 — Check if shared-posture is readable from untrusted-net
# (It should NOT be — it's a file on the gateway's filesystem)
# From attacker, try to reach any file API or port that might expose it

# 3.2 — If attacker has breached trusted-net, they can write directly:
echo '{"10.10.2.10": {"posture": "healthy", "healthy": true, "signals": {...}, "checked_at": 9999999999}}' \
  > /opt/ztlab/gateway/shared-posture/posture.json

# 3.3 — After spoofing, attempt access
curl -vk -H "Cookie: $OAUTH_COOKIE" https://10.10.2.1/sensitive 2>&1
```

### Interpretation

| Result | Meaning | Verdict |
|--------|---------|---------|
| Posture file not reachable from attacker | File-based store is at least segmented | **PASS** (for network) |
| Spoofed data accepted without authentication | No integrity on posture data | **FAIL** |
| OPA reads spoofed data and allows access | Posture source not authenticated | **FAIL** (cascading) |

### FALSE-PASS alert
If you can't reach the posture file from the attacker, test from the gateway itself to verify the file-based mechanism actually affects decisions:
```bash
# From gateway — write unhealthy, confirm deny; write healthy, confirm allow
```

### CRITICAL NOTE
The posture store is a bind-mounted JSON file with no authentication or integrity. This is a **deliberate lab shortcut** flagged in all phase docs. A real deployment needs:
1. Signed posture assertions (JWT with device attestation)
2. A proper store (Redis, DB) instead of a file
3. Device identity that can't be spoofed by IP

---

## Attempt 4: Accessing /sensitive Without Fresh Re-auth

**What this tests:** Step-up auth — can /sensitive be accessed without a recent OIDC re-authentication?

### Commands
```bash
# 4.1 — Capture valid cookie
OAUTH_COOKIE="_oauth2_proxy=eyJhbGciOiJ..."

# 4.2 — Verify /public works
curl -vk -w "\nHTTP %{http_code}\n" \
  -H "Cookie: $OAUTH_COOKIE" \
  https://10.10.2.1/public 2>&1 | tail -3

# 4.3 — Access /sensitive, check status and deny reason
curl -vk -o /tmp/sensitive.txt -w "%{http_code}" -D - \
  -H "Cookie: $OAUTH_COOKIE" \
  https://10.10.2.1/sensitive 2>&1 | grep -E "HTTP/|X-ZTLab-Reason"

# 4.4 — Examine the body
cat /tmp/sensitive.txt
```

### Interpretation

| Result | Meaning | Verdict |
|--------|---------|---------|
| 403 + `X-ZTLab-Reason: denied: sensitive path requires re-auth within 5 minutes` | OPA correctly enforced re-auth | **PASS** |
| 200 + "SENSITIVE ZONE — RE-AUTH REQUIRED" visible | App rendered the right page but OPA allowed it through | **PARTIAL PASS** — check OPA policy |
| 200 + "SENSITIVE ZONE" without re-auth warning | Access granted without re-auth | **FAIL** |

### FALSE-PASS alert
A 403 with a deny reason other than "re-auth" (e.g., "device unhealthy") doesn't test re-auth enforcement. You need all three: valid session ✅, MFA verified ✅, device healthy ✅, but auth_time > 5 minutes ago ❌ — only then does a 403 prove re-auth enforcement.

### What this tests
Even with a valid, unexpired session cookie, /sensitive requires a recent authentication event. This is step-up authentication — the cookie alone isn't enough for high-value endpoints.

---

## Documented Results Template

```markdown
# Zero-Trust Attack Simulation Results — ZTLab v2 (nginx + OPA)

## Attempt 1: Direct Network Access
**Commands:** nmap -Pn -p 1-65535 10.10.1.20
**Result:** All 65535 ports filtered/timed out
**False-pass ruled out?** Yes — gateway:443 was reachable confirming network is up
**Interpretation:** PASS — network segmentation holds

## Attempt 2: Session Replay
**Commands:** Captured _oauth2_proxy cookie, waited 2m (TTL reduced to 1m), replayed
**Result:** HTTP 302 redirect to Authentik login
**False-pass ruled out?** Yes — confirmed X-ZTLab-Reason was absent (nginx redirect, not OPA deny)
**Interpretation:** PASS — session properly expired

## Attempt 3: Posture Spoofing
**Commands:** Direct file write to shared-posture/posture.json (requires trusted-net access first)
**Result:** No direct route from attacker — file unreachable
**Commands:** (From gateway) Wrote spoofed unhealthy → deny. Wrote healthy → allow.
**Interpretation:** PARTIAL PASS — store is segmented but has no authentication once on trusted-net
**Notes:** This is a real design gap. The posture file has no integrity protection.

## Attempt 4: Missing Re-auth
**Commands:** curl -H "Cookie: ..." https://10.10.2.1/sensitive
**Result:** HTTP 403 with X-ZTLab-Reason: "denied: sensitive path requires re-auth within 5 min"
**False-pass ruled out?** Yes — confirmed MFA and device were healthy, only auth_time was old
**Interpretation:** PASS — re-auth enforcement working via OPA
```

## Summary Table

| Attempt | Objective | Expected | Actual | Verdict |
|---------|-----------|----------|--------|---------|
| 1 | Direct network access to app | Timeout / no route | | □ PASS □ FAIL |
| 2 | Replay expired session cookie | 302 redirect / 401 | | □ PASS □ FAIL |
| 3 | Spoof healthy posture | Denied (or file unreachable) | | □ PASS □ FAIL |
| 4 | Access /sensitive without re-auth | 403 / re-auth reason | | □ PASS □ FAIL |

## Lab Shortcuts Flagged

1. **Attempt 3 is the most likely real gap.** The posture file has no integrity or authentication. Segmentation protects it but a trusted-net breach compromises it completely.
2. **Attempt 2 depends on oauth2-proxy session config.** Verify `cookie_expire` is set.
3. **Attempt 4 depends on auth_time being correctly populated.** Verify oauth2-proxy passes the `auth_time` claim and authz-bridge reads it correctly.
