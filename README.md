# ZTLab — Zero Trust Lab

A self-hosted, from-scratch zero-trust access control system running on 4 KVM/libvirt Debian 12 VMs. Built as a learning/portfolio project against the CISA Zero Trust Maturity Model v2.0.

**Architecture correction:** Uses nginx + oauth2-proxy + authz-bridge + OPA (not Pomerium — Pomerium Community doesn't support custom Rego policies, that's Enterprise-only). This is a fully open-source, properly separated PEP/PDP stack.

## Architecture

```
                          untrusted-net (10.10.2.0/24)
                            │
                    ┌───────┘
               ┌────┴────┐
               │ attacker │
               │ 10.10.2.10│
               └────┬────┘
                    │
             gateway:443 (only ingress)
                    │
          ┌─────────┴──────────────────┐
          │         gateway VM         │
          │  10.10.1.1                │
          │                            │
          │  nginx (PEP transport)     │
          │    └── auth_request ──────►│
          │  authz-bridge (PEP logic)  │
          │    ├──► oauth2-proxy (authn)│
          │    ├──► OPA (PDP, authz)   │
          │    └──► posture store      │
          │  WireGuard + nftables      │
          └─────────┬──────────────────┘
                    │ wg0 tunnel
          ┌─────────┴──────────┐
          │                    │
   ┌──────┴──────┐     ┌──────┴──────┐
   │   idp VM    │     │   app VM    │
   │  10.10.1.10 │     │ 10.10.1.20  │
   │  Authentik  │     │  Flask app  │
   │  (OIDC IdP) │     │  /public    │
   └─────────────┘     │  /sensitive │
                        └─────────────┘

```

**Logical flow:** client → nginx:443 → auth_request → authz-bridge → oauth2-proxy (session check) + OPA (Rego policy: MFA + posture + auth_time) → if allow → proxy to Flask app.

## VM Specs

| VM | IP | Role | RAM | Disk |
|----|----|------|-----|------|
| gateway | 10.10.1.1 | PEP/PDP, WireGuard, nftables, logs | 2 GB | 20 GB |
| idp | 10.10.1.10 | Authentik (OIDC identity provider) | 2 GB | 20 GB |
| app | 10.10.1.20 | Protected Flask demo app | 2 GB | 20 GB |
| attacker | 10.10.2.10 | Untrusted client for attack tests | 2 GB | 20 GB |

## Quick Start

```bash
# 1. Define networks
sudo virsh net-define networks/trusted-net.xml && sudo virsh net-start trusted-net
sudo virsh net-define networks/untrusted-net.xml && sudo virsh net-start untrusted-net

# 2. Create VMs (edit scripts/create-vms.sh for your ISO path)
sudo bash scripts/create-vms.sh

# 3. Install Debian 12 minimal on each VM, configure networking

# 4. Follow phases in order:
#    Phase 1: idp VM — Authentik docker-compose, OIDC, WebAuthn
#    Phase 2: client VMs — osquery + posture_check.py
#    Phase 3: gateway + app — WireGuard + nftables
#    Phase 4: gateway — docker compose up (nginx + oauth2-proxy + authz-bridge + OPA)
#    Phase 5: included in docker-compose (Flask demo app)
#    Phase 6: logs + revocation script
#    Phase 7: attacker VM — run 4 bypass tests
#    Phase 8: maturity scorecard
```

Each phase has a detailed checkpoint document with pre-reqs, failure modes, rollback, and definition-of-done checklist. Do not proceed to the next phase until the current one's checklist is complete.

## Phase Map

| Phase | Topic | Key File(s) |
|-------|-------|-------------|
| 0 | Lab environment | `networks/trusted-net.xml`, `gateway/nftables.conf` |
| 1 | Identity (Authentik) | `idp/docker-compose.yml` |
| 2 | Device posture | `scripts/posture_check.py`, `scripts/ztlab-posture.{service,timer}` |
| 3 | Network segmentation (WireGuard) | `gateway/wg0.conf`, `scripts/wg-add-peer.sh` |
| 4 | PEP+PDP (nginx+oauth2-proxy+authz-bridge+OPA) | `gateway/docker-compose.yml`, `gateway/opa/policy.rego`, `gateway/authz-bridge/app.py` |
| 5 | Demo app (Flask) | `app/app.py`, `app/Dockerfile` |
| 6 | Visibility + automation | `scripts/posture_revoker.py` |
| 7 | Attack simulation | `phase7-attack-simulation.md` |
| 8 | Maturity self-assessment | `phase8-maturity-scorecard.md` |

## Key Architecture Decisions

- **Why nginx + oauth2-proxy + authz-bridge instead of Pomerium?** Pomerium Community doesn't support custom Rego policies — that's Enterprise-only. The nginx `auth_request` pattern with a separate authz-bridge service gives us a real, decoupled PDP/PEP separation using only free software.
- **Why a shared JSON file for posture data?** Lab simplicity. The pattern (PEP reads posture at request time and includes it in OPA input) is architecture-identical to a production Redis-backed approach.
- **Why Flask instead of FastAPI?** Simpler for a two-route demo with inline templates. The app is intentionally dumb — it has no auth logic, trusting the upstream PEP.

## Lab Shortcuts (Not Production-Ready)

- Self-signed TLS certs
- Posture data in a JSON file keyed by IP (no integrity, no authentication)
- No mTLS between services
- oauth2-proxy header names are version-dependent — must verify against installed version
- No persistent log storage (Docker default loses on restart)
- Mock re-auth (auth_time from OIDC claim, not actual WebAuthn re-prompt)
