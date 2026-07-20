# Phase 8 — CISA Zero Trust Maturity Model v2.0 Self-Assessment (v2)

**Scored against:** CISA ZTMM v2.0 (April 2024) — 5 pillars × 4 stages (Traditional → Initial → Advanced → Optimal)

**Architecture assessed:** nginx + oauth2-proxy + authz-bridge + OPA (Phase 4+), WireGuard + nftables (Phase 0/3), Authentik OIDC (Phase 1), osquery posture (Phase 2)

## Scorecard

| Pillar | Stage | Justification (traceable to a specific phase's definition-of-done) | Highest-Leverage Next Step |
|--------|-------|---------------------------------------------------------------------|---------------------------|
| **Identity** | Advanced | Authentik OIDC with phishing-resistant WebAuthn MFA (Phase 1 DoD: password alone explicitly fails), 20-min session verified by waiting, session validation at PEP layer via oauth2-proxy (Phase 4 DoD: auth_time-check OPA policy verified), step-up auth for /sensitive (Phase 5 DoD: last-auth-time check confirmed operational) | Add continuous authentication with risk-based step-up (anomalous location/device triggers additional factor) to reach Optimal |
| **Devices** | Advanced | Osquery-based posture checks for disk encryption, patch age, blocklisted processes (Phase 2 DoD: fail-closed verified, manual force of both states); automated revocation on posture failure (Phase 6 DoD: triggers verified); device presence gates network access via WireGuard peer approval (Phase 3 DoD: no tunnel = no app access) | Add hardware-rooted attestation (TPM 2.0 measured boot, device identity certs) to eliminate pure-software reporting and reach Optimal |
| **Networks** | Advanced | WireGuard segmentation with default-deny nftables (Phase 0 DoD: nftables survives reboot, attacker can reach only gateway:443); app reachable only via wg0 regardless of subnet (Phase 3 DoD: trusted-net device without tunnel cannot reach app); separate trusted/untrusted libvirt networks with no direct route | Implement per-application microsegmentation (one WireGuard tunnel per workload instead of per-VM) |
| **Applications & Workloads** | Initial | nginx as PEP transport with auth_request → authz-bridge → OPA (Phase 4 DoD: OPA denies unhealthy device, both allow/deny verified via curl before browser); Rego policy with MFA + posture + auth_time checks; Flask demo app with no local auth logic (correct trust-the-PEP pattern); attack simulation confirms all 4 bypass attempts blocked (Phase 7) | Add mutual TLS (mTLS) with SPIFFE/SPIRE workload identity for service-to-service auth — this moves from Initial to Advanced |
| **Data** | Traditional | No data-level protections. The Flask app distinguishes routes (/public vs /sensitive) with different banners, but the data objects themselves have no classification labels, no ABAC, no per-class encryption. Route-level enforcement works (Phase 5 DoD: /sensitive denied without fresh auth), but if the route check is bypassed, all data is equally accessible. | Implement data classification labels at the data object level and attribute-based access control (ABAC) in OPA to reach Initial |

## Summary

```
Identity       ████████████████████░░░░  Advanced
Devices        ████████████████████░░░░  Advanced
Networks       ████████████████████░░░░  Advanced
Applications   ████████░░░░░░░░░░░░░░░░  Initial
Data           ██████░░░░░░░░░░░░░░░░░░  Traditional
               ────────────────────────
Overall        ██████████████░░░░░░░░░░  Advanced-Initial (weighted)
```

**Strongest:** Networks + Identity — the WireGuard-gated nftables segmentation (Phase 3) and Authentik+oauth2-proxy OIDC with MFA enforcement (Phase 1+4) are the most thoroughly tested layers.

**Weakest:** Data — no classification or ABAC. This is the most common gap in real-world zero-trust deployments and the hardest to retrofit. The Flask app's route-level distinction is a start but doesn't qualify above Traditional because the data itself has no labels.

**Fastest path to Optimal:** Add hardware attestation (Devices pillar via TPM) and risk-based step-up (Identity). Both achievable without architectural changes.

**Longest path:** Data pillar — requires fundamental data classification, labeling, and attribute-based access controls. This separates portfolio projects from production zero-trust.

## Phase Traceability

| Pillar | Verifies In | Key Verified Behavior |
|--------|-------------|----------------------|
| Identity | Phase 1, Phase 4, Phase 5, Phase 7 | Password-alone fails, MFA required, 20-min expiry, auth_time check, session replay blocked |
| Devices | Phase 2, Phase 3, Phase 6, Phase 7 | Posture fail-closed, manual force test, revocation, posture spoofing blocked |
| Networks | Phase 0, Phase 3, Phase 7 | Default-deny persists, WireGuard gating, direct access blocked |
| Applications | Phase 4, Phase 5, Phase 7 | OPA allow/deny verified, step-up auth, all 4 bypass attempts blocked |
| Data | Phase 5, Phase 7 | Route-level control works but no data-level classification exists |
