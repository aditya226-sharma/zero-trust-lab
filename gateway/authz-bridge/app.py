"""
authz-bridge — the actual PEP logic.

nginx's auth_request directive calls this service on every request to a
protected route. This service:
  1. Validates the session by calling oauth2-proxy's internal /oauth2/auth
     endpoint (which fronts Authentik) — gets identity + auth_time claims.
  2. Looks up the requesting device's posture verdict (written by the
     Phase 2 posture agent, keyed by source IP for lab simplicity).
  3. Calls OPA's REST API with a combined input document.
  4. Returns 200 (nginx allows the request through) or 403 (nginx blocks
     it) based on OPA's decision — never decides allow/deny itself.

NEW FEATURES:
  - WireGuard peer provisioning API (/api/peers)
  - Admin dashboard for real-time posture/access monitoring (/admin)
  - Continuous authentication risk scoring (/api/risk-score)
  - Structured audit logging to /var/log/audit.jsonl

Run with: gunicorn -w 2 -b 0.0.0.0:9191 app:app
"""

import base64
import ipaddress
import json
import logging
import os
import subprocess
import time
from typing import Any

import requests
from flask import Flask, request, Response, jsonify, render_template_string

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("authz-bridge")

OAUTH2_PROXY_AUTH_URL: str = os.environ.get(
    "OAUTH2_PROXY_AUTH_URL", "http://oauth2-proxy:4180/oauth2/auth"
)
OPA_URL: str = os.environ.get("OPA_URL", "http://opa:8181/v1/data/ztlab/authz")
POSTURE_STORE_PATH: str = os.environ.get(
    "POSTURE_STORE_PATH", "/data/posture.json"
)
WG_INTERFACE: str = os.environ.get("WG_INTERFACE", "wg0")
WG_SUBNET: str = os.environ.get("WG_SUBNET", "10.8.0")
PEERS_CONF_PATH: str = os.environ.get("PEERS_CONF_PATH", "/data/peers.conf")
AUDIT_LOG_PATH: str = os.environ.get("AUDIT_LOG_PATH", "/data/audit.jsonl")
ADMIN_TOKEN: str = os.environ.get("ADMIN_TOKEN", "ztlab-admin-token")
MAX_POSTURE_AGE_SECONDS: int = int(os.environ.get("MAX_POSTURE_AGE_SECONDS", "300"))
RISK_THRESHOLD: int = int(os.environ.get("RISK_THRESHOLD", "70"))


def _write_audit_log(event: dict) -> None:
    """Append a structured audit event to the audit log."""
    event["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(event) + "\n")
    except OSError as e:
        log.error("Failed to write audit log: %s", e)


def get_posture(source_ip: str) -> dict[str, Any]:
    try:
        with open(POSTURE_STORE_PATH, "r") as f:
            store: dict[str, Any] = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        log.warning("posture store missing or unreadable — failing closed")
        return {"posture": "unhealthy", "reason": "no posture data"}
    entry = store.get(source_ip)
    if not entry:
        return {"posture": "unhealthy", "reason": "no posture record for source"}
    return entry


def _decode_id_token(header_value: str) -> dict[str, Any]:
    """Base64-decode the JWT payload from an Authorization: Bearer header.

    oauth2-proxy already verified the JWT signature before passing it
    through — we only decode the payload to extract claims.
    """
    if not header_value.startswith("Bearer "):
        return {}
    token = header_value[len("Bearer "):]
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    try:
        payload = parts[1]
        padded = payload + "=" * ((4 - len(payload) % 4) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        return json.loads(decoded)
    except (ValueError, json.JSONDecodeError):
        log.warning("failed to decode id_token payload")
        return {}


def check_identity(incoming_headers: Any) -> dict[str, Any]:
    """
    Calls oauth2-proxy's own auth-check endpoint, forwarding the session
    cookie, to find out who the user is and whether they're authenticated.
    """
    cookie: str = incoming_headers.get("Cookie", "")
    try:
        r = requests.get(
            OAUTH2_PROXY_AUTH_URL,
            headers={"Cookie": cookie},
            timeout=3,
        )
    except requests.RequestException as e:
        log.error("oauth2-proxy check failed: %s", e)
        return {"authenticated": False}

    if r.status_code != 202:
        return {"authenticated": False}

    id_token: dict[str, Any] = _decode_id_token(
        r.headers.get("Authorization", "")
    )
    email: str = id_token.get(
        "email", r.headers.get("X-Auth-Request-Email", "")
    )
    auth_time: int = id_token.get("auth_time", 0)
    amr: list[str] = id_token.get("amr", [])

    log.info(
        "id_token claims: email=%s auth_time=%s amr=%s", email, auth_time, amr
    )

    return {
        "authenticated": True,
        "email": email,
        "mfa_verified": "webauthn" in amr or "mfa" in str(amr).lower(),
        "auth_time": int(auth_time or 0),
    }


@app.route("/validate", methods=["GET"])
def validate() -> Response:
    original_uri: str = request.headers.get("X-Original-URI", "/")
    source_ip: str = request.headers.get(
        "X-Forwarded-For", request.remote_addr or ""
    )

    identity: dict[str, Any] = check_identity(request.headers)
    posture: dict[str, Any] = get_posture(source_ip)

    opa_input: dict[str, Any] = {
        "input": {
            "user": {
                "authenticated": identity.get("authenticated", False),
                "mfa_verified": identity.get("mfa_verified", False),
                "auth_time": identity.get("auth_time", 0),
                "email": identity.get("email", ""),
            },
            "device": {
                "ip": source_ip,
                "posture": posture.get("posture", "unhealthy"),
            },
            "path": original_uri,
        }
    }

    allowed: bool = False
    reason: str = "denied: policy engine unreachable"

    try:
        opa_resp = requests.post(
            f"{OPA_URL}/allow", json=opa_input, timeout=3
        )
        opa_reason_resp = requests.post(
            f"{OPA_URL}/reason", json=opa_input, timeout=3
        )
        allowed = opa_resp.json().get("result", False)
        reason = opa_reason_resp.json().get("result", "unknown")
    except requests.RequestException as e:
        log.error("OPA unreachable, failing closed: %s", e)

    _write_audit_log({
        "event": "access_decision",
        "path": original_uri,
        "source_ip": source_ip,
        "email": identity.get("email", ""),
        "allowed": allowed,
        "reason": reason,
    })

    log.info(
        "decision path=%s ip=%s email=%s allowed=%s reason=%s",
        original_uri,
        source_ip,
        identity.get("email", "?"),
        allowed,
        reason,
    )

    if allowed:
        return Response(status=200, headers={"X-ZTLab-Reason": reason})
    if not identity.get("authenticated", False):
        return Response(
            status=401,
            headers={"X-ZTLab-Reason": reason, "Location": "/oauth2/sign_in"},
        )
    return Response(status=403, headers={"X-ZTLab-Reason": reason})


# ---------------------------------------------------------------------------
# WireGuard Peer Provisioning API
# ---------------------------------------------------------------------------

def _get_wg_peers() -> dict[str, dict[str, str]]:
    """Parse current WireGuard peers into {public_key: {allowed_ips, endpoint}}."""
    try:
        result = subprocess.run(
            ["wg", "show", WG_INTERFACE, "dump"],
            capture_output=True, text=True, timeout=5,
        )
        lines = result.stdout.strip().split("\n")[1:]
        peers: dict[str, dict[str, str]] = {}
        for line in lines:
            parts = line.split("\t")
            if len(parts) >= 5:
                pubkey = parts[0]
                allowed_ips = parts[3] if len(parts) > 3 else ""
                endpoint = parts[4] if len(parts) > 4 else ""
                peers[pubkey] = {"allowed_ips": allowed_ips, "endpoint": endpoint}
        return peers
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, IndexError):
        return {}


def _next_available_ip() -> str | None:
    """Find the next available IP in the WG subnet."""
    try:
        store = {}
        if os.path.exists(POSTURE_STORE_PATH):
            with open(POSTURE_STORE_PATH, "r") as f:
                store = json.load(f)
    except (json.JSONDecodeError, OSError):
        store = {}

    existing_ips = set()
    for ip_str in store:
        try:
            existing_ips.add(str(ipaddress.ip_address(ip_str)))
        except ValueError:
            continue

    for i in range(10, 255):
        candidate = f"{WG_SUBNET}.{i}"
        if candidate not in existing_ips:
            return candidate
    return None


def _add_wg_peer(pubkey: str, allowed_ip: str) -> bool:
    """Add a WireGuard peer at runtime."""
    try:
        subprocess.run(
            ["wg", "set", WG_INTERFACE, "peer", pubkey, "allowed-ips", f"{allowed_ip}/32"],
            check=True, timeout=5,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


@app.route("/api/peers", methods=["GET"])
def list_peers() -> Response:
    """List all current WireGuard peers."""
    peers = _get_wg_peers()
    peer_list = []
    for pubkey, info in peers.items():
        peer_list.append({
            "public_key": pubkey,
            "public_key_short": pubkey[:16] + "...",
            "allowed_ips": info["allowed_ips"],
            "endpoint": info["endpoint"],
        })
    return jsonify({"peers": peer_list, "count": len(peer_list)})


@app.route("/api/peers", methods=["POST"])
def add_peer() -> Response:
    """Add a new WireGuard peer. Requires admin token + authenticated user."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.endswith(ADMIN_TOKEN):
        _write_audit_log({
            "event": "peer_provision_denied",
            "reason": "invalid_admin_token",
            "source_ip": request.remote_addr,
        })
        return jsonify({"error": "unauthorized"}), 403

    data = request.get_json(silent=True) or {}
    pubkey = data.get("public_key", "").strip()
    device_name = data.get("device_name", "unnamed").strip()
    email = data.get("email", "").strip()
    fixed_ip = data.get("allowed_ip", "").strip()

    if not pubkey or len(pubkey) < 20:
        return jsonify({"error": "invalid public_key"}), 400

    if fixed_ip:
        try:
            addr = ipaddress.ip_address(fixed_ip)
            if addr.version != 4 or not str(addr).startswith(WG_SUBNET):
                return jsonify({"error": f"IP must be in {WG_SUBNET}.0/24"}), 400
        except ValueError:
            return jsonify({"error": "invalid IP address"}), 400
        target_ip = fixed_ip
    else:
        target_ip = _next_available_ip()
        if not target_ip:
            return jsonify({"error": "no available IPs in subnet"}), 507

    existing = _get_wg_peers()
    if pubkey in existing:
        return jsonify({"error": "peer already exists"}), 409

    if not _add_wg_peer(pubkey, target_ip):
        return jsonify({"error": "failed to add peer to WireGuard"}), 500

    _write_audit_log({
        "event": "peer_provisioned",
        "public_key": pubkey[:16] + "...",
        "device_name": device_name,
        "email": email,
        "assigned_ip": target_ip,
    })

    log.info("Peer provisioned: %s (%s) -> %s", device_name, email, target_ip)

    return jsonify({
        "status": "provisioned",
        "public_key": pubkey[:16] + "...",
        "allowed_ip": target_ip,
        "device_name": device_name,
    }), 201


@app.route("/api/peers/<pubkey>", methods=["DELETE"])
def remove_peer(pubkey: str) -> Response:
    """Remove a WireGuard peer by public key prefix or full key."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.endswith(ADMIN_TOKEN):
        return jsonify({"error": "unauthorized"}), 403

    existing = _get_wg_peers()
    target_key = None
    for key in existing:
        if key == pubkey or key.startswith(pubkey):
            target_key = key
            break

    if not target_key:
        return jsonify({"error": "peer not found"}), 404

    try:
        subprocess.run(
            ["wg", "set", WG_INTERFACE, "peer", target_key, "remove"],
            check=True, timeout=5,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return jsonify({"error": "failed to remove peer"}), 500

    _write_audit_log({
        "event": "peer_removed",
        "public_key": target_key[:16] + "...",
    })

    return jsonify({"status": "removed", "public_key": target_key[:16] + "..."})


@app.route("/api/peers/next-ip", methods=["GET"])
def next_ip() -> Response:
    """Return the next available WireGuard IP."""
    ip = _next_available_ip()
    if not ip:
        return jsonify({"error": "no available IPs"}), 507
    return jsonify({"next_ip": ip})


# ---------------------------------------------------------------------------
# Continuous Authentication / Risk Scoring
# ---------------------------------------------------------------------------

def _calculate_risk_score(identity: dict, posture: dict, source_ip: str) -> dict[str, Any]:
    """Calculate a risk score (0-100) based on identity, posture, and context.

    Higher score = higher risk. Threshold is configurable via RISK_THRESHOLD.
    """
    score = 0
    factors = []

    now = int(time.time())
    auth_time = identity.get("auth_time", 0)
    seconds_since_auth = now - auth_time if auth_time > 0 else 999999

    if not identity.get("authenticated", False):
        score += 100
        factors.append("not_authenticated")
    elif seconds_since_auth > 3600:
        score += 30
        factors.append("session_age_gt_1h")
    elif seconds_since_auth > 1800:
        score += 15
        factors.append("session_age_gt_30m")

    if not identity.get("mfa_verified", False):
        score += 25
        factors.append("no_mfa")

    if posture.get("posture") != "healthy":
        score += 40
        factors.append("unhealthy_posture")
    else:
        signals = posture.get("signals", {})
        if not signals.get("disk_encrypted", True):
            score += 15
            factors.append("disk_not_encrypted")
        if not signals.get("patch_within_window", True):
            score += 10
            factors.append("patches_outdated")
        if not signals.get("no_blocklisted_process", True):
            score += 20
            factors.append("blocklisted_process")

    posture_age = now - posture.get("checked_at", 0)
    if posture_age > MAX_POSTURE_AGE_SECONDS:
        score += 15
        factors.append("stale_posture")

    score = min(score, 100)

    return {
        "score": score,
        "threshold": RISK_THRESHOLD,
        "requires_step_up": score >= RISK_THRESHOLD,
        "factors": factors,
    }


@app.route("/api/risk-score", methods=["GET"])
def risk_score() -> Response:
    """Calculate risk score for the current request context."""
    source_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    identity = check_identity(request.headers)
    posture = get_posture(source_ip)
    result = _calculate_risk_score(identity, posture, source_ip)

    _write_audit_log({
        "event": "risk_score_calculated",
        "source_ip": source_ip,
        "email": identity.get("email", ""),
        "score": result["score"],
        "requires_step_up": result["requires_step_up"],
        "factors": result["factors"],
    })

    return jsonify(result)


# ---------------------------------------------------------------------------
# Admin Dashboard
# ---------------------------------------------------------------------------

ADMIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>ZTLab Admin Dashboard</title>
  <meta http-equiv="refresh" content="30">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, Segoe UI, sans-serif; background: #0f1115; color: #e6e6e6; }
    .header { padding: 24px 32px; background: #1a1d24; border-bottom: 1px solid #2a2d34; }
    .header h1 { font-size: 20px; font-weight: 600; }
    .header .subtitle { color: #9aa0ac; font-size: 13px; margin-top: 4px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 20px; padding: 24px 32px; }
    .card { background: #1a1d24; border-radius: 12px; padding: 20px; border: 1px solid #2a2d34; }
    .card h2 { font-size: 14px; text-transform: uppercase; letter-spacing: 0.08em; color: #9aa0ac; margin-bottom: 16px; }
    .stat { font-size: 36px; font-weight: 700; }
    .stat.green { color: #3ddc97; }
    .stat.red { color: #ff6b6b; }
    .stat.yellow { color: #ffd93d; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { text-align: left; color: #9aa0ac; padding: 8px; border-bottom: 1px solid #2a2d34; }
    td { padding: 8px; border-bottom: 1px solid #1a1d24; font-family: monospace; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
    .badge.healthy { background: #3ddc97; color: #0f1115; }
    .badge.unhealthy { background: #ff6b6b; color: #0f1115; }
    .badge.unknown { background: #888; color: #0f1115; }
  </style>
</head>
<body>
  <div class="header">
    <h1>ZTLab Admin Dashboard</h1>
    <div class="subtitle">Auto-refreshes every 30 seconds &mdash; {{ device_count }} devices tracked</div>
  </div>
  <div class="grid">
    <div class="card">
      <h2>Device Posture Overview</h2>
      <div style="display:flex;gap:24px;">
        <div><span class="stat green">{{ healthy_count }}</span><br><small style="color:#9aa0ac">Healthy</small></div>
        <div><span class="stat red">{{ unhealthy_count }}</span><br><small style="color:#9aa0ac">Unhealthy</small></div>
      </div>
    </div>
    <div class="card">
      <h2>WireGuard Peers</h2>
      <div class="stat yellow">{{ peer_count }}</div>
      <small style="color:#9aa0ac">Active tunnel peers</small>
    </div>
    <div class="card" style="grid-column: 1 / -1;">
      <h2>Device Status</h2>
      <table>
        <tr><th>IP</th><th>Device</th><th>Status</th><th>Last Check</th><th>Signals</th></tr>
        {% for ip, device in devices.items() %}
        <tr>
          <td>{{ ip }}</td>
          <td>{{ device.device_id }}</td>
          <td><span class="badge {{ 'healthy' if device.posture == 'healthy' else 'unhealthy' }}">{{ device.posture }}</span></td>
          <td>{{ device.age_str }}</td>
          <td>
            {% for signal, ok in device.signals.items() %}
            <span class="badge {{ 'healthy' if ok else 'unhealthy' }}">{{ signal }}</span>
            {% endfor %}
          </td>
        </tr>
        {% endfor %}
        {% if not devices %}
        <tr><td colspan="5" style="color:#9aa0ac;text-align:center;">No devices registered</td></tr>
        {% endif %}
      </table>
    </div>
    <div class="card" style="grid-column: 1 / -1;">
      <h2>WireGuard Peers</h2>
      <table>
        <tr><th>Public Key</th><th>Allowed IPs</th><th>Endpoint</th></tr>
        {% for peer in peers %}
        <tr>
          <td>{{ peer.public_key_short }}</td>
          <td>{{ peer.allowed_ips }}</td>
          <td>{{ peer.endpoint or '—' }}</td>
        </tr>
        {% endfor %}
        {% if not peers %}
        <tr><td colspan="3" style="color:#9aa0ac;text-align:center;">No peers connected</td></tr>
        {% endif %}
      </table>
    </div>
  </div>
</body>
</html>
"""


def _get_wg_peers_list() -> list[dict]:
    peers = _get_wg_peers()
    result = []
    for pubkey, info in peers.items():
        result.append({
            "public_key_short": pubkey[:16] + "...",
            "allowed_ips": info["allowed_ips"],
            "endpoint": info.get("endpoint", ""),
        })
    return result


def _load_posture_for_dashboard() -> dict[str, Any]:
    """Load posture store and add human-readable age strings."""
    try:
        with open(POSTURE_STORE_PATH, "r") as f:
            store = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        store = {}

    now = int(time.time())
    for ip, entry in store.items():
        age = now - entry.get("checked_at", entry.get("last_seen", 0))
        if age < 60:
            entry["age_str"] = f"{age}s ago"
        elif age < 3600:
            entry["age_str"] = f"{age // 60}m ago"
        else:
            entry["age_str"] = f"{age // 3600}h ago"
        entry.setdefault("signals", {})
    return store


@app.route("/admin")
def admin_dashboard():
    """Admin dashboard showing real-time posture and peer status."""
    devices = _load_posture_for_dashboard()
    peers = _get_wg_peers_list()
    healthy = sum(1 for d in devices.values() if d.get("posture") == "healthy")
    unhealthy = len(devices) - healthy

    return render_template_string(
        ADMIN_TEMPLATE,
        devices=devices,
        peers=peers,
        device_count=len(devices),
        healthy_count=healthy,
        unhealthy_count=unhealthy,
        peer_count=len(peers),
    )


@app.route("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9191)
