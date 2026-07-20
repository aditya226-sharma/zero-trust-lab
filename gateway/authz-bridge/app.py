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

Run with: gunicorn -w 2 -b 0.0.0.0:9191 app:app
"""

import base64
import json
import logging
import os
import time

import requests
from flask import Flask, request, Response

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("authz-bridge")

OAUTH2_PROXY_AUTH_URL = os.environ.get(
    "OAUTH2_PROXY_AUTH_URL", "http://oauth2-proxy:4180/oauth2/auth"
)
OPA_URL = os.environ.get("OPA_URL", "http://opa:8181/v1/data/ztlab/authz")
# Lab-simplicity posture store: a JSON file the Phase 2 posture agent writes
# to, keyed by source IP. In a real deployment this would be a proper store
# (Redis, a database) keyed by a real device identity, not a spoofable IP —
# flagged here deliberately as a lab shortcut, see Phase 7 test #3.
POSTURE_STORE_PATH = os.environ.get("POSTURE_STORE_PATH", "/data/posture.json")


def get_posture(source_ip: str) -> dict:
    try:
        with open(POSTURE_STORE_PATH, "r") as f:
            store = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        log.warning("posture store missing or unreadable — failing closed")
        return {"posture": "unhealthy", "reason": "no posture data"}
    entry = store.get(source_ip)
    if not entry:
        # No posture data for this device at all => fail closed, not open.
        return {"posture": "unhealthy", "reason": "no posture record for source"}
    return entry


def _decode_id_token(header_value: str) -> dict:
    """Base64-decode the JWT payload from an Authorization: Bearer header.

    oauth2-proxy already verified the JWT signature before passing it
    through — we only decode the payload to extract claims. This avoids
    depending on oauth2-proxy version-specific header injection behaviour.
    """
    if not header_value.startswith("Bearer "):
        return {}
    token = header_value[len("Bearer ") :]
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    try:
        payload = parts[1]
        padded = payload + "=" * (4 - len(payload) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        return json.loads(decoded)
    except (ValueError, json.JSONDecodeError):
        log.warning("failed to decode id_token payload")
        return {}


def check_identity(incoming_headers) -> dict:
    """
    Calls oauth2-proxy's own auth-check endpoint, forwarding the session
    cookie, to find out who the user is and whether they're authenticated.
    oauth2-proxy returns 202 + Authorization: Bearer <id_token> on success,
    401 otherwise.

    auth_time and amr (authentication methods reference) are extracted
    from the ID token payload rather than from arbitrary headers — this is
    version-independent and reliable.
    """
    cookie = incoming_headers.get("Cookie", "")
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

    id_token = _decode_id_token(r.headers.get("Authorization", ""))
    email = id_token.get("email", r.headers.get("X-Auth-Request-Email", ""))
    auth_time = id_token.get("auth_time", 0)
    amr = id_token.get("amr", [])

    log.info("id_token claims: email=%s auth_time=%s amr=%s", email, auth_time, amr)

    return {
        "authenticated": True,
        "email": email,
        "mfa_verified": "webauthn" in amr or "mfa" in str(amr).lower(),
        "auth_time": int(auth_time or 0),
    }


@app.route("/validate", methods=["GET"])
def validate():
    original_uri = request.headers.get("X-Original-URI", "/")
    source_ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    identity = check_identity(request.headers)
    posture = get_posture(source_ip)

    opa_input = {
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

    try:
        opa_resp = requests.post(f"{OPA_URL}/allow", json=opa_input, timeout=3)
        opa_reason_resp = requests.post(f"{OPA_URL}/reason", json=opa_input, timeout=3)
        allowed = opa_resp.json().get("result", False)
        reason = opa_reason_resp.json().get("result", "unknown")
    except requests.RequestException as e:
        # OPA unreachable => fail closed. This line is the single most
        # important line in this file — do not change it to default-allow.
        log.error("OPA unreachable, failing closed: %s", e)
        allowed = False
        reason = "denied: policy engine unreachable"

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
        # 401 triggers nginx to redirect to oauth2-proxy login
        return Response(
            status=401,
            headers={"X-ZTLab-Reason": reason, "Location": "/oauth2/sign_in"},
        )
    return Response(status=403, headers={"X-ZTLab-Reason": reason})


@app.route("/healthz")
def healthz():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9191)
