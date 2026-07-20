"""
Demo app — this is the actual "protected resource" in the architecture
diagram. It has NO auth logic of its own; every request reaching it has
already passed nginx's auth_request -> authz-bridge -> OPA check. That's
deliberate: the app trusts the enforcement layer completely and stays
dumb, which is the point of putting the PEP in front of it rather than
inside it.

NEW: Data classification layer — every response includes an X-Data-Classification
header that labels the sensitivity of the data being returned. This addresses
the Data pillar (CISA ZTMM v2.0) by adding attribute-based data labeling
even though the PEP handles access decisions.
"""
import logging
import time

from flask import Flask, request, jsonify

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("demo-app")

DATA_CLASSIFICATIONS = {
    "/public": {
        "classification": "PUBLIC",
        "retention_days": 90,
        "encryption_required": False,
        "label": "General information, no sensitivity restrictions",
    },
    "/sensitive": {
        "classification": "CONFIDENTIAL",
        "retention_days": 30,
        "encryption_required": True,
        "label": "Requires fresh MFA, subject to strict retention",
    },
    "/api/data": {
        "classification": "INTERNAL",
        "retention_days": 180,
        "encryption_required": True,
        "label": "Internal API data, not for external distribution",
    },
    "/admin": {
        "classification": "RESTRICTED",
        "retention_days": 365,
        "encryption_required": True,
        "label": "Administrative data, highest sensitivity",
    },
}

DATA_OBJECTS = {
    "public-announcement": {
        "id": "public-announcement",
        "classification": "PUBLIC",
        "owner": "communications@zerotrust.lab",
        "content": "Q3 all-hands meeting scheduled for Friday.",
    },
    "employee-records": {
        "id": "employee-records",
        "classification": "CONFIDENTIAL",
        "owner": "hr@zerotrust.lab",
        "content": "Employee PII — access logged and audited.",
    },
    "api-config": {
        "id": "api-config",
        "classification": "INTERNAL",
        "owner": "platform@zerotrust.lab",
        "content": "Service mesh configuration parameters.",
    },
    "encryption-keys": {
        "id": "encryption-keys",
        "classification": "RESTRICTED",
        "owner": "security@zerotrust.lab",
        "content": "Root CA private keys — never expose via API.",
    },
}

PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>ZTLab demo — {zone_label}</title>
  <style>
    body {{
      font-family: -apple-system, Segoe UI, sans-serif;
      margin: 0;
      padding: 0;
      background: #0f1115;
      color: #e6e6e6;
    }}
    .banner {{
      padding: 28px 32px;
      font-size: 22px;
      font-weight: 700;
      letter-spacing: 0.04em;
      color: #0f1115;
      background: {banner_color};
    }}
    .content {{
      padding: 32px;
      line-height: 1.6;
    }}
    .meta {{
      margin-top: 24px;
      padding: 16px;
      background: #1a1d24;
      border-radius: 8px;
      font-family: monospace;
      font-size: 13px;
      color: #9aa0ac;
    }}
    .classification-badge {{
      display: inline-block;
      padding: 4px 12px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.05em;
      color: #0f1115;
      background: {classification_color};
      margin-top: 8px;
    }}
  </style>
</head>
<body>
  <div class="banner">{zone_label}</div>
  <div class="content">
    <p>{body_text}</p>
    <div class="classification-badge">{classification} DATA</div>
    <div class="meta">
      request path: {path}<br>
      data classification: {classification}<br>
      encryption required: {encryption_required}<br>
      retention: {retention_days} days<br>
      served by: demo-app (no local auth logic — enforced upstream)
    </div>
  </div>
</body>
</html>
"""


def _get_classification_for_path(path: str) -> dict:
    """Determine data classification based on request path."""
    for prefix, meta in sorted(
        DATA_CLASSIFICATIONS.items(), key=lambda x: -len(x[0])
    ):
        if path.startswith(prefix):
            return meta
    return {
        "classification": "UNCLASSIFIED",
        "retention_days": 0,
        "encryption_required": False,
        "label": "No classification defined",
    }


def _classification_color(classification: str) -> str:
    return {
        "PUBLIC": "#3ddc97",
        "INTERNAL": "#ffd93d",
        "CONFIDENTIAL": "#ff6b6b",
        "RESTRICTED": "#ff3333",
        "UNCLASSIFIED": "#888888",
    }.get(classification, "#888888")


@app.before_request
def _start_timer():
    request._start_time = time.monotonic()


@app.after_request
def _log_request(response):
    elapsed_ms = (time.monotonic() - getattr(request, "_start_time", 0)) * 1000
    identity = request.headers.get("X-Auth-Request-Email", "-")
    reason = request.headers.get("X-ZTLab-Reason", "-")
    classification = _get_classification_for_path(request.path)

    response.headers["X-Data-Classification"] = classification["classification"]
    response.headers["X-Data-Encryption-Required"] = str(
        classification["encryption_required"]
    ).lower()
    response.headers["X-Data-Retention-Days"] = str(classification["retention_days"])

    log.info(
        "%s %s %s identity=%s reason=%s classification=%s %.1fms",
        request.method,
        request.path,
        response.status_code,
        identity,
        reason,
        classification["classification"],
        elapsed_ms,
    )
    return response


@app.route("/public")
def public():
    """Public zone — accessible with any valid session + healthy posture."""
    meta = _get_classification_for_path("/public")
    return PAGE_TEMPLATE.format(
        zone_label="PUBLIC ZONE",
        banner_color="#3ddc97",
        body_text="Any valid authenticated session with healthy device "
                   "posture reaches this page. No re-authentication "
                   "freshness requirement applies here.",
        path=request.path,
        classification=meta["classification"],
        classification_color=_classification_color(meta["classification"]),
        encryption_required=meta["encryption_required"],
        retention_days=meta["retention_days"],
    )


@app.route("/sensitive")
def sensitive():
    """Sensitive zone — requires fresh WebAuthn re-auth within 5 minutes."""
    meta = _get_classification_for_path("/sensitive")
    return PAGE_TEMPLATE.format(
        zone_label="SENSITIVE ZONE — RE-AUTH REQUIRED",
        banner_color="#ff6b6b",
        body_text="Reaching this page requires a WebAuthn re-authentication "
                   "within the last 5 minutes, checked against your actual "
                   "last-auth timestamp — not just session-start time.",
        path=request.path,
        classification=meta["classification"],
        classification_color=_classification_color(meta["classification"]),
        encryption_required=meta["encryption_required"],
        retention_days=meta["retention_days"],
    )


@app.route("/api/data")
def api_data():
    """API endpoint returning classified data objects with labels."""
    classification = _get_classification_for_path("/api/data")
    return jsonify({
        "classification": classification["classification"],
        "encryption_required": classification["encryption_required"],
        "retention_days": classification["retention_days"],
        "objects": DATA_OBJECTS,
    })


@app.route("/api/data/<object_id>")
def api_data_object(object_id):
    """Return a single data object with its classification metadata."""
    obj = DATA_OBJECTS.get(object_id)
    if not obj:
        return jsonify({"error": "object not found"}), 404
    classification = _get_classification_for_path("/api/data")
    return jsonify({
        "id": obj["id"],
        "classification": obj["classification"],
        "owner": obj["owner"],
        "content": obj["content"],
        "parent_classification": classification["classification"],
    })


@app.route("/healthz")
def healthz():
    """Liveness probe — returns 200 when the process is up."""
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
