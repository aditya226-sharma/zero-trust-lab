"""
Demo app — this is the actual "protected resource" in the architecture
diagram. It has NO auth logic of its own; every request reaching it has
already passed nginx's auth_request -> authz-bridge -> OPA check. That's
deliberate: the app trusts the enforcement layer completely and stays
dumb, which is the point of putting the PEP in front of it rather than
inside it.
"""
from flask import Flask, request

app = Flask(__name__)

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
  </style>
</head>
<body>
  <div class="banner">{zone_label}</div>
  <div class="content">
    <p>{body_text}</p>
    <div class="meta">
      request path: {path}<br>
      served by: demo-app (no local auth logic — enforced upstream)
    </div>
  </div>
</body>
</html>
"""


@app.route("/public")
def public():
    return PAGE_TEMPLATE.format(
        zone_label="PUBLIC ZONE",
        banner_color="#3ddc97",
        body_text="Any valid authenticated session with healthy device "
                   "posture reaches this page. No re-authentication "
                   "freshness requirement applies here.",
        path=request.path,
    )


@app.route("/sensitive")
def sensitive():
    return PAGE_TEMPLATE.format(
        zone_label="SENSITIVE ZONE — RE-AUTH REQUIRED",
        banner_color="#ff6b6b",
        body_text="Reaching this page requires a WebAuthn re-authentication "
                   "within the last 5 minutes, checked against your actual "
                   "last-auth timestamp — not just session-start time.",
        path=request.path,
    )


@app.route("/healthz")
def healthz():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
