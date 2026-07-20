import json
import base64
import time
import uuid
from flask import Flask, jsonify, request

app = Flask(__name__)

ISSUER = "http://mock-oidc:9000"
CLIENT_ID = "ztlab-client"
CLIENT_SECRET = "ztlab-secret"

JWK = {
    "kty": "oct",
    "alg": "HS256",
    "k": base64.urlsafe_b64encode(b"zerotrustlab-mock-secret-key-32!").decode(),
}

CONFIG = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/oauth/authorize",
    "token_endpoint": f"{ISSUER}/oauth/token",
    "userinfo_endpoint": f"{ISSUER}/userinfo",
    "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
    "response_types_supported": ["code", "id_token"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["HS256"],
}

USERINFO = {
    "sub": "user-ztlab-001",
    "name": "Alice Zero-Trust",
    "preferred_username": "alice",
    "email": "alice@zerotrust.lab",
    "groups": ["engineers", "admins"],
}


def b64_encode(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def make_jwt(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    body = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "jti": str(uuid.uuid4()),
        **payload,
    }
    return f"{b64_encode(header)}.{b64_encode(body)}.{b64_encode({'sig': 'mock'})}"


@app.route("/.well-known/openid-configuration")
def openid_config():
    return jsonify(CONFIG)


@app.route("/.well-known/jwks.json")
def jwks():
    return jsonify({"keys": [JWK]})


@app.route("/oauth/token", methods=["POST"])
def token():
    grant_type = request.form.get("grant_type", "authorization_code")
    if grant_type != "authorization_code":
        return jsonify({"error": "unsupported_grant_type"}), 400

    access_token = make_jwt({"sub": USERINFO["sub"], "scope": "openid profile email"})
    id_token = make_jwt(
        {
            "sub": USERINFO["sub"],
            "name": USERINFO["name"],
            "preferred_username": USERINFO["preferred_username"],
            "email": USERINFO["email"],
        }
    )

    return jsonify(
        {
            "access_token": access_token,
            "id_token": id_token,
            "token_type": "Bearer",
            "expires_in": 3600,
        }
    )


@app.route("/userinfo")
def userinfo():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "invalid_token"}), 401
    return jsonify(USERINFO)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
