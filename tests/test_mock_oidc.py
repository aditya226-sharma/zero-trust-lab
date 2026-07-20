import base64
import json

import pytest


@pytest.fixture
def mock_oidc_client():
    from importlib.util import module_from_spec, spec_from_file_location
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    spec = spec_from_file_location(
        "mock_oidc", root / "gateway/mock-oidc/app.py"
    )
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    module.app.config["TESTING"] = True
    return module.app.test_client(), module


class TestOpenIDConfiguration:
    def test_returns_valid_config(self, mock_oidc_client):
        client, _ = mock_oidc_client
        resp = client.get("/.well-known/openid-configuration")

        assert resp.status_code == 200
        data = resp.get_json()
        assert "issuer" in data
        assert "authorization_endpoint" in data
        assert "token_endpoint" in data
        assert "jwks_uri" in data

    def test_issuer_is_correct(self, mock_oidc_client):
        client, _ = mock_oidc_client
        data = client.get("/.well-known/openid-configuration").get_json()

        assert data["issuer"] == "http://mock-oidc:9000"


class TestJWKS:
    def test_returns_keys(self, mock_oidc_client):
        client, _ = mock_oidc_client
        resp = client.get("/.well-known/jwks.json")

        assert resp.status_code == 200
        data = resp.get_json()
        assert "keys" in data
        assert len(data["keys"]) == 1
        assert data["keys"][0]["kty"] == "oct"


class TestTokenEndpoint:
    def test_authorization_code_grant(self, mock_oidc_client):
        client, _ = mock_oidc_client
        resp = client.post("/oauth/token", data={
            "grant_type": "authorization_code",
            "code": "test-code",
        })

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["token_type"] == "Bearer"
        assert data["expires_in"] == 3600
        assert "access_token" in data
        assert "id_token" in data

    def test_unsupported_grant_type(self, mock_oidc_client):
        client, _ = mock_oidc_client
        resp = client.post("/oauth/token", data={
            "grant_type": "password",
        })

        assert resp.status_code == 400
        assert resp.get_json()["error"] == "unsupported_grant_type"

    def test_tokens_are_valid_jwt_format(self, mock_oidc_client):
        client, _ = mock_oidc_client
        data = client.post("/oauth/token", data={
            "grant_type": "authorization_code",
        }).get_json()

        for token_key in ("access_token", "id_token"):
            parts = data[token_key].split(".")
            assert len(parts) == 3, f"{token_key} should have 3 JWT parts"

            # Decode the payload (middle part)
            payload_b64 = parts[1]
            padded = payload_b64 + "=" * ((4 - len(payload_b64) % 4) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded))
            assert payload["iss"] == "http://mock-oidc:9000"
            assert payload["aud"] == "ztlab-client"


class TestUserInfo:
    def test_valid_token_returns_userinfo(self, mock_oidc_client):
        client, _ = mock_oidc_client
        token_data = client.post("/oauth/token", data={
            "grant_type": "authorization_code",
        }).get_json()

        resp = client.get("/userinfo", headers={
            "Authorization": f"Bearer {token_data['access_token']}",
        })

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["email"] == "alice@zerotrust.lab"
        assert data["preferred_username"] == "alice"

    def test_missing_token_returns_401(self, mock_oidc_client):
        client, _ = mock_oidc_client
        resp = client.get("/userinfo")

        assert resp.status_code == 401
        assert resp.get_json()["error"] == "invalid_token"

    def test_non_bearer_token_returns_401(self, mock_oidc_client):
        client, _ = mock_oidc_client
        resp = client.get("/userinfo", headers={
            "Authorization": "Basic abc123",
        })

        assert resp.status_code == 401
