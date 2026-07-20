import base64
import json
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# _decode_id_token tests
# ---------------------------------------------------------------------------

class TestDecodeIdToken:
    def test_valid_token_returns_claims(self, authz_bridge_module):
        payload = base64.urlsafe_b64encode(
            json.dumps({"email": "alice@test.com", "amr": ["webauthn"]}).encode()
        ).decode().rstrip("=")

        result = authz_bridge_module._decode_id_token(f"Bearer hdr.{payload}.sig")

        assert result["email"] == "alice@test.com"
        assert result["amr"] == ["webauthn"]

    def test_non_bearer_header_returns_empty(self, authz_bridge_module):
        assert authz_bridge_module._decode_id_token("Basic abc123") == {}

    def test_empty_string_returns_empty(self, authz_bridge_module):
        assert authz_bridge_module._decode_id_token("") == {}

    def test_malformed_jwt_returns_empty(self, authz_bridge_module):
        assert authz_bridge_module._decode_id_token("Bearer not-a-jwt") == {}

    def test_two_part_token_returns_empty(self, authz_bridge_module):
        assert authz_bridge_module._decode_id_token("Bearer header.payload") == {}

    def test_invalid_base64_returns_empty(self, authz_bridge_module):
        assert authz_bridge_module._decode_id_token("Bearer hdr.!!!invalid!!!.sig") == {}

    def test_empty_payload_returns_empty_dict(self, authz_bridge_module):
        payload = base64.urlsafe_b64encode(b"").decode().rstrip("=")
        result = authz_bridge_module._decode_id_token(f"Bearer .{payload}.sig")
        assert result == {}

    def test_jwt_with_auth_time(self, authz_bridge_module):
        payload = base64.urlsafe_b64encode(
            json.dumps({"email": "a@b.c", "auth_time": 1700000000}).encode()
        ).decode().rstrip("=")

        result = authz_bridge_module._decode_id_token(f"Bearer h.{payload}.s")

        assert result["auth_time"] == 1700000000


# ---------------------------------------------------------------------------
# get_posture tests
# ---------------------------------------------------------------------------

class TestGetPosture:
    def test_returns_healthy_when_present(self, authz_bridge_module, tmp_path):
        store = tmp_path / "posture.json"
        store.write_text(json.dumps({
            "10.10.1.50": {"posture": "healthy", "device_id": "laptop-1"}
        }))
        authz_bridge_module.POSTURE_STORE_PATH = str(store)

        result = authz_bridge_module.get_posture("10.10.1.50")

        assert result["posture"] == "healthy"
        assert result["device_id"] == "laptop-1"

    def test_returns_unhealthy_for_unknown_ip(self, authz_bridge_module, tmp_path):
        store = tmp_path / "posture.json"
        store.write_text(json.dumps({
            "10.10.1.50": {"posture": "healthy"}
        }))
        authz_bridge_module.POSTURE_STORE_PATH = str(store)

        result = authz_bridge_module.get_posture("10.10.1.99")

        assert result["posture"] == "unhealthy"
        assert "no posture record" in result["reason"]

    def test_returns_unhealthy_when_store_missing(self, authz_bridge_module, tmp_path):
        authz_bridge_module.POSTURE_STORE_PATH = str(tmp_path / "nonexistent.json")

        result = authz_bridge_module.get_posture("10.10.1.50")

        assert result["posture"] == "unhealthy"
        assert result["reason"] == "no posture data"

    def test_returns_unhealthy_on_malformed_json(self, authz_bridge_module, tmp_path):
        store = tmp_path / "posture.json"
        store.write_text("NOT JSON{{{")
        authz_bridge_module.POSTURE_STORE_PATH = str(store)

        result = authz_bridge_module.get_posture("10.10.1.50")

        assert result["posture"] == "unhealthy"

    def test_returns_unhealthy_when_store_empty(self, authz_bridge_module, tmp_path):
        store = tmp_path / "posture.json"
        store.write_text("{}")
        authz_bridge_module.POSTURE_STORE_PATH = str(store)

        result = authz_bridge_module.get_posture("10.10.1.50")

        assert result["posture"] == "unhealthy"


# ---------------------------------------------------------------------------
# check_identity tests (mocked oauth2-proxy)
# ---------------------------------------------------------------------------

class TestCheckIdentity:
    def test_authenticated_with_mfa(self, authz_bridge_module):
        payload = base64.urlsafe_b64encode(
            json.dumps({
                "email": "alice@test.com",
                "auth_time": 1700000000,
                "amr": ["webauthn", "pwd"],
            }).encode()
        ).decode().rstrip("=")
        fake_response = MagicMock()
        fake_response.status_code = 202
        fake_response.headers = {"Authorization": f"Bearer hdr.{payload}.sig"}

        with patch("requests.get", return_value=fake_response):
            result = authz_bridge_module.check_identity({"Cookie": "session=abc"})

        assert result["authenticated"] is True
        assert result["email"] == "alice@test.com"
        assert result["mfa_verified"] is True
        assert result["auth_time"] == 1700000000

    def test_not_authenticated_returns_401(self, authz_bridge_module):
        fake_response = MagicMock()
        fake_response.status_code = 401

        with patch("requests.get", return_value=fake_response):
            result = authz_bridge_module.check_identity({"Cookie": "bad=cookie"})

        assert result["authenticated"] is False

    def test_oauth2_proxy_unreachable_fails_closed(self, authz_bridge_module):
        import requests as req_lib

        with patch("requests.get", side_effect=req_lib.ConnectionError("refused")):
            result = authz_bridge_module.check_identity({"Cookie": "x=1"})

        assert result["authenticated"] is False

    def test_mfa_false_when_no_webauthn_in_amr(self, authz_bridge_module):
        payload = base64.urlsafe_b64encode(
            json.dumps({
                "email": "bob@test.com",
                "auth_time": 1700000000,
                "amr": ["pwd"],
            }).encode()
        ).decode().rstrip("=")
        fake_response = MagicMock()
        fake_response.status_code = 202
        fake_response.headers = {"Authorization": f"Bearer hdr.{payload}.sig"}

        with patch("requests.get", return_value=fake_response):
            result = authz_bridge_module.check_identity({"Cookie": "s=1"})

        assert result["mfa_verified"] is False


# ---------------------------------------------------------------------------
# /validate endpoint tests (integration with mocked OPA + oauth2-proxy)
# ---------------------------------------------------------------------------

class TestValidateEndpoint:
    @pytest.fixture
    def client(self, authz_bridge_module):
        authz_bridge_module.app.config["TESTING"] = True
        return authz_bridge_module.app.test_client()

    def _setup_posture(self, authz_bridge_module, tmp_path, ip, posture="healthy"):
        store = tmp_path / "posture.json"
        store.write_text(json.dumps({ip: {"posture": posture}}))
        authz_bridge_module.POSTURE_STORE_PATH = str(store)

    def _mock_oauth2_proxy(self, email="alice@test.com", amr=None):
        if amr is None:
            amr = ["webauthn"]
        payload = base64.urlsafe_b64encode(
            json.dumps({"email": email, "auth_time": 1700000000, "amr": amr}).encode()
        ).decode().rstrip("=")
        fake_resp = MagicMock()
        fake_resp.status_code = 202
        fake_resp.headers = {"Authorization": f"Bearer hdr.{payload}.sig"}
        return fake_resp

    def test_allow_public_healthy(self, client, authz_bridge_module, tmp_path):
        self._setup_posture(authz_bridge_module, tmp_path, "127.0.0.1")
        oauth_resp = self._mock_oauth2_proxy()
        opa_allow = MagicMock(json=lambda: {"result": True})
        opa_reason = MagicMock(json=lambda: {"result": "allowed"})

        with patch("requests.get", return_value=oauth_resp), \
             patch("requests.post", side_effect=[opa_allow, opa_reason]):
            resp = client.get("/validate", headers={
                "X-Original-URI": "/public",
                "X-Forwarded-For": "127.0.0.1",
                "Cookie": "session=abc",
            })

        assert resp.status_code == 200

    def test_deny_unhealthy_posture(self, client, authz_bridge_module, tmp_path):
        self._setup_posture(authz_bridge_module, tmp_path, "127.0.0.1", "unhealthy")
        oauth_resp = self._mock_oauth2_proxy()
        opa_allow = MagicMock(json=lambda: {"result": False})
        opa_reason = MagicMock(json=lambda: {"result": "denied: device posture unhealthy"})

        with patch("requests.get", return_value=oauth_resp), \
             patch("requests.post", side_effect=[opa_allow, opa_reason]):
            resp = client.get("/validate", headers={
                "X-Original-URI": "/public",
                "X-Forwarded-For": "127.0.0.1",
                "Cookie": "session=abc",
            })

        assert resp.status_code == 403
        assert b"posture unhealthy" in resp.headers.get("X-ZTLab-Reason", b"").encode()

    def test_deny_not_authenticated(self, client, authz_bridge_module, tmp_path):
        self._setup_posture(authz_bridge_module, tmp_path, "127.0.0.1")
        fake_resp = MagicMock()
        fake_resp.status_code = 401
        opa_allow = MagicMock(json=lambda: {"result": False})
        opa_reason = MagicMock(json=lambda: {"result": "denied: user not authenticated"})

        with patch("requests.get", return_value=fake_resp), \
             patch("requests.post", side_effect=[opa_allow, opa_reason]):
            resp = client.get("/validate", headers={
                "X-Original-URI": "/public",
                "X-Forwarded-For": "127.0.0.1",
                "Cookie": "bad=cookie",
            })

        assert resp.status_code == 401
        assert resp.headers.get("Location") == "/oauth2/sign_in"

    def test_opa_unreachable_fails_closed(self, client, authz_bridge_module, tmp_path):
        self._setup_posture(authz_bridge_module, tmp_path, "127.0.0.1")
        oauth_resp = self._mock_oauth2_proxy()

        import requests as req_lib

        with patch("requests.get", return_value=oauth_resp), \
             patch("requests.post", side_effect=req_lib.ConnectionError("refused")):
            resp = client.get("/validate", headers={
                "X-Original-URI": "/public",
                "X-Forwarded-For": "127.0.0.1",
                "Cookie": "session=abc",
            })

        assert resp.status_code == 403

    def test_healthz(self, client):
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.get_json() == {"status": "ok"}
