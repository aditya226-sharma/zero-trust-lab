import json
import time
from unittest.mock import patch, MagicMock

import pytest


class TestRiskScore:
    @pytest.fixture
    def client(self, authz_bridge_module):
        authz_bridge_module.app.config["TESTING"] = True
        return authz_bridge_module.app.test_client()

    def _mock_oauth2(
        self, email="alice@test.com", amr=None, auth_time=0,
    ):
        import base64
        if amr is None:
            amr = ["webauthn"]
        payload = base64.urlsafe_b64encode(
            json.dumps({
                "email": email,
                "auth_time": auth_time,
                "amr": amr,
            }).encode()
        ).decode().rstrip("=")
        fake_resp = MagicMock()
        fake_resp.status_code = 202
        fake_resp.headers = {
            "Authorization": f"Bearer hdr.{payload}.sig",
        }
        return fake_resp

    def _setup_posture(
        self, authz_bridge_module, tmp_path, ip,
        posture="healthy", signals=None,
    ):
        store = tmp_path / "posture.json"
        entry = {"posture": posture}
        if signals:
            entry["signals"] = signals
            entry["checked_at"] = int(time.time())
        store.write_text(json.dumps({ip: entry}))
        authz_bridge_module.POSTURE_STORE_PATH = str(store)

    def test_risk_score_low_for_healthy_session(
        self, client, authz_bridge_module, tmp_path,
    ):
        healthy_signals = {
            "disk_encrypted": True,
            "patch_within_window": True,
            "no_blocklisted_process": True,
        }
        self._setup_posture(
            authz_bridge_module, tmp_path,
            "127.0.0.1", "healthy", healthy_signals,
        )
        oauth_resp = self._mock_oauth2(auth_time=1700000000)

        with patch("requests.get", return_value=oauth_resp):
            resp = client.get("/api/risk-score", headers={
                "X-Forwarded-For": "127.0.0.1",
                "Cookie": "session=abc",
            })

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["score"] < 70
        assert data["requires_step_up"] is False

    def test_risk_score_high_for_unhealthy_posture(
        self, client, authz_bridge_module, tmp_path,
    ):
        self._setup_posture(
            authz_bridge_module, tmp_path,
            "127.0.0.1", "unhealthy",
        )
        oauth_resp = self._mock_oauth2(auth_time=1700000000)

        with patch("requests.get", return_value=oauth_resp):
            resp = client.get("/api/risk-score", headers={
                "X-Forwarded-For": "127.0.0.1",
                "Cookie": "session=abc",
            })

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["score"] >= 40
        assert "unhealthy_posture" in data["factors"]

    def test_risk_score_high_for_no_mfa(
        self, client, authz_bridge_module, tmp_path,
    ):
        self._setup_posture(
            authz_bridge_module, tmp_path,
            "127.0.0.1", "healthy",
        )
        oauth_resp = self._mock_oauth2(
            amr=["pwd"], auth_time=1700000000,
        )

        with patch("requests.get", return_value=oauth_resp):
            resp = client.get("/api/risk-score", headers={
                "X-Forwarded-For": "127.0.0.1",
                "Cookie": "session=abc",
            })

        assert resp.status_code == 200
        data = resp.get_json()
        assert "no_mfa" in data["factors"]
        assert data["score"] >= 25

    def test_risk_score_unauthenticated_is_max(
        self, client, authz_bridge_module, tmp_path,
    ):
        self._setup_posture(
            authz_bridge_module, tmp_path,
            "127.0.0.1", "healthy",
        )
        fake_resp = MagicMock()
        fake_resp.status_code = 401

        with patch("requests.get", return_value=fake_resp):
            resp = client.get("/api/risk-score", headers={
                "X-Forwarded-For": "127.0.0.1",
                "Cookie": "bad=cookie",
            })

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["score"] == 100
        assert data["requires_step_up"] is True

    def test_risk_score_includes_all_factors(
        self, client, authz_bridge_module, tmp_path,
    ):
        bad_signals = {
            "disk_encrypted": False,
            "patch_within_window": False,
            "no_blocklisted_process": False,
        }
        self._setup_posture(
            authz_bridge_module, tmp_path,
            "127.0.0.1", "healthy", bad_signals,
        )
        oauth_resp = self._mock_oauth2(
            amr=["pwd"], auth_time=1700000000,
        )

        with patch("requests.get", return_value=oauth_resp):
            resp = client.get("/api/risk-score", headers={
                "X-Forwarded-For": "127.0.0.1",
                "Cookie": "session=abc",
            })

        assert resp.status_code == 200
        data = resp.get_json()
        assert "no_mfa" in data["factors"]
        assert "disk_not_encrypted" in data["factors"]
        assert "patches_outdated" in data["factors"]
        assert "blocklisted_process" in data["factors"]
        assert data["score"] >= 70
