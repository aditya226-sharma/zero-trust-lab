import json
from unittest.mock import patch, MagicMock

import pytest


class TestAdminDashboard:
    @pytest.fixture
    def client(self, authz_bridge_module):
        authz_bridge_module.app.config["TESTING"] = True
        return authz_bridge_module.app.test_client()

    def _mock_signals(self, disk=True, patch_ok=True, process=True):
        return {
            "disk_encrypted": disk,
            "patch_within_window": patch_ok,
            "no_blocklisted_process": process,
        }

    def test_admin_dashboard_renders(self, client, authz_bridge_module, tmp_path):
        store = tmp_path / "posture.json"
        store.write_text(json.dumps({
            "10.10.1.50": {
                "posture": "healthy",
                "device_id": "laptop-alice",
                "checked_at": 1784569000,
                "signals": self._mock_signals(),
            }
        }))
        authz_bridge_module.POSTURE_STORE_PATH = str(store)

        with patch.object(authz_bridge_module, "_get_wg_peers", return_value={}):
            resp = client.get("/admin")

        assert resp.status_code == 200
        assert b"ZTLab Admin Dashboard" in resp.data
        assert b"laptop-alice" in resp.data
        assert b"healthy" in resp.data

    def test_admin_dashboard_shows_unhealthy_devices(self, client, authz_bridge_module, tmp_path):
        store = tmp_path / "posture.json"
        store.write_text(json.dumps({
            "10.10.1.50": {
                "posture": "unhealthy",
                "device_id": "laptop-bob",
                "checked_at": 1784569000,
                "signals": self._mock_signals(disk=False),
            }
        }))
        authz_bridge_module.POSTURE_STORE_PATH = str(store)

        with patch.object(authz_bridge_module, "_get_wg_peers", return_value={}):
            resp = client.get("/admin")

        assert resp.status_code == 200
        assert b"laptop-bob" in resp.data
        assert b"unhealthy" in resp.data

    def test_admin_dashboard_empty_store(self, client, authz_bridge_module, tmp_path):
        authz_bridge_module.POSTURE_STORE_PATH = str(tmp_path / "nonexistent.json")

        with patch.object(authz_bridge_module, "_get_wg_peers", return_value={}):
            resp = client.get("/admin")

        assert resp.status_code == 200
        assert b"No devices registered" in resp.data

    def test_healthz(self, client):
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.get_json() == {"status": "ok"}


class TestPeerProvisioningAPI:
    @pytest.fixture
    def client(self, authz_bridge_module):
        authz_bridge_module.app.config["TESTING"] = True
        return authz_bridge_module.app.test_client()

    def _auth_headers(self, token="ztlab-admin-token"):
        return {"Authorization": f"Bearer {token}"}

    def test_list_peers_empty(self, client, authz_bridge_module):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="pvtkey\t1\t0.0.0.0/0\t\n",
                returncode=0,
            )
            resp = client.get("/api/peers")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 0

    def test_add_peer_requires_admin_token(self, client, authz_bridge_module, tmp_path):
        authz_bridge_module.POSTURE_STORE_PATH = str(tmp_path / "posture.json")
        authz_bridge_module.PEERS_CONF_PATH = str(tmp_path / "peers.conf")

        resp = client.post("/api/peers", json={
            "public_key": "A" * 44,
            "device_name": "test-device",
            "email": "test@test.com",
        })

        assert resp.status_code == 403

    def test_add_peer_invalid_key(self, client, authz_bridge_module, tmp_path):
        authz_bridge_module.POSTURE_STORE_PATH = str(tmp_path / "posture.json")

        resp = client.post("/api/peers", json={
            "public_key": "short",
            "device_name": "test",
        }, headers=self._auth_headers())

        assert resp.status_code == 400

    def test_add_peer_success(self, client, authz_bridge_module, tmp_path):
        authz_bridge_module.POSTURE_STORE_PATH = str(tmp_path / "posture.json")
        authz_bridge_module.PEERS_CONF_PATH = str(tmp_path / "peers.conf")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="", stderr="",
            )

            resp = client.post("/api/peers", json={
                "public_key": "A" * 44,
                "device_name": "laptop-alice",
                "email": "alice@test.com",
            }, headers=self._auth_headers())

        assert resp.status_code == 201
        data = resp.get_json()
        assert data["status"] == "provisioned"
        assert data["device_name"] == "laptop-alice"

    def test_next_ip_endpoint(self, client, authz_bridge_module, tmp_path):
        authz_bridge_module.POSTURE_STORE_PATH = str(
            tmp_path / "posture.json"
        )

        resp = client.get("/api/peers/next-ip")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["next_ip"].startswith("10.8.0.")

    def test_remove_peer_not_found(self, client, authz_bridge_module):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="pvtkey\t1\t0.0.0.0/0\t\n",
                returncode=0,
            )
            resp = client.delete(
                "/api/peers/nonexistent",
                headers=self._auth_headers(),
            )

        assert resp.status_code == 404

    def test_remove_peer_requires_auth(self, client, authz_bridge_module):
        resp = client.delete("/api/peers/somekey")

        assert resp.status_code == 403
