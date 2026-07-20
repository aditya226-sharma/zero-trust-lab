import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def revoker_module():
    from importlib.util import module_from_spec, spec_from_file_location
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    spec = spec_from_file_location(
        "posture_revoker", root / "scripts/posture_revoker.py"
    )
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestGetWireguardPeers:
    def test_returns_peers(self, revoker_module):
        fake = MagicMock()
        fake.stdout = (
            "interface\twg0\t10.8.0.1/24\t\n"
            "pubkey1\t1\t300\t0\t10.8.0.2/32\n"
            "pubkey2\t1\t300\t0\t10.8.0.3/32\n"
        )
        fake.returncode = 0

        with patch("subprocess.run", return_value=fake):
            peers = revoker_module.get_wireguard_peers()

        assert "pubkey1" in peers
        assert "pubkey2" in peers

    def test_returns_empty_on_error(self, revoker_module):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("wg", 10)):
            peers = revoker_module.get_wireguard_peers()

        assert peers == {}


class TestRemoveWireguardPeer:
    def test_removes_peer_successfully(self, revoker_module):
        fake = MagicMock()
        fake.returncode = 0

        with patch("subprocess.run", return_value=fake) as mock_run:
            result = revoker_module.remove_wireguard_peer("test-pubkey")

        assert result is True
        mock_run.assert_called_once_with(
            ["wg", "set", "wg0", "peer", "test-pubkey", "remove"],
            check=True,
            timeout=10,
        )

    def test_returns_false_on_failure(self, revoker_module):
        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, "wg")):
            result = revoker_module.remove_wireguard_peer("test-pubkey")

        assert result is False


class TestRevokeAuthentikSessions:
    def test_skips_when_no_token(self, revoker_module):
        revoker_module.AUTHENTIK_TOKEN = ""
        result = revoker_module.revoke_authentik_sessions("alice@test.com")
        assert result is False

    def test_revokes_sessions(self, revoker_module):
        revoker_module.AUTHENTIK_TOKEN = "test-token"

        user_resp = MagicMock()
        user_resp.__enter__ = MagicMock(return_value=user_resp)
        user_resp.__exit__ = MagicMock(return_value=False)
        user_resp.status = 200
        user_resp.read.return_value = json.dumps({
            "results": [{"pk": 42, "email": "alice@test.com"}]
        }).encode()

        terminate_resp = MagicMock()
        terminate_resp.__enter__ = MagicMock(return_value=terminate_resp)
        terminate_resp.__exit__ = MagicMock(return_value=False)
        terminate_resp.status = 204

        with patch("urllib.request.urlopen", side_effect=[user_resp, terminate_resp]):
            result = revoker_module.revoke_authentik_sessions("alice@test.com")

        assert result is True

    def test_returns_false_when_user_not_found(self, revoker_module):
        revoker_module.AUTHENTIK_TOKEN = "test-token"

        user_resp = MagicMock()
        user_resp.status = 200
        user_resp.read.return_value = json.dumps({"results": []}).encode()

        with patch("urllib.request.urlopen", return_value=user_resp):
            result = revoker_module.revoke_authentik_sessions("nobody@test.com")

        assert result is False


class TestProcessPostureLog:
    def test_triggers_revocation_on_posture_degradation(self, revoker_module, tmp_path):
        log_file = tmp_path / "device_posture.log"
        log_file.write_text(json.dumps({
            "device_id": "10.10.1.50",
            "healthy": False,
            "user_email": "alice@test.com",
        }) + "\n")

        revocation_log = tmp_path / "posture_revoker.log"

        revoker_module.POSTURE_LOG = str(log_file)
        revoker_module.device_state = {"10.10.1.50": True}

        fake_peer_resp = MagicMock()
        fake_peer_resp.stdout = "interface\twg0\t10.8.0.1/24\n"
        fake_peer_resp.returncode = 0

        real_open = open

        def mock_open(path, *args, **kwargs):
            if path == "/var/log/posture_revoker.log":
                return real_open(str(revocation_log), *args, **kwargs)
            return real_open(path, *args, **kwargs)

        with patch("subprocess.run", return_value=fake_peer_resp), \
             patch.object(revoker_module, "revoke_authentik_sessions") as mock_revoke, \
             patch("builtins.open", side_effect=mock_open):
            revoker_module.process_posture_log()

        mock_revoke.assert_called_once_with("alice@test.com")
        log_entry = json.loads(revocation_log.read_text().strip())
        assert log_entry["event"] == "automatic_revocation"
        assert log_entry["device_id"] == "10.10.1.50"

    def test_no_action_when_state_unchanged(self, revoker_module, tmp_path):
        log_file = tmp_path / "device_posture.log"
        log_file.write_text(json.dumps({
            "device_id": "10.10.1.50",
            "healthy": True,
            "user_email": "alice@test.com",
        }) + "\n")

        revoker_module.POSTURE_LOG = str(log_file)
        revoker_module.device_state = {"10.10.1.50": True}

        with patch("subprocess.run"), \
             patch.object(revoker_module, "revoke_authentik_sessions") as mock_revoke:
            revoker_module.process_posture_log()

        mock_revoke.assert_not_called()

    def test_handles_missing_log_file(self, revoker_module, tmp_path):
        revoker_module.POSTURE_LOG = str(tmp_path / "nonexistent.log")
        # Should not raise
        revoker_module.process_posture_log()
