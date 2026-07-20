import json
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def posture_module():
    from importlib.util import module_from_spec, spec_from_file_location
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    spec = spec_from_file_location(
        "posture_check", root / "scripts/posture_check.py"
    )
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestRunOsquery:
    def test_returns_parsed_json(self, posture_module):
        fake = MagicMock()
        fake.stdout = '[{"name": "test"}]'
        fake.returncode = 0

        with patch("subprocess.run", return_value=fake):
            result = posture_module.run_osquery("SELECT * FROM test;")

        assert result == [{"name": "test"}]

    def test_returns_none_on_command_error(self, posture_module):
        import subprocess as sp

        with patch("subprocess.run", side_effect=sp.CalledProcessError(1, "osqueryi")):
            result = posture_module.run_osquery("BAD QUERY")

        assert result is None

    def test_returns_none_on_timeout(self, posture_module):
        import subprocess as sp

        with patch("subprocess.run", side_effect=sp.TimeoutExpired("osqueryi", 10)):
            result = posture_module.run_osquery("SLOW QUERY")

        assert result is None

    def test_returns_none_on_invalid_json(self, posture_module):
        fake = MagicMock()
        fake.stdout = "not json"
        fake.returncode = 0

        with patch("subprocess.run", return_value=fake):
            result = posture_module.run_osquery("SELECT * FROM test;")

        assert result is None

    def test_returns_none_on_missing_binary(self, posture_module):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = posture_module.run_osquery("SELECT 1;")

        assert result is None


class TestCheckDiskEncryption:
    def test_healthy_when_encrypted(self, posture_module):
        with patch.object(posture_module, "run_osquery", return_value=[{"encrypted": 1}]):
            assert posture_module.check_disk_encryption() is True

    def test_unhealthy_when_not_encrypted(self, posture_module):
        with patch.object(posture_module, "run_osquery", return_value=[]):
            assert posture_module.check_disk_encryption() is False

    def test_unhealthy_on_osquery_failure(self, posture_module):
        with patch.object(posture_module, "run_osquery", return_value=None):
            assert posture_module.check_disk_encryption() is False


class TestCheckBlocklistedProcesses:
    def test_clean_when_no_hits(self, posture_module):
        with patch.object(posture_module, "run_osquery", return_value=[
            {"name": "sshd"}, {"name": "python3"}
        ]):
            assert posture_module.check_blocklisted_processes() is True

    def test_unhealthy_when_nc_running(self, posture_module):
        with patch.object(posture_module, "run_osquery", return_value=[
            {"name": "sshd"}, {"name": "nc"}
        ]):
            assert posture_module.check_blocklisted_processes() is False

    def test_unhealthy_when_mimikatz_running(self, posture_module):
        with patch.object(posture_module, "run_osquery", return_value=[
            {"name": "mimikatz"}
        ]):
            assert posture_module.check_blocklisted_processes() is False

    def test_unhealthy_on_osquery_failure(self, posture_module):
        with patch.object(posture_module, "run_osquery", return_value=None):
            assert posture_module.check_blocklisted_processes() is False


class TestMain:
    def test_writes_healthy_verdict(self, posture_module, tmp_path):
        posture_file = tmp_path / "posture.json"

        with patch.object(posture_module, "POSTURE_STORE_PATH", str(posture_file)), \
             patch.object(posture_module, "check_disk_encryption", return_value=True), \
             patch.object(posture_module, "check_patch_age", return_value=True), \
             patch.object(posture_module, "check_blocklisted_processes", return_value=True), \
             patch("socket.gethostname", return_value="test-host"), \
             patch("socket.gethostbyname", return_value="10.10.1.50"):
            posture_module.main()

        store = json.loads(posture_file.read_text())
        assert store["10.10.1.50"]["posture"] == "healthy"
        assert store["10.10.1.50"]["healthy"] is True

    def test_writes_unhealthy_when_any_check_fails(self, posture_module, tmp_path):
        posture_file = tmp_path / "posture.json"

        with patch.object(posture_module, "POSTURE_STORE_PATH", str(posture_file)), \
             patch.object(posture_module, "check_disk_encryption", return_value=False), \
             patch.object(posture_module, "check_patch_age", return_value=True), \
             patch.object(posture_module, "check_blocklisted_processes", return_value=True), \
             patch("socket.gethostname", return_value="test-host"), \
             patch("socket.gethostbyname", return_value="10.10.1.50"):
            posture_module.main()

        store = json.loads(posture_file.read_text())
        assert store["10.10.1.50"]["posture"] == "unhealthy"
        assert store["10.10.1.50"]["healthy"] is False

    def test_appends_to_existing_store(self, posture_module, tmp_path):
        posture_file = tmp_path / "posture.json"
        posture_file.write_text(json.dumps({"10.10.1.99": {"posture": "healthy"}}))

        with patch.object(posture_module, "POSTURE_STORE_PATH", str(posture_file)), \
             patch.object(posture_module, "check_disk_encryption", return_value=True), \
             patch.object(posture_module, "check_patch_age", return_value=True), \
             patch.object(posture_module, "check_blocklisted_processes", return_value=True), \
             patch("socket.gethostname", return_value="test-host"), \
             patch("socket.gethostbyname", return_value="10.10.1.50"):
            posture_module.main()

        store = json.loads(posture_file.read_text())
        assert "10.10.1.99" in store
        assert "10.10.1.50" in store
