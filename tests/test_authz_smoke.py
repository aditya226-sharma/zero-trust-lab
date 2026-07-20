import base64
import json


def test_decode_id_token_reads_verified_upstream_claims(authz_bridge_module):
    payload = base64.urlsafe_b64encode(
        json.dumps({"email": "user@example.test", "amr": ["webauthn"]}).encode()
    ).decode().rstrip("=")

    claims = authz_bridge_module._decode_id_token(f"Bearer header.{payload}.signature")

    assert claims["email"] == "user@example.test"
    assert claims["amr"] == ["webauthn"]


def test_missing_posture_store_fails_closed(authz_bridge_module, tmp_path):
    authz_bridge_module.POSTURE_STORE_PATH = str(tmp_path / "missing.json")

    posture = authz_bridge_module.get_posture("192.0.2.10")

    assert posture["posture"] == "unhealthy"
    assert posture["reason"] == "no posture data"
