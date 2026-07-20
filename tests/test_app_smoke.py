def test_public_page_describes_the_public_zone(demo_app_module):
    client = demo_app_module.app.test_client()

    response = client.get("/public")

    assert response.status_code == 200
    assert b"PUBLIC ZONE" in response.data


def test_sensitive_page_describes_step_up_authentication(demo_app_module):
    client = demo_app_module.app.test_client()

    response = client.get("/sensitive")

    assert response.status_code == 200
    assert b"RE-AUTH REQUIRED" in response.data


def test_demo_app_health_endpoint(demo_app_module):
    response = demo_app_module.app.test_client().get("/healthz")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}
