
def test_public_page_has_classification_header(demo_app_module):
    client = demo_app_module.app.test_client()
    response = client.get("/public")

    assert response.status_code == 200
    assert response.headers.get("X-Data-Classification") == "PUBLIC"
    assert response.headers.get("X-Data-Encryption-Required") == "false"
    assert response.headers.get("X-Data-Retention-Days") == "90"


def test_sensitive_page_has_classification_header(demo_app_module):
    client = demo_app_module.app.test_client()
    response = client.get("/sensitive")

    assert response.status_code == 200
    assert response.headers.get("X-Data-Classification") == "CONFIDENTIAL"
    assert response.headers.get("X-Data-Encryption-Required") == "true"
    assert response.headers.get("X-Data-Retention-Days") == "30"


def test_api_data_returns_classified_objects(demo_app_module):
    client = demo_app_module.app.test_client()
    response = client.get("/api/data")

    assert response.status_code == 200
    data = response.get_json()
    assert data["classification"] == "INTERNAL"
    assert "objects" in data
    assert "public-announcement" in data["objects"]
    assert "employee-records" in data["objects"]


def test_api_data_single_object(demo_app_module):
    client = demo_app_module.app.test_client()
    response = client.get("/api/data/employee-records")

    assert response.status_code == 200
    data = response.get_json()
    assert data["id"] == "employee-records"
    assert data["classification"] == "CONFIDENTIAL"
    assert data["owner"] == "hr@zerotrust.lab"


def test_api_data_object_not_found(demo_app_module):
    client = demo_app_module.app.test_client()
    response = client.get("/api/data/nonexistent")

    assert response.status_code == 404


def test_public_page_shows_classification_badge(demo_app_module):
    client = demo_app_module.app.test_client()
    response = client.get("/public")

    assert b"PUBLIC DATA" in response.data


def test_sensitive_page_shows_classification_badge(demo_app_module):
    client = demo_app_module.app.test_client()
    response = client.get("/sensitive")

    assert b"CONFIDENTIAL DATA" in response.data


def test_healthz_still_works(demo_app_module):
    response = demo_app_module.app.test_client().get("/healthz")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}
