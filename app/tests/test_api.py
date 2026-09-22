import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("APP_SECRET", "test-secret-value")
    monkeypatch.setenv("APP_ENV", "test")
    from secure_api.main import create_app

    return TestClient(create_app())


def test_healthz(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_status_never_leaks_secret(client: TestClient) -> None:
    r = client.get("/api/v1/status")
    body = r.json()
    assert r.status_code == 200
    assert body["environment"] == "test" and body["secret_configured"] is True
    assert len(body["secret_fingerprint"]) == 12
    assert "test-secret-value" not in r.text


def test_missing_secret_fails_fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APP_SECRET", raising=False)
    from secure_api.main import create_app

    with pytest.raises(RuntimeError, match="APP_SECRET"):
        create_app()


def test_security_headers(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"


def test_docs_disabled(client: TestClient) -> None:
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
