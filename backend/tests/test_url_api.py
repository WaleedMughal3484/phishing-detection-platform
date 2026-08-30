from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_normal_url_returns_low_risk():
    response = client.post(
        "/api/analyze/url",
        json={"url": "https://example.com/"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["risk_score"] == 0
    assert data["risk_level"] == "LOW"
    assert data["finding_count"] == 0
    assert data["findings"] == []


def test_suspicious_url_returns_findings():
    response = client.post(
        "/api/analyze/url",
        json={
            "url": "http://192.0.2.1/secure/account/verify",
        },
    )

    assert response.status_code == 200

    data = response.json()
    finding_codes = {
        finding["code"]
        for finding in data["findings"]
    }

    assert data["risk_score"] == 45
    assert data["risk_level"] == "MEDIUM"
    assert data["finding_count"] == 3

    assert "URL_INSECURE_HTTP" in finding_codes
    assert "URL_IP_ADDRESS" in finding_codes
    assert "URL_SUSPICIOUS_KEYWORDS" in finding_codes


def test_shortened_url_returns_warning():
    response = client.post(
        "/api/analyze/url",
        json={"url": "https://bit.ly/example-link"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["risk_score"] == 20
    assert data["risk_level"] == "LOW"
    assert data["finding_count"] == 1
    assert data["findings"][0]["code"] == "URL_SHORTENED_LINK"


def test_invalid_url_is_rejected():
    response = client.post(
        "/api/analyze/url",
        json={"url": "this is not a URL"},
    )

    assert response.status_code == 422


def test_missing_url_is_rejected():
    response = client.post(
        "/api/analyze/url",
        json={},
    )

    assert response.status_code == 422