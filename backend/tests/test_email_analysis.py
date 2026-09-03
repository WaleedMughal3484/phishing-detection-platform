from fastapi.testclient import TestClient

from app.analyzers.email_analyzer import extract_urls
from app.analyzers.language_analyzer import analyze_language
from app.main import app


client = TestClient(app)


def get_finding_codes(findings) -> set[str]:
    return {finding.code for finding in findings}


def test_urgent_language_is_detected():
    findings = analyze_language(
        subject="Urgent action required",
        body="You must act immediately.",
    )

    assert "EMAIL_URGENT_LANGUAGE" in get_finding_codes(findings)


def test_credential_request_is_detected():
    findings = analyze_language(
        subject="Account notice",
        body="Please confirm your password.",
    )

    assert "EMAIL_CREDENTIAL_REQUEST" in get_finding_codes(findings)


def test_threatening_language_is_detected():
    findings = analyze_language(
        subject="Security warning",
        body="Your account will be suspended.",
    )

    assert "EMAIL_THREATENING_LANGUAGE" in get_finding_codes(findings)


def test_urls_are_extracted_from_email():
    urls = extract_urls(
        "Visit https://example.com and https://bit.ly/test."
    )

    assert urls == [
        "https://example.com",
        "https://bit.ly/test",
    ]


def test_email_endpoint_returns_analysis():
    response = client.post(
        "/api/analyze/email",
        json={
            "sender": "security@example.com",
            "subject": "Urgent action required",
            "body": (
                "Your account will be suspended. "
                "Verify your account immediately at "
                "http://192.0.2.1/login"
            ),
        },
    )

    assert response.status_code == 200

    data = response.json()
    codes = {
        finding["code"]
        for finding in data["findings"]
    }

    assert data["risk_score"] > 0
    assert data["links_analyzed"] == 1
    assert data["finding_count"] > 0
    assert "EMAIL_THREATENING_LANGUAGE" in codes
    assert "URL_IP_ADDRESS" in codes


def test_email_without_body_is_rejected():
    response = client.post(
        "/api/analyze/email",
        json={
            "sender": "security@example.com",
            "subject": "Hello",
            "body": "",
        },
    )

    assert response.status_code == 422