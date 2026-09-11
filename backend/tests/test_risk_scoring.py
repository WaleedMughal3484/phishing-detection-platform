import pytest

from app.models.finding import SecurityFinding
from app.services.risk_scoring import (
    calculate_risk_score,
    get_risk_level,
)


def create_finding(score: int) -> SecurityFinding:
    return SecurityFinding(
        code="TEST_FINDING",
        title="Test finding",
        severity="MEDIUM",
        description="A finding used for testing.",
        recommendation="No action is required.",
        score=score,
    )


def test_empty_findings_return_zero():
    assert calculate_risk_score([]) == 0


def test_finding_scores_are_added():
    findings = [
        create_finding(10),
        create_finding(20),
    ]

    assert calculate_risk_score(findings) == 30


def test_score_is_limited_to_one_hundred():
    findings = [
        create_finding(60),
        create_finding(60),
    ]

    assert calculate_risk_score(findings) == 100


@pytest.mark.parametrize(
    ("score", "expected_level"),
    [
        (0, "LOW"),
        (24, "LOW"),
        (25, "MEDIUM"),
        (49, "MEDIUM"),
        (50, "HIGH"),
        (74, "HIGH"),
        (75, "CRITICAL"),
        (100, "CRITICAL"),
    ],
)
def test_risk_level_thresholds(
    score: int,
    expected_level: str,
):
    assert get_risk_level(score) == expected_level