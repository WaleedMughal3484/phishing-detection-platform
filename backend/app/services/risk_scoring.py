from typing import Literal

from app.models.finding import SecurityFinding


RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def calculate_risk_score(
    findings: list[SecurityFinding],
) -> int:
    total_score = sum(
        finding.score
        for finding in findings
    )

    return min(total_score, 100)


def get_risk_level(score: int) -> RiskLevel:
    if score >= 75:
        return "CRITICAL"

    if score >= 50:
        return "HIGH"

    if score >= 25:
        return "MEDIUM"

    return "LOW"