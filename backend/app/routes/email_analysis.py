from typing import Literal

from fastapi import APIRouter

from app.analyzers.email_analyzer import analyze_email
from app.models.email_scan import EmailScanRequest, EmailScanResponse


router = APIRouter(
    prefix="/api/analyze",
    tags=["Email Analysis"],
)


def get_risk_level(
    score: int,
) -> Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


@router.post("/email", response_model=EmailScanResponse)
def analyze_submitted_email(
    request: EmailScanRequest,
) -> EmailScanResponse:
    findings, urls = analyze_email(
        subject=request.subject,
        body=request.body,
    )

    risk_score = min(
        sum(finding.score for finding in findings),
        100,
    )

    return EmailScanResponse(
        sender=request.sender,
        risk_score=risk_score,
        risk_level=get_risk_level(risk_score),
        finding_count=len(findings),
        links_analyzed=len(urls),
        findings=findings,
    )