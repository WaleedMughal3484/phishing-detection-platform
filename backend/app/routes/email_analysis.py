from fastapi import APIRouter

from app.analyzers.email_analyzer import analyze_email
from app.models.email_scan import EmailScanRequest, EmailScanResponse
from app.services.risk_scoring import (
    calculate_risk_score,
    get_risk_level,
)


router = APIRouter(
    prefix="/api/analyze",
    tags=["Email Analysis"],
)


@router.post("/email", response_model=EmailScanResponse)
def analyze_submitted_email(
    request: EmailScanRequest,
) -> EmailScanResponse:
    findings, urls = analyze_email(
        sender=request.sender,
        subject=request.subject,
        body=request.body,
    )

    risk_score = calculate_risk_score(findings)

    return EmailScanResponse(
        sender=request.sender,
        risk_score=risk_score,
        risk_level=get_risk_level(risk_score),
        finding_count=len(findings),
        links_analyzed=len(urls),
        findings=findings,
    )