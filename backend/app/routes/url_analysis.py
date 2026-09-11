from fastapi import APIRouter

from app.analyzers.url_analyzer import analyze_url
from app.models.url_scan import URLScanRequest, URLScanResponse
from app.services.risk_scoring import (
    calculate_risk_score,
    get_risk_level,
)


router = APIRouter(
    prefix="/api/analyze",
    tags=["URL Analysis"],
)


@router.post("/url", response_model=URLScanResponse)
def analyze_submitted_url(
    request: URLScanRequest,
) -> URLScanResponse:
    url = str(request.url)
    findings = analyze_url(url)
    risk_score = calculate_risk_score(findings)

    return URLScanResponse(
        url=url,
        risk_score=risk_score,
        risk_level=get_risk_level(risk_score),
        finding_count=len(findings),
        findings=findings,
    )