from fastapi import APIRouter

from app.analyzers.url_analyzer import analyze_url
from app.models.url_scan import URLScanRequest, URLScanResponse

router = APIRouter(
    prefix="/api/analyze",
    tags=["URL Analysis"],
)


def get_risk_level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


@router.post("/url", response_model=URLScanResponse)
def analyze_submitted_url(request: URLScanRequest):
    url = str(request.url)
    findings = analyze_url(url)
    risk_score = min(sum(finding.score for finding in findings), 100)

    return URLScanResponse(
        url=url,
        risk_score=risk_score,
        risk_level=get_risk_level(risk_score),
        finding_count=len(findings),
        findings=findings,
    )