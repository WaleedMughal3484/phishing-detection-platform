from fastapi import APIRouter

from app.models.url_scan import URLScanRequest, URLScanResponse

router = APIRouter(
    prefix="/api/analyze",
    tags=["URL Analysis"],
)


@router.post("/url", response_model=URLScanResponse)
def analyze_url(request: URLScanRequest):
    return URLScanResponse(
        url=str(request.url),
        message="URL accepted and ready for security analysis.",
    )