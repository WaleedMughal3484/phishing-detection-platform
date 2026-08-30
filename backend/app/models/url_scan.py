from typing import Literal

from pydantic import BaseModel, Field, HttpUrl

from app.models.finding import SecurityFinding


class URLScanRequest(BaseModel):
    url: HttpUrl = Field(
        ...,
        description="The URL that should be analyzed for phishing indicators.",
        examples=["https://example.com/login"],
    )


class URLScanResponse(BaseModel):
    url: str
    risk_score: int = Field(ge=0, le=100)
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    finding_count: int = Field(ge=0)
    findings: list[SecurityFinding]