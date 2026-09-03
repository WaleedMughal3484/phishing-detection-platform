from typing import Literal

from pydantic import BaseModel, Field

from app.models.finding import SecurityFinding


class EmailScanRequest(BaseModel):
    sender: str = Field(
        min_length=1,
        max_length=320,
        examples=["security@example.com"],
    )
    subject: str = Field(
        default="",
        max_length=500,
        examples=["Urgent: Verify your account"],
    )
    body: str = Field(
        min_length=1,
        examples=[
            "Your account will be suspended. "
            "Verify it at https://example.com/login"
        ],
    )


class EmailScanResponse(BaseModel):
    sender: str
    risk_score: int = Field(ge=0, le=100)
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    finding_count: int = Field(ge=0)
    links_analyzed: int = Field(ge=0)
    findings: list[SecurityFinding]