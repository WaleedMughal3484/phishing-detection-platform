from typing import Literal

from pydantic import BaseModel, Field


class SecurityFinding(BaseModel):
    code: str
    title: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    description: str
    recommendation: str
    score: int = Field(ge=0, le=100)