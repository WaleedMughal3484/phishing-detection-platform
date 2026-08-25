from pydantic import BaseModel, Field, HttpUrl


class URLScanRequest(BaseModel):
    url: HttpUrl = Field(
        ...,
        description="The URL that should be analyzed for phishing indicators.",
        examples=["https://example.com/login"],
    )


class URLScanResponse(BaseModel):
    url: str
    message: str