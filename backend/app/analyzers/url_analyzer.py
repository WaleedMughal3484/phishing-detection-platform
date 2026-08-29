import ipaddress
from urllib.parse import urlparse

from app.models.finding import SecurityFinding


SUSPICIOUS_KEYWORDS = {
    "account",
    "confirm",
    "credential",
    "login",
    "password",
    "secure",
    "signin",
    "update",
    "verification",
    "verify",
}


def uses_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def analyze_url(url: str) -> list[SecurityFinding]:
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ""
    lowercase_url = url.lower()

    findings: list[SecurityFinding] = []

    if uses_ip_address(hostname):
        findings.append(
            SecurityFinding(
                code="URL_IP_ADDRESS",
                title="IP address used as hostname",
                severity="HIGH",
                description=(
                    "The URL uses an IP address instead of a recognizable domain."
                ),
                recommendation=(
                    "Avoid opening the URL until its destination has been verified."
                ),
                score=30,
            )
        )

    if "@" in url:
        findings.append(
            SecurityFinding(
                code="URL_AT_SYMBOL",
                title="URL contains an @ symbol",
                severity="HIGH",
                description=(
                    "An @ symbol can obscure the true destination of a URL."
                ),
                recommendation=(
                    "Inspect the actual hostname before opening the link."
                ),
                score=25,
            )
        )

    if len(url) > 100:
        findings.append(
            SecurityFinding(
                code="URL_EXCESSIVE_LENGTH",
                title="Unusually long URL",
                severity="MEDIUM",
                description=(
                    "The URL is unusually long and may conceal suspicious information."
                ),
                recommendation=(
                    "Review the complete URL and destination domain carefully."
                ),
                score=15,
            )
        )

    matched_keywords = sorted(
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in lowercase_url
    )

    if matched_keywords:
        findings.append(
            SecurityFinding(
                code="URL_SUSPICIOUS_KEYWORDS",
                title="Suspicious keywords detected",
                severity="MEDIUM",
                description=(
                    "The URL contains words commonly used in phishing links: "
                    + ", ".join(matched_keywords)
                ),
                recommendation=(
                    "Confirm that the domain belongs to the expected organization."
                ),
                score=10,
            )
        )

    return findings