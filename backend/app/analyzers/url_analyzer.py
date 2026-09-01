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

SHORTENER_DOMAINS = {
    "bit.ly",
    "buff.ly",
    "cutt.ly",
    "is.gd",
    "ow.ly",
    "rebrand.ly",
    "shorturl.at",
    "t.co",
    "tiny.cc",
    "tinyurl.com",
}


def uses_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def uses_punycode(hostname: str) -> bool:
    labels = hostname.lower().split(".")
    return any(label.startswith("xn--") for label in labels)


def has_excessive_subdomains(hostname: str) -> bool:
    if uses_ip_address(hostname):
        return False

    labels = [label for label in hostname.split(".") if label]
    return len(labels) > 4


def analyze_url(url: str) -> list[SecurityFinding]:
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ""
    lowercase_url = url.lower()

    findings: list[SecurityFinding] = []

    if parsed_url.scheme.lower() == "http":
        findings.append(
            SecurityFinding(
                code="URL_INSECURE_HTTP",
                title="URL does not use HTTPS",
                severity="LOW",
                description=(
                    "The URL uses an unencrypted HTTP connection."
                ),
                recommendation=(
                    "Avoid entering passwords or personal information "
                    "on websites that do not use HTTPS."
                ),
                score=5,
            )
        )

    if hostname.lower() in SHORTENER_DOMAINS:
        findings.append(
            SecurityFinding(
                code="URL_SHORTENED_LINK",
                title="Shortened URL detected",
                severity="MEDIUM",
                description=(
                    "This URL uses a link-shortening service that hides "
                    "the final destination."
                ),
                recommendation=(
                    "Expand the shortened link using a trusted preview "
                    "service before opening it."
                ),
                score=20,
            )
        )

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

    if uses_punycode(hostname):
        findings.append(
            SecurityFinding(
                code="URL_PUNYCODE_DOMAIN",
                title="Punycode domain detected",
                severity="HIGH",
                description=(
                    "The domain uses Punycode characters, which can be used "
                    "to imitate the appearance of a trusted domain."
                ),
                recommendation=(
                    "Verify the domain carefully before entering personal "
                    "information or login credentials."
                ),
                score=25,
            )
        )

    if has_excessive_subdomains(hostname):
        findings.append(
            SecurityFinding(
                code="URL_EXCESSIVE_SUBDOMAINS",
                title="Excessive number of subdomains",
                severity="MEDIUM",
                description=(
                    "The hostname contains an unusually large number "
                    "of domain sections."
                ),
                recommendation=(
                    "Read the hostname from right to left and verify "
                    "the actual registered domain."
                ),
                score=15,
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