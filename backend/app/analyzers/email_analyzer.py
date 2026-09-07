import re
from urllib.parse import urlparse

from app.analyzers.language_analyzer import analyze_language
from app.analyzers.url_analyzer import analyze_url
from app.models.finding import SecurityFinding


URL_PATTERN = re.compile(r"https?://[^\s<>()\"']+")


def extract_urls(text: str) -> list[str]:
    matches = URL_PATTERN.findall(text)

    cleaned_urls = [
        match.rstrip(".,;:!?)]}")
        for match in matches
    ]

    return list(dict.fromkeys(cleaned_urls))


def extract_sender_domain(sender: str) -> str:
    if "@" not in sender:
        return ""

    return sender.rsplit("@", 1)[1].strip().lower()


def domains_match(
    sender_domain: str,
    link_hostname: str,
) -> bool:
    sender_domain = sender_domain.lower()
    link_hostname = link_hostname.lower()

    return (
        link_hostname == sender_domain
        or link_hostname.endswith("." + sender_domain)
    )


def find_mismatched_domains(
    sender: str,
    urls: list[str],
) -> list[str]:
    sender_domain = extract_sender_domain(sender)

    if not sender_domain:
        return []

    mismatched_domains: list[str] = []

    for url in urls:
        hostname = urlparse(url).hostname or ""

        if hostname and not domains_match(sender_domain, hostname):
            mismatched_domains.append(hostname.lower())

    return sorted(set(mismatched_domains))


def analyze_email(
    sender: str,
    subject: str,
    body: str,
) -> tuple[list[SecurityFinding], list[str]]:
    findings = analyze_language(subject, body)
    urls = extract_urls(body)

    mismatched_domains = find_mismatched_domains(
        sender,
        urls,
    )

    if mismatched_domains:
        findings.append(
            SecurityFinding(
                code="EMAIL_SENDER_LINK_MISMATCH",
                title="Sender and link domains do not match",
                severity="HIGH",
                description=(
                    "The email sender's domain does not match these "
                    "linked domains: "
                    + ", ".join(mismatched_domains)
                ),
                recommendation=(
                    "Verify the sender and visit the organization's "
                    "official website directly instead of using the link."
                ),
                score=25,
            )
        )

    for url in urls:
        findings.extend(analyze_url(url))

    return findings, urls