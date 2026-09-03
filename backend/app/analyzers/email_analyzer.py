import re

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


def analyze_email(
    subject: str,
    body: str,
) -> tuple[list[SecurityFinding], list[str]]:
    findings = analyze_language(subject, body)
    urls = extract_urls(body)

    for url in urls:
        findings.extend(analyze_url(url))

    return findings, urls