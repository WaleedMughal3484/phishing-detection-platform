from app.analyzers.url_analyzer import analyze_url


def get_finding_codes(url: str) -> set[str]:
    findings = analyze_url(url)
    return {finding.code for finding in findings}


def test_normal_url_has_no_findings():
    findings = analyze_url("https://example.com/")

    assert findings == []


def test_ip_address_is_detected():
    codes = get_finding_codes("http://192.0.2.1/")

    assert "URL_IP_ADDRESS" in codes


def test_at_symbol_is_detected():
    codes = get_finding_codes("https://example.com@192.0.2.1/login")

    assert "URL_AT_SYMBOL" in codes


def test_long_url_is_detected():
    long_url = "https://example.com/" + ("a" * 120)
    codes = get_finding_codes(long_url)

    assert "URL_EXCESSIVE_LENGTH" in codes


def test_suspicious_keywords_are_detected():
    codes = get_finding_codes(
        "https://example.com/secure/account/verify"
    )

    assert "URL_SUSPICIOUS_KEYWORDS" in codes


def test_multiple_patterns_are_detected():
    codes = get_finding_codes(
        "http://192.0.2.1/secure/account/verify"
    )

    assert "URL_IP_ADDRESS" in codes
    assert "URL_SUSPICIOUS_KEYWORDS" in codes