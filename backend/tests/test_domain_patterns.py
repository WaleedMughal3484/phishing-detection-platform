from app.analyzers.url_analyzer import analyze_url


def get_finding_codes(url: str) -> set[str]:
    findings = analyze_url(url)
    return {finding.code for finding in findings}


def test_punycode_domain_is_detected():
    codes = get_finding_codes("https://xn--example-9za.com/")

    assert "URL_PUNYCODE_DOMAIN" in codes


def test_normal_domain_is_not_marked_as_punycode():
    codes = get_finding_codes("https://example.com/")

    assert "URL_PUNYCODE_DOMAIN" not in codes


def test_excessive_subdomains_are_detected():
    codes = get_finding_codes(
        "https://secure.login.account.service.example.com/"
    )

    assert "URL_EXCESSIVE_SUBDOMAINS" in codes


def test_normal_subdomain_is_allowed():
    codes = get_finding_codes("https://support.example.com/")

    assert "URL_EXCESSIVE_SUBDOMAINS" not in codes


def test_ip_address_is_not_treated_as_subdomains():
    codes = get_finding_codes("https://192.0.2.1/")

    assert "URL_IP_ADDRESS" in codes
    assert "URL_EXCESSIVE_SUBDOMAINS" not in codes