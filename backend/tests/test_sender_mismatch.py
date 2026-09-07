from app.analyzers.email_analyzer import (
    domains_match,
    extract_sender_domain,
    find_mismatched_domains,
)


def test_sender_domain_is_extracted():
    domain = extract_sender_domain(
        "security@example.com"
    )

    assert domain == "example.com"


def test_invalid_sender_has_no_domain():
    domain = extract_sender_domain(
        "not-an-email-address"
    )

    assert domain == ""


def test_matching_domain_is_allowed():
    assert domains_match(
        "example.com",
        "example.com",
    )


def test_matching_subdomain_is_allowed():
    assert domains_match(
        "example.com",
        "login.example.com",
    )


def test_different_domain_is_detected():
    assert not domains_match(
        "example.com",
        "example-security.com",
    )


def test_mismatched_link_is_returned():
    mismatches = find_mismatched_domains(
        sender="security@example.com",
        urls=["https://example-security.com/login"],
    )

    assert mismatches == ["example-security.com"]


def test_matching_link_is_not_returned():
    mismatches = find_mismatched_domains(
        sender="security@example.com",
        urls=["https://login.example.com/account"],
    )

    assert mismatches == []