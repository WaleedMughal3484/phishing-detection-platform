from app.models.finding import SecurityFinding


URGENT_PHRASES = {
    "act immediately",
    "act now",
    "immediate action",
    "respond immediately",
    "urgent action",
    "verify immediately",
}

CREDENTIAL_PHRASES = {
    "confirm your password",
    "enter your password",
    "login credentials",
    "provide your password",
    "verify your account",
    "verify your identity",
}

THREATENING_PHRASES = {
    "account will be closed",
    "account will be locked",
    "account will be suspended",
    "legal action",
    "payment will be cancelled",
    "service will be terminated",
}


def find_matching_phrases(
    text: str,
    phrases: set[str],
) -> list[str]:
    lowercase_text = text.lower()

    return sorted(
        phrase
        for phrase in phrases
        if phrase in lowercase_text
    )


def analyze_language(
    subject: str,
    body: str,
) -> list[SecurityFinding]:
    email_text = f"{subject}\n{body}"
    findings: list[SecurityFinding] = []

    urgent_matches = find_matching_phrases(
        email_text,
        URGENT_PHRASES,
    )

    if urgent_matches:
        findings.append(
            SecurityFinding(
                code="EMAIL_URGENT_LANGUAGE",
                title="Urgent language detected",
                severity="MEDIUM",
                description=(
                    "The email creates urgency using these phrases: "
                    + ", ".join(urgent_matches)
                ),
                recommendation=(
                    "Pause and verify the request through an official "
                    "communication channel."
                ),
                score=15,
            )
        )

    credential_matches = find_matching_phrases(
        email_text,
        CREDENTIAL_PHRASES,
    )

    if credential_matches:
        findings.append(
            SecurityFinding(
                code="EMAIL_CREDENTIAL_REQUEST",
                title="Credential request detected",
                severity="HIGH",
                description=(
                    "The email appears to request account or identity "
                    "information using these phrases: "
                    + ", ".join(credential_matches)
                ),
                recommendation=(
                    "Do not provide credentials through links in the email. "
                    "Visit the official website directly."
                ),
                score=25,
            )
        )

    threatening_matches = find_matching_phrases(
        email_text,
        THREATENING_PHRASES,
    )

    if threatening_matches:
        findings.append(
            SecurityFinding(
                code="EMAIL_THREATENING_LANGUAGE",
                title="Threatening language detected",
                severity="HIGH",
                description=(
                    "The email pressures the recipient with these threats: "
                    + ", ".join(threatening_matches)
                ),
                recommendation=(
                    "Verify the claim independently before responding "
                    "or taking action."
                ),
                score=20,
            )
        )

    return findings