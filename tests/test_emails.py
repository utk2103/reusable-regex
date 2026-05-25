import pytest
from regex_patterns.emails import EmailPattern


VALID_EMAILS = [
    "user@example.com",
    "first.last+tag@sub.domain.org",
    "test_user@company.io",
    "noreply@mail.example.co.uk",
]

INVALID_EMAILS = [
    "notanemail",
    "@nodomain.com",
    "user@",
    "user@domain",  # no TLD
]


@pytest.mark.parametrize("email", VALID_EMAILS)
def test_valid_emails(email):
    matches = EmailPattern.extract(email)
    assert any(m.value == email for m in matches), f"Should match: {email}"


def test_domain_extraction():
    text = "alice@gmail.com bob@yahoo.com"
    domains = EmailPattern.extract_domains(text)
    assert "gmail.com" in domains
    assert "yahoo.com" in domains


def test_deduplication():
    text = "user@test.com is logged as user@test.com again"
    unique = EmailPattern.extract_unique(text)
    assert len(unique) == 1


def test_line_tracking():
    text = "header\nuser@example.com\nfooter"
    matches = EmailPattern.extract(text)
    assert matches[0].line == 2
