import pytest
from regex_patterns.ipv4 import IPv4Pattern


VALID = [
    ("192.168.1.1",     1),
    ("10.0.0.1",        1),
    ("255.255.255.255", 1),
    ("0.0.0.0",         1),
    ("172.16.0.1 and 8.8.8.8", 2),
]

INVALID = [
    "256.1.1.1",
    "999.0.0.1",
    "192.168.1",      # only 3 octets
    "notanip",
    "192.168.1.1.1",  # 5 octets
]


@pytest.mark.parametrize("text,expected_count", VALID)
def test_valid_ips(text, expected_count):
    matches = IPv4Pattern.extract(text)
    assert len(matches) == expected_count


def test_unique():
    text = "10.0.0.1 visited 10.0.0.1 twice"
    assert IPv4Pattern.extract_unique(text) == {"10.0.0.1"}


def test_invalid_ips():
    for ip in INVALID:
        matches = IPv4Pattern.extract(ip)
        valid_values = [m.value for m in matches]
        for v in valid_values:
            octets = list(map(int, v.split(".")))
            assert all(0 <= o <= 255 for o in octets), f"False positive: {v} from {ip}"


def test_line_numbers():
    text = "line1\n192.168.1.1\nline3"
    matches = IPv4Pattern.extract(text)
    assert matches[0].line == 2
