import pytest
from regex_patterns.hashes import HashPattern, HashType


MD5_SAMPLES    = ["d41d8cd98f00b204e9800998ecf8427e", "098f6bcd4621d373cade4e832627b4f6"]
SHA1_SAMPLES   = ["da39a3ee5e6b4b0d3255bfef95601890afd80709", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"]
SHA256_SAMPLES = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
]


def test_md5_detection():
    for h in MD5_SAMPLES:
        matches = HashPattern.extract(h)
        assert any(m.hash_type == HashType.MD5 for m in matches), f"MD5 not detected: {h}"


def test_sha1_detection():
    for h in SHA1_SAMPLES:
        matches = HashPattern.extract(h)
        assert any(m.hash_type == HashType.SHA1 for m in matches), f"SHA1 not detected: {h}"


def test_sha256_detection():
    for h in SHA256_SAMPLES:
        matches = HashPattern.extract(h)
        assert any(m.hash_type == HashType.SHA256 for m in matches), f"SHA256 not detected: {h}"


def test_no_overlap():
    """SHA256 match should not also trigger SHA1/MD5."""
    h = SHA256_SAMPLES[0]
    matches = HashPattern.extract(h)
    types = [m.hash_type for m in matches]
    assert HashType.SHA256 in types
    assert HashType.MD5 not in types


def test_mixed_text():
    text = f"md5={MD5_SAMPLES[0]} sha256={SHA256_SAMPLES[0]}"
    unique = HashPattern.extract_unique(text)
    assert HashType.MD5 in unique
    assert HashType.SHA256 in unique
