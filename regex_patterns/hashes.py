"""Cryptographic hash extraction — MD5, SHA1, SHA256."""
import re
from dataclasses import dataclass
from enum import Enum


class HashType(str, Enum):
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    UNKNOWN = "unknown"


MD5_PATTERN    = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_PATTERN   = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')

BREAKDOWN = {
    HashType.MD5: [
        ("[bold cyan]\\b[/]",                   "Word boundary"),
        ("[bold yellow][a-fA-F0-9]{32}[/]",     "Exactly 32 hex chars — MD5 output length"),
        ("[bold cyan]\\b[/]",                    "Closing word boundary"),
    ],
    HashType.SHA1: [
        ("[bold cyan]\\b[/]",                   "Word boundary"),
        ("[bold green][a-fA-F0-9]{40}[/]",      "Exactly 40 hex chars — SHA1 output length"),
        ("[bold cyan]\\b[/]",                    "Closing word boundary"),
    ],
    HashType.SHA256: [
        ("[bold cyan]\\b[/]",                   "Word boundary"),
        ("[bold magenta][a-fA-F0-9]{64}[/]",    "Exactly 64 hex chars — SHA256 output length"),
        ("[bold cyan]\\b[/]",                    "Closing word boundary"),
    ],
}

DESCRIPTION = "MD5 (32), SHA1 (40), SHA256 (64) hex digests — common in malware IOC feeds"
NAME = "hash"


@dataclass
class Match:
    value: str
    hash_type: HashType
    start: int
    end: int
    line: int = 0


class HashPattern:
    name = NAME
    description = DESCRIPTION
    breakdown = BREAKDOWN

    @classmethod
    def extract(cls, text: str) -> list[Match]:
        matches = []
        for i, line in enumerate(text.splitlines(), 1):
            # SHA256 first — avoids SHA1/MD5 false-positive matches inside 64-char strings
            seen_spans: list[tuple[int, int]] = []
            for m in SHA256_PATTERN.finditer(line):
                seen_spans.append((m.start(), m.end()))
                matches.append(Match(value=m.group(), hash_type=HashType.SHA256, start=m.start(), end=m.end(), line=i))
            for m in SHA1_PATTERN.finditer(line):
                if not any(s <= m.start() and m.end() <= e for s, e in seen_spans):
                    seen_spans.append((m.start(), m.end()))
                    matches.append(Match(value=m.group(), hash_type=HashType.SHA1, start=m.start(), end=m.end(), line=i))
            for m in MD5_PATTERN.finditer(line):
                if not any(s <= m.start() and m.end() <= e for s, e in seen_spans):
                    matches.append(Match(value=m.group(), hash_type=HashType.MD5, start=m.start(), end=m.end(), line=i))
        return matches

    @classmethod
    def extract_unique(cls, text: str) -> dict[HashType, set[str]]:
        result: dict[HashType, set[str]] = {t: set() for t in HashType if t != HashType.UNKNOWN}
        for m in cls.extract(text):
            result[m.hash_type].add(m.value.lower())
        return result
