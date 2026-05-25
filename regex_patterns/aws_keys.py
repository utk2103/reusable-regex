"""AWS credential extraction — access key IDs and secret keys."""
import re
from dataclasses import dataclass
from enum import Enum


class AWSKeyType(str, Enum):
    ACCESS_KEY_ID = "access_key_id"
    SECRET_ACCESS_KEY = "secret_access_key"


# AWS access key IDs always start with AKIA (long-term) or other prefixes
ACCESS_KEY_PATTERN = re.compile(
    r'\b(AKIA|ASIA|AROA|AIDA|ANPA|ANVA|APKA)[0-9A-Z]{16}\b'
)

# Secret keys: 40-char base64-ish string, often appears after "aws_secret" context
SECRET_KEY_PATTERN = re.compile(
    r'(?i)(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*["\']?([A-Za-z0-9/+]{40})["\']?'
)

BREAKDOWN = {
    AWSKeyType.ACCESS_KEY_ID: [
        ("[bold cyan]\\b[/]",                       "Word boundary"),
        ("[bold red](AKIA|ASIA|AROA|AIDA|...)[/]",  "AWS key prefix — encodes key type (AKIA=long-term, ASIA=STS temp)"),
        ("[bold yellow][0-9A-Z]{16}[/]",             "16 uppercase alphanums — account-specific suffix"),
        ("[bold cyan]\\b[/]",                        "Closing word boundary"),
    ],
    AWSKeyType.SECRET_ACCESS_KEY: [
        ("[bold magenta](?i)(?:aws_secret...)[/]",   "Case-insensitive context anchor — key name before the value"),
        ("[bold white]\\s*[=:]\\s*[/]",              "Assignment operator with optional spaces"),
        ("[bold yellow][\"']?[/]",                   "Optional quote wrapping"),
        ("[bold green]([A-Za-z0-9/+]{40})[/]",      "40-char base64 secret — captured in group 1"),
    ],
}

DESCRIPTION = "AWS access key IDs (AKIA/ASIA/etc.) and secret keys via context anchoring"
NAME = "aws_key"


@dataclass
class Match:
    value: str
    key_type: AWSKeyType
    start: int
    end: int
    line: int = 0


class AWSKeyPattern:
    name = NAME
    description = DESCRIPTION
    breakdown = BREAKDOWN

    @classmethod
    def extract(cls, text: str) -> list[Match]:
        matches = []
        for i, line in enumerate(text.splitlines(), 1):
            for m in ACCESS_KEY_PATTERN.finditer(line):
                matches.append(Match(value=m.group(), key_type=AWSKeyType.ACCESS_KEY_ID, start=m.start(), end=m.end(), line=i))
            for m in SECRET_KEY_PATTERN.finditer(line):
                matches.append(Match(value=m.group(1), key_type=AWSKeyType.SECRET_ACCESS_KEY, start=m.start(1), end=m.end(1), line=i))
        return matches

    @classmethod
    def extract_unique(cls, text: str) -> dict[AWSKeyType, set[str]]:
        result: dict[AWSKeyType, set[str]] = {t: set() for t in AWSKeyType}
        for m in cls.extract(text):
            result[m.key_type].add(m.value)
        return result
