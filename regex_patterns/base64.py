"""Base64 payload extraction — useful in malware, PowerShell, and encoded C2 comms."""
import re
import base64
from dataclasses import dataclass, field

# Minimum length 16 chars to avoid false positives on short tokens
PATTERN = re.compile(
    r'(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})(?![A-Za-z0-9+/=])'
)

MIN_LENGTH = 16  # ignore tiny base64 tokens

BREAKDOWN = [
    ("[bold cyan](?<![A-Za-z0-9+/])[/]",           "Negative lookbehind — don't start in the middle of a base64 string"),
    ("[bold yellow](?:[A-Za-z0-9+/]{4})*[/]",       "Zero or more full 4-char base64 groups"),
    ("[bold green](?:[A-Za-z0-9+/]{2}==[/]|...[bold green])[/]", "Terminal group: 2-char+== or 3-char+= or 4-char (padding variants)"),
    ("[bold cyan](?![A-Za-z0-9+/=])[/]",            "Negative lookahead — don't end in the middle of a string"),
]

DESCRIPTION = "Base64-encoded payloads (min 16 chars) with optional padding — covers PowerShell and malware encoding"
NAME = "base64"


@dataclass
class Match:
    value: str
    start: int
    end: int
    line: int = 0
    decoded: str = ""
    decode_error: bool = False

    def __post_init__(self):
        try:
            self.decoded = base64.b64decode(self.value + "==").decode("utf-8", errors="replace")
        except Exception:
            self.decode_error = True


class Base64Pattern:
    name = NAME
    description = DESCRIPTION
    breakdown = BREAKDOWN
    pattern = PATTERN

    @classmethod
    def extract(cls, text: str) -> list[Match]:
        matches = []
        for i, line in enumerate(text.splitlines(), 1):
            for m in cls.pattern.finditer(line):
                if len(m.group()) >= MIN_LENGTH:
                    matches.append(Match(value=m.group(), start=m.start(), end=m.end(), line=i))
        return matches

    @classmethod
    def extract_unique(cls, text: str) -> set[str]:
        return {m.value for m in cls.extract(text)}
