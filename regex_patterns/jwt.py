"""JWT token extraction from auth logs, HTTP headers, and client-side code."""
import re
import json
import base64
from dataclasses import dataclass, field

# JWTs always start with eyJ (base64 of {"  )
PATTERN = re.compile(
    r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
)

BREAKDOWN = [
    ("[bold cyan]eyJ[/]",                         "Literal 'eyJ' — base64url encoding of '{\"' (every JWT header starts here)"),
    ("[bold yellow][A-Za-z0-9_-]+[/]",            "Header payload: base64url chars (note _ and - instead of + and /)"),
    ("[bold white]\\.[/]",                         "Dot separator between JWT segments"),
    ("[bold green]eyJ[A-Za-z0-9_-]+[/]",          "Claims payload segment — also base64url-encoded JSON"),
    ("[bold white]\\.[/]",                         "Second dot separator"),
    ("[bold magenta][A-Za-z0-9_-]+[/]",           "Signature segment — HMAC or RSA signature, base64url-encoded"),
]

DESCRIPTION = "JWT tokens (3-part dot-separated, base64url) — found in auth logs, Authorization headers, localStorage"
NAME = "jwt"


@dataclass
class Match:
    value: str
    start: int
    end: int
    line: int = 0
    header: dict = field(default_factory=dict)
    claims: dict = field(default_factory=dict)
    decode_error: bool = False

    def __post_init__(self):
        try:
            parts = self.value.split(".")
            def _decode(s: str) -> dict:
                padded = s + "=" * (-len(s) % 4)
                return json.loads(base64.urlsafe_b64decode(padded))
            self.header = _decode(parts[0])
            self.claims = _decode(parts[1])
        except Exception:
            self.decode_error = True


class JWTPattern:
    name = NAME
    description = DESCRIPTION
    breakdown = BREAKDOWN
    pattern = PATTERN

    @classmethod
    def extract(cls, text: str) -> list[Match]:
        matches = []
        for i, line in enumerate(text.splitlines(), 1):
            for m in cls.pattern.finditer(line):
                matches.append(Match(value=m.group(), start=m.start(), end=m.end(), line=i))
        return matches

    @classmethod
    def extract_unique(cls, text: str) -> set[str]:
        return {m.value for m in cls.extract(text)}
