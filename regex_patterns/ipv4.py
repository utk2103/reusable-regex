"""IPv4 address extraction — matches valid 0-255 octets only."""
import re
from dataclasses import dataclass

PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

BREAKDOWN = [
    ("[bold cyan]\\b[/]",                       "Word boundary — no partial matches inside strings"),
    ("[bold yellow](?:[/][bold white]...[/][bold yellow])\\.){3}[/]", "Non-capturing group repeated 3x for first three octets + literal dot"),
    ("[bold green]25[0-5][/]",                  "Matches 250-255"),
    ("[bold green]2[0-4]\\d[/]",                "Matches 200-249"),
    ("[bold green][01]?\\d\\d?[/]",             "Matches 0-199 (leading zero optional)"),
    ("[bold cyan]\\b[/]",                        "Closing word boundary"),
]

DESCRIPTION = "IPv4 addresses (strict 0-255 per octet, no false positives on version strings)"
NAME = "ipv4"


@dataclass
class Match:
    value: str
    start: int
    end: int
    line: int = 0


class IPv4Pattern:
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
