"""Email address extraction from breach dumps, logs, and documents."""
import re
from dataclasses import dataclass

PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
)

BREAKDOWN = [
    ("[bold cyan]\\b[/]",                    "Word boundary"),
    ("[bold yellow][A-Za-z0-9._%+\\-]+[/]",  "Local part: alphanums + dots/underscores/percent/plus/hyphen, 1+ chars"),
    ("[bold white]@[/]",                      "Literal @ separator"),
    ("[bold green][A-Za-z0-9.\\-]+[/]",      "Domain: alphanums, dots, hyphens"),
    ("[bold white]\\.[/]",                    "Literal dot before TLD"),
    ("[bold magenta][A-Za-z]{2,}[/]",         "TLD: 2+ alpha chars (covers .io, .co.uk, etc.)"),
    ("[bold cyan]\\b[/]",                     "Closing word boundary"),
]

DESCRIPTION = "RFC-ish email addresses — covers common formats found in breach data"
NAME = "email"


@dataclass
class Match:
    value: str
    start: int
    end: int
    line: int = 0
    domain: str = ""

    def __post_init__(self):
        if "@" in self.value:
            self.domain = self.value.split("@")[1].lower()


class EmailPattern:
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
        return {m.value.lower() for m in cls.extract(text)}

    @classmethod
    def extract_domains(cls, text: str) -> set[str]:
        return {m.domain for m in cls.extract(text)}
