"""URL extraction from proxy logs, PCAPs, and web traffic dumps."""
import re
from dataclasses import dataclass
from urllib.parse import urlparse

PATTERN = re.compile(
    r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?::\d+)?(?:/[^\s\'"<>]*)?',
    re.IGNORECASE,
)

BREAKDOWN = [
    ("[bold yellow]https?://[/]",              "Protocol: http or https (s is optional)"),
    ("[bold green](?:[-\\w.]|(?:%[\\da-fA-F]{2}))+[/]", "Host: word chars, dots, hyphens, or percent-encoded chars"),
    ("[bold white](?::\\d+)?[/]",              "Optional port number :8080"),
    ("[bold cyan](?:/[^\\s\\'\"<>]*)?[/]",    "Optional path, query, fragment — stops at whitespace/quotes/tags"),
]

DESCRIPTION = "HTTP/HTTPS URLs — handles encoded chars, ports, paths, and query strings"
NAME = "url"


@dataclass
class Match:
    value: str
    start: int
    end: int
    line: int = 0
    scheme: str = ""
    host: str = ""
    path: str = ""

    def __post_init__(self):
        parsed = urlparse(self.value)
        self.scheme = parsed.scheme
        self.host = parsed.netloc.lower()
        self.path = parsed.path


class URLPattern:
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

    @classmethod
    def extract_hosts(cls, text: str) -> set[str]:
        return {m.host for m in cls.extract(text)}
