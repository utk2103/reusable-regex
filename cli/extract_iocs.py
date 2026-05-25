"""extract_iocs — pull IOCs from any text source."""
from __future__ import annotations
import json
import csv
import sys
from enum import Enum
from pathlib import Path
from typing import Optional

import typer

from regex_patterns import ALL_PATTERNS, IPv4Pattern, EmailPattern, URLPattern, HashPattern, AWSKeyPattern, Base64Pattern, JWTPattern
from utils.file_loader import load_text
from utils.formatter import print_matches_table, print_summary, print_breakdown, print_error, print_success, console

app = typer.Typer(help="Extract IOCs (IPs, emails, URLs, hashes, secrets) from text.")


class OutputFormat(str, Enum):
    table = "table"
    json = "json"
    csv = "csv"
    txt = "txt"


class PatternType(str, Enum):
    all = "all"
    ipv4 = "ipv4"
    email = "email"
    url = "url"
    hash = "hash"
    aws_key = "aws_key"
    base64 = "base64"
    jwt = "jwt"


PATTERN_MAP = {
    "ipv4": IPv4Pattern,
    "email": EmailPattern,
    "url": URLPattern,
    "hash": HashPattern,
    "aws_key": AWSKeyPattern,
    "base64": Base64Pattern,
    "jwt": JWTPattern,
}


@app.command()
def extract(
    source: Optional[str] = typer.Argument(None, help="File path or '-' for stdin"),
    type: PatternType = typer.Option(PatternType.all, "--type", "-t", help="IOC type to extract"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write results to file"),
    format: OutputFormat = typer.Option(OutputFormat.table, "--format", "-f", help="Output format"),
    unique: bool = typer.Option(False, "--unique", "-u", help="Deduplicate results"),
    explain: bool = typer.Option(False, "--explain", "-e", help="Show regex breakdown for each pattern"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress decorative output"),
):
    """Extract IOCs from a file, stdin, or piped input."""
    text = load_text(source)
    if not text.strip():
        print_error("No input text.")
        raise typer.Exit(1)

    patterns = list(PATTERN_MAP.values()) if type == PatternType.all else [PATTERN_MAP[type.value]]

    all_results: dict[str, list] = {}
    counts: dict[str, int] = {}

    for pat in patterns:
        matches = pat.extract(text)
        if unique:
            seen = set()
            deduped = []
            for m in matches:
                if m.value not in seen:
                    seen.add(m.value)
                    deduped.append(m)
            matches = deduped
        all_results[pat.name] = matches
        counts[pat.name] = len(matches)

        if not quiet and explain:
            breakdown = pat.breakdown if isinstance(pat.breakdown, list) else list(pat.breakdown.values())[0]
            print_breakdown(breakdown, pat.name)

        if not quiet and format == OutputFormat.table and matches:
            cols = [("Line", "line"), ("Value", "value")]
            print_matches_table(matches, f"[bold]{pat.name.upper()}[/] Matches", cols)

    if not quiet:
        print_summary(counts)

    if output:
        _write_output(all_results, output, format)
        print_success(f"Results written to {output}")

    if format == OutputFormat.json and quiet:
        out = {k: [m.value for m in v] for k, v in all_results.items()}
        print(json.dumps(out, indent=2))


def _write_output(results: dict[str, list], path: Path, format: OutputFormat) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if format == OutputFormat.json:
        data = {k: [m.value for m in v] for k, v in results.items()}
        path.write_text(json.dumps(data, indent=2))
    elif format == OutputFormat.csv:
        with path.open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["pattern", "line", "value"])
            for pat_name, matches in results.items():
                for m in matches:
                    writer.writerow([pat_name, getattr(m, "line", ""), m.value])
    else:
        lines = []
        for pat_name, matches in results.items():
            lines.append(f"# {pat_name.upper()}")
            lines.extend(m.value for m in matches)
            lines.append("")
        path.write_text("\n".join(lines))


if __name__ == "__main__":
    app()
