"""scan_logs — scan log files for suspicious IOCs and flag anomalies."""
from __future__ import annotations
from pathlib import Path

import typer
from rich.table import Table
from rich import box

from regex_patterns import IPv4Pattern, URLPattern, HashPattern
from utils.file_loader import iter_files
from utils.formatter import console, print_error, print_summary

app = typer.Typer(help="Scan log files for IOCs. Supports directories and recursive scan.")


@app.command()
def scan(
    paths: list[Path] = typer.Argument(..., help="Log files or directories to scan"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Recurse into directories"),
    min_hits: int = typer.Option(1, "--min-hits", help="Only show files with >= N matches"),
    show_lines: bool = typer.Option(False, "--lines", "-l", help="Show matching lines"),
):
    """Scan logs for IPv4s, URLs, and hashes. Groups results by file."""
    table = Table(
        title="Log Scan Results",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("File", style="bold white")
    table.add_column("IPs", justify="right", style="green")
    table.add_column("URLs", justify="right", style="yellow")
    table.add_column("Hashes", justify="right", style="magenta")
    table.add_column("Total", justify="right", style="bold red")

    grand: dict[str, int] = {"IPs": 0, "URLs": 0, "Hashes": 0}

    for fpath, text in iter_files(paths, recursive=recursive):
        ips    = IPv4Pattern.extract(text)
        urls   = URLPattern.extract(text)
        hashes = HashPattern.extract(text)
        total  = len(ips) + len(urls) + len(hashes)

        if total < min_hits:
            continue

        grand["IPs"]    += len(ips)
        grand["URLs"]   += len(urls)
        grand["Hashes"] += len(hashes)

        table.add_row(str(fpath), str(len(ips)), str(len(urls)), str(len(hashes)), str(total))

        if show_lines:
            for m in ips + urls + hashes:
                console.print(f"  [dim]{fpath}:{m.line}[/]  {m.value}")

    console.print(table)
    print_summary(grand, "Grand Total")


if __name__ == "__main__":
    app()
