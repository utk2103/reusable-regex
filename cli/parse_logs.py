"""parse_logs — clean production uvicorn/systemd log viewer."""
from __future__ import annotations
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich import box

from regex_patterns.uvicorn_logs import UvicornLogPattern, LogMatch, LineType
from utils.file_loader import load_text

app     = typer.Typer(help="Clean viewer for uvicorn + systemd production logs.")
console = Console()

# ── Color scheme ─────────────────────────────────────────────────────────────

METHOD_COLOR = {
    "GET":     "cyan",
    "POST":    "green",
    "PUT":     "yellow",
    "DELETE":  "red",
    "PATCH":   "magenta",
    "OPTIONS": "dim",
    "HEAD":    "dim",
}

def _status_style(code: int) -> str:
    if code < 300:  return "bold green"
    if code < 400:  return "bold yellow"
    if code < 500:  return "bold red"
    return "bold white on red"

def _level_style(level: str) -> str:
    return {
        "INFO":     "dim cyan",
        "WARNING":  "bold yellow",
        "ERROR":    "bold red",
        "CRITICAL": "bold white on red",
        "DEBUG":    "dim",
    }.get(level, "white")


# ── Renderers ────────────────────────────────────────────────────────────────

def _render_http(m: LogMatch) -> None:
    t = Text()
    t.append(f"{m.time:<10}", style="dim white")
    t.append(f"{m.method:<8}", style=f"bold {METHOD_COLOR.get(m.method, 'white')}")
    t.append(f"{m.status}  ", style=_status_style(m.status))
    t.append(f"{m.path:<55}", style="white")
    t.append(f"  {m.client_ip}", style="dim")
    console.print(t)


def _render_app(m: LogMatch) -> None:
    t = Text()
    t.append(f"{m.time:<10}", style="dim white")
    t.append(f"[{m.level}]  ", style=_level_style(m.level))
    t.append(m.message, style="white")
    console.print(t)


def _render_traceback(m: LogMatch) -> None:
    t = Text()
    t.append(f"{m.time:<10}", style="dim white")
    t.append("TRACEBACK  ", style="bold red")
    t.append(m.message, style="red")
    console.print(t)


def _render_warning(m: LogMatch) -> None:
    t = Text()
    t.append(f"{m.time:<10}", style="dim white")
    t.append(f"{m.level:<10}", style=_level_style(m.level))
    t.append(m.message, style="yellow" if m.level == "WARNING" else "red")
    console.print(t)


def _render_match(m: LogMatch) -> None:
    if m.line_type == LineType.HTTP:
        _render_http(m)
    elif m.line_type == LineType.TRACEBACK:
        _render_traceback(m)
    elif m.line_type in (LineType.STRUCT, LineType.APP_LOG):
        _render_app(m)
    elif m.line_type == LineType.WARNING:
        _render_warning(m)


# ── CLI ───────────────────────────────────────────────────────────────────────

@app.command()
def view(
    source: Optional[str] = typer.Argument(None, help="Log file path or '-' for stdin"),
    errors_only: bool   = typer.Option(False,  "--errors",   "-e", help="Show only errors, warnings, and non-2xx responses"),
    no_options:  bool   = typer.Option(True,   "--no-options/--options",     help="Hide OPTIONS preflight requests (default: hide)"),
    no_2xx:      bool   = typer.Option(False,  "--no-2xx",                   help="Hide successful (2xx) HTTP lines"),
    method:      Optional[str] = typer.Option(None, "--method", "-m",        help="Filter by HTTP method (GET, POST, ...)"),
    path_filter: Optional[str] = typer.Option(None, "--path",  "-p",        help="Only show paths containing this string"),
    ip_filter:   Optional[str] = typer.Option(None, "--ip",                  help="Only show requests from this IP"),
    status_gte:  Optional[int] = typer.Option(None, "--status-gte",          help="Only show lines with status >= N (e.g. 400)"),
    summary:     bool   = typer.Option(False,  "--summary",   "-s",          help="Print request count summary table at the end"),
    no_collapse: bool   = typer.Option(False,  "--no-collapse",              help="Don't collapse traceback blocks"),
):
    """
    Parse and display production uvicorn logs cleanly.

    Strips the systemd/syslog prefix noise, color-codes HTTP methods
    and status codes, and collapses multi-line tracebacks to one line.

    \b
    Examples:
      parse-logs app.log
      parse-logs app.log --errors
      parse-logs app.log --method POST --status-gte 400
      journalctl -u myapp | parse-logs -
    """
    text = load_text(source)
    if not text.strip():
        console.print("[bold red]No input.[/]")
        raise typer.Exit(1)

    matches = UvicornLogPattern.parse(
        text,
        skip_options=no_options,
        skip_2xx=no_2xx,
        collapse_tracebacks=not no_collapse,
    )

    # ── Filters ──────────────────────────────────────────────────────────────
    if errors_only:
        matches = [m for m in matches if m.is_error]
    if method:
        matches = [m for m in matches if m.method == method.upper() or m.line_type != LineType.HTTP]
    if path_filter:
        matches = [m for m in matches if path_filter in m.path or m.line_type != LineType.HTTP]
    if ip_filter:
        matches = [m for m in matches if m.client_ip == ip_filter or m.line_type != LineType.HTTP]
    if status_gte is not None:
        matches = [m for m in matches if m.line_type != LineType.HTTP or m.status >= status_gte]

    if not matches:
        console.print("[dim]No matching log lines.[/]")
        return

    # ── Header ───────────────────────────────────────────────────────────────
    console.print()
    console.print(
        f"  [dim white]{'TIME':<10}{'METHOD':<8}{'STATUS':<6}{'PATH':<55}  CLIENT IP[/]"
    )
    console.rule(style="dim")

    for m in matches:
        _render_match(m)

    # ── Summary ───────────────────────────────────────────────────────────────
    if summary:
        console.rule(style="dim")
        _print_summary(matches)


def _print_summary(matches: list[LogMatch]) -> None:
    http = [m for m in matches if m.line_type == LineType.HTTP]
    errs = [m for m in matches if m.is_error]

    from collections import Counter
    path_counts = Counter(m.path for m in http)
    status_counts = Counter(m.status for m in http)
    ip_counts = Counter(m.client_ip for m in http)

    # Top paths
    tbl = Table(title="Top Paths", box=box.SIMPLE, header_style="bold cyan")
    tbl.add_column("Path")
    tbl.add_column("Hits", justify="right", style="yellow")
    for path, count in path_counts.most_common(10):
        tbl.add_row(path, str(count))
    console.print(tbl)

    # Status breakdown
    tbl2 = Table(title="Status Codes", box=box.SIMPLE, header_style="bold cyan")
    tbl2.add_column("Status")
    tbl2.add_column("Count", justify="right")
    for code, count in sorted(status_counts.items()):
        style = _status_style(code)
        tbl2.add_row(str(code), str(count), style=style if code >= 400 else "")
    console.print(tbl2)

    # Top IPs
    tbl3 = Table(title="Top Client IPs", box=box.SIMPLE, header_style="bold cyan")
    tbl3.add_column("IP")
    tbl3.add_column("Requests", justify="right", style="yellow")
    for ip, count in ip_counts.most_common(10):
        tbl3.add_row(ip, str(count))
    console.print(tbl3)

    console.print(
        f"\n  Total: [bold]{len(matches)}[/] lines  "
        f"({len(http)} HTTP, [bold red]{len(errs)} errors/warnings[/])"
    )


if __name__ == "__main__":
    app()
