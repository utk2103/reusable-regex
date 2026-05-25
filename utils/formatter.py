"""Rich output helpers — tables, panels, and breakdown displays."""
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()


def print_matches_table(matches: list, title: str, columns: list[tuple[str, str]]) -> None:
    """Render matches as a rich table. columns = [(header, attr_name)]."""
    table = Table(title=title, box=box.ROUNDED, show_lines=True, header_style="bold magenta")
    for header, _ in columns:
        table.add_column(header, style="cyan", no_wrap=True)
    for m in matches:
        table.add_row(*[str(getattr(m, attr, "")) for _, attr in columns])
    console.print(table)


def print_summary(counts: dict[str, int], title: str = "Summary") -> None:
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold green")
    table.add_column("Pattern", style="bold")
    table.add_column("Matches", justify="right", style="yellow")
    for k, v in counts.items():
        table.add_row(k, str(v))
    console.print(Panel(table, title=f"[bold]{title}[/]", border_style="green"))


def print_breakdown(breakdown: list[tuple[str, str]], pattern_name: str) -> None:
    """Print color-coded regex breakdown."""
    console.print(Panel(
        f"[bold white]Pattern:[/] [bold yellow]{pattern_name}[/]",
        title="[bold cyan]Regex Breakdown[/]",
        border_style="cyan",
    ))
    for token, explanation in breakdown:
        console.print(f"  {token}  [dim]->[/]  {explanation}")


def print_error(msg: str) -> None:
    console.print(f"[bold red]ERROR:[/] {msg}")


def print_success(msg: str) -> None:
    console.print(f"[bold green]OK[/] {msg}")
