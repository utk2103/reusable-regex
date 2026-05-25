"""detect_secrets — scan for hardcoded secrets: AWS keys, JWTs, base64 payloads."""
from __future__ import annotations
from pathlib import Path

import typer
from rich.table import Table
from rich.panel import Panel
from rich import box

from regex_patterns import AWSKeyPattern, JWTPattern, Base64Pattern
from utils.file_loader import iter_files
from utils.formatter import console, print_error, print_summary

app = typer.Typer(help="Detect hardcoded secrets in source code and config files.")

SEVERITY = {
    "aws_key": "[bold red]CRITICAL[/]",
    "jwt":     "[bold yellow]HIGH[/]",
    "base64":  "[bold blue]MEDIUM[/]",
}


@app.command()
def detect(
    paths: list[Path] = typer.Argument(..., help="Files or directories to scan"),
    recursive: bool = typer.Option(False, "--recursive", "-r"),
    decode: bool = typer.Option(False, "--decode", "-d", help="Attempt to decode base64/JWT payloads"),
    fail_on_find: bool = typer.Option(False, "--fail", help="Exit code 1 if any secret found (CI use)"),
):
    """Detect hardcoded AWS keys, JWTs, and suspicious base64 in code and configs."""
    findings: list[dict] = []

    for fpath, text in iter_files(paths, recursive=recursive):
        for m in AWSKeyPattern.extract(text):
            findings.append({"file": str(fpath), "line": m.line, "type": "aws_key", "value": m.value[:12] + "...", "severity": "CRITICAL"})
        for m in JWTPattern.extract(text):
            alg = m.header.get("alg", "?") if not m.decode_error else "?"
            sub = m.claims.get("sub", "") if not m.decode_error else ""
            display = f"{m.value[:20]}... [alg={alg}" + (f", sub={sub}" if sub else "") + "]"
            findings.append({"file": str(fpath), "line": m.line, "type": "jwt", "value": display, "severity": "HIGH"})
        for m in Base64Pattern.extract(text):
            decoded_preview = ""
            if decode and not m.decode_error:
                decoded_preview = m.decoded[:40].replace("\n", "\\n")
            findings.append({"file": str(fpath), "line": m.line, "type": "base64", "value": m.value[:20] + "...", "severity": "MEDIUM", "decoded": decoded_preview})

    if not findings:
        console.print("[bold green]No secrets detected.[/]")
        return

    table = Table(title="Secret Findings", box=box.ROUNDED, show_lines=True, header_style="bold red")
    table.add_column("Severity", style="bold")
    table.add_column("Type")
    table.add_column("File:Line", style="cyan")
    table.add_column("Value Preview")
    if decode:
        table.add_column("Decoded Preview", style="dim")

    for f in findings:
        sev = SEVERITY.get(f["type"], f["severity"])
        row = [sev, f["type"], f"{f['file']}:{f['line']}", f["value"]]
        if decode:
            row.append(f.get("decoded", ""))
        table.add_row(*row)

    console.print(table)
    print_summary(
        {s: sum(1 for f in findings if f["severity"] == s) for s in ["CRITICAL", "HIGH", "MEDIUM"]},
        "Severity Breakdown",
    )

    if fail_on_find:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
