"""Load text from files, stdin, or raw strings."""
import sys
from pathlib import Path


def load_text(source: str | Path | None) -> str:
    """Load text from file path, '-' for stdin, or return source if it's already text."""
    if source is None:
        return sys.stdin.read()
    path = Path(source)
    if str(source) == "-":
        return sys.stdin.read()
    if path.exists():
        return path.read_text(encoding="utf-8", errors="replace")
    # treat as raw text (e.g. from piped string)
    return str(source)


def load_lines(source: str | Path | None) -> list[str]:
    return load_text(source).splitlines()


def iter_files(paths: list[Path], recursive: bool = False):
    """Yield (path, text) for each file, expanding directories."""
    for p in paths:
        if p.is_dir():
            pattern = "**/*" if recursive else "*"
            for f in sorted(p.glob(pattern)):
                if f.is_file():
                    yield f, f.read_text(encoding="utf-8", errors="replace")
        else:
            yield p, p.read_text(encoding="utf-8", errors="replace")
