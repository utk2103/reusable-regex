"""Structured logging with rich."""
import logging
from rich.logging import RichHandler


def get_logger(name: str = "reusable-regex") -> logging.Logger:
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, markup=True)],
    )
    return logging.getLogger(name)
