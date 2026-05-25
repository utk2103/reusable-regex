"""Uvicorn/systemd log parser — strips syslog noise, extracts signal."""
import re
from dataclasses import dataclass, field
from enum import Enum


class LineType(str, Enum):
    HTTP     = "http"
    APP_LOG  = "app_log"
    STRUCT   = "structured"
    WARNING  = "warning"
    TRACEBACK= "traceback"
    RAW      = "raw"


# ── Core patterns ────────────────────────────────────────────────────────────

# Strips: "May 25 09:54:25 ip-172-31-14-253 uvicorn[647066]: "
SYSLOG_PREFIX = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+\S+\[\d+\]:\s*'
)

# After prefix — uvicorn HTTP access line
# INFO:     14.143.254.194:0 - "GET /api/path HTTP/1.1" 200 OK
HTTP_LINE = re.compile(
    r'INFO:\s+'
    r'(\d{1,3}(?:\.\d{1,3}){3}):\d+'    # group 1: client IP
    r'\s+-\s+"'
    r'(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|PRI)\s+'  # group 2: method
    r'([^\s"]+)'                          # group 3: path (no query yet)
    r'[^"]*"\s+'
    r'(\d{3})'                            # group 4: status code
)

# After prefix — structured app log: "11:16:00 | WARNING | message"
STRUCTURED_LOG = re.compile(
    r'(\d{2}:\d{2}:\d{2})\s+\|\s+'
    r'(INFO|WARNING|ERROR|DEBUG|CRITICAL)\s+\|\s+'
    r'(.*)'
)

# After prefix — bare uvicorn WARNING/ERROR (not HTTP)
BARE_LEVEL = re.compile(r'^(WARNING|ERROR|CRITICAL):\s+(.*)')

# Traceback detection
TRACEBACK_START = re.compile(
    r'Traceback \(most recent call last\)|Exception Group Traceback|ExceptionGroup:'
)
RUNTIME_ERROR   = re.compile(r'^(RuntimeError|ValueError|TypeError|KeyError|AttributeError):\s+(.*)')

BREAKDOWN = [
    ("[bold cyan]SYSLOG_PREFIX[/]",   r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+\[\d+\]:\s* — strips date/hostname/pid noise"),
    ("[bold yellow]HTTP_LINE[/]",     r'INFO:\s+IP:\d+\s+-\s+"METHOD PATH HTTP/x" STATUS — captures ip/method/path/status'),
    ("[bold green]STRUCTURED_LOG[/]", r"HH:MM:SS | LEVEL | message — app-level structured logs"),
    ("[bold red]BARE_LEVEL[/]",       r"WARNING|ERROR: message — raw uvicorn warnings"),
    ("[bold magenta]TRACEBACK_START[/]",r"Traceback (most recent call last) — collapses multi-line tracebacks to one line"),
]

DESCRIPTION = "Uvicorn + systemd log parser — strips prefix noise, classifies HTTP/app/warning/traceback lines"
NAME = "uvicorn_logs"


# ── Match dataclass ──────────────────────────────────────────────────────────

@dataclass
class LogMatch:
    line_type: LineType
    time: str          = ""
    client_ip: str     = ""
    method: str        = ""
    path: str          = ""
    status: int        = 0
    level: str         = ""
    message: str       = ""
    raw: str           = ""
    line_no: int       = 0

    @property
    def is_error(self) -> bool:
        return self.status >= 400 or self.level in ("WARNING", "ERROR", "CRITICAL")

    @property
    def is_4xx(self) -> bool:
        return 400 <= self.status < 500

    @property
    def is_5xx(self) -> bool:
        return self.status >= 500


# ── Parser ───────────────────────────────────────────────────────────────────

class UvicornLogPattern:
    name        = NAME
    description = DESCRIPTION
    breakdown   = BREAKDOWN

    @classmethod
    def parse(
        cls,
        text: str,
        skip_options: bool = True,
        skip_2xx: bool = False,
        collapse_tracebacks: bool = True,
    ) -> list[LogMatch]:
        results: list[LogMatch] = []
        lines = text.splitlines()
        i = 0

        while i < len(lines):
            raw = lines[i]
            i += 1

            prefix_m = SYSLOG_PREFIX.match(raw)
            timestamp = ""
            body = raw

            if prefix_m:
                # syslog date like "May 25 09:54:25" → keep only HH:MM:SS
                parts = prefix_m.group(1).split()
                timestamp = parts[-1]  # HH:MM:SS
                body = raw[prefix_m.end():]
            else:
                # no syslog prefix — might be continuation / structured log
                body = raw.lstrip()

            # ── Traceback block ──────────────────────────────────────────────
            if collapse_tracebacks and TRACEBACK_START.search(body):
                tb_lines = [body]
                while i < len(lines):
                    peek = lines[i]
                    peek_body = peek[SYSLOG_PREFIX.match(peek).end():] if SYSLOG_PREFIX.match(peek) else peek
                    # traceback block ends when we see a non-indented, non-pipe line
                    if peek_body and not peek_body[0] in (' ', '|', '+', '^') and not RUNTIME_ERROR.match(peek_body):
                        break
                    tb_lines.append(peek_body)
                    i += 1
                # grab the root cause — strip traceback prefix chars (|, +, spaces)
                def _clean(s: str) -> str:
                    return re.sub(r'^[\s|+]*', '', s)

                cause = next(
                    (l for l in reversed(tb_lines) if RUNTIME_ERROR.match(_clean(l))),
                    tb_lines[-1],
                )
                cause = _clean(cause)
                results.append(LogMatch(
                    line_type=LineType.TRACEBACK,
                    time=timestamp,
                    level="ERROR",
                    message=f"[{len(tb_lines)} traceback lines] → {cause.strip()}",
                    raw=raw,
                    line_no=i,
                ))
                continue

            # ── HTTP access line ─────────────────────────────────────────────
            http_m = HTTP_LINE.match(body)
            if http_m:
                method = http_m.group(2)
                status = int(http_m.group(4))
                if skip_options and method == "OPTIONS":
                    continue
                if skip_2xx and 200 <= status < 300:
                    continue
                results.append(LogMatch(
                    line_type=LineType.HTTP,
                    time=timestamp,
                    client_ip=http_m.group(1),
                    method=method,
                    path=http_m.group(3),
                    status=status,
                    raw=raw,
                    line_no=i,
                ))
                continue

            # ── Structured app log ───────────────────────────────────────────
            struct_m = STRUCTURED_LOG.match(body)
            if struct_m:
                lvl = struct_m.group(2)
                results.append(LogMatch(
                    line_type=LineType.STRUCT,
                    time=struct_m.group(1),
                    level=lvl,
                    message=struct_m.group(3),
                    raw=raw,
                    line_no=i,
                ))
                continue

            # ── Bare WARNING / ERROR ─────────────────────────────────────────
            bare_m = BARE_LEVEL.match(body)
            if bare_m:
                results.append(LogMatch(
                    line_type=LineType.WARNING,
                    time=timestamp,
                    level=bare_m.group(1),
                    message=bare_m.group(2),
                    raw=raw,
                    line_no=i,
                ))
                continue

            # ── Non-HTTP INFO lines (custom prints, S3 URLs, etc.) ───────────
            if body.startswith("INFO:") or body.startswith("http"):
                # e.g. bare S3 URL, or INFO: startup message
                results.append(LogMatch(
                    line_type=LineType.APP_LOG,
                    time=timestamp,
                    level="INFO",
                    message=body.strip(),
                    raw=raw,
                    line_no=i,
                ))
                continue

            # ── Anything else — drop or keep as RAW ─────────────────────────
            # (indented traceback continuations already consumed above)

        return results

    @classmethod
    def errors_only(cls, text: str) -> list[LogMatch]:
        return [m for m in cls.parse(text) if m.is_error]
