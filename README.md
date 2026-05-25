# reusable-regex

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![pytest](https://img.shields.io/badge/tested%20with-pytest-orange)

Production-ready regex + IOC extraction toolkit for security engineers.

Extract IPv4 addresses, emails, URLs, cryptographic hashes, AWS credentials, JWTs, and base64 payloads from any text — log files, breach dumps, sandbox reports, or source code — with a single command.

---

## Features

- **7 battle-tested patterns**: IPv4, email, URL, MD5/SHA1/SHA256 hashes, AWS keys, JWT tokens, Base64 payloads
- **3 purpose-built CLIs**: `ioc-extract`, `log-scan`, `secret-detect`
- **Rich terminal output**: color-coded tables, severity panels, regex breakdowns
- **Multiple export formats**: JSON, CSV, plain text
- **CI-friendly**: `--fail` flag returns exit code 1 when secrets are found
- **Deduplication and unique extraction** built into every pattern
- **Realistic sample files** for testing and demos

---

## Installation

```bash
git clone https://github.com/yourname/reusable-regex
cd reusable-regex

pip install -e .
# or just install deps without entry points:
pip install -r requirements.txt
```

For development (includes pytest):

```bash
pip install -e ".[dev]"
```

---

## Quick Demo

Run IOC extraction against the included access log sample:

```bash
ioc-extract samples/access_logs.txt
```

The command prints a Rich table for each pattern that finds matches — IPv4 addresses in one table, URLs in another — followed by a summary panel showing match counts per pattern type. Use `--type ipv4` to narrow to a single pattern, `--unique` to deduplicate, and `--format json` to get machine-readable output.

Scan a directory of logs recursively:

```bash
log-scan samples/ --recursive --lines
```

Detect secrets in source code with CI exit code:

```bash
secret-detect . --recursive --decode --fail
```

---

## Pattern Reference

| Pattern | Regex Anchors | Use Case |
|---------|--------------|----------|
| **IPv4** | `\b...\b` | C2 IPs in proxy logs, firewall events, SIEM alerts |
| **Email** | `\b...\b` | Breach dumps, phishing headers, OSINT |
| **URL** | `https?://` prefix | Proxy logs, PCAPs, malware sandbox output |
| **MD5** | `\b[a-fA-F0-9]{32}\b` | Malware file hashes, IOC feeds |
| **SHA1** | `\b[a-fA-F0-9]{40}\b` | Certificate thumbprints, legacy IOC feeds |
| **SHA256** | `\b[a-fA-F0-9]{64}\b` | EDR alerts, VirusTotal lookups |
| **AWS Key ID** | `(AKIA\|ASIA\|AROA\|...)` prefix | Credential leaks in source code, CI/CD logs |
| **JWT** | `eyJ...eyJ...` structure | Auth logs, Authorization headers, localStorage dumps |
| **Base64** | Lookbehind/lookahead guards | PowerShell droppers, encoded C2 configs |

---

## CLI Reference

### `ioc-extract`

Extract IOCs from any file or stdin.

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--type` | `-t` | `all` | Filter to one pattern: `ipv4`, `email`, `url`, `hash`, `aws_key`, `base64`, `jwt` |
| `--format` | `-f` | `table` | Output format: `table`, `json`, `csv`, `txt` |
| `--output` | `-o` | — | Write results to file |
| `--unique` | `-u` | false | Deduplicate results |
| `--explain` | `-e` | false | Print annotated regex breakdown |
| `--quiet` | `-q` | false | Suppress decorative output (use with `--format json` for piping) |

```bash
# Extract all IOCs, export JSON
ioc-extract breach_dump.txt --format json --output outputs/extracted_results/iocs.json

# Unique IPs only, pipe-friendly
ioc-extract access.log --type ipv4 --unique --format json --quiet | jq '.ipv4[]'

# Show regex anatomy
ioc-extract sample.txt --type hash --explain
```

### `log-scan`

Scan log files or directories, grouped by file.

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--recursive` | `-r` | false | Recurse into subdirectories |
| `--min-hits` | — | `1` | Only show files with at least N total matches |
| `--lines` | `-l` | false | Print each matching line beneath the file row |

```bash
log-scan /var/log/nginx/ --recursive --min-hits 5
log-scan samples/ --lines
```

### `secret-detect`

Detect hardcoded secrets (AWS keys, JWTs, base64 blobs).

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--recursive` | `-r` | false | Recurse into subdirectories |
| `--decode` | `-d` | false | Attempt to decode base64/JWT payloads and show preview |
| `--fail` | — | false | Exit with code 1 if any finding (CI gate) |

```bash
# CI pipeline gate
secret-detect . --recursive --fail

# Interactive review with decoded content
secret-detect src/ config/ --recursive --decode
```

---

## Pattern Breakdown

Every pattern class exposes a `BREAKDOWN` list of `(token, explanation)` tuples. Pass `--explain` to `ioc-extract` to render them as color-coded panels in the terminal.

Example — IPv4 breakdown rendered by `--explain`:

```
Regex Breakdown: ipv4
  \b               → Word boundary — no partial matches inside strings
  (?:...\.){3}     → Non-capturing group repeated 3x for first three octets + dot
  25[0-5]          → Matches 250-255
  2[0-4]\d         → Matches 200-249
  [01]?\d\d?       → Matches 0-199 (leading zero optional)
  \b               → Closing word boundary
```

This is intentionally educational — the breakdown makes the pattern auditable without requiring the reader to parse raw regex.

---

## Running Tests

```bash
pytest
# with coverage:
pytest --cov=regex_patterns --cov=utils --cov=cli
```

Tests cover valid/invalid cases, deduplication, line number tracking, and hash type disambiguation (SHA256 must not also fire MD5/SHA1 on the same span).

---

## Sample Files

| File | Contents |
|------|---------|
| `samples/access_logs.txt` | Apache access log with IPs, URLs, base64 user agents |
| `samples/breach_dump.txt` | Email:hash pairs in various formats |
| `samples/proxy_logs.txt` | Squid proxy log with timestamps, IPs, full URLs |
| `samples/malware_payloads.txt` | Base64 blobs, obfuscated URLs, hash IOCs, fictional AWS keys |
| `samples/auth_logs.txt` | Linux `auth.log` with SSH brute-force, sudo events, JWT in headers |

All sample data is **fictional** — no real credentials, no real infrastructure.

---

## Roadmap

- [ ] CIDR range support (e.g. match all IPs in `10.0.0.0/8`)
- [ ] YARA rule export from extracted IOCs
- [ ] Shodan API integration for live IP enrichment
- [ ] Web UI (FastAPI + Next.js) for drag-and-drop analysis
- [ ] IPv6 pattern
- [ ] Domain/hostname pattern (non-URL context)
- [ ] GCP and Azure credential patterns

---

## License

MIT — see [LICENSE](LICENSE).
