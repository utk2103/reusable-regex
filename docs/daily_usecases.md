# Regex for Day-to-Day Engineering

Practical regex patterns and shell one-liners across four disciplines. Each section covers common problems, the regex, the shell equivalent, and when to pick one over the other.

---

## When to Use Regex vs Shell Scripting

| Situation | Prefer |
|-----------|--------|
| Ad-hoc search in terminal | Shell (`grep`, `sed`, `awk`) |
| Embedded in application code | Regex in Python/Go/Node |
| Complex multi-field extraction | `awk` or Python |
| Transform/replace in-place on files | `sed` |
| Validate user input at runtime | Compiled regex in app code |
| Pipeline chaining with other tools | Shell |
| Reuse across languages/services | Named regex pattern library |

**Rule of thumb**: if you're typing it once in a terminal, use shell tools. If it runs in code or CI, compile it as a proper regex with a name and tests.

---

## 1. Backend Engineering

### 1.1 Validate Email Addresses

**Pattern:**
```
^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$
```

**Python (application validation):**
```python
import re
EMAIL = re.compile(r'^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$')

def is_valid_email(addr: str) -> bool:
    return bool(EMAIL.match(addr))
```

**Shell (find invalid emails in a CSV dump):**
```bash
# Print lines that do NOT look like valid emails (column 3)
awk -F',' '{ if ($3 !~ /^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$/) print NR, $3 }' users.csv
```

**When to use which**: Validate in application code at the API boundary. Use shell when auditing a bulk data file once.

---

### 1.2 Extract UUIDs from Application Logs

**Pattern:**
```
[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}
```

**Shell:**
```bash
# Extract all UUIDs from a request log
grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' app.log | sort -u

# Count how many times each UUID appears (finding hot resources)
grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' app.log \
  | sort | uniq -c | sort -rn | head -20
```

**Python (tag a request trace):**
```python
import re
UUID_RE = re.compile(
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    re.IGNORECASE
)
uuids = UUID_RE.findall(log_line)
```

---

### 1.3 Parse HTTP Status Codes from Access Logs

**Pattern (match 5xx errors):**
```
\s(5\d{2})\s
```

**Shell:**
```bash
# Count 5xx errors by status code
grep -oE '\s5[0-9]{2}\s' access.log | tr -d ' ' | sort | uniq -c | sort -rn

# Show full log lines for 500s only
grep -E '" 500 ' access.log

# Alert if 500s exceed threshold in last 100 lines
count=$(tail -100 access.log | grep -cE '" 5[0-9]{2} ')
[ "$count" -gt 10 ] && echo "ALERT: $count server errors in last 100 requests"
```

**When to use which**: Shell one-liners for ops during incidents. Compile as regex in your log ingestion service for continuous alerting.

---

### 1.4 Scrub PII from API Responses Before Logging

**Pattern (phone numbers — US format):**
```
\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b
```

**Python (middleware redaction):**
```python
import re
PHONE_RE = re.compile(
    r'\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'
)

def redact_phones(text: str) -> str:
    return PHONE_RE.sub('[PHONE REDACTED]', text)
```

**Shell (one-time scrub of a log file):**
```bash
sed -E 's/(\+?1[-. ]?)?\(?[0-9]{3}\)?[-. ]?[0-9]{3}[-. ]?[0-9]{4}/[PHONE REDACTED]/g' raw.log > scrubbed.log
```

**When to use which**: Always redact in code before writing logs. Shell `sed` for retroactive cleanup of already-written files.

---

### 1.5 Match Semantic Version Strings

**Pattern:**
```
\bv?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([\w.\-]+))?(?:\+([\w.\-]+))?\b
```

**Shell:**
```bash
# Find all version strings referenced in a changelog
grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.\-]+)?' CHANGELOG.md

# Check if a package.json version is a pre-release
version=$(jq -r '.version' package.json)
echo "$version" | grep -qE '\-(alpha|beta|rc)\.' && echo "pre-release" || echo "stable"
```

---

## 2. DevOps

### 2.1 Validate Docker Image Tags in CI

**Pattern (disallow `latest` tag, require explicit version):**
```
^[a-z0-9]([a-z0-9\-._/]*[a-z0-9])?:[a-zA-Z0-9_.\-]+$
```

**Shell (CI gate script):**
```bash
IMAGE="$1"
# Reject if tag is "latest" or missing
if echo "$IMAGE" | grep -qE ':(latest)$|^[^:]+$'; then
  echo "ERROR: image must have explicit version tag, not 'latest'" >&2
  exit 1
fi
echo "OK: $IMAGE"
```

**Bash function (reusable in deploy scripts):**
```bash
validate_image_tag() {
  local image="$1"
  if [[ ! "$image" =~ ^[a-z0-9][a-z0-9._/-]*:[a-zA-Z0-9_.\-]+$ ]]; then
    echo "invalid image reference: $image" >&2
    return 1
  fi
  if [[ "$image" =~ :latest$ ]]; then
    echo "latest tag not allowed in production" >&2
    return 1
  fi
}
```

---

### 2.2 Extract Pod Names and Namespaces from kubectl Output

**Pattern (k8s pod name):**
```
[a-z0-9][a-z0-9\-]{0,251}[a-z0-9]
```

**Shell:**
```bash
# Get all crashlooping pods across all namespaces
kubectl get pods -A | grep -E 'CrashLoopBackOff|Error|OOMKilled' \
  | awk '{print $1, $2}'

# Extract just pod names matching a deployment prefix
kubectl get pods -n production | grep -oE 'api-server-[a-z0-9]+-[a-z0-9]+'

# Watch and alert on restarts exceeding threshold
kubectl get pods -A --no-headers | awk '$5 > 5 { print $1, $2, "restarts:", $5 }'
```

---

### 2.3 Parse Terraform Plan Output for Destructive Changes

**Shell (fail CI if plan contains destroys):**
```bash
# Count resources to be destroyed
destroy_count=$(terraform plan -no-color 2>&1 | grep -cE '^\s*-\s+')

if [ "$destroy_count" -gt 0 ]; then
  echo "WARN: plan will destroy $destroy_count resource(s)" >&2
  terraform plan -no-color 2>&1 | grep -E '^\s*-\s+' >&2
  exit 1
fi
```

**Extract changed resource addresses:**
```bash
terraform plan -no-color | grep -oE '(aws|google|azurerm|module)\.[a-zA-Z0-9_.\[\]"]+' | sort -u
```

---

### 2.4 Validate Environment Variable Names

**Pattern (POSIX-compliant env var name):**
```
^[A-Z_][A-Z0-9_]*$
```

**Shell (lint a `.env` file):**
```bash
# Find lines with invalid env var names (ignores comments and blank lines)
grep -vE '^\s*(#|$)' .env | grep -vE '^[A-Z_][A-Z0-9_]*=' | while read -r line; do
  echo "INVALID: $line"
done
```

**Python (validate before os.environ injection):**
```python
import re
ENV_VAR_NAME = re.compile(r'^[A-Z_][A-Z0-9_]*$')

def validate_env_vars(mapping: dict) -> list[str]:
    return [k for k in mapping if not ENV_VAR_NAME.match(k)]
```

---

### 2.5 Match CIDR Blocks in Network Config

**Pattern:**
```
\b((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)\/(3[0-2]|[12]?\d)\b
```

**Shell:**
```bash
# Extract all CIDR blocks from a Terraform vars file
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}' terraform.tfvars

# Find overly permissive rules (0.0.0.0/0)
grep -rE '0\.0\.0\.0/0' infra/ && echo "WARN: public CIDR found"
```

---

## 3. Logging and Monitoring

### 3.1 Parse Structured Log Lines (key=value format)

**Pattern (key=value pair):**
```
(\w+)=("([^"]*)"|(\S+))
```

**Shell:**
```bash
# Extract specific fields from structured logs
grep 'level=error' app.log | grep -oE 'request_id=\S+|user_id=\S+|duration_ms=\S+'

# Compute average duration from structured logs
grep 'level=info' app.log \
  | grep -oE 'duration_ms=[0-9]+' \
  | awk -F= '{ sum += $2; count++ } END { printf "avg: %.2f ms\n", sum/count }'
```

**Python (generic kv parser for log ingestion):**
```python
import re
KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')

def parse_kv_log(line: str) -> dict:
    return {
        m.group(1): m.group(2) or m.group(3)
        for m in KV_RE.finditer(line)
    }
```

---

### 3.2 Extract Timestamps from Mixed-Format Logs

**Patterns:**

| Format | Pattern |
|--------|---------|
| ISO 8601 | `\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z\|[+-]\d{2}:\d{2})?` |
| Nginx / Apache CLF | `\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}` |
| Syslog | `\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}` |
| Epoch ms | `\b1[0-9]{12}\b` |

**Shell:**
```bash
# Extract ISO timestamps from app log
grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}' app.log | head -5

# Show log lines from a specific hour
grep -E '2024-01-15T14:[0-9]{2}:[0-9]{2}' app.log

# Convert epoch ms to human-readable (macOS date)
grep -oE '\b1[0-9]{12}\b' app.log | head -1 | xargs -I{} bash -c 'date -r $(echo {} | cut -c1-10)'
```

---

### 3.3 Detect Error Spikes (Rate-Based Alerting)

**Shell (sliding window error rate check):**
```bash
#!/bin/bash
# Alert if error rate in last N lines exceeds threshold
LOGFILE="/var/log/app/app.log"
WINDOW=200
THRESHOLD=10

total=$(tail -"$WINDOW" "$LOGFILE" | wc -l)
errors=$(tail -"$WINDOW" "$LOGFILE" | grep -cE '"level"\s*:\s*"(error|fatal)"')
rate=$(( errors * 100 / total ))

if [ "$rate" -gt "$THRESHOLD" ]; then
  echo "ALERT: error rate ${rate}% (${errors}/${total}) in last ${WINDOW} lines" >&2
  exit 1
fi
```

---

### 3.4 Identify Slow Queries in Database Logs

**Pattern (PostgreSQL slow query log):**
```
duration: (\d+\.\d+) ms\s+statement: (.+)
```

**Shell:**
```bash
# Find queries slower than 1000ms
grep -E 'duration: [0-9]{4,}\.' postgresql.log | grep -oE 'duration: [0-9]+\.[0-9]+ ms'

# Top 10 slowest queries with duration
grep -oE 'duration: [0-9]+\.[0-9]+ ms  statement: .+' postgresql.log \
  | sort -t: -k2 -rn | head -10

# Extract just durations, compute stats with awk
grep -oE 'duration: [0-9]+\.[0-9]+' postgresql.log \
  | awk '{ sum+=$2; if($2>max) max=$2; count++ } END { printf "count=%d avg=%.1fms max=%.1fms\n", count, sum/count, max }'
```

---

### 3.5 Parse JSON Logs for Specific Fields

**Shell (using `grep` + `jq` combo):**
```bash
# Extract all error messages from JSON logs
grep '"level":"error"' app.log | jq -r '.message'

# Filter by time range and extract trace IDs
grep '"level":"error"' app.log \
  | jq -r 'select(.timestamp >= "2024-01-15T10:00:00") | .trace_id'

# Regex inside jq — find messages matching a pattern
cat app.log | jq -r 'select(.message | test("timeout|connection refused")) | [.timestamp, .level, .message] | @tsv'
```

**When to use which**: `grep` for pre-filtering large files before `jq` parses JSON — orders-of-magnitude faster than piping everything through `jq` directly.

---

## 4. Automation Tooling

### 4.1 Rename Files in Bulk (date-based patterns)

**Pattern (match YYYYMMDD in filenames):**
```
(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])
```

**Shell:**
```bash
# Rename report_20240115.csv → report_2024-01-15.csv
for f in report_????????.csv; do
  newname=$(echo "$f" | sed -E 's/report_([0-9]{4})([0-9]{2})([0-9]{2})\.csv/report_\1-\2-\3.csv/')
  mv "$f" "$newname"
done

# Find all files with old date format
find . -name '*[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]*' -type f
```

---

### 4.2 Extract Function/Method Names from Source Code

**Pattern (Python function definitions):**
```
^\s*(?:async\s+)?def\s+([a-zA-Z_]\w*)\s*\(
```

**Shell:**
```bash
# List all function names in a Python file
grep -oE '^\s*(async )?def [a-zA-Z_][a-zA-Z0-9_]+' service.py | awk '{print $NF}'

# Find all public functions (not starting with _) across the codebase
grep -rE '^\s*(async )?def [a-zA-Z][a-zA-Z0-9_]+\s*\(' src/ \
  | grep -vE 'def _' \
  | sed -E 's/.*def ([a-zA-Z][a-zA-Z0-9_]+)\s*\(.*/\1/' \
  | sort -u

# Count functions per file
grep -rncE '^\s*(async )?def ' src/ | sort -t: -k2 -rn | head -10
```

---

### 4.3 Parse CLI Argument Patterns in Scripts

**Pattern (long flags like `--output-dir`):**
```
--[a-z][a-z0-9\-]*(?:=\S+)?
```

**Shell (validate script received required flags):**
```bash
#!/bin/bash
# Check required flags are present
check_flag() {
  echo "$@" | grep -qE -- "--$1(=|\s)" || { echo "missing --$1" >&2; exit 1; }
}

check_flag "output" "$@"
check_flag "config" "$@"
```

**Shell (extract all flags from a help page for docs):**
```bash
my_tool --help | grep -oE '\-\-[a-z][a-z0-9\-]+' | sort -u
```

---

### 4.4 Find and Replace Config Values Across Files

**Shell (update version string across all YAML files):**
```bash
# Preview changes first
grep -rn 'image: myapp:' k8s/ | grep -oE 'myapp:[0-9.]+'

# Replace in-place (GNU sed)
find k8s/ -name '*.yaml' -exec sed -i -E 's/image: myapp:[0-9.]+/image: myapp:2.1.0/g' {} +

# macOS sed requires backup extension
find k8s/ -name '*.yaml' -exec sed -i '' -E 's/image: myapp:[0-9.]+/image: myapp:2.1.0/g' {} +
```

**Python (safer, with dry-run):**
```python
import re
from pathlib import Path

VERSION_RE = re.compile(r'image: myapp:[0-9.]+')
NEW_VALUE = 'image: myapp:2.1.0'

for yaml_file in Path('k8s').rglob('*.yaml'):
    content = yaml_file.read_text()
    new_content, count = VERSION_RE.subn(NEW_VALUE, content)
    if count:
        print(f"{yaml_file}: {count} replacement(s)")
        yaml_file.write_text(new_content)  # remove this line for dry-run
```

**When to use which**: Shell `sed` for speed on known-safe files. Python when you need dry-run, backup, or confirmation before mutating.

---

### 4.5 Watch Log Files and Trigger Actions

**Shell (tail + regex trigger):**
```bash
#!/bin/bash
# Tail a log and trigger an alert on pattern match
PATTERN='(FATAL|panic:|OOM killed|disk quota exceeded)'
LOGFILE='/var/log/app/app.log'

tail -F "$LOGFILE" | while IFS= read -r line; do
  if echo "$line" | grep -qE "$PATTERN"; then
    timestamp=$(date '+%Y-%m-%dT%H:%M:%S')
    echo "[$timestamp] ALERT: $line" >> /var/log/app/alerts.log
    # Hook: send to Slack, PagerDuty, etc.
    # curl -s -X POST "$SLACK_WEBHOOK" -d "{\"text\": \"ALERT: $line\"}"
  fi
done
```

---

### 4.6 Validate Config File Structure

**Shell (ensure all required keys present in `.env`):**
```bash
#!/bin/bash
REQUIRED_KEYS="DATABASE_URL REDIS_URL SECRET_KEY APP_ENV"

for key in $REQUIRED_KEYS; do
  if ! grep -qE "^${key}=" .env; then
    echo "MISSING: $key not set in .env" >&2
    exit 1
  fi
done
echo "OK: all required env vars present"
```

**Shell (detect duplicate keys in config):**
```bash
grep -E '^[A-Z_]+=.' .env | cut -d= -f1 | sort | uniq -d | while read -r key; do
  echo "DUPLICATE KEY: $key"
done
```

---

## Quick Reference: Shell Tools

| Tool | Best For | Regex Support |
|------|----------|---------------|
| `grep -E` | Find lines matching pattern | ERE (Extended) |
| `grep -P` | Perl-compatible features (lookaheads) | PCRE |
| `grep -o` | Extract matched text only | ERE/PCRE |
| `sed -E` | Find and replace in streams/files | ERE |
| `awk` | Field-based extraction, math, multi-column | ERE via `~` operator |
| `perl -pe` | Complex transforms, full PCRE | PCRE |
| `python3 -c` | Multi-step logic, named groups | Python `re` |

**When shell regex falls short, reach for Python**: lookaheads/lookbehinds in `grep -P` are PCRE but not available on macOS BSD grep. `perl -pe` or Python are portable alternatives for complex patterns.
