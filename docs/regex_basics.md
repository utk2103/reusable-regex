# Regex Fundamentals for Security Engineers

A working reference for the regex constructs used throughout this toolkit. Each concept is illustrated with examples drawn directly from the patterns in `regex_patterns/`.

---

## Anchors

Anchors match a position in the string, not a character.

**`\b` — word boundary**
Matches the boundary between a word character (`[A-Za-z0-9_]`) and a non-word character. This is critical for IOC extraction to avoid partial matches.

```
Pattern:  \b192\.168\.1\.1\b
Input:    "192.168.1.1 192.168.1.10"
Matches:  ["192.168.1.1"]   ← does NOT match 192.168.1.10
```

Without `\b`, `192.168.1.1` would also match inside `192.168.1.10`.

**`^` and `$` — line anchors**
`^` matches the start of a line; `$` matches the end. Used with `re.MULTILINE` to process log files line by line. The toolkit uses `.splitlines()` instead, which avoids needing `re.MULTILINE`.

**`(?=...)` and `(?!...)` — lookahead anchors**
Assertions that match a position where the pattern ahead does (or does not) match. No characters are consumed.

---

## Character Classes

A character class `[...]` matches exactly one character from the set.

| Syntax | Meaning |
|--------|---------|
| `[a-z]` | Any lowercase letter |
| `[A-Z]` | Any uppercase letter |
| `[0-9]` or `\d` | Any digit |
| `[a-fA-F0-9]` | Hex digit (used in all hash patterns) |
| `\w` | Word character: `[A-Za-z0-9_]` |
| `\s` | Whitespace: space, tab, newline |
| `[^...]` | Negated class — any char NOT in the set |

**Toolkit example — SHA256:**
```python
r'\b[a-fA-F0-9]{64}\b'
```
The class `[a-fA-F0-9]` matches any hex character; `{64}` requires exactly 64 of them.

**Toolkit example — URL path:**
```python
r'(?:/[^\s\'"<>]*)?'
```
`[^\s\'"<>]` matches any character that is NOT whitespace, quote, or an HTML angle bracket — a practical stop condition for URL extraction from HTML source.

---

## Quantifiers

Quantifiers control how many times the preceding element must match.

| Quantifier | Meaning |
|------------|---------|
| `*` | 0 or more |
| `+` | 1 or more |
| `?` | 0 or 1 (optional) |
| `{n}` | Exactly n times |
| `{n,}` | At least n times |
| `{n,m}` | Between n and m times (inclusive) |

All quantifiers are **greedy** by default (match as much as possible). Append `?` to make them lazy: `.*?`.

**Toolkit example — email local part:**
```python
r'[A-Za-z0-9._%+\-]+'
```
`+` requires at least one character. The class allows dots, underscores, percent signs, and hyphens, which covers the full range of valid email local parts found in breach data.

**Toolkit example — JWT signature:**
```python
r'[A-Za-z0-9_-]+'
```
Note `_` and `-` instead of `+` and `/`. JWT uses base64url encoding, which swaps those characters to make tokens safe in URLs and HTTP headers without percent-encoding.

---

## Groups: Capturing vs Non-Capturing

**Capturing group `(...)`** stores the matched substring, accessible via `m.group(1)`, `m.group(2)`, etc.

```python
SECRET_KEY_PATTERN = re.compile(
    r'(?i)(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*["\']?([A-Za-z0-9/+]{40})["\']?'
)
# m.group(1) gives just the 40-char secret, not the "aws_secret_access_key=" prefix
```

**Non-capturing group `(?:...)`** groups elements for quantifiers or alternation without storing the match. Use this when you don't need the captured value — it's slightly faster and avoids polluting group indices.

```python
# IPv4: non-capturing groups for the repeating octet pattern
r'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
```

The outer `(?:...){3}` repeats the group three times without capturing. The inner `(?:25[0-5]|2[0-4]\d|[01]?\d\d?)` handles the three alternation branches for valid octet ranges.

**Named group `(?P<name>...)`** — useful when accessing groups by name instead of index. Not used in this toolkit for simplicity, but worth knowing for complex patterns.

---

## Lookaheads and Lookbehinds

Lookarounds assert context without consuming characters. They are zero-width.

| Syntax | Type | Meaning |
|--------|------|---------|
| `(?=...)` | Positive lookahead | What follows must match |
| `(?!...)` | Negative lookahead | What follows must NOT match |
| `(?<=...)` | Positive lookbehind | What precedes must match |
| `(?<!...)` | Negative lookbehind | What precedes must NOT match |

**Toolkit example — base64 extraction:**
```python
r'(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{4})*...'
```
The negative lookbehind `(?<![A-Za-z0-9+/])` ensures the match doesn't start in the middle of a longer base64 string. Without it, you'd get overlapping fragments.

```python
r'...(?![A-Za-z0-9+/=])'
```
The negative lookahead at the end prevents matching a prefix of a longer token.

---

## Flags

| Flag | `re` constant | Effect |
|------|--------------|--------|
| Case-insensitive | `re.IGNORECASE` or `re.I` | `[a-z]` also matches `[A-Z]` |
| Multiline | `re.MULTILINE` or `re.M` | `^`/`$` match line starts/ends |
| Dotall | `re.DOTALL` or `re.S` | `.` matches newlines too |
| Verbose | `re.VERBOSE` or `re.X` | Allows whitespace and `#` comments in patterns |

**Toolkit example — URL pattern uses `re.IGNORECASE`:**
```python
PATTERN = re.compile(
    r'https?://...',
    re.IGNORECASE,
)
```
This matches `HTTP://`, `HTTPS://`, and mixed-case variants seen in some log formats.

**AWS secret key uses inline flag `(?i)`:**
```python
r'(?i)(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]...'
```
Inline flags apply only within the pattern and are useful when you want case-insensitivity on part of a pattern, or when passing a pre-compiled object.

---

## Alternation

The pipe `|` separates alternatives. The engine tries each alternative left to right and stops at the first match. **Order matters**: place longer or more specific alternatives first.

**Toolkit example — IPv4 octet matching:**
```python
r'25[0-5]|2[0-4]\d|[01]?\d\d?'
```
`25[0-5]` is checked first (covers 250–255). If it fails, `2[0-4]\d` is tried (200–249). The fallback `[01]?\d\d?` covers 0–199. If `[01]?\d\d?` were listed first, it would also match `25` and `24`, making the other branches unreachable.

**Toolkit example — AWS key prefix alternation:**
```python
r'(AKIA|ASIA|AROA|AIDA|ANPA|ANVA|APKA)'
```
Each prefix encodes the key type in AWS's identity system: `AKIA` for long-term IAM user keys, `ASIA` for STS temporary credentials, etc. Anchoring on the prefix dramatically reduces false positives compared to matching any 20-char uppercase string.
