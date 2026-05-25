# Regex Cheatsheet

## Anchors

| Pattern | Matches |
|---------|---------|
| `^` | Start of string (or line with `re.M`) |
| `$` | End of string (or line with `re.M`) |
| `\b` | Word boundary (between `\w` and `\W`) |
| `\B` | Non-word boundary |
| `\A` | Absolute start of string |
| `\Z` | Absolute end of string |

## Character Classes

| Pattern | Matches |
|---------|---------|
| `.` | Any character except newline (use `re.S` to include newlines) |
| `\d` | Digit: `[0-9]` |
| `\D` | Non-digit: `[^0-9]` |
| `\w` | Word char: `[A-Za-z0-9_]` |
| `\W` | Non-word char |
| `\s` | Whitespace: space, tab, `\n`, `\r`, `\f`, `\v` |
| `\S` | Non-whitespace |
| `[abc]` | One of: a, b, or c |
| `[^abc]` | Any char except a, b, c |
| `[a-z]` | Range: lowercase letters |
| `[a-fA-F0-9]` | Hex digit |

## Quantifiers

| Pattern | Meaning |
|---------|---------|
| `*` | 0 or more (greedy) |
| `+` | 1 or more (greedy) |
| `?` | 0 or 1 (optional) |
| `{n}` | Exactly n times |
| `{n,}` | At least n times |
| `{n,m}` | Between n and m times |
| `*?` `+?` `??` | Lazy (non-greedy) versions |

## Groups

| Pattern | Meaning |
|---------|---------|
| `(...)` | Capturing group — access via `m.group(1)` |
| `(?:...)` | Non-capturing group — for quantifiers/alternation only |
| `(?P<name>...)` | Named capturing group — access via `m.group('name')` |
| `(?P=name)` | Back-reference to named group |
| `\1` `\2` | Back-reference to group by index |
| `a\|b` | Alternation: match a or b |

## Lookarounds (Zero-Width Assertions)

| Pattern | Type | Meaning |
|---------|------|---------|
| `(?=...)` | Positive lookahead | Must be followed by ... |
| `(?!...)` | Negative lookahead | Must NOT be followed by ... |
| `(?<=...)` | Positive lookbehind | Must be preceded by ... |
| `(?<!...)` | Negative lookbehind | Must NOT be preceded by ... |

Lookbehind patterns must have a fixed width in Python's `re` module.

## Flags

| Flag | Inline | Effect |
|------|--------|--------|
| `re.IGNORECASE` | `(?i)` | Case-insensitive matching |
| `re.MULTILINE` | `(?m)` | `^`/`$` match line boundaries |
| `re.DOTALL` | `(?s)` | `.` matches newlines |
| `re.VERBOSE` | `(?x)` | Whitespace and `#` comments in pattern |

## Escape Reference

| Literal | Escaped |
|---------|---------|
| `.` | `\.` |
| `*` `+` `?` | `\*` `\+` `\?` |
| `(` `)` | `\(` `\)` |
| `[` `]` | `\[` `\]` |
| `{` `}` | `\{` `\}` |
| `\` | `\\` |
| `^` `$` | `\^` `\$` |
| `\|` | `\\|` |

---

## Security Patterns Quick Reference

| Pattern | Name | Use Case |
|---------|------|----------|
| `\b(?:(?:25[0-5]\|2[0-4]\d\|[01]?\d\d?)\.){3}(?:25[0-5]\|2[0-4]\d\|[01]?\d\d?)\b` | IPv4 | C2 IPs in proxy logs, firewall events |
| `\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b` | Email | Breach dumps, phishing logs |
| `https?://(?:[-\w.]\|(?:%[\da-fA-F]{2}))+(?::\d+)?(?:/[^\s'"<>]*)?` | URL | Proxy logs, PCAPs, sandbox output |
| `\b[a-fA-F0-9]{32}\b` | MD5 | Malware file hashes, IOC feeds |
| `\b[a-fA-F0-9]{40}\b` | SHA1 | Certificate thumbprints, malware hashes |
| `\b[a-fA-F0-9]{64}\b` | SHA256 | VirusTotal lookups, EDR alerts |
| `\b(AKIA\|ASIA\|AROA\|AIDA\|ANPA\|ANVA\|APKA)[0-9A-Z]{16}\b` | AWS Key ID | Credential leaks in source code, CI logs |
| `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` | JWT | Auth logs, Authorization headers, localStorage |
| `(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==\|[A-Za-z0-9+/]{3}=\|[A-Za-z0-9+/]{4})` | Base64 | PowerShell droppers, encoded C2 configs |

### Pattern Notes

**IPv4**: The three-way alternation `25[0-5]|2[0-4]\d|[01]?\d\d?` is ordered longest-match-first to avoid `25` being consumed by the fallback branch before `25[0-5]` can match.

**Email**: Uses `\b` anchors; covers subdomains and `+` tags. Does not validate MX records.

**URL**: `re.IGNORECASE` flag handles `HTTP://` variants. Path stops at whitespace, quotes, and HTML angle brackets.

**Hashes**: Run SHA256 extraction before SHA1 and MD5 to avoid false positives — a 64-char hex string contains valid 32-char and 40-char substrings.

**JWT**: `eyJ` is the base64url encoding of `{"`, which every JWT header must start with. The underscore `_` and hyphen `-` in the character class distinguish base64url from standard base64.

**AWS Key**: Prefix (`AKIA`, `ASIA`, etc.) encodes key type. Matching on prefix + 16 uppercase alphanums cuts false positives to near zero.

**Base64**: Lookbehind/lookahead guards prevent fragment matching. Enforce a minimum length (16 chars) to filter noise.
