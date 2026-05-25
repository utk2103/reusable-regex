# Real-World Use Cases

Three concrete scenarios where this toolkit pays for itself in a security workflow.

---

## 1. SOC Analyst: Hunting C2 IPs in Proxy Logs

**Scenario**: The SOC receives a threat intel feed naming several IP addresses associated with an APT campaign. The analyst needs to determine whether any internal hosts communicated with those IPs in the last 30 days of Squid proxy logs stored as flat files.

**Workflow**:

1. Extract all destination IPs from proxy logs across a directory tree.
2. Cross-reference against the threat intel IP list.
3. Identify which internal hosts initiated connections.

**Command**:

```bash
# Scan all .log files recursively, show matching lines for triage
log-scan /var/log/squid/ --recursive --lines

# Extract unique IPs to a file for cross-referencing
ioc-extract /var/log/squid/access.log --type ipv4 --unique --format txt --output outputs/extracted_results/c2_ips.txt

# Or pipe directly into a lookup script
ioc-extract /var/log/squid/access.log --type ipv4 --unique --format json --quiet | python3 scripts/check_threat_intel.py
```

**What the toolkit does**: The IPv4 pattern's strict octet validation (0–255) prevents false positives on version strings like `1.2.3.4.5` or log format artifacts. The `--unique` flag deduplicates thousands of connections to dozens of distinct IPs before the lookup.

---

## 2. DevSecOps: Scanning Repos for AWS Credential Leaks

**Scenario**: A developer accidentally committed an `.env` file containing AWS credentials to a feature branch before it was merged to main. The security team needs to (a) confirm what was exposed and (b) establish whether any other repos in the org contain similar leaks.

**Workflow**:

1. Run secret detection across all source code and config files.
2. Exit with code 1 if anything is found so CI fails the build.
3. Decode any suspicious base64 blobs to check for embedded configs.

**Command**:

```bash
# CI pipeline gate — fails the build if any secrets found
secret-detect . --recursive --fail

# Interactive review with decoded payloads for base64 blobs
secret-detect src/ config/ --recursive --decode

# Export findings for incident ticket
ioc-extract . --type aws_key --recursive --format json --output outputs/extracted_results/aws_leak_report.json
```

**What the toolkit does**: The AWS access key pattern anchors on known prefixes (`AKIA`, `ASIA`, etc.), which encodes the key type in the identifier itself — this nearly eliminates false positives compared to matching any 20-char uppercase string. The secret key pattern uses context anchoring (looking for `aws_secret_access_key =`) to find the 40-char value. The `--fail` flag makes `secret-detect` return exit code 1, which any CI system interprets as a build failure.

---

## 3. DFIR Analyst: Extracting IOCs from Malware Sandbox Output

**Scenario**: A suspected malware sample has been detonated in a sandbox. The sandbox exports a multi-thousand-line report containing network connections, dropped files, registry modifications, decoded strings, and process trees. The DFIR analyst needs to extract all IOCs in under a minute for enrichment in the SIEM.

**Workflow**:

1. Run full IOC extraction across the sandbox report.
2. Export to JSON for automated SIEM ingestion.
3. Decode any base64 or JWT blobs found in the report to inspect embedded configs.

**Command**:

```bash
# Full extraction — all IOC types — exported as JSON
ioc-extract sandbox_report.txt --format json --output outputs/extracted_results/iocs.json

# Deduplicated IPs and URLs only (for quick firewall block list)
ioc-extract sandbox_report.txt --type ipv4 --unique --format txt --output outputs/extracted_results/block_ips.txt
ioc-extract sandbox_report.txt --type url --unique --format txt --output outputs/extracted_results/block_urls.txt

# Check for embedded secrets with decoded preview
secret-detect sandbox_report.txt --decode

# Show regex breakdown to understand what fired and why
ioc-extract sandbox_report.txt --type hash --explain
```

**What the toolkit does**: The hash extractor runs SHA256 → SHA1 → MD5 in that order with overlap detection, so a 64-char string is correctly classified as SHA256 rather than triggering MD5 and SHA1 matches against substrings. The `--explain` flag prints the annotated regex breakdown with Rich markup, useful for training junior analysts on why a particular string matched. The JSON output is directly ingestible by SIEM platforms like Splunk or Elastic.
