#!/usr/bin/env python3
import os
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path
from time import time

LOG_PATH = Path("/var/log/dnsmasq.log")
OUT_PATH = Path("/var/lib/node_exporter/textfile_collector/dns.prom")
RECENT_LINES = 5000

# Example suspicious TLDs used for detection logic (non-exhaustive)
SUSPICIOUS_TLDS = (
    ".top", ".xyz", ".tk", ".cc", ".click", ".work",
    ".gq", ".ml", ".ga", ".cf", ".zip", ".mov",
    ".cam", ".rest", ".fit", ".surf"
)

QUERY_RE = re.compile(r"query\[(?P<qtype>[^\]]+)\]\s+(?P<domain>\S+)\s+from\s+(?P<client>\S+)")
REPLY_RE = re.compile(r"(?:reply|cached)\s+(?P<domain>\S+)\s+is\s+(?P<answer>.+)$", re.IGNORECASE)

def esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')

def normalize_domain(domain: str) -> str:
    return domain.rstrip(".").lower()

def is_suspicious_tld(domain: str) -> bool:
    d = normalize_domain(domain)
    return d.endswith(SUSPICIOUS_TLDS)

def read_lines(path: Path):
    if not path.exists():
        return []
    try:
        return path.read_text(errors="replace").splitlines()
    except Exception:
        return []

def prom_help_type(lines, name, help_text, metric_type="gauge"):
    lines.append(f"# HELP {name} {help_text}")
    lines.append(f"# TYPE {name} {metric_type}")

def prom_metric(lines, name, value, labels=None):
    if labels:
        rendered = ",".join(f'{k}="{esc(str(v))}"' for k, v in labels.items())
        lines.append(f"{name}{{{rendered}}} {value}")
    else:
        lines.append(f"{name} {value}")

def main():
    all_lines = read_lines(LOG_PATH)
    recent = all_lines[-RECENT_LINES:]

    # Totals over the whole current log file (good for increase(...[5m]) style panels)
    total_query_lines = 0
    total_reply_lines = 0
    total_nxdomain = 0
    total_suspicious_tld = 0

    for line in all_lines:
        q = QUERY_RE.search(line)
        if q:
            total_query_lines += 1
            if is_suspicious_tld(q.group("domain")):
                total_suspicious_tld += 1

        if REPLY_RE.search(line):
            total_reply_lines += 1

        low = line.lower()
        if "nxdomain" in low:
            total_nxdomain += 1

    # Snapshot-style metrics over the recent window
    domain_counts = Counter()
    qtype_counts = Counter()
    client_counts = Counter()
    suspicious_domain_counts = Counter()
    answer_counts = Counter()

    for line in recent:
        q = QUERY_RE.search(line)
        if q:
            domain = normalize_domain(q.group("domain"))
            qtype = q.group("qtype")
            client = q.group("client")

            domain_counts[domain] += 1
            qtype_counts[qtype] += 1
            client_counts[client] += 1

            if is_suspicious_tld(domain):
                suspicious_domain_counts[domain] += 1

        r = REPLY_RE.search(line)
        if r:
            answer = r.group("answer").strip()
            answer_counts[answer] += 1

    rare_domains = {d: c for d, c in domain_counts.items() if c == 1}

    out_lines = []

    prom_help_type(out_lines, "dns_exporter_last_run_unixtime", "Last successful run of dns_to_prom.sh")
    prom_metric(out_lines, "dns_exporter_last_run_unixtime", int(time()))

    prom_help_type(out_lines, "dns_log_recent_lines", "Number of dnsmasq log lines inspected in the recent snapshot window")
    prom_metric(out_lines, "dns_log_recent_lines", len(recent))

    prom_help_type(out_lines, "dns_query_line_total", "Total number of DNS query lines observed in the current dnsmasq log file")
    prom_metric(out_lines, "dns_query_line_total", total_query_lines)

    prom_help_type(out_lines, "dns_reply_line_total", "Total number of DNS reply lines observed in the current dnsmasq log file")
    prom_metric(out_lines, "dns_reply_line_total", total_reply_lines)

    prom_help_type(out_lines, "dns_nxdomain_total", "Total number of NXDOMAIN-style lines observed in the current dnsmasq log file")
    prom_metric(out_lines, "dns_nxdomain_total", total_nxdomain)

    prom_help_type(out_lines, "dns_suspicious_tld_total", "Total number of suspicious-TLD query lines observed in the current dnsmasq log file")
    prom_metric(out_lines, "dns_suspicious_tld_total", total_suspicious_tld)

    prom_help_type(out_lines, "dns_top_domain_queries", "DNS query counts per domain in the recent snapshot window")
    for domain, count in domain_counts.items():
        prom_metric(out_lines, "dns_top_domain_queries", count, {"domain": domain})

    prom_help_type(out_lines, "dns_query_type_total", "DNS query counts per query type in the recent snapshot window")
    for qtype, count in qtype_counts.items():
        prom_metric(out_lines, "dns_query_type_total", count, {"qtype": qtype})

    prom_help_type(out_lines, "dns_queries_by_client", "DNS query counts per client in the recent snapshot window")
    for client, count in client_counts.items():
        prom_metric(out_lines, "dns_queries_by_client", count, {"client": client})

    prom_help_type(out_lines, "dns_suspicious_tld_queries", "Suspicious-TLD query counts per domain in the recent snapshot window")
    for domain, count in suspicious_domain_counts.items():
        prom_metric(out_lines, "dns_suspicious_tld_queries", count, {"domain": domain})

    prom_help_type(out_lines, "dns_resolved_answers", "DNS reply counts per resolved answer value in the recent snapshot window")
    for answer, count in answer_counts.items():
        prom_metric(out_lines, "dns_resolved_answers", count, {"answer": answer})

    prom_help_type(out_lines, "dns_rare_domain_total", "Number of domains queried exactly once in the recent snapshot window")
    prom_metric(out_lines, "dns_rare_domain_total", len(rare_domains))

    prom_help_type(out_lines, "dns_rare_domain_queries", "Domains queried exactly once in the recent snapshot window")
    for domain in rare_domains:
        prom_metric(out_lines, "dns_rare_domain_queries", 1, {"domain": domain})

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile("w", dir=str(OUT_PATH.parent), delete=False) as tmp:
        tmp.write("\n".join(out_lines))
        tmp.write("\n")
        tmp_path = Path(tmp.name)

    os.chmod(tmp_path, 0o644)
    os.replace(tmp_path, OUT_PATH)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
