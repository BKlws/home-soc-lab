#!/usr/bin/env python3
import ipaddress
import os
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

FLOW_DIR = Path("/var/cache/nfdump")
BAD_IP_FILE = Path("/opt/threatintel/bad_ips.txt")
OUT_PATH = Path("/var/lib/node_exporter/textfile_collector/ti.prom")

LOOKBACK_MINUTES = 60
RECENT_MINUTES = 5
TOP_MATCH_LIMIT = 20


def esc(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def prom_help_type(lines, name, help_text, metric_type="gauge"):
    lines.append(f"# HELP {name} {help_text}")
    lines.append(f"# TYPE {name} {metric_type}")


def prom_metric(lines, name, value, labels=None):
    if labels:
        rendered = ",".join(f'{k}="{esc(v)}"' for k, v in labels.items())
        lines.append(f"{name}{{{rendered}}} {value}")
    else:
        lines.append(f"{name} {value}")


def load_bad_ips(path: Path):
    """
    Supported formats in bad_ips.txt:
      1.1.1.1
      1.1.1.1,abuseipdb
      1.1.1.1|abuseipdb
      1.1.1.1 abuseipdb

    Blank lines and lines starting with # are ignored.
    """
    bad = {}

    if not path.exists():
        return bad

    for raw in path.read_text(errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        feed_source = "bad_ips.txt"
        ip_part = line

        if "," in line:
            parts = [p.strip() for p in line.split(",", 1)]
            if len(parts) == 2:
                ip_part, feed_source = parts
        elif "|" in line:
            parts = [p.strip() for p in line.split("|", 1)]
            if len(parts) == 2:
                ip_part, feed_source = parts
        else:
            parts = line.split(None, 1)
            if len(parts) == 2:
                ip_part, feed_source = parts

        try:
            ipaddress.ip_address(ip_part)
        except ValueError:
            continue

        bad[ip_part] = feed_source

    return bad


def run_nfdump(minutes: int):
    """
    Ask nfdump for only source and destination IPs in CSV form.

    We use csv custom formatting so parsing stays simple:
      src_ip,dst_ip
    """
    cmd = [
        "nfdump",
        "-R", str(FLOW_DIR),
        "-t", f"now-{minutes}m",
        "-N",
        "-q",
        "-o", "csv:%sa,%da",
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=120,
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "nfdump failed")

    return result.stdout.splitlines()


def parse_flow_lines(lines):
    """
    Parse:
      sa,da
    while skipping headers/comments/empty lines.
    """
    flows = []

    for raw in lines:
        line = raw.strip()
        if not line:
            continue

        lower = line.lower()

        if lower.startswith("sa,da"):
            continue
        if lower.startswith("#"):
            continue
        if lower.startswith("summary"):
            continue

        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 2:
            continue

        src_ip, dst_ip = parts[0], parts[1]

        try:
            ipaddress.ip_address(src_ip)
            ipaddress.ip_address(dst_ip)
        except ValueError:
            continue

        flows.append((src_ip, dst_ip))

    return flows


def build_metrics(flows_all, flows_recent, bad_ips):
    src_hits = Counter()
    dst_hits = Counter()
    bad_ip_hits = Counter()
    feed_hits = Counter()

    recent_total_hits = 0

    for src_ip, dst_ip in flows_all:
        if src_ip in bad_ips:
            src_hits[src_ip] += 1
            bad_ip_hits[src_ip] += 1
            feed_hits[bad_ips[src_ip]] += 1

        if dst_ip in bad_ips:
            dst_hits[dst_ip] += 1
            bad_ip_hits[dst_ip] += 1
            feed_hits[bad_ips[dst_ip]] += 1

    for src_ip, dst_ip in flows_recent:
        if src_ip in bad_ips:
            recent_total_hits += 1
        if dst_ip in bad_ips:
            recent_total_hits += 1

    total_hits = sum(src_hits.values()) + sum(dst_hits.values())

    lines = []

    prom_help_type(lines, "ti_last_run_unixtime", "Last successful run of ti_to_prom.py")
    prom_metric(lines, "ti_last_run_unixtime", int(time.time()))

    prom_help_type(lines, "ti_feed_ip_count", "Number of bad IPs loaded from the threat intel feed file")
    prom_metric(lines, "ti_feed_ip_count", len(bad_ips))

    prom_help_type(lines, "ti_malicious_ip_hits_total", "Total source or destination flow hits involving listed bad IPs")
    prom_metric(lines, "ti_malicious_ip_hits_total", total_hits)

    prom_help_type(lines, "ti_recent_malicious_hits_5m", "Total source or destination flow hits involving listed bad IPs during the last 5 minutes")
    prom_metric(lines, "ti_recent_malicious_hits_5m", recent_total_hits)

    prom_help_type(lines, "ti_malicious_source_ip_hits", "Flow hits where the source IP matched a listed bad IP")
    for ip, count in src_hits.items():
        prom_metric(lines, "ti_malicious_source_ip_hits", count, {
            "ip": ip,
            "feed_source": bad_ips.get(ip, "bad_ips.txt"),
        })

    prom_help_type(lines, "ti_malicious_destination_ip_hits", "Flow hits where the destination IP matched a listed bad IP")
    for ip, count in dst_hits.items():
        prom_metric(lines, "ti_malicious_destination_ip_hits", count, {
            "ip": ip,
            "feed_source": bad_ips.get(ip, "bad_ips.txt"),
        })

    prom_help_type(lines, "ti_top_matched_bad_ip_hits", "Top matched listed bad IPs by total flow hits")
    for ip, count in bad_ip_hits.most_common(TOP_MATCH_LIMIT):
        prom_metric(lines, "ti_top_matched_bad_ip_hits", count, {
            "ip": ip,
            "feed_source": bad_ips.get(ip, "bad_ips.txt"),
        })

    prom_help_type(lines, "ti_matches_by_feed_source", "Flow hits grouped by threat intel feed source")

    # Emit zero-valued metrics for every known feed source, so Grafana panels
    # still render even when there are currently no matches.
    all_feed_sources = sorted(set(bad_ips.values()))
    for feed_source in all_feed_sources:
        prom_metric(lines, "ti_matches_by_feed_source", feed_hits.get(feed_source, 0), {
            "feed_source": feed_source,
        })

    prom_help_type(lines, "ti_distinct_malicious_source_ips", "Number of distinct listed bad source IPs observed in flows")
    prom_metric(lines, "ti_distinct_malicious_source_ips", len(src_hits))

    prom_help_type(lines, "ti_distinct_malicious_destination_ips", "Number of distinct listed bad destination IPs observed in flows")
    prom_metric(lines, "ti_distinct_malicious_destination_ips", len(dst_hits))

    return lines


def write_atomically(path: Path, lines):
    path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile("w", dir=str(path.parent), delete=False) as tmp:
        tmp.write("\n".join(lines))
        tmp.write("\n")
        tmp_path = Path(tmp.name)

    os.chmod(tmp_path, 0o644)
    os.replace(tmp_path, path)


def main():
    if not FLOW_DIR.exists():
        raise RuntimeError(f"Flow directory not found: {FLOW_DIR}")

    bad_ips = load_bad_ips(BAD_IP_FILE)
    if not bad_ips:
        raise RuntimeError(f"No valid bad IPs found in {BAD_IP_FILE}")

    flows_all = parse_flow_lines(run_nfdump(LOOKBACK_MINUTES))
    flows_recent = parse_flow_lines(run_nfdump(RECENT_MINUTES))

    metrics = build_metrics(flows_all, flows_recent, bad_ips)
    write_atomically(OUT_PATH, metrics)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
