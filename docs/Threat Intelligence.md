# Threat Intelligence

This document describes the threat intelligence integration implemented in the SOC Lab.

The design provides:

* IOC-based enrichment
* correlation with NetFlow telemetry
* Prometheus-based visibility
* alerting via Alertmanager

---

## 1. Overview

Threat intelligence is implemented using a local IOC file and automated correlation against observed network traffic.

Pipeline:

IOC file → ti_to_prom.py → Prometheus → Alertmanager

Workflow:

1. NetFlow telemetry is collected from the Cisco router
2. `ti_to_prom.py` reads recent flow data from the local nfdump cache
3. A local IOC file (`bad_ips.txt`) is loaded
4. Source and destination IPs are matched against the IOC list
5. Matches are exported as Prometheus metrics
6. Prometheus evaluates alert rules
7. Alertmanager routes notifications

This provides:

* enrichment of network telemetry
* visibility into known-bad infrastructure
* actionable alerting on IOC matches

---

## 2. Data Source

### IOC File

```text
/opt/threatintel/bad_ips.txt
```

### Supported Format

```text
1.2.3.4
1.2.3.4,abuseipdb
1.2.3.4|otx
1.2.3.4 spamhaus
```

Blank lines and comments (`#`) are ignored.

---

## 3. Feed Model (v1.0)

The v1.0 implementation uses a **locally managed IOC list with source attribution**.

Supported feed sources include:

* AbuseIPDB
* AlienVault OTX
* Spamhaus

These are represented as labels within the IOC file.

This design demonstrates:

* feed attribution
* metric labeling
* alert correlation

Live API ingestion is intentionally deferred to v2.0.

---

## 4. Processing Logic

Threat intelligence matching is performed by:

```text
ti_to_prom.py
```

The script:

* loads IOC data from `bad_ips.txt`
* parses recent NetFlow records
* extracts source and destination IPs
* matches both sides of each flow against IOC entries
* exports structured Prometheus metrics

This ensures that both inbound and outbound communication with malicious infrastructure is detected.

---

## 5. Exported Metrics

The TI pipeline exports multiple metrics to support detection, analysis, and attribution:

* `ti_malicious_ip_hits_total`
* `ti_recent_malicious_hits_5m`
* `ti_malicious_source_ip_hits`
* `ti_malicious_destination_ip_hits`
* `ti_top_matched_bad_ip_hits`
* `ti_matches_by_feed_source`
* `ti_distinct_malicious_source_ips`
* `ti_distinct_malicious_destination_ips`

These metrics allow:

* detection of new IOC matches
* visibility into most active malicious IPs
* attribution to feed sources
* differentiation between source and destination behavior

---

## 6. Dashboards

Relevant panels:

**SOC – Overview**

* TI Alert Active
* TI Matches by Source

These provide:

* immediate visibility of active TI alerts
* attribution of matches by feed source

---

## 7. Alerting

Prometheus rule:

```promql
increase(ti_malicious_ip_hits_total[5m]) > 0
```

Alert:

* **Threat_Intel_Match**

Triggered when new malicious IP activity is observed within the 5-minute window.

---

## 8. Analyst Interpretation

Threat intelligence answers:

> “Did any recent traffic involve infrastructure already known to be malicious or suspicious?”

Interpretation guidelines:

* single match → requires validation
* repeated matches → higher confidence
* recent spike → immediate attention

Key validation questions:

* Is the IP internal or external?
* Is it a source or destination?
* Does it match expected behavior?

---

## 9. Detection vs Enrichment

Threat intelligence is treated as an **enrichment signal**, not a standalone verdict.

IOC matches must be interpreted together with:

* DNS anomalies
* NetFlow behavior
* ASN and geographic context
* frequency and timing

---

## 10. Source Attribution Behavior

The metric:

```promql
sum by (feed_source) (ti_matches_by_feed_source)
```

may display feed sources even when no active matches exist.

This is by design:

* zero-value series are emitted for configured feeds
* ensures panels remain visible
* distinguishes “no matches” from “missing data”

---

## 11. Limitations

The v1.0 implementation has known limitations:

* static IOC list (no automated feed updates)
* no feed freshness tracking
* no confidence scoring
* no deduplication or expiry logic
* IP-based correlation only
* Low-volume port scans are not reliably detected due to NetFlow aggregation and lack of behavioral detection logic
* Bandwidth events are confirmed in raw NetFlow data but may not always be clearly visible in Grafana due to top-N aggregation and lack of time-window delta metrics.

These are acceptable for v1.0 because the goal is to demonstrate:

* enrichment logic
* telemetry correlation
* alertable TI workflow

---

IOC Limitation:

IOC-based detection alone is insufficient.

Attackers frequently rotate infrastructure, making IP-based matching unreliable as a primary detection method.

In this lab, threat intelligence is used as an enrichment signal alongside behavioral detections (DNS and NetFlow).

---

## 12. Security and Publication Notes

The public repository should not include:

* real IOC data
* sensitive telemetry
* operational secrets

Instead use:

* sanitized IOC examples
* placeholder feeds
* documented integration steps

---

## 13. Future Improvements (v2.0)

Planned enhancements:

* live API-based feeds
* confidence scoring
* feed freshness tracking
* deduplication and expiry
* domain and ASN-based enrichment
* external reputation enrichment

These improvements are valuable but not required for v1.0.

---

## Summary

The threat intelligence component provides:

* enrichment of network telemetry
* detection of known malicious infrastructure
* alertable correlation via Prometheus

It demonstrates:

* pipeline-level integration
* SOC-relevant enrichment logic
* practical detection support for investigations

