# Detection Engineering

This document defines the detection logic implemented in the SOC Lab.

All detections are based on:

* DNS telemetry (dnsmasq → dns_to_prom.sh → Prometheus)
* NetFlow telemetry (Cisco C1121 → nfdump → nfdump_to_prom.sh → Prometheus)
* Threat intelligence correlation (ti_to_prom.py)

Dashboards are the primary analysis interface:

* SOC – DNS Analysis
* SOC – Flow Analysis
* Network Traffic Analysis
* SOC – Overview

---

## Detection Model

The SOC Lab distinguishes between:

**Detection Signals**

* Time-based anomaly indicators using PromQL (e.g. `increase(...[5m])`)

**Operator Context Panels**

* Ranking and aggregation panels (e.g. `topk(...)`) used for investigation

**Health / Pipeline Signals**

* Exporter freshness and system health indicators

---

## Time Window Standard

All time-based detections use a **5-minute observation window** unless stated otherwise.

---

## Alerting

All detections are:

* defined in `alerts.yml`
* evaluated by Prometheus
* routed through Alertmanager

---

## Severity Mapping (Lab Model)

Severity reflects how urgently an alert should be handled in a SOC context.

- Critical → immediate action (e.g. Threat Intelligence match)
- High → strong anomaly requiring investigation (e.g. scanning behavior)
- Medium → suspicious activity requiring monitoring (e.g. DNS anomalies)
- Low → informational or context-dependent signals (e.g. traffic spikes)

Severity in this lab is illustrative and not tied to asset criticality.

---

## D1 — NXDOMAIN Spike Detection

### Data Sources

* `dns_nxdomain_total`

### Dashboards

* SOC – DNS Analysis → NXDOMAIN Count
* SOC – DNS Analysis → NXDOMAIN spike
* SOC – Overview → NXDOMAIN Rate

### Detection Logic

```promql
increase(dns_nxdomain_total[5m])
```

### Threshold Example

* <5 → normal
* 5–20 → suspicious
* > 20 → alert condition

### Alert

NXDOMAIN_Spike

### Analyst Interpretation

Sustained spikes indicate:

* DGA / beaconing
* repeated failed lookups
* misconfigured applications

### Potential False Positives

* software updates
* browser DNS prefetching
* misconfigured services

---

## D2 — Rare Domain Detection

### Data Sources

* `dns_rare_domain_total`

### Dashboards

* SOC – DNS Analysis → Rare DNS domains
* SOC – DNS Analysis → Rare domain spike detected
* SOC – Overview → Rare Domains (5m)

### Detection Logic

```promql
increase(dns_rare_domain_total[5m])
```

### Threshold Example

* <10 → normal
* 10–30 → unusual
* > 30 → strong anomaly

### Alert

Rare_Domain_Surge

### Analyst Interpretation

High volume of one-time domains:

* beaconing
* staging infrastructure
* automated domain generation

### Potential False Positives

* ad tracking domains
* telemetry endpoints
* content delivery edge cases

---

## D3 — Suspicious TLD Detection

### Data Sources

* `dns_suspicious_tld_total`

### Dashboards

* SOC – DNS Analysis → Suspicious TLD Queries
* SOC – DNS Analysis → Suspicious TLD activity
* SOC – Overview → Suspicious TLD Activity

### Detection Logic

```promql
increase(dns_suspicious_tld_total[5m])
```

### Threshold Example

* 0 → normal
* 1–10 → low signal
* > 10 → suspicious

### Alert

Suspicious_TLD_Spike

### Analyst Interpretation

Indicates interaction with:

* low-cost infrastructure
* phishing or malware domains

### Potential False Positives

* new legitimate domains
* startup / test environments
* marketing campaign domains

---

## D4 — Traffic / Bandwidth Anomaly

### Data Sources

* `netflow_dst_bytes_mb`
* `netflow_src_bytes_mb`

### Dashboards (Context)

* SOC – Flow Analysis → Top Destination IPs by Traffic
* SOC – Flow Analysis → Top Source IPs by Traffic
* Network Traffic Analysis → External source IPs by bandwidth

### Detection Logic (Time-Based)

```promql
increase(netflow_dst_bytes_mb[5m])
```

### Threshold Example

* baseline dependent
* sudden spike vs normal traffic → anomaly

### Alert

Traffic_Spike

### Analyst Interpretation

Potential:

* large download
* exfiltration-like activity
* abnormal service usage

### Potential False Positives

* software updates
* backups
* streaming or downloads

---

## D5 — High Flow Count / Scanning

### Data Sources

* `netflow_src_flows`

### Dashboards (Context)

* SOC – Flow Analysis → Top Source IPs by Flow Count
* SOC – Flow Analysis → Top Destination Ports
* Network Traffic Analysis → External source IPs by flow count

### Detection Logic (Time-Based)

```promql
increase(netflow_src_flows[5m])
```

### Threshold Example

* baseline dependent
* sudden spike in flow count → suspicious

### Alert

High_Flow_Anomaly

### Analyst Interpretation

Likely:

* port scanning
* brute-force attempts
* automated tooling

### Potential False Positives

* load testing
* monitoring tools
* bursty applications

---

## D6 — ASN Anomaly Detection

### Data Sources

* `netflow_src_asn_flows`
* `netflow_src_asn_bytes_mb`

### Dashboards (Context)

* Network Traffic Analysis → External ASNs by flow count
* Network Traffic Analysis → External ASNs by bandwidth

### Detection Logic

```promql
topk(10, netflow_src_asn_flows)
```

### Threshold Example

* New ASN not seen in last 24h → investigate
* Sudden ASN volume spike (>2x baseline) → suspicious

### Alert

ASN_Anomaly

### Analyst Interpretation

New or dominant ASN:

* infrastructure change
* suspicious provider
* unexpected traffic source

### Potential False Positives

* new CDN nodes
* cloud provider scaling
* legitimate infrastructure changes

---

## D7 — Country Anomaly Detection

### Data Sources

* `netflow_src_country_bytes_mb`

### Dashboards (Context)

* Network Traffic Analysis → External countries by traffic
* SOC – Overview → Top Country Traffic

### Detection Logic

```promql
topk(10, netflow_src_country_bytes_mb)
```

### Threshold Example

* New country appears → low signal
* Sudden dominant country → suspicious

### Alert

Country_Anomaly

### Analyst Interpretation

Unusual geography:

* new communication pattern
* suspicious region interaction

### Potential False Positives

* global services
* CDN routing changes
* VPN usage

---

## D8 — Threat Intelligence Match

### Data Sources

* `ti_malicious_ip_hits_total`
* `ti_matches_by_feed_source`

### Dashboards

* SOC – Overview → TI Alert Active
* SOC – Overview → TI Matches by Source

### Detection Logic

```promql
increase(ti_malicious_ip_hits_total[5m])
```

### Threshold

* ≥1 → critical

### Alert

Threat_Intel_Match

### Analyst Interpretation

* Direct match with known malicious IP
* Requires immediate validation and triage

### Potential False Positives

* outdated IOC
* shared infrastructure
* benign services previously flagged

---

## Summary

The detection set covers:

* DNS anomalies
* network flow anomalies
* threat intelligence correlation

All detections are:

* observable via dashboards
* alertable via Prometheus
* actionable via defined workflow


Baseline Consideration:
Thresholds are based on observed lab behavior.
In production, baselines would be derived from historical data and adjusted per environment.
