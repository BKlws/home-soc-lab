# Attack Simulations

This document defines validation scenarios used to test detection logic within the SOC Lab.

Each scenario maps directly to detections defined in **detections.md (D1–D8)**.

---

## Success Criteria

A simulation is considered successful when:

* Detection signal is visible in Grafana dashboards
* Corresponding alert fires in Prometheus
* Alert is received via Alertmanager (email)

---

## Simulation Model

Each scenario includes:

* Execution
* Expected Signals
* Dashboards
* Alerts
* Analyst Value
* Potential False Positives
* Verification

---

# Core Scenarios

---

## S1 — DNS Anomaly Burst

### Execution

```bash
for i in {1..50}; do nslookup random$i.xyz TARGET_DNS=LAB_DNS_IP > /dev/null; done
```

### Expected Signals

* NXDOMAIN spike
* Rare domain spike
* Suspicious TLD spike

### Dashboards

* SOC – DNS Analysis → NXDOMAIN spike
* SOC – DNS Analysis → Rare domain spike detected
* SOC – DNS Analysis → Suspicious TLD activity
* SOC – Overview → NXDOMAIN Rate

### Alerts

* NXDOMAIN_Spike
* Rare_Domain_Surge
* Suspicious_TLD_Spike

### Analyst Value

Demonstrates detection of DGA-like DNS behavior and ability to distinguish abnormal domain patterns from normal traffic.

### Potential False Positives

* browser DNS prefetching
* misconfigured services
* application retry logic

### Verification

* Confirm spike in Grafana panels
* Check Prometheus alerts (`/api/v1/alerts`)
* Validate Alertmanager email

---

## S2 — External Recon (Nmap Scan)

### Execution

```bash
nmap -p 1-1000 TARGET_HOST=LAB_TARGET_IP
```

### Expected Signals

* High flow count
* Increased port distribution

### Dashboards

* SOC – Flow Analysis → Top Source IPs by Flow Count
* Network Traffic Analysis → Destination ports by flow count
* Network Traffic Analysis → High destination ports by flow count

### Alerts

* Flow_Anomaly

### Analyst Value

Demonstrates ability to detect scanning behavior based on flow volume and port distribution.

### Potential False Positives

* vulnerability scans
* monitoring tools
* load testing

### Verification

* Identify source IP spike in flow panels
* Confirm alert firing
* Validate increase in destination ports

---

## S3 — Bandwidth Spike

### Execution

```
wget http://example.com/testfile.zip
```

### Expected Signals

* Traffic spike

### Dashboards

* SOC – Flow Analysis → Top Destination IPs by Traffic
* Network Traffic Analysis → External ASNs by bandwidth
* SOC – Overview → Top Destination Traffic

### Alerts

* Traffic_Spike

### Analyst Value

Demonstrates detection of abnormal traffic volume and ability to differentiate large transfers from normal behavior.

### Potential False Positives

* legitimate downloads
* updates
* streaming

### Verification

* Confirm spike in traffic panels
* Validate ASN or destination dominance
* Check alert firing

---

## S4 — Threat Intelligence Match

### Execution

```bash
# Add IOC, then:
curl http://<IOC_IP>
```

### Expected Signals

* Threat intelligence match

### Dashboards

* SOC – Overview → TI Alert Active
* SOC – Overview → TI Matches by Source

### Alerts

* Threat_Intel_Match

### Analyst Value

Demonstrates correlation of live traffic with known malicious indicators.

### Potential False Positives

* outdated IOC
* shared infrastructure
* benign flagged IPs

### Verification

* Confirm TI metric increase
* Check feed source attribution
* Validate alert firing

---

## S5 — Multi-stage Attack

### Execution

```bash
nmap -p 80,443 TARGET_HOST=LAB_TARGET_IP
curl http://example.com
for i in {1..20}; do nslookup random$i.xyz TARGET_DNS=LAB_DNS_IP > /dev/null; done
```

### Expected Signals

* Scan activity
* Traffic spike
* DNS anomaly

### Dashboards

* SOC – DNS Analysis panels
* SOC – Flow Analysis panels
* SOC – Overview

### Alerts

* NXDOMAIN_Spike
* Flow_Anomaly
* Traffic_Spike

### Analyst Value

Demonstrates ability to correlate multi-stage activity across DNS and network telemetry.

### Potential False Positives

* combined legitimate activity
* testing environments

### Verification

* Confirm multiple alerts triggered
* Validate cross-dashboard correlation
* Identify sequence of events

---

# Validation Matrix

| Scenario       | Detections | Alerts             | Notes                       |
| -------------- | ---------- | ------------------ | --------------------------- |
| S1 DNS Burst   | D1, D2, D3 | NXDOMAIN_Spike     | Strong DNS anomaly          |
| S2 Scan        | D5         | Flow_Anomaly  | Clear scanning behavior     |
| S3 Bandwidth   | D4         | Traffic_Spike      | High-volume transfer        |
| S4 TI          | D8         | Threat_Intel_Match | Direct IOC match            |
| S5 Multi-stage | D1–D5      | Multiple           | Correlated attack chain     |

---

# Future Validation Scenarios (Summary)

The following scenarios are planned but not included in v1.0:

* Repeated NXDOMAIN (misconfiguration)
* Beaconing Simulation
* Single suspicious TLD query
* Normal CDN traffic
* Slow scan (low and slow reconnaissance)
* Mixed DNS traffic
* Low & slow DGA
* TI + DNS correlation
* ASN anomaly
* Country anomaly

---

# Summary

These simulations demonstrate:

* controlled signal generation
* detection validation across DNS, flow, and TI
* alert verification via Prometheus and Alertmanager
* analyst-driven investigation workflows

They validate the SOC Lab as an operational detection and analysis environment.

