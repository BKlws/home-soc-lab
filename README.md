# Home SOC Lab v1.0

## Overview

This project implements a fully functional Security Operations Center (SOC) lab designed to demonstrate:

* Network telemetry collection (NetFlow + DNS)
* Data enrichment (ASN, GeoIP, Threat Intelligence)
* Detection engineering
* Alerting via Prometheus + Alertmanager
* Investigation workflows
* Attack simulation and validation

The lab is built as a **self-contained monitoring environment** running on a Raspberry Pi, with real telemetry ingestion and detection logic.

---

## Architecture

```
Network (Cisco C1121)
        │
        ▼
NetFlow Export (UDP 2055) + DNS Logs (dnsmasq)
        │
        ▼
Exporters (systemd timers)
    - nfdump_to_prom.sh
    - dns_to_prom.py
    - ti_to_prom.py
        │
        ▼
Node Exporter (textfile collector)
        │
        ▼
Prometheus (metrics + alert rules)
        │
        ▼
Alertmanager (email alerting)
        │
        ▼
Grafana (visualization + investigation)
```

---

## Infrastructure

* Monitoring host: Raspberry Pi 400
* Router: Cisco C1121 (NetFlow exporter)
* DNS telemetry: dnsmasq
* Metrics ingestion: node_exporter (textfile collector)
* Alerting: Prometheus + Alertmanager (email configured)
* Remote access: Tailscale VPN

---

## Dashboards

The lab contains five operational dashboards:

* SOC – Overview
* SOC – DNS Analysis
* SOC – Flow Analysis
* SOC – Health Monitor
* Network Traffic Analysis

### Screenshots


* SOC Overview
  <img width="991" height="658" alt="Screenshot from 2026-04-02 14-21-53" src="https://github.com/user-attachments/assets/d0fe14b9-6319-45a5-a9a5-1408cfb635ef" />


* DNS Analysis
<img width="1522" height="997" alt="SOC - DNS Analysis " src="https://github.com/user-attachments/assets/2e65c676-8b29-4c80-b3a3-158c58fbf6bb" />

* Flow Analysis
<img width="1522" height="997" alt="soc - Flow Analysis" src="https://github.com/user-attachments/assets/e0fae768-40d3-42c8-b9ea-98aa729148ee" />

* Health Monitor
<img width="1522" height="997" alt="soc - Health Monitor " src="https://github.com/user-attachments/assets/648ff53c-8275-44ee-80a9-af8d35ba652e" />

* Network Traffic Analysis
<img width="1617" height="998" alt="Network Traffic Analysis " src="https://github.com/user-attachments/assets/92c77757-a4be-45de-8f1d-e385ca0d0ec5" />

* Alertmanager
<img width="1229" height="550" alt="Screenshot from 2026-04-02 13-33-11" src="https://github.com/user-attachments/assets/5958f709-9e38-4f87-9e6b-e60bf9f58bba" />

* Email Alert
<img width="1756" height="953" alt="mail alert " src="https://github.com/user-attachments/assets/870332a7-cd20-4b03-8ff3-a09c5cce159d" />

---

## Detection Capabilities

The following alert rules are implemented and active:

* NXDOMAIN_Spike
* Suspicious_TLD_Activity
* Rare_Domain_Surge
* Traffic_Spike
* Flow_Anomaly
* Threat_Intel_Match

These detections are based on real telemetry and mapped directly to dashboard metrics.

---

## Threat Intelligence

* Source: Local IOC file (`/opt/threatintel/bad_ips.txt`)
* Enrichment: IP matching against NetFlow data
* Output: Prometheus metrics (`ti_matches_by_feed_source`)
* Alert: `Threat_Intel_Match`

---

## Validation Methodology

All detections were validated through controlled attack simulations.

Each scenario follows a structured approach:

* Execution (attack simulation)
* Expected telemetry signals
* Detection mapping
* Alert verification
* Analyst interpretation

---

## Simulated Attack Scenarios

### Core Scenarios (Fully Documented)

1. **DNS Anomaly Burst**

   ```
   for i in {1..50}; do nslookup random$i.xyz 10.0.0.50 > /dev/null; done
   ```

2. **External Reconnaissance (Port Scan)**

   ```
   nmap -p 1-1000 10.0.0.1
   ```

3. **Bandwidth Spike**

   ```
   wget http://speedtest.tele2.net/100MB.zip
   ```

4. **Threat Intelligence Match**

   ```
   curl http://<IOC_IP>
   ```

5. **Beaconing / Repeated Connections**

   ```
   for i in {1..100}; do curl http://1.1.1.1 > /dev/null; done
   ```

6. **Multi-stage Attack**

   ```
   nmap -p 80,443 10.0.0.1
   curl http://example.com
   for i in {1..20}; do nslookup random$i.xyz 10.0.0.50 > /dev/null; done
   ```

---

## Future Validation Scenarios

The following scenarios are defined but not fully documented:

* Repeated NXDOMAIN (misconfiguration)
* Single suspicious TLD query
* Normal CDN traffic baseline
* Slow / stealth scan
* Mixed DNS traffic
* Low & slow DGA
* TI + DNS correlation
* ASN anomaly
* Country anomaly

---

## Investigation Workflow

The lab supports a standard SOC workflow:

1. Alert appears in **SOC – Overview**
2. Analyst pivots to:

   * DNS Analysis (domain behavior)
   * Flow Analysis (network behavior)
   * Network Traffic Analysis (ASN / country / IP context)
3. Validate signal vs baseline
4. Correlate with Threat Intelligence
5. Determine:

   * False positive
   * Misconfiguration
   * Suspicious activity
   * Confirmed malicious behavior

---

## Automation

All exporters are automated using systemd timers:

* dns-to-prom.timer
* netflow-to-prom.timer
* ti-to-prom.timer

No cron jobs are used.

---

## Operational Considerations

This lab operates in a controlled environment.

In real SOC environments:

* Alerts arrive simultaneously
* Signals are incomplete
* False positives require tuning
* Prioritization is required

This lab demonstrates detection logic and investigation workflows, but not production-scale alert volume.

---

## Key Takeaways

This project demonstrates:

* End-to-end telemetry pipeline design
* Detection engineering based on real signals
* Practical alert validation through simulations
* Structured investigation workflows
* Operational awareness of monitoring systems

---

## Repository Structure

```
docs/               → Detection logic, simulations, workflows  
dashboards/         → Grafana dashboard JSON exports  
scripts/            → Exporters (NetFlow, DNS, Threat Intel)  
systemd/            → Service + timer definitions  
screenshots/        → Dashboard and alert visuals  
sample-data/        → Sanitized IOC data  
```

---

## Status

**Version:** v1.0 (Frozen)
**State:** Complete and validated

---
