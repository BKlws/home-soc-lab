# Investigation Workflow

This document defines the investigation and triage process used within the SOC Lab.

The workflow is designed to:

* analyze detected anomalies
* correlate telemetry sources
* guide consistent decision-making
* simulate real-world SOC analyst behavior

---

## 1. General Triage Workflow

When a detection is triggered, the analyst follows a structured process:

### Step 1 — Identify the Signal

* Which dashboard panel triggered?
* What type of detection is it?

  * DNS anomaly
  * Flow anomaly
  * Threat intelligence match
  * Pipeline / health issue

---

### Step 2 — Identify the Asset

* Determine:

  * source IP (internal system)
  * destination IP or domain

* Map to known system or role if possible

---

### Business Context Consideration

In a real SOC environment, impact is determined by:

- asset criticality (server vs workstation)
- user role (admin vs standard user)
- system function (production vs test)

This lab does not include asset classification, so impact is estimated generically.

---

### Step 3 — Classify the Anomaly

Determine behavior type:

* DNS anomaly (NXDOMAIN, rare domains, suspicious TLDs)
* flow anomaly (volume or connection count)
* scanning / reconnaissance
* threat intelligence match
* ASN / geographic anomaly

---

### Step 4 — Evaluate Time Behavior

Always evaluate:

* duration (seconds vs minutes vs hours)
* repetition pattern (single vs recurring)
* trend (increasing, stable, decreasing)

---

### Step 5 — Enrich the Context

Use available telemetry:

**Network context**

* destination IP
* ASN (provider)
* country

**DNS context**

* queried domains
* frequency
* NXDOMAIN behavior

**Threat intelligence**

* is the IP listed in bad_ips.txt?
* which feed source flagged it?

---

### Step 6 — Form a Hypothesis

Classify as:

* **Benign**

  * expected user or service activity

* **Misconfiguration**

  * failing service
  * repeated DNS failures

* **Suspicious**

  * abnormal pattern requiring monitoring

* **Potentially Malicious**

  * strong anomaly signals
  * multi-signal correlation

---

### Step 7 — Decide Action

* Close (benign)
* Monitor (track behavior over time)
* Escalate (requires deeper investigation)

---

## Correlation Priority

When multiple signals exist, prioritize:

1. Threat Intelligence match
2. Multi-signal anomaly (DNS + flow + ASN/country)
3. Single-signal anomaly

---

## 2. Investigation Walkthroughs

---

### Scenario 1 — DNS Anomaly Burst

**Trigger**

* SOC – Overview → NXDOMAIN Rate spike
* SOC – DNS Analysis → Rare domain spike detected
* SOC – DNS Analysis → Suspicious TLD activity

---

**Steps**

1. Identify domains:

   * SOC – DNS Analysis → Top Queried Domains
   * Confirm domains are random / one-time

2. Identify source:

   * determine originating system

3. Analyze pattern:

   * high NXDOMAIN rate
   * many unique domains
   * suspicious TLD usage

4. Correlate:

   * SOC – Flow Analysis → no major traffic spike

---

**Analysis**

Strong indication of DGA-like behavior based on:

* high NXDOMAIN rate
* unique domains
* suspicious TLD usage

---

**Verdict**

Suspicious

**Confidence**
Medium

**Impact**
Low

**Recommended Action**
Monitor and validate source system

---

**Confidence increases if:**

* repeated over time
* multiple hosts involved
* combined with TI matches

---

**Analyst Value**

Demonstrates ability to identify DGA-like behavior and distinguish it from normal DNS activity.

---

### Scenario 2 — Port Scan / Reconnaissance

**Trigger**

* SOC – Flow Analysis → Top Source IPs by Flow Count spike
* Network Traffic Analysis → Destination ports by flow count

---

**Steps**

1. Identify source IP

2. Identify port distribution:

   * wide range of ports
   * sequential probing

3. Analyze behavior:

   * many short-lived connections

4. Correlate:

   * presence across multiple flow panels

---

**Analysis**

Clear scanning behavior characterized by:

* high flow count
* broad port coverage
* short-lived connections

---

**Verdict**

Potentially Malicious

**Confidence**
High

**Impact**
Medium

**Recommended Action**
Investigate source system and block if necessary

---

**Analyst Value**

Demonstrates identification of reconnaissance activity and scanning patterns.

---

### Scenario 3 — Bandwidth / Traffic Spike

**Trigger**

* SOC – Flow Analysis → Top Destination IPs by Traffic spike
* Network Traffic Analysis → External ASNs by bandwidth

---

**Steps**

1. Identify destination IP

2. Analyze volume:

   * size of spike
   * duration

3. Enrich:

   * ASN and country
   * expected service or not

4. Correlate:

   * DNS queries for same service

---

**Analysis**

High-volume traffic observed.

---

**Verdict**

Suspicious

**Confidence**
Medium

**Impact**
Medium

**Recommended Action**
Validate destination and monitor activity

---

**Confidence increases if:**

* repeated large transfers
* unexpected destination
* combined DNS anomalies

---

**Analyst Value**

Demonstrates ability to differentiate benign large transfers from potential exfiltration.

---

### Scenario 4 — Threat Intelligence Match

**Trigger**

* SOC – Overview → TI Alert Active
* SOC – Overview → TI Matches by Source

---

**Steps**

1. Identify matched IP

2. Determine role:

   * source or destination

3. Check frequency:

   * single hit vs repeated

4. Enrich:

   * ASN and country
   * feed source

5. Correlate:

   * DNS and flow activity

---

**Analysis**

Direct interaction with known malicious indicator.

---

**Verdict**

Potentially Malicious

**Confidence**
High

**Impact**
High

**Recommended Action**
Immediate investigation and containment if confirmed

---

**Key Questions**

* Is the IP internal or external?
* Is it source or destination?
* Does it match expected behavior?

---

**Analyst Value**

Demonstrates ability to use threat intelligence as an enrichment signal and not a standalone verdict.

---

### Scenario 5 — Pipeline Degradation (Health)

**Trigger**

* SOC – Overview → Exporter Delay spike
* SOC – Health Monitor → Last Flow Timestamp stale

---

**Steps**

1. Check exporter freshness

2. Validate timestamps

3. Confirm ingestion activity

---

**Analysis**

Telemetry delay or pipeline issue, not attacker activity.

---

**Verdict**

Benign (System Issue)

**Confidence**
High

**Impact**
Medium

**Recommended Action**
Investigate pipeline health

---

**Analyst Value**

Demonstrates ability to distinguish infrastructure issues from security events.

---

## 3. MITRE ATT&CK Mapping

| Detection                 | MITRE Technique                                            |
| ------------------------- | ---------------------------------------------------------- |
| NXDOMAIN Spike            | T1071.004 (DNS), T1568 (Dynamic Resolution)                |
| Rare Domain Detection     | T1071.004, T1568                                           |
| Suspicious TLD Activity   | T1071.004                                                  |
| Bandwidth Spike           | T1041 (Exfiltration), T1105 (Ingress Tool Transfer)        |
| Flow / Scan Detection     | T1046 (Network Service Discovery), T1595 (Active Scanning) |
| Threat Intelligence Match | Context-dependent (enrichment-based)                       |

---

## 4. Workflow Summary

The SOC Lab investigation process is based on:

* anomaly detection
* context enrichment
* cross-telemetry correlation
* structured decision-making

This demonstrates:

* practical SOC analyst reasoning
* ability to investigate network-based signals
* readiness for real-world incident triage

