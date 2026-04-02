### Scenario: S5 — Multi-stage Attack

Execution:

```bash
nmap -p 80,443 10.0.0.1
curl http://90.130.70.73
for i in {1..20}; do nslookup random$i.xyz 10.0.0.50 > /dev/null; done
```


Observed Behavior:

Clear multi-signal activity observed across DNS and Flow dashboards.

DNS panels reacted strongly:
- NXDOMAIN count increased significantly (~1900+)
- Rare DNS domains increased (peaking around ~19–29)
- Suspicious TLD queries increased (~400+)

Flow dashboards showed increased traffic:
- Internal destination traffic increased (notably 10.0.0.x hosts)
- External source/destination activity visible but not dominant

SOC Overview reflected:
- Rare Domains spike visible (~19+)
- Exporter delay stable (~18–60s)
- Flow ingestion stable (1.02 flow files)

Detection latency:
- DNS anomalies visible almost immediately (<10s)
- Alert triggered with slight delay (~30–60s)

Signals:
- NXDOMAIN spike: YES (high magnitude ~1900+)
- Flow spike: PARTIAL (visible but not dominant)
- TI hit: YES (1 match observed)
- Rare domains: YES (clear spike)
- Suspicious TLD: YES (strong signal)

Alerts:

Triggered alerts:
- Rare_Domain_Surge (warning)
- Threat_Intel_Match (critical)

Alert timing:
- Rare domain alert triggered first (fast detection)
- TI alert triggered after matching traffic

Missing alerts:
- No dedicated scan detection alert (expected limitation)

Correlation:

Strong correlation across multiple panels:

- NXDOMAIN spike aligns with rare domain increase
- Suspicious TLD activity confirms abnormal DNS behavior
- TI match confirms known malicious indicator
- Flow data provides supporting but secondary context

Overall: multi-layer detection (DNS + TI + Flow)

Unexpected Behavior:

Flow-based visibility was weaker than expected.

Reasons:
- NetFlow aggregates traffic, reducing scan visibility
- nmap activity not clearly distinguishable in flow metrics
- No dedicated scan detection logic implemented

Bandwidth impact was limited despite multi-stage activity.

Verdict:

PARTIAL → STRONG DETECTION

- DNS-based detections: STRONG
- Threat Intelligence: STRONG
- Flow-based detection: WEAK

Overall: attack successfully detected through correlation,
but not fully visible through all telemetry layers.

Notes:

This scenario demonstrates the strength of DNS-based detection.

Key insight:
- DNS telemetry is highly sensitive to abnormal behavior
- Flow telemetry provides context but lacks granularity

Detection quality depends on:
- Volume (NXDOMAIN + rare domains)
- Pattern (repeated queries)
- Enrichment (TI matching)

Limitation:
- Low-and-slow or scan-based behavior is not reliably detected via NetFlow alone
