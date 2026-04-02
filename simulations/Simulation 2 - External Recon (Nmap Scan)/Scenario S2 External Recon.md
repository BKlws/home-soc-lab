### Scenario: S2 — External Recon (Nmap Scan)

Execution:

nmap -p 1-1000 10.0.0.1

Observed Behavior:

-No visible changes were observed across:
* SOC Overview dashboard
* Flow Analysis dashboard
* Network Traffic Analysis dashboard

No panels showed a clear spike or anomaly.

Signals:
- NXDOMAIN spike? (no)
- Flow spike? (no, significant increase observed)
- TI hit? (no)
- Port activity anomaly → NOT DETECTED

Alerts:
- Which alerts fired?
none
- Time delay before firing?
none
- Any alerts missing?
none (based on current detection design)

Correlation:

No correlation observed across panels.

Unexpected Behavior:

* No indication of scanning activity in dashboards
* No increase in flow-based metrics despite scan execution

Technical Explanation:

This behavior is expected due to current system design:
* NetFlow aggregation may not capture short-lived scan traffic reliably
* Detection logic is based on volume thresholds, not behavioral patterns
* No detection exists for:
        high number of destination ports per source
        scan-like connection patterns


Verdict:

Expected non-detection (outside current detection scope)

Notes:
* The scan was likely too short and low-volume to trigger flow-based thresholds
* Current lab focuses on volumetric and DNS-based detections
* Detecting scans would require:
        port diversity metrics
        per-source connection pattern 
