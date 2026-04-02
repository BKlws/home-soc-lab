### Scenario: <S4 — Threat Intelligence Match>

Execution:


```
# Add IOC [ 90.130.70.73,speedtest ], then:
curl http://90.130.70.73
```

Observed Behavior:

- TI Alert Active → increased to 1 
- Threat_Intel_Match → fired 
- Email alert → received 
- TI Matches by Source → visible 

Signals:
- NXDOMAIN spike → No 
- Flow spike → No significant anomaly 
- TI hit → Yes (deterministic match)

Alerts:
- Alert Fired → Threat_Intel_Match  

- Time to detection → Delayed (flow export dependent)

- Alert frequency → Single alert despite multiple connections

Correlation:

Detection was isolated to Threat Intelligence panels.

No strong correlation with:
- NXDOMAIN Rate
- Suspicious TLD Activity
- Flow anomaly panels

This is expected for IOC-based detections.


Unexpected Behavior:
- Repeated connections to the same malicious IP did NOT generate multiple alerts.

- Detection occurred only once despite multiple curl/ping attempts.

- Alert timing was delayed and occurred after traffic completion.


Root Cause Analysis: 

The system operates on NetFlow data, which aggregates traffic into flows.

Multiple connections within a short time window are grouped into a single flow,
resulting in a single detection event instead of multiple alerts.

Flow export is governed by:
- Active timeout (60s)
- Inactive timeout (15s)

This introduces delay between traffic generation and detection.


Limitation identified: 

Detection is flow-based, not event-based.

This results in:
- No per-connection alerting
- No packet-level visibility
- Delayed alerting due to flow export timing


Interpretation:

This behavior is expected in NetFlow-based monitoring systems.

The detection confirms the presence of communication with a known malicious IP,
but does not reflect interaction frequency or session count.

Higher fidelity detection would require packet-based telemetry (e.g., Zeek).



Verdict:

Detection successful.

The system reliably detects known malicious IPs via threat intelligence matching.

However, detection granularity is limited by flow aggregation,
resulting in reduced visibility into repeated or high-frequency interactions.
