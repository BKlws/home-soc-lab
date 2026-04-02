### Scenario: <S3 — Bandwidth Spike>

Execution:
wget http://speedtest.tele2.net/100MB.zip

Observed Behavior:

Bandwidth events are confirmed in raw NetFlow data but may not always be clearly visible in Grafana due to top-N aggregation and lack of time-window delta metrics.

Signals:

NXDOMAIN spike → NO
Flow spike → NO (no strong increase observed)
TI hit → NO
Bandwidth spike → NOT clearly visible in dashboards

Alerts:

Alerts triggered → NONE
Delay → N/A
Missing alerts → No bandwidth-related alert exists in current design

Correlation:
No strong multi-panel correlation observed in Grafana.

The expected bandwidth spike was not clearly visible across:

Top Destination Traffic
External ASNs by bandwidth
Destination ports by bandwidth

Unexpected Behavior:
No visible bandwidth spike despite large download
No dominant destination IP shift in panels
Event was not clearly surfaced in dashboards

Technical Investigation:

Further analysis was performed to validate each stage of the pipeline:

Router export verified
NetFlow exporter counters increased during test
Network delivery verified
UDP/2055 packets observed via tcpdump
Collector validation
Completed nfdump files contained the wget traffic
Raw flow verification:

The following flows were confirmed in nfdump:

~90.7 MB inbound transfer from 90.130.70.73
~18.8 MB additional inbound transfer

This confirms the bandwidth event was fully captured at the NetFlow level.

Technical Explanation:

The lack of visible spike in Grafana is not caused by routing, export, or collection failure.

The root cause lies in the exporter and dashboard model:

NetFlow exporter publishes top-N aggregate snapshot metrics
Metrics such as netflow_dst_bytes_mb represent current top talkers
Short-lived bandwidth spikes may not dominate enough to appear clearly
No time-window delta (e.g. increase over 5m) is used for bandwidth panels

As a result:

The bandwidth event is present in raw flow data but is not clearly surfaced in dashboards.


Verdict:

Partial validation — bandwidth event confirmed in raw NetFlow data, but not clearly visible in Grafana due to aggregation and presentation limitations.

Notes:

* Initial assumption was telemetry failure; investigation proved otherwise
* This scenario highlights the importance of validating raw data vs dashboards
* Current design favors stable top-N visibility over short-lived event detection
* This reflects a realistic SOC challenge: data exists, but visibility depends on how it is aggregated and presented
