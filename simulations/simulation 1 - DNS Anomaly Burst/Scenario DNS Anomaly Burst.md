### Scenario: <DNS Anomaly Burst>

Execution:

```
for i in {1..50}; do nslookup random$i.xyz 10.0.0.50 > /dev/null; done
```

Observed Behavior:


Immediately after the execution, a visible increase occured in: 
   * Rare Domains (126 --> 148)
   * DNS Activity Rate

The change was near-instant in Grafana


These changes were immediately apparent.

Signals:
- NXDOMAIN spike? (no,0 observed)
- Flow spike? (no)
- TI hit? (no)
- Rare domain activity? (yes, significant increase)


Alerts:
- Which alerts fired?

Suspicious TLD Activity

- Time delay before firing?

1-2 minutes (evaluation + Alertmanager delay)

- Any alerts missing?

none confirmed


Correlation:
- Did multiple panels align?

* Rare Domains (5m) increased
* DNS Activity Rate increased
* DNS Analysis dashboard confirmed spike

This allowed quick pivot from overview -> DNS Analysis dashboard

- Or was it unclear?

Unexpected Behavior:

* "Active Alerts" panel did not reflect the triggered alert
=> caused by panel filtering mismatch (Rare_Domain_Surge vs Suspicious_TLD_Activity)

* NXDOMAIN panel remained at 0
+> expected, as queries resolved successfully



Verdict:
- clear detection (behavioral DNS anomaly)

Detection was:
    * fast
    * visible across multiple panels
    * correctly alerted

Notes:
- What made this easy or hard to interpret?

* Initial confusion came from dashboard familiarity, not detection quality
* Correlation between panels becomes clearer with experience
* Panel/alert alignment is critical for operational clarity
