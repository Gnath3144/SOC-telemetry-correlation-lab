# SOC Detective - Correlated Incident Finding Report

**Case ID:** CASE-DAY4-001
**Generated (UTC):** 2026-10-29T11:19:57.920711+00:00
**Environment:** Synthetic training environment

## Executive Summary

The synthetic evidence contains a suspicious authentication sequence with related endpoint and network activity. Further validation is required before declaring a confirmed compromise.

## Evidence Reviewed

- Total events: 16
- Correlated incidents: 1

- Authentication: 8 events
- Process: 5 events
- Network: 3 events

## Incident Findings

### INC-001: Suspicious authentication with related endpoint/network activity

- **Account:** svc_backup
- **Host:** WS-FIN-023
- **Authentication source:** 198.51.100.23
- **Successful logon:** 2026-10-29T10:00:16Z
- **Related process records:** 4
- **Related network records:** 2

**Evidence timeline:**

- `AUTH-006` (authentication): 5 failed logons preceded a successful logon for svc_backup.
- `PROC-001` (process): whoami.exe /all
- `PROC-002` (process): ipconfig.exe /all
- `PROC-003` (process): net.exe user
- `PROC-004` (process): powershell.exe -NoProfile -Command "Get-Service"
- `NET-001` (network): Suricata telemetry: 192.0.2.45 -> 203.0.113.77:443
- `NET-002` (network): Zeek telemetry: 192.0.2.45 -> 203.0.113.77:443

**Assessment:**

Suspicious sequence requiring analyst investigation. Correlation establishes temporal and host-level relationships, not proof of compromise or causation.

## Recommended Next Steps

- Validate the account owner and whether the activity was expected.
- Review original Windows and endpoint event records.
- Verify network connections using trusted sensor data.
- Check relevant account privileges and recent account changes.
- Escalate according to the organisation's incident response process.

## Limitations

- All records are fictional and intended for training.
- Correlation by host and time does not prove causation.
- The authentication and network source IP addresses differ.
- The rules are illustrative and are not production-tuned.
- No live SIEM or endpoint collection system was queried.

## Reproducibility

This report was generated from the project's synthetic JSON evidence files using the Python detection and correlation pipeline.

No live systems were accessed or modified.
