
from datetime import timedelta

from src.detector import (
    detect_failed_logon_bursts,
    detect_interesting_processes,
    parse_timestamp,
)


def correlate_incident(evidence, correlation_window_minutes=10):
    """
    Correlate synthetic authentication, process and network evidence.

    Correlation uses shared endpoint names and timestamps.
    It does not claim that matching events prove causation.
    """
    auth_events = evidence["authentication"]
    process_events = evidence["process"]
    network_events = evidence["network"]

    auth_alerts = detect_failed_logon_bursts(auth_events)
    process_alerts = detect_interesting_processes(process_events)

    incidents = []

    for auth_alert in auth_alerts:
        account = auth_alert.get("username")
        host = auth_alert.get("computer")
        auth_time = parse_timestamp(auth_alert.get("successful_logon"))

        if auth_time is None:
            continue

        start_time = auth_time - timedelta(
            minutes=correlation_window_minutes
        )
        end_time = auth_time + timedelta(
            minutes=correlation_window_minutes
        )

        related_processes = []
        for event in process_events:
            event_time = parse_timestamp(event.get("timestamp"))

            if (
                event.get("username") == account
                and event.get("computer") == host
                and event_time is not None
                and start_time <= event_time <= end_time
            ):
                related_processes.append(event)

        related_network = []
        for event in network_events:
            event_time = parse_timestamp(event.get("timestamp"))

            if (
                event.get("computer") == host
                and event_time is not None
                and start_time <= event_time <= end_time
            ):
                related_network.append(event)

        related_process_alerts = [
            alert for alert in process_alerts
            if alert.get("username") == account
            and alert.get("computer") == host
            and alert.get("event_id") in {
                event.get("event_id") for event in related_processes
            }
        ]

        evidence_summary = [
            {
                "type": "authentication",
                "event_id": auth_alert.get("success_event_id"),
                "detail": (
                    f"{auth_alert.get('failed_attempts')} failed logons "
                    f"preceded a successful logon for {account}."
                ),
            }
        ]

        for event in related_processes:
            evidence_summary.append({
                "type": "process",
                "event_id": event.get("event_id"),
                "detail": event.get("command_line", "Process created"),
            })

        for event in related_network:
            evidence_summary.append({
                "type": "network",
                "event_id": event.get("event_id"),
                "detail": (
                    f"{event.get('source')} telemetry: "
                    f"{event.get('src_ip')} -> {event.get('dest_ip')}:{event.get('dest_port')}"
                ),
            })

        incidents.append({
            "incident_id": f"INC-{len(incidents) + 1:03d}",
            "title": "Suspicious authentication with related endpoint/network activity",
            "account": account,
            "host": host,
            "source_ip": auth_alert.get("source_ip"),
            "successful_logon": auth_alert.get("successful_logon"),
            "authentication_alert": auth_alert,
            "related_process_count": len(related_processes),
            "related_process_alert_count": len(related_process_alerts),
            "related_network_count": len(related_network),
            "evidence": evidence_summary,
            "assessment": (
                "Suspicious sequence requiring analyst investigation. "
                "Correlation establishes temporal and host-level relationships, "
                "not proof of compromise or causation."
            ),
        })

    return incidents


if __name__ == "__main__":
    from src.loader import load_all_evidence

    evidence = load_all_evidence()
    incidents = correlate_incident(evidence)

    print("\nCORRELATED INCIDENT FINDINGS")
    print("=" * 65)

    if not incidents:
        print("No correlated incidents generated.")
    else:
        for incident in incidents:
            print(f"\n{incident['incident_id']}: {incident['title']}")
            print(f"Account: {incident['account']}")
            print(f"Host: {incident['host']}")
            print(
                f"Related processes: {incident['related_process_count']}"
            )
            print(
                f"Related process alerts: "
                f"{incident['related_process_alert_count']}"
            )
            print(
                f"Related network records: {incident['related_network_count']}"
            )

            for item in incident["evidence"]:
                print(
                    f"  [{item['type'].upper()}] "
                    f"{item['event_id']}: {item['detail']}"
                )

            print(f"Assessment: {incident['assessment']}")
