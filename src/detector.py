
from datetime import datetime, timezone


def parse_timestamp(value):
    """Convert an ISO 8601 timestamp into a timezone-aware datetime."""
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))

        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)

        return parsed
    except (ValueError, TypeError):
        return None


def detect_failed_logon_bursts(auth_events, threshold=5, window_minutes=5):
    """
    Detect repeated failed logons followed by a successful logon
    from the same account and source IP within a time window.

    This is a triage heuristic, not proof of compromise.
    """
    alerts = []
    failures = [
        event for event in auth_events
        if event.get("windows_event_id") == 4625
    ]
    successes = [
        event for event in auth_events
        if event.get("windows_event_id") == 4624
    ]

    for success in successes:
        account = success.get("username")
        source_ip = success.get("source_ip")
        success_time = parse_timestamp(success.get("timestamp"))

        if not account or not source_ip or success_time is None:
            continue

        matching_failures = []

        for failure in failures:
            failure_time = parse_timestamp(failure.get("timestamp"))

            if failure_time is None:
                continue

            same_account = failure.get("username") == account
            same_source = failure.get("source_ip") == source_ip
            before_success = failure_time <= success_time
            within_window = (
                0 <= (success_time - failure_time).total_seconds()
                <= window_minutes * 60
            )

            if (
                same_account
                and same_source
                and before_success
                and within_window
            ):
                matching_failures.append(failure)

        if len(matching_failures) >= threshold:
            alerts.append({
                "rule_id": "AUTH-001",
                "title": "Repeated failed logons followed by success",
                "username": account,
                "source_ip": source_ip,
                "computer": success.get("computer"),
                "failed_attempts": len(matching_failures),
                "success_event_id": success.get("event_id"),
                "first_failure": min(
                    event["timestamp"] for event in matching_failures
                ),
                "successful_logon": success.get("timestamp"),
                "severity": "HIGH",
                "reason": (
                    f"{len(matching_failures)} failed logons were followed "
                    f"by a successful logon for {account} from {source_ip}."
                )
            })

    return alerts


def detect_interesting_processes(process_events):
    """
    Flag selected discovery-oriented commands for analyst review.

    These commands can be legitimate administrative activity.
    """
    discovery_terms = (
        "whoami",
        "ipconfig",
        "net user",
        "get-service"
    )

    alerts = []

    for event in process_events:
        command = event.get("command_line", "").lower()

        if any(term in command for term in discovery_terms):
            alerts.append({
                "rule_id": "PROC-001",
                "title": "Discovery-oriented process execution",
                "username": event.get("username"),
                "computer": event.get("computer"),
                "event_id": event.get("event_id"),
                "timestamp": event.get("timestamp"),
                "command_line": event.get("command_line"),
                "severity": "MEDIUM",
                "reason": (
                    "A command associated with system or account discovery "
                    "was observed. Validate the user and business context."
                )
            })

    return alerts


def run_detections(evidence):
    """Run the detection rules and return a combined alert list."""
    alerts = []

    alerts.extend(
        detect_failed_logon_bursts(evidence["authentication"])
    )
    alerts.extend(
        detect_interesting_processes(evidence["process"])
    )

    return alerts


if __name__ == "__main__":
    from src.loader import load_all_evidence

    evidence = load_all_evidence()
    alerts = run_detections(evidence)

    print("\nDETECTION RESULTS")
    print("=" * 55)

    if not alerts:
        print("No alerts generated.")
    else:
        for index, alert in enumerate(alerts, start=1):
            print(
                f"\n[{index}] {alert['severity']} | "
                f"{alert['rule_id']} — {alert['title']}"
            )
            print(f"    Reason: {alert['reason']}")
            print(f"    Account: {alert.get('username')}")
            print(f"    Host: {alert.get('computer')}")
