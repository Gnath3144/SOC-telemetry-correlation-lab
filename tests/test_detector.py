
import unittest

from src.detector import (
    parse_timestamp,
    detect_failed_logon_bursts,
    detect_interesting_processes,
    run_detections,
)
from src.correlator import correlate_incident


class TestSOCDetector(unittest.TestCase):

    def setUp(self):
        """Create a small, isolated dataset for each test."""
        self.auth_events = [
            {
                "event_id": f"FAIL-{i}",
                "timestamp": f"2026-10-29T09:{55 + i:02}:00Z",
                "computer": "WS-TEST-01",
                "username": "test_user",
                "windows_event_id": 4625,
                "logon_type": 3,
                "source_ip": "198.51.100.10",
                "status": "FAILURE",
            }
            for i in range(5)
        ]

        self.auth_events.append({
            "event_id": "SUCCESS-001",
            "timestamp": "2026-10-29T10:00:00Z",
            "computer": "WS-TEST-01",
            "username": "test_user",
            "windows_event_id": 4624,
            "logon_type": 3,
            "source_ip": "198.51.100.10",
            "status": "SUCCESS",
        })

    def test_timestamp_parsing(self):
        """Valid ISO 8601 timestamps should be parsed."""
        result = parse_timestamp("2026-10-29T10:00:00Z")
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2026)

    def test_invalid_timestamp_returns_none(self):
        """Invalid timestamps should not crash the parser."""
        self.assertIsNone(parse_timestamp("not-a-timestamp"))

    def test_failed_logons_followed_by_success_are_detected(self):
        """Five matching failures followed by success should alert."""
        alerts = detect_failed_logon_bursts(self.auth_events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["username"], "test_user")
        self.assertEqual(alerts[0]["failed_attempts"], 5)

    def test_too_few_failures_do_not_alert(self):
        """Four failures should not meet the default threshold."""
        alerts = detect_failed_logon_bursts(
            self.auth_events[:4] + [self.auth_events[-1]]
        )
        self.assertEqual(alerts, [])

    def test_different_source_ip_does_not_match(self):
        """Failures from a different source must not be counted."""
        events = [dict(event) for event in self.auth_events]

        for event in events:
            if event["windows_event_id"] == 4625:
                event["source_ip"] = "198.51.100.99"

        alerts = detect_failed_logon_bursts(events)
        self.assertEqual(alerts, [])

    def test_discovery_process_is_flagged(self):
        """A selected discovery-oriented command should be flagged."""
        events = [{
            "event_id": "PROC-TEST",
            "timestamp": "2026-10-29T10:01:00Z",
            "computer": "WS-TEST-01",
            "username": "test_user",
            "sysmon_event_id": 1,
            "command_line": "whoami.exe /all",
        }]

        alerts = detect_interesting_processes(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "PROC-001")

    def test_ordinary_notepad_process_is_not_flagged(self):
        """Notepad should not match our current discovery rule."""
        events = [{
            "event_id": "PROC-NORMAL",
            "username": "analyst01",
            "computer": "WS-TEST-01",
            "command_line": "notepad.exe",
        }]

        self.assertEqual(
            detect_interesting_processes(events),
            []
        )

    def test_combined_detection_returns_alerts(self):
        """The detection pipeline should combine rule results."""
        evidence = {
            "authentication": self.auth_events,
            "process": [{
                "event_id": "PROC-TEST",
                "username": "test_user",
                "computer": "WS-TEST-01",
                "command_line": "whoami.exe",
            }],
            "network": [],
        }

        alerts = run_detections(evidence)

        self.assertEqual(len(alerts), 2)

    def test_correlation_links_related_evidence(self):
        """The correlator should group events by account, host and time."""
        evidence = {
            "authentication": self.auth_events,
            "process": [{
                "event_id": "PROC-RELATED",
                "timestamp": "2026-10-29T10:01:00Z",
                "computer": "WS-TEST-01",
                "username": "test_user",
                "command_line": "whoami.exe",
            }],
            "network": [{
                "event_id": "NET-RELATED",
                "timestamp": "2026-10-29T10:02:00Z",
                "computer": "WS-TEST-01",
                "source": "Zeek",
                "src_ip": "192.0.2.10",
                "dest_ip": "203.0.113.10",
                "dest_port": 443,
            }],
        }

        incidents = correlate_incident(evidence)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["account"], "test_user")
        self.assertEqual(incidents[0]["related_process_count"], 1)
        self.assertEqual(incidents[0]["related_network_count"], 1)


if __name__ == "__main__":
    unittest.main()
