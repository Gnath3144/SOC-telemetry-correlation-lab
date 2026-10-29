
from src.loader import load_all_evidence
from src.detector import run_detections
from src.correlator import correlate_incident
from src.reporter import (
    build_report,
    ensure_output_directory,
    save_json_report,
    save_markdown_report,
)


def main():
    print("=" * 60)
    print("       SOC DETECTIVE - SECURITY INVESTIGATION")
    print("=" * 60)

    try:
        # Stage 1: Load the synthetic evidence.
        print("\n[1/5] Loading evidence...")
        evidence = load_all_evidence()

        # Stage 2: Run the detection rules.
        print("\n[2/5] Running detection rules...")
        alerts = run_detections(evidence)
        print(f"Detection alerts generated: {len(alerts)}")

        # Stage 3: Correlate events into incidents.
        print("\n[3/5] Correlating security telemetry...")
        incidents = correlate_incident(evidence)
        print(f"Correlated incidents: {len(incidents)}")

        # Stage 4: Build the report.
        print("\n[4/5] Preparing the investigation report...")
        ensure_output_directory()
        report = build_report(evidence, incidents)

        # Include a count of individual detection alerts.
        report["detection_alert_count"] = len(alerts)

        # Stage 5: Save the deliverables.
        print("\n[5/5] Saving investigation deliverables...")
        json_path = save_json_report(report)
        markdown_path = save_markdown_report(report)

        print("\n" + "=" * 60)
        print("INVESTIGATION COMPLETE")
        print("=" * 60)
        print(f"Events reviewed: {report['total_events_reviewed']}")
        print(f"Detection alerts: {len(alerts)}")
        print(f"Correlated incidents: {len(incidents)}")
        print(f"JSON report: {json_path}")
        print(f"Markdown report: {markdown_path}")
        print("\nReview the report before drawing conclusions.")
        print("All evidence in this lab is synthetic.")

    except (FileNotFoundError, ValueError) as error:
        print(f"\n[INPUT ERROR] {error}")
        print("Check the data files and their JSON formatting.")

    except OSError as error:
        print(f"\n[FILE ERROR] Unable to access a project file: {error}")


if __name__ == "__main__":
    main()
