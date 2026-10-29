
import json
from pathlib import Path


# Find the project root regardless of the current terminal directory.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"


def load_json_file(filename):
    """
    Load one JSON evidence file and return its contents.

    Raises a helpful error if the file is missing or contains invalid JSON.
    """
    file_path = DATA_DIR / filename

    if not file_path.exists():
        raise FileNotFoundError(
            f"Evidence file not found: {file_path}"
        )

    try:
        with file_path.open("r", encoding="utf-8") as file:
            content = file.read()
            data = json.loads(content) if content.strip() else []
    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid JSON in {filename}: {error}"
        ) from error

    if not isinstance(data, list):
        raise ValueError(
            f"{filename} must contain a JSON list of events."
        )

    for index, event in enumerate(data):
        if not isinstance(event, dict):
            raise ValueError(
                f"Record {index} in {filename} must be a JSON object."
            )

    print(f"[LOADED] {filename}: {len(data)} records")
    return data


def load_all_evidence():
    """
    Load authentication, process, and network evidence.

    Returns a dictionary containing the three event collections.
    """
    evidence = {
        "authentication": load_json_file("auth_events.json"),
        "process": load_json_file("process_events.json"),
        "network": load_json_file("network_alerts.json"),
    }

    total = sum(len(events) for events in evidence.values())

    print("-" * 45)
    print(f"Total evidence records loaded: {total}")
    print("-" * 45)

    return evidence


if __name__ == "__main__":
    evidence = load_all_evidence()

    print("\nEvidence source summary:")

    for source, events in evidence.items():
        print(f"  {source.title():16} {len(events)} records")
