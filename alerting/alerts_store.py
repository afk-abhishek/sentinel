import os
from datetime import datetime

INCIDENT_LOG = "incidents.log"


def incident_fingerprint(incident):
    """
    Fingerprint for deduplication.
    One incident per IP + attack_type.
    """
    return f"{incident['attack_type']}|{incident['ip']}"


def load_existing_incidents():
    if not os.path.exists(INCIDENT_LOG):
        return set()

    fingerprints = set()
    with open(INCIDENT_LOG, "r") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) >= 3:
                fingerprint = "|".join(parts[1:3])
                fingerprints.add(fingerprint)

    return fingerprints


def persist_incidents(incidents):
    """
    Persist correlated incidents to disk.
    Storage only — no intelligence.
    """
    existing = load_existing_incidents()

    with open(INCIDENT_LOG, "a") as f:
        for incident in incidents:
            fp = incident_fingerprint(incident)
            if fp in existing:
                continue  # deduplicated

            timestamp = datetime.utcnow().isoformat() + "Z"

            line = (
                f"{timestamp} | "
                f"{incident['attack_type']} | "
                f"{incident['ip']} | "
                f"severity={incident['severity']} | "
                f"score={incident['total_score']} | "
                f"start={incident['start']} | "
                f"end={incident['end']}\n"
            )

            f.write(line)
            existing.add(fp)

