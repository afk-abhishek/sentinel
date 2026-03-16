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
            # Remove spacing issues
            parts = [p.strip() for p in line.strip().split("|")]

            if len(parts) >= 3:
                fingerprint = "|".join(parts[1:3])
                fingerprints.add(fingerprint)

    return fingerprints


def persist_incidents(incidents):
    """
    Persist correlated incidents to disk.
    Storage only — no intelligence.
    """

    if not incidents:
        return

    existing = load_existing_incidents()

    with open(INCIDENT_LOG, "a") as f:

        for incident in incidents:

            # Safety check (defensive programming)
            if "attack_type" not in incident or "ip" not in incident:
                continue

            fp = incident_fingerprint(incident)

            if fp in existing:
                continue  # deduplicated

            timestamp = datetime.utcnow().isoformat() + "Z"

            # Safe access (no crashes)
            severity = incident.get("severity", "UNKNOWN")
            score = incident.get("total_score", 0)
            start = incident.get("start", "NA")
            end = incident.get("end", "NA")

            line = (
                f"{timestamp} | "
                f"{incident['attack_type']} | "
                f"{incident['ip']} | "
                f"severity={severity} | "
                f"score={score} | "
                f"start={start} | "
                f"end={end}\n"
            )

            f.write(line)

            existing.add(fp)

