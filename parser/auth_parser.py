from datetime import datetime
import re
import os


# Matching Failed password for user from 'IP'
FAILED_PASSWORD_REGEX = re.compile(
    r'Failed password for (?:invalid user )?(?P<user>\w+) from (?P<ip>\S+)'
)

# Matching Connection closed by invalid user 'IP'
CONNECTION_CLOSED_REGEX = re.compile(
    r'Connection closed by (?:invalid user )?(?P<user>\w+)\s+(?P<ip>\S+)'
)


def parse_auth_log(log_path=None):
    """
    Parse authentication log and extract failed authentication events.

    Supports:
    - Live mode: /var/log/auth.log (default)
    - Replay mode: custom log file
    
    Priority:
    - Real Authentication Failure
    - Fallback Noise
    """

    if log_path is None:
        log_path = os.getenv("AUTH_LOG", "/var/log/auth.log")

    events = []

    with open(log_path, "r") as f:

        for line in f:
            timestamp=None
            try:
                timestamp_str=line.split(None,1)[0] if line.strip() else None
                if timestamp_str:
                    timestamp=datetime.fromisoformat(timestamp_str)
            except (ValueError,IndexError):
                pass

            # PRIMARY: Failed password
            m = FAILED_PASSWORD_REGEX.search(line)
            if m:
                events.append({
                    "event_type": "invalid_password",
                    "user": m.group("user"),
                    "ip": m.group("ip"),
                    "timestamp": timestamp
                })
                continue

            # FALLBACK: Connection closed
            m = CONNECTION_CLOSED_REGEX.search(line)
            if m:
                events.append({
                    "event_type": "connection_closed",
                    "user": m.group("user"),
                    "ip": m.group("ip"),
                    "timestamp": timestamp
                })

    return events

