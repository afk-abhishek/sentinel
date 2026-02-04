from datetime import datetime
import re
import os


# Match: Failed password for (invalid user )?user from IP
FAILED_PASSWORD_REGEX = re.compile(
    r'^(?P<ts>[\d\-T:\.+]+)\s+\S+\s+sshd.*?Failed password for (invalid user )?(?P<user>\w+) from (?P<ip>[0-9a-fA-F:.]+)'
)

# Match: Connection closed by invalid user user IP
CONNECTION_CLOSED_REGEX = re.compile(
    r'^(?P<ts>[\d\-T:\.+]+)\s+\S+\s+sshd.*?Connection closed by (invalid user )?(?P<user>\w+)\s+(?P<ip>[0-9a-fA-F:.]+)'
)


def parse_auth_log(log_path=None):
    """
    Parse authentication log and extract failed authentication events.

    Supports:
    - Live mode: /var/log/auth.log (default)
    - Replay mode: custom log file

    Priority:
    1. Failed password (real auth failure)
    2. Connection closed (fallback noise)
    """

    # Default path (for Docker / host)
    if log_path is None:
        log_path = os.getenv("AUTH_LOG", "/var/log/auth.log")

    events = []

    with open(log_path, "r") as f:
        for line in f:

            # PRIMARY: Failed password
            m = FAILED_PASSWORD_REGEX.search(line)
            if m:
                events.append({
                    "status": "FAILED",
                    "user": m.group("user"),
                    "ip": m.group("ip"),
                    "timestamp": datetime.fromisoformat(m.group("ts"))
                })
                continue

            # FALLBACK: Connection closed
            m = CONNECTION_CLOSED_REGEX.search(line)
            if m:
                events.append({
                    "status": "FAILED",
                    "user": m.group("user"),
                    "ip": m.group("ip"),
                    "timestamp": datetime.fromisoformat(m.group("ts"))
                })

    return events

