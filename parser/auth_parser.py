from datetime import datetime
import re

# Match: Failed password for (invalid user )?user from IP
FAILED_PASSWORD_REGEX = re.compile(
    r'^(?P<ts>[\d\-T:\.+]+)\s+\S+\s+sshd.*?Failed password for (invalid user )?(?P<user>\w+) from (?P<ip>[0-9a-fA-F:.]+)'
)

# Match: Connection closed by invalid user user IP
CONNECTION_CLOSED_REGEX = re.compile(
    r'^(?P<ts>[\d\-T:\.+]+)\s+\S+\s+sshd.*?Connection closed by (invalid user )?(?P<user>\w+)\s+(?P<ip>[0-9a-fA-F:.]+)'
)


def parse_auth_log(log_path="/var/log/auth.log"):
    """
    Parse /var/log/auth.log and extract FAILED authentication events.

    Priority:
    1. Failed password (real auth failure)
    2. Connection closed (fallback noise)
    """

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
                    "time": datetime.fromisoformat(m.group("ts"))
                })
                continue

            # FALLBACK: Connection closed
            m = CONNECTION_CLOSED_REGEX.search(line)
            if m:
                events.append({
                    "status": "FAILED",
                    "user": m.group("user"),
                    "ip": m.group("ip"),
                    "time": datetime.fromisoformat(m.group("ts"))
                })

    return events

