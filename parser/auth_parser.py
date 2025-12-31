from datetime import datetime
import re

FAILED_REGEX = re.compile(
    r'^(?P<ts>[\d\-T:\.+]+)\s+\S+\s+sshd.*?(Failed password|Connection closed) by (invalid user )?(?P<user>\w+)\s+(?P<ip>[0-9a-fA-F:.]+)'
) #to find patterns

def parse_auth_log(log_path="/var/log/auth.log"): #specifying the path of log files
    events = []

    with open(log_path, "r") as f:
        for line in f:
            m = FAILED_REGEX.search(line)
            if m:
                events.append({
                    "status": "FAILED",
                    "user": m.group("user"),
                    "ip": m.group("ip"),
                    "time": datetime.fromisoformat(m.group("ts"))
                })

    return events


