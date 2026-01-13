from collections import defaultdict
from datetime import timedelta

SPRAY_USER_THRESHOLD = 3      # ≥ 3 different users
SPRAY_MAX_ATTEMPTS = 3        # ≤ 3 attempts per user
SPRAY_WINDOW = timedelta(minutes=3)


def detect_password_spray(events):
    """
    Detect password spray signals:
    - Same IP
    - Multiple distinct users
    - Few attempts per user
    - Within a short time window

    Emits factual alerts only.
    """

    alerts = []

    # ip -> user -> timestamps
    data = defaultdict(lambda: defaultdict(list))

    for e in events:
        data[e["ip"]][e["user"]].append(e["time"])

    for ip, users in data.items():
        valid_users = {}

        for user, times in users.items():
            times.sort()
            if len(times) <= SPRAY_MAX_ATTEMPTS:
                valid_users[user] = times

        if len(valid_users) < SPRAY_USER_THRESHOLD:
            continue

        # Flatten times for window check
        all_times = sorted(t for ts in valid_users.values() for t in ts)
        start = all_times[0]
        end = all_times[-1]

        if end - start <= SPRAY_WINDOW:
            alerts.append({
                "ip": ip,
                "event_type": "password_spray",
                "count": len(valid_users),
                "window_minutes": int(SPRAY_WINDOW.total_seconds() / 60),
                "timestamp": end
            })

    return alerts

