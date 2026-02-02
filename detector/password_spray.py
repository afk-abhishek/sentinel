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

    Emits factual signals only.
    """

    alerts = []

    # ip -> user -> list[events]
    data = defaultdict(lambda: defaultdict(list))

    # Group only failed auth events
    for event in events:
        if event.get("event_type") != "invalid_password":
            continue
        if "user" not in event:
            continue
        data[event["ip"]][event["user"]].append(event)

    for ip, users in data.items():
        valid_users = {}

        # Keep users with low attempt count
        for user, user_events in users.items():
            if len(user_events) <= SPRAY_MAX_ATTEMPTS:
                user_events.sort(key=lambda e: e["timestamp"])
                valid_users[user] = user_events

        if len(valid_users) < SPRAY_USER_THRESHOLD:
            continue

        # Flatten timestamps for window check
        all_events = [e for events in valid_users.values() for e in events]
        all_events.sort(key=lambda e: e["timestamp"])

        start = all_events[0]["timestamp"]
        end = all_events[-1]["timestamp"]

        if end - start <= SPRAY_WINDOW:
            alerts.append({
                "ip": ip,
                "attempts": len(valid_users),          # proof
                "total_attempts": len(all_events),     # severity
                "users": list(valid_users.keys()),
                "start": start,
                "end": end,
            })

    return alerts

