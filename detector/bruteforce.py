from collections import defaultdict
from datetime import timedelta


"""
Detect fast brute-force attacks:
    - Same IP
    - Multiple failed attempts
    - Within a short time window
"""


def detect_bruteforce(events, threshold=5, window_minutes=5):
    alerts = []

    # Group failed auth events by IP
    events_by_ip = defaultdict(list)
    for event in events:
        if event.get("event_type") != "invalid_password":
            continue
        events_by_ip[event["ip"]].append(event)

    window_delta = timedelta(minutes=window_minutes)

    for ip, ip_events in events_by_ip.items():
        # Sort events by time
        ip_events.sort(key=lambda e: e["timestamp"])

        window = []
        for event in ip_events:
            window.append(event)

            # Shrink window from the left
            while window and (event["timestamp"] - window[0]["timestamp"]) > window_delta:
                window.pop(0)

            if len(window) >= threshold:
                alerts.append({
                    "ip": ip,
                    "attempts": threshold,              # proof
                    "total_attempts": len(ip_events),   # severity
                    "start": window[0]["timestamp"],
                    "end": window[-1]["timestamp"],
                })
                break  # one alert per IP

    return alerts

