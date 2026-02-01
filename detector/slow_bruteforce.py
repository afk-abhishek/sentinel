from collections import defaultdict
from datetime import timedelta


def detect_slow_bruteforce(events, threshold=10, window_hours=1.0):
    """
    Detect slow brute-force signals:
    - Same IP
    - Repeated invalid password attempts
    - Spread over a long time window

    Emits factual signals only.
    """

    alerts = []
    events_by_ip = defaultdict(list)

    # Group only failed auth events by IP
    for event in events:
        if event.get("event_type") != "invalid_password":
            continue
        events_by_ip[event["ip"]].append(event)

    window_delta = timedelta(hours=window_hours)

    for ip, ip_events in events_by_ip.items():
        ip_events.sort(key=lambda e: e["timestamp"])

        times = [e["timestamp"] for e in ip_events]

        for i in range(len(times)):
            window = times[i:i + threshold]

            if len(window) < threshold:
                break

            if window[-1] - window[0] <= window_delta:
                alerts.append({
                    "ip": ip,
                    "attempts": threshold,              # proof
                    "total_attempts": len(ip_events),   # severity
                    "start": window[0],
                    "end": window[-1],
                })
                break  # one alert per IP

    return alerts

