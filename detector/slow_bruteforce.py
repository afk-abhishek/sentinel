from collections import defaultdict
from datetime import timedelta


def detect_slow_bruteforce(events, threshold=10, window_hours=1.0):
    """
    Detect slow brute-force signals:
    - Same IP
    - Repeated invalid password attempts
    - Spread over a long time window

    Emits factual alerts only.
    """

    attempts = defaultdict(list)
    alerts = []

    # Group attempts by IP
    for event in events:
        attempts[event["ip"]].append(event["time"])

    for ip, times in attempts.items():
        times.sort()

        for i in range(len(times)):
            window = times[i:i + threshold]

            if len(window) < threshold:
                break

            if window[-1] - window[0] <= timedelta(hours=window_hours):
                alerts.append({
                    "ip": ip,
                    "event_type": "invalid_password",
                    "count": threshold,
                    "window_minutes": int(window_hours * 60),
                    "timestamp": window[-1]
                })
                break  # one alert per IP

    return alerts

