from collections import defaultdict
from datetime import timedelta


def detect_bruteforce(events, threshold=5, window_minutes=2):
    """
    Detect fast brute-force attacks:
    - Same IP
    - Multiple failed attempts
    - Within a short time window
    """

    failures = defaultdict(list)
    alerts = []

    # Group failures by source IP
    for event in events:
        failures[event["ip"]].append(event["time"])

    for ip, times in failures.items():
        times.sort()

        for i in range(len(times)):
            window = times[i:i + threshold]

            if len(window) < threshold:
                break

            if window[-1] - window[0] <= timedelta(minutes=window_minutes):
                alerts.append({
                    "attack_type": "FAST_BRUTE",
                    "ip": ip,
                    "attempts": threshold,          # proof
                    "total_attempts": len(times),  # severity
                    "start": window[0],
                    "end": window[-1]
                })
                break  # one alert per IP

    return alerts

