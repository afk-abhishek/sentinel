from collections import defaultdict
from datetime import timedelta


def detect_slow_bruteforce(events, threshold=10, window_hours=1.0):
    """
    Detect slow brute-force attacks:
    - Same IP
    - Same username
    - Multiple failed attempts
    - Spread over a long time window

    threshold: minimum attempts to prove attack
    window_hours: maximum duration in which threshold attempts must occur
    """

    attempts = defaultdict(list)
    alerts = []

    # Group attempts by (IP, user)
    for event in events:
        key = (event["ip"], event["user"])
        attempts[key].append(event["time"])

    # Sliding window detection
    for (ip, user), times in attempts.items():
        times.sort()

        for i in range(len(times)):
            window = times[i:i + threshold]

            if len(window) < threshold:
                break

            if window[-1] - window[0] <= timedelta(hours=window_hours):
                alerts.append({
                    "attack_type": "SLOW_BRUTE",   # normalized name
                    "ip": ip,
                    "user": user,
                    "attempts": threshold,         # proof
                    "total_attempts": len(times),  # severity
                    "start": window[0],
                    "end": window[-1]
                })
                break  # one alert per (ip, user)

    return alerts

