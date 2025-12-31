from collections import defaultdict
from datetime import timedelta

def detect_bruteforce(events, threshold=5, window_minutes=2):
    failures = defaultdict(list) #dictionary for storing failures
    alerts = []

    # group failures by IP: IP --> 'key' and time --> 'value' 
    for event in events:
        failures[event["ip"]].append(event["time"])

    for ip, times in failures.items():
        times.sort()

        for i in range(len(times)):
            window = times[i:i+threshold]

            if len(window) < threshold:
                continue

            if window[-1] - window[0] <= timedelta(minutes=window_minutes):
                alerts.append({
                    "ip": ip,
                    "attempts": threshold,
                    "start": window[0],
                    "end": window[-1]
                })
                break

    return alerts
    

