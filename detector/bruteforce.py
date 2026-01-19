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

    for ip, attempts in events.items():
        if attempts >= threshold:
            alerts.append({
                "ip": ip,
                "event_type": "invalid_password",
                "count": attempts,
                "window_minutes": window_minutes
                "timestamp": window[-1]   # last event time
            })

    return alerts

