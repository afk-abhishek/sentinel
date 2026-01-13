'''Detection → Scoring → Correlation → Decision pipeline.'''

from datetime import datetime

def infer_attack_type(ip_alerts, total_score, event_types):
    if "password_spray" in event_types:
        return "PASSWORD_SPRAY"

    if "invalid_password" in event_types:
        # slow brute = lower score but persistent
        if total_score >= 10:
            return "FAST_BRUTE"
        if total_score >= 4:
            return "SLOW_BRUTE"

    return "SUSPICIOUS_ACTIVITY"


def correlate_alerts(alerts):
    incidents = []
    by_ip = {}

    for a in alerts:
        by_ip.setdefault(a["ip"], []).append(a)

    for ip, ip_alerts in by_ip.items():
        timestamps = [a["timestamp"] for a in ip_alerts]
        event_types = set(a["event_type"] for a in ip_alerts)
        total_score = sum(a["score"] for a in ip_alerts)

        attack_type = infer_attack_type(ip_alerts, total_score, event_types)

        incident = {
            "ip": ip,
            "attack_type": attack_type,
            "total_score": total_score,
            "severity": max(a["severity"] for a in ip_alerts),
            "signals": list(event_types),
            "start": min(timestamps),
            "end": max(timestamps),
            "alerts": ip_alerts
        }

        incidents.append(incident)

    return incidents


