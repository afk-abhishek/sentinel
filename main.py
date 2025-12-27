from parser.auth_parser import parse_auth_log
from detector.bruteforce import detect_bruteforce
from detector.slow_bruteforce import detect_slow_bruteforce
from alerting.alerts_store import persist_alerts
from detector.password_spray import detect_password_spray


def normalize_alerts(alerts, is_slow=False):
    hits = {}

    for alert in alerts:
        ip = alert["ip"]

        if ip not in hits:
            hits[ip] = {
                "attempts": alert["attempts"],
                "users": set(),
                "window_seconds": int((alert["end"] - alert["start"]).total_seconds())
            }

        if is_slow and "user" in alert:
            hits[ip]["users"].add(alert["user"])

    return hits

def main():
    events = parse_auth_log()

    fast_alerts = detect_bruteforce(events)
    slow_alerts = detect_slow_bruteforce(events)

    if not fast_alerts and not slow_alerts:
        print("No suspicious activity detected.")
        return

    # Normalize detector outputs
    fast_hits = normalize_alerts(fast_alerts)
    slow_hits = normalize_alerts(slow_alerts, is_slow=True)
    
    spray_hits = normalize_alerts(spray_alerts, is_slow=True)


    # Classify attacks (Day 4 logic)
    final_alerts = classify_attacks(fast_hits, slow_hits, spray_hits)

    # Print unified alerts
    print_alerts(final_alerts)
    persist_alerts(final_alerts)
    spray_alerts = detect_password_spray(events)


            
def classify_attacks(fast_hits, slow_hits):
    alerts = []

    all_ips = set(fast_hits.keys()) | set(slow_hits.keys())

    for ip in all_ips:
        spray=spray_hits.get(ip)
        fast = fast_hits.get(ip)
        slow = slow_hits.get(ip)

        # RULE PRIORITY:
        # SLOW_BRUTE >PASSWORD_SPRAY >FAST_BRUTE > NORMAL
        if slow:
            attack_type = "SLOW_BRUTE"
            attempts = slow["attempts"]
            window = slow["window_seconds"]
            users = slow["users"]
            rules_triggered = ["SLOW_BRUTE"]
            if fast:
                rules_triggered.append("FAST_BRUTE")
            
        elif spray:
            attack_type = "PASSWORD_SPRAY"
            attempts = spray["attempts"]
            window = spray["window_seconds"]
            users = spray["users"]
            rules_triggered = ["PASSWORD_SPRAY"]
            if fast:
                rules_triggered.append("FAST_BRUTE")

        elif fast:
            attack_type = "FAST_BRUTE"
            attempts = fast["attempts"]
            window = fast["window_seconds"]
            users = fast["users"]
            rules_triggered = ["FAST_BRUTE"]

        else:
            continue  # NORMAL traffic, ignore

        alert = {
            "ip": ip,
            "attack_type": attack_type,
            "attempts": attempts,
            "window_seconds": window,
            "users": list(users),
            "rules_triggered": rules_triggered
        }

        alerts.append(alert)

    return alerts
    
def print_alerts(alerts):
    for a in alerts:
        print(
            f"[ALERT] {a['attack_type']} | "
            f"IP {a['ip']} | "
            f"Attempts {a['attempts']} | "
            f"Users {','.join(a['users'])} | "
            f"Window {a['window_seconds']}s"
        )


if __name__ == "__main__":
    main()

