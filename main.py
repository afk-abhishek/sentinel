from parser.auth_parser import parse_auth_log
from detector.bruteforce import detect_bruteforce
from detector.slow_bruteforce import detect_slow_bruteforce
from alerting.alerts_store import persist_alerts
from detector.password_spray import detect_password_spray


def normalize_alerts(alerts, is_slow=False, is_spray=False):
    hits = {}

    for alert in alerts:
        ip = alert["ip"]

        if ip not in hits:
            hits[ip] = {
                "attempts": 0,
                "users": set(),
                "window_seconds": int((alert["end"] - alert["start"]).total_seconds())
            }

        if is_slow:
            hits[ip]["attempts"] += alert["attempts"]
            if "user" in alert:
                hits[ip]["users"].add(alert["user"])

        elif is_spray:
            hits[ip]["attempts"] += len(alert["users"])
            hits[ip]["users"].update(alert["users"])

        else:  # fast brute
            hits[ip]["attempts"] += alert["attempts"]
            if "user" in alert:
                hits[ip]["users"].add(alert["user"])

    return hits

def main():
    events = parse_auth_log()

    fast_alerts = detect_bruteforce(events)
    slow_alerts = detect_slow_bruteforce(events)
    spray_alerts = detect_password_spray(events)

    if not fast_alerts and not slow_alerts:
        print("No suspicious activity detected.")
        return

    # Normalize detector outputs
    fast_hits = normalize_alerts(fast_alerts)
    slow_hits = normalize_alerts(slow_alerts, is_slow=True)
    spray_hits = normalize_alerts(spray_alerts, is_spray=True)


    # Classify attacks (Day 4 logic)
    final_alerts = classify_attacks(fast_hits, slow_hits, spray_hits)
    # Decide response actions (Day 7)
    for alert in final_alerts:
        response = decide_response(alert)
        alert.update(response)


    # Print unified alerts
    print_alerts(final_alerts)
    persist_alerts(final_alerts)
    


            
def classify_attacks(fast_hits, slow_hits, spray_hits):
    alerts = []

    all_ips = set(fast_hits.keys()) | set(slow_hits.keys()) | set(spray_hits.keys())

    for ip in all_ips:
        spray = spray_hits.get(ip)
        fast = fast_hits.get(ip)
        slow = slow_hits.get(ip)
        
        users=set() # for repetitive users
        attempts=0
        window=0
        rules_triggered=[]

        # RULE PRIORITY:
        # SLOW_BRUTE >PASSWORD_SPRAY >FAST_BRUTE > NORMAL
        if slow:
            attempts = slow["attempts"]
            window = slow["window_seconds"]
            users = slow["users"]
            rules_triggered.append("SLOW_BRUTE")
            
        if spray:
            attempts = spray["attempts"]
            window = spray["window_seconds"]
            users = spray["users"]
            rules_triggered.append("PASSWORD_SPRAY")
            
        if fast:
            attempts = fast["attempts"]
            window = fast["window_seconds"]
            users = fast["users"]
            rules_triggered.append("FAST_BRUTE")

        if not rules_triggered:
            continue  # NORMAL traffic, ignore
        
        

        alert = {
            "ip": ip,
            "attack_type": rules_triggered[0],
            "attempts": attempts,
            "window_seconds": window,
            "users": list(users),
            "rules_triggered": rules_triggered
        }

        alerts.append(alert)

    return alerts
    
def decide_response(alert):
    attack_type = alert["attack_type"]
    attempts = alert["attempts"]
    users_count = len(alert["users"])

    if attack_type == "SLOW_BRUTE":
        return {
            "response_action": "BLOCK",
            "confidence": "HIGH",
            "response_reason": "Sustained authentication failures over extended time window"
        }

    if attack_type == "PASSWORD_SPRAY":
        return {
            "response_action": "FLAG_FOR_REVIEW",
            "confidence": "MEDIUM",
            "response_reason": "Multiple user accounts targeted from a single IP"
        }

    if attack_type == "FAST_BRUTE":
        if attempts >= 5:
            return {
                "response_action": "FLAG_FOR_REVIEW",
                "confidence": "MEDIUM",
                "response_reason": "Rapid repeated login failures for a single account"
            }
        else:
            return {
                "response_action": "MONITOR",
                "confidence": "LOW",
                "response_reason": "Low-volume authentication failures"
            }

    return {
        "response_action": "MONITOR",
        "confidence": "LOW",
        "response_reason": "No strong attack indicators"
    }
    

def print_alerts(alerts):
    for a in alerts:
        print(
            f"[ALERT] {a['attack_type']} | "
            f"IP {a['ip']} | "
            f"Attempts {a['attempts']} | "
            f"Users {','.join(a['users']) if a['users'] else '-'} | "
            f"Window {a['window_seconds']}s\n"
            f"  ↳ Response: {a['response_action']} | "
            f"Confidence: {a['confidence']}\n"
            f"  ↳ Reason: {a['response_reason']}\n"
        )



if __name__ == "__main__":
    main()

