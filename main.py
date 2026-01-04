from parser.auth_parser import parse_auth_log
from detector.bruteforce import detect_bruteforce
from detector.slow_bruteforce import detect_slow_bruteforce
from detector.password_spray import detect_password_spray
from alerting.alerts_store import persist_alerts
from execution.executor import execute_plan
from execution.planner import generate_execution_plan

# NORMALIZATION
def normalize_alerts(alerts, is_slow=False, is_spray=False):
    hits = {}

    for alert in alerts:
        ip = alert["ip"]

        if ip not in hits:
            hits[ip] = {
                "attempts": 0,
                "users": set(),
                "window_seconds": int(
                    (alert["end"] - alert["start"]).total_seconds()
                )
            }

        if is_slow:
            hits[ip]["attempts"] += alert["attempts"]
            if "user" in alert:
                hits[ip]["users"].add(alert["user"])

        elif is_spray:
            hits[ip]["attempts"] += len(alert["users"])
            hits[ip]["users"].update(alert["users"])

        else:  # FAST_BRUTE
            hits[ip]["attempts"] += alert["attempts"]
            if "user" in alert:
                hits[ip]["users"].add(alert["user"])

    return hits


# CLASSIFICATION

def classify_attacks(fast_hits, slow_hits, spray_hits):
    alerts = []

    all_ips = set(fast_hits) | set(slow_hits) | set(spray_hits)

    for ip in all_ips:
        fast = fast_hits.get(ip)
        slow = slow_hits.get(ip)
        spray = spray_hits.get(ip)

        attempts = 0
        users = set()
        window = 0
        rules_triggered = []

        # Priority:
        # SLOW > SPRAY > FAST

        if slow:
            attempts = slow["attempts"]
            users = slow["users"]
            window = slow["window_seconds"]
            rules_triggered.append("SLOW_BRUTE")

        if spray:
            attempts = spray["attempts"]
            users = spray["users"]
            window = spray["window_seconds"]
            rules_triggered.append("PASSWORD_SPRAY")

        if fast:
            attempts = fast["attempts"]
            users = fast["users"]
            window = fast["window_seconds"]
            rules_triggered.append("FAST_BRUTE")

        if not rules_triggered:
            continue

        alerts.append({
            "ip": ip,
            "attack_type": rules_triggered[0],
            "attempts": attempts,
            "users": list(users),
            "window_seconds": window,
            "rules_triggered": rules_triggered
        })

    return alerts


# RESPONSE DECISION
def decide_response(alert):
    attack = alert["attack_type"]
    attempts = alert["attempts"]
    users = len(alert["users"])

    if attack == "SLOW_BRUTE":
        return {
            "response_action": "BLOCK",
            "confidence": "HIGH",
            "response_reason": "Sustained authentication failures over long duration"
        }

    if attack == "PASSWORD_SPRAY":
        return {
            "response_action": "FLAG_FOR_REVIEW",
            "confidence": "MEDIUM",
            "response_reason": "Multiple accounts targeted from a single IP"
        }

    if attack == "FAST_BRUTE":
        if attempts >= 5:
            return {
                "response_action": "FLAG_FOR_REVIEW",
                "confidence": "MEDIUM",
                "response_reason": "Rapid repeated authentication failures"
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
        "response_reason": "No strong indicators"
    }


# OUTPUT

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


# MAIN

def main():
    events = parse_auth_log()

    fast_alerts = detect_bruteforce(events)
    slow_alerts = detect_slow_bruteforce(events)
    spray_alerts = detect_password_spray(events)

    if not fast_alerts and not slow_alerts and not spray_alerts:
        print("No suspicious activity detected.")
        return

    fast_hits = normalize_alerts(fast_alerts)
    slow_hits = normalize_alerts(slow_alerts, is_slow=True)
    spray_hits = normalize_alerts(spray_alerts, is_spray=True)

    final_alerts = classify_attacks(fast_hits, slow_hits, spray_hits)

    for alert in final_alerts:
        alert.update(decide_response(alert))

    print_alerts(final_alerts)
    persist_alerts(final_alerts)

    # DAY 8: EXECUTION PLANS

    execution_plans = []

    for alert in final_alerts:
        plan = generate_execution_plan(alert)
        execution_plans.append(plan)

    for plan in execution_plans:
        execute_plan(plan)


if __name__ == "__main__":
    main()

