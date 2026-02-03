"""
Main Orchestrator for Linux Authentication Threat Detection

This module implements the end-to-end detection → classification →
response pipeline for authentication-based attacks detected from
/var/log/auth.log.
"""

from parser.auth_parser import parse_auth_log
from detector.bruteforce import detect_bruteforce
from detector.slow_bruteforce import detect_slow_bruteforce
from detector.password_spray import detect_password_spray
from alerting.alerts_store import persist_incidents # earlier persist_alerts
from execution.executor import execute_plan
from execution.planner import generate_execution_plan
from execution.state import is_action_in_cooldown


#  NORMALIZATION 

def normalize_alerts(alerts, is_slow=False, is_spray=False):
    hits = {}

    for alert in alerts:
        ip = alert["ip"]

        if ip not in hits:
            hits[ip] = {
                "attempts": 0,
                "total_attempts": 0,
                "users": set(),
                "window_seconds": int(
                    (alert["end"] - alert["start"]).total_seconds()
                )
            }

        hits[ip]["attempts"] = max(
            hits[ip]["attempts"],
            alert["attempts"]
        )

        hits[ip]["total_attempts"] = max(
            hits[ip]["total_attempts"],
            alert.get("total_attempts", alert["attempts"])
        )

        if "user" in alert:
            hits[ip]["users"].add(alert["user"])

        if is_spray and "users" in alert:
            hits[ip]["users"].update(alert["users"])

    return hits


# CLASSIFICATION 

def classify_attacks(fast_hits, slow_hits, spray_hits):
    alerts = []
    all_ips = set(fast_hits) | set(slow_hits) | set(spray_hits)

    for ip in all_ips:
        fast = fast_hits.get(ip)
        slow = slow_hits.get(ip)
        spray = spray_hits.get(ip)

        if slow:
            attack_type = "SLOW_BRUTE"
            data = slow
            rules_triggered = ["SLOW_BRUTE"]

        elif spray:
            attack_type = "PASSWORD_SPRAY"
            data = spray
            rules_triggered = ["PASSWORD_SPRAY"]

        elif fast:
            attack_type = "FAST_BRUTE"
            data = fast
            rules_triggered = ["FAST_BRUTE"]

        else:
            continue

        alerts.append({
            "ip": ip,
            "attack_type": attack_type,
            "attempts": data["attempts"],
            "total_attempts": data["total_attempts"],
            "users": list(data["users"]),
            "window_seconds": data["window_seconds"],
            "rules_triggered": rules_triggered
        })

    return alerts


# DECISION LAYER

def decide_response(signal):
    attack = signal["attack_type"]
    attempts = signal["attempts"]

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


# MAIN ORCHESTRATOR

def main():
    events = parse_auth_log()

    fast_signals = detect_bruteforce(events)
    slow_signals = detect_slow_bruteforce(events)
    spray_signals = detect_password_spray(events)

    if not fast_signals and not slow_signals and not spray_signals:
        print("No suspicious activity detected.")
        return

    fast_hits = normalize_alerts(fast_signals)
    slow_hits = normalize_alerts(slow_signals, is_slow=True)
    spray_hits = normalize_alerts(spray_signals, is_spray=True)

    signals = classify_attacks(fast_hits, slow_hits, spray_hits)

    decisions = []
    for signal in signals:
        decision = decide_response(signal)
        decisions.append({**signal, **decision})

    persist_alerts(decisions)

    for decision in decisions:
    ip = decision["ip"]
    action = decision["response_action"]

    cooldown = EXECUTION_COOLDOWNS.get(action, 0)

    if cooldown > 0 and is_action_in_cooldown(ip, action):
        # Skip repeated execution
        continue

    plan = generate_execution_plan(decision)
    execute_plan(plan)

    if cooldown > 0:
        mark_action_executed(ip, action, cooldown)



if __name__ == "__main__":
    main()

