"""
Main Orchestrator for Linux Authentication Threat Detection

This module implements the end-to-end detection → classification →
response pipeline for authentication-based attacks detected from
/var/log/auth.log.

Pipeline stages:
1. Parse authentication logs into structured events
2. Detect attack patterns (fast brute-force, slow brute-force, password spray)
3. Normalize detector outputs into a common format
4. Classify attacks with priority rules
5. Decide response actions based on severity and confidence
6. Generate and (optionally) execute response plans

Design principles:
- Early detection using sliding windows
- Separation of detection vs response logic
- Safe-by-default execution (dry-run mode)
- Clear distinction between proof vs enrichment
"""

from parser.auth_parser import parse_auth_log
from detector.bruteforce import detect_bruteforce
from detector.slow_bruteforce import detect_slow_bruteforce
from detector.password_spray import detect_password_spray
from alerting.alerts_store import persist_alerts
from execution.executor import execute_plan
from execution.planner import generate_execution_plan
from alerting.score import score_alert


# NORMALIZATION:

def normalize_alerts(alerts, is_slow=False, is_spray=False):
    """
    Normalize raw detector alerts into per-IP aggregated hits.

    Why normalization?
    - Multiple detectors may trigger on the same IP
    - Each detector reports only the *minimum proof* needed to fire
    - We want a clean per-IP view before classification

    Key fields:
    - attempts: minimum proof that triggered detection
    - total_attempts: total failures observed (severity context)
    - users: affected usernames
    - window_seconds: duration of the triggering window

    Args:
        alerts (list): Raw alerts from detectors
        is_slow (bool): Indicates slow brute-force detector output
        is_spray (bool): Indicates password spray detector output

    Returns:
        dict: { ip -> normalized attack data }
    """

    hits = {}

    for alert in alerts:
        ip = alert["ip"]

        # Initialize per-IP structure
        if ip not in hits:
            hits[ip] = {
                "attempts": 0,          # proof (threshold-based)
                "total_attempts": 0,    # enrichment (severity)
                "users": set(),
                "window_seconds": int(
                    (alert["end"] - alert["start"]).total_seconds()
                )
            }

        # Proof-based attempts:
        # Use max(), not sum(), because each detector already
        # represents a complete proof of malicious behavior.
        hits[ip]["attempts"] = max(
            hits[ip]["attempts"],
            alert["attempts"]
        )

        # Severity-based attempts:
        # Captures how bad the activity became overall.
        hits[ip]["total_attempts"] = max(
            hits[ip]["total_attempts"],
            alert.get("total_attempts", alert["attempts"])
        )

        # Track affected users (if applicable)
        if "user" in alert:
            hits[ip]["users"].add(alert["user"])

        if is_spray and "users" in alert:
            hits[ip]["users"].update(alert["users"])

    return hits

# CLASSIFICATION:

def classify_attacks(fast_hits, slow_hits, spray_hits):
    """
    Classify attacks per IP using detector priority.

    Priority order:
    1. Slow brute-force (most stealthy & dangerous)
    2. Password spray
    3. Fast brute-force

    Only the highest-priority attack is reported as the
    primary attack_type, while others can be retained
    as contextual signals.

    Args:
        fast_hits (dict)
        slow_hits (dict)
        spray_hits (dict)

    Returns:
        list: Final classified alerts
    """

    alerts = []
    all_ips = set(fast_hits) | set(slow_hits) | set(spray_hits)

    for ip in all_ips:
        fast = fast_hits.get(ip)
        slow = slow_hits.get(ip)
        spray = spray_hits.get(ip)

        # Apply priority rules
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
            "attempts": data["attempts"],              # proof
            "total_attempts": data["total_attempts"],  # severity
            "users": list(data["users"]),
            "window_seconds": data["window_seconds"],
            "rules_triggered": rules_triggered
        })

    return alerts


# RESPONSE DECISION:

def decide_response(alert):
    """
    Decide response action and confidence based on attack type.

    Detection and response are intentionally decoupled:
    - Detectors prove malicious behavior
    - Response logic decides how aggressively to act

    Returns:
        dict: response_action, confidence, response_reason
    """

    attack = alert["attack_type"]
    attempts = alert["attempts"]

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


# MAIN :

def main():
    """
    Entry point for the detection pipeline.
    """

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

    persist_alerts(final_alerts)

    for alert in final_alerts:
        plan = generate_execution_plan(alert)
        execute_plan(plan)
    
    


if __name__ == "__main__":
    main()

