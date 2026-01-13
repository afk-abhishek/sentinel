'''Map incident-level conclusions → response decisions,
the incident hash-map helps us in mapping attack type and 
severity'''

#Detection → Scoring → Correlation → Decision pipeline.

def decide_response(incident):
    attack = incident["attack_type"]
    severity = incident["severity"]

    if attack == "PASSWORD_SPRAY":
        action = "FLAG_FOR_REVIEW"
        reason = "Multiple users targeted from same IP"

    elif attack == "FAST_BRUTE" and severity in ("HIGH", "CRITICAL"):
        action = "BLOCK_SIMULATED"
        reason = "High-rate brute force detected"

    elif attack == "SLOW_BRUTE" and severity in ("MEDIUM", "HIGH", "CRITICAL"):
        action = "FLAG_FOR_REVIEW"
        reason = "Persistent low-rate brute force"

    else:
        action = "MONITOR"
        reason = "Low confidence activity"

    return {
        "ip": incident["ip"],
        "attack_type": attack,
        "severity": severity,
        "action": action,
        "reason": reason,
        "start": incident["start"],
        "end": incident["end"],
        "confidence": incident["total_score"]
    }

