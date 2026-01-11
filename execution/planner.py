
from datetime import datetime

def generate_execution_plan(alert):
    action = alert["response_action"]

    plan = {
        "ip": alert["ip"],
        "attack_type": alert["attack_type"],
        "confidence": alert["confidence"],
        "response_action": action,
        "planned_action": None,
        "cooldown_seconds": 0,
        "requires_human_approval": True,
        "created_at": datetime.utcnow(),
        "executed": False
    }

    if action == "MONITOR":
        plan["planned_action"] = "LOG_ONLY"
        plan["requires_human_approval"] = False

    elif action == "FLAG_FOR_REVIEW":
        plan["planned_action"] = "ESCALATE_TO_ANALYST"
        plan["cooldown_seconds"] = 1800

    elif action == "BLOCK":
        plan["planned_action"] = "BLOCK_IP"
        plan["cooldown_seconds"] = 3600

    else:
        # Safe fallback
        plan["planned_action"] = "LOG_ONLY"
        plan["requires_human_approval"] = True

    return plan

