from datetime import datetime

def generate_execution_plan(response):
    plan = {
        "ip": response["ip"],
        "attack_type": response["attack_type"],
        "confidence": response["confidence"],
        "planned_action": None,
        "requires_human_approval": True,
        "cooldown_seconds": 0,
        "created_at": datetime.utcnow(),
        "executed": False
    }

    action = response["response_action"]

    if action == "MONITOR":
        plan["planned_action"] = "LOG_ONLY"
        plan["requires_human_approval"] = False

    elif action == "FLAG_FOR_REVIEW":
        plan["planned_action"] = "ESCALATE_TO_ANALYST"
        plan["cooldown_seconds"] = 1800  # 30 min

    elif action == "BLOCK":
        plan["planned_action"] = "BLOCK_IP"
        plan["cooldown_seconds"] = 3600  # 1 hour

    return plan

