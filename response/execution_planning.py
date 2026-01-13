#Convert response decisions → execution plans

def create_execution_plan(decision, live_mode=False):
    action = decision["action"]

    if action == "BLOCK_SIMULATED":
        planned_action = "BLOCK"
        requires_approval = True
        cooldown = 3600

    elif action == "FLAG_FOR_REVIEW":
        planned_action = "NONE"
        requires_approval = True
        cooldown = 0

    else:  # MONITOR
        planned_action = "NONE"
        requires_approval = False
        cooldown = 0

    return {
        "ip": decision["ip"],
        "attack_type": decision["attack_type"],
        "planned_action": planned_action,
        "reason": decision["reason"],
        "requires_human_approval": requires_approval,
        "cooldown_seconds": cooldown,
        "mode": "LIVE" if live_mode else "DRY_RUN",
        "executed": False
    }

