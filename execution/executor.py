import subprocess
from datetime import datetime
from execution.state import is_in_cooldown, mark_executed

LIVE_MODE = False  # Day 10 only
PROTECTED_IPS = {"127.0.0.1", "::1"}


def approve_execution(plan):
    ip = plan["ip"]

    if ip in PROTECTED_IPS:
        return False, "Protected IP"

    if is_in_cooldown(ip):
        return False, "IP in cooldown period"

    if plan["planned_action"] == "BLOCK_IP" and plan["confidence"] != "HIGH":
        return False, "Insufficient confidence"

    return True, "Approved"


def execute_plan(plan):
    approved, reason = approve_execution(plan)

    if not approved:
        print(f"[SKIPPED] {plan['planned_action']} on {plan['ip']} — {reason}")
        return plan

    if not LIVE_MODE:
        print(
            f"[DRY-RUN] Would execute {plan['planned_action']} "
            f"on {plan['ip']} for {plan['cooldown_seconds']}s"
        )
        return plan

    # LIVE EXECUTION (DAY 10)

    if plan["planned_action"] == "BLOCK_IP":
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", plan["ip"], "-j", "DROP"],
            check=False
        )

        mark_executed(
            ip=plan["ip"],
            action=plan["planned_action"],
            cooldown_seconds=plan["cooldown_seconds"]
        )

        plan["executed"] = True
        plan["executed_at"] = datetime.utcnow()

        print(f"[EXECUTED] Blocked IP {plan['ip']}")

    return plan

