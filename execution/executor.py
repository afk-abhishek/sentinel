import subprocess
from datetime import datetime
from execution.state import is_action_in_cooldown, mark_action_executed

LIVE_MODE = False  # Safety first
PROTECTED_IPS = {"127.0.0.1", "::1"}


def approve_execution(plan):
    ip = plan["ip"]
    action = plan["planned_action"]

    if ip in PROTECTED_IPS:
        return False, "Protected IP"

    if is_in_cooldown(ip, action):
        return False, "IP-action in cooldown period"

    if action == "BLOCK_IP" and plan["confidence"] != "HIGH":
        return False, "Insufficient confidence"

    return True, "Approved"


def execute_plan(plan):
    approved, reason = approve_execution(plan)

    if not approved:
        print(
            f"[EXECUTION-SKIPPED] {plan['planned_action']} | "
            f"IP {plan['ip']} | Reason: {reason}"
        )
        plan["execution_status"] = "SKIPPED"
        plan["execution_reason"] = reason
        return plan

    # Mark execution intent EVEN in dry-run
    mark_executed(
        ip=plan["ip"],
        action=plan["planned_action"],
        cooldown_seconds=plan["cooldown_seconds"]
    )

    if not LIVE_MODE:
        print(
            f"[DRY-RUN] Would execute {plan['planned_action']} "
            f"on {plan['ip']} for {plan['cooldown_seconds']}s"
        )
        plan["execution_status"] = "DRY-RUN"
        return plan

    # LIVE EXECUTION 

    if plan["planned_action"] == "BLOCK_IP":
        # IPv6 vs IPv4 handling
        if ":" in plan["ip"]:
            cmd = ["ip6tables", "-A", "INPUT", "-s", plan["ip"], "-j", "DROP"]
        else:
            cmd = ["iptables", "-A", "INPUT", "-s", plan["ip"], "-j", "DROP"]

        subprocess.run(cmd, check=False)

        plan["executed"] = True
        plan["executed_at"] = datetime.utcnow()
        plan["execution_status"] = "EXECUTED"

        print(f"[EXECUTED] Blocked IP {plan['ip']}")

    return plan

