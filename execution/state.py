from datetime import datetime, timedelta

# in-memory execution state
# key: (ip, action)
EXECUTION_STATE = {}


def is_in_cooldown(ip, action):
    state = EXECUTION_STATE.get((ip, action))
    if not state:
        return False

    cooldown_until = state.get("cooldown_until")
    if not cooldown_until:
        return False

    return datetime.utcnow() < cooldown_until


def mark_executed(ip, action, cooldown_seconds):
    now = datetime.utcnow()

    EXECUTION_STATE[(ip, action)] = {
        "last_action": action,
        "executed_at": now,
        "cooldown_until": (
            now + timedelta(seconds=cooldown_seconds)
            if cooldown_seconds > 0
            else None
        )
    }


def get_state(ip, action=None):
    if action:
        return EXECUTION_STATE.get((ip, action))

    # return all actions for an IP
    return {
        k[1]: v
        for k, v in EXECUTION_STATE.items()
        if k[0] == ip
    }

