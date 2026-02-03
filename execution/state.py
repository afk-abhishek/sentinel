from datetime import datetime, timedelta

STATE = {}


def _now():
    return datetime.utcnow()


def _ensure_ip(ip):
    if ip not in STATE:
        STATE[ip] = {
            "actions": {},
            "alerts": {}
        }


# Execution / Cooldown 

def is_action_in_cooldown(ip, action):
    _ensure_ip(ip)
    action_state = STATE[ip]["actions"].get(action)

    if not action_state:
        return False

    cooldown_until = action_state.get("cooldown_until")
    return cooldown_until and _now() < cooldown_until


def mark_action_executed(ip, action, cooldown_seconds=0):
    _ensure_ip(ip)
    now = _now()

    STATE[ip]["actions"][action] = {
        "executed_at": now,
        "cooldown_until": (
            now + timedelta(seconds=cooldown_seconds)
            if cooldown_seconds > 0 else None
        )
    }


# Alert Tracking 
# Will be used in future: Real-time streaming alerts

def was_alerted_recently(ip, alert_type, window_seconds):  
    _ensure_ip(ip)
    last_alert = STATE[ip]["alerts"].get(alert_type)

    if not last_alert:
        return False

    return _now() - last_alert < timedelta(seconds=window_seconds)


def mark_alerted(ip, alert_type):
    _ensure_ip(ip)
    STATE[ip]["alerts"][alert_type] = _now()


# Debug / Introspection 

def get_ip_state(ip):
    return STATE.get(ip)


def reset_state():
    STATE.clear()

