
def calculate_score(alert):
    """
    Calculate a severity score for a given alert.
    """

    # storing scores of attacks in a map 
    base_scores = {
        "invalid_password": 1.0,
        "connection_closed": 0.5,
        "slow_bruteforce": 2.0,
        "password_spray": 3.0
    }

    event_type = alert.get("event_type")
    count = alert.get("count", 1)

    base = base_scores.get(event_type, 1.0)

    score = base * count
    return round(score, 2)

#a simple function to assign severity score
def assign_severity(score):
    """
    Map numeric score to severity label.
    """

    if score >= 10:
        return "CRITICAL"
    elif score >= 6:
        return "HIGH"
    elif score >= 3:
        return "MEDIUM"
    else:
        return "LOW"

#function to be called!
def score_alert(alert):
    """
    Enrich alert with score and severity.
    """

    score = calculate_score(alert)
    severity = assign_severity(score)

    alert["score"] = score
    alert["severity"] = severity
    return alert

