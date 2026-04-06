def calculate_severity(result):

    score = 0

    if result.get("SQL", {}).get("status") == "Vulnerable":
        score += 4

    if result.get("XSS", {}).get("status") in ["Vulnerable", "Possible"]:
        score += 3

    if result.get("Headers", {}).get("status") == "Warning":
        score += 2

    if score >= 6:
        return "High"
    elif score >= 3:
        return "Medium"
    else:
        return "Low"