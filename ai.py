def explain(result):
    try:
        explanation = []

        # SQL
        if result.get("SQL", {}).get("status") == "Vulnerable":
            explanation.append("⚠️ SQL Injection → Use parameterized queries")

        # XSS
        if result.get("XSS", {}).get("status") in ["Vulnerable", "Possible"]:
            explanation.append("⚠️ XSS → Sanitize user inputs")

        # Headers
        if result.get("Headers", {}).get("status") == "Warning":
            explanation.append("🛡 Missing security headers → Add CSP, HSTS, X-Frame-Options")

        # Default safe message
        if not explanation:
            explanation.append("✅ No major vulnerabilities found")

        return " | ".join(explanation).strip()

    except Exception as e:
        return f"AI Error: {str(e)}"