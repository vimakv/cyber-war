import requests

def scan_headers(url):
    try:
        r = requests.get(url, timeout=5)

        headers = r.headers
        missing = []

        if "Content-Security-Policy" not in headers:
            missing.append("CSP Missing")

        if "X-Frame-Options" not in headers:
            missing.append("Clickjacking Protection Missing")

        if "X-Content-Type-Options" not in headers:
            missing.append("MIME Sniffing Protection Missing")

        if missing:
            return "Vulnerable: " + ", ".join(missing)

        return "Safe"

    except:
        return "Error"