import requests

def scan_headers(url):

    required = [
        "X-Frame-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security"
    ]

    try:
        res = requests.get(url, timeout=6)

        missing = [h for h in required if h not in res.headers]

        if missing:
            return {
                "status": "Warning",
                "missing": missing
            }

        return {"status": "Safe"}

    except:
        return {"status": "Error"}