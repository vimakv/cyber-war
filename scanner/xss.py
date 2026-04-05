import requests

def scan_xss(url):
    payloads = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>"
    ]

    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    try:
        for payload in payloads:

            if "?" in url:
                test_url = url + "&q=" + payload
            else:
                test_url = url + "?q=" + payload

            r = requests.get(test_url, headers=headers, timeout=5)

            # 🔥 reflected XSS check
            if payload.lower() in r.text.lower():
                return "Vulnerable"

        return "Safe"

    except requests.exceptions.Timeout:
        return "Timeout"
    except:
        return "Unreachable"