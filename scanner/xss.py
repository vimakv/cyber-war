import requests

def scan_xss(url):
    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "\"><script>alert(1)</script>"
    ]

    try:
        for payload in payloads:

            if "?" in url:
                test_url = url + "&q=" + payload
            else:
                test_url = url + "?q=" + payload

            res = requests.get(test_url, timeout=4)

            if payload.lower() in res.text.lower():
                return "Vulnerable"

        return "Safe"

    except requests.exceptions.Timeout:
        return "No Response"
    except Exception as e:
        return "Error"