import requests

def scan_redirect(url):
    payload = "https://evil.com"

    try:
        if "?" in url:
            test_url = url + "&redirect=" + payload
        else:
            test_url = url + "?redirect=" + payload

        r = requests.get(test_url, allow_redirects=False, timeout=5)

        if "Location" in r.headers and payload in r.headers["Location"]:
            return "Vulnerable"

        return "Safe"

    except:
        return "Error"