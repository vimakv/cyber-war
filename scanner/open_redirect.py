import requests
from urllib.parse import urlparse

def scan_redirect(url):

    payload = "https://example.com"

    try:
        # Inject payload
        if "?" in url:
            test_url = url + "&redirect=" + payload
        else:
            test_url = url + "?redirect=" + payload

        res = requests.get(test_url, allow_redirects=False, timeout=6)

        location = res.headers.get("Location", "")

        if not location:
            return {"status": "Safe"}

        # Extract domains
        original_domain = urlparse(url).netloc
        redirect_domain = urlparse(location).netloc

        # Only flag if redirect goes OUTSIDE original domain
        if redirect_domain and redirect_domain != original_domain:
            if "example.com" in redirect_domain:
                return {
                    "status": "Possible",
                    "reason": "External redirect allowed"
                }

        return {"status": "Safe"}

    except requests.exceptions.Timeout:
        return {"status": "Timeout"}

    except:
        return {"status": "Error"}