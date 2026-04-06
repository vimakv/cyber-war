import requests

def scan_xss(url):

    payload = "<script>alert(1)</script>"

    try:
        if "?" in url:
            test_url = url + "&q=" + payload
        else:
            test_url = url + "?q=" + payload

        res = requests.get(test_url, timeout=6)

        if payload in res.text:
            return {
                "status": "Possible",
                "reason": "Payload reflected"
            }

        return {"status": "Safe"}

    except:
        return {"status": "Error"}