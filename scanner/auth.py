import requests

def check_auth(url):
    try:
        res = requests.get(url, timeout=5)
        if res.status_code == 200:
            return "No Authentication"
        elif res.status_code == 401:
            return "Protected"
    except:
        return "Error"

    return "Unknown"