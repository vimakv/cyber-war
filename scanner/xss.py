import requests

def scan_xss(url):
    payload="<script>alert(1)</script>"
    try:
        r=requests.get(url,params={"q":payload})
        if payload in r.text:
            return "Vulnerable"
    except:
        return "Error"
    return "Safe"