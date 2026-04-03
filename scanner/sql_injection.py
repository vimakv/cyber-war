import requests

def scan_sql(url):
    try:
        requests.get(url)
        return "Safe"
    except:
        return "Error"