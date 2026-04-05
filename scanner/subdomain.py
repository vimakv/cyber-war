import requests

def scan_subdomains(domain):
    subs = ["www","mail","ftp","test","dev","api","blog"]

    found = []

    for sub in subs:
        url = f"http://{sub}.{domain}"

        try:
            requests.get(url, timeout=2)
            found.append(sub)
        except:
            pass

    if found:
        return "Found: " + ", ".join(found)

    return "No subdomains found"