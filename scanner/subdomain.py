import requests

def scan_subdomains(domain):

    subdomains = ["www", "mail", "ftp", "api", "dev", "test"]
    found = []

    for sub in subdomains:
        url = f"http://{sub}.{domain}"

        try:
            requests.get(url, timeout=3)
            found.append(url)
        except:
            continue

    return found