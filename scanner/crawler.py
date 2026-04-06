import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl(url, max_pages=10):
    visited = set()
    to_visit = [url]

    domain = urlparse(url).netloc

    while to_visit and len(visited) < max_pages:
        current = to_visit.pop(0)

        try:
            res = requests.get(current, timeout=5)
            soup = BeautifulSoup(res.text, "html.parser")

            visited.add(current)

            for link in soup.find_all("a", href=True):
                full_url = urljoin(current, link['href'])

                if urlparse(full_url).netloc == domain:
                    if full_url not in visited:
                        to_visit.append(full_url)

        except:
            continue

    return list(visited)