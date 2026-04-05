import requests

def scan_sql(url):
    payloads = [
        "' OR '1'='1",
        "' OR 1=1 --",
        "' OR 'a'='a",
        "\" OR \"1\"=\"1"
    ]

    errors = [
        "sql syntax",
        "mysql",
        "syntax error",
        "unclosed quotation",
        "database error",
        "pdo",
        "odbc"
    ]

    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    try:
        for payload in payloads:

            if "?" in url:
                test_url = url + "&id=" + payload
            else:
                test_url = url + "?id=" + payload

            r = requests.get(test_url, headers=headers, timeout=5)

            content = r.text.lower()

            # 🔥 error-based detection
            for err in errors:
                if err in content:
                    return "Vulnerable"

            # 🔥 response difference check
            normal = requests.get(url, headers=headers, timeout=5)
            if len(r.text) != len(normal.text):
                return "Possible"

        return "Safe"

    except requests.exceptions.Timeout:
        return "Timeout"
    except:
        return "Unreachable"