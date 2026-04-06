import requests

def scan_sql(url):

    payloads = [
        "'",
        "' OR '1'='1",
        "' OR 1=1 --"
    ]

    sql_errors = [
        "sql syntax",
        "mysql",
        "syntax error",
        "unclosed quotation",
        "database error",
        "sqlstate"
    ]

    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        for payload in payloads:

            if "?" in url:
                test_url = url + "&id=" + payload
            else:
                test_url = url + "?id=" + payload

            res = requests.get(test_url, headers=headers, timeout=6)
            content = res.text.lower()

            # STRICT: only error-based detection
            for err in sql_errors:
                if err in content:
                    return {
                        "status": "Vulnerable",
                        "reason": "SQL error message detected"
                    }

        return {"status": "Safe"}

    except requests.exceptions.Timeout:
        return {"status": "Timeout"}

    except:
        return {"status": "Unreachable"}