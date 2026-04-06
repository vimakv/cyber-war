import time

def simulate_bruteforce():
    passwords = ["admin", "123456", "password", "admin@123"]
    attempts = []

    for p in passwords:
        attempts.append(f"Trying password: {p}")
        time.sleep(0.2)

    return {
        "status": "Simulated",
        "attempts": len(passwords),
        "result": "Weak passwords detected (demo)",
        "details": attempts
    }