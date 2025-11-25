import requests
import string
import time
import os
import json
import itertools

# ======================================
# GENERAL SETTINGS
# ======================================
MAX_ATTEMPTS = 20000
MAX_TIME = 30
GROUP_SEED = "GROUP42"

os.makedirs("logs", exist_ok=True)

# ======================================
# USERS + CATEGORIES
# ======================================
USERS = {
    "weak": {
        "username": "user01",
        "charset": string.ascii_lowercase + string.digits,
        "min_len": 4,
        "max_len": 6
    },
    "medium": {
        "username": "user11",
        "charset": string.ascii_letters + string.digits,
        "min_len": 7,
        "max_len": 10
    },
    "strong": {
        "username": "user21",
        "charset": string.ascii_letters + string.digits + "!@#$%^&*",
        "min_len": 11,
        "max_len": 16
    }
}

# ======================================
# SEND LOGIN ATTEMPT
# ======================================
def send_attempt(url, username, password):
    """Send login attempt + measure latency."""
    t0 = time.time()
    try:
        r = requests.post(url, json={
            "username": username,
            "password": password
        })
        latency = (time.time() - t0) * 1000
        data = r.json()
        return data.get("status"), latency
    except:
        return "error", (time.time() - t0) * 1000


# ======================================
# GENERATE PASSWORDS IN RANGE
# ======================================
def generate_passwords(charset, min_len, max_len):
    """Yield passwords between min_len and max_len inclusive."""
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            yield "".join(combo)


# ======================================
# BRUTE FORCE FOR ONE LOG FILE
# ======================================
def brute_force_attack(url, hash_mode, protections_flag, logfile):
    start_time = time.time()
    attempts = 0

    with open(logfile, "w") as f:
        pass  # reset file

    print(f"\n>>> START brute-force: {hash_mode}, protections={protections_flag}")
    print(f"→ Log: {logfile}")

    while True:
        elapsed = time.time() - start_time
        if attempts >= MAX_ATTEMPTS or elapsed >= MAX_TIME:
            print(f"STOP: attempts={attempts}, time={round(elapsed, 2)} sec")
            return

        for category, cfg in USERS.items():
            username = cfg["username"]
            charset = cfg["charset"]
            min_len = cfg["min_len"]
            max_len = cfg["max_len"]

            for pwd in generate_passwords(charset, min_len, max_len):
                attempts += 1

                status, lat_ms = send_attempt(url, username, pwd)

                entry = {
                    "timestamp": time.time(),
                    "group_seed": GROUP_SEED,
                    "username": username,
                    "category": category,
                    "password_attempt": pwd,
                    "result": status,
                    "latency_ms": round(lat_ms, 3),
                    "hash_mode": hash_mode,
                    "protection_flags": protections_flag
                }

                with open(logfile, "a") as f:
                    f.write(json.dumps(entry) + "\n")

                if attempts >= MAX_ATTEMPTS or (time.time() - start_time) >= MAX_TIME:
                    return

                if status == "success":
                    print(f"[+] SUCCESS for {username} → {pwd}")
                    return


# ======================================
# MAIN (6 LOG FILES)
# ======================================
def main():

    CONFIGS = [
        ("sha256",   "OFF", "http://127.0.0.1:6000/login"),
        ("sha256",   "ON",  "http://127.0.0.1:5000/login"),

        ("bcrypt",   "OFF", "http://127.0.0.1:6000/login"),
        ("bcrypt",   "ON",  "http://127.0.0.1:5000/login"),

        ("argon2id", "OFF", "http://127.0.0.1:6000/login"),
        ("argon2id", "ON",  "http://127.0.0.1:5000/login"),
    ]

    for hash_mode, prot, url in CONFIGS:

        # ===================================
        # RESET SERVER STATE BEFORE ATTACK
        # ===================================
        reset_url = url.replace("/login", "/reset")
        try:
            requests.post(reset_url)
            print(f"[RESET] Server counters cleared at {reset_url}")
        except:
            print(f"[RESET ERROR] Could not reset server at {reset_url}")

        logfile = f"logs/{hash_mode}_{'with' if prot=='ON' else 'no'}_protection.log"
        brute_force_attack(url, hash_mode, prot, logfile)


main()
