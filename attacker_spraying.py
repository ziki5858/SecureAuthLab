import requests
import time
import json
import pyotp
import os
from datetime import datetime
from crypto_utils import GROUP_SEED

SERVER_URL = "http://127.0.0.1:5000"
COMMON_PASSWORDS_PATH = "common_passwords.txt"

# =========================================
# EXPERIMENT LIMITS
# =========================================
MAX_GLOBAL_ATTEMPTS = 1000000
TIME_LIMIT_SECONDS = 7200


def get_experiment_tag():
    """Fetch server configuration to create a tag matching the BF logic."""
    try:
        resp = requests.get(f"{SERVER_URL}/admin/get_config", timeout=5).json()

        # Start with hash_mode (e.g., 'none', 'pbkdf2')
        tag_parts = [resp.get('hash_mode', 'none')]

        # Append active security features to the tag
        if resp.get('used_totp') is True:   tag_parts.append("totp")
        if resp.get('used_salt') is True:   tag_parts.append("salt")
        if resp.get('used_pepper') is True: tag_parts.append("pepper")

        dyn = resp.get('dynamic_defences', {})
        if dyn.get('lockout'):    tag_parts.append("lockout")
        if dyn.get('rate_limit'): tag_parts.append("rl")
        if dyn.get('captcha'):    tag_parts.append("captcha")

        return "_".join(tag_parts)
    except Exception:
        return "unknown_spray"


def main():
    # Ensure required files exist
    if not os.path.exists("users_experiment_private.json"):
        print("[!] Error: users_experiment_private.json not found.")
        return

    if not os.path.exists(COMMON_PASSWORDS_PATH):
        print(f"[!] Error: {COMMON_PASSWORDS_PATH} not found.")
        return

    # Load ground truth and common passwords
    with open("users_experiment_private.json", "r") as f:
        ground_truth = json.load(f)

    with open(COMMON_PASSWORDS_PATH, "r", encoding="utf-8") as f:
        common_passwords = [line.strip() for line in f if line.strip()]

    tag = get_experiment_tag()
    os.makedirs("logs", exist_ok=True)
    log_path = os.path.join("logs", f"spray_{tag}.log")

    print(f"[*] Starting Spraying: {tag} | Saving to: {log_path}")

    global_attempts = 0
    start_time = time.perf_counter()
    locked_users = set()

    with open(log_path, "w", encoding="utf-8") as log_file:
        for password in common_passwords:
            if global_attempts >= MAX_GLOBAL_ATTEMPTS or (time.perf_counter() - start_time) > TIME_LIMIT_SECONDS:
                break

            print(f"[!] Spraying password: '{password}'")
            captcha_token = None

            for user in ground_truth:
                username = user['username']

                if global_attempts >= MAX_GLOBAL_ATTEMPTS or (time.perf_counter() - start_time) > TIME_LIMIT_SECONDS:
                    break

                if username in locked_users:
                    continue

                otp_secret = user.get('secret_totp') or user.get('totp_secret')
                totp = pyotp.TOTP(otp_secret).now() if otp_secret else None

                attempt_start = time.perf_counter()
                try:
                    res = requests.post(f"{SERVER_URL}/login", json={
                        "username": username,
                        "password": password,
                        "totp_code": totp,
                        "captcha_token": captcha_token
                    }, timeout=10)

                    latency_ms = (time.perf_counter() - attempt_start) * 1000
                    global_attempts += 1

                    try:
                        resp_data = res.json()
                        detail = resp_data.get("reason", "unknown")
                    except:
                        detail = "no_json"

                    log_entry = {
                        "timestamp": datetime.now().isoformat(),
                        "group_seed": GROUP_SEED,
                        "username": username,
                        "category": user['category'],
                        "password_tried": password,
                        "latency_ms": round(latency_ms, 3),
                        "global_count": global_attempts,
                        "result": "success" if res.status_code == 200 else "failure",
                        "detail": detail
                    }

                    log_file.write(json.dumps(log_entry) + "\n")
                    log_file.flush()

                    if res.status_code == 200:
                        print(f"    [+] Success! Found: {username}")

                    if res.status_code == 423:
                        print(f"    [!] User {username} is now locked out.")
                        locked_users.add(username)

                    if res.status_code == 403:
                        c_url = f"{SERVER_URL}/admin/get_captcha_token?group_seed={GROUP_SEED}"
                        captcha_token = requests.get(c_url).json().get("captcha_token")

                except Exception as e:
                    print(f"[!] Error during spray for {username}: {e}")
                    continue

    print(f"[*] Spraying finished. Total attempts logged: {global_attempts}")


if __name__ == "__main__":
    main()