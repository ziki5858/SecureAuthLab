import requests
import time
import json
import pyotp
import itertools
import string
import os
from datetime import datetime
from crypto_utils import GROUP_SEED

SERVER_URL = "http://127.0.0.1:5000"
CHAR_SET = string.ascii_lowercase + string.digits + string.punctuation

# =========================================
# EXPERIMENT LIMITS
# =========================================
MAX_USER_ATTEMPTS = 100
MAX_GLOBAL_ATTEMPTS = 1000000
TIME_LIMIT_SECONDS = 7200


def get_experiment_tag():
    try:
        resp = requests.get(f"{SERVER_URL}/admin/get_config", timeout=5).json()

        tag_parts = [resp.get('hash_mode', 'none')]

        if resp.get('used_totp') is True:   tag_parts.append("totp")
        if resp.get('used_salt') is True:   tag_parts.append("salt")
        if resp.get('used_pepper') is True: tag_parts.append("pepper")

        dyn = resp.get('dynamic_defences', {})
        if dyn.get('lockout'):    tag_parts.append("lockout")
        if dyn.get('rate_limit'): tag_parts.append("rl")
        if dyn.get('captcha'):    tag_parts.append("captcha")

        return "_".join(tag_parts)
    except Exception as e:
        return "unknown_bf"

def infinite_password_generator(chars):
    for length in itertools.count(1):
        for combo in itertools.product(chars, repeat=length):
            yield "".join(combo)


def main():
    if not os.path.exists("users_experiment_private.json"):
        print("[!] Error: users_experiment_private.json not found.")
        return

    with open("users_experiment_private.json", "r") as f:
        ground_truth = json.load(f)

    tag = get_experiment_tag()
    os.makedirs("logs", exist_ok=True)
    log_filename = f"bf_{tag}.log"  # <--- NEW: Storing filename for the log entry
    log_path = os.path.join("logs", log_filename)

    print(f"[*] Starting Brute Force: {tag} | Saving to: {log_path}")

    global_attempts = 0
    start_time = time.perf_counter()

    # Get server config once to include in logs
    try:
        server_cfg = requests.get(f"{SERVER_URL}/admin/get_config").json()
        protection_flags = server_cfg.get("dynamic_defences")  # <--- NEW: Get flags
    except:
        protection_flags = {}

    with open(log_path, "w", encoding="utf-8") as log_file:
        for user in ground_truth:
            current_elapsed = time.perf_counter() - start_time
            if global_attempts >= MAX_GLOBAL_ATTEMPTS or current_elapsed > TIME_LIMIT_SECONDS:
                break

            print(f"[>] Testing user: {user['username']}")
            captcha_token = None
            user_attempts = 0
            combinations = infinite_password_generator(CHAR_SET)

            for guess in combinations:
                if user_attempts >= MAX_USER_ATTEMPTS or global_attempts >= MAX_GLOBAL_ATTEMPTS:
                    break
                if (time.perf_counter() - start_time) > TIME_LIMIT_SECONDS:
                    break

                user_attempts += 1
                global_attempts += 1

                otp_secret = user.get('secret_totp') or user.get('totp_secret')
                totp = pyotp.TOTP(otp_secret).now() if otp_secret else None

                attempt_start = time.perf_counter()
                try:
                    res = requests.post(f"{SERVER_URL}/login", json={
                        "username": user['username'],
                        "password": guess,
                        "totp_code": totp,
                        "captcha_token": captcha_token
                    }, timeout=10)

                    latency_ms = (time.perf_counter() - attempt_start) * 1000

                    try:
                        resp_data = res.json()
                        detail = resp_data.get("reason", "unknown")
                    except:
                        detail = "no_json"


                    log_entry = {
                        "timestamp": datetime.now().isoformat(),
                        "group_seed": GROUP_SEED,
                        "username": user['username'],
                        "category": user['category'],
                        "password_tried": guess,
                        "latency_ms": round(latency_ms, 3),
                        "global_count": global_attempts,
                        "result": "success" if res.status_code == 200 else "failure",
                        "detail": detail
                    }

                    log_file.write(json.dumps(log_entry) + "\n")
                    log_file.flush()

                    if res.status_code == 200:
                        print(f"[+] Success! Cracked {user['username']} with: {guess}")
                        break

                    if res.status_code == 423:
                        print(f"[!] User {user['username']} is locked out.")
                        break

                    if res.status_code == 403:
                        c_url = f"{SERVER_URL}/admin/get_captcha_token?group_seed={GROUP_SEED}"
                        captcha_token = requests.get(c_url).json().get("captcha_token")

                except Exception as e:
                    print(f"[!] Connection error: {e}")
                    break

    print(f"[*] Experiment finished. Total attempts: {global_attempts}")


if __name__ == "__main__":
    main()