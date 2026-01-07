from flask import Flask, request, jsonify
import json
import time
import os
import secrets
import argparse
import hashlib
import bcrypt
from datetime import datetime
from collections import defaultdict
import pyotp

import crypto_utils

app = Flask(__name__)

# =========================================
# CONFIGURATION & STATE
# =========================================

CONFIG = {
    "rate_limit": False,
    "lockout": False,
    "captcha": False,
    "totp": False,
    "pepper": False,
}

# Experiment Parameters
RATE_LIMIT_COUNT = 5
RATE_WINDOW = 10.0  # seconds
LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION = 60.0  # seconds
CAPTCHA_THRESHOLD = 3
CAPTCHA_TTL = 300  # seconds

# In-Memory State (Reset on restart)
REQUEST_LOG = defaultdict(list)  # For Rate Limiting
FAILED_ATTEMPTS = defaultdict(int)  # For Lockout/CAPTCHA triggers
LOCKED_UNTIL = {}  # For Lockout enforcement
CAPTCHA_TOKENS = {}  # Valid tokens for automation

# =========================================
# DATA LOADING
# =========================================

SERVER_DATA_PATH = "server_data.json"
USERS = {}


def load_users():
    """Loads users from the pre-processed JSON file."""
    global USERS
    if not os.path.exists(SERVER_DATA_PATH):
        raise Exception(f"[!] CRITICAL: {SERVER_DATA_PATH} not found. Run generate_server_db.py first.")

    with open(SERVER_DATA_PATH, "r", encoding="utf-8") as f:
        user_list = json.load(f)
        # Convert list to dict for O(1) lookup
        USERS = {u["username"]: u for u in user_list}

    print(f"[*] Loaded {len(USERS)} users.")
    print(f"[*] Group Seed: {crypto_utils.GROUP_SEED}")



# =========================================
# VERIFICATION LOGIC
# =========================================
def verify_password(user_entry, provided_password):
    """
    Automatically detects the security settings for each user_entry
    based on the metadata
    """
    stored_credential = user_entry["password"]

    #Pepper Detection
    if user_entry.get("used_pepper", False):
        if not crypto_utils.GLOBAL_PEPPER_SECRET:
            print("[!] Error: Pepper is required by data but missing in Server.")
            return False
        pwd_to_check = crypto_utils.GLOBAL_PEPPER_SECRET + provided_password
    else:
        pwd_to_check = provided_password

    #Hash Mode Detection
    mode = user_entry.get("hash_mode", "none")

    try:
        if mode == "argon2":
            return crypto_utils.argon2_hasher.verify(stored_credential, pwd_to_check)

        elif mode == "bcrypt":
            return bcrypt.checkpw(pwd_to_check.encode(), stored_credential.encode())

        elif mode == "sha":
            salt = user_entry.get("salt", "")
            # Reconstruct: sha256(salt + peppered_password)
            check = hashlib.sha256((salt + pwd_to_check).encode()).hexdigest()
            return check == stored_credential


        else:
            salt = user_entry.get("salt", "")
            return (pwd_to_check + salt) == stored_credential

    except Exception as e:
        print(f"[!] Verification fail: {e}")
        return False


def verify_totp(user_entry, token):
    """Verifies TOTP token if user_entry has a secret."""
    secret = user_entry.get("totp_secret")
    if not secret:
        return True  # If user_entry has no secret, skip TOTP check

    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=1)


# =========================================
# ROUTES
# =========================================

@app.route("/login", methods=["POST"])
def login():
    start_time = time.time()
    data = request.json or {}

    username = data.get("username", "unknown")
    password = data.get("password", "")
    totp_input = data.get("totp_code")
    captcha_input = data.get("captcha_token")

    user_entry = USERS.get(username)
    category = user_entry["category"] if user_entry else "unknown"
    # --- LAYER 1: RATE LIMITING ---
    if CONFIG["rate_limit"]:
        now = time.time()
        # Filter old requests
        REQUEST_LOG[username] = [t for t in REQUEST_LOG[username] if now - t < RATE_WINDOW]

        if len(REQUEST_LOG[username]) >= RATE_LIMIT_COUNT:
            latency = (time.time() - start_time) * 1000
            return jsonify({"status": "fail", "reason": "rate limit exceeded"}), 429

        REQUEST_LOG[username].append(now)

    # --- LAYER 2: USER EXISTENCE ---
    if not user_entry:
        latency = (time.time() - start_time) * 1000
        return jsonify({"status": "fail", "reason": "invalid credentials"}), 401

    # --- LAYER 3: ACCOUNT LOCKOUT ---
    if CONFIG["lockout"] and username in LOCKED_UNTIL:
        if time.time() < LOCKED_UNTIL[username]:
            latency = (time.time() - start_time) * 1000
            return jsonify({"status": "fail", "reason": "account locked"}), 423
        else:
            del LOCKED_UNTIL[username]  # Lock expired

    # --- LAYER 4: CAPTCHA ENFORCEMENT ---
    if CONFIG["captcha"] and FAILED_ATTEMPTS[username] >= CAPTCHA_THRESHOLD:
        # Check if valid token provided
        if not captcha_input or \
                captcha_input not in CAPTCHA_TOKENS or \
                time.time() > CAPTCHA_TOKENS[captcha_input]:
            latency = (time.time() - start_time) * 1000
            return jsonify({
                "status": "fail",
                "reason": "captcha required",
                "captcha_required": True
            }), 403

        # Burn token (one-time use)
        del CAPTCHA_TOKENS[captcha_input]

    # --- LAYER 5: PASSWORD VERIFICATION ---
    if not verify_password(user_entry, password):
        # Handle Failure
        FAILED_ATTEMPTS[username] += 1 # need to be per ip

        # Trigger Lockout if threshold reached
        if CONFIG["lockout"] and FAILED_ATTEMPTS[username] >= LOCKOUT_THRESHOLD:
            LOCKED_UNTIL[username] = time.time() + LOCKOUT_DURATION

        latency = (time.time() - start_time) * 1000
        return jsonify({"status": "fail", "reason": "invalid credentials"}), 401

    # --- LAYER 6: TOTP VERIFICATION ---
    if CONFIG["totp"]:
        if not verify_totp(user_entry, totp_input):
            latency = (time.time() - start_time) * 1000
            return jsonify({"status": "fail", "reason": "totp invalid"}), 401

    # --- SUCCESS ---
    FAILED_ATTEMPTS[username] = 0  # Reset failures on success
    if username in LOCKED_UNTIL: del LOCKED_UNTIL[username]

    latency = (time.time() - start_time) * 1000
    return jsonify({"status": "success", "username": username}), 200


@app.route("/admin/get_captcha_token", methods=["GET"])
def get_captcha_token():
    """
    Automation endpoint for the attacker script to solve CAPTCHA.
    Requires providing the correct GROUP_SEED.
    """
    seed_param = request.args.get("group_seed")
    if str(seed_param) == str(crypto_utils.GROUP_SEED):
        token = secrets.token_hex(6)
        CAPTCHA_TOKENS[token] = time.time() + CAPTCHA_TTL
        return jsonify({"captcha_token": token, "ttl": CAPTCHA_TTL}), 200

    return jsonify({"error": "unauthorized"}), 403


@app.route("/admin/get_config", methods=["GET"])
def get_server_config():
    """
       Exposes current server protections and data-level metadata
       for automated log tagging in attacker scripts.
       """
    first_user = next(iter(USERS.values()), {})

    config_info = {
        "hash_mode": first_user.get("hash_mode", "none"),
        "used_pepper": first_user.get("used_pepper", False),
        "used_salt": bool(first_user.get("salt")),
        "used_totp": bool(first_user.get("totp_secret")),
        "dynamic_defences": CONFIG,
        "group_seed": crypto_utils.GROUP_SEED
    }
    return jsonify(config_info), 200

# =========================================
# MAIN
# =========================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure Auth Server Experiment")
    parser.add_argument("--rate-limit", action="store_true", help="Enable Rate Limiting")
    parser.add_argument("--lockout", action="store_true", help="Enable Account Lockout")
    parser.add_argument("--captcha", action="store_true", help="Enable CAPTCHA Simulation")
    parser.add_argument("--totp", action="store_true", help="Enable TOTP Requirement")
    parser.add_argument("--pepper", action="store_true", help="Enable Global Pepper")
    parser.add_argument("--port", type=int, default=5000)

    args = parser.parse_args()

    # Update Config
    CONFIG["rate_limit"] = args.rate_limit
    CONFIG["lockout"] = args.lockout
    CONFIG["captcha"] = args.captcha
    CONFIG["totp"] = args.totp
    CONFIG["pepper"] = args.pepper

    # Initial Setup
    load_users()

    active_defences = [k for k, v in CONFIG.items() if v]
    print(f"[*] Server starting on port {args.port}")
    print(f"[*] Active Defences: {active_defences if active_defences else 'None'}")

    app.run(host="0.0.0.0", port=args.port, debug=False, threaded=True)