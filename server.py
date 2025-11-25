from flask import Flask, request, jsonify
import json
import time
import hashlib
import bcrypt
from argon2 import PasswordHasher
from datetime import datetime
from collections import defaultdict
import pyotp
import os
import argparse

# =========================================
# GLOBAL CONFIGURATION
# =========================================

GROUP_SEED = 6631928
ENABLE_PROTECTIONS = True

RATE_LIMIT = 5
RATE_WINDOW = 10
REQUEST_LOG = defaultdict(list)

LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION = 60
FAILED_ATTEMPTS = defaultdict(int)
LOCKED_UNTIL = {}

CAPTCHA_THRESHOLD = 3
CAPTCHA_VALUE = "IAMHUMAN"

PEPPER = "my_super_secret_pepper_123"

os.makedirs("logs", exist_ok=True)

# =========================================
# LOAD USERS
# =========================================

with open("users.json", "r") as f:
    user_list = json.load(f)

USERS = {user["username"]: user for user in user_list}

argon2_verify = PasswordHasher(
    time_cost=1,
    memory_cost=65536,
    parallelism=1
)

app = Flask(__name__)


# =========================================
# RESET SECURITY STATE
# =========================================

def reset_security_state():
    """Clear all rate-limit, lockout, and failed-attempt counters."""
    REQUEST_LOG.clear()
    FAILED_ATTEMPTS.clear()
    LOCKED_UNTIL.clear()


@app.route("/reset", methods=["POST"])
def reset():
    reset_security_state()
    return jsonify({"status": "reset"}), 200


# =========================================
# PASSWORD VERIFICATION
# =========================================

def verify_password(password_attempt: str, user: dict) -> bool:
    hash_mode = user["hash_mode"]
    stored_hash = user["password_hash"]
    salt = user["salt"]
    use_pepper = user.get("use_pepper", False)

    pwd = (password_attempt + PEPPER) if use_pepper else password_attempt

    if hash_mode == "sha256":
        attempt_hash = hashlib.sha256((pwd + salt).encode()).hexdigest()
        return attempt_hash == stored_hash

    elif hash_mode == "bcrypt":
        return bcrypt.checkpw(pwd.encode(), stored_hash.encode())

    elif hash_mode == "argon2id":
        try:
            argon2_verify.verify(stored_hash, pwd)
            return True
        except Exception:
            return False

    return False


# =========================================
# TOTP VERIFICATION
# =========================================

def verify_totp(user: dict, totp_code: str | None) -> bool:
    secret = user.get("totp_secret", "")
    if not secret:
        return True
    if not totp_code:
        return False

    totp = pyotp.TOTP(secret)
    return totp.verify(totp_code, valid_window=1)


# =========================================
# RAW ATTEMPT LOGGING
# =========================================

def log_attempt(username, hash_mode, category, result,
                latency_ms, protections_enabled, protection_flags):

    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "group_seed": GROUP_SEED,
        "username": username,
        "category": category,
        "hash_mode": hash_mode,
        "protections_enabled": protections_enabled,
        "protection_flags": protection_flags,
        "latency_ms": round(latency_ms, 3),
        "result": result
    }

    with open("logs/attempts.log", "a") as f:
        f.write(json.dumps(entry) + "\n")


# =========================================
# LOGIN ENDPOINT
# =========================================

@app.route("/login", methods=["POST"])
def login():
    global ENABLE_PROTECTIONS

    start_time = time.time()
    protection_flags = []

    data = request.json or {}
    username = data.get("username", "")
    password_attempt = data.get("password", "")
    captcha_value = data.get("captcha")
    totp_code = data.get("totp_code")

    now = time.time()

    user = USERS.get(username)
    hash_mode = user["hash_mode"] if user else "N/A"
    category = user.get("category", "unknown") if user else "unknown"

    # If protections are OFF, ignore all rate-limit, lockout, captcha, totp
    if ENABLE_PROTECTIONS:

        # Rate limit
        REQUEST_LOG[username] = [
            t for t in REQUEST_LOG[username] if now - t < RATE_WINDOW
        ]

        if len(REQUEST_LOG[username]) >= RATE_LIMIT:
            protection_flags.append("rate_limit")
            latency = (time.time() - start_time) * 1000
            log_attempt(username, hash_mode, category, "fail",
                        latency, ENABLE_PROTECTIONS, protection_flags)
            return jsonify({"status": "fail", "reason": "rate limited"}), 429

        REQUEST_LOG[username].append(now)

        # Unknown user
        if username not in USERS:
            latency = (time.time() - start_time) * 1000
            log_attempt(username, "N/A", "unknown", "fail",
                        latency, ENABLE_PROTECTIONS, protection_flags)
            return jsonify({"status": "fail", "reason": "user not found"}), 400

        # Lockout
        locked_until = LOCKED_UNTIL.get(username)
        if locked_until and now < locked_until:
            protection_flags.append("lockout_active")
            latency = (time.time() - start_time) * 1000
            log_attempt(username, hash_mode, category, "fail",
                        latency, ENABLE_PROTECTIONS, protection_flags)
            return jsonify({"status": "fail", "reason": "account locked"}), 423

        # CAPTCHA
        if FAILED_ATTEMPTS[username] >= CAPTCHA_THRESHOLD:
            if captcha_value != CAPTCHA_VALUE:
                protection_flags.append("captcha_required")
                latency = (time.time() - start_time) * 1000
                log_attempt(username, hash_mode, category, "fail",
                            latency, ENABLE_PROTECTIONS, protection_flags)
                return jsonify({"status": "fail", "reason": "captcha required"}), 403

    # If protections are OFF, just validate password
    else:
        if username not in USERS:
            latency = (time.time() - start_time) * 1000
            log_attempt(username, "N/A", "unknown", "fail",
                        latency, False, [])
            return jsonify({"status": "fail", "reason": "user not found"}), 400

    # Password verification
    ok = verify_password(password_attempt, user)

    if not ok:
        if ENABLE_PROTECTIONS:
            FAILED_ATTEMPTS[username] += 1
            if FAILED_ATTEMPTS[username] >= LOCKOUT_THRESHOLD:
                LOCKED_UNTIL[username] = now + LOCKOUT_DURATION
                protection_flags.append("lockout_set")

        latency = (time.time() - start_time) * 1000
        log_attempt(username, hash_mode, category, "fail",
                    latency, ENABLE_PROTECTIONS, protection_flags)
        return jsonify({"status": "fail", "reason": "wrong password"}), 401

    # Reset after success
    if ENABLE_PROTECTIONS:
        FAILED_ATTEMPTS[username] = 0
        LOCKED_UNTIL.pop(username, None)

        # TOTP
        if not verify_totp(user, totp_code):
            protection_flags.append("totp_failed")
            latency = (time.time() - start_time) * 1000
            log_attempt(username, hash_mode, category, "fail",
                        latency, ENABLE_PROTECTIONS, protection_flags)
            return jsonify({"status": "fail", "reason": "totp required or invalid"}), 401

        if user.get("totp_secret"):
            protection_flags.append("totp_passed")

    latency = (time.time() - start_time) * 1000
    log_attempt(username, hash_mode, category, "success",
                latency, ENABLE_PROTECTIONS, protection_flags)

    return jsonify({"status": "success"}), 200


# =========================================
# MAIN
# =========================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--protections",
        choices=["on", "off"],
        default="on",
        help="Enable or disable all security protections."
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Port to bind the server."
    )
    args = parser.parse_args()

    ENABLE_PROTECTIONS = (args.protections == "on")
    print(f"[*] ENABLE_PROTECTIONS = {ENABLE_PROTECTIONS}")

    reset_security_state()

    app.run(host="0.0.0.0", port=args.port, debug=True)
