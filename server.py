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
import secrets

# =========================================
# GLOBAL CONFIGURATION
# =========================================

GROUP_SEED = 6631928
GLOBAL_PEPPER_SECRET = os.getenv("MAMAN16_PEPPER")

CONFIG = {
    "rate_limit": False,
    "lockout": False,
    "captcha": False,
    "totp": False,
    "pepper": False
}

RATE_LIMIT_COUNT = 5
RATE_WINDOW = 10
LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION = 60.0  # Seconds
CAPTCHA_THRESHOLD = 3

REQUEST_LOG = defaultdict(list)
FAILED_ATTEMPTS = defaultdict(int)
LOCKED_UNTIL = {}

# CAPTCHA tokens store (minimal but correct simulation)
CAPTCHA_TOKENS = {}  # token -> expiry_time
CAPTCHA_TOKEN_TTL = 180  # seconds

argon2_verify = PasswordHasher(
    time_cost=1,
    memory_cost=65536,
    parallelism=1
)

app = Flask(__name__)
os.makedirs("logs", exist_ok=True)

# =========================================
# HELPERS
# =========================================

try:
    with open("users.json", "r") as f:
        user_list = json.load(f)
    USERS = {user["username"]: user for user in user_list}
    for u in USERS.values():
        u["totp_offset"] = 0
    print(f"[*] Loaded {len(USERS)} users.")
except FileNotFoundError:
    print("[!] ERROR: users.json not found. Run generate_users.py first.")
    USERS = {}


def log_attempt(username, hash_mode, category, result, latency_ms, protection_flags: dict):
    """
    Keep detailed reason in 'detail', but ensure required fields are:
      result: success/failure
      status: success/failure
    """
    status = "success" if result == "success" else "failure"

    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "group_seed": GROUP_SEED,
        "username": username,
        "category": category,
        "hash_mode": hash_mode,
        "protection_flags": protection_flags,
        "latency_ms": round(latency_ms, 3),

        "result": status,
        "status": status,
        "detail": result
    }
    with open("logs/attempts.log", "a") as f:
        f.write(json.dumps(entry) + "\n")


def check_totp(user, token):
    secret = user.get("totp_secret")
    if not secret:
        return True  # no secret => treat as no-TOTP user (lab choice)
    if not token:
        return False

    offset = user.get("totp_offset", 0)
    totp = pyotp.TOTP(secret)
    adjusted_time = time.time() + offset
    return totp.verify(token, for_time=adjusted_time, valid_window=1)


def verify_captcha_token(token: str) -> bool:
    if not token:
        return False
    exp = CAPTCHA_TOKENS.get(token)
    if not exp:
        return False
    if time.time() > exp:
        del CAPTCHA_TOKENS[token]
        return False
    # one-time use
    del CAPTCHA_TOKENS[token]
    return True


def verify_password_hash(password, user):
    """
    Minimal critical fixes:
    - Pepper: if enabled + used_pepper in user => candidate password = pepper + password
      (and works for sha256/bcrypt/argon2id)
    - SHA256 order: sha256( salt + candidate_password )
    """
    mode = user["hash_mode"]
    stored_hash = user["password_hash"]
    salt = user.get("salt", "")  # Might be empty string

    user_hash_is_peppered = bool(user.get("used_pepper", False))

    # Apply pepper ONLY if globally enabled AND user record has it
    if CONFIG["pepper"] and user_hash_is_peppered:
        if not GLOBAL_PEPPER_SECRET:
            return False
        # CONSISTENT ORDER: pepper + password
        pwd_to_check = GLOBAL_PEPPER_SECRET + password
    else:
        pwd_to_check = password

    if mode == "sha256":
        # CONSISTENT ORDER: salt + password
        attempt = hashlib.sha256((salt + pwd_to_check).encode()).hexdigest()
        return attempt == stored_hash

    elif mode == "bcrypt":
        try:
            return bcrypt.checkpw(pwd_to_check.encode(), stored_hash.encode())
        except ValueError:
            return False

    elif mode == "argon2id":
        try:
            return argon2_verify.verify(stored_hash, pwd_to_check)
        except Exception:
            return False

    return False


# =========================================
# ROUTES
# =========================================

@app.route("/reset", methods=["POST"])
def reset_state():
    REQUEST_LOG.clear()
    FAILED_ATTEMPTS.clear()
    LOCKED_UNTIL.clear()
    CAPTCHA_TOKENS.clear()
    for u in USERS.values():
        u["totp_offset"] = 0
    return jsonify({"status": "security state reset"}), 200


@app.route("/admin/get_captcha_token", methods=["GET"])
def get_captcha_token():
    seed_param = request.args.get("group_seed")
    if str(seed_param) == str(GROUP_SEED):
        token = secrets.token_hex(4)
        CAPTCHA_TOKENS[token] = time.time() + CAPTCHA_TOKEN_TTL
        return jsonify({"captcha_token": token, "ttl_sec": CAPTCHA_TOKEN_TTL}), 200
    return jsonify({"error": "unauthorized"}), 403


@app.route("/register", methods=["POST"])
def register():
    # Minimal endpoint to satisfy assignment minimum endpoints.
    # Users are generated offline via generate_users.py
    return jsonify({"status": "fail", "reason": "register_disabled_in_lab"}), 501


@app.route("/login", methods=["POST"])
def login():
    start_time = time.time()
    data = request.json or {}
    username = data.get("username", "unknown")
    password = data.get("password", "")
    totp_input = data.get("totp_code", None)
    captcha_input = data.get("captcha_token", None)

    user = USERS.get(username)
    category = user["category"] if user else "unknown"
    hash_mode = user["hash_mode"] if user else "N/A"
    current_time = time.time()

    # Capture full config state
    current_protection_state = {k: CONFIG[k] for k in CONFIG.keys()}

    # 1. Rate Limit
    if CONFIG["rate_limit"]:
        REQUEST_LOG[username] = [t for t in REQUEST_LOG[username] if current_time - t < RATE_WINDOW]
        if len(REQUEST_LOG[username]) >= RATE_LIMIT_COUNT:
            latency = (time.time() - start_time) * 1000
            log_attempt(username, hash_mode, category, "fail_rate_limit", latency, current_protection_state)
            return jsonify({"status": "fail", "reason": "rate limit exceeded"}), 429
        REQUEST_LOG[username].append(current_time)

    if not user:
        latency = (time.time() - start_time) * 1000
        log_attempt(username, "N/A", "unknown", "fail_user_not_found", latency, current_protection_state)
        return jsonify({"status": "fail", "reason": "invalid credentials"}), 401

    # 2. Lockout
    if CONFIG["lockout"]:
        if username in LOCKED_UNTIL:
            if current_time < LOCKED_UNTIL[username]:
                latency = (time.time() - start_time) * 1000
                log_attempt(username, hash_mode, category, "fail_locked", latency, current_protection_state)
                return jsonify({"status": "fail", "reason": "account locked"}), 423
            else:
                del LOCKED_UNTIL[username]

    # 3. CAPTCHA (now actually validates token)
    if CONFIG["captcha"]:
        if FAILED_ATTEMPTS[username] >= CAPTCHA_THRESHOLD:
            if not verify_captcha_token(captcha_input):
                latency = (time.time() - start_time) * 1000
                log_attempt(username, hash_mode, category, "fail_captcha_required", latency, current_protection_state)
                return jsonify({
                    "status": "fail",
                    "reason": "captcha required",
                    "captcha_required": True
                }), 403

    # 4. Password Verification
    if not verify_password_hash(password, user):
        if CONFIG["lockout"] or CONFIG["captcha"]:
            FAILED_ATTEMPTS[username] += 1
            if CONFIG["lockout"] and FAILED_ATTEMPTS[username] >= LOCKOUT_THRESHOLD:
                LOCKED_UNTIL[username] = current_time + LOCKOUT_DURATION

        latency = (time.time() - start_time) * 1000
        log_attempt(username, hash_mode, category, "fail_password", latency, current_protection_state)
        return jsonify({"status": "fail", "reason": "invalid credentials"}), 401

    # 5. TOTP
    if CONFIG["totp"]:
        if not check_totp(user, totp_input):
            latency = (time.time() - start_time) * 1000
            log_attempt(username, hash_mode, category, "fail_totp", latency, current_protection_state)
            return jsonify({"status": "fail", "reason": "totp invalid"}), 401

    # Success
    FAILED_ATTEMPTS[username] = 0
    if username in LOCKED_UNTIL:
        del LOCKED_UNTIL[username]

    latency = (time.time() - start_time) * 1000
    log_attempt(username, hash_mode, category, "success", latency, current_protection_state)
    return jsonify({"status": "success", "username": username}), 200


@app.route("/login_totp", methods=["POST"])
def login_totp():
    old = CONFIG["totp"]
    CONFIG["totp"] = True
    try:
        return login()
    finally:
        CONFIG["totp"] = old


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rate-limit", action="store_true")
    parser.add_argument("--lockout", action="store_true")
    parser.add_argument("--captcha", action="store_true")
    parser.add_argument("--totp", action="store_true")
    parser.add_argument("--pepper", action="store_true")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    CONFIG.update(vars(args))
    print(f"[*] Server port {args.port}. Active: {[k for k, v in CONFIG.items() if v]}")

    # Safety: if pepper flag enabled but missing env var, warn (lab-friendly)
    if CONFIG["pepper"] and not GLOBAL_PEPPER_SECRET:
        print("[!] WARNING: --pepper enabled but MAMAN16_PEPPER is not set. Peppered users will fail login.")

    app.run(host="0.0.0.0", port=args.port, debug=False)
