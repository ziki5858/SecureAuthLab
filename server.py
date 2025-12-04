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
# GLOBAL CONFIGURATION & STATE
# =========================================

GROUP_SEED = 6631928
GLOBAL_PEPPER_SECRET = os.getenv("MAMAN16_PEPPER")

if not GLOBAL_PEPPER_SECRET:
    print("[WARNING] MAMAN16_PEPPER env var is not set! Set it before running.")

# Flags
CONFIG = {
    "rate_limit": False,
    "lockout": False,
    "captcha": False,
    "totp": False,
    "pepper": False
}

# Constants
RATE_LIMIT_COUNT = 5
RATE_WINDOW = 10
LOCKOUT_THRESHOLD = 5

# CHANGE: Lockout is now PERMANENT (until admin reset), per professor instructions.
# We use infinity to represent "forever".
LOCKOUT_DURATION = float('inf')

CAPTCHA_THRESHOLD = 3

# State
REQUEST_LOG = defaultdict(list)
FAILED_ATTEMPTS = defaultdict(int)
LOCKED_UNTIL = {}

argon2_verify = PasswordHasher(
    time_cost=1,
    memory_cost=65536,
    parallelism=1
)

app = Flask(__name__)
os.makedirs("logs", exist_ok=True)

# =========================================
# LOAD USERS
# =========================================
try:
    with open("users.json", "r") as f:
        user_list = json.load(f)
    USERS = {user["username"]: user for user in user_list}

    # Initialize TOTP offset for all users (Default 0)
    for u in USERS.values():
        u['totp_offset'] = 0

    print(f"[*] Loaded {len(USERS)} users.")
except FileNotFoundError:
    print("[!] ERROR: users.json not found.")
    USERS = {}


# =========================================
# HELPER FUNCTIONS
# =========================================

def log_attempt(username, hash_mode, category, result, latency_ms, protection_flags):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "group_seed": GROUP_SEED,
        "username": username,
        "category": category,
        "hash_mode": hash_mode,
        "protection_flags": protection_flags,
        "latency_ms": round(latency_ms, 3),
        "result": result
    }
    with open("logs/attempts.log", "a") as f:
        f.write(json.dumps(entry) + "\n")


def check_totp(user, token):
    """Verifies TOTP considering the learned Time Offset."""
    secret = user.get("totp_secret")
    if not secret:
        return True

        # Get the saved offset for this user (learned from sync)
    offset = user.get('totp_offset', 0)
    totp = pyotp.TOTP(secret)

    # We adjust the server's check time by adding the offset
    # If user is +5min ahead, offset is +300. We check at T+300.
    adjusted_time = time.time() + offset

    # valid_window=1 allows for small jitter (+/- 30s) on top of the offset
    return totp.verify(token, for_time=adjusted_time, valid_window=1)


def verify_password_hash(password, user):
    mode = user["hash_mode"]
    stored_hash = user["password_hash"]
    salt = user["salt"]

    pwd_to_check = password
    if CONFIG["pepper"] and GLOBAL_PEPPER_SECRET:
        pwd_to_check = password + GLOBAL_PEPPER_SECRET

    if mode == "sha256":
        attempt = hashlib.sha256((pwd_to_check + salt).encode()).hexdigest()
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
    """Simulates Admin Intervention: Clears all locks and counters."""
    REQUEST_LOG.clear()
    FAILED_ATTEMPTS.clear()
    LOCKED_UNTIL.clear()
    # Reset offsets too (Starting fresh for new experiment)
    for u in USERS.values(): u['totp_offset'] = 0
    return jsonify({"status": "security state reset (admin intervention)"}), 200


@app.route("/admin/get_captcha_token", methods=["GET"])
def get_captcha_token():
    seed_param = request.args.get("group_seed")
    if str(seed_param) == str(GROUP_SEED):
        token = secrets.token_hex(4)
        return jsonify({"captcha_token": token}), 200
    return jsonify({"error": "unauthorized"}), 403


# --- TOTP SYNC ENDPOINT ---
@app.route("/totp/sync", methods=["POST"])
def totp_sync():
    """
    Checks if the server can adapt to drift.
    We search for the code in a window of +/- 10 minutes.
    """
    data = request.json or {}
    username = data.get("username")
    code = data.get("totp_code")

    user = USERS.get(username)
    if not user or not user.get("totp_secret"):
        return jsonify({"status": "fail", "reason": "user not found or no totp"}), 400

    secret = user["totp_secret"]
    totp = pyotp.TOTP(secret)
    now = time.time()

    # Search window: +/- 600 seconds (10 minutes)
    for drift in range(-600, 601, 30):
        if totp.verify(code, for_time=now + drift, valid_window=0):
            user['totp_offset'] = drift
            print(f"[*] SYNCED: User {username} has drift of {drift} seconds.")
            return jsonify({"status": "success", "synced_drift": drift}), 200

    return jsonify({"status": "fail", "reason": "drift too large or invalid code"}), 401


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
    active_flags = []
    current_time = time.time()

    # 1. Rate Limit (Temporary/Short blocking)
    if CONFIG["rate_limit"]:
        active_flags.append("rate_limit")
        REQUEST_LOG[username] = [t for t in REQUEST_LOG[username] if current_time - t < RATE_WINDOW]
        if len(REQUEST_LOG[username]) >= RATE_LIMIT_COUNT:
            log_attempt(username, hash_mode, category, "fail_rate_limit", (time.time() - start_time) * 1000,
                        active_flags)
            return jsonify({"status": "fail", "reason": "rate limit exceeded"}), 429
        REQUEST_LOG[username].append(current_time)

    # 2. Lockout (Permanent until Admin Reset)
    if CONFIG["lockout"]:
        active_flags.append("lockout")
        if username in LOCKED_UNTIL:
            # Check if locked. Since duration is infinite, this is always true unless deleted.
            if current_time < LOCKED_UNTIL[username]:
                log_attempt(username, hash_mode, category, "fail_locked", (time.time() - start_time) * 1000,
                            active_flags)
                return jsonify({"status": "fail", "reason": "account locked (contact admin)"}), 423
            else:
                # This branch effectively never happens with infinite duration
                del LOCKED_UNTIL[username]
                FAILED_ATTEMPTS[username] = 0

    # 3. Captcha
    if CONFIG["captcha"]:
        active_flags.append("captcha")
        if FAILED_ATTEMPTS[username] >= CAPTCHA_THRESHOLD:
            if not captcha_input:
                log_attempt(username, hash_mode, category, "fail_captcha_required", (time.time() - start_time) * 1000,
                            active_flags)
                return jsonify({"status": "fail", "reason": "captcha required", "captcha_required": True}), 403

    # 4. Password Check
    if not user:
        log_attempt(username, "N/A", "unknown", "fail_user_not_found", (time.time() - start_time) * 1000, active_flags)
        return jsonify({"status": "fail", "reason": "invalid credentials"}), 401

    if not verify_password_hash(password, user):
        # Increment failures for Lockout/Captcha
        if CONFIG["lockout"] or CONFIG["captcha"]:
            FAILED_ATTEMPTS[username] += 1

            # Check if we need to LOCK the account PERMANENTLY
            if CONFIG["lockout"] and FAILED_ATTEMPTS[username] >= LOCKOUT_THRESHOLD:
                LOCKED_UNTIL[username] = float('inf')  # Locked forever until reset

        log_attempt(username, hash_mode, category, "fail_password", (time.time() - start_time) * 1000, active_flags)
        return jsonify({"status": "fail", "reason": "invalid credentials"}), 401

    # 5. TOTP (with learned offset)
    if CONFIG["totp"]:
        active_flags.append("totp")
        if not check_totp(user, totp_input):
            log_attempt(username, hash_mode, category, "fail_totp", (time.time() - start_time) * 1000, active_flags)
            return jsonify({"status": "fail", "reason": "totp invalid"}), 401

    # Success - Reset counters
    FAILED_ATTEMPTS[username] = 0
    if username in LOCKED_UNTIL: del LOCKED_UNTIL[username]

    log_attempt(username, hash_mode, category, "success", (time.time() - start_time) * 1000, active_flags)
    return jsonify({"status": "success", "username": username}), 200


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
    print(f"[*] Server port {args.port}. Protections: {[k for k, v in CONFIG.items() if v]}")
    app.run(host="0.0.0.0", port=args.port, debug=False)