from flask import Flask, request, jsonify
import json
import time
import hashlib
import bcrypt
from argon2 import PasswordHasher
from datetime import datetime
from collections import defaultdict
import pyotp  # TOTP support

# =========================
#   GLOBAL CONFIGURATION
# =========================

GROUP_SEED = 6631928

# Rate limiting configuration
RATE_LIMIT = 5               # Max allowed login attempts per window
RATE_WINDOW = 10             # Time window in seconds
REQUEST_LOG = defaultdict(list)   # Logs login timestamps per username

# Account lockout configuration
LOCKOUT_THRESHOLD = 5         # Failed attempts before locking account
LOCKOUT_DURATION = 60         # Lockout time in seconds
FAILED_ATTEMPTS = defaultdict(int)   # Failed login counter per username
LOCKED_UNTIL = {}                     # Username → unlock timestamp

# CAPTCHA simulation settings
CAPTCHA_THRESHOLD = 3         # Failed attempts before requiring CAPTCHA
CAPTCHA_VALUE = "IAMHUMAN"    # Expected CAPTCHA solution

# Pepper (applied only if user has use_pepper=true)
PEPPER = "my_super_secret_pepper_123"  # Note: insecure in real-world systems

# =========================
#   LOAD USER DATABASE
# =========================

with open("users.json", "r") as f:
    user_list = json.load(f)

# Convert list format into a dictionary for fast lookup
USERS = {user["username"]: user for user in user_list}

# Argon2id verifier using the same parameters used during hashing
argon2_verify = PasswordHasher(
    time_cost=1,
    memory_cost=65536,
    parallelism=1
)

app = Flask(__name__)


# =========================
#   HELPER FUNCTIONS
# =========================

def verify_password(password_attempt: str, user: dict) -> bool:
    """
    Verifies the provided password against the user's stored hash.
    Supports optional pepper based on user configuration.
    """
    hash_mode = user["hash_mode"]
    stored_hash = user["password_hash"]
    salt = user["salt"]
    use_pepper = user.get("use_pepper", False)

    # Append pepper only if configured for this user
    pwd = (password_attempt + PEPPER) if use_pepper else password_attempt

    # SHA-256 + salt verification
    if hash_mode == "sha256":
        attempt_hash = hashlib.sha256((pwd + salt).encode()).hexdigest()
        return attempt_hash == stored_hash

    # bcrypt verification (salt included inside the hash)
    elif hash_mode == "bcrypt":
        return bcrypt.checkpw(pwd.encode(), stored_hash.encode())

    # Argon2id verification
    elif hash_mode == "argon2id":
        try:
            argon2_verify.verify(stored_hash, pwd)
            return True
        except Exception:
            return False

    # Unknown hashing method
    return False


def verify_totp(user: dict, totp_code: str | None) -> bool:
    """
    Validates TOTP (2FA). If user has no TOTP secret, skip validation.
    Returns True if:
    - user does not require TOTP, OR
    - provided code is correct.
    """
    secret = user.get("totp_secret", "")
    if not secret:
        return True  # no TOTP required

    if not totp_code:
        return False  # missing code

    totp = pyotp.TOTP(secret)
    return totp.verify(totp_code, valid_window=1)


def log_attempt(username, hash_mode, result, latency_ms, protections):
    """
    Appends a JSON log entry to attempts.log for monitoring and analysis.
    """
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "username": username,
        "hash_mode": hash_mode,
        "group_seed": GROUP_SEED,
        "protection_flags": protections,
        "latency_ms": latency_ms,
        "result": result
    }

    with open("logs/attempts.log", "a") as f:
        f.write(json.dumps(entry) + "\n")


# =========================
#   LOGIN ENDPOINT
# =========================

@app.route("/login", methods=["POST"])
def login():
    start_time = time.time()
    protections = []  # List of security mechanisms triggered during this attempt

    data = request.json or {}
    username = data.get("username", "")
    password_attempt = data.get("password", "")
    captcha_value = data.get("captcha")
    totp_code = data.get("totp_code")

    now = time.time()

    # -------------------------
    # Rate Limiting Protection
    # -------------------------
    REQUEST_LOG[username] = [
        t for t in REQUEST_LOG[username] if now - t < RATE_WINDOW
    ]

    if len(REQUEST_LOG[username]) >= RATE_LIMIT:
        protections.append("rate_limit")
        latency = (time.time() - start_time) * 1000
        log_attempt(username, "N/A", "fail", latency, protections)
        return jsonify({"status": "fail", "reason": "rate limited"}), 429

    REQUEST_LOG[username].append(now)

    # -------------------------
    # Username Validation
    # -------------------------
    if username not in USERS:
        latency = (time.time() - start_time) * 1000
        log_attempt(username, "N/A", "fail", latency, protections)
        return jsonify({"status": "fail", "reason": "user not found"}), 400

    user = USERS[username]
    hash_mode = user["hash_mode"]

    # -------------------------
    # Account Lockout Protection
    # -------------------------
    locked_until = LOCKED_UNTIL.get(username)
    if locked_until and now < locked_until:
        protections.append("lockout")
        latency = (time.time() - start_time) * 1000
        log_attempt(username, hash_mode, "fail", latency, protections)
        return jsonify({"status": "fail", "reason": "account locked"}), 423

    # -------------------------
    # CAPTCHA Simulation
    # -------------------------
    if FAILED_ATTEMPTS[username] >= CAPTCHA_THRESHOLD:
        if captcha_value != CAPTCHA_VALUE:
            protections.append("captcha_required")
            latency = (time.time() - start_time) * 1000
            log_attempt(username, hash_mode, "fail", latency, protections)
            return jsonify({"status": "fail", "reason": "captcha required"}), 403

    # -------------------------
    # Password Verification
    # -------------------------
    ok = verify_password(password_attempt, user)

    if not ok:
        FAILED_ATTEMPTS[username] += 1

        # Set lockout if threshold exceeded
        if FAILED_ATTEMPTS[username] >= LOCKOUT_THRESHOLD:
            LOCKED_UNTIL[username] = now + LOCKOUT_DURATION
            protections.append("lockout_set")

        latency = (time.time() - start_time) * 1000
        log_attempt(username, hash_mode, "fail", latency, protections)
        return jsonify({"status": "fail", "reason": "wrong password"}), 401

    # Reset counters on successful authentication
    FAILED_ATTEMPTS[username] = 0
    if username in LOCKED_UNTIL:
        del LOCKED_UNTIL[username]

    # -------------------------
    # TOTP (Two-Factor Authentication)
    # -------------------------
    if not verify_totp(user, totp_code):
        protections.append("totp_failed")
        latency = (time.time() - start_time) * 1000
        log_attempt(username, hash_mode, "fail", latency, protections)
        return jsonify({"status": "fail", "reason": "totp required or invalid"}), 401
    else:
        if user.get("totp_secret"):
            protections.append("totp_passed")

    # -------------------------
    # SUCCESS
    # -------------------------
    latency = (time.time() - start_time) * 1000
    log_attempt(username, hash_mode, "success", latency, protections)
    return jsonify({"status": "success"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
