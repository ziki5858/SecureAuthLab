from flask import Flask, request, jsonify
import json
import time
import hashlib
import bcrypt
from argon2 import PasswordHasher
from datetime import datetime

# Load users into memory
with open("users.json", "r") as f:
    user_list = json.load(f)

# המרה של הרשימה למילון לפי שם המשתמש
USERS = {user["username"]: user for user in user_list}


# Argon2 verifier (same config used for hashing)
argon2_verify = PasswordHasher(
    time_cost=1,
    memory_cost=65536,
    parallelism=1
)

app = Flask(__name__)


def verify_password(password_attempt, user):
    hash_mode = user["hash_mode"]
    stored_hash = user["password_hash"]
    salt = user["salt"]

    if hash_mode == "sha256":
        attempt_hash = hashlib.sha256((password_attempt + salt).encode()).hexdigest()
        return attempt_hash == stored_hash

    elif hash_mode == "bcrypt":
        return bcrypt.checkpw(password_attempt.encode(), stored_hash.encode())

    elif hash_mode == "argon2id":
        try:
            argon2_verify.verify(stored_hash, password_attempt)
            return True
        except:
            return False

    return False


def log_attempt(username, hash_mode, result, latency_ms, protections):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "username": username,
        "hash_mode": hash_mode,
        "group_seed": 6631928,
        "protection_flags": protections,
        "latency_ms": latency_ms,
        "result": result
    }

    with open("logs/attempts.log", "a") as f:
        f.write(json.dumps(entry) + "\n")


@app.route("/login", methods=["POST"])
def login():
    start_time = time.time()

    data = request.json
    username = data.get("username")
    password_attempt = data.get("password")

    if username not in USERS:
        latency = (time.time() - start_time) * 1000
        log_attempt(username, "N/A", "fail", latency, [])
        return jsonify({"status": "fail", "reason": "user not found"}), 400

    user = USERS[username]
    hash_mode = user["hash_mode"]

    ok = verify_password(password_attempt, user)

    latency = (time.time() - start_time) * 1000
    log_attempt(username, hash_mode, "success" if ok else "fail", latency, [])

    if ok:
        return jsonify({"status": "success"}), 200
    else:
        return jsonify({"status": "fail", "reason": "wrong password"}), 401


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
