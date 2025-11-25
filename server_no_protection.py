from flask import Flask, request, jsonify
import json
import hashlib
import bcrypt
from argon2 import PasswordHasher

# ======================
#   LOAD USERS
# ======================

with open("users.json", "r") as f:
    user_list = json.load(f)

# convert user list to dictionary by username
USERS = {user["username"]: user for user in user_list}

# Argon2id verifier
argon2_verify = PasswordHasher(
    time_cost=1,
    memory_cost=65536,
    parallelism=1
)

app = Flask(__name__)


# ======================
#   PASSWORD VERIFY
# ======================

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
        except Exception:
            return False

    return False


# ======================
#       LOGIN API
# ======================

@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username", "")
    password_attempt = data.get("password", "")

    # no protections — just verify
    if username not in USERS:
        return jsonify({"status": "fail"}), 400

    user = USERS[username]

    if verify_password(password_attempt, user):
        return jsonify({"status": "success"}), 200
    else:
        return jsonify({"status": "fail"}), 401


# ======================
#       RUN SERVER
# ======================

if __name__ == "__main__":
    # Running on port 6000 to avoid collision with protected server (5000)
    app.run(host="0.0.0.0", port=6000, debug=False)
