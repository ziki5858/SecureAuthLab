import json
import secrets
import string
import pyotp
from hasher import hash_sha256, hash_bcrypt, hash_argon2

# --- CONFIGURATION ---
GROUP_SEED = 6631928
OUTPUT_JSON = "users.json"
OUTPUT_PASSWORDS = "passwords.txt"

COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789", "admin123"
]


def generate_weak_password(is_common=False):
    if is_common:
        return secrets.choice(COMMON_PASSWORDS)
    length = secrets.randbelow(3) + 4
    chars = string.ascii_lowercase + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))


def generate_medium_password():
    length = secrets.randbelow(4) + 7
    chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))


def generate_strong_password():
    length = secrets.randbelow(6) + 11
    chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(chars) for _ in range(length))


def main():
    users_data = []
    plaintext_log = []

    plaintext_log.append(f"GROUP_SEED: {GROUP_SEED}\n")
    plaintext_log.append("-" * 30 + "\n")

    print(f"Generating 30 users for Group Seed: {GROUP_SEED}...")

    for i in range(30):
        # 1. Determine Category
        if i < 10:
            category = "weak"
            hash_mode = "sha256"
            # First 5 get common passwords for Spraying test
            password = generate_weak_password(is_common=(i < 5))
        elif i < 20:
            category = "medium"
            hash_mode = "bcrypt"
            password = generate_medium_password()
        else:
            category = "strong"
            hash_mode = "argon2id"
            password = generate_strong_password()

        # 2. TOTP Secret - CHANGE: Only give TOTP to 1/3 of users (indexes 0, 3, 6...)
        totp_secret = ""
        if i % 3 == 0:
            totp_secret = pyotp.random_base32()

        # 3. Hash the password
        salt = ""
        password_hash = ""
        # Generate with pepper=False by default for the DB
        if hash_mode == "sha256":
            salt, password_hash = hash_sha256(password, use_pepper=False)
        elif hash_mode == "bcrypt":
            salt, password_hash = hash_bcrypt(password, use_pepper=False)
        elif hash_mode == "argon2id":
            salt, password_hash = hash_argon2(password, use_pepper=False)

        # 4. Build User Object
        user_entry = {
            "username": f"user{i + 1:02d}",
            "category": category,
            "hash_mode": hash_mode,
            "salt": salt,
            "password_hash": password_hash,
            "totp_secret": totp_secret,  # Most users will have empty string here
            "group_seed": GROUP_SEED
        }

        users_data.append(user_entry)
        has_totp = "YES" if totp_secret else "NO"
        plaintext_log.append(f"{user_entry['username']} ({category}): {password} [TOTP: {has_totp}]\n")

    with open(OUTPUT_JSON, "w") as f:
        json.dump(users_data, f, indent=4)

    with open(OUTPUT_PASSWORDS, "w") as f:
        f.writelines(plaintext_log)

    print("Done. Users saved to users.json (Only ~33% have TOTP secrets).")


if __name__ == "__main__":
    main()