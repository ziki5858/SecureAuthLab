import json
import secrets
import string
import pyotp
from typing import List, Dict, Any
from hasher import hash_sha256, hash_bcrypt, hash_argon2

# =========================================
# CONFIGURATION
# =========================================

GROUP_SEED = 6631928
OUTPUT_JSON = "users.json"
OUTPUT_PASSWORDS = "passwords.txt"

COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789", "admin123",
    "welcome", "login", "princess", "football", "monkey", "dragon"
]


# =========================================
# GENERATORS
# =========================================

def generate_weak_password(is_common: bool = False) -> str:
    if is_common:
        return secrets.choice(COMMON_PASSWORDS)
    length = secrets.randbelow(3) + 4
    chars = string.ascii_lowercase + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))


def generate_medium_password() -> str:
    length = secrets.randbelow(4) + 7
    password_chars = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits)
    ]
    remaining_length = length - len(password_chars)
    all_allowed = string.ascii_letters + string.digits
    for _ in range(remaining_length):
        password_chars.append(secrets.choice(all_allowed))
    secrets.SystemRandom().shuffle(password_chars)
    return ''.join(password_chars)


def generate_strong_password() -> str:
    length = secrets.randbelow(6) + 11
    specials = "!@#$%^&*"
    password_chars = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(specials)
    ]
    remaining_length = length - len(password_chars)
    all_allowed = string.ascii_letters + string.digits + specials
    for _ in range(remaining_length):
        password_chars.append(secrets.choice(all_allowed))
    secrets.SystemRandom().shuffle(password_chars)
    return ''.join(password_chars)


# =========================================
# MAIN
# =========================================

def main():
    users_data: List[Dict[str, Any]] = []
    plaintext_log: List[str] = []

    plaintext_log.append(f"GROUP_SEED: {GROUP_SEED}\n")
    plaintext_log.append("-" * 30 + "\n")

    print(f"[*] Initializing user generation for Group Seed: {GROUP_SEED}...")

    for i in range(30):
        # Default flags
        use_salt = True
        used_pepper = False
        totp_secret = ""

        # 1. Determine Category & Salt Logic
        if i < 10:
            category = "weak"
            hash_mode = "sha256"
            password = generate_weak_password(is_common=(i < 5))

            # Group A (0-4): NO SALT. Group B (5-9): WITH SALT.
            if i < 5:
                use_salt = False

        elif i < 20:
            category = "medium"  # Group C
            hash_mode = "bcrypt"
            password = generate_medium_password()
        else:
            category = "strong"  # Group D & E
            hash_mode = "argon2id"
            password = generate_strong_password()

        # 2. TOTP Configuration (Every 3rd user)
        if i % 3 == 0:
            totp_secret = pyotp.random_base32()

        # 3. Pepper Configuration (Group D: Users 20-24)
        if i >= 20 and i < 25:
            used_pepper = True

        # 4. Generate Hash
        salt = ""
        password_hash = ""

        if hash_mode == "sha256":
            salt, password_hash = hash_sha256(password, use_salt=use_salt, use_pepper=used_pepper)
        elif hash_mode == "bcrypt":
            salt, password_hash = hash_bcrypt(password, use_pepper=used_pepper)
        elif hash_mode == "argon2id":
            salt, password_hash = hash_argon2(password, use_pepper=used_pepper)

        # 5. Build Record
        user_entry = {
            "username": f"user{i + 1:02d}",
            "category": category,
            "hash_mode": hash_mode,
            "salt": salt,  # Empty for bcrypt/argon2 (internal salt), or if no salt used
            "password_hash": password_hash,
            "totp_secret": totp_secret,
            "group_seed": GROUP_SEED,
            "used_pepper": used_pepper
        }

        users_data.append(user_entry)

        # --- LOGGING DISPLAY LOGIC (FIXED) ---
        # Logic: It has salt if 'salt' string is not empty OR if mode is bcrypt/argon2 (which always salt)
        has_salt_display = "NO"
        if salt or hash_mode in ["bcrypt", "argon2id"]:
            has_salt_display = "YES"

        has_pepper = "YES" if used_pepper else "NO"
        has_totp = "YES" if totp_secret else "NO"

        plaintext_log.append(
            f"{user_entry['username']} [{hash_mode}] Salt:{has_salt_display}, Pepper:{has_pepper} -> {password}\n")

    # 6. Save Files
    try:
        with open(OUTPUT_JSON, "w") as f:
            json.dump(users_data, f, indent=4)
        with open(OUTPUT_PASSWORDS, "w") as f:
            f.writelines(plaintext_log)
        print(f"[+] Done. Generated {len(users_data)} users.")
        print(f"[+] Output: {OUTPUT_JSON}")
        print(f"[+] Log: {OUTPUT_PASSWORDS}")

    except IOError as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()