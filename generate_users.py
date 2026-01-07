import json
import secrets
import string
import os

from crypto_utils import GROUP_SEED

# =========================================
# CONFIGURATION
# =========================================

users_plain_data_path = "users_experiment_private.json"
COMMON_PASSWORDS_PATH = "common_passwords.txt"

common_passwords = []


# =========================================
# GENERATORS
# =========================================

def generate_weak_password() -> str:
    # 4-6 characters, lowercase + digits
    length = secrets.randbelow(3) + 4
    chars = string.ascii_lowercase + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))


def generate_medium_password() -> str:
    # 7-10 characters, mixed case + digits
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
    # 11-16 characters, mixed case + digits + symbols
    length = secrets.randbelow(6) + 11
    specials = string.punctuation
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
    WEAK = 'weak'
    MEDIUM = 'medium'
    STRONG = 'strong'
    COMMON = 'common'
    users_data = []

    # Check if file exists
    if os.path.exists(COMMON_PASSWORDS_PATH):
        with open(COMMON_PASSWORDS_PATH, "r", encoding='utf-8') as f:
            # Strip newlines and empty spaces
            common_passwords = [line.strip() for line in f.readlines() if line.strip()]
    else:
        # Fail fast if file is missing
        raise FileNotFoundError(f"CRITICAL ERROR: {COMMON_PASSWORDS_PATH} is missing!")

    # Check if file was empty (prevents crash in secrets.choice)
    if not common_passwords:
        raise ValueError(f"CRITICAL ERROR: {COMMON_PASSWORDS_PATH} is empty!")

    # --- Generate Standard Users (1-30) ---
    for i in range(30):
        if i < 10:
            category = WEAK
            current_password = generate_weak_password()
        elif i < 20:
            category = MEDIUM
            current_password = generate_medium_password()
        else:
            category = STRONG
            current_password = generate_strong_password()

        username = f'{category}_{i + 1}'
        users_data.append({'username': username, 'password': current_password, 'category': category})

    # --- Generate Common Password Users (31-35) ---
    for i in range(5):
        category = COMMON
        username = f'{category}_{i + 31}'
        current_password = secrets.choice(common_passwords)
        users_data.append({'username': username, 'password': current_password, 'category': category})

    # --- Password is Group Seed
    username = f'Group_seed'
    current_password = GROUP_SEED
    users_data.append({'username': username, 'password': current_password, 'category': COMMON})

    # --- Save to JSON ---
    with open(users_plain_data_path, "w", encoding='utf-8') as f:
        json.dump(users_data, f, indent=4, ensure_ascii=False)

    print(f"Success. Generated {len(users_data)} users into {users_plain_data_path}")


if __name__ == "__main__":
    main()