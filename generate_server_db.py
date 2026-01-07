import argparse
import json
import secrets
import pyotp
import crypto_utils

# =========================================
# CONFIGURATION
# =========================================
PRIVATE_USERS_JSON = "users_experiment_private.json"
OUTPUT_JSON = "server_data.json"


def main():

    parser = argparse.ArgumentParser(description="Apply security defences to user data.")
    #hashs
    parser.add_argument('--hash', choices=['sha', 'bcrypt', 'argon2', 'none'], default='none', help="Base hashing algorithm")
    # more flags
    parser.add_argument('--salt', action='store_true', help="Apply salt (only relevant for SHA)")
    parser.add_argument('--pepper', action='store_true', help="Apply global pepper")
    parser.add_argument('--totp', action='store_true', help="Enable TOTP for users")

    args = parser.parse_args()

    try:
        with open(PRIVATE_USERS_JSON, "r", encoding='utf-8') as f:
            private_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: {PRIVATE_USERS_JSON} not found. Run File generate_users.py first.")
        return

    for entry in private_data:
        entry['salt'] = False
        entry['totp_secret'] = False
        original_pwd = entry['password']
        if args.hash == 'none':
            if args.salt:
                salt = secrets.token_hex(4)
                entry['password'] = original_pwd + salt
                entry['salt'] = salt
            else:
                entry['password'] = original_pwd

        if args.totp:
            entry['totp_secret'] = pyotp.random_base32()

        if args.hash == 'sha':
            salt, hashed_pwd = crypto_utils.hash_sha256(original_pwd, use_salt=args.salt, use_pepper=args.pepper)
            entry['password'] = hashed_pwd
            if salt: entry['salt'] = salt

        if args.hash == 'bcrypt':
            hashed_pwd = crypto_utils.hash_bcrypt(original_pwd, use_pepper=args.pepper)
            entry['password'] = hashed_pwd
            entry['salt'] = True

        if args.hash == 'argon2':
            hashed_pwd = crypto_utils.hash_argon2(original_pwd, use_pepper=args.pepper)
            entry['password'] = hashed_pwd
            entry['salt'] = True

        entry['hash_mode'] = args.hash
        entry['used_pepper'] = args.pepper
        entry['GROUP_SEED'] = crypto_utils.GROUP_SEED

    with open(OUTPUT_JSON, "w", encoding='utf-8') as f:
        json.dump(private_data, f, indent=4, ensure_ascii=False)


if __name__ == "__main__":
    main()