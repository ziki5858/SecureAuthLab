import json
from password_generator import (
    generate_weak_password,
    generate_medium_password,
    generate_strong_password
)
from hasher import (
    hash_sha256,
    hash_bcrypt,
    hash_argon2
)

USERS_FILE = "users.json"
PASSWORD_OUTPUT_FILE = "generated_passwords.txt"


def generate_password(category):
    if category == "weak":
        return generate_weak_password()
    elif category == "medium":
        return generate_medium_password()
    elif category == "strong":
        return generate_strong_password()
    else:
        raise ValueError("Unknown password category")


def apply_hash(password, hash_mode):
    if hash_mode == "sha256":
        return hash_sha256(password)
    elif hash_mode == "bcrypt":
        return hash_bcrypt(password)
    elif hash_mode == "argon2id":
        return hash_argon2(password)
    else:
        raise ValueError("Unknown hash mode")


def main():
    with open(USERS_FILE, "r") as f:
        users = json.load(f)

    output = []

    for user in users:
        username = user["username"]
        category = user["category"]
        hash_mode = user["hash_mode"]

        # 1. generate password
        password = generate_password(category)

        # 2. hash password
        salt, password_hash = apply_hash(password, hash_mode)

        # 3. update JSON
        user["salt"] = salt
        user["password_hash"] = password_hash

        # 4. save original password in a separate file (NOT in JSON)
        output.append(f"{username}: {password}\n")

    # save updated users.json
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

    # save actual passwords
    with open(PASSWORD_OUTPUT_FILE, "w") as f:
        f.writelines(output)

    print("Users generated successfully!")
    print(f"Passwords saved to: {PASSWORD_OUTPUT_FILE}")


if __name__ == "__main__":
    main()
