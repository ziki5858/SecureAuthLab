import os
import hashlib
import bcrypt
from argon2 import PasswordHasher

# =========================================
# CONFIGURATION
# =========================================

GLOBAL_PEPPER_SECRET = os.getenv("MAMAN16_PEPPER", "DEFAULT_PEPPER_CHANGE_ME")

argon2_hasher = PasswordHasher(
    time_cost=1,
    memory_cost=65536,
    parallelism=1
)


def _get_peppered_password(password: str, use_pepper: bool) -> str:
    """Prepends the Pepper (PEPPER + password)."""
    if use_pepper:
        return GLOBAL_PEPPER_SECRET + password
    return password


def hash_sha256(password: str, use_salt: bool = True, use_pepper: bool = False):
    """Generates SHA256 with optional salt and pepper."""
    pwd = _get_peppered_password(password, use_pepper)

    salt = ""
    if use_salt:
        salt = os.urandom(16).hex()

    hash_value = hashlib.sha256((salt + pwd).encode()).hexdigest()
    return salt, hash_value


def hash_bcrypt(password: str, use_pepper: bool = False):
    """Generates bcrypt hash with optional pepper."""
    pwd = _get_peppered_password(password, use_pepper)
    hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt(rounds=12))
    return "", hashed.decode()


def hash_argon2(password: str, use_pepper: bool = False):
    """Generates Argon2id hash with optional pepper."""
    pwd = _get_peppered_password(password, use_pepper)
    hash_value = argon2_hasher.hash(pwd)  # Argon2 expects STRING, not bytes
    return "", hash_value
