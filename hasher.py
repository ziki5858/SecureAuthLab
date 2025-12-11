import os
import hashlib
import bcrypt
from argon2 import PasswordHasher

# =========================================
# CONFIGURATION
# =========================================

# Retrieves the secret key from the environment variables.
GLOBAL_PEPPER_SECRET = os.getenv("MAMAN16_PEPPER")

# Argon2id configuration
argon2_hasher = PasswordHasher(
    time_cost=1,  # Iterations
    memory_cost=65536,  # 64 MB
    parallelism=1
)


def _get_peppered_password(password: str, use_pepper: bool) -> str:
    """Appends the global secret pepper to the password if enabled."""
    if use_pepper and GLOBAL_PEPPER_SECRET:
        return password + GLOBAL_PEPPER_SECRET
    return password


def hash_sha256(password: str, use_salt: bool = True, use_pepper: bool = False):
    """
    Generates SHA-256 hash.
    If use_salt is False, uses an empty salt (for baseline comparison).
    """
    password_to_hash = _get_peppered_password(password, use_pepper)

    salt = ""
    if use_salt:
        salt = os.urandom(16).hex()

    hash_value = hashlib.sha256((password_to_hash + salt).encode()).hexdigest()
    return salt, hash_value


def hash_bcrypt(password: str, use_pepper: bool = False):
    """Generates bcrypt hash (Always salted by design)."""
    password_to_hash = _get_peppered_password(password, use_pepper)
    salt = bcrypt.gensalt(rounds=12)
    hash_value = bcrypt.hashpw(password_to_hash.encode(), salt).decode()
    return "", hash_value


def hash_argon2(password: str, use_pepper: bool = False):
    """Generates Argon2id hash (Always salted by design)."""
    password_to_hash = _get_peppered_password(password, use_pepper)
    hash_value = argon2_hasher.hash(password_to_hash.encode())
    return "", hash_value