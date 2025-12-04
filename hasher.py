import os
import hashlib
import bcrypt
from argon2 import PasswordHasher

# =========================================
# CONFIGURATION
# =========================================

# CHANGE: Load Pepper from Environment Variable (OS)
# If the variable is missing, it returns None.
GLOBAL_PEPPER_SECRET = os.getenv("MAMAN16_PEPPER")

if not GLOBAL_PEPPER_SECRET:
    # This is just a warning so you don't forget to set it in the terminal
    print(" [!] WARNING: 'MAMAN16_PEPPER' env var is not set. Pepper logic will fail or be empty.")

# Argon2id configuration
argon2_hasher = PasswordHasher(
    time_cost=1,        # Iterations
    memory_cost=65536,  # 64 MB
    parallelism=1
)

def _get_peppered_password(password: str, use_pepper: bool) -> str:
    """
    Appends the global secret pepper to the password if pepper usage is enabled.
    """
    if use_pepper:
        # If pepper is required but env var is missing, this might cause issues,
        # but that is the intended behavior for security.
        pepper = GLOBAL_PEPPER_SECRET if GLOBAL_PEPPER_SECRET else ""
        return password + pepper
    return password


def hash_sha256(password: str, use_pepper: bool = False):
    password_to_hash = _get_peppered_password(password, use_pepper)
    salt = os.urandom(16).hex()
    hash_value = hashlib.sha256((password_to_hash + salt).encode()).hexdigest()
    return salt, hash_value


def hash_bcrypt(password: str, use_pepper: bool = False):
    password_to_hash = _get_peppered_password(password, use_pepper)
    salt = bcrypt.gensalt(rounds=12)
    hash_value = bcrypt.hashpw(password_to_hash.encode(), salt).decode()
    return "", hash_value


def hash_argon2(password: str, use_pepper: bool = False):
    password_to_hash = _get_peppered_password(password, use_pepper)
    hash_value = argon2_hasher.hash(password_to_hash)
    return "", hash_value