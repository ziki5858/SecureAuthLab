import os
import hashlib
import bcrypt
from argon2 import PasswordHasher

# Argon2id configuration (exactly as required by the project)
argon2_hasher = PasswordHasher(
    time_cost=1,        # iterations
    memory_cost=65536,  # 64 MB
    parallelism=1
)

def hash_sha256(password: str):
    """
    Generates a random salt and returns (salt, sha256_hash)
    """
    salt = os.urandom(16).hex()
    hash_value = hashlib.sha256((password + salt).encode()).hexdigest()
    return salt, hash_value


def hash_bcrypt(password: str):
    """
    Returns (salt, bcrypt_hash)
    Note: bcrypt generates its own internal salt.
    """
    salt = bcrypt.gensalt(rounds=12)
    hash_value = bcrypt.hashpw(password.encode(), salt).decode()
    # bcrypt salt is inside the hash, so we store salt="" for consistency
    return "", hash_value


def hash_argon2(password: str):
    """
    Returns (salt, argon2id_hash)
    Argon2 stores its salt inside the hash string.
    """
    hash_value = argon2_hasher.hash(password)
    return "", hash_value
