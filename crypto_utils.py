import os
import hashlib
import bcrypt
import secrets
from argon2 import PasswordHasher

# =========================================
# 1. GROUP_SEED Calculation
# =========================================
ID1 = 211838172
ID2 = 207745316
GROUP_SEED = str(ID1 ^ ID2)

# =========================================
# 2. CONFIGURATION & HASHER SETUP
# =========================================
# Pepper
GLOBAL_PEPPER_SECRET = os.getenv("MAMAN16_PEPPER", "SecretPepper123!")

#time=1, memory=64MB, parallelism=1
argon2_hasher = PasswordHasher(
    time_cost=1,
    memory_cost=65536,  # 64MB in KB
    parallelism=1
)


# =========================================
# 3. HASHING FUNCTIONS
# =========================================

def _apply_pepper(password: str, use_pepper: bool) -> str:
    return GLOBAL_PEPPER_SECRET + password if use_pepper else password


def hash_sha256(password: str, use_salt: bool = True, use_pepper: bool = False):
    """SHA256: salt256 + SHA-256 (as per appendix 4)"""
    pwd = _apply_pepper(password, use_pepper)
    salt = ""
    if use_salt:
        salt = secrets.token_hex(32)

    hash_value = hashlib.sha256((salt + pwd).encode()).hexdigest()
    return salt, hash_value


def hash_bcrypt(password: str, use_pepper: bool = False):
    """bcrypt: cost = 12 (as per appendix 4)"""
    pwd = _apply_pepper(password, use_pepper)
    hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt(rounds=12))
    return hashed.decode()


def hash_argon2(password: str, use_pepper: bool = False):
    """Argon2id: default params as per appendix 4"""
    pwd = _apply_pepper(password, use_pepper)
    hash_value = argon2_hasher.hash(pwd)
    return hash_value