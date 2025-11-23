import random
import string

def generate_weak_password():
    """4–6 chars, lowercase + digits"""
    length = random.randint(4, 6)
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choices(chars, k=length))


def generate_medium_password():
    """7–10 chars, lowercase + uppercase + digits"""
    length = random.randint(7, 10)
    chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
    return ''.join(random.choices(chars, k=length))


def generate_strong_password():
    """11–16 chars, mixed complexity"""
    length = random.randint(11, 16)
    chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&*"
    return ''.join(random.choices(chars, k=length))
