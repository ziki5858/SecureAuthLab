import json
from datetime import datetime

ID1 = 211838172  # Ishay Abakiev
ID2 = 207745316  # Lior Zipori


def calculate_group_seed(id1, id2):
    return id1 ^ id2  # XOR


GROUP_SEED = calculate_group_seed(ID1, ID2)

LOG_PATH = "logs/attempts.log"


def write_log(username, hash_mode, result, latency_ms, protection_flags=None):
    # JSON line foramt
    if protection_flags is None:
        protection_flags = []

    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "username": username,
        "hash_mode": hash_mode,
        "group_seed": GROUP_SEED,
        "protection_flags": protection_flags,
        "latency_ms": latency_ms,
        "result": result
    }

    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")
