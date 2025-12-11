import os
import json
import subprocess
from datetime import datetime

# ======================================================
# CONFIG
# ======================================================

BRUTE_SCRIPT = "attack_bruteforce.py"
SPRAY_SCRIPT = "attack_spraying.py"

LOG_DIR = "logs"
BF_DIR = os.path.join(LOG_DIR, "bruteforce")
SP_DIR = os.path.join(LOG_DIR, "spraying")

for d in [BF_DIR, SP_DIR]:
    os.makedirs(d, exist_ok=True)

# Load users.json
with open("users.json", "r") as f:
    USERS = json.load(f)

# Helper: get user entry
def get_user(name):
    return next(u for u in USERS if u["username"] == name)

# ======================================================
# SELECT DIVERSE USERS FOR EACH ATTACK TYPE
# ======================================================

BF_TARGETS = {   # Brute-force representatives
    "A": "user01",
    "B": "user06",
    "C": "user11",
    "D": "user21",
    "E": "user26"
}

PS_TARGETS = {   # Spraying representatives (different from BF)
    "A": "user03",
    "B": "user08",
    "C": "user14",
    "D": "user23",
    "E": "user29"
}

# ======================================================
# EXPERIMENT EXECUTION
# ======================================================

def run_full_experiment():

    print("\n==============================================")
    print("      Running FULL PASSWORD EXPERIMENT SUITE")
    print("==============================================\n")

    summary = []

    for group in ["A", "B", "C", "D", "E"]:

        # -----------------------------
        # BRUTE-FORCE USER
        # -----------------------------
        bf_user = BF_TARGETS[group]
        bf_info = get_user(bf_user)

        print(f"\n[BF] Group {group} → attacking {bf_user}")

        bf_log = f"{BF_DIR}/BF_{bf_user}_group{group}.csv"

        bf_cmd = [
            "python", BRUTE_SCRIPT,
            "--username", bf_user,
            "--category", bf_info["category"],
            "--attempts", "2000",
            "--tag", f"group{group}"
        ]

        subprocess.run(bf_cmd)

        # -----------------------------
        # SPRAYING USER (DIFFERENT)
        # -----------------------------
        sp_user = PS_TARGETS[group]
        sp_info = get_user(sp_user)

        print(f"[SP] Group {group} → spraying {sp_user}")

        sp_log = f"{SP_DIR}/SP_{sp_user}_group{group}.csv"

        sp_cmd = [
            "python", SPRAY_SCRIPT,
            "--url", "http://127.0.0.1:5000/login",
            "--delay", "0",
            "--tag", f"group{group}"
        ]

        subprocess.run(sp_cmd)

        # Add entry to summary
        summary.append({
            "group": group,
            "BF_user": bf_user,
            "BF_category": bf_info["category"],
            "BF_log": bf_log,
            "SP_user": sp_user,
            "SP_category": sp_info["category"],
            "SP_log": sp_log
        })

    # Save experiment summary
    summary_file = f"{LOG_DIR}/summary_experiment_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=4)

    print("\n==============================================")
    print("         FULL EXPERIMENT COMPLETED")
    print("==============================================")
    print(f"Summary saved to: {summary_file}")


if __name__ == "__main__":
    run_full_experiment()
