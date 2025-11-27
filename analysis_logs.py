import json
import os
import math
from collections import defaultdict
from datetime import datetime

# Directory with log files
LOG_DIR = "logs"

# Group seed
GROUP_SEED = 6631928

# Keyspace configuration per category
KEYSPACES = {
    "weak": {
        "charset": 36,        # a-z + digits
        "min": 4,
        "max": 6
    },
    "medium": {
        "charset": 62,        # a-z + A-Z + digits
        "min": 7,
        "max": 10
    },
    "strong": {
        "charset": 70,        # letters + digits + special chars (~8)
        "min": 11,
        "max": 16
    }
}

def calc_keyspace(cfg):
    """Calculate keyspace sum for lengths min..max."""
    base = cfg["charset"]
    total = 0
    for L in range(cfg["min"], cfg["max"] + 1):
        total += base ** L
    return total


def load_log(filepath):
    """Load all JSON-log entries from a file."""
    entries = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            try:
                if line.startswith("{"):
                    entries.append(json.loads(line))
            except:
                pass
    return entries


def summarize(entries):
    """Compute summary metrics from a list of log entries."""
    if not entries:
        return None

    timestamps = [e["timestamp"] for e in entries]
    t_start = min(timestamps)
    t_end = max(timestamps)
    duration = t_end - t_start if t_end > t_start else 1

    total_attempts = len(entries)
    attempts_per_sec = total_attempts / duration

    # Average latency
    latencies = [e["latency_ms"] for e in entries]
    avg_latency = sum(latencies) / len(latencies)

    # Success info
    successes = [e for e in entries if e["result"] == "success"]
    time_to_first_success = None
    if successes:
        first = min(s["timestamp"] for s in successes)
        time_to_first_success = first - t_start

    # Success rate by category
    by_cat = defaultdict(lambda: {"attempts": 0, "successes": 0})
    for e in entries:
        cat = e.get("category")
        by_cat[cat]["attempts"] += 1
        if e["result"] == "success":
            by_cat[cat]["successes"] += 1

    return {
        "total_attempts": total_attempts,
        "duration_sec": duration,
        "attempts_per_sec": attempts_per_sec,
        "avg_latency_ms": avg_latency,
        "time_to_first_success": time_to_first_success,
        "success_by_category": by_cat,
    }


def extrapolate(summary, entries):
    """Perform extrapolation for each category when no success was achieved."""
    results = {}
    aps = summary["attempts_per_sec"]

    for e in entries:
        cat = e["category"]
        break  # entries all belong to same config; categories separated by brute-force script

    # Determine which categories appear in log
    cats_seen = set(e["category"] for e in entries)

    for cat in cats_seen:
        keyspace = calc_keyspace(KEYSPACES[cat])
        est_time_sec = keyspace / aps
        results[cat] = {
            "keyspace": keyspace,
            "estimated_time_sec": est_time_sec,
            "estimated_time_hours": est_time_sec / 3600,
            "estimated_time_days": est_time_sec / 86400,
        }
    return results


def analyze_all():
    """Analyze all log files under logs/ directory."""
    print("\n==================== LOG ANALYSIS REPORT ====================\n")

    for filename in os.listdir(LOG_DIR):
        if not filename.endswith(".log"):
            continue

        path = os.path.join(LOG_DIR, filename)
        entries = load_log(path)
        if not entries:
            continue

        print(f"\n---------------------------------------------------------")
        print(f" FILE: {filename}")
        print("---------------------------------------------------------")

        summary = summarize(entries)

        print(f"Total attempts: {summary['total_attempts']}")
        print(f"Duration (sec): {summary['duration_sec']:.2f}")
        print(f"Attempts/sec: {summary['attempts_per_sec']:.2f}")
        print(f"Average latency (ms): {summary['avg_latency_ms']:.2f}")

        if summary["time_to_first_success"] is not None:
            print(f"Time to first success: {summary['time_to_first_success']:.2f} sec")
        else:
            print("Time to first success: None (no success)")

        print("\nSuccess rate by category:")
        for cat, data in summary["success_by_category"].items():
            rate = (data["successes"] / data["attempts"]) * 100 if data["attempts"] > 0 else 0
            print(f"  {cat}: {data['successes']} / {data['attempts']}  ({rate:.2f}%)")

        # Extrapolation if needed
        if summary["time_to_first_success"] is None:
            print("\n>>> EXTRAPOLATION (no success found)")
            ex = extrapolate(summary, entries)
            for cat, data in ex.items():
                print(f"\nCategory: {cat}")
                print(f"  Keyspace: {data['keyspace']:,}")
                print(f"  Estimated time (sec): {data['estimated_time_sec']:.2e}")
                print(f"  Estimated time (hours): {data['estimated_time_hours']:.2e}")
                print(f"  Estimated time (days): {data['estimated_time_days']:.2e}")

    print("\n================ END OF REPORT ================\n")


if __name__ == "__main__":
    analyze_all()
