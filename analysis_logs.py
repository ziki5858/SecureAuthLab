import json
import os
import math
from collections import defaultdict
import matplotlib.pyplot as plt
import csv

LOG_DIR = "logs"
OUT_DIR = "analysis_output"
os.makedirs(OUT_DIR, exist_ok=True)

GROUP_SEED = 6631928

KEYSPACES = {
    "weak":  {"charset": 36, "min": 4, "max": 6},
    "medium": {"charset": 62, "min": 7, "max": 10},
    "strong": {"charset": 70, "min": 11, "max": 16}
}

def calc_keyspace(cfg):
    base = cfg["charset"]
    total = 0
    for L in range(cfg["min"], cfg["max"] + 1):
        total += base ** L
    return total


def load_log(filepath):
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
    if not entries:
        return None

    numeric_ts = []
    for e in entries:
        ts = e.get("timestamp")
        if isinstance(ts, (float, int)):
            numeric_ts.append(ts)

    if not numeric_ts:
        return None

    t_start = min(numeric_ts)
    t_end = max(numeric_ts)
    duration = t_end - t_start if t_end > t_start else 1

    total_attempts = len(entries)
    attempts_per_sec = total_attempts / duration

    latencies = [e["latency_ms"] for e in entries if isinstance(e.get("latency_ms"), (int, float))]
    avg_latency = sum(latencies) / len(latencies) if latencies else 0

    successes = [e for e in entries if e.get("result") == "success"]
    time_to_first_success = None
    if successes:
        ts_list = [s["timestamp"] for s in successes if isinstance(s["timestamp"], (int, float))]
        if ts_list:
            time_to_first_success = min(ts_list) - t_start

    by_cat = defaultdict(lambda: {"attempts": 0, "successes": 0})
    for e in entries:
        cat = e.get("category")
        by_cat[cat]["attempts"] += 1
        if e.get("result") == "success":
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
    results = {}
    aps = summary["attempts_per_sec"]

    cats_seen = set(e.get("category") for e in entries if "category" in e)

    for cat in cats_seen:
        keyspace = calc_keyspace(KEYSPACES[cat])
        est_time_sec = keyspace / aps if aps > 0 else float("inf")

        results[cat] = {
            "keyspace": keyspace,
            "sec": est_time_sec,
            "hours": est_time_sec / 3600,
            "days": est_time_sec / 86400,
        }
    return results


def analyze_all():
    print("\n==================== LOG ANALYSIS REPORT ====================\n")

    summary_table = []
    attempts_sec_data = []
    latency_data = []
    extrapolation_days_data = []

    for filename in os.listdir(LOG_DIR):

        if not filename.endswith(".log"):
            continue

        path = os.path.join(LOG_DIR, filename)
        entries = load_log(path)
        summary = summarize(entries)

        if summary is None:
            print(f"[SKIP] {filename} — invalid or missing numeric timestamps\n")
            continue

        print(f"\n---------------------------------------------------------")
        print(f" FILE: {filename}")
        print("---------------------------------------------------------")

        print(f"Total attempts: {summary['total_attempts']}")
        print(f"Duration (sec): {summary['duration_sec']:.2f}")
        print(f"Attempts/sec: {summary['attempts_per_sec']:.2f}")
        print(f"Average latency (ms): {summary['avg_latency_ms']:.2f}")

        if summary["time_to_first_success"]:
            print(f"Time to first success: {summary['time_to_first_success']:.2f} sec")
        else:
            print("Time to first success: None (no success)")

        print("\nSuccess rate by category:")
        for cat, data in summary["success_by_category"].items():
            rate = (data["successes"] / data["attempts"]) * 100 if data["attempts"] else 0
            print(f"  {cat}: {data['successes']} / {data['attempts']}  ({rate:.2f}%)")

        summary_table.append([
            filename,
            summary["total_attempts"],
            round(summary["attempts_per_sec"], 2),
            round(summary["avg_latency_ms"], 2),
            summary["time_to_first_success"]
        ])

        attempts_sec_data.append((filename, summary["attempts_per_sec"]))
        latency_data.append((filename, summary["avg_latency_ms"]))

        if summary["time_to_first_success"] is None:
            print("\n>>> EXTRAPOLATION (no success found)")
            ex = extrapolate(summary, entries)
            for cat, data in ex.items():
                extrapolation_days_data.append((f"{filename}-{cat}", data["days"]))
                print(f"\nCategory: {cat}")
                print(f"  Keyspace: {data['keyspace']:,}")
                print(f"  Estimated time (sec): {data['sec']:.2e}")
                print(f"  Estimated time (hours): {data['hours']:.2e}")
                print(f"  Estimated time (days): {data['days']:.2e}")

    # =====================
    # EXPORT TABLE CSV
    # =====================
    with open(os.path.join(OUT_DIR, "summary_table.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Config", "Total Attempts", "Attempts/sec", "Avg Latency (ms)", "Time to First Success"])
        writer.writerows(summary_table)

    # =====================
    # GRAPH: Attempts/sec
    # =====================
    labels, values = zip(*attempts_sec_data)
    plt.figure(figsize=(12, 6))
    plt.bar(labels, values, color="skyblue")
    plt.xticks(rotation=45, ha="right")
    plt.title("Attempts per Second by Configuration")
    plt.ylabel("Attempts/sec")
    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, "attempts_per_sec.png"))
    plt.close()

    # =====================
    # GRAPH: latency
    # =====================
    labels, values = zip(*latency_data)
    plt.figure(figsize=(12, 6))
    plt.bar(labels, values, color="orange")
    plt.xticks(rotation=45, ha="right")
    plt.ylabel("Avg Latency (ms)")
    plt.title("Average Latency per Configuration")
    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, "avg_latency.png"))
    plt.close()

    # =====================
    # GRAPH: Extrapolation Days
    # =====================
    if extrapolation_days_data:
        labels, values = zip(*extrapolation_days_data)
        plt.figure(figsize=(12, 6))
        plt.bar(labels, values, color="green")
        plt.xticks(rotation=45, ha="right")
        plt.ylabel("Estimated Days to Crack")
        plt.title("Extrapolated Time to Crack (Days)")
        plt.yscale("log")  # חשוב – כי המספרים עצומים
        plt.tight_layout()
        plt.savefig(os.path.join(OUT_DIR, "extrapolation_days.png"))
        plt.close()

    print("\n================ END OF REPORT ================\n")
    print(f"Summary table saved to: {OUT_DIR}/summary_table.csv")
    print(f"Graphs saved to: {OUT_DIR}/")



if __name__ == "__main__":
    analyze_all()
