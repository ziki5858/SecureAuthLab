import json
import glob
import os
import statistics
import time
from collections import defaultdict

SUMMARY_FILE = "logs/final_summary_report.txt"

# Force strict order for Brute Force report
BF_ORDER = ["weak", "medium", "strong"]

# Keyspace definitions for BF extrapolation
KEYSPACES = {
    "weak": sum(36 ** i for i in range(4, 7)),
    "medium": sum(62 ** i for i in range(7, 11)),
    "strong": sum(94 ** i for i in range(11, 17))
}


def generate_report_string(file_path, prefix):
    """
    Analyzes log files with research-grade logic:
    - BF: Performance derived from Median Latency, Keyspace extrapolation.
    - Spray: Cycle Time and Expected Time to Hit Success.
    """
    tag = os.path.basename(file_path).replace(f"{prefix}_", "").replace(".log", "").upper()

    stats = defaultdict(lambda: {
        "users": set(), "cracked": 0, "locked": 0, "lats": [], "attempts": 0, "unique_pwds": set()
    })

    if not os.path.exists(file_path): return ""

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                entry = json.loads(line)
                cat = entry.get('category') or entry.get('cat')

                # --- CATEGORY FILTERING ---
                if prefix == "bf" and cat not in BF_ORDER: continue
                if prefix == "spray" and cat != "common": continue

                username = entry.get('username') or entry.get('user')
                password = entry.get('password_tried') or entry.get('password')

                stats[cat]["users"].add(username)
                stats[cat]["attempts"] += 1
                if password: stats[cat]["unique_pwds"].add(password)

                lat = entry.get('latency_ms') or entry.get('latency', 0)
                if lat > 0: stats[cat]["lats"].append(lat)

                if entry.get('result') == "success" or entry.get('status') == 200:
                    stats[cat]["cracked"] += 1
                if entry.get('detail') == "locked" or entry.get('status') == 423:
                    stats[cat]["locked"] += 1
            except:
                continue

    if not stats: return ""

    report_lines = ["\n" + "=" * 130, f" {prefix.upper()} EXPERIMENT REPORT: {tag}", "=" * 130]

    if prefix == "bf":
        header = f"{'Category':<10} | {'Users':<6} | {'Cracked':<8} | {'Locked':<7} | {'Med Lat':<10} | {'Att/sec':<10} | {'Full Keyspace Time'}"
        categories = [c for c in BF_ORDER if c in stats]
    else:  # Spraying logic
        header = f"{'Category':<10} | {'Users':<6} | {'Cracked':<8} | {'Med Lat':<10} | {'Cycle Time':<12} | {'Exp. Time to Hit 1'}"
        categories = ["common"] if "common" in stats else []

    report_lines.append(header)
    report_lines.append("-" * len(header))

    for cat in categories:
        data = stats[cat]
        lats = sorted(data["lats"])
        num_users = len(data["users"])
        med_lat = statistics.median(lats) if lats else 0.001

        if prefix == "bf":
            # POINT 1 & 3: Deriving performance directly from Latency to eliminate noise
            att_per_sec = 1000 / med_lat

            keyspace = KEYSPACES.get(cat, 1)
            est_seconds = keyspace / att_per_sec

            if est_seconds > 31536000:
                extrap = f"{est_seconds / 31536000:.1e} years"
            elif est_seconds > 86400:
                extrap = f"{est_seconds / 86400:.1f} days"
            else:
                extrap = f"{est_seconds / 3600:.1f} hours"

            line = f"{cat:<10} | {num_users:<6} | {data['cracked']:<8} | {data['locked']:<7} | {med_lat:>8.2f}ms | {att_per_sec:>8.2f} | {extrap}"

        else:  # Spraying: Logic for 'common' passwords
            cycle_time_sec = (med_lat * num_users) / 1000

            # Predict time to find at least one success based on hit rate
            num_pwds_tried = len(data["unique_pwds"])
            if data["cracked"] > 0 and num_pwds_tried > 0:
                pwds_per_hit = num_pwds_tried / data["cracked"]
                hit_time_sec = pwds_per_hit * cycle_time_sec

                if hit_time_sec > 3600:
                    hit_extrap = f"{hit_time_sec / 3600:.2f} hours"
                elif hit_time_sec > 60:
                    hit_extrap = f"{hit_time_sec / 60:.2f} mins"
                else:
                    hit_extrap = f"{hit_time_sec:.2f} seconds"
            else:
                hit_extrap = "N/A (No hits)"

            line = f"{cat:<10} | {num_users:<6} | {data['cracked']:<8} | {med_lat:>8.2f}ms | {cycle_time_sec:>9.2f}s | {hit_extrap}"

        report_lines.append(line)
    return "\n".join(report_lines)


def main():
    all_reports = []
    # Process files in alphabetical order (BF then Spray)
    for pattern, pref in [("logs/bf_*.log", "bf"), ("logs/spray_*.log", "spray")]:
        for f in sorted(glob.glob(pattern)):
            report = generate_report_string(f, pref)
            if report: all_reports.append(report)

    with open(SUMMARY_FILE, "w", encoding="utf-8") as out_file:
        out_file.write(
            f"AUTHENTICATION SECURITY RESEARCH - CONSOLIDATED REPORT\nGenerated at: {time.ctime()}\n" + "".join(
                all_reports))
    print(f"[+] Mathematically consistent report generated: {SUMMARY_FILE}")


if __name__ == "__main__":
    main()