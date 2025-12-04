import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import math

# =========================================
# CONFIGURATION
# =========================================
LOG_DIR = "logs"
OUT_DIR = "analysis_output"
os.makedirs(OUT_DIR, exist_ok=True)

# Keyspace definitions based on generate_users.py
# Format: Base (charset size) ** Length
KEYSPACES = {
    "weak": {"base": 36, "min_len": 4, "max_len": 6},  # a-z, 0-9
    "medium": {"base": 62, "min_len": 7, "max_len": 10},  # a-z, A-Z, 0-9
    "strong": {"base": 70, "min_len": 11, "max_len": 16}  # alphanumeric + symbols
}


def calculate_keyspace_size(category):
    """Calculates total combinations for the category's length range."""
    cfg = KEYSPACES.get(category, KEYSPACES["strong"])
    total_combinations = 0
    for length in range(cfg["min_len"], cfg["max_len"] + 1):
        total_combinations += cfg["base"] ** length
    return total_combinations


def parse_filename(filename):
    """Extracts metadata from filename (e.g., 'bruteforce_user01_baseline.csv')"""
    parts = filename.replace(".csv", "").split("_")
    # Simple heuristic to get a readable label
    if "bruteforce" in filename:
        return f"BruteForce ({parts[-1]})"
    elif "spraying" in filename:
        return f"Spraying ({parts[-1]})"
    return filename


def analyze_log_file(filepath):
    """Reads a CSV log and returns a summary dictionary."""
    try:
        df = pd.read_csv(filepath)
    except Exception as e:
        print(f"[!] Could not read {filepath}: {e}")
        return None

    if df.empty:
        return None

    # Convert timestamps
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    # 1. Duration & Speed
    start_time = df['timestamp'].min()
    end_time = df['timestamp'].max()
    duration_sec = (end_time - start_time).total_seconds()
    if duration_sec < 1: duration_sec = 1  # Avoid div/0

    total_attempts = len(df)
    attempts_per_sec = total_attempts / duration_sec

    # 2. Latency Stats (Assignment Requirement: Mean, Median, 90th Percentile)
    latency_mean = df['latency_ms'].mean()
    latency_median = df['latency_ms'].median()
    latency_p90 = df['latency_ms'].quantile(0.9)

    # 3. Success Analysis
    success_rows = df[df['status'] == 'success']
    time_to_crack = None
    if not success_rows.empty:
        first_success = success_rows.iloc[0]['timestamp']
        time_to_crack = (first_success - start_time).total_seconds()

    return {
        "df": df,  # Keep raw data for plotting
        "summary": {
            "Label": parse_filename(os.path.basename(filepath)),
            "Total Attempts": total_attempts,
            "Duration (s)": round(duration_sec, 2),
            "Attempts/Sec": round(attempts_per_sec, 2),
            "Avg Latency (ms)": round(latency_mean, 2),
            "Median Latency (ms)": round(latency_median, 2),
            "90% Latency (ms)": round(latency_p90, 2),
            "Time to Crack (s)": round(time_to_crack, 2) if time_to_crack else None
        }
    }


def perform_extrapolation(summary_list):
    """Calculates estimated time to crack for strong passwords based on observed speed."""
    extrapolations = []

    print("\n--- EXTRAPOLATION ANALYSIS ---")

    for item in summary_list:
        stats = item["summary"]
        aps = stats["Attempts/Sec"]
        label = stats["Label"]

        # Only meaningful to extrapolate for Brute Force
        if "BruteForce" in label and aps > 0:
            # Calculate for Strong Category
            keyspace = calculate_keyspace_size("strong")
            seconds_to_crack = keyspace / aps

            # Convert to readable units
            days = seconds_to_crack / (24 * 3600)
            years = days / 365

            extrapolations.append({
                "Label": label,
                "Estimated Years (Strong)": years,
                "Keyspace": keyspace
            })

            print(f"[{label}] Speed: {aps} att/sec")
            print(f"   -> Estimated time to crack STRONG password: {years:,.0f} years")

    return pd.DataFrame(extrapolations)


def generate_graphs(results):
    """Generates the required plots."""
    summary_df = pd.DataFrame([r["summary"] for r in results])

    # Set style
    sns.set_theme(style="whitegrid")

    # 1. Attempts Per Second Comparison
    plt.figure(figsize=(10, 6))
    sns.barplot(data=summary_df, x="Label", y="Attempts/Sec", palette="viridis")
    plt.xticks(rotation=45)
    plt.title("Attack Speed Comparison (Attempts/Sec)")
    plt.tight_layout()
    plt.savefig(f"{OUT_DIR}/attempts_per_sec.png")
    plt.close()

    # 2. Latency Distribution (Box Plot)
    # Combine all raw dataframes
    all_dfs = []
    for r in results:
        d = r["df"].copy()
        d["Experiment"] = r["summary"]["Label"]
        all_dfs.append(d)

    if all_dfs:
        combined_df = pd.concat(all_dfs)
        plt.figure(figsize=(12, 6))
        sns.boxplot(data=combined_df, x="Experiment", y="latency_ms",
                    showfliers=False)  # Hide extreme outliers for clarity
        plt.xticks(rotation=45)
        plt.title("Latency Distribution by Experiment (Lower is Better)")
        plt.tight_layout()
        plt.savefig(f"{OUT_DIR}/latency_distribution.png")
        plt.close()

    # 3. Time to Crack (Actual)
    # Filter only successful cracks
    cracked_df = summary_df[summary_df["Time to Crack (s)"].notnull()]
    if not cracked_df.empty:
        plt.figure(figsize=(10, 6))
        sns.barplot(data=cracked_df, x="Label", y="Time to Crack (s)", palette="magma")
        plt.xticks(rotation=45)
        plt.title("Actual Time to Crack (Weak Passwords)")
        plt.tight_layout()
        plt.savefig(f"{OUT_DIR}/time_to_crack.png")
        plt.close()


def main():
    print(f"[*] Analyzing logs from: {LOG_DIR}")

    results = []

    # Process each log file
    for filename in os.listdir(LOG_DIR):
        if filename.endswith(".csv"):
            filepath = os.path.join(LOG_DIR, filename)
            res = analyze_log_file(filepath)
            if res:
                results.append(res)

    if not results:
        print("[!] No CSV logs found. Run experiments first!")
        return

    # 1. Generate Summary CSV
    summary_df = pd.DataFrame([r["summary"] for r in results])
    summary_csv_path = f"{OUT_DIR}/final_summary_table.csv"
    summary_df.to_csv(summary_csv_path, index=False)

    print("\n--- SUMMARY TABLE ---")
    print(summary_df[["Label", "Total Attempts", "Attempts/Sec", "Avg Latency (ms)"]].to_string(index=False))
    print(f"\nSaved summary to {summary_csv_path}")

    # 2. Perform Extrapolation
    perform_extrapolation(results)

    # 3. Generate Visualizations
    generate_graphs(results)
    print(f"\n[*] Graphs saved to {OUT_DIR}/ folder.")


if __name__ == "__main__":
    main()