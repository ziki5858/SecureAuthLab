import os
import json
import pandas as pd

LOG_DIR = "logs"
OUT_DIR = "analysis_output"
USERS_JSON = "users.json"  # optional
os.makedirs(OUT_DIR, exist_ok=True)

# --- keyspace assumptions (match your generator) ---
KEYSPACES = {
    "weak":   {"base": 36, "min_len": 4,  "max_len": 6},
    "medium": {"base": 62, "min_len": 7,  "max_len": 10},
    "strong": {"base": 70, "min_len": 11, "max_len": 16},
}

def keyspace_size(cat: str) -> int:
    cfg = KEYSPACES.get(cat, KEYSPACES["strong"])
    total = 0
    for L in range(cfg["min_len"], cfg["max_len"] + 1):
        total += cfg["base"] ** L
    return total

def load_users_categories(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    m = {}
    if isinstance(data, list):
        for u in data:
            if isinstance(u, dict) and "username" in u:
                m[str(u["username"])] = u.get("category")
    elif isinstance(data, dict):
        # maybe {username: {...}}
        for username, obj in data.items():
            if isinstance(obj, dict):
                m[str(username)] = obj.get("category")
    return m

def normalize_success(v) -> bool:
    s = str(v).strip().lower()
    return s in ("success", "ok", "true", "1", "yes")

def normalize_flags(v) -> dict:
    keys = ["rate_limit", "lockout", "captcha", "totp", "pepper"]
    out = {k: 0 for k in keys}

    if v is None:
        return out

    if isinstance(v, dict):
        for k in keys:
            out[k] = 1 if bool(v.get(k, False)) else 0
        return out

    if isinstance(v, list):
        s = set(map(str, v))
        for k in keys:
            out[k] = 1 if k in s else 0
        return out

    # string like "rate_limit=1,totp=0"
    txt = str(v)
    parts = [p.strip() for p in txt.replace(";", ",").split(",") if p.strip()]
    for p in parts:
        if "=" in p:
            k, vv = p.split("=", 1)
            k = k.strip()
            vv = vv.strip().lower()
            if k in out:
                out[k] = 1 if vv in ("1", "true", "yes", "on") else 0
        else:
            if p in out:
                out[p] = 1
    return out

def flags_to_str(d: dict) -> str:
    keys = ["rate_limit", "lockout", "captcha", "totp", "pepper"]
    return ",".join(f"{k}={int(d.get(k, 0))}" for k in keys)

def read_attempts_jsonl(path: str) -> pd.DataFrame:
    rows = []
    bad = 0
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                bad += 1
    if bad:
        print(f"[!] Skipped {bad} bad JSON lines in {path}")
    return pd.DataFrame(rows)

def read_all_csv_logs(dir_path: str) -> pd.DataFrame:
    frames = []
    for fn in os.listdir(dir_path):
        if fn.lower().endswith(".csv"):
            frames.append(pd.read_csv(os.path.join(dir_path, fn)))
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()

# --- load logs (prefer attempts.log if exists) ---
attempts_log_path = os.path.join(LOG_DIR, "attempts.log")
if os.path.exists(attempts_log_path):
    df = read_attempts_jsonl(attempts_log_path)
else:
    df = read_all_csv_logs(LOG_DIR)

if df.empty:
    print("[!] No logs found (attempts.log or CSVs).")
    raise SystemExit(1)

# --- standardize columns ---
# handle older CSV schema
if "result" not in df.columns and "status" in df.columns:
    df["result"] = df["status"]

if "latency_ms" not in df.columns:
    for alt in ["latency", "ms_latency", "latencyMs"]:
        if alt in df.columns:
            df["latency_ms"] = df[alt]
            break

for col in ["timestamp", "username", "hash_mode", "protection_flags", "result", "latency_ms"]:
    if col not in df.columns:
        df[col] = None

# parse timestamps
df["ts"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
df = df[df["ts"].notna()].copy()

# success + latency
df["success"] = df["result"].apply(normalize_success)
df["latency_ms"] = pd.to_numeric(df["latency_ms"], errors="coerce")

# category (from users.json if missing)
users_cat = load_users_categories(USERS_JSON)
if "category" not in df.columns or df["category"].isna().all():
    df["category"] = df["username"].astype(str).map(users_cat)

# normalize protection flags to stable string
df["flags_norm"] = df["protection_flags"].apply(normalize_flags)
df["protection_toggles"] = df["flags_norm"].apply(flags_to_str)

# --- REQUIRED SUMMARY: per (hash_mode, protection_toggles) ---
rows = []
for (hm, tog), g in df.groupby(["hash_mode", "protection_toggles"]):
    g = g.sort_values("ts")
    start = g["ts"].min()
    end = g["ts"].max()
    dur = (end - start).total_seconds()
    if dur <= 0:
        dur = 1.0

    total = len(g)
    aps = total / dur

    t_first = None
    if g["success"].any():
        first = g.loc[g["success"], "ts"].min()
        t_first = (first - start).total_seconds()

    # success rate by category (if category exists)
    rates = {}
    gg = g.dropna(subset=["category"])
    if not gg.empty:
        rates = gg.groupby("category")["success"].mean().to_dict()

    rows.append({
        "hash_mode": hm,
        "protection_toggles": tog,
        "total_attempts": int(total),
        "attempts_per_second": round(aps, 2),
        "time_to_first_success": round(t_first, 2) if t_first is not None else None,
        "avg_latency_ms": round(g["latency_ms"].mean(), 2) if g["latency_ms"].notna().any() else None,
        "success_rate_by_category": json.dumps({k: float(v) for k, v in rates.items()}, ensure_ascii=False)
    })

summary_df = pd.DataFrame(rows).sort_values(["hash_mode", "protection_toggles"])
summary_path = os.path.join(OUT_DIR, "required_summary_table.csv")
summary_df.to_csv(summary_path, index=False, encoding="utf-8")
print(f"[*] Wrote: {summary_path}")

# --- EXTRAPOLATION (based on measured attempts/sec) ---
extra_rows = []
for _, r in summary_df.iterrows():
    aps = r["attempts_per_second"]
    if aps is None or aps <= 0:
        continue
    for cat in ["weak", "medium", "strong"]:
        ks = keyspace_size(cat)
        worst = ks / aps
        avg = 0.5 * ks / aps  # expected average tries
        extra_rows.append({
            "hash_mode": r["hash_mode"],
            "protection_toggles": r["protection_toggles"],
            "category": cat,
            "keyspace": ks,
            "measured_attempts_per_second": aps,
            "worst_case_years": worst / (3600 * 24 * 365),
            "expected_average_years": avg / (3600 * 24 * 365),
        })

extra_df = pd.DataFrame(extra_rows)
extra_path = os.path.join(OUT_DIR, "extrapolation.csv")
extra_df.to_csv(extra_path, index=False, encoding="utf-8")
print(f"[*] Wrote: {extra_path}")

# --- quick preview ---
print("\n--- PREVIEW (first 15 rows) ---")
print(summary_df.head(15).to_string(index=False))
