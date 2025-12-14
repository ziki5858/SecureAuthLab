# Password Authentication Mechanisms – SecureAuthLab (Course 20940)

GitHub repository: https://github.com/ziki5858/SecureAuthLab

## Group Information
- Student ID 1: 211838172
- Student ID 2: 207745316

### GROUP_SEED
Computed as XOR between the two IDs:

`211838172 ^ 207745316 = 6631928`

**GROUP_SEED = 6631928**

---

## Project Goal
This project implements and evaluates password authentication mechanisms and common defenses against online password attacks.  
We measure attack performance and success across different hashing algorithms and protection configurations, using reproducible logs and automated analysis.

---

## Password Strength Categories

### Weak
- **Length:** 4–6  
- **Charset:** lowercase letters + digits (`a–z`, `0–9`)  
- **No special characters**  
- **Hashing:** SHA-256 (with optional per-user salt, depending on group)

### Medium
- **Length:** 7–10  
- **Charset:** lowercase + uppercase + digits (`a–z`, `A–Z`, `0–9`)  
- **No special characters**  
- **Hashing:** bcrypt (**cost = 12**)

### Strong
- **Length:** 11–16  
- **Charset:** lowercase + uppercase + digits + special characters (`!@#$%^&*`, etc.)  
- **Hashing:** Argon2id (**t = 1, m = 64MB, p = 1**)

---

## Users Dataset (`users.json`)
`users.json` contains **30 generated users**:
- 10 weak users
- 10 medium users
- 10 strong users

Each user record has the following structure:

```json
{
  "username": "user01",
  "category": "weak",
  "salt": "random_hex_string_or_empty",
  "password_hash": "hashed_password_value",
  "hash_mode": "sha256",
  "totp_secret": "",
  "group_seed": 6631928,
  "used_pepper": false
}
```

---

## Experimental Groups and Security Matrix
The 30 users are divided into 5 groups to isolate security mechanisms.

| Group | Users | Category | Hash Algorithm | Salt | Pepper | Purpose |
|------:|-------|----------|----------------|:----:|:------:|---------|
| **A** | `user01`–`user05` | Weak | SHA-256 | ❌ | ❌ | **Baseline** — no salt and no pepper. Measures raw online attack speed. |
| **B** | `user06`–`user10` | Weak | SHA-256 | ✅ | ❌ | **Salt effect** — compare against Group A under identical attack conditions. |
| **C** | `user11`–`user20` | Medium | bcrypt (cost=12) | ✅ | ❌ | **Algorithm comparison** — quantify slowdown vs SHA-256. |
| **D** | `user21`–`user25` | Strong | Argon2id (t=1, m=64MB, p=1) | ✅ | ✅ | **Pepper defense** — server-only secret applied for these users. |
| **E** | `user26`–`user30` | Strong | Argon2id (t=1, m=64MB, p=1) | ✅ | ❌ | **Pepper control** — Argon2id without pepper. |

### Notes
- **Salt** is per-user and stored in `users.json` (may be empty for baseline users).
- **Pepper** is a global server-only secret loaded from environment variable `MAMAN16_PEPPER` (never stored in `users.json`).
- **TOTP (2FA)** is enabled for selected users via the `totp_secret` field (e.g., `user01`, `user04`, `user07`, ...).

---

## Security Mechanisms Implemented
The server supports the following defenses (toggle via CLI flags):
- Rate limiting (`--rate-limit`)
- Account lockout (`--lockout`)
- CAPTCHA simulation (`--captcha`)
- TOTP verification / 2FA (`--totp`)
- Pepper (server-side secret) (`--pepper`)

---

## Log Format (Required)
All authentication attempts are written to:

`logs/attempts.log` (JSON-lines)

Each entry includes (minimum required fields):
- `timestamp`
- `group_seed`
- `username`
- `hash_mode`
- `protection_flags`
- `result` (`success` / `failure`)
- `latency_ms`

Additional helpful fields (for analysis/debugging):
- `category`
- `status` (`success` / `failure`, same as result)
- `detail` (fine-grained reason such as `fail_password`, `fail_locked`, etc.)

---

## Installation
Create a virtual environment and install dependencies:

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

pip install -r requirements.txt
```

---

## Running the Server

### 1) Start the server (baseline)
```bash
python server.py --port 5000
```

### 2) Start the server with protections enabled
Example: enable rate-limit + lockout + captcha + totp + pepper.

Linux/Mac:
```bash
export MAMAN16_PEPPER="your_lab_pepper"
python server.py --rate-limit --lockout --captcha --totp --pepper --port 5000
```

Windows PowerShell:
```powershell
$env:MAMAN16_PEPPER="your_lab_pepper"
python server.py --rate-limit --lockout --captcha --totp --pepper --port 5000
```

Health check:
```bash
curl http://127.0.0.1:5000/health
```

CAPTCHA token (simulation):
```bash
curl "http://127.0.0.1:5000/admin/get_captcha_token?group_seed=6631928"
```

---

## Running Experiments

### 1) Generate users (if needed)
```bash
python generate_users.py
```

### 2) Run attacks
Brute force:
```bash
python attack_bruteforce.py --username user01 --category weak --attempts 2000 --tag groupA
```

Password spraying:
```bash
python attack_spraying.py --url http://127.0.0.1:5000/login --delay 0 --tag groupA
```

Full suite runner:
```bash
python run_experiments.py
```

### Fairness note
For **protection-enabled** configurations (rate-limit/lockout/captcha/totp), experiments should be executed **sequentially** (not concurrently) to avoid interference from server load.

---

## Log Analysis
Run the analysis script to generate summary tables and graphs:

```bash
python analysis_logs.py
```

Outputs are written to:
- `analysis_output/final_summary_table.csv`
- `analysis_output/*.png`

The analysis includes:
- Total attempts
- Attempts per second
- Time to first success (if any)
- Latency mean / median / p90
- Extrapolation for strong-password keyspace using measured attempts/sec

---

## Reproducibility
To reproduce results:
1. Use the same `users.json` (includes `group_seed` and `used_pepper` flags).
2. If pepper is enabled, set the same `MAMAN16_PEPPER` value used during generation.
3. Start the server with the exact same protection flags.
4. Run attack scripts.
5. Run `analysis_logs.py` on the produced logs.

---

## Ethical Statement
All experiments were performed **locally** against our own test server and synthetic user data created for this assignment.  
No real user credentials were used, and no external systems or third-party services were targeted.
