# Password Authentication Mechanisms – SecureAuthLab (Course 20940)

GitHub repository: https://github.com/ziki5858/SecureAuthLab

## Group Information
- Student ID 1: 211838172
- Student ID 2: 207745316

### GROUP_SEED
Computed as XOR between the two IDs:

str(`211838172 ^ 207745316) = 12686840`

**GROUP_SEED = 12686840**

---

## Project Goal
This project implements and evaluates password authentication mechanisms and common defenses against online password attacks.  
We measure attack performance and success across different hashing algorithms and protection configurations, using reproducible logs and automated analysis.

---

## Password Strength Categories
### Weak
- **Length:** 4–6  (lowercase + digits = 36)
- **Charset:** lowercase letters + digits (`a–z`, `0–9`)  
- **No special characters**  
- **Hashing:** SHA-256 (with optional per-user salt, depending on group)

### Medium
- **Length:** 7–10  (mixed case + digits = 62)
- **Charset:** lowercase + uppercase + digits (`a–z`, `A–Z`, `0–9`)  
- **No special characters**  
- **Hashing:** bcrypt (**cost = 12**)

### Strong
- **Length:** 11–16  (mixed case + digits + symbols = ~94)
- **Charset:** lowercase + uppercase + digits + special characters (`!@#$%^&*`, etc.)  
- **Hashing:** Argon2id (**t = 1, m = 64MB, p = 1**)

---

## Users Dataset (`users.json`)
`users.json` contains **30 generated users**:
- 10 weak users
- 10 medium users
- 10 strong users
- 5 common users (common pwd)
- group_seed user(pwd = group_seed)

we created a clean users set base with the  following structure:
{
        "username": "weak_1",
        "password": "alewsp",
        "category": "weak"
    }
Each hash/defence has the following structure (different json file then the base.):
```json
{
        "username": "weak_1",
        "password": "87a65adbe7f737f3fae081897a12faaac07aa7a6c7b64d541196acb99ae55535",
        "category": "weak",
        "salt": "2c07811c982f0fd03b019217e93ff3d26641bde88904abf96071b149992f3e35",
        "totp_secret": false,
        "hash_mode": "sha",
        "used_pepper": false,
        "GROUP_SEED": "12686840"
    }

```

## Security Mechanisms Implemented
The server supports the following defenses (toggle via CLI flags):
- Rate limiting (`--rate-limit`)
- Account lockout (`--lockout`)
- CAPTCHA simulation (`--captcha`)
- TOTP verification / 2FA (`--totp`)
- Pepper (server-side secret) (`--pepper`)

---

## Log Format
each defence is automatically create a log file with the defences in its name

Each entry includes:

- "timestamp"
- "group_seed"
- "username"
- "category"
- "password_tried"
- "latency_ms"
- "global_count"
- "result"
- "detail"

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
python server.py
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
python server.py --rate-limit --lockout --captcha --totp --pepper
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

### 1) Generate users base (if needed)
```bash
python generate_users.py
```
### 2) Generate users hashes
python generate_server_db.py --hash/salt/pepper

### 3) Run attacks
Brute force:
```bash
python attacker_bf.py
```

Password spraying:
```bash
python attacker_spraying.py
```


## Log Analysis
Run the analysis script to generate summary tables and graphs:

```bash
python analyze_result.py
```

Outputs are written to:
- `final_summary_report.txt`


The analysis includes:
- Total attempts
- Attempts per second
- Time to first success (if any)
- Latency mean / median / p90
- Extrapolation for cracking password using measured attempts/sec

---

## Ethical Statement
All experiments were performed **locally** against our own test server and synthetic user data created for this assignment.  
No real user credentials were used, and no external systems or third-party services were targeted.
