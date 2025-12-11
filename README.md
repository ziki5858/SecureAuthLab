# Password Authentication Mechanisms – Project Summary
github_repository: "https://github.com/ziki5858/SecureAuthLab"

## Group Information
- ID 1: 211838172
- ID 2: 207745316

### GROUP_SEED
Calculated as bitwise XOR between the two IDs:  
`211838172 ^ 207745316 = 6631928`

**GROUP_SEED = 6631928**

---
## Password Strength Categories

### Weak Passwords
- Length: 4–6 characters
- Contains only lowercase letters and/or digits
- No special characters
- Hashing algorithm used: **SHA-256 + salt**
- Examples: `abcd`, `12345`, `qwer12`

### Medium Passwords
- Length: 7–10 characters
- Contains: lowercase letters, digits, and uppercase letters
- No special characters
- Hashing algorithm used: **bcrypt (cost = 12)**
- Examples: `blUe1234`, `Matan2020`

### Strong Passwords
- Length: 11–16 characters
- Contains a combination of:
  - lowercase letters  
  - uppercase letters  
  - digits  
  - special characters (`!@#$%^&*`, etc.)
- Hashing algorithm used: **Argon2id (time = 1, memory = 64MB, parallelism = 1)**
- Examples: `G7_tP9!bxD42`, `qA!82nfL3@wK`
---

## users.json Structure

The file **users.json** will contain a list of **30 users**:
- 10 users with weak passwords  
- 10 users with medium passwords  
- 10 users with strong passwords  

Each user entry has the following structure:

```json
{
  "username": "user01",
  "category": "weak",
  "salt": "random_hex_string",
  "password_hash": "hashed_password_value",
  "hash_mode": "sha256",
  "totp_secret": ""
}
## 👥 User Groups & Security Configuration Matrix

The 30 generated users are divided into **5 experimental groups**, each designed to test a specific security mechanism.

| Group | Users | Category | Hash Algorithm | Salt | Pepper | Purpose |
|------|--------|-----------|----------------|:----:|:------:|---------|
| **A** | `user01`–`user05` | 🟠 Weak | SHA-256 | ❌ | ❌ | **Baseline Control** — No Salt, no Pepper. Measures raw cracking speed & vulnerability. |
| **B** | `user06`–`user10` | 🟠 Weak | SHA-256 | ✅ | ❌ | **Salt Effectiveness** — Compare attack difficulty & latency vs. Group A. |
| **C** | `user11`–`user20` | 🔵 Medium | bcrypt (cost=12) | ✅ | ❌ | **Algorithm Comparison** — Evaluate slowdown caused by bcrypt vs. SHA-256. |
| **D** | `user21`–`user25` | 🟣 Strong | Argon2id (t=1, m=64MB, p=1) | ✅ | ✅ | **Pepper Defense** — Strong hashing + external secret; measure verification impact. |
| **E** | `user26`–`user30` | 🟣 Strong | Argon2id | ✅ | ❌ | **Pepper Control Group** — Ensures Argon2id runs normally when Pepper is disabled. |

### ⭐ Notes
- **Salt** → Unique per-user salt stored in `users.json`.  
- **Pepper** → Global secret stored *only on the server*, never in the database.  
- **TOTP (2FA)** → Enabled for **every 3rd user** (e.g., `user01`, `user04`, `user07`, …).  
- Groups are structured to isolate the effect of each specific protection mechanism.
