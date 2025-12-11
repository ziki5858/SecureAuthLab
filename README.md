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
## 👥 User Data Structure & Experiment Groups

To facilitate a comparative analysis of different security mechanisms (Salt, Pepper, Algorithms), the 30 generated users are divided into 5 distinct experimental groups.

| Group | Users | Category | Hash Algo | Salt | Pepper | Experiment Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **A** | `user01` - `user05` | **Weak** | SHA-256 | ❌ **No** | ❌ No | **Baseline Control:** Measuring maximum speed and vulnerability without Salt. |
| **B** | `user06` - `user10` | **Weak** | SHA-256 | ✅ **Yes** | ❌ No | **Salt Effectiveness:** Comparing attack latency vs. Group A. |
| **C** | `user11` - `user20` | **Medium** | bcrypt | ✅ Yes | ❌ No | **Algorithm Comparison:** Measuring the slowdown caused by bcrypt (cost=12). |
| **D** | `user21` - `user25` | **Strong** | Argon2id | ✅ Yes | ✅ **Yes** | **Pepper Defense:** Testing the server's ability to verify using an external secret. |
| **E** | `user26` - `user30` | **Strong** | Argon2id | ✅ Yes | ❌ No | **Pepper Control:** Ensuring standard Strong users are unaffected when Pepper is enabled. |

* **TOTP:** Two-Factor Authentication is enabled for every 3rd user (e.g., `user01`, `user04`, `user22`...) across all groups.