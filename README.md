# Password Authentication Mechanisms – Project Summary

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
