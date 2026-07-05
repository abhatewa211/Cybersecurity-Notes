## 1. Password Spraying

### Definition

**Password spraying** is a type of **brute-force attack** in which an attacker attempts **one password against many different user accounts** instead of trying many passwords against a single account.

This technique helps avoid account lockouts because each user account receives only a small number of login attempts.

### Why it Works

Many organizations assign **default or temporary passwords** when creating new user accounts.

Example:

```
ChangeMe123!
Welcome123!
Password@123
Company@2026
```

If employees forget to change these passwords, an attacker can compromise multiple accounts.

### Example Scenario

Company policy:

```
New Employee Password = ChangeMe123!
```

Attacker has:

```
john
mary
alex
david
emma
```

The attacker tries:

```
Password:
ChangeMe123!
```

against every user.

If **mary** never changed her password:

```
mary : ChangeMe123!
```

✔ Login successful.

---

## Password Spraying Workflow

```
Obtain usernames
        │
        ▼
Choose one common password
        │
        ▼
Try against every account
        │
        ▼
Valid account discovered
        │
        ▼
Repeat later with another password
```

---

## Advantages

- Low chance of account lockout
    
- Difficult to detect if performed slowly
    
- Very effective against default passwords
    
- Common in Active Directory environments
    

---

## Common Tools

|Environment|Tool|
|---|---|
|Active Directory|NetExec|
|Kerberos|Kerbrute|
|Web Applications|Burp Suite|
|SSH|Hydra|

---

## HTB Example

```bash
netexec smb 10.100.38.0/24 \
-u usernames.list \
-p 'ChangeMe123!'
```

### Breakdown

```
netexec
```

SMB authentication tool.

```
smb
```

Protocol.

```
10.100.38.0/24
```

Target subnet.

```
-u usernames.list
```

Username list.

```
-p 'ChangeMe123!'
```

Password being sprayed.

---

## Important Points

✅ One password

✅ Many usernames

❌ Not many passwords on one account

---

# 2. Credential Stuffing

![Image](https://images.openai.com/static-rsc-4/ucTrFzxAANt5nnBnF7Xw-hXFtCKLuhb3l34BLSZ5y76s45vJAzjc8ikjtSBRKF1pyJCB1oE69Hq7vAKZiju6xsPv6fco4Q0ZEaMogUr-ghmsM2WcMBP7PIX8GPCriOUkKZunsXfIR3BFQBI5GYE29ZsxrWdRy9Pi77_PmCTRyoO4TxEPZAY2zP4EFpNVc-g6?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/l9vJSc6gbKnX_Ms8XhktDNa6WUwgtKBmtKorr4hROTlhsYgcPLInTu_0Yq98ZMB6PTFS7B5vzEeCL0aKSXBvX4c17Is63Pf-xlzCN5HT775_jxibgzR5a_btZFvGVft6zbAzZN3T2s3BJM5Ub2ooJRVmBfPIrvFwhexCGHoA5krZbROQtTocy4ZPPeVLtoU9?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/2VtD5v_OZgOBNrLyptqIGKh8P2SIa7uXW0DPVZuZ3UsVHpf5rm-U4SOojbJUhDsVkXVY00nDb0aOFTP8btRia-Lc9cqF-J9u281853sXfcUh4mzOtYdftAoiVNSu8z978X4O0oK_iXL43LPunewwyy9NomI2ZcUNocXpDVUnqakHZ7MDUNYgeWtxORFiLPkY?purpose=fullsize)

### Definition

Credential stuffing is a brute-force attack where an attacker uses **previously leaked username/password combinations** from one service to log into another service.

It relies on **password reuse**.

---

### Example

A data breach exposes:

```
john@gmail.com : Summer2025!
```

The attacker tries the same credentials on:

- Gmail
    
- Facebook
    
- LinkedIn
    
- VPN
    
- Office365
    
- SSH
    
- Company Portal
    

If John reused the password:

✔ Access granted.

---

## Credential Stuffing Workflow

```
Database Breach
        │
        ▼
Username:Password list
        │
        ▼
Automated login attempts
        │
        ▼
Password reused?
        │
        ▼
Account compromised
```

---

## Why It Works

Many users reuse passwords.

Example:

```
Facebook
↓

john123 / Password@123

↓

LinkedIn
↓

john123 / Password@123

↓

Company VPN
↓

john123 / Password@123
```

One breach can compromise multiple accounts.

---

## Hydra Example

```bash
hydra -C user_pass.list ssh://10.100.38.23
```

### Breakdown

```
-C user_pass.list
```

Credential file:

```
john:Password123
mary:Summer2024
alex:qwerty
```

```
ssh://10.100.38.23
```

SSH target.

Hydra tests each username/password pair.

---

## Important Points

Uses:

✔ Known usernames

✔ Known passwords

No guessing involved.

---

# Password Spraying vs Credential Stuffing

|Password Spraying|Credential Stuffing|
|---|---|
|One password|Username/password pairs|
|Many users|Multiple services|
|Guesses password|Uses leaked credentials|
|Default passwords|Password reuse|

---

# 3. Default Credentials

![Image](https://images.openai.com/static-rsc-4/LZZUkZRFrk5nPk1Q0yFo6mdYGhpbxzTLsnlhenJ_qC_VY0XV0qC2-IMDzutVo7sVLv0Jx8FJx-X8D4THawNN08UOIG0aBruOfHVuYgdLPqpDIpCNLrDaaxlw8hdsdIPFRR24na5GJ_V97A-GbswZXXNVLP4I0oLPyhd-a3tFrVGK2HLDF98IJtClD_X9lA6y?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/5FOpSm4lIjuiWwdPbwYZyKrGpFdtOilIStDdqJUJ3Utoof5ds3C38PoFLO4G7HANos9e7UC-g-OYBGunyTdLQp3qwaLx8REq5007wLz_X1BZkAhngpd8ABOzIQofG_3S05oKLOp-6oZAwOqSPSUb0zvWlHsVLrNKih0LMqbhUY1CSXk2Bv1BO4cqt6KD4NxE?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/S3N7QTxi5_2ALNYEVg0zxig5tHBRSyrpx293DE77ZEG2FeLF1Q1XuZ1eeXlKJCYRSW51CHWnIMdMjG7v4DVrlFoQm_Se9uBsPB_Vxo1xhWI77bxA8iwRTeFVWD5WVTjrSV9DrUn354Ps6j2fhhiB8uy8CBJdfKxWSEPWGM4ArFsOThaEyxhpyLR-hqJNhJNM?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/-xrRZ-8bg9MwwVtlWq6Mqfr4U0IIJBsXqhECgkNm8gWhihaVsVv_87m0vYaEhMojATeO1Bgn7hWc6tYzUqPmUbebzaxWblCVIjOgmG64JWpA0JrNg4L11ON-ayoMusZJJGk7yS_DESgXXoIHkNvo6VpRAh4zTFbgB6zLkJEsakDCu5QtQhiHBWectupTF8u5?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/dGj2vd1zY3NB4nOKKau3jZqEWvm_oVuyWPNyNLNNtuts-ABey50CwbgwfEmPKkKH3-ektFqJZ1chJpiY6DegRBz4MQJz9YUfybT2I0dNmZIeL1UiQqG68qH-nB6ge8vDlkeSJpAvhJKAz2Fk7g9v2oZ9QbgJyWAqtVGE-1hC-UFdSFG5aAxJVJ8kiFpTLpsx?purpose=fullsize)

### Definition

Many systems are shipped with **default usernames and passwords**.

Administrators are expected to change them during installation.

Unfortunately, they are often forgotten.

---

## Common Devices

- Routers
    
- Firewalls
    
- Switches
    
- Databases
    
- Web Applications
    
- Network Appliances
    
- Cameras
    
- IoT Devices
    

---

## Why They're Dangerous

Default credentials are publicly documented.

Anyone can search them online.

Example:

```
admin
admin
```

or

```
root
password
```

---

## HTB Example

Install the cheat sheet:

```bash
pip3 install defaultcreds-cheat-sheet
```

Search:

```bash
creds search linksys
```

Example output:

```
admin : admin

admin :

Administrator : admin

root : admin

admin : password
```

---

## Common Sources

- Product documentation
    
- Vendor websites
    
- GitHub
    
- Security cheat sheets
    
- Installation manuals
    

---

## Hydra with Default Credentials

Create:

```
admin:admin
root:root
admin:password
```

Save as:

```
defaults.txt
```

Then test (only on systems you are authorized to assess):

```bash
hydra -C defaults.txt ssh://TARGET
```

---

# Common Router Default Credentials

|Brand|Default IP|Username|Password|
|---|---|---|---|
|3Com|[http://192.168.1.1](http://192.168.1.1)|admin|Admin|
|Belkin|[http://192.168.2.1](http://192.168.2.1)|admin|admin|
|BenQ|[http://192.168.1.1](http://192.168.1.1)|admin|Admin|
|D-Link|[http://192.168.0.1](http://192.168.0.1)|admin|Admin|
|Digicom|[http://192.168.1.254](http://192.168.1.254)|admin|Michelangelo|
|Linksys|[http://192.168.1.1](http://192.168.1.1)|admin|Admin|
|Netgear|[http://192.168.0.1](http://192.168.0.1)|admin|password|

---

# Key Differences

|Feature|Password Spraying|Credential Stuffing|Default Credentials|
|---|---|---|---|
|Uses guessed password|✔|❌|❌|
|Uses leaked passwords|❌|✔|❌|
|Uses vendor defaults|❌|❌|✔|
|One password for many users|✔|❌|❌|
|Username/password pairs|❌|✔|✔ (known defaults)|

---

# HTB Commands (Keep These)

### Password Spraying

```bash
netexec smb 10.100.38.0/24 -u usernames.list -p 'ChangeMe123!'
```

---

### Credential Stuffing

```bash
hydra -C user_pass.list ssh://10.100.38.23
```

---

### Install Default Credential Cheat Sheet

```bash
pip3 install defaultcreds-cheat-sheet
```

---

### Search Default Credentials

```bash
creds search linksys
```

---

# Exam Tips ⭐

- **Password Spraying** = **One Password → Many Users**
    
- **Credential Stuffing** = **Many Username:Password Pairs → Many Services**
    
- **Default Credentials** = **Vendor's Factory Username & Password**
    
- **Hydra** is commonly used for testing username/password pairs against supported services.
    
- **NetExec** is commonly used for SMB authentication testing in Windows/Active Directory environments.
    
- **Burp Suite** is commonly used for web login testing.
    
- **Kerbrute** is commonly used for Kerberos username enumeration and password spraying in Active Directory.
    
- Always conduct these techniques **only on systems you own or are explicitly authorized to test**, such as HTB labs or approved penetration tests.