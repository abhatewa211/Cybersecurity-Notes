# 1. Windows Authentication Overview

![Image](https://images.openai.com/static-rsc-4/0gP7Jf3aizFwXSwp6-caf2LxlmgG-SCEdbeVHwHwMg__9eHpIRK8KzSerHNs6YBCh4dqGST5XcKMTi-X2vq06km6IXeJWz_oUk4y414bXRmuthPnQrH71j2HBkchAOHN8xnwWksrI3W0qGy3jX8L5lXlVRCeGi0Ns1J7xETLI0zGy1SaqE8QZXzzrAYcS_PJ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/RwSIwXg9BD3n-cV6koJGMef7uu9Eqa2bYYcDZxHiG8UYgX2GkQspkRbFZxjLCENte7X3ck4MFyM17-p8WU3RwkNT_dt3NSY1dZDrimbK03mTQcokiUCbNSo-oF6B7PPBjKRz_74ARNVuVw2HUdSpqLWv4LDY4LCeg0E3Wm_r66CApCr32qaQwXW7VhQs9QSo?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/JuAWQCEJ--PntzOR7qEesjpVOyWmMklAekVQS_qSz7mC11r82H6lxqSoiJonmqXnzbpxgcqrWrXTWGH1-4RLLJgWbldru8XJH6iP-yQkKWo_WLkENk8mff4JVAvzAMXiwtpvoHsoq9U_Q_6TL84j4uhDeHH-tNUrQEGfT8e7DFXwbZG7QJhdPhftape9NZFM?purpose=fullsize)

## What is Windows Authentication?

Windows Authentication is the process used by Windows to verify the identity of a user before granting access to the operating system or network resources.

It involves several Windows components working together:

- **WinLogon**
    
- **LogonUI**
    
- **Credential Providers**
    
- **LSASS**
    
- **Authentication Packages**
    
- **SAM Database**
    
- **Active Directory (NTDS.dit)**
    

---

## High-Level Authentication Flow

```
User
   │
   ▼
Keyboard Input
   │
   ▼
WinLogon.exe
   │
   ▼
LogonUI.exe
   │
   ▼
Credential Provider
   │
   ▼
LSASS.exe
   │
   ├────────► Kerberos.dll
   │
   ├────────► Msv1_0.dll
   │
   └────────► NTLM
   │
   ▼
SAM Database (Local Computer)
        OR
Active Directory (NTDS.dit)
   │
   ▼
Authentication Result
   │
   ▼
Desktop Access
```

---

# 2. Local Security Authority (LSA)

## Definition

The **Local Security Authority (LSA)** is a protected Windows subsystem responsible for:

- Authenticating users
    
- Managing local logons
    
- Enforcing security policies
    
- Translating usernames into **Security Identifiers (SIDs)**
    
- Managing access control
    
- Generating security audit logs
    

Think of LSA as the **security manager of Windows**.

---

## Responsibilities

✔ User Authentication

✔ Local Security Policy

✔ Access Control

✔ Permission Checks

✔ Security Auditing

✔ SID Management

---

## Important

On a:

### Standalone Computer

LSA checks the **local SAM database**.

### Domain Computer

LSA contacts the **Domain Controller** and verifies credentials against **Active Directory (NTDS.dit)**.

---

# 3. Windows Authentication Components

## Main Components

|Component|Purpose|
|---|---|
|WinLogon|Handles login process|
|LogonUI|Login screen|
|Credential Provider|Collects username/password|
|LSASS|Performs authentication|
|Authentication Package|Validates credentials|
|SAM|Local account database|
|Active Directory|Domain account database|

---

# 4. WinLogon.exe

![Image](https://images.openai.com/static-rsc-4/dzqy5zVSBYm5_5oZ0rVmfAWMdyKtXX8wBVT9oSFFWY2cYdT6recuUolaaoG41CijtTCEPD2SjbAWYY2SEe0YB3YENYArMPrY0IOhX1-PikIyzxoDPSO9uhvWKtnUdf9F2ui1O86IiIfnEZDTUonwlBKCb2hHdJ5KsqG-M7LyQfM4o_DzPqwiK29INVHz344w?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/00wPaa_tgkNzMfU6ocI3cNIV23SxJ8afG_1efjBeoBYDQoT6220Yci3qv5Yatg7Fc2BS4kfgF-MHns_kQVvQ68Nu00pHpKCmc7BiOulhrE0nDdeCBNGhh3cvLn5V_Y4H0dSNOf_LekAA09pu394kofyK1koTmVKXZnhNoZoTwSf_hWlSgnPGmsxyu3bzuMWu?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/aoa7eB17Yg9I9V1u_jv0NIsDIzVuYN1aHDoc-Pwu6upQZCz17LvOOo13K-jeMexJiTuetwfXkknbSanmApOlsh3HtmQsw10AsPo_mw2mDu8PRXwmBIj0fEtJLS2znptWfIU0p2GIuXghCJdbiJbs53QfzMwMsHoPC4PwgquPZthAcQF3Ima4VkWkpT7uQaGX?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/2KLiYXD0fA5Cp5_bLf3jDFrHFij1rgHgau5qp238nyfQFf_AaOwbKHhVXI99AAX53RskyAbCunHapbG3-oY4kKg1N8RMJdjVWLshd9lNhZXB9HF_ok7t_J3Mb56AZnupuG_DHoYGRREJ7-Az28cuu7uZBdfFd0olygs8T2pt2wWZiKVGEuey0agStkdihKql?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/436v-EKTUWuSyPyQVQSBFNv_oWicqdcw5K1vEqEop0g-BXY28fufDdDMJ2dkwbzSEC7O7MJmZW32bBrZlWSaIwMIYsaChA3DT9ju5HymzgoAhl-cbaPc9ZSBduAY9_ESvtVgfASUbmVSQnK711mvgQOsepzIizsrVgm7JekSa9FdSjblaqD_js97NDLzTNA9?purpose=fullsize)

## Definition

**WinLogon** is a trusted Windows process responsible for managing secure user logons.

It is the **only process** that receives keyboard login requests.

---

## Responsibilities

- Launches **LogonUI**
    
- Handles password changes
    
- Locks workstation
    
- Unlocks workstation
    
- Sends credentials to LSASS
    

---

## Login Flow

```
User presses Ctrl+Alt+Del
        │
        ▼
WinLogon
        │
        ▼
Starts LogonUI
        │
        ▼
Credential Provider
        │
        ▼
Collect Username + Password
        │
        ▼
Pass credentials to LSASS
```

---

## Important

WinLogon receives login requests through:

```
Win32k.sys
```

using

```
RPC Messages
```

---

# 5. LogonUI.exe

## Definition

LogonUI provides the graphical login interface.

It displays:

- Username box
    
- Password box
    
- PIN login
    
- Windows Hello
    
- Smart Card login
    

It **does not authenticate users**.

It only collects credentials.

---

# 6. Credential Providers

## Definition

Credential Providers are **COM Objects (DLLs)** that collect authentication information from users.

Examples:

- Password login
    
- PIN
    
- Fingerprint
    
- Smart Card
    
- Face Recognition
    

---

## Process

```
User Types Password

↓

Credential Provider

↓

WinLogon

↓

LSASS
```

---

# 7. LSASS.exe

![Image](https://images.openai.com/static-rsc-4/E8KG-PIMt7DeJ7kW3bY0w5xSuJvCUn29fTGqor18AQAHzFEZR4nCk4qTUzOEdbwLfQ2-ZX1pOVcZzkFRKO0SJF-qW3fYTXH4UsMDK2ttBoaENfTPMW0Ug2WEz-LFxZm6G3qY_kKqUVwklnAqdkzV9_huc_itkkcxwQLrrhfyqzVwmtvHG804IIixyFiJYusa?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/7aI7KVF96Rzsb1Vl5CG6ilguUSFTZP94fZ4u3F3T-cktaxivFm9mwx77QoQI7XkW9n65tsXn7us-R6vRxxfXQ9__PheSPYrpSBn-nZebC49o9kqTUCLjOGYFWA0h2lBbXpb_P4K4Jz7oU1hbNoSb75EZjmzKEhZdhz1CKm45vZSNX0vj-pFg2l9pbGCDFe1q?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/436v-EKTUWuSyPyQVQSBFNv_oWicqdcw5K1vEqEop0g-BXY28fufDdDMJ2dkwbzSEC7O7MJmZW32bBrZlWSaIwMIYsaChA3DT9ju5HymzgoAhl-cbaPc9ZSBduAY9_ESvtVgfASUbmVSQnK711mvgQOsepzIizsrVgm7JekSa9FdSjblaqD_js97NDLzTNA9?purpose=fullsize)

## Definition

LSASS stands for

> **Local Security Authority Subsystem Service**

Location:

```
%SystemRoot%\System32\lsass.exe
```

LSASS is one of the most important Windows processes.

It controls:

- Authentication
    
- Security policies
    
- Access tokens
    
- Password verification
    
- Audit logs
    

---

## Why Attackers Target LSASS

LSASS stores authentication material in memory.

It may contain:

- NTLM hashes
    
- Kerberos tickets
    
- Plaintext passwords (depending on configuration)
    
- Cached credentials
    

Because of this, tools like **Mimikatz** often target LSASS (only in authorized security testing).

---

## LSASS Authentication Flow

```
Credential Provider
        │
        ▼
WinLogon
        │
        ▼
LSASS
        │
 ┌──────┼───────────┐
 │      │           │
 ▼      ▼           ▼
NTLM  Kerberos   Local SAM
```

---

# 8. Authentication Packages

Authentication Packages are DLLs loaded by LSASS to perform authentication.

## 8.1 Lsasrv.dll

### Purpose

- Security Package Manager
    
- Enforces security policies
    
- Chooses authentication protocol
    

It contains:

```
Negotiate()
```

which selects:

- Kerberos
    
- NTLM
    

depending on the situation.

---

## 8.2 Msv1_0.dll

Purpose:

Authentication package used for:

- Local logons
    
- Non-domain systems
    
- NTLM authentication
    

---

## 8.3 Samsrv.dll

Purpose:

Manages the

**Security Accounts Manager (SAM)**

Functions:

- Stores local accounts
    
- Stores password hashes
    
- Applies local security policies
    

---

## 8.4 Kerberos.dll

Purpose:

Provides

**Kerberos Authentication**

Used when computer belongs to a Windows Domain.

---

## 8.5 Netlogon.dll

Purpose:

Network authentication service.

Communicates with:

- Domain Controllers
    
- Active Directory
    

---

## 8.6 Ntdsa.dll

Only loaded on:

✔ Domain Controllers

Responsible for:

- Managing NTDS.dit
    
- LDAP Queries
    
- Active Directory Replication
    

---

# Authentication Package Summary

|DLL|Function|
|---|---|
|Lsasrv.dll|Security manager, chooses NTLM/Kerberos|
|Msv1_0.dll|Local authentication|
|Samsrv.dll|Local SAM database|
|Kerberos.dll|Kerberos authentication|
|Netlogon.dll|Domain communication|
|Ntdsa.dll|Active Directory database management|

---

# 9. Security Account Manager (SAM)

![Image](https://images.openai.com/static-rsc-4/436v-EKTUWuSyPyQVQSBFNv_oWicqdcw5K1vEqEop0g-BXY28fufDdDMJ2dkwbzSEC7O7MJmZW32bBrZlWSaIwMIYsaChA3DT9ju5HymzgoAhl-cbaPc9ZSBduAY9_ESvtVgfASUbmVSQnK711mvgQOsepzIizsrVgm7JekSa9FdSjblaqD_js97NDLzTNA9?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ilNEgjR9bHhyZLQdHEElUFIWuykjB3EDLgXisBMHkjRD9waKgyOYL5fIhlH_nDfTyvNaORV_9sUpLkEpVgx5evGbTHhVLW0RBkz-uOlvyzBGpvHuRVDNcQWqzYmYFR66JlPyYBby2DvmORqQ4FNIQG-mj5GVNqZrj-qbwyDMnKH3mDiwW0Os3g2PV8J4YGym?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/0LLfeHGfJaEA08R_4QtIBvPT3__ZYv5iRlV9JrBolVDJNylKX239hAKVPJZd6KKQ_y3xwywmk7uxpmHZcXjke-R7jJPcBhDCcfpzfbwJrU-dcsgLO3GCK0dSyA_RE432zNIBq_SJHVOHQtlBd3WV2Ril8sZOKcSgGiYx3qLO4cc1f-BKdQ0Bkh67NvpPOgVI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/5xwnrHdWt5Uv9W2LexU0c2V55FFZHKj3_fbo833BlZAhwETNiAQXvnMbUfySqEKXqFq1mzORyylmrSqrdm3gYL--JFf0SQzXH4Z2qDJtT8U8RWBgCcfxy2yN2MltcGIQlW_CHAgMh4NBu51-8G9g2w1puO-bFeRW-yaSNpM3KqKlXbIEmwRMCMWa1y6tzmZ2?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/49ZKy0emHcBLnGJGzGVy8b_lV5maUPZvWQm2ZZMppO1fTapg9H21sIeC9F2IdJSquvc5YHQLzLG9ATnIfm0_vsDe0gs5SXoSrIM9YUWVVYOQQeowLoNK8AFS4K1KEiSvmfIWud-cJWBkw_pvXTjJeF3JiIDKPMEmWVjMIvTnhwjS_jpVUt7RIRqW9kCMXFYn?purpose=fullsize)

## Definition

SAM stands for

**Security Account Manager**

It stores:

- Local usernames
    
- Password hashes
    
- Security policies
    

---

## Location

```
%SystemRoot%\System32\Config\SAM
```

Registry Location

```
HKLM\SAM
```

---

## Access Requirement

Viewing SAM requires:

```
SYSTEM Privileges
```

---

## What Does SAM Store?

- Usernames
    
- LM Hashes
    
- NTLM Hashes
    
- Local Groups
    

Passwords are **not** stored in plaintext.

---

## Local Computer Authentication

```
User Login

↓

LSASS

↓

SAM

↓

Hash Comparison

↓

Access Granted
```

---

# 10. LM vs NTLM Hashes

|LM Hash|NTLM Hash|
|---|---|
|Old|Modern|
|Weak|Stronger|
|Uppercase only|Case-sensitive|
|Easily cracked|More secure|

Modern Windows primarily uses **NTLM hashes**.

---

# 11. Workgroup vs Domain

## Workgroup

Authentication:

```
Computer

↓

Local SAM
```

Everything is stored locally.

---

## Domain

Authentication:

```
Computer

↓

Domain Controller

↓

NTDS.dit
```

Centralized authentication.

---

# 12. SYSKEY

## Definition

Microsoft introduced

```
SYSKEY
```

in

Windows NT 4.0

Purpose:

Encrypt SAM database on disk.

It encrypts password hashes using a system-generated key to make offline cracking more difficult.

---

# 13. Credential Manager

![Image](https://images.openai.com/static-rsc-4/tVJO2MCosSKrEFM17sQ3FnlyxtwNSseugAuLTuJw6CRe71YJmBkYEHo_o3qiGb7qYuqaCQWmn4v9uCUS2GJFsLOc6wvggehX5A120A07u1X6ByFTY2Jx6t4g7eO4J9Sqicqco_kKp38eMkBkBpxnrDQ7lByIZ_XHO327aIPa86jM64Yi7E5vusr-geYpXlOp?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/4tVI4MLF_Ogx8JGnEM92Y0_w2AnCETGzE167dRHbdGCdm9RPBZO6KHYAE_I8N66FByN7WlsJahHnTWwo-bQ2AmPmHr3F4Eru4VYzMZb8M2B-dkULXsCXj8lkDYxFWke9bVATlbpmzaMOZlF86NHDWFL5Mbq1tv4P_79k-HsZi7aHQIY3pV1gDKT9dEeMzXL4?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/SWFTa1mOh-2drj_poUxCIydX9fxOTou0H96ge0rZDnRJPtRCNn1Zh7Aos299Po2XJWaVT3gYdfxSa5AH5id794wFARS3x1TdrtgBfJ3gp6_3-ax95Htx5WIEcCIn9hcVU6saGCqve1BZNhapcgaWDcSgbglKNp7hhbKkmV1B34RSjocd_wnqurq2NHfblCUy?purpose=fullsize)

## Definition

Credential Manager stores credentials for:

- Websites
    
- Network Shares
    
- Remote Desktop
    
- Applications
    
- VPNs
    

---

## Storage Location

```
C:\Users\<Username>\AppData\Local\Microsoft\
```

Inside:

```
Vault
```

or

```
Credentials
```

---

## Credentials Are

✔ Per User

✔ Encrypted

✔ Stored in Credential Locker

---

## Examples

Saved:

```
RDP Password

Wi-Fi Password

VPN Password

Website Password
```

---

# 14. NTDS.dit

![Image](https://images.openai.com/static-rsc-4/rCPKxwR6D9vE3Q8h3NvAfl21o28t-Dt0MEZ54WPiQxQ76ui5jlxvVF_z0hSlxkUiBk9o1u4cUuYaGedPV_2DQUqakwsKTNXJfmMNcGnxsFKP_Xcr9DSkiFsboHKPTftSrHNtrh-WNnvbLgDlmPLK6ooMp3AYtYDRlyE3pSPhNljTmNyeEGksGT4jawGQk3hC?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/lO4ZfieG4XXpVUqHzDfDpfidva36ecgeusIsB9wl0FR5Qbkkbaq8gn8NZjBokF5WISuuCANKrEOAvIsSRVjI-kDxIAW_fXlzrjQ69-fUYMWFjMnZNNhT13CU56atHauxFc4tOrwjpoHUeuTDMy4lD9IoZsjn2lCMxDfIWP3-pVVRMbSfezcWYigt9CnggCDd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/JuAWQCEJ--PntzOR7qEesjpVOyWmMklAekVQS_qSz7mC11r82H6lxqSoiJonmqXnzbpxgcqrWrXTWGH1-4RLLJgWbldru8XJH6iP-yQkKWo_WLkENk8mff4JVAvzAMXiwtpvoHsoq9U_Q_6TL84j4uhDeHH-tNUrQEGfT8e7DFXwbZG7QJhdPhftape9NZFM?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ZWSxQVznfNypTp6-NeuMQORFkDn7Xmm_c7oQveMWkXNDUFU5D-O9e5Of5X2KJ3INhpDdqtbu61JyWNJ7paozh-0qwPiUon1VRg_FW5OYp-aPTfgkHCn-oHcNEhClvbENlIFgMHE5hJe5Gu6TIYv4S9zI3f4Ng7AQXYKeyIbP3fNDmkzKeX_HrtkFOS9MFwKp?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/mbe9VEnOl6DDnkR19bDJbLo24oHYU_Cmekv2JpnqGkUn2YIFLx_3PS1TC9YNEmoPPifm_UMdWKvHsC5l4ZFBVZefzTn29EWFRmDvUxv9nxIqBmApat4ywFbieUkTpGIwh8I856vwtjhN4-TD9X8YLb77ICNaVSWwGWpQ61RMZKuob2Thrv5HWeb5W7xER05C?purpose=fullsize)

## Definition

NTDS.dit is the main database of **Active Directory**.

Every Domain Controller stores a copy.

(Except **Read-Only Domain Controllers (RODCs)**.)

---

## Location

```
%SystemRoot%\NTDS\NTDS.dit
```

---

## What Does NTDS.dit Store?

- User Accounts
    
- Password Hashes
    
- Computer Accounts
    
- Group Accounts
    
- Organizational Units (OUs)
    
- Group Policy Objects (GPOs)
    

---

## Domain Authentication

```
User Login

↓

Computer

↓

Domain Controller

↓

NTDS.dit

↓

Password Hash Verification

↓

Authentication Successful
```

---

# SAM vs NTDS.dit

|SAM|NTDS.dit|
|---|---|
|Local Computer|Domain Controller|
|Local Users|Domain Users|
|Local Password Hashes|Entire Domain Hashes|
|Workgroup|Active Directory|

---

# Overall Windows Authentication Process

```
User
      │
      ▼
WinLogon
      │
      ▼
LogonUI
      │
      ▼
Credential Provider
      │
      ▼
LSASS
      │
 ┌────┴────────────┐
 │                 │
 ▼                 ▼
Local SAM      Active Directory
                    │
                    ▼
                 NTDS.dit
                    │
                    ▼
           Authentication Result
                    │
                    ▼
             Desktop Access
```

---

# Important File Locations

|Item|Location|
|---|---|
|LSASS|`%SystemRoot%\System32\lsass.exe`|
|SAM|`%SystemRoot%\System32\Config\SAM`|
|SAM Registry|`HKLM\SAM`|
|Credential Manager|`C:\Users\<Username>\AppData\Local\Microsoft\Vault` or `Credentials`|
|Active Directory Database|`%SystemRoot%\NTDS\NTDS.dit`|

---

# HTB / Exam Tips ⭐

- **LSASS** is the central Windows authentication service and enforces security policies.
    
- **WinLogon** launches **LogonUI**, receives credentials from the **Credential Provider**, and forwards them to **LSASS**.
    
- **LSASS** uses authentication packages such as **Kerberos.dll** (domain authentication) and **Msv1_0.dll** (local/NTLM authentication).
    
- **SAM** stores **local** account password hashes and requires **SYSTEM** privileges to access.
    
- **NTDS.dit** stores **Active Directory** data for an entire domain, including user and computer accounts, groups, GPOs, and password hashes.
    
- **Credential Manager** stores **per-user encrypted credentials** in the user's profile.
    
- **Workgroup** systems authenticate against the **local SAM**, while **domain-joined** systems authenticate through a **Domain Controller** using **NTDS.dit**.
    
- **SYSKEY** was introduced to add encryption protection to the SAM database against offline attacks.