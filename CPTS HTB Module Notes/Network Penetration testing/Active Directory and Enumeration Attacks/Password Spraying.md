## 1. What is Password Spraying?

**Password spraying** is an authentication attack where an attacker attempts to log in to **many different user accounts using one common password**, rather than trying many passwords against a single account.

### Basic idea

```text
              ONE COMMON PASSWORD
                     │
        ┌────────────┼────────────┐
        ↓            ↓            ↓
     User 1       User 2       User 3
        │            │            │
     Login         Login         Login
        │            │            │
        ↓            ↓            ↓
     Failed?       SUCCESS!      Failed?
```

The goal is to identify accounts where a weak, reused, or commonly used password has been accepted.

### Password Spraying vs. Brute Force

|Technique|Approach|
|---|---|
|**Brute Force**|Many passwords → one username|
|**Password Spraying**|One password → many usernames|
|**Credential Stuffing**|Previously leaked username/password pairs → target service|

Password spraying is generally more measured than brute forcing because it sends **fewer authentication attempts against each individual account**.

---

# 2. Why Password Spraying Is Useful in Penetration Testing

Password spraying can potentially provide:

- Initial access to a system
    
- A foothold inside a network
    
- Access to internal services
    
- Credentials for low-privileged accounts
    
- Information that can lead to further enumeration
    
- Opportunities for lateral movement
    

A penetration test is **not static**. Testers continuously iterate through techniques as new information becomes available.

For example:

```text
OSINT
  ↓
Username discovery
  ↓
Service enumeration
  ↓
Valid-user enumeration
  ↓
Password spraying
  ↓
Valid credentials
  ↓
Initial foothold
  ↓
Further enumeration
  ↓
Additional attack paths
```

The module emphasizes that penetration testers often perform **multiple TTPs simultaneously** to use their time effectively, especially because assessments are normally **time-boxed**.

---

# 3. Building a Target Username List

A successful password spray depends heavily on having a useful **username/email list**.

Potential sources include:

### OSINT

Information gathered from publicly available sources:

- Company websites
    
- Search engines
    
- LinkedIn
    
- Public documents
    
- Published PDFs
    
- Document metadata
    

### Internal Enumeration

Depending on the environment and authorization:

- LDAP enumeration
    
- SMB enumeration
    
- Kerberos user enumeration
    
- Other service enumeration
    

### Important Concept

The larger and more accurate the valid-user list, the greater the opportunity to identify an account using a weak/common password.

---

# 4. Story Time — Scenario 1

The first scenario describes an internal assessment where standard checks did **not** reveal useful information such as:

- SMB NULL sessions
    
- LDAP anonymous bind
    

Because a valid username list wasn't readily available, the tester used **Kerbrute** to enumerate valid domain users.

### Username-list construction

The tester combined:

```text
statistically-likely-usernames
             +
LinkedIn scraping results
             ↓
      Combined username list
             ↓
          Kerbrute
             ↓
      Valid domain users
```

The username list referenced in the module is:

**`jsmith.txt`**

from the `statistically-likely-usernames` repository.

After enumerating valid users, the tester performed password spraying using:

```text
Welcome1
```

The spray resulted in two valid accounts belonging to low-privileged users.

Although the privileges were limited, access was sufficient to run **BloodHound** and identify attack paths that eventually led to domain compromise.

### Key lesson

A low-privileged account can still be valuable because it may provide access to information that exposes additional attack paths.

---

# 5. Story Time — Scenario 2

The second scenario involved another environment where common username lists and LinkedIn results didn't produce useful results.

The tester then searched Google for **PDF documents published by the organization**.

The documents revealed an interesting detail through their metadata.

### Username format discovered

The internal usernames followed a four-character format:

```text
F9L8
```

The characters were generated from:

```text
A-Z
0-9
```

The information was found in the PDF **Author** field.

This demonstrates why organizations should properly **scrub document metadata** before publishing documents online.

---

# 6. Generating Username Combinations

The module provides this Bash script:

```bash
#!/bin/bash

for x in {{A..Z},{0..9}}{{A..Z},{0..9}}{{A..Z},{0..9}}{{A..Z},{0..9}}
    do echo $x;
done
```

This generates possible four-character combinations using:

```text
A-Z
+
0-9
```

The module states that this produces:

**1,679,616 possible username combinations.**

The generated list can then be used with **Kerbrute** to enumerate valid domain accounts.

### Attack-chain concept

```text
PDF metadata
     ↓
Username format discovered
     ↓
Generate possible usernames
     ↓
Kerbrute
     ↓
Valid domain accounts
     ↓
Large target list
     ↓
Password spraying
```

The important lesson is that attempting to make username enumeration difficult through a predictable format can still expose a large number of accounts when combined with publicly available information.

---

# 7. Why Username Enumeration Matters

The module gives an important comparison:

A common username list such as `jsmith.txt` may identify approximately **40–60%** of valid accounts in some situations.

However, discovering the organization's username-generation pattern can significantly increase the number of accounts available for testing.

### Example

```text
Generic username list
        ↓
Maybe 40–60% discovered

Known username-generation pattern
        ↓
Generate possible accounts
        ↓
Potentially enumerate a much larger portion
```

This makes username-generation conventions an important part of reconnaissance.

---

# 8. Password Spraying Considerations

Password spraying can be effective, but **careless spraying can cause account lockouts**.

This is one of the most important sections of the module.

### Brute Force

Example:

```text
bob.smith
   ↓
Password1
Password2
Password3
Password4
Password5
...
```

This produces many failed authentication attempts against **one account**.

### Password Spray

Instead:

```text
Welcome1
   ↓
bob.smith
john.doe
jane.doe
alice.smith
...
```

The same password is tested across many accounts.

---

# 9. Password Spray Visualization

The module's example:

|Attack|Username|Password|
|---|---|---|
|1|[bob.smith@inlanefreight.local](mailto:bob.smith@inlanefreight.local)|`Welcome1`|
|1|[john.doe@inlanefreight.local](mailto:john.doe@inlanefreight.local)|`Welcome1`|
|1|[jane.doe@inlanefreight.local](mailto:jane.doe@inlanefreight.local)|`Welcome1`|
|**DELAY**|||
|2|[bob.smith@inlanefreight.local](mailto:bob.smith@inlanefreight.local)|`Passw0rd`|
|2|[john.doe@inlanefreight.local](mailto:john.doe@inlanefreight.local)|`Passw0rd`|
|2|[jane.doe@inlanefreight.local](mailto:jane.doe@inlanefreight.local)|`Passw0rd`|
|**DELAY**|||
|3|[bob.smith@inlanefreight.local](mailto:bob.smith@inlanefreight.local)|`Winter2022`|
|3|[john.doe@inlanefreight.local](mailto:john.doe@inlanefreight.local)|`Winter2022`|
|3|[jane.doe@inlanefreight.local](mailto:jane.doe@inlanefreight.local)|`Winter2022`|

The key pattern is:

```text
Password 1
   ↓
All usernames
   ↓
DELAY
   ↓
Password 2
   ↓
All usernames
   ↓
DELAY
   ↓
Password 3
   ↓
All usernames
```

The **delay is important** because it reduces the likelihood of triggering account-lockout policies.

---

# 10. Account Lockout Risk

Password spraying is **not risk-free**.

An organization might have a policy such as:

```text
5 failed attempts
       ↓
Account locked
       ↓
30-minute automatic unlock
```

Some organizations may have stricter policies where:

```text
Failed attempts
      ↓
Account locked
      ↓
Administrator intervention required
```

Therefore, blindly spraying passwords can potentially lock out many legitimate users.

---

# 11. Password Policy

Before performing password spraying during an authorized assessment, understanding the organization's password policy is extremely valuable.

Things to determine include:

- Number of failed attempts before lockout
    
- Lockout duration
    
- Whether the account automatically unlocks
    
- Whether administrator intervention is required
    
- Whether different account types have different policies
    

### Ideal workflow

```text
Obtain password policy
        ↓
Understand lockout threshold
        ↓
Determine safe testing rate
        ↓
Build target list
        ↓
Select common password
        ↓
Perform controlled spray
        ↓
Wait according to policy
        ↓
Continue if authorized
```

---

# 12. If the Password Policy Is Unknown

The module recommends being cautious when the password policy cannot be determined.

A tester may choose to:

- Make a single targeted password-spraying attempt.
    
- Use a weak/common password.
    
- Introduce a substantial delay.
    
- Ask the client to clarify the password policy.
    
- Avoid unnecessary authentication attempts.
    

The module describes a single targeted attempt as a possible **"hail mary"** when other foothold options have been exhausted.

---

# 13. Internal Password Spraying

Password spraying isn't limited to obtaining initial access.

If you already have a foothold, password spraying can potentially assist with:

```text
Existing account
      ↓
Internal enumeration
      ↓
Additional usernames
      ↓
Password spraying
      ↓
Another valid account
      ↓
Lateral movement
```

However, **account-lockout considerations still apply**.

The module notes that with internal access, it may be possible to obtain the organization's password policy, which can significantly reduce the risk of accidental lockouts.

---

# 14. Important Tools Mentioned

## Kerbrute

Used in the scenarios to:

- Enumerate valid domain users
    
- Build a list of valid accounts
    
- Perform password spraying
    

---

## BloodHound

Used after obtaining access to identify relationships and potential attack paths within an Active Directory environment.

Conceptually:

```text
Valid credentials
       ↓
BloodHound
       ↓
AD relationships
       ↓
Attack paths
       ↓
Potential privilege escalation
```

---

# 15. RBCD and Shadow Credentials

The scenarios mention two advanced Active Directory attack concepts:

### Resource-Based Constrained Delegation (RBCD)

RBCD is an Active Directory delegation mechanism that can become part of an attack chain when an attacker gains the appropriate permissions or control over relevant computer objects.

### Shadow Credentials

Shadow Credentials involve abusing attributes associated with authentication mechanisms to establish an alternative authentication path when the attacker has the necessary permissions.

The module's Scenario 2 describes these techniques as later stages of a larger attack chain rather than as the initial password-spraying technique.

---

# 16. Most Important Concepts to Remember

### 🔴 1. Password spraying ≠ brute force

**Brute force:**

```text
Many passwords → One account
```

**Password spraying:**

```text
One password → Many accounts
```

---

### 🔴 2. Username enumeration is extremely important

A good username list increases the effectiveness of the spray.

Potential sources include:

```text
OSINT
LinkedIn
Public documents
PDF metadata
Internal enumeration
Kerbrute
```

---

### 🔴 3. Document metadata can leak information

The module's second scenario demonstrates that PDF metadata can reveal organizational information such as username formats.

```text
Public PDF
    ↓
Metadata
    ↓
Author field
    ↓
Username format
    ↓
Generate usernames
```

---

### 🔴 4. Account lockouts are the major operational risk

Never blindly spray large numbers of credentials.

Know:

```text
Lockout threshold
Lockout duration
Password policy
```

when possible.

---

### 🔴 5. Delays matter

The module repeatedly emphasizes introducing a **delay between attempts**.

```text
Users → Password
       ↓
     DELAY
       ↓
Users → Next password
```

---

### 🔴 6. A low-privileged account can still be valuable

The Scenario 1 example demonstrates:

```text
Password spray
      ↓
Low-privileged account
      ↓
BloodHound
      ↓
Attack paths
      ↓
Further compromise
```

So obtaining a low-privileged account does not necessarily mean the attack has reached a dead end.

---

# 17. Mentor Cheat Sheet

|Concept|Remember|
|---|---|
|**Password Spraying**|One common password → many accounts|
|**Brute Force**|Many passwords → one account|
|**Target list**|Usernames/emails|
|**OSINT**|Useful source for usernames|
|**LinkedIn**|Can help identify naming patterns|
|**PDF metadata**|May expose username information|
|**Kerbrute**|User enumeration + spraying in the module|
|**BloodHound**|Identify AD relationships/attack paths|
|**Common password**|Example: `Welcome1`|
|**Delay**|Helps reduce lockout risk|
|**Lockout threshold**|Critical before spraying|
|**Internal spraying**|Can potentially support lateral movement|
|**RBCD**|Advanced AD attack-chain technique mentioned|
|**Shadow Credentials**|Advanced AD attack-chain technique mentioned|

---

## 18. The Core Mental Model

Keep this workflow in your head:

```text
                 RECON
                   │
                   ▼
          Find usernames/emails
                   │
                   ▼
          Validate user accounts
                   │
                   ▼
        Understand password policy
                   │
                   ▼
       Choose controlled password
                   │
                   ▼
          PASSWORD SPRAY
                   │
            ┌──────┴──────┐
            ▼             ▼
          Failed        Valid
            │             │
            │             ▼
            │       Initial foothold
            │             │
            │             ▼
            │        Enumeration
            │             │
            │             ▼
            │       BloodHound / AD
            │             │
            └─────────────┘
```

### 🧠 Mentor takeaway

The biggest lesson from this module isn't simply **"run a password-spraying tool."** The important skill is understanding the entire process: **build a quality username list → understand the lockout policy → make controlled authentication attempts → analyze any valid access → use the new information to continue enumeration.**

And remember: the examples and credentials in this module are **lab/assessment examples**; don't apply password spraying to systems or accounts without explicit authorization.