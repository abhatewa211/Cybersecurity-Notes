![Image](https://images.openai.com/static-rsc-4/rPRc1oU0TgXzhI2qdzCJMgbfVSUXe8ewMMFlUOK7XJxtFoQIx-Vm2rhBRzn9us9FLSCbvsmtg8s_-FFkSNkgGsbFZ289P-jCswkiVuwpjDzULSmS8a1nPjhh4ZKKZvQYguS8MfNlBIFtnuLLNP8T3gtR7ULbE1wPDXtzFFu2j4zVSbm3D-_zhsqAAzoKHsyG?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/_iICJwsOLCzSp4qMSAW_crEDx9MElm_nNuvE3Of8dckSobmHW9BLmjhjgTzPGADBDHgFjde22lSJVOZ_3phxJGrvCX3e9cViY1GVIdz1EJgpd8o-SEq2xPV6AHpz2a2ksDAMOn_PcO6yGsicLL2CCHs4uwTPaMUJiwreleQFg9HIIJPGZCT7LcvoGjdPV0jf?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ucTrFzxAANt5nnBnF7Xw-hXFtCKLuhb3l34BLSZ5y76s45vJAzjc8ikjtSBRKF1pyJCB1oE69Hq7vAKZiju6xsPv6fco4Q0ZEaMogUr-ghmsM2WcMBP7PIX8GPCriOUkKZunsXfIR3BFQBI5GYE29ZsxrWdRy9Pi77_PmCTRyoO4TxEPZAY2zP4EFpNVc-g6?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/eoQeyjkBKin0t_KXi-uMHl9rq7zQgN-KGblu4lkhzZ8vK-P-jytybFlRJbHZfRoZKXDz2K3AeyufmWhe0kAu5v7hEAOIr4XLg62z7HQuAzjnG0B7qbMAqPydSv_u9-UgWdIkJnwUrkhsDxZ4bObWQDz0P22A1fifqotBIH8_uDvrgCYznpyIukb1IiqShOXM?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/VyhFVKP80XF307Xjvad2RTyl9C0pbG2soTLwSmbIGPzKWG-MNG_JNrXVO4uLxtNQDR4MmJfxxDPadehQlIgj_CcRAnHygR_UtHJigAkyk45yOeE4Rk8EUu495LW1W7k1AgYCTwq2hwqMGso3Cl_2aCwXZdEE2J9j8t0hRUH_ApBfWWRRLOzyA9Ud7DzmF-FC?purpose=fullsize)

# Part 1 — Hybrid Attacks

## 1. What Is a Hybrid Attack?

A **hybrid attack** combines ideas from:

- **Dictionary attacks**
    
- **Brute-force attacks**
    

Instead of blindly trying every possible password, a hybrid attack starts with **likely words/passwords** and then applies predictable modifications to them.

### Core idea ⭐

```text
Dictionary Word
      +
Predictable Modification
      ↓
New Password Candidate
```

For example:

```text
Summer2023
     ↓
Summer2023!
Summer2024
Summer2025
Summer2023@
Summer2023#
```

The attacker isn't searching the entire universe of possible passwords.

Instead, they're exploiting **patterns in how humans modify passwords**.

---

# 2. Why Password Expiration Can Create Predictable Patterns

Many organizations historically required users to change their passwords periodically.

The intention is:

```text
Old password
     ↓
Password expires
     ↓
New password
     ↓
Better security
```

But users sometimes respond by making only tiny changes:

```text
Summer2023
     ↓
Summer2023!
     ↓
Summer2024
     ↓
Summer2024!
```

The password technically changes, but the underlying pattern remains predictable.

### Important concept

> **Changing a password does not necessarily make it unpredictable.**

---

# 3. The Human Behavior Behind Hybrid Attacks

Suppose a user originally chooses:

```text
Summer2023
```

When forced to change it, they might use:

```text
Summer2023!
```

or:

```text
Summer2024
```

Why?

Because people generally prefer passwords that are:

- Memorable
    
- Familiar
    
- Easy to type
    
- Easy to remember
    

This creates predictable transformations.

---

# 4. Common Password Transformations

Hybrid attacks can target patterns such as:

### Adding a number

```text
password
     ↓
password1
```

### Adding a special character

```text
password
     ↓
password!
```

### Adding both

```text
password
     ↓
password123!
```

### Incrementing a year

```text
Summer2023
     ↓
Summer2024
```

### Capitalization changes

```text
summer
     ↓
Summer
```

### Combining modifications

```text
summer
   ↓
Summer2024!
```

The exact transformations depend on the password behavior being assessed.

---

# 5. Hybrid Attack Workflow

![Image](https://images.openai.com/static-rsc-4/rPRc1oU0TgXzhI2qdzCJMgbfVSUXe8ewMMFlUOK7XJxtFoQIx-Vm2rhBRzn9us9FLSCbvsmtg8s_-FFkSNkgGsbFZ289P-jCswkiVuwpjDzULSmS8a1nPjhh4ZKKZvQYguS8MfNlBIFtnuLLNP8T3gtR7ULbE1wPDXtzFFu2j4zVSbm3D-_zhsqAAzoKHsyG?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/rU9LApniTnPWFu2F5OjQm1b_UOq4nu0cP5EEKJAaj5k_oOgbvgGapIRarOHSzZw7ZhbS8fA1uBVnu0p37YevVntdN95eN3sHCPC_VxUnfAyc_wDXGqGlGV4p9n2-r9D-8hM8_Ug0E0WvVk6Fqewq9v8HWTB6j7Dn9cPWLEx_U_PzLRlJ9OpCGzO9LOPmbP6G?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/aH9hcF2lC0JenDSn03-L_SRaEtdpJnX6B6B7l4ZkVEMaGbF-oBfHdR1SSbwhDGJlpkwey6Nyf1Dpp6p46vtDlJyhLBIyDXICiAtiahPFiRX8XSkaXzgJ6ZkcoeUU0y73TacndQ_MuEs0vvQWeDZ6khYBWRHYT05GoiwK_gjtuwKbTjFS9sjddcqBA9HoTqjr?purpose=fullsize)

The basic process can be visualized as:

```text
                 Target
                   │
                   ↓
             Reconnaissance
                   │
                   ↓
             Build Wordlist
                   │
                   ↓
          Dictionary Attempts
                   │
          ┌────────┴────────┐
          ↓                 ↓
       Success            Failure
          │                 │
          ↓                 ↓
        Stop          Modify Candidates
                            │
                   ┌────────┼────────┐
                   ↓        ↓        ↓
                Numbers  Symbols   Years
                   │        │        │
                   └────────┼────────┘
                            ↓
                     Try Candidates
```

The key idea is that the second phase is **targeted**, rather than completely random.

---

# 6. Why Hybrid Attacks Are Efficient

Suppose a completely random brute-force attack has to search:

```text
1,000,000,000,000 possibilities
```

A dictionary attack might start with:

```text
10,000 likely passwords
```

A hybrid approach might take those 10,000 passwords and generate useful variations.

For example:

```text
10,000 base words
        ↓
+ numbers
+ symbols
+ years
+ capitalization
        ↓
Expanded candidate list
```

This can still be vastly smaller than the complete theoretical search space.

### ⭐ Key principle

> **Hybrid attacks reduce the search space by using knowledge about likely human password behavior.**

---

# 7. Hybrid vs Brute Force vs Dictionary

|Technique|Candidate Generation|Main Strength|
|---|---|---|
|**Brute Force**|Every possible combination|Complete/exhaustive|
|**Dictionary**|Predefined likely passwords|Fast against common passwords|
|**Hybrid**|Dictionary words + modifications|Effective against predictable variations|

### Memory trick

```text
Brute Force
→ Everything

Dictionary
→ Likely words

Hybrid
→ Likely words + modifications
```

---

# 8. When Hybrid Attacks Are Particularly Useful

Hybrid attacks are useful when there is evidence of predictable password patterns.

Examples:

### Organization uses annual password changes

```text
Company2023
Company2024
Company2025
```

### Users add symbols

```text
Password1
Password1!
Password1@
```

### Users append numbers

```text
Summer
Summer1
Summer2
Summer123
```

### Users modify capitalization

```text
summer2026
Summer2026
SUMMER2026
```

---

# 9. Password Policy Example

The provided lab gives an example password policy:

```text
Minimum length: 8 characters

Must contain:
✓ At least one uppercase letter
✓ At least one lowercase letter
✓ At least one number
```

This is important because it gives the tester information about the **candidate search space**.

Instead of blindly using all 10,000 passwords in a wordlist, we can filter the list to identify candidates that satisfy the known policy.

---

# 10. Filtering a Wordlist

The lab uses Linux/Unix command-line tools, especially:

```text
grep
```

and:

```text
regular expressions (regex)
```

The purpose is to filter candidates.

### Overall process

```text
10,000 passwords
       ↓
Minimum length ≥ 8
       ↓
Uppercase required
       ↓
Lowercase required
       ↓
Number required
       ↓
89 candidates
```

This is an excellent demonstration of **search-space reduction**.

---

# 11. Downloading the Wordlist

The lab uses:

```text
darkweb2017_top-10000.txt
```

from SecLists.

The provided command is:

```bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/darkweb2017_top-10000.txt
```

### What does `wget` do?

`wget` downloads a file from a URL.

Conceptually:

```text
Internet
   ↓
Wordlist
   ↓
wget
   ↓
Local file
```

---

# 12. Filter #1 — Minimum Length

The command:

```bash
grep -E '^.{8,}$' darkweb2017_top-10000.txt > darkweb2017-minlength.txt
```

filters the original wordlist.

The regex:

```text
^.{8,}$
```

means:

- `^` → beginning of the line
    
- `.` → any character
    
- `{8,}` → at least 8 occurrences
    
- `$` → end of the line
    

### In simple English:

> Keep passwords that contain **at least 8 characters**.

---

# 13. Filter #2 — Uppercase Letter

Next:

```bash
grep -E '[A-Z]' darkweb2017-minlength.txt > darkweb2017-uppercase.txt
```

The regex:

```text
[A-Z]
```

means:

> Match at least one uppercase English letter.

Examples:

```text
Password123 → ✅
PASSWORD123 → ✅
password123 → ❌
```

The output is saved into:

```text
darkweb2017-uppercase.txt
```

---

# 14. Filter #3 — Lowercase Letter

Next:

```bash
grep -E '[a-z]' darkweb2017-uppercase.txt > darkweb2017-lowercase.txt
```

The regex:

```text
[a-z]
```

requires at least one lowercase letter.

Example:

```text
PASSWORD123 → ❌
Password123 → ✅
```

---

# 15. Filter #4 — Number

Finally:

```bash
grep -E '[0-9]' darkweb2017-lowercase.txt > darkweb2017-number.txt
```

The regex:

```text
[0-9]
```

requires at least one digit.

Examples:

```text
Password → ❌
Password1 → ✅
```

---

# 16. Complete Filtering Chain

The entire process looks like:

```text
darkweb2017_top-10000.txt
             │
             ↓
       ≥ 8 characters
             │
             ↓
       Has uppercase
             │
             ↓
       Has lowercase
             │
             ↓
        Has number
             │
             ↓
  darkweb2017-number.txt
             │
             ↓
        89 passwords
```

---

# 17. Measuring the Result

The command:

```bash
wc -l darkweb2017-number.txt
```

returns:

```text
89 darkweb2017-number.txt
```

`wc -l` counts the number of lines.

Therefore:

```text
Original candidates = 10,000
Filtered candidates = 89
```

That's a massive reduction.

---

# 18. Search-Space Reduction ⭐⭐⭐

This is one of the most important concepts in this section.

The original wordlist contains:

[  
10,000  
]

candidates.

After filtering:

[  
89  
]

candidates remain.

The reduction is:

[  
10,000-89=9,911  
]

So **9,911 candidates were eliminated**.

The remaining proportion is:

[  
\frac{89}{10,000}\times100=0.89%  
]

Only **0.89% of the original list** remains.

### This demonstrates:

> **Knowledge of the target's password policy can dramatically reduce the candidate space.**

---

# 19. Why This Matters for Pentesting

A pentester doesn't necessarily want to throw every possible password at a target.

Instead, they want to make testing:

- Efficient
    
- Focused
    
- Controlled
    
- Relevant to the engagement
    

If the password policy is known, candidate lists can be filtered accordingly.

### Conceptual process

```text
Known policy
     ↓
Filter candidates
     ↓
Smaller wordlist
     ↓
Fewer authentication attempts
     ↓
More efficient testing
```

⚠️ In real environments, authentication testing must stay within the engagement's authorization and rate limits.

---

# 20. Credential Stuffing

The next major concept is **credential stuffing**.

![Image](https://images.openai.com/static-rsc-4/hM83TIzKViQ8nQ49o7NurjFGOaeCuZ9q1lvfZY59POaBKFwp2Hq7DFK-Sm8frKiohb6smGlMAiydyxIIlWzHLJrBuqdaBcaizPj0VQgP1EmcA-53h8oyDjMb-2Ui3Z9PMExtWb1FLLbmJOK6HPSCafyo4ge6j0eIWOmatAa8GrzZrUIp0MXuV2bCXMrqfgE3?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ucTrFzxAANt5nnBnF7Xw-hXFtCKLuhb3l34BLSZ5y76s45vJAzjc8ikjtSBRKF1pyJCB1oE69Hq7vAKZiju6xsPv6fco4Q0ZEaMogUr-ghmsM2WcMBP7PIX8GPCriOUkKZunsXfIR3BFQBI5GYE29ZsxrWdRy9Pi77_PmCTRyoO4TxEPZAY2zP4EFpNVc-g6?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/0vgiBgtethRnFC9kMZ-VU5xOW7AnafqVlQaj8V8QaTf1GiA7ygRz1wPFCjEtQoVqivBwf37diKoVcgdDzF0e2yCpeIii-IN-F52GQazH9Q38tKBd1l2gCK3sH3FjQ2TyPvJQZRdg97-ijNAOgi1g6bjvFDqYBH_64y6EUTi8TIL-RLin8rpENMJ6S8dqclSl?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/NaJEmXSi3zTwxhtMaMfgpGwbLUHHj1ONSVYF-vYvlCX6MOEBtkv7AJ3kGX7Lk541TzRqLtSVEQO_zCnJ1bY4NEvG3OxD-5ZhmdjfWazZNTZfaKg1vIkCr_NLoEq-uWw6lWngxkHcsloxZnIKQsx212UQy8x0--na-G-0W586m6AcWDT3z3TVhTWJUOuRcv-o?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/DCVO9kfsmhVM-ST017fOtl08DKNS2U_-tjcYx2K0zCNQ33qgYTZrBNpDml4IH97AO2cgv6rv9bo3Vg1bIgtU8-gyRLoKMS3vx4Txcib-AMpVII8hGHof3OeYsKsVytH4shnbvEwfRNXsUGavsx-f7l8g-7S7g8PPGag_iDYNpuFoqnWm-I08a0u5pnYVuL8g?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/MuazCBugDdtTbapzp-uKsaqy1BfuqYPv5RbYx3dWo_DogmXuk1kJ2WcvXw4rA7FJxCGBzZwfU_rSXN372-2SG2FxiR1t8denreJeyPOTYugSfGWk_q39orhDzP3kzapb_1D0_XsZf22LKfaZ71aBBaXqWZhQmooJKoyxQhuCLFOglXUNqP4NJMATCftxDD0_?purpose=fullsize)

Credential stuffing is different from brute force and dictionary attacks.

### Definition

> **Credential stuffing is the use of previously compromised username/password combinations to attempt authentication against other services.**

The key word is:

### **Previously compromised**

The attacker isn't necessarily guessing the password.

They already have a username/password pair.

---

# 21. How Credential Stuffing Works

The general process is:

```text
        Data Breach / Phishing / Malware
                    │
                    ↓
           Stolen Credentials
                    │
                    ↓
       Username + Password Pairs
                    │
                    ↓
          Identify Other Services
                    │
                    ↓
         Automated Login Attempts
                    │
             ┌──────┴──────┐
             ↓             ↓
          Match         No Match
             │             │
             ↓             ↓
      Unauthorized      Continue
          Access
```

---

# 22. Where Do Stolen Credentials Come From?

Credentials may originate from:

- Data breaches
    
- Phishing
    
- Malware
    
- Credential leaks
    
- Previously compromised accounts
    

The attacker may obtain a dataset containing:

```text
username : password
```

and then test those credentials against another service.

---

# 23. Credential Stuffing vs Brute Force

This distinction is **extremely important**.

### Brute Force

```text
Username
   +
Generated guesses
   ↓
Try combinations
```

### Dictionary Attack

```text
Username
   +
Password wordlist
   ↓
Try likely passwords
```

### Credential Stuffing

```text
Known username
   +
Known leaked password
   ↓
Try same credential elsewhere
```

### 🧠 Memory trick

> **Brute force = guess.**  
> **Dictionary = likely guesses.**  
> **Credential stuffing = reuse known credentials.**

---

# 24. Why Credential Stuffing Works

The core problem is:

# **Password Reuse**

Suppose a user has:

```text
Email:
Password = MyPassword123!
```

Then uses the same password on:

```text
Gaming account
Shopping account
Social media
Cloud account
```

If the password is exposed through one service:

```text
Service A breached
       ↓
Password discovered
       ↓
Same password tested elsewhere
       ↓
Multiple accounts potentially compromised
```

This is the **domino effect** of password reuse.

---

# 25. The Password Reuse Problem

Password reuse is dangerous because one compromise can affect many accounts.

### Example

```text
              Password leaked
                    │
          ┌─────────┼─────────┐
          ↓         ↓         ↓
       Email     Shopping   Gaming
          │         │         │
          ↓         ↓         ↓
      Compromised Compromised Compromised
```

This is why every important account should have its own unique password.

---

# 26. Target Services

Credential stuffing can target many types of services, such as:

- Email
    
- Social media
    
- E-commerce
    
- Cloud services
    
- Banking
    
- Corporate applications
    

The risk is especially serious when the compromised account contains:

- Personal information
    
- Financial information
    
- Business information
    
- Recovery credentials
    
- Access to other services
    

---

# 27. Automation

Credential stuffing is commonly automated because attackers may have large datasets.

Conceptually:

```text
Credential #1
     ↓
Target login
     ↓
Success / Failure
     ↓
Credential #2
     ↓
Target login
     ↓
Success / Failure
     ↓
...
```

Automation allows large numbers of credential pairs to be tested.

Defenders therefore look for abnormal authentication patterns rather than relying only on individual failed logins.

---

# 28. Impact of Successful Credential Stuffing

A successful match can lead to:

- Unauthorized account access
    
- Data theft
    
- Identity fraud
    
- Financial crimes
    
- Further attacks
    
- Malware distribution
    
- Access to connected systems
    

The compromised account can potentially become a stepping stone to other resources.

---

# 29. Hybrid Attacks vs Credential Stuffing

|Feature|Hybrid Attack|Credential Stuffing|
|---|---|---|
|Starting point|Password wordlist|Stolen credentials|
|Password source|Generated/modified candidates|Previously compromised passwords|
|Main weakness exploited|Predictable password patterns|Password reuse|
|Guessing involved?|Yes|Usually no|
|Example|`Summer2023 → Summer2024`|`user@example.com + leakedPassword`|
|Main defense|Strong/unpredictable passwords|Unique passwords + MFA|

---

# 30. Password Security Defenses 🛡️

The most effective defense against these attacks is **layered authentication security**.

## Strong, Unique Passwords

Use a unique credential for every important account.

## MFA

Multi-factor authentication can prevent password-only access even if credentials are compromised.

## Password Managers

Password managers make it easier to create and maintain unique credentials.

## Rate Limiting

Restrict excessive authentication attempts.

## Monitoring

Detect unusual patterns such as:

```text
Many accounts
     +
Same IP / unusual source
     +
Many failed logins
     ↓
Potential attack
```

## Breach Detection

Organizations can monitor whether credentials associated with their users have appeared in known compromises and force appropriate remediation.

---

# 31. ⭐ Important Command-Line Concepts

### `wget`

Downloads a file.

```bash
wget URL
```

### `grep -E`

Searches/filter lines using extended regular expressions.

```bash
grep -E 'PATTERN' file
```

### `>`

Redirects output into another file.

```bash
command > output.txt
```

### `wc -l`

Counts lines.

```bash
wc -l file.txt
```

### Regex Cheat Sheet

|Regex|Meaning|
|---|---|
|`^`|Start of line|
|`$`|End of line|
|`.`|Any character|
|`{8,}`|At least 8 occurrences|
|`[A-Z]`|Uppercase letter|
|`[a-z]`|Lowercase letter|
|`[0-9]`|Digit|

---

# 32. 🧠 Complete Attack Comparison

```text
                         PASSWORD ATTACKS
                                │
        ┌───────────────────────┼───────────────────────┐
        ↓                       ↓                       ↓
   BRUTE FORCE              DICTIONARY              HYBRID
        │                       │                       │
   Try everything          Try wordlist          Wordlist +
        │                       │                 modifications
        │                       │                       │
        ↓                       ↓                       ↓
   Complete but             Fast against          Targets human
   expensive                common passwords       patterns
                                                       
                                │
                                ↓
                       CREDENTIAL STUFFING
                                │
                       Already-known credentials
                                │
                         Password reuse
```

---

# 33. 🔥 Most Important Things to Memorize

### Hybrid Attack

> **Dictionary + predictable modifications.**

### Why Hybrid Works

> Users often make small predictable changes to passwords.

### Example

```text
Summer2023
     ↓
Summer2023!
Summer2024
```

### Wordlist Filtering

```text
10,000 passwords
      ↓
≥8 characters
      ↓
uppercase
      ↓
lowercase
      ↓
number
      ↓
89 candidates
```

### Credential Stuffing

> **Using compromised credentials against other services.**

### Root Cause

> **Password reuse.**

### Best Defense

```text
Unique passwords
       +
MFA
       +
Rate limiting
       +
Monitoring
```

---

# 🎯 Final Mental Model

```text
                  PASSWORD ATTACKS
                         │
       ┌─────────────────┼─────────────────┐
       ↓                 ↓                 ↓
   Dictionary        Brute Force         Hybrid
       │                 │                 │
  Known words       All combinations   Words + mutations
       │                 │                 │
       └─────────────────┼─────────────────┘
                         ↓
                  Candidate Generation
                         
                         +
                         
                  Credential Stuffing
                         │
                 Known leaked credentials
                         │
                         ↓
                   Password Reuse
```

### 🔑 One-line takeaways

> **Hybrid attack:** Uses dictionary candidates and predictable modifications to reduce the search space compared with pure brute force.

> **Wordlist filtering:** Uses known password-policy requirements to remove irrelevant candidates and make authorized testing more focused.

> **Credential stuffing:** Uses previously compromised credentials against other services, primarily exploiting password reuse.

> **Biggest lesson:** **Unique passwords + MFA dramatically reduce the impact of credential compromise and password-guessing attacks.**