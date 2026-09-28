## 1. Module Objective

Before performing password spraying in an Active Directory environment, we first need a **list of valid domain users**.

The module presents several ways to build this list:

1. **SMB NULL session**
    
2. **LDAP anonymous bind**
    
3. **Kerbrute username enumeration**
    
4. Existing credentials
    
5. External information gathering such as email/LinkedIn-derived usernames
    

The password policy is also important because it tells us about:

- Minimum password length
    
- Password complexity
    
- Account lockout threshold
    
- Bad-password timer
    

These values affect how authentication testing can safely be performed.

---

# 🧠 2. What Is a Target User List?

A target user list is simply a list of **valid usernames/accounts in the domain**.

Example:

```text
administrator
guest
krbtgt
htb-student
avazquez
pfalcon
...
```

The goal of enumeration is to distinguish:

```text
Potential username
       ↓
Does this account actually exist?
       ↓
Valid domain account
```

This is important because password spraying against random usernames is inefficient and can create unnecessary authentication attempts.

---

# ⚠️ 3. Password Policy Comes First

One of the most important concepts from the previous module carries over here.

Before password spraying, understand:

```text
Password Policy
      |
      +-- Minimum password length
      |
      +-- Password complexity
      |
      +-- Lockout threshold
      |
      +-- Bad-password timer
```

The module specifically emphasizes that the **account lockout threshold and bad-password timer** help determine how many attempts can be made and how long to wait between attempts.

### 🔥 Mentor rule

**Never treat a password spray as simply “try a password against everyone.”**

You must understand the environment's lockout behavior first.

---

# 4. Keep an Activity Log

The module recommends keeping a detailed record of spraying activity.

Record:

|Information|Why?|
|---|---|
|Accounts targeted|Know who was tested|
|Domain Controller used|Identify authentication infrastructure|
|Time|Correlate with logs|
|Date|Maintain timeline|
|Password(s) attempted|Avoid duplicate attempts|

### Why is this important?

Suppose an account becomes locked.

You should be able to determine:

```text
Which account?
      ↓
Which DC?
      ↓
When?
      ↓
Which password was attempted?
```

This allows the penetration-testing team and client to correlate activity with their security logs.

---

# 5. SMB NULL Session → User Enumeration

![Image](https://images.openai.com/static-rsc-4/-na-hRAZt1jMESvFyY_I1HNv2LnjAdnj7Ol6LYifw9BTUVQBbbPRY4rQtbAKMtVJDjRz_XtmV76F_AotYPpuEV9lfwmUiFRzaMaEBGtNM1vaQ9f566a0LgDsiSG44Rnvcf0Y-MH8NhRTpYHeQAgVPNflDp-AmVAndt_P5upiM9b1xh9IOYe1F6PnUUIM2Y8K?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/1SuWoTDOmuNvQ1O3Rh_VmXxc9gPauU2d1qBmJY-_8wFvUcjr2yI_SlTmsvCEO63v88-BA3h0IPl1Qa989HAVpMcSbMSksSEzkS3oDoV138PyLS5eq2WHgbnPeyG4h67VpjohtoV8Qfpbv0WTr1dvT-VRqyznwNBsF8MfWupnfqGrhuHXvNt6cuyEkBTReqpI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/scZY0tsLCjdfaGci1fGLEGMt4X1e6oDwZxk7Q8-VxrVqYtVI0TRIyd-tKnJGpDwae-HLk0DeiroIavsvzvdXfR3gnjPBmgM56XXUVTDCUPXJY65g7zlPrAahqayjdSFMAMM4hqvsxL0kSayaymI8Dau9fI_Y76hnFSXY-Jp18hUc_NFhbwro_KKCC0YgyTj_?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/YSdIfTNa9q2DlpZvzPm_4HN46K-6mSM1Hdq5MgRL-Fbr4X0-nIPJhZFpTynO-L_sMuynKDJsN6aDcft44kfWNVOiDIyA4cySciI-rki_MpdzMhf5EAiwvbIaaVroCh79Qt4lMs-SIMMvohcbgVliHuFJWsPV77TL6jTWkN0v97wFpzL6p4MUz3yBHPBJr-ek?purpose=fullsize)

If you are inside an internal network but **do not have valid domain credentials**, one possibility is an SMB NULL session.

The module explains that SMB NULL sessions or LDAP anonymous binds can potentially provide:

- User lists
    
- Password policy information
    

If valid credentials or `SYSTEM` access are already available, Active Directory can be queried directly.

---

# 6. Why SYSTEM Can Be Useful

The module makes an important point:

A Windows `SYSTEM` account can impersonate the computer.

A **computer object** is treated as a domain user account, although there are differences, including behavior across forest trusts.

Therefore:

```text
SYSTEM access
      ↓
Computer identity
      ↓
Can potentially query AD
```

---

# 7. Tools for SMB/LDAP Enumeration

The module mentions:

- `enum4linux`
    
- `rpcclient`
    
- `CrackMapExec`
    

These can help retrieve domain users when SMB NULL sessions or LDAP anonymous binds are available.

---

# 8. enum4linux User Enumeration

The relevant option is:

```bash
enum4linux -U <IP>
```

The module uses:

```bash
enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```

The important part is:

```text
-U
```

→ Enumerate users.

The rest of the pipeline cleans the output so that only usernames remain.

---

# 9. Understanding the Linux Pipeline

This command is worth understanding rather than memorizing blindly:

```bash
enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```

### Step 1

```bash
enum4linux -U 172.16.5.5
```

Enumerates domain users.

### Step 2

```bash
grep "user:"
```

Keeps lines containing:

```text
user:
```

### Step 3

```bash
cut -f2 -d"["
```

Extracts the content after `[`.

Example:

```text
user:[administrator]
```

becomes approximately:

```text
administrator]
```

### Step 4

```bash
cut -f1 -d"]"
```

Removes the closing `]`.

Final:

```text
administrator
```

### 🧠 General lesson

This is a classic Linux enumeration workflow:

```text
Enumeration tool
      ↓
grep
      ↓
cut
      ↓
Clean username list
```

---

# 10. rpcclient → `enumdomusers`

Another way to retrieve domain users is through `rpcclient`.

Connect anonymously:

```bash
rpcclient -U "" -N 172.16.5.5
```

Then:

```text
enumdomusers
```

Example:

```text
user:[administrator] rid:[0x1f4]
user:[guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[lab_adm] rid:[0x3e9]
user:[htb-student] rid:[0x457]
user:[avazquez] rid:[0x458]
```

### Important

`enumdomusers` → **Enumerate domain users**

The `RID` is the Relative Identifier associated with the account.

---

# 11. CrackMapExec `--users`

Another option is:

```bash
crackmapexec smb <IP> --users
```

Example:

```bash
crackmapexec smb 172.16.5.5 --users
```

The particularly useful feature here is that the output includes:

```text
badpwdcount
baddpwdtime
```

---

# 12. `badpwdcount`

`badpwdcount` represents the number of **invalid login attempts** associated with the account.

Example:

```text
administrator    badpwdcount: 0
```

versus:

```text
avazquez         badpwdcount: 20
```

The latter account has accumulated many bad-password attempts.

### Why does this matter?

Suppose:

```text
Lockout threshold = 5
```

and an account already has a high `badpwdcount`.

That account deserves special attention because another failed authentication attempt could potentially contribute to lockout depending on the environment's behavior.

The module specifically says accounts close to the lockout threshold can be removed from the target list.

---

# 13. `baddpwdtime`

`baddpwdtime` tells us the date/time associated with the last bad-password attempt.

Example:

```text
baddpwdtime: 2022-02-17 22:59:22
```

This is useful together with `badpwdcount` because it gives context about the account's recent failed authentication activity.

---

# 14. Multiple Domain Controllers

This is a **very important concept**.

In an environment with multiple Domain Controllers, the module states that `badpwdcount` information is maintained separately on each DC.

Therefore:

```text
DC01 → badpwdcount
DC02 → badpwdcount
DC03 → badpwdcount
```

may not necessarily show the same value.

To obtain an accurate total, the module explains that you would need to:

1. Query each Domain Controller and sum the values, **or**
    
2. Query the Domain Controller with the **PDC Emulator FSMO role**.
    

### 🧠 Remember

**Multiple DCs = password-attempt counters can be distributed.**

---

# 15. LDAP Anonymous User Enumeration

![Image](https://images.openai.com/static-rsc-4/QlL72qLFpiItG3Py5k5ue02X0JG6sME3y2ljOtIAFvswM-1n4w2aJhLxp-nnuW0HFhwh9_t6xK9Kf-VbEsiTDQpvCgT8NV8xlKBx29dYYWAeUm_CpTfWQ9L34C3u9Ez9UWJzB05kWTrumMs9OP-GXvKBB_mxPSNGWan9oXoJyp9x_tLfHGm9CEe-lT_jjTeI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Cs4ikI7-TMKRB-QoSnCWEzL52HiDZ_kDqnK58j-pmYS76aNPkvIY43bXFq9SxhVjOU57-A9AF4KDp3ZsU6PXxrFblqiT3CH-fe6QPeUoCks8tHvlUH8itiQUXXzUNEicPXxotVMySXX9kIrl__f3rki8-gIegR9PlVQL4z7tlPiWu1eHc7GgUP8_aifQR7rY?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/H2rTT7Q1TJTIq58Sjx8m2CbMo15CTfW7yvp7yGa-tMQpazeoi2dV8uaWQupWnE1Rq70zsvM5zacZ262UkhURz1-HW76dViNa2CyBTQEzxv2N-nUshDU_Q9tjOV5jNj8Xkv_2uYBGuRizceqW8AoPojOIJSr_mKDVZwsfA1zBsX6hRQB5hoorqp5i5s1ZsqMc?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/n3I6ko_x9otIH3SwWRmI6zOkGAu7IE5yl3l2scqxbrf18NlmK4sfIcNCVvU3HQc7LjeZdUmfxPYqFzdxnXzMFI4dlevOaxMl5ZkvAHUS3kw8AidZPzgpX-zPhgnl1WzPy0UhD_Wc_jWCat-07ta_TJV26i5lZMx4DAvfZzfh2ZP5ZKapWiMBdseDr3cqH4nn?purpose=fullsize)

If LDAP anonymous bind is available, we can enumerate users using tools such as:

- `ldapsearch`
    
- `windapsearch`
    

The module emphasizes that with `ldapsearch`, we need an appropriate LDAP search filter.

---

# 16. ldapsearch User Enumeration

The module uses:

```bash
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "
```

The important LDAP filter is:

```text
(&(objectclass=user))
```

This searches for objects whose object class is `user`.

Then:

```bash
grep sAMAccountName:
```

extracts the username attribute.

Finally:

```bash
cut -f2 -d" "
```

cleans the output.

---

# 17. Important LDAP Attribute: `sAMAccountName`

In Active Directory:

```text
sAMAccountName
```

is an important attribute representing the user's logon/account name.

Example:

```text
sAMAccountName: htb-student
```

The module uses this attribute to produce a clean username list.

---

# 18. windapsearch

`windapsearch` makes LDAP enumeration easier.

The module uses:

```bash
./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
```

Important options:

|Option|Purpose in module|
|---|---|
|`--dc-ip`|Specify Domain Controller|
|`-u ""`|Blank username → anonymous bind|
|`-U`|Retrieve users|

The tool reports:

```text
No username provided. Will try anonymous bind.
```

Then discovers:

```text
DC=INLANEFREIGHT,DC=LOCAL
```

and successfully binds anonymously.

The example finds:

```text
Found 2906 users
```

---

# 19. Kerbrute User Enumeration

This is one of the most important sections of the module.

If we have **no access at all** from our internal network position, `Kerbrute` can be used to enumerate valid Active Directory accounts.

![Image](https://images.openai.com/static-rsc-4/R7-1196QbTl18PN8r5OSF8VtGtBb5Cvxdw34DF91wSxo-eUcf4C-Pi-u8T6nk9fo80zct2Uw0P-kC05LEEcatt5DeyAtm5Dnhrsjn8UrOnuo7kFEK4HSrnRY1u26O6T2YR0Itjl7x3ZRNALQMd9BxzXo2TbyyY_PdW2C_95puCzUhKv_hlnwn0luqkBZqkqI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/uY37IKNQFALoKNI7v9CDUOgqulM-ZrXGVn1KLmC0zfbXsT1Wd5BNd6URBzzLBnbX0RamWPpf6zGj-_s4XOwCxv7h-gMShdBwlWxOtQlQwsRWxc2WQaqiz7H7TkYOIu-ZkFNw7E0AppZh3OP19WkK9vTnDD7e3CxJanm9STzBS5f8F33l5OLZI6c41Z6qZ1gc?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/t4x4d-dXjxg-NRpsKEM4IKuW5KEekrkVZHFWUKGgl3MeGYkDagCVqOysqn8Y-BRamOEx720PBr3acJ3v71sXuS8I3eZhsclBtHhVb4Na5XHudGhcVAEFN87MzhiaAY2eF4t6FhwvyPmjSe4Gg3QuECTr1tkd7p-xKuRlmcyccVQgO0LEAEX157cb9VX2OyCR?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/bpvhrCKEXioz0dZs-H6WD9LcofMUv_gQ0r5kS9oDhLa3ovK-3GRDfs1jb0xDJl1kriCmgzV4xG-dNi0NQjaZnD0pz-8nrds8Hsk2XY51HPXmTFoX9Jtio2uYXU9ZB12moDeB_YLi-LoSD6yt00l2qlC2xtvrPEqW1jhOk9o0fSfiPG4Fr2I2hIjsOAaUhx7Q?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/xQpDwjmx5sqwOyKThh2mtNefgFlVa-IY7saV6onHcWBEMQW6Plk7hG6HAiRIxuA0MjprgABmyITNYit5YAU4HguBUNXis50zcNCh9ivCBmQkxk_TT-n24l0sbEnzLyhBy4elUfzk-9pNUtApvkym4QzC0DHAkOHL-QT2odjMkHPlMGItb9Hsvt2ptE3Ok5TZ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/O0tgPaYGae7rpF5wO10SMJKeDgjzTKdJBHWilZgXa2DZAwDbCGk7dzWbuqxY7ujtLK_67CQT_OTx0cuvbWQzuHAirzglgyp40mBrnXxQoOAehgIKrHx4BgeFKpTbIKsmW9XM6NvzL64bfMMeabzZojY7c84SYTLDbo5izA7oK8plkzS6V33HLTZCNcGmr-0K?purpose=fullsize)

Kerbrute uses **Kerberos Pre-Authentication behavior** to determine whether usernames exist.

The basic concept:

```text
Username
   ↓
Kerberos request
   ↓
Domain Controller / KDC
   ↓
Response
   ↓
Valid or invalid username
```

---

# 20. How Kerbrute Identifies Users

The module describes two important responses.

### Invalid username

If the KDC responds with:

```text
PRINCIPAL UNKNOWN
```

→ Username is invalid.

### Valid username

If the KDC requests:

```text
Kerberos Pre-Authentication
```

→ Username exists.

Kerbrute can therefore distinguish valid from invalid usernames without performing a traditional password authentication attempt.

---

# 21. Why Kerbrute Is Interesting

The module notes that username enumeration through this technique:

- Does not cause normal logon failures.
    
- Does not lock out accounts during the **username enumeration** stage.
    
- Can be relatively fast.
    
- May be less noisy than some traditional authentication-based enumeration.
    

However, **this changes when you actually perform password spraying**.

Failed Kerberos pre-authentication attempts during password spraying can count toward failed login attempts and potentially cause account lockout.

### 🚨 Critical distinction

```text
Kerbrute username enumeration
        ≠
Kerbrute password spraying
```

Username enumeration may avoid lockouts.

Password spraying can cause them.

---

# 22. Kerbrute Wordlists

The module uses:

```text
jsmith.txt
```

from the `statistically-likely-usernames` repository.

The example contains:

```text
48,705
```

possible usernames in the `flast` format.

Example format:

```text
jsmith
```

Meaning:

```text
j + smith
```

The repository contains different username formats useful for enumeration.

---

# 23. Kerbrute Command

The module uses:

```bash
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
```

Understand the components:

```text
kerbrute
   ↓
userenum
   ↓
-d inlanefreight.local
   ↓
--dc 172.16.5.5
   ↓
/opt/jsmith.txt
```

### Meaning

- `userenum` → Username enumeration
    
- `-d` → Domain
    
- `--dc` → Domain Controller
    
- Wordlist → Candidate usernames
    

---

# 24. Kerbrute Output

Valid accounts appear as:

```text
[+] VALID USERNAME: jjones@inlanefreight.local
[+] VALID USERNAME: sbrown@inlanefreight.local
[+] VALID USERNAME: tjohnson@inlanefreight.local
```

This gives us a list of confirmed domain accounts.

---

# 25. Kerbrute Speed

The module demonstrates that more than:

```text
48,000 usernames
```

were checked in just over:

```text
12 seconds
```

and more than:

```text
50 valid usernames
```

were identified.

This demonstrates why Kerbrute can be useful for rapid username enumeration.

---

# 26. Kerberos Event ID 4768

A key defensive point:

Kerbrute username enumeration generates:

```text
Event ID 4768
```

when Kerberos event logging is enabled through Group Policy.

Event 4768 represents:

> **A Kerberos authentication ticket (TGT) was requested.**

### Blue-team perspective

A defender can tune SIEM detection to look for an unusual influx of:

```text
4768
```

events.

Therefore:

```text
Large username enumeration
        ↓
Many Kerberos requests
        ↓
Event 4768
        ↓
Potential detection opportunity
```

---

# 27. External Information Gathering

If SMB NULL sessions, LDAP anonymous access, and Kerbrute don't produce a usable list, the module discusses external information gathering.

Potential sources include:

- Company email addresses
    
- LinkedIn
    
- Username-generation tools
    

One example is:

```text
linkedin2username
```

The purpose is to generate possible usernames from publicly available company/person information.

### Important limitation

Externally generated usernames are **potential** usernames, not necessarily confirmed valid accounts.

---

# 28. Credentialed Enumeration

If we have valid credentials, building a user list becomes much easier.

The module uses CrackMapExec:

```bash
sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users
```

The tool authenticates and then enumerates domain users.

---

# 29. Credentialed Enumeration Output

The output again provides:

```text
username
badpwdcount
baddpwdtime
```

Example:

```text
administrator   badpwdcount: 1
guest           badpwdcount: 0
lab_adm         badpwdcount: 0
krbtgt          badpwdcount: 0
htb-student     badpwdcount: 0
avazquez        badpwdcount: 20
pfalcon         badpwdcount: 0
```

### What should immediately catch your attention?

```text
avazquez → badpwdcount: 20
```

This is significantly different from the accounts showing `0`.

The point of the exercise is not simply to collect usernames; the additional account-state information can affect how the target list is handled.

---

# 30. Complete Enumeration Methodology

Here's the workflow you should remember:

![Image](https://images.openai.com/static-rsc-4/_zxx9NYv1wv9XHND7PwmHm0PvJs8xZrng4q7h_aHqqAAMpqNlmma-rlsPgJ5Ia3_Qa-eYDuDqDYZypUoJqTLWokucJ4QcT9PwE9mIdu4XKnEAC27k2iaO7kRkQoEGV4CNHKXlYUzM4q4Xnsmkq2SdQA-hbiZVXgwitfdeQT4YRC7l2hYxSFmRts1Rqft68vI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/1SuWoTDOmuNvQ1O3Rh_VmXxc9gPauU2d1qBmJY-_8wFvUcjr2yI_SlTmsvCEO63v88-BA3h0IPl1Qa989HAVpMcSbMSksSEzkS3oDoV138PyLS5eq2WHgbnPeyG4h67VpjohtoV8Qfpbv0WTr1dvT-VRqyznwNBsF8MfWupnfqGrhuHXvNt6cuyEkBTReqpI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/mYHrtfxbA0kYWFik1SN36uyfv4hTWy-UaD2jyPd8Y4W615VOW4ErKcKCS2YhRAO_Pt7yHgcIuhdQqCUIX_mFJhSWKOadCydSMXc5ep-aLn2YzSFOC6M3OQA8sIH9GYhG88vsGYuuvTVhRS64LGkUxpsvnpgEste91UHaEtbkws_sEFGiBWR2MPHl8s4sDl6p?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/j202UrMekneIjjHNkz5MjqRuhmGpF3Mg1LLGNxqJirzDhYsORci8l-K9lMOBGfJ-_C4etZahuV1n8eNUrgghTsiEYfkYpB19S7llZ7SdVPvMBgz5wc91Ydne3IOYwqUbew7pEY2zf2o7ZFQIdNhJYdGbMXq65ixur6fNUW8bh8QblnaBDkjsRiVlWVsJi3f7?purpose=fullsize)

```text
              Need valid AD users
                      |
          +-----------+-----------+
          |                       |
     Have credentials?       No credentials
          |                       |
          v                       v
 Credentialed AD             Test available
 enumeration                 anonymous access
          |                       |
          |               +-------+-------+
          |               |               |
          |           SMB NULL         LDAP
          |               |           anonymous
          |               |               |
          +---------------+---------------+
                          |
                          v
                 Still no user list?
                          |
                          v
                     Kerbrute
                          |
                          v
                External enumeration
                          |
                          v
                  Valid user list
                          |
                          v
                 Check password policy
                          |
                          v
                Assess safely / document
```

---

# 31. Tool Comparison

|Method|Authentication|Main purpose|
|---|---|---|
|`enum4linux -U`|NULL/available access|Enumerate users|
|`rpcclient enumdomusers`|NULL/available access|Enumerate domain users|
|`CrackMapExec --users`|Can use credentials|Enumerate users + bad password information|
|`ldapsearch`|Anonymous/authenticated|LDAP user enumeration|
|`windapsearch`|Anonymous/authenticated|LDAP enumeration|
|`Kerbrute userenum`|Kerberos|Validate usernames|
|`linkedin2username`|External information|Generate possible usernames|

---

# 32. Must-Know Commands

### enum4linux

```bash
enum4linux -U <IP>
```

### Clean enum4linux output

```bash
enum4linux -U <IP> | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```

### rpcclient

```bash
rpcclient -U "" -N <IP>
```

Then:

```text
enumdomusers
```

### CrackMapExec

```bash
crackmapexec smb <IP> --users
```

### LDAP

```bash
ldapsearch -h <IP> -x -b "DC=DOMAIN,DC=LOCAL" -s sub "(&(objectclass=user))"
```

### windapsearch

```bash
./windapsearch.py --dc-ip <IP> -u "" -U
```

### Kerbrute

```bash
kerbrute userenum -d <DOMAIN> --dc <DC-IP> <WORDLIST>
```

---

# 🧠 33. Important Things to Memorize

### `enum4linux`

```text
-U → user enumeration
```

### `rpcclient`

```text
enumdomusers → enumerate domain users
```

### CrackMapExec

```text
--users → enumerate domain users
```

and:

```text
badpwdcount → invalid login attempts
baddpwdtime → time/date of last bad-password attempt
```

### LDAP

```text
sAMAccountName → account/logon name
objectclass=user → search for user objects
```

### Kerbrute

```text
PRINCIPAL UNKNOWN
        ↓
Invalid username
```

```text
Kerberos Pre-Authentication requested
        ↓
Valid username
```

### Detection

```text
Kerbrute enumeration
        ↓
Kerberos requests
        ↓
Event ID 4768
```

---

# 🔥 34. The Most Important Concept

Don't think of this module as:

> **"How do I password spray?"**

The focus is actually:

> **"How do I safely and accurately build a list of valid Active Directory users before password spraying?"**

The workflow is:

```text
1. Identify possible enumeration method
                ↓
2. Enumerate usernames
                ↓
3. Clean/filter the results
                ↓
4. Examine account state
                ↓
5. Understand password policy
                ↓
6. Document everything
                ↓
7. Only then proceed with authorized testing
```

The module itself ends by transitioning from **building the target user list** into performing password-spraying attacks from Linux and Windows.

---

## 🎯 Quick Revision Table

|Question|Remember|
|---|---|
|SMB user enumeration|`enum4linux -U`|
|rpcclient user enumeration|`enumdomusers`|
|CME user enumeration|`--users`|
|Failed-attempt counter|`badpwdcount`|
|Last bad-password time|`baddpwdtime`|
|LDAP username attribute|`sAMAccountName`|
|LDAP user filter|`(&(objectclass=user))`|
|LDAP enumeration tool|`windapsearch`|
|Kerberos username enumeration|`Kerbrute userenum`|
|Invalid Kerberos username|`PRINCIPAL UNKNOWN`|
|Valid Kerberos username indication|Pre-Authentication request|
|Kerberos TGT event|**4768**|
|External username generation|`linkedin2username`|

**Module → Detailed Notes → Commands → Concepts → Methodology → Revision complete ✅**

When we move to the exercises, I'll follow the corrected mentor workflow: **I will give you hints and commands where appropriate, but I will not reveal the answer unless you explicitly ask for it.**