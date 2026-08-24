![Image](https://images.openai.com/static-rsc-4/dgJImxaP3qfXsdtP_V_00szlNouOvhBEeMh1o6sQkIR9JK79QVdVJNGiwQjBpuo9uhefYJEysC01r7JmwuW5NUk5S0irYaOyV4VNjnhXuEE2U4r3zsWZsxs-kc2X9zGyKxHj80gVNs7gIqna0QaR5q1AbN9fhr_0NhR4tKil83HXqARmQiF1qUXNgs4Rx6Cq?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ll7BQADP5K_-8Ajo5qSzc6YaJLxbW9EZ1CnWGIfWzyB2x_jAT_Bdx-fc8lHgTZkrxAZcaXGJp_PSQq5OAWeI9XouJHWOsbAX6ZZWHBMXDZUj0QRkzXkovhF4jDUIVzGKG2yBd5rwqoE5E8YfGKb101ze6A8VkVIJc0_M-7LIoVJu84HpdYpdLZix78NO8zWA?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Z17_H6BvvTLS4RHUaAQFNgbMjflgqCM7r8OBSkUW5sMyCYPwV8cp1UB8ycARUAn0xrfl-iMNNIK_lBMXJBaD8xk4llemFzTalrvHLFg3iHVWP0gxj-W08m_a83e5OhtEY1wRSisZl95yTypHXDLGa0AZ6cVZROu62vIybmqNjhsCd0dswyln18C6UXSwfjMc?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/giLmVOnHqtQISoaBSHitNaInohLOQWoWo-4mrn7-a3_ah27W__OU24iqesmS-fHQeGJxwx5ukriBbEwDaLcm8YKDHS6mUYwBj3zaM-edu7AlA6IuqzvWLob74fSuhG6gkhcPsQOtAWRXHP0AucG3XC2OVvehYGShUXgeIvlgkaqkKMHXfKNrWRZA3NOztBa1?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/iydlmeAmSlRYab1qudmi6OFwdg-WvyTAgT5uSG1_8rh24Z4ihA7pXEEXl7Btb10zpSAYcgFmR_b8m_CN_mQ9SPkBzER0ExPZqF_xpfXORC21CjXPAW-G616lIqEBAc3b46hFZrNnXKel0TgBUEFfwkpfzmsxCm46sC769Rk8jjG7JApgOfs7rJf74rzY1H1g?purpose=fullsize)

## 1. Introduction

**Keys and passwords** are the modern equivalent of locks and combinations that secure the digital world.

But what if someone tries **every possible combination** until they find the one that opens the door?

That, in essence, is **`brute forcing`**.

> **Core idea:** Brute forcing is based on systematic trial and error rather than exploiting a specific vulnerability.

---

# 2. What is Brute Forcing?

In cybersecurity, **brute forcing** is a **trial-and-error method** used to crack:

- Passwords
    
- Login credentials
    
- Encryption keys
    
- Authentication mechanisms
    

It involves systematically trying possible combinations until the correct one is found.

### Simple analogy

Imagine a thief has a lock with a 4-digit combination:

```text
0000
0001
0002
0003
...
9998
9999
```

If there is no protection against repeated attempts, the thief can eventually find the correct combination.

The same principle applies to digital authentication.

### Definition

> **Brute force attack:** A technique in which an attacker systematically attempts possible credentials, keys, or combinations until the correct one is discovered.

---

# 3. What Determines the Success of a Brute-Force Attack?

The success of brute forcing depends on several important factors.

## 3.1 Password Complexity

The complexity of a password has a major impact on how difficult it is to brute force.

A password such as:

```text
password
```

is extremely weak because it is common and easy to guess.

A password such as:

```text
T7!qZ#91mL@xP
```

has a much larger search space.

### Complexity increases through:

- Greater password length
    
- Uppercase letters
    
- Lowercase letters
    
- Numbers
    
- Special characters
    

**Important:** Password length is particularly important because the number of possible combinations grows rapidly as the password becomes longer.

---

## 3.2 Computational Power

The attacker must perform potentially huge numbers of attempts.

Modern computers and specialized hardware can test enormous numbers of possibilities, depending on the target and attack type.

For example:

```text
More computational power
        ↓
More guesses per second
        ↓
Less time required
        ↓
Higher probability of success
```

However, the exact speed depends heavily on what is being attacked.

A **local password hash** can often be attacked much faster than an online login form because online authentication is limited by network speed and defensive controls.

---

## 3.3 Security Measures

Defensive mechanisms can make brute forcing significantly harder.

Common protections include:

- Account lockouts
    
- Rate limiting
    
- CAPTCHA
    
- Multi-factor authentication (MFA)
    
- Strong password policies
    
- Login monitoring
    
- IP reputation/blocking
    
- Progressive delays between attempts
    

For example:

```text
Attempt 1 → allowed
Attempt 2 → allowed
Attempt 3 → allowed
Attempt 4 → delay
Attempt 5 → longer delay
Attempt 6 → account temporarily locked
```

These controls dramatically reduce the practicality of online brute-force attacks.

---

# 4. How Brute Forcing Works

![Image](https://images.openai.com/static-rsc-4/Z17_H6BvvTLS4RHUaAQFNgbMjflgqCM7r8OBSkUW5sMyCYPwV8cp1UB8ycARUAn0xrfl-iMNNIK_lBMXJBaD8xk4llemFzTalrvHLFg3iHVWP0gxj-W08m_a83e5OhtEY1wRSisZl95yTypHXDLGa0AZ6cVZROu62vIybmqNjhsCd0dswyln18C6UXSwfjMc?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/D66lsTCw8ipTLuZ0gphg1FBBMBAnoA4fyD9eI7RN2h7SLh_tmhi3jVKbWB4MKbDi-96-orNfWOuyVGL010h3F8MYdCuggkdR-kOoJ5MVwSSSvES5IdT-aksU5XqEz2UiGsp5DKM8nQn59atwHLCFvgC8l4U3Z4BAGSe84uxAbjJlUiubCXhwYb0JoKiTtxc3?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/dgJImxaP3qfXsdtP_V_00szlNouOvhBEeMh1o6sQkIR9JK79QVdVJNGiwQjBpuo9uhefYJEysC01r7JmwuW5NUk5S0irYaOyV4VNjnhXuEE2U4r3zsWZsxs-kc2X9zGyKxHj80gVNs7gIqna0QaR5q1AbN9fhr_0NhR4tKil83HXqARmQiF1qUXNgs4Rx6Cq?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/syHMYH6f_XeRBxnqb4700ymBO3uW0MYnQm3JqNd0QhisTnwbw4-8VBB-f0B6ROplDAj1Nx-R92j3o8sBskLR_OleuDjWBrDspCBJNm7JBxZ_PNHIWoHdH5nt9mZdrkeGztT5VVgmr1AZ1K9ZUM5tALwwtLDu0Z5kM86Q9CNb3XYwxZeuzq1ISKa7p9onzFPP?purpose=fullsize)

The general brute-force process can be understood as follows:

```text
             ┌─────────┐
             │  Start  │
             └────┬────┘
                  ↓
       ┌─────────────────────┐
       │ Generate candidate  │
       │    combination      │
       └──────────┬──────────┘
                  ↓
       ┌─────────────────────┐
       │ Apply / attempt the │
       │     combination     │
       └──────────┬──────────┘
                  ↓
       ┌─────────────────────┐
       │ Was it successful?  │
       └──────┬────────┬─────┘
              │        │
            YES        NO
              │        │
              ↓        ↓
       ┌──────────┐  Generate
       │  Access  │  next attempt
       │ Granted  │      │
       └────┬─────┘      │
            ↓            │
           END ←─────────┘
```

### Step 1 — Start

The attacker initiates the brute-force process.

This may involve specialized software or scripts that automate repeated attempts.

---

### Step 2 — Generate Possible Combination

The software generates a candidate based on predefined parameters.

These parameters might include:

- Character sets
    
- Minimum password length
    
- Maximum password length
    
- Known usernames
    
- Known password patterns
    
- Dictionary words
    
- Numbers
    
- Special characters
    

Example:

```text
aaaa
aaab
aaac
aaad
...
```

---

### Step 3 — Apply Combination

The generated candidate is submitted to the target.

For example, against an authorized test login:

```text
Username: admin
Password: candidate
```

The system then evaluates the credentials.

---

### Step 4 — Check if Successful

The system determines whether the supplied credentials are correct.

```text
Correct?
 ├── YES → Access granted
 └── NO  → Try next candidate
```

---

### Step 5 — Access Granted

If the correct credentials are discovered, authentication succeeds.

The attacker/tester may then gain access to the protected resource.

In a **penetration test**, this demonstrates that the authentication mechanism or password policy needs improvement.

---

### Step 6 — End

If the correct credential is found, the process stops.

If not, the process continues until:

- The password is discovered
    
- The available candidates are exhausted
    
- The tester stops the attack
    
- Defensive controls prevent further attempts
    

---

# 5. Types of Brute Forcing

Brute forcing is **not a single technique**.

There are several approaches, each with different strengths, weaknesses, and use cases.

|Method|Description|Example|Best Used When|
|---|---|---|---|
|**Simple Brute Force**|Systematically tries all possible combinations within a defined character set and length range.|Trying all lowercase combinations from `a-z` for passwords of length 4–6.|No prior information about the password is available and computational resources are abundant.|
|**Dictionary Attack**|Uses a pre-compiled list of common words, phrases, and passwords.|Trying passwords from `rockyou.txt`.|The target is likely to use a weak or common password.|
|**Hybrid Attack**|Combines dictionary attacks with brute-force modifications.|Adding numbers or special characters to dictionary words.|The password is likely to be a modified common word.|
|**Credential Stuffing**|Uses leaked username/password combinations against other services.|Trying previously leaked credentials on another service.|Users are suspected of reusing passwords.|
|**Password Spraying**|Attempts a small number of common passwords against many accounts.|Testing one common password across many usernames.|Account lockout policies make repeated attempts against one account risky.|
|**Rainbow Table Attack**|Uses pre-computed tables of password hashes to recover plaintext passwords.|Comparing captured hashes against pre-computed hash tables.|Large numbers of unsalted/weakly protected hashes are available.|
|**Reverse Brute Force**|Uses one known/common password against many usernames.|Testing one password across multiple accounts.|There is suspicion that the same password is reused.|
|**Distributed Brute Force**|Splits the workload across multiple computers/devices.|Multiple systems simultaneously testing different candidates.|A very large search space needs to be processed faster.|

---

# 6. Simple Brute Force

A **simple brute-force attack** attempts every possible combination within a defined search space.

For example, if a password consists only of lowercase letters and has four characters:

```text
aaaa
aaab
aaac
...
zzzz
```

The attacker doesn't rely on knowing anything about the password.

### Advantages

- Doesn't require prior password knowledge.
    
- Can eventually find the password if the search space is completely covered.
    

### Disadvantages

- Can become extremely slow as password length and character diversity increase.
    
- Large search spaces can make exhaustive searching impractical.
    

### Key concept

**Larger search space = more possible combinations = more work.**

---

# 7. Dictionary Attack

![Image](https://images.openai.com/static-rsc-4/3Mas-zi8lov1TGsP71uxRrcxJDyi4wiA-4Y2ce2nRdWbY71NTh0bmrPptlc9CPdqpNtI-HjZU_C3qVm7kyfT2j6QLEw1ajHsPUhytdFPqT0FxyNkISIxUcePokFQxs3ZRhL5CPPtiblaJfKuXt5nAB6cVG2TVLfNLaorvTO9nwColgPCBIr3d95Re1llGjUc?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/jC0ssTXcAVD1TFEONQr7ZUc3OZ_GLIxNp2Ur_d8E2DV6yMR2z1tu1eQSyiiYG0x0g0rpdoU1RvteDei0WUNqBpH2KkssGt-i1i4o9YcsmQjoykW_IIrdC_4LjPAjrWLmKkvKDcIkrKasKEUtWDQqmJraQjugkCDY1qqIgHvD8A_xieFzgtyicWdOiNz8p0eR?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/s2jcSusOrQBxMu4ovnGNiyuK_ZA199HJH1GaTMgx5zFWtQlCk13Tn1OtR-JZ8nEbfRZYGAZ5GfUV06vDcJecfTMsjaaaY__4l_NyVVoclww_mWmkAPmHHWSxuxN5qqWBMo8686lw1i-x0jON9Bu4pxgJrPmFyMtwkEDad6mfH_tHbCLAFpiIe1PxBTcZPpfh?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/aH9hcF2lC0JenDSn03-L_SRaEtdpJnX6B6B7l4ZkVEMaGbF-oBfHdR1SSbwhDGJlpkwey6Nyf1Dpp6p46vtDlJyhLBIyDXICiAtiahPFiRX8XSkaXzgJ6ZkcoeUU0y73TacndQ_MuEs0vvQWeDZ6khYBWRHYT05GoiwK_gjtuwKbTjFS9sjddcqBA9HoTqjr?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/svsvrQTxuEMuI2DT4NQh0TIlPVOfqFpqlgV1Fr1pP5KwT4hBvXh3MarD3U9djTIWLkDSYuebhxo8mi4_mEU_JK9g89LQ9CuZ_ZfCsU7uigGasJFgqeT8JALUy7p9yViYTd_JMrM3wpzqFbe0t2w2hEZ6LoqeD8AnspsrSpf_kXs5r625RJEqAEA86wUzX4i2?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/yK6F2DxJtc0M2HptABvpwFWVOSKrzPcVwlWL29RRomCUNVR2mnQmxze11YqjJjjzQ2qlzKw4_G9ujKYEqZewjQG7JGW79vNrTA3ngiOWzzluy5n1HKt32rl68xuv3KdA9HjFVJszHDxPh-B8YhvufTGaaheI-Y9Lbwuv3OzaTn65WrIK3cfL1kGHuz6Nj4gM?purpose=fullsize)

A **dictionary attack** uses a predefined list of likely passwords rather than generating every possible combination.

A famous example in penetration-testing environments is:

```text
rockyou.txt
```

A dictionary may contain entries such as:

```text
password
password1
qwerty
admin
letmein
football
welcome
```

### Why is this effective?

Many people choose passwords based on:

- Common words
    
- Names
    
- Sports
    
- Places
    
- Dates
    
- Keyboard patterns
    
- Popular passwords
    

Therefore, testing common passwords first can be much more efficient than testing every possible combination.

### Key difference

```text
Simple brute force
→ Try everything

Dictionary attack
→ Try likely things first
```

---

# 8. Hybrid Attack

A **hybrid attack** combines dictionary-based guessing with brute-force modifications.

For example, suppose the dictionary contains:

```text
password
```

A hybrid technique might consider variations such as:

```text
password1
password123
Password1
password!
password2026
```

The basic idea is:

```text
Dictionary word
      +
Modification
      ↓
Candidate password
```

This works because users often take a familiar word and make a small modification to satisfy password requirements.

---

# 9. Credential Stuffing

**Credential stuffing** is different from traditional brute forcing.

Instead of generating passwords, an attacker uses **previously leaked username/password combinations**.

For example:

```text
user1 : password123
user2 : Summer2025!
user3 : qwerty123
```

These credentials may have originated from a previous data breach.

The attacker then attempts to use the same combinations on another service.

### Why does it work?

Because some users **reuse passwords across multiple websites**.

### Important distinction

```text
Brute Force
→ Generate/guess credentials

Credential Stuffing
→ Reuse known leaked credentials
```

---

# 10. Password Spraying

**Password spraying** reverses the usual approach.

Instead of trying many passwords against one account, the attacker tries **one or a small number of common passwords against many accounts**.

Example:

```text
Password: Winter2026!

User A → attempt
User B → attempt
User C → attempt
User D → attempt
```

Then another password may be tried later.

### Why?

This can reduce the likelihood of triggering account-specific lockout mechanisms.

### Important distinction

```text
Brute force:
Many passwords → One account

Password spraying:
Few passwords → Many accounts
```

---

# 11. Rainbow Table Attack

![Image](https://images.openai.com/static-rsc-4/o8nS3pticljAQAF2JvSIUYOYwCz6jHz5_CEaGAqylMlYiKgf4diQY9Z9QZafMIATWLKmzyatXQ1O5L3Mzi2mCIDXcCCsYRo3-o9vUFybYqguiaNLp9QV3LrJ7iOL4IABkc7I94Rxs7JsBEnZYBqPC1piECpYxqItEJD-f983ikFtqD2XlnfQ6d2TT8gCpHze?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/7ByHKrunBo5FYwQv6iXj0PhZG1WhPEhWvY7cJ3OGXmHuYPQ3oy01Gz5Gw_eg74_RqVnMMQjEHG6YFacpbSGmXY-wHwJIpFowjT2tWglODH3s-KWDuEqnuhz7s76hLrl2Kn6Do538dSKDtIODG5MHx8DnjhlkSNzT4M-KwXue6STCOaOYN0ptug9PFqBeotOp?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ArkSqraOOYqKWOihKzrJdBmoIAK-BoDnD61rF8j8PdCtIG1zUIU-Jv9fZEkrq73PnD0iErCxbPAATQB7sZnRH80YPBh6c522594zmBsqH8CKFaVyyeKtywRoFzU2MYrBZLYNT1xUh83wssNkVJgosF3AD-Pu6NcRdpHP36zVC_srRIGwIqfGWwr5rAPgH4e2?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/gOemrHyKpnG0gNPWUvBj06Q-w-ry_qFjDVoZOTFWG745ROzBkKWja6Iijo38I7EfmwJynQi-4EFYyUr3dEEwjoTOKNgqXlKhD2gd-RPE2qKXK_IX5gcuSyXFfksA2PbnLETyn2A037o24qRwBJ3a0149xMRGeFtKxo0Lrh7xpFBWVfhDtuRnJXkWPvTrHEfp?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/1YZeNCxjU7XC7JbfF__nAaYjAuovN3ZigipMGXkyx1E-2tB1548kOv6xJb7IqI5kYEEPkWrZxKJkevJi-KRIPD7r7EywuCnZEx0VTfsL3sS4VxdUQnbbziZqWTquVVRbznjWuthUJzdRPEiMLwcbz2CBhbbmIhoh2AX2SspnLDlMX2_3bmAKBTCfaGmqG_ko?purpose=fullsize)

A **rainbow table attack** uses pre-computed data to help recover passwords from password hashes.

Instead of calculating every candidate hash from scratch during an attack, an attacker can compare captured hashes against pre-computed information.

### Basic concept

```text
Password
   ↓
Hash function
   ↓
Password Hash
```

The attacker has a collection of pre-computed password/hash relationships and searches for a match.

### Important defense: Salting

Modern password storage should use **unique salts** with password hashing.

A salt makes pre-computed rainbow tables much less useful because identical passwords produce different stored hashes when different salts are used.

---

# 12. Reverse Brute Force

A **reverse brute-force attack** starts with a known or suspected password and attempts it against many usernames.

Example:

```text
Known password:
Winter2026!

admin      → attempt
john       → attempt
alice      → attempt
bob        → attempt
```

This is particularly relevant when there is reason to believe a password is reused across accounts.

### Remember

```text
Normal brute force:
Many passwords → One account

Reverse brute force:
One password → Many accounts
```

---

# 13. Distributed Brute Force

A **distributed brute-force attack** divides the workload across multiple systems.

For example:

```text
             Target
                ↑
       ┌────────┼────────┐
       │        │        │
    System 1  System 2  System 3
       │        │        │
   Candidates Candidates Candidates
```

Instead of one computer testing all candidates, several machines share the workload.

### Benefit

The total number of attempts per unit of time can increase.

### Limitation

The attack still depends on the size of the search space and the target's defenses.

---

# 14. Brute Forcing in Penetration Testing

![Image](https://images.openai.com/static-rsc-4/di1VZLPJkhKbW9IU0mRD5Eeq9H7--kbTJFJW8JpR86mqVk6LqfXWYs85eGl6BYaqnc_fQobfK_7E0Wzk6oEWqfa7sk0LyQkRU7hOYsDKDeG9w06IyCfIVPqxcvaUaYs-W2O4uLDOjnc4wDkgwpupUZqeFsvhqRq2ihxQvZixfkHoVDL9mqBFCLkSkMiaFYDd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/CkoG8-KYxZ9Qoi6SD-VNNlp51dd8hwPGaYh8QPZEAs65RudGHrIrD6NCU780QUbVPDe3Oai1cKbQSJlmg46gn7R8sVnmDty66cLUUawIA4Vdg8eKQ8qboxhi40nvPNaiZ37aM7gv_hz3aJJVY5fgbd43QiSwqn6UXOVDwCyTiYPCKt0OVD45IGbdUzd8lmJL?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/s8ZZsDbUQhtBcIQG7T63f5RoLJ5V-w-JgI1NDm8mJUPMKOsdGojlxRs6HZplf2NWl0OWRswiMutrZ2MHM_BGMBCp-NESAvTeGNO5CkT8izxoKf3bCmVHUQZBn4qEHINGiefeGqhVdJEzeQELta-Z70yuTrIZbcKNfi3srYYKTJXAjCISkvEPax-KgDB_xe-n?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ZKydTZHO_-L8-5GHO1sAIH_0nScMsCMvYpDd8hDXpdH2z0GuZX8XW6Sn5nAlXCgESXdc4SL5K8Jl3lIk9pA0ebN9eCOyHCs_ti5OA_j43wV8-FiwN2XDVULk6dP3k2iAuS2JIFXTpt0YyYhMd6F0h4xxo6PuhDn2FSUqXkUnfqfBY-2EaLxcpJbKnyByCfOX?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/oKMRJLez7XhWbWwYQl1fYdWpXLB68wJ0LEVTuc-XWVDQq9q-foRJbOGVremHyn7pV2qAt_5gh3h1CpCZVLeZgwC6cv7K4IuDmQ8zI0G4xVUzZMY2GO95nY5nWuG1m-hoOt4dcoz77YhotJA5UyE9K46CoX2l4w0b6O6-3pjoKjuZY5jNiL9SgG5qQ46BP-9B?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/4SlkZJqRWExns5gKkr7TqDH884ddN2TPb1Y03Hx2rk8_q4aNTVE_w8Fd0sTXk3bgxbgOR7kpIbrNa7LYVCqc9l3G1_A7QNc3pnwrE2DUtmQSJfmW-v0kd-jPc8TE5lTtstD9PkkkyHj3ll3j-mNUDbO_F2O1dJet2iuHKQeaaP80SWcZlB-cjQ1sCs8HM0c0?purpose=fullsize)

**Penetration testing**, or **ethical hacking**, is a proactive cybersecurity activity designed to simulate real-world attacks in an authorized environment.

Brute forcing can be an important part of testing the resilience of **password-based authentication mechanisms**.

The purpose isn't simply to obtain a password.

The objective is to determine whether the organization's authentication controls can withstand realistic attacks.

---

# 15. When Is Brute Forcing Used in a Penetration Test?

## 15.1 Other Avenues Are Exhausted

Initial testing may involve:

- Identifying exposed services
    
- Checking for known vulnerabilities
    
- Testing authentication controls
    
- Reviewing application behavior
    
- Examining configuration weaknesses
    

If these avenues do not provide access, controlled credential testing may be appropriate within the agreed scope.

---

## 15.2 Password Policies Are Weak

Weak password policies increase the likelihood of users selecting predictable passwords.

Examples of weaknesses include:

- Very short passwords
    
- No complexity requirements
    
- No MFA
    
- Password reuse
    
- No rate limiting
    
- Weak account lockout policies
    

A penetration test can demonstrate whether these weaknesses make accounts vulnerable.

---

## 15.3 Specific Accounts Are Targeted

Sometimes testing focuses on particular accounts, especially accounts with elevated privileges.

Examples:

```text
Administrator
Domain Admin
Database Admin
Application Admin
Service Account
```

In an authorized assessment, testing these accounts can help determine whether privileged access is adequately protected.

---

# 16. Brute Force vs Dictionary Attack

This distinction is **very important**.

|Feature|Brute Force|Dictionary Attack|
|---|---|---|
|Approach|Exhaustive guessing|Likely-password guessing|
|Candidate source|Generated combinations|Word/password list|
|Prior knowledge|Usually unnecessary|Useful|
|Speed|Can be slow|Often faster|
|Search space|Potentially enormous|Usually smaller|
|Example|`aaaa → aaab → aaac...`|`password → qwerty → admin...`|

### Easy way to remember

> **Brute force = try everything.**  
> **Dictionary = try likely things.**

---

# 17. Brute Force vs Password Spraying

|Technique|Passwords|Accounts|
|---|--:|--:|
|Brute Force|Many|Usually one/few|
|Password Spraying|Few|Many|
|Reverse Brute Force|One/few known|Many|

### Memory trick

```text
BRUTE FORCE
Many passwords → One account

PASSWORD SPRAYING
Few passwords → Many accounts

REVERSE BRUTE FORCE
Known password → Many accounts
```

---

# 18. Brute Force vs Credential Stuffing

These are also frequently confused.

### Brute Force

The attacker **guesses** credentials.

```text
admin : password1
admin : password2
admin : password3
...
```

### Credential Stuffing

The attacker uses **already leaked credentials**.

```text
john : leakedPassword123
alice : leakedPassword456
```

The difference is the **source of the credentials**.

---

# 19. Factors Affecting Brute-Force Difficulty

A useful way to think about brute-force difficulty is:

```text
Difficulty
    ↑
    │       Strong password
    │           /
    │          /
    │         /
    │        /
    │_______/____________→ Search space
```

The main factors include:

### Target-side factors

- Password length
    
- Password complexity
    
- Password hashing algorithm
    
- Salt usage
    
- Rate limiting
    
- Account lockout
    
- MFA
    
- CAPTCHA
    

### Attacker-side factors

- CPU power
    
- GPU power
    
- Number of machines
    
- Available wordlists
    
- Knowledge of the target
    
- Quality of candidate generation
    

---

# 20. Important Defensive Measures

Understanding brute forcing is equally important for **defenders**.

Organizations can reduce brute-force risk by implementing:

### Strong Password Policies

Encourage long, unique passwords.

### Multi-Factor Authentication

Even if a password is compromised, another authentication factor can prevent unauthorized access.

### Rate Limiting

Restrict how quickly authentication attempts can be made.

### Account Lockout / Temporary Locking

Temporarily prevent additional attempts after repeated failures.

### CAPTCHA

Help distinguish automated activity from legitimate users.

### Monitoring and Alerting

Look for suspicious patterns such as:

```text
100 login attempts
      ↓
Many failures
      ↓
Same source/IP
      ↓
Security alert
```

### Secure Password Storage

Passwords should not be stored as plaintext.

Instead, applications should use appropriate password hashing mechanisms with unique salts.

---

# 21. Key Concepts to Remember

> 🔑 **Brute forcing** = systematic trial and error.

> 📚 **Dictionary attack** = use a list of likely passwords.

> 🔀 **Hybrid attack** = dictionary + modifications.

> 🔓 **Credential stuffing** = use leaked credentials elsewhere.

> 🌧️ **Password spraying** = few passwords against many accounts.

> 🔄 **Reverse brute force** = one known password against many usernames.

> 🗃️ **Rainbow table** = pre-computed password/hash information.

> 🖥️ **Distributed brute force** = divide the workload among multiple systems.

---

# 22. Quick Revision Sheet

```text
                    BRUTE FORCING
                         │
       ┌─────────────────┼─────────────────┐
       │                 │                 │
   Simple BF        Dictionary         Hybrid
       │                 │                 │
   Everything       Wordlist          Wordlist +
                                      modifications

       ┌─────────────────┼─────────────────┐
       │                 │                 │
 Credential         Password          Reverse BF
 Stuffing           Spraying               │
       │                 │             One password
 Leaked creds       Few passwords      → many users
       ↓             → many users

                 Other Technique
                       │
                Rainbow Tables
                       │
                Pre-computed
                hash information

                Distributed BF
                       │
               Multiple systems
                share workload
```

---

# 23. Exam / Interview Points ⭐

### Q: What is brute forcing?

**Answer:**  
Brute forcing is a trial-and-error technique that systematically attempts possible passwords, credentials, or keys until the correct one is found.

### Q: What is a dictionary attack?

**Answer:**  
A dictionary attack uses a predefined list of common words, passwords, or phrases instead of testing every possible combination.

### Q: What is password spraying?

**Answer:**  
Password spraying attempts a small number of commonly used passwords against many accounts.

### Q: What is credential stuffing?

**Answer:**  
Credential stuffing uses previously leaked username/password combinations to attempt authentication against other services.

### Q: What is reverse brute force?

**Answer:**  
Reverse brute force uses a known or suspected password against multiple usernames.

### Q: What makes brute forcing difficult?

**Answer:**  
Long and complex passwords, strong password hashing, salting, rate limiting, account lockout, MFA, and other authentication defenses make brute forcing more difficult.

### Q: Why is MFA effective against brute forcing?

**Answer:**  
MFA adds another authentication factor, meaning knowing the password alone is insufficient to authenticate.

---

# 🧠 Final Takeaway

The most important concept is that **brute forcing relies on systematically trying possibilities**.

The effectiveness of the attack depends on the relationship between:

```text
Search Space
     +
Attacker Resources
     +
Target Defenses
     ↓
Practicality of the Attack
```

For penetration testers, brute forcing can reveal weaknesses in **password policies and authentication controls**. For defenders, understanding these techniques helps in designing stronger authentication systems.

**The core lesson:**

> **The stronger the credentials and the better the authentication defenses, the less practical brute-force attacks become.**