![Image](https://images.openai.com/static-rsc-4/3Mas-zi8lov1TGsP71uxRrcxJDyi4wiA-4Y2ce2nRdWbY71NTh0bmrPptlc9CPdqpNtI-HjZU_C3qVm7kyfT2j6QLEw1ajHsPUhytdFPqT0FxyNkISIxUcePokFQxs3ZRhL5CPPtiblaJfKuXt5nAB6cVG2TVLfNLaorvTO9nwColgPCBIr3d95Re1llGjUc?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/dL9Ey8AJyCTmzs-1ESFjvlDLej5g4Mknd7DUw-bft8g5UhYWzfq1FjLpXjSvTIGXt8i2f5mYli05vsUfY__Y4Bddnk5mYq1NM_G8nBU4goWYkR58FdpZajzS6QH4KaVPFolQgwif8b8sed46J01ljy3Cm8Ca_29KIakCDfpk7MaNwYebpyskcQrO2wIBoohD?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/s2jcSusOrQBxMu4ovnGNiyuK_ZA199HJH1GaTMgx5zFWtQlCk13Tn1OtR-JZ8nEbfRZYGAZ5GfUV06vDcJecfTMsjaaaY__4l_NyVVoclww_mWmkAPmHHWSxuxN5qqWBMo8686lw1i-x0jON9Bu4pxgJrPmFyMtwkEDad6mfH_tHbCLAFpiIe1PxBTcZPpfh?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/1YuH1F68yI84t1Zu1Y5i8K63PLBfh6_xX-_d8o4fhftZ6JbPDbwRjYXQwNlPg6va30gf64QN3NOwDmqCLY6hVKfpfCQI91Gu4hJwIm7M9ERqd04ECf9sBBbcvcYW5pSgo3zNKB_z2omyl7xvxDoPZ6p6mF85zwmGqVvqjkXFFVFBuku-sDm_lgvrIEHWADuP?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/rPRc1oU0TgXzhI2qdzCJMgbfVSUXe8ewMMFlUOK7XJxtFoQIx-Vm2rhBRzn9us9FLSCbvsmtg8s_-FFkSNkgGsbFZ289P-jCswkiVuwpjDzULSmS8a1nPjhh4ZKKZvQYguS8MfNlBIFtnuLLNP8T3gtR7ULbE1wPDXtzFFu2j4zVSbm3D-_zhsqAAzoKHsyG?purpose=fullsize)

## 1. What Is a Dictionary Attack?

A **dictionary attack** is a password-guessing technique that uses a **predefined list of likely passwords** rather than trying every possible character combination.

The basic idea is:

```text
Wordlist
   ↓
Password 1 → Try
Password 2 → Try
Password 3 → Try
Password 4 → Try
   ↓
Correct password?
   ├── NO → Continue
   └── YES → Success
```

### Core idea ⭐

> **Brute force tries possibilities. Dictionary attacks prioritize likely possibilities.**

This makes dictionary attacks much faster when the target uses a common or predictable password.

---

# 2. Why Dictionary Attacks Work

Dictionary attacks exploit an important human behavior:

> **People often choose passwords that are memorable rather than truly unpredictable.**

Common password choices may be based on:

- Dictionary words
    
- Names
    
- Common phrases
    
- Sports
    
- Hobbies
    
- Favorite things
    
- Company names
    
- Keyboard patterns
    
- Simple numbers
    
- Common password variations
    

For example:

```text
password
password123
qwerty
football
tiger
welcome
```

These passwords may be much easier to discover using a wordlist than through pure brute force.

---

# 3. The Power of Words

Imagine a theoretical password search space containing billions of possibilities.

A pure brute-force attack might have to consider:

```text
aaaa
aaab
aaac
aaad
...
```

A dictionary attack instead starts with likely candidates:

```text
password
123456
qwerty
admin
welcome
football
tiger
```

If the target selected one of these common passwords, the correct password could be discovered extremely early.

### Therefore:

```text
Huge theoretical search space
             ↓
Human chooses predictable password
             ↓
Password appears in wordlist
             ↓
Small effective search space
             ↓
Fast discovery
```

---

# 4. Wordlist Quality Matters ⭐

The effectiveness of a dictionary attack depends heavily on the **quality of the wordlist**.

A generic wordlist might contain:

```text
password
123456
qwerty
admin
welcome
```

But a specialized wordlist could contain terminology relevant to the target.

### Example: Gaming-related target

A generic list:

```text
password
welcome
admin
```

A gaming-oriented list could contain:

```text
gaming terms
game titles
character names
player terminology
popular gaming phrases
```

If the target audience consists heavily of gamers, the specialized list may have a higher probability of containing passwords based on those interests.

---

# 5. Targeted Wordlists

A **targeted wordlist** is created or selected specifically for the target environment.

For example, in an **authorized penetration test**, information discovered during reconnaissance might include:

```text
Company name
Department names
Public project names
Technology names
Industry terminology
Publicly known organizational information
```

A tester could use relevant information to create candidate passwords.

### Concept

```text
Target information
       ↓
Likely password patterns
       ↓
Custom wordlist
       ↓
Dictionary attack
```

⚠️ This should only be performed with explicit authorization.

---

# 6. Brute Force vs Dictionary Attack ⭐⭐⭐

This is one of the most important distinctions in the module.

## Brute Force

A pure brute-force attack systematically tests **every possible combination** within a defined search space.

```text
aaaa
aaab
aaac
aaad
...
zzzz
```

### Characteristics

- Broad
    
- Exhaustive
    
- Doesn't necessarily rely on human behavior
    
- Can eventually find a password if the search space is fully covered
    
- Can become extremely expensive for long/complex passwords
    

---

## Dictionary Attack

A dictionary attack uses a **precompiled list of likely passwords**.

```text
password
123456
qwerty
welcome
football
tiger
...
```

### Characteristics

- Targeted
    
- Faster when passwords are predictable
    
- Depends heavily on wordlist quality
    
- Does not guarantee success
    
- Can fail completely against a truly random password that isn't in the list
    

---

# 7. Side-by-Side Comparison

|Feature|Dictionary Attack|Brute Force Attack|
|---|---|---|
|**Efficiency**|Generally faster and more resource-efficient|Can be extremely time-consuming|
|**Search Space**|Limited to wordlist entries|Potentially enormous|
|**Targeting**|Can be highly targeted|No inherent targeting|
|**Effectiveness**|Excellent against common/predictable passwords|Works against any password if enough time/resources are available|
|**Wordlist Required**|Yes|No|
|**Random Passwords**|Usually ineffective|Theoretically effective|
|**Resource Requirements**|Usually lower|Can become extremely high|
|**Main Weakness**|Depends on password appearing in the list|Search space can become impractical|

---

# 8. Easy Way to Remember

```text
BRUTE FORCE
────────────────────────
Try everything.

aaaa
aaab
aaac
...
zzzz
```

```text
DICTIONARY
────────────────────────
Try likely things.

password
123456
qwerty
admin
welcome
```

### 🧠 Memory trick

> **Brute force = exhaustive.**  
> **Dictionary = selective.**

---

# 9. Efficiency

Dictionary attacks can be **considerably faster** than pure brute force when the target uses a common password.

Why?

Because the attacker doesn't need to search the entire theoretical space.

### Example

Suppose the theoretical search space contains:

```text
100 billion possibilities
```

But a wordlist contains:

```text
500 likely passwords
```

The dictionary attack only tests those 500 candidates.

If the target password is among them, it can be discovered extremely quickly compared with exhaustive search.

---

# 10. Targeting

Dictionary attacks are particularly powerful because wordlists can be **customized**.

For example, during an authorized assessment of a fictional company:

```text
Company: TechCorp
Industry: Gaming
Departments:
Development
Marketing
Support
```

A tester might create a targeted candidate list based on authorized reconnaissance.

The idea is:

```text
Generic wordlist
       ↓
Likely passwords

Targeted wordlist
       ↓
Likely passwords specifically relevant
to the target
```

---

# 11. Effectiveness

Dictionary attacks are especially effective against:

- Common passwords
    
- Short passwords
    
- Dictionary words
    
- Common phrases
    
- Passwords based on hobbies
    
- Passwords based on names
    
- Predictable variations
    

However, they are much less effective against genuinely random passwords.

### Example

A password such as:

```text
tiger
```

has a good chance of appearing in a wordlist.

A randomly generated password such as:

```text
v7#Qm2!xP9@L
```

is much less likely to appear in a traditional dictionary.

---

# 12. Limitations

Dictionary attacks are **not guaranteed to work**.

The biggest limitation is:

> **The correct password must be present in the wordlist, or the wordlist must contain a useful candidate that matches the target's password pattern.**

For example:

```text
Wordlist:
password
qwerty
admin
welcome
football
```

Target:

```text
8z!Qp7#Lm2
```

The dictionary attack will fail because the password isn't represented by the list.

---

# 13. Truly Random Passwords

A genuinely random password can defeat a basic dictionary attack because attackers cannot rely on human predictability.

Compare:

```text
Weak:
football123
```

with:

```text
Random:
rT7#kP2!vX9@
```

The second password is much less likely to appear directly in a common wordlist.

### Important distinction

A password can be **complex-looking but predictable**.

For example:

```text
P@ssw0rd123
```

looks complicated but uses a well-known substitution pattern.

Therefore:

> **Unpredictability matters more than simply adding a symbol or number.**

---

# 14. Building and Obtaining Wordlists

Wordlists can come from several sources.

## 14.1 Publicly Available Lists

There are publicly available password lists containing:

- Common passwords
    
- Frequently used credentials
    
- Previously exposed passwords
    
- Default credentials
    
- Usernames
    

One widely used collection in penetration-testing environments is **SecLists**.

[SecLists Passwords repository](https://github.com/danielmiessler/SecLists/tree/master/Passwords?utm_source=chatgpt.com)

---

# 15. Custom-Built Wordlists

Penetration testers can create wordlists specifically for an authorized engagement.

Sources of candidate information can include legitimate reconnaissance findings such as:

- Organization terminology
    
- Public project names
    
- Industry terminology
    
- Publicly known names
    
- Application-specific terminology
    

### Workflow

```text
Reconnaissance
      ↓
Relevant information
      ↓
Candidate password ideas
      ↓
Custom wordlist
      ↓
Authorized testing
```

---

# 16. Specialized Wordlists

Specialized wordlists focus on a particular context.

Examples might target:

- A particular industry
    
- A specific application
    
- A technology
    
- Default device credentials
    
- Common usernames
    
- Common passwords
    

The advantage is that irrelevant candidates can be removed while relevant candidates are prioritized.

---

# 17. Pre-existing Wordlists

Penetration-testing distributions often include commonly used wordlists.

One famous example is:

```text
rockyou.txt
```

It contains a very large collection of passwords originating from a historical password breach.

### Why is `rockyou.txt` important?

It is commonly used in security training and password auditing because it contains many real-world password choices.

⚠️ Use such lists only in authorized testing environments.

---

# 18. Important Wordlists

The provided material highlights these useful examples:

|Wordlist|Purpose|
|---|---|
|`rockyou.txt`|Large collection of leaked/common passwords|
|`top-usernames-shortlist.txt`|Common usernames|
|`xato-net-10-million-usernames.txt`|Large username collection|
|`2023-200_most_used_passwords.txt`|Commonly used passwords|
|`Default-Credentials/default-passwords.txt`|Default usernames/passwords|

### Categories

```text
PASSWORD LISTS
       │
 ┌─────┼──────────────┐
 ↓     ↓              ↓
Common Leaked     Default
passwords passwords credentials

USERNAME LISTS
       │
 ┌─────┴─────────────┐
 ↓                   ↓
Common usernames   Large username sets
```

---

# 19. `rockyou.txt`

`rockyou.txt` is one of the most recognizable password wordlists in cybersecurity training.

Its importance comes from the fact that it contains passwords from the historical **RockYou data breach**.

It is commonly used for:

- Password auditing
    
- Security labs
    
- Penetration-testing exercises
    
- Hash-cracking demonstrations
    

It should not be interpreted as a list of every possible password.

Instead, it represents **real-world password choices**.

---

# 20. Username Wordlists

Dictionary-style attacks aren't necessarily limited to passwords.

Username lists can also be useful during authorized authentication testing.

Examples:

```text
admin
administrator
root
user
guest
test
```

A username wordlist can be combined with password candidates.

Conceptually:

```text
Username candidates
        +
Password candidates
        ↓
Credential candidates
```

---

# 21. The HTB Dictionary Attack Lab

![Image](https://images.openai.com/static-rsc-4/3Mas-zi8lov1TGsP71uxRrcxJDyi4wiA-4Y2ce2nRdWbY71NTh0bmrPptlc9CPdqpNtI-HjZU_C3qVm7kyfT2j6QLEw1ajHsPUhytdFPqT0FxyNkISIxUcePokFQxs3ZRhL5CPPtiblaJfKuXt5nAB6cVG2TVLfNLaorvTO9nwColgPCBIr3d95Re1llGjUc?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/qH2kGt3Mn5BzEBk8kGsttimbtTwa_A45DjRSZego_rIgO_w9OWsquD5Tl2pIVfbhFECvnQ06Q1Cz3SyT2KnrKPYvqL1cnnt-XsK8dcsfYsFsaD1fSXas5ADtCu0e-bPEyJisfNaSEM3Dsd9bNUL8AINyCkFDTOec3yV-Ucp9qciy9vW8th5AESnzp2i1_Hhe?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/mD4aK0LVLpTnvt4HfhcIx8nEyTC2zQ7bJjZ7zjBAM5Hh101O4Eulu4kzkRU-k0X6WtgxbBs3D4hSx8wLfDh-IaTIfXRtoFqaxvnJLT2lACBHn5_pZcPY8s0_TohyJECqQKbZsHhkBUplBuaT_u9pZiry3evVRydNMIxk1LRQ_Mw7w9xgYPAsb-N1A-qBj--F?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/8gWJ6p4PwGgJiFNk0ZY9aR8tfiQpQdG0JxeNWR1HDM1vjNSoyhKFg5aY9NRaSdEc48NTSiH5MgEbOLCQQaEo6Dq5Od6I7rXrI_id6LgofqkJAzzTSbCqgXe8fHimZ1ilySHTklLG-PWYoXQjRoaELHMJEgCwGY37UGZp7jQreOhm_v7g5WaHljkdVUWe4cMr?purpose=fullsize)

The provided lab demonstrates a dictionary attack against an **authorized HTB target**.

The target application exposes:

```text
/dictionary
```

The application accepts a password through a POST request.

The goal is to identify the correct password from the supplied wordlist and retrieve the lab flag.

---

# 22. Python Script — High-Level Logic

The supplied script follows this process:

```text
Start
  ↓
Download wordlist
  ↓
Read passwords line-by-line
  ↓
Try password
  ↓
POST /dictionary
  ↓
Check response
  ↓
Flag present?
 ├── YES → Print password + flag → Stop
 └── NO  → Try next password
```

---

# 23. Step 1 — Import `requests`

The script begins with:

```python
import requests
```

`requests` is a Python library used to make HTTP requests.

In this lab it allows the script to communicate with the web application.

Conceptually:

```text
Python script
      ↓
HTTP request
      ↓
HTB lab server
      ↓
HTTP response
      ↓
Python script
```

---

# 24. Step 2 — Target Configuration

The script defines:

```python
ip = "127.0.0.1"
port = 1234
```

These are placeholders.

For the HTB instance, they need to correspond to the **IP address and port of the authorized lab target**.

---

# 25. Step 3 — Download the Wordlist

The script retrieves a wordlist from SecLists:

```python
passwords = requests.get(
    "..."
).text.splitlines()
```

The important concepts are:

### `requests.get()`

Downloads the resource.

### `.text`

Gets the response body as text.

### `.splitlines()`

Splits the text into individual lines.

So conceptually:

```text
Online wordlist
      ↓
Downloaded text
      ↓
splitlines()
      ↓
["password1", "password2", "password3", ...]
```

---

# 26. Step 4 — Iterate Through Passwords

The script uses:

```python
for password in passwords:
```

This means:

> Take each password from the wordlist one at a time.

For example:

```text
Password #1 → password
Password #2 → 123456
Password #3 → qwerty
Password #4 → welcome
...
```

---

# 27. Step 5 — Display the Attempt

The script prints:

```python
print(f"Attempted password: {password}")
```

This allows the tester to see progress.

Example:

```text
Attempted password: turtle
Attempted password: tiffany
Attempted password: golf
Attempted password: bear
Attempted password: tiger
```

---

# 28. Step 6 — Send the POST Request

The script sends the candidate password to:

```text
/dictionary
```

using a POST request.

Conceptually:

```text
POST /dictionary

password=tiger
```

The Flask application receives the candidate and determines whether it is correct.

---

# 29. Step 7 — Analyze the Response

The script checks:

```python
if response.ok and 'flag' in response.json():
```

This means it is looking for:

1. A successful HTTP response
    
2. A JSON response containing a `flag`
    

If both conditions are satisfied, the password was correct for the lab.

---

# 30. Step 8 — Stop When Successful

Once the correct password is discovered:

```python
print(f"Correct password found: {password}")
print(f"Flag: {response.json()['flag']}")
break
```

The important part is:

```python
break
```

It terminates the loop.

There is no reason to continue testing passwords once the correct one has been found.

---

# 31. Understanding the Example Output

The lab output looks like:

```text
Attempted password: turtle
Attempted password: tiffany
Attempted password: golf
Attempted password: bear
Attempted password: tiger
Correct password found: ...
Flag: HTB{...}
```

This demonstrates the entire dictionary attack:

```text
Wordlist
   ↓
turtle → wrong
   ↓
tiffany → wrong
   ↓
golf → wrong
   ↓
bear → wrong
   ↓
tiger → correct
   ↓
Flag
```

---

# 32. Dictionary Attack vs PIN Brute Force

This connects directly to the previous section.

### PIN brute force

```text
0000
0001
0002
0003
...
9999
```

The program generates candidates mathematically.

### Dictionary attack

```text
password
123456
qwerty
turtle
tiffany
golf
bear
tiger
```

The program gets candidates from a **wordlist**.

### ⭐ Main difference

```text
BRUTE FORCE
Generate candidates

DICTIONARY
Retrieve candidates
```

---

# 33. Why the Dictionary Attack Can Be Much Faster

Suppose the target password is:

```text
tiger
```

A dictionary might contain:

```text
...
turtle
tiffany
golf
bear
tiger
...
```

The password could be discovered after only a small number of attempts.

A pure brute-force attack would have to potentially search through an enormous character space before reaching the same string.

### Therefore:

> **Dictionary attacks trade completeness for efficiency.**

---

# 34. Dictionary Attack — Complete Workflow

```text
                 TARGET
                   │
                   ↓
           Understand context
                   │
                   ↓
            Select wordlist
                   │
        ┌──────────┴──────────┐
        ↓                     ↓
   Generic list          Targeted list
        │                     │
        └──────────┬──────────┘
                   ↓
           Test candidates
                   ↓
           Analyze responses
                   ↓
          ┌────────┴────────┐
          ↓                 ↓
       Success            Failure
          │                 │
          ↓                 ↓
     Stop testing      Next candidate
```

---

# 35. Defensive Perspective 🛡️

Understanding dictionary attacks also tells defenders what they need to protect against.

### Avoid common passwords

Don't use passwords likely to appear in popular wordlists.

### Use unique passwords

Password reuse allows attackers to leverage credentials obtained elsewhere.

### Use long passwords/passphrases

Longer credentials increase the search space.

### Use MFA

Even if a password is guessed, MFA can provide another barrier.

### Rate-limit authentication

Reduce the number of attempts that can be made within a given period.

### Detect unusual authentication behavior

Monitor:

- Large numbers of failed logins
    
- Repeated attempts
    
- Unusual IP addresses
    
- Multiple accounts being targeted
    
- Automated-looking traffic
    

---

# 36. 🧠 Most Important Concepts

### Dictionary Attack

> Uses a predefined list of likely passwords.

### Wordlist

> A collection of candidate passwords or usernames.

### Targeted Wordlist

> A wordlist tailored to information relevant to a particular authorized target.

### `rockyou.txt`

> A widely used password wordlist derived from passwords exposed in the historical RockYou breach.

### Brute Force

> Attempts combinations systematically across a defined search space.

### Dictionary

> Attempts likely candidates from a predefined list.

### Key limitation

> If the password isn't represented by the wordlist, a basic dictionary attack won't find it.

---

# 🎯 Final Mental Model

```text
             DICTIONARY ATTACK
                    │
                    ↓
              Human Behavior
                    │
                    ↓
       People choose memorable passwords
                    │
                    ↓
        Predictable password patterns
                    │
                    ↓
              Create Wordlist
                    │
          ┌─────────┴─────────┐
          ↓                   ↓
      Generic              Targeted
      Wordlist             Wordlist
          │                   │
          └─────────┬─────────┘
                    ↓
             Test candidates
                    │
                    ↓
             Analyze response
                    │
             ┌──────┴──────┐
             ↓             ↓
          Correct        Incorrect
             │             │
             ↓             ↓
          Success      Next candidate
```

### 🔑 One-line takeaway

> **A dictionary attack is an efficient, targeted password-guessing technique that exploits human predictability by testing likely passwords from a wordlist instead of attempting every possible combination.**

And the key comparison to keep in your HTB notes:

> **Brute force = complete search of possibilities.**  
> **Dictionary attack = intelligent search of likely possibilities.**