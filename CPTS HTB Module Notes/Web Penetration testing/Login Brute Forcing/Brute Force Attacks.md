![Image](https://images.openai.com/static-rsc-4/NtlhjmmdGB9EcW_g75e8toNiGD_8VBQLoX07Dwz8WvLgd-gaz6KMmGAX-5oxs_rxJ1zGFUL_zOeNcnwi21God6pMBxGacceBgS4yGu4i0nxGlsia9kD2UxmBpWxExe9Enq90VM4wNWXzLFKHrAUgTrROTPIY6p4VAsMXiDNp19T0iXh4UbkxQH2D5PtH6nJm?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/6kC0PA9KAWF6WXE7MldglVuOiO_YaQ3yYz8Bn1FD0FPOdTgDiRRjo_vGxXMaeWvMjryaDAdbtX5m4ECLSo9txrL4JP3zbbkh3LjMPvo592nHlfoHr6FVV6cR1C6vKG-oy7w0viLaKn8-x-BBsj0b27mYhqFEV4pRxZq6zdFNZX6iE94TBfA-cX_iEswwqAUH?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/OpkPtF7J0FPdv82YHrp8fSXNgt2sIUMNaUdHF0v3OWEr86yiNuiHDx2tjdpJaia1c5tbzIIalVnPkzAqznu2ZnUMHFct5m5xxStIMpfvjH_PsxG_099WdDgqtxlrubqm3426ShrR0FKYyaP1CKZq7KCaslaz1KbA_JKL1I9YskINAWQ3UMMvizi2ajh08CNw?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Z17_H6BvvTLS4RHUaAQFNgbMjflgqCM7r8OBSkUW5sMyCYPwV8cp1UB8ycARUAn0xrfl-iMNNIK_lBMXJBaD8xk4llemFzTalrvHLFg3iHVWP0gxj-W08m_a83e5OhtEY1wRSisZl95yTypHXDLGa0AZ6cVZROu62vIybmqNjhsCd0dswyln18C6UXSwfjMc?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/syHMYH6f_XeRBxnqb4700ymBO3uW0MYnQm3JqNd0QhisTnwbw4-8VBB-f0B6ROplDAj1Nx-R92j3o8sBskLR_OleuDjWBrDspCBJNm7JBxZ_PNHIWoHdH5nt9mZdrkeGztT5VVgmr1AZ1K9ZUM5tALwwtLDu0Z5kM86Q9CNb3XYwxZeuzq1ISKa7p9onzFPP?purpose=fullsize)

## 1. The Mathematics Behind Brute Forcing

To truly understand brute-force attacks, you need to understand the **size of the search space**.

The fundamental formula is:

[  
\boxed{\text{Possible Combinations} = \text{Character Set Size}^{\text{Password Length}}}  
]

Or:

```text
Possible Combinations = C^L
```

Where:

- **C** = number of possible characters
    
- **L** = password length
    

---

# 2. Simple Example

Suppose a password contains only lowercase letters:

```text
a b c d ... z
```

There are:

```text
26 possible characters
```

For a **6-character password**:

[  
26^6 = 308,915,776  
]

Approximately:

> **309 million possible combinations**

For an **8-character password**:

[  
26^8 = 208,827,064,576  
]

Approximately:

> **209 billion possible combinations**

### 🚨 Important Observation

Increasing the password from **6 → 8 characters** doesn't merely add two possibilities.

It multiplies the search space enormously.

```text
6 characters
≈ 309 million

        ↓ increase length

8 characters
≈ 209 billion
```

This is why password length is extremely important.

---

# 3. Why the Search Space Grows Exponentially

The exponent is the key.

If:

```text
Character set = 26
```

then:

```text
1 character → 26 possibilities
2 characters → 26²
3 characters → 26³
4 characters → 26⁴
...
12 characters → 26¹²
```

Every additional character multiplies the search space by another **26**.

If you increase the character set, the effect becomes even greater.

---

# 4. Character Sets

The character set determines how many choices are available at every position.

### Lowercase letters

```text
a-z
= 26 characters
```

### Uppercase + lowercase

```text
a-z + A-Z
= 52 characters
```

### Letters + numbers

```text
a-z + A-Z + 0-9
= 62 characters
```

### ASCII-style character set

The provided example uses:

```text
94 possible characters
```

The more characters available, the larger the search space becomes.

---

# 5. Password Length vs Character Set

The two major variables are:

```text
             Search Space
                  │
          ┌───────┴───────┐
          ↓               ↓
      Password          Character
       Length              Set
          │               │
          └───────┬───────┘
                  ↓
          Possible combinations
```

Both can dramatically affect brute-force difficulty.

---

# 6. Important Examples

|Scenario|Length|Character Set|Possible Combinations|
|---|--:|---|--:|
|**Short and Simple**|6|Lowercase `a-z`|`26⁶ = 308,915,776`|
|**Longer but Still Simple**|8|Lowercase `a-z`|`26⁸ = 208,827,064,576`|
|**Adding Complexity**|8|Lower + Uppercase|`52⁸ = 53,459,728,531,456`|
|**Maximum Complexity**|12|Lower + Upper + Numbers + Symbols|`94¹² = 475,920,493,781,698,549,504`|

### ⭐ Memorize these relationships

```text
Increase LENGTH
       ↓
Search space increases exponentially

Increase CHARACTER SET
       ↓
Search space increases exponentially
```

---

# 7. Comparing the Search Spaces

Let's compare the examples.

### 6 lowercase characters

```text
308,915,776
```

### 8 lowercase characters

```text
208,827,064,576
```

### 8 upper + lowercase characters

```text
53,459,728,531,456
```

### 12 characters with 94 possible characters

```text
475,920,493,781,698,549,504
```

The difference is enormous.

### Conceptual visualization

```text
6 lowercase
████

8 lowercase
████████

8 upper + lowercase
████████████████

12 / 94-character set
████████████████████████████████████████
```

The exact proportions aren't represented here; the point is that the search space grows **very rapidly**.

---

# 8. Search Space ≠ Actual Password Difficulty

⚠️ **Very important distinction.**

The mathematical formula assumes that every possible combination is equally likely.

Real passwords often aren't.

For example:

```text
Password = password123
```

may technically exist somewhere within a huge theoretical search space, but an attacker using a dictionary or password list could try it extremely early.

Therefore:

> **The theoretical search space can be enormous while the effective search space is much smaller if the password is predictable.**

This is why **randomness and unpredictability** matter in addition to length.

---

# 9. Computational Power

Search-space size isn't the only factor.

The attacker's **computational power** also matters.

Think of it like this:

```text
Total candidates
       ÷
Guesses per second
       ↓
Approximate attack time
```

More hardware can mean more guesses per second.

Attackers may potentially use:

- CPUs
    
- GPUs
    
- Multiple machines
    
- Cloud computing resources
    
- Distributed systems
    

---

# 10. Basic Computer vs Supercomputer

The material gives two illustrative examples.

### Basic Computer

Approximately:

> **1 million passwords/second**

This can be enough to test relatively small search spaces quickly.

However, larger search spaces become impractical.

The provided example states that an **8-character password using letters and digits** could take approximately **6.92 years** under these assumptions.

---

### Supercomputer

Approximately:

> **1 trillion passwords/second**

This is dramatically faster.

However, even enormous computational power doesn't automatically make extremely large search spaces practical.

The material gives the example that a **12-character password using all ASCII characters** could still take approximately **15,000 years** under the stated assumptions.

---

# 11. Why Hardware Matters

Imagine:

```text
Attack A
1 million guesses/sec

Attack B
1 trillion guesses/sec
```

Attack B can theoretically test:

[  
\frac{10^{12}}{10^6}=10^6  
]

or **1,000,000× as many guesses per second**.

So hardware can drastically reduce attack time.

But:

> **Increasing the search space can still overwhelm even extremely powerful hardware.**

---

# 12. Exponential Complexity vs Hardware

This is the central lesson of the section.

```text
Password gets slightly longer
              ↓
Search space grows exponentially
              ↓
Attacker needs dramatically more attempts
              ↓
Attack takes much longer
```

Even if the attacker upgrades their hardware:

```text
More powerful hardware
        ↓
More guesses/sec
```

a sufficiently large search space can remain impractical.

---

# 13. Average vs Worst-Case Brute Force

Another useful concept:

If the correct password is somewhere in the search space, an exhaustive attack might eventually find it.

But the attacker doesn't necessarily need to test **every** possibility.

If candidates are ordered intelligently, the correct password might appear earlier.

For a uniformly random password, the average number of attempts required is approximately:

[  
\frac{N}{2}  
]

where **N** is the total search space.

The worst case is approximately:

[  
N  
]

attempts.

### Example

If there are:

```text
10,000 possible PINs
```

then:

```text
Worst case ≈ 10,000 attempts
Average ≈ 5,000 attempts
```

This assumes the PIN is uniformly random and candidates are tested without repetition.

---

# 14. 🔢 Cracking the PIN — Lab Concept

The training lab provides a simple example of brute forcing an API endpoint.

The application generates a **random 4-digit PIN**.

It exposes:

```text
/pin
```

The endpoint accepts a PIN as a query parameter.

Conceptually:

```text
GET /pin?pin=XXXX
```

If the supplied PIN is correct:

```text
Success
+
Flag
```

If the PIN is incorrect:

```text
Error
```

### Lab objective

Systematically test:

```text
0000
0001
0002
0003
...
9999
```

until the correct PIN is identified.

> This is appropriate in the provided **authorized Hack The Box lab environment**.

---

# 15. Why a 4-Digit PIN Is Easy to Brute Force

A 4-digit PIN has:

```text
10 possible digits
```

Each position has 10 possibilities.

Therefore:

[  
10^4 = 10,000  
]

possible PINs.

That's a very small search space.

```text
0000 → 9999
```

Only **10,000 possibilities** exist.

---

# 16. Python Lab Script — What It Does

The provided script uses Python's `requests` library to communicate with the lab's HTTP endpoint.

The core logic is:

```text
Start
  ↓
Generate PIN
  ↓
Send HTTP request
  ↓
Check response
  ↓
Correct?
 ├── YES → Print PIN + flag → Stop
 └── NO  → Try next PIN
```

### Important components

```python
for pin in range(10000):
```

This generates:

```text
0 → 9999
```

---

## 16.1 Formatting the PIN

The script uses:

```python
formatted_pin = f"{pin:04d}"
```

This ensures the PIN always has **four digits**.

For example:

```text
7    → 0007
42   → 0042
405  → 0405
4053 → 4053
```

This is important because:

```text
7
```

and

```text
0007
```

represent the same numeric value but aren't necessarily the same string representation expected by an API.

---

# 17. Sending the Request

The script sends a GET request:

```python
response = requests.get(
    f"http://{ip}:{port}/pin?pin={formatted_pin}"
)
```

Conceptually:

```text
Client
  │
  │ GET /pin?pin=0007
  ↓
Lab Server
  │
  ├── Incorrect → Error
  │
  └── Correct → Success + flag
```

---

# 18. Checking the Response

The script checks:

```python
if response.ok and 'flag' in response.json():
```

There are two conditions.

### `response.ok`

Checks whether the HTTP response indicates success.

The material explains this as a successful HTTP status such as **200 OK**.

### `'flag' in response.json()`

The script then checks whether the returned JSON contains a `flag` field.

Conceptually:

```text
HTTP response successful?
       │
       ├── NO → Continue
       │
       └── YES
             ↓
       Does JSON contain flag?
             │
          ┌──┴──┐
         NO    YES
          │      │
       Continue  Stop
```

---

# 19. Understanding the Example Output

The provided output eventually reaches:

```text
Attempted PIN: 4049
Attempted PIN: 4050
Attempted PIN: 4051
Attempted PIN: 4052
Correct PIN found: 4053
Flag: HTB{...}
```

This demonstrates the basic brute-force process.

The script started from:

```text
0000
```

and incremented sequentially until it reached:

```text
4053
```

where the application accepted the PIN.

---

# 20. How Many Attempts Were Needed?

Because the script starts at `0000` and increments by one:

```text
0000
0001
0002
...
4053
```

The number of attempts is:

[  
4053 + 1 = 4054  
]

So the example required **4,054 attempts**.

This is below the theoretical maximum of:

[  
10,000  
]

---

# 21. Why the Lab Is a Good Demonstration

The PIN lab makes the mathematics visible.

We know:

```text
Character set = 10 digits
Password/PIN length = 4
```

Therefore:

[  
10^4 = 10,000  
]

The program can simply enumerate the entire search space.

There are no billions or trillions of possibilities.

---

# 22. Generalizing the PIN Example

The same formula works for different PIN lengths.

|PIN|Possible combinations|
|---|--:|
|1 digit|`10¹ = 10`|
|2 digits|`10² = 100`|
|3 digits|`10³ = 1,000`|
|4 digits|`10⁴ = 10,000`|
|5 digits|`10⁵ = 100,000`|
|6 digits|`10⁶ = 1,000,000`|
|8 digits|`10⁸ = 100,000,000`|

Notice the pattern:

> **Every additional digit multiplies the search space by 10.**

---

# 23. Password vs PIN Search Spaces

Compare:

### 4-digit PIN

[  
10^4=10,000  
]

### 8 lowercase letters

[  
26^8=208,827,064,576  
]

The difference is enormous.

```text
4-digit PIN
10,000
   ↓
Very small search space

8 lowercase letters
208,827,064,576
   ↓
Much larger search space
```

This demonstrates why **character set and length both matter**.

---

# 24. ⚠️ Important Real-World Difference

The lab is intentionally simple.

Real authentication systems may have defenses such as:

- Rate limiting
    
- Account lockouts
    
- CAPTCHA
    
- MFA
    
- IP restrictions
    
- Detection and alerting
    
- Request throttling
    
- Temporary authentication blocks
    

Therefore, being able to brute-force a 4-digit PIN in a controlled lab **does not mean a real-world login system can necessarily be brute-forced in the same way**.

---

# 25. Key Formula Sheet 🧠

### Fundamental formula

[  
\boxed{N=C^L}  
]

Where:

- `N` = total possible combinations
    
- `C` = character set size
    
- `L` = password length
    

### Average exhaustive-search attempts

[  
\boxed{\text{Average} \approx \frac{N}{2}}  
]

### Worst-case attempts

[  
\boxed{\text{Worst Case} = N}  
]

### Approximate attack time

[  
\boxed{\text{Time} \approx \frac{\text{Number of guesses}}{\text{Guesses per second}}}  
]

These formulas are useful for understanding the **theoretical feasibility** of brute-force attacks.

---

# 26. ⭐ Most Important Things to Memorize

```text
1. Possible Combinations = Character Set Size ^ Password Length

2. Increasing password length increases the search space exponentially.

3. Increasing the character set also increases the search space exponentially.

4. More computational power = more guesses per second.

5. A huge search space can remain impractical even with powerful hardware.

6. A 4-digit PIN has only:
   10^4 = 10,000 possibilities.

7. A brute-force program systematically tests candidates until success.

8. Real-world authentication systems can use:
   MFA + rate limiting + lockouts + monitoring
   to make brute-force attacks much harder.

9. Theoretical search space isn't the same as effective difficulty:
   predictable passwords can often be found much earlier.

10. Brute-force testing should only be performed against systems
    you are explicitly authorized to test.
```

---

# 🎯 Final Mental Model

```text
             BRUTE FORCE
                  │
                  ↓
        Determine Search Space
                  │
          ┌───────┴────────┐
          ↓                ↓
   Character Set       Password Length
          │                │
          └───────┬────────┘
                  ↓
             C^L combinations
                  │
                  ↓
        Attacker's Hardware
                  │
                  ↓
        Guesses / Second
                  │
                  ↓
        Estimated Attack Time
                  │
          ┌───────┴────────┐
          ↓                ↓
      Practical         Impractical
          │
          ↓
    Target Defenses
   MFA / Rate limits /
   Lockouts / Monitoring
```

### 🔑 The one sentence to remember:

> **Brute-force difficulty is fundamentally a race between the size of the search space and the attacker's ability to test candidates, while real-world defenses can drastically reduce the number of attempts an attacker can make.**