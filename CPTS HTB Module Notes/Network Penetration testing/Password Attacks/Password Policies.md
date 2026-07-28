# What is a Password Policy?

A **Password Policy** is a **set of rules and guidelines** designed to improve security by ensuring users create and manage passwords according to an organization's security standards.

A password policy is **not just about creating passwords**. It covers the **entire password lifecycle**, including:

- Password Creation
    
- Password Storage
    
- Password Management
    
- Password Transmission
    

---

# Why Do We Need Password Policies?

Imagine driving without traffic rules.

```text
No Speed Limits
       │
       ▼
Accidents
Chaos
Unsafe Roads
```

Similarly,

without password policies:

```text
No Password Rules
        │
        ▼
Weak Passwords
Password Reuse
Easy Attacks
Compromised Accounts
```

Password policies exist to **protect users and organizations** from weak authentication practices.

---

# Example Scenario

Meet **Mark**, a new employee at **Inlanefreight Corp**.

Mark creates the password:

```text
password123
```

The system rejects it because it does **not satisfy the organization's password policy**.

He later creates

```text
Inlanefreight01!
```

The password is accepted.

However...

Although it follows the policy,

it is still weak because it contains the **company name**, which attackers commonly guess.

---

# Password Policy Components

A successful password policy has **two major parts**.

```text
          Password Policy
                │
      ┌─────────┴─────────┐
      │                   │
      ▼                   ▼
 Definition          Enforcement
      │                   │
Rules & Standards   Technology
```

---

## 1. Definition

Defines:

- Password length
    
- Complexity
    
- Expiration
    
- Blacklisted words
    
- Other requirements
    

---

## 2. Enforcement

Technology ensures users **cannot bypass the policy**.

Examples:

- Active Directory
    
- Identity Providers
    
- Applications
    

---

# Password Policy Lifecycle

A password policy covers more than password creation.

```text
Password Lifecycle

     Create
        │
        ▼
      Store
        │
        ▼
     Manage
        │
        ▼
    Transmit Securely
```

---

# Password Policy Standards

Many organizations follow established security standards.

The HTB material lists:

- **NIST SP800-63B**
    
- **CIS Password Policy Guide**
    
- **PCI DSS**
    

These standards provide guidance for creating secure password policies but **compliance alone does not guarantee security**.

---

# Password Expiration

Historically,

many organizations required passwords to be changed every:

```text
90 Days
```

Modern guidance has changed.

The HTB material explains that many organizations now **disable routine password expiration**, because users often create predictable passwords such as:

```text
Password01!

↓

Password02!

↓

Password03!
```

This weakens security instead of improving it.

---

# Sample Password Policy

The example policy requires passwords to:

✔ Minimum **8 characters**

✔ Uppercase letters

✔ Lowercase letters

✔ At least **one number**

✔ At least **one special character**

✔ Must **not be the username**

✔ Changed every **60 days**

---

Diagram

```text
Password Requirements

Minimum Length
      │
      ▼
8 Characters

──────────────

Uppercase

Lowercase

Numbers

Special Characters

Not Username

60-Day Expiration
```

---

# Why Policies Alone Are Not Enough

Example:

```text
Password:

Inlanefreight01!
```

Policy:

✔ 8+ characters

✔ Uppercase

✔ Lowercase

✔ Number

✔ Symbol

But attackers often try:

```text
CompanyName01!

CompanyName2025!

CompanyName123!
```

Therefore,

meeting complexity requirements **does not always mean a password is strong**.

---

# Password Mutation

Users commonly modify passwords in predictable ways.

Example

```text
Inlanefreight01!

↓

Inlanefreight02!

↓

Inlanefreight03!
```

This still satisfies the policy,

but is easy for attackers to guess.

---

Diagram

```text
Original Password

↓

Change Numbers

↓

Policy Passed

↓

Still Weak
```

---

# Blacklisted Words

A password policy should reject passwords containing predictable words.

The HTB material recommends blacklisting:

### Company Information

- Company Name
    
- Company-related words
    

---

### Calendar Words

- Month names
    
- Season names
    

---

### Common Password Words

- welcome
    
- password
    
- password123
    
- 123456
    
- abcde
    

---

Diagram

```text
Blacklist

      │
 ┌────┼───────────────┐
 │    │               │
 ▼    ▼               ▼

Company

Months

Common Passwords
```

---

# Password Policy Enforcement

A password policy is useless unless it is enforced.

Technology ensures users follow the rules.

---

# Active Directory

Organizations using Active Directory can enforce password policies through

```text
Group Policy Object (GPO)
```

Diagram

```text
Administrator

        │

Configure GPO

        │

Active Directory

        │

Users

        │

Password Policy Enforced
```

---

# Beyond Technology

The HTB material explains that enforcement also requires:

✔ Communicating the policy to employees

✔ Creating organizational processes

✔ Applying the policy consistently across systems

---

Diagram

```text
Password Policy

      │

Technology

      │

Employees

      │

Processes

      │

Organization
```

---

# Creating Strong Passwords

Creating a strong password doesn't have to be difficult.

The HTB material references tools such as:

- PasswordMonster
    
- 1Password Password Generator
    

These tools help users:

- Generate passwords
    
- Evaluate password strength
    

---

# Example Strong Password

Generated password:

```text
CjDC2x[U
```

Characteristics:

✔ Uppercase

✔ Lowercase

✔ Numbers

✔ Symbols

Estimated crack time:

```text
~1000 Years
```

(as shown in the HTB example).

---

Diagram

```text
Strong Password

CjDC2x[U

↓

Uppercase

Lowercase

Numbers

Symbols

↓

Very Strong
```

---

# Using Passphrases

Instead of random characters,

the HTB material suggests using long phrases.

Example

```text
This is my secure password
```

Another example

```text
The name of my dog is Popy
```

These are easier to remember and still provide strong security because of their length.

---

# Improve a Passphrase

Adding symbols increases complexity.

Example

```text
()The name of my dog is Popy!
```

Diagram

```text
Simple Phrase

↓

Add Symbols

↓

Long Password

↓

Harder to Crack
```

---

# OSINT Warning

Even long passphrases can become weak if they contain personal information.

Attackers can collect information using

```text
OSINT
```

(Open Source Intelligence).

Example

If your dog's name is publicly visible on social media,

the password

```text
The name of my dog is Popy
```

may become guessable.

---

Diagram

```text
Social Media

↓

Dog Name

↓

OSINT

↓

Password Guess
```

---

# Password Managers

As users accumulate many unique passwords,

remembering them becomes difficult.

The HTB material notes that password managers help by:

✔ Generating passwords

✔ Securely storing passwords

This topic is introduced as the next section.

---

# Complete Password Policy Workflow

```text
Organization

↓

Create Policy

↓

Define Rules

↓

Configure Technology

↓

Enforce Policy

↓

Educate Users

↓

Strong Passwords

↓

Better Security
```

---

# Good vs Weak Passwords

|Weak|Strong|
|---|---|
|password123|CjDC2x[U|
|Company01!|Long passphrase|
|Welcome123|Unique random password|
|Password02!|Password manager generated|

(The examples reflect the concepts discussed in the HTB material.)

---

# Best Practices from the HTB Material

✔ Use long passwords

✔ Avoid company names

✔ Avoid months and seasons

✔ Avoid predictable words

✔ Avoid password mutations

✔ Consider using memorable passphrases

✔ Use password managers for many accounts

---

# Important Concepts

### Password Policy

Rules governing password creation and management.

---

### Enforcement

Technology that forces users to follow the policy.

---

### Password Lifecycle

```text
Create

↓

Store

↓

Manage

↓

Transmit
```

---

### Password Mutation

```text
Password01

↓

Password02

↓

Password03
```

---

### Blacklist

Reject passwords containing predictable words.

---

### Passphrase

Long, memorable sentence used as a password.

---

### OSINT

Publicly available information that attackers can use to guess passwords.

---

# HTB Exam Tips

✅ A password policy covers the **entire password lifecycle**, not just creation.

✅ Two key components are **definition** and **enforcement**.

✅ Common standards mentioned are:

- NIST SP800-63B
    
- CIS Password Policy Guide
    
- PCI DSS
    

✅ The HTB material notes that many organizations now avoid routine password expiration because it often leads to predictable password changes.

✅ Blacklist company names, months, seasons, and common passwords.

✅ Active Directory can enforce password policies using **Password Policy GPOs**.

✅ Long passphrases are easier to remember and can be highly secure.

✅ Be cautious about using personal information in passphrases due to **OSINT** risks.

---

# 🚀 1-Minute Revision Sheet

```text
PASSWORD POLICY

        │
        ▼
Definition
+
Enforcement

────────────────────

Password Lifecycle

Create
↓

Store
↓

Manage
↓

Transmit

────────────────────

Requirements

8+ Characters

Uppercase

Lowercase

Number

Special Character

Not Username

────────────────────

Blacklist

Company Name

Months

Seasons

Password

123456

────────────────────

Avoid

Password Mutation

Company Words

Personal OSINT

────────────────────

Enforcement

Active Directory

GPO

────────────────────

Strong Passwords

Random

Passphrases

Password Managers
```

These notes are based solely on the content of your uploaded HTB Academy material. The terminology, examples, and guidance (including the sample policy, discussion of password expiration, and passphrase examples) are preserved from the source, with additional diagrams and structured formatting for easier study.