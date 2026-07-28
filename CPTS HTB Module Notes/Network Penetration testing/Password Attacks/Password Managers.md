# What is a Password Manager?

A **Password Manager** is an application that securely stores passwords and other sensitive information inside an **encrypted database (vault)**.

Instead of remembering hundreds of passwords, users only need to remember **one master password**.

---

# Why Do We Need Password Managers?

Today almost everything requires a password:

- Home Wi-Fi
    
- Social Media
    
- Banking
    
- Business Email
    
- Shopping Websites
    
- Cloud Services
    
- Mobile Apps
    

According to the HTB material (referencing a NordPass study), **the average person has around 100 passwords**, making password reuse or weak passwords much more likely.

---

# The Password Problem

```text
                Internet

        Facebook
        Gmail
        Bank
        Amazon
        GitHub
        Netflix
        Wi-Fi
        Work Email
        VPN
        Cloud

              │
              ▼

      Hundreds of Passwords

              │

Remember All?

              │

        Almost Impossible
```

---

# Solution

```text
          Password Manager

                 │

        Master Password

                 │

     Encrypted Password Vault

                 │

  ┌──────────────┼──────────────┐
  │              │              │

 Gmail        Banking       Social Media

  │              │              │

 Auto Fill   Auto Login   Strong Passwords
```

---

# Benefits of Password Managers

Password Managers provide much more than password storage.

They commonly include:

✔ Password Storage

✔ Password Generator

✔ Two-Factor Authentication (2FA)

✔ Browser Integration

✔ Secure Form Filling

✔ Multi-device Synchronization

✔ Security Alerts

✔ Secure Notes

---

# Password Manager Architecture

```text
             User

               │

      Master Password

               │

       Encryption Engine

               │

      Encrypted Database

               │

   ┌───────────┼────────────┐

 Passwords   Secure Notes   Cards

               │

        Browser Extension

               │

         Auto Login
```

---

# How Password Managers Work

Most password managers work using a **Master Password**.

The Master Password is **never stored directly**.

Instead,

it is used to derive cryptographic keys.

---

# Simplified Workflow

```text
Master Password

        │

Key Derivation Function (KDF)

        │

Master Key

        │

AES Encryption

        │

Encrypted Vault

        │

Passwords
```

---

# Important Components

According to the HTB material, cloud password managers generally use three important components:

---

## 1. Master Key

Derived from

```text
Master Password
```

using a

```text
Key Derivation Function (KDF)
```

Purpose

Encrypt the vault.

---

## 2. Master Password Hash

Generated from

```text
Master Password
```

Purpose

Authenticate the user to the cloud service.

---

## 3. Decryption Key

Generated using

```text
Master Key
```

Purpose

Decrypt stored vault items.

---

# Password Manager Workflow

```text
Master Password

        │

PBKDF2 / KDF

        │

Master Key

        │

Authentication

        │

AES-256

        │

Encrypted Vault

        │

Passwords
```

---

# Zero-Knowledge Encryption

One of the most important concepts.

Definition

The service provider **cannot read your passwords**.

Only the user possessing the Master Password can decrypt the vault.

---

Diagram

```text
           Cloud

             │

Encrypted Vault

             │

Provider Cannot Read

             │

      Only User Can

      (Master Password)
```

---

# Example: Bitwarden

The HTB material uses **Bitwarden** to explain password derivation.

Simplified process

```text
Master Password

↓

PBKDF2-SHA256

↓

Master Key

↓

Master Password Hash

↓

AES-256

↓

Vault
```

The uploaded material notes that this is a **simplified explanation**, and vendor whitepapers provide deeper implementation details.

---

# Cloud Password Managers

Cloud password managers synchronize encrypted vaults across devices.

---

## Typical Features

✔ Mobile App

✔ Browser Extension

✔ Synchronization

✔ Automatic Backup

✔ Multi-device Support

---

Diagram

```text
         Cloud Password Manager

                  │

     ┌────────────┼─────────────┐

     │            │             │

 Windows       Android      Browser

     │            │             │

     └────────────┼─────────────┘

             Same Vault
```

---

# Popular Cloud Password Managers

The HTB material lists:

- **1Password**
    
- **Bitwarden**
    
- **Dashlane**
    
- **Keeper**
    
- **LastPass**
    
- **NordPass**
    
- **RoboForm**
    

---

# Cloud Password Manager Advantages

✔ Synchronization

✔ Automatic Backup

✔ Easy Sharing

✔ Multi-device Access

✔ Convenience

---

# Local Password Managers

Some users prefer to keep their vault **only on their own devices**.

Everything remains under their control.

---

Diagram

```text
        Local Password Manager

              Computer

                 │

       Local Encrypted Vault

                 │

       User Responsible

          for Security
```

---

# Characteristics

Instead of relying on cloud synchronization,

the user is responsible for:

✔ Storage

✔ Backup

✔ Protection

✔ Recovery

---

# Security Features

According to the HTB material, local password managers commonly use:

✔ Encryption

✔ Key Derivation Functions

✔ Random Salt

✔ Memory Protection

✔ Keylogger Resistance

✔ Secure Desktop

---

# Secure Desktop

Some local password managers display password prompts using a **secure desktop**, similar to:

```text
Windows UAC
```

This helps defend against keyloggers and interface spoofing.

---

# Local Password Managers

Examples listed in the HTB material:

- **KeePass**
    
- **KWalletManager**
    
- **Pleasant Password Server**
    
- **Password Safe**
    

---

# Cloud vs Local

|Cloud|Local|
|---|---|
|Syncs across devices|Stored locally|
|Provider hosts encrypted vault|User stores vault|
|Convenient|More user responsibility|
|Automatic backup|Manual backup|

The uploaded material notes that **local storage is not automatically more secure**, and the choice depends on the user's requirements.

---

# Choosing a Password Manager

The HTB example describes a user who:

- Uses Linux
    
- Uses Android
    
- Uses ChromeOS
    
- Wants synchronization
    
- Needs 2FA
    
- Has a budget of **$5/month**
    

These requirements help determine the most suitable password manager.

---

# Common Features

When selecting a password manager, compare:

✔ 2FA Support

✔ Multi-platform Support

✔ Browser Extension

✔ Login Autocomplete

✔ Import / Export

✔ Password Generation

---

Diagram

```text
Password Manager

        │

2FA

Browser Extension

Password Generator

Sync

Import

Export

Autocomplete
```

---

# Alternatives to Passwords

The HTB material explains that passwords are **not the only authentication method**.

Alternatives include:

- Multi-Factor Authentication (MFA)
    
- FIDO2
    
- One-Time Passwords (OTP)
    
- Time-Based One-Time Passwords (TOTP)
    
- IP Restrictions
    
- Device Compliance
    

---

# Multi-Factor Authentication (MFA)

Uses more than one authentication factor.

Example

```text
Password

+

Phone Approval

=

MFA
```

---

# FIDO2

An open authentication standard supporting **passwordless authentication**.

Commonly uses physical devices such as:

```text
YubiKey
```

---

Diagram

```text
User

 │

YubiKey

 │

FIDO2

 │

Authentication
```

---

# One-Time Password (OTP)

Password is valid

```text
One Time Only
```

---

# Time-Based One-Time Password (TOTP)

Example apps

- Google Authenticator
    
- Microsoft Authenticator
    

Codes expire every few seconds.

---

Diagram

```text
Phone

↓

6 Digit Code

↓

30 Seconds

↓

Expires
```

---

# Device Compliance

Authentication can depend on whether the device complies with organizational policies.

Examples mentioned:

- Microsoft Endpoint Manager
    
- Workspace ONE
    

---

# Passwordless Authentication

Many organizations are moving toward:

```text
Passwordless
```

The uploaded material cites vendors including:

- Microsoft
    
- Auth0
    
- Okta
    
- Ping Identity
    

---

# Authentication Factors

## Knowledge Factor

```text
Something You Know

↓

Password
```

---

## Possession Factor

```text
Something You Have

↓

Phone

↓

YubiKey

↓

Security Token
```

---

## Inherent Factor

```text
Something You Are

↓

Fingerprint

↓

Face

↓

Iris
```

---

Diagram

```text
Authentication Factors

        │

 ┌──────┼─────────────┐

 ▼      ▼             ▼

Know   Have          Are

Password Phone     Fingerprint
```

---

# Why Passwordless?

Passwords suffer from:

✔ Theft

✔ Sharing

✔ Reuse

✔ Guessing

✔ Cracking

Passwordless authentication reduces dependence on knowledge-based authentication.

---

# Complete Workflow

```text
User

↓

Master Password

↓

Password Manager

↓

Encrypted Vault

↓

Strong Password

↓

Browser

↓

Website

↓

Authentication
```

---

# Cloud Password Manager Workflow

```text
Master Password

↓

KDF

↓

Master Key

↓

AES-256

↓

Encrypted Vault

↓

Cloud

↓

Multiple Devices
```

---

# Important Concepts

### Master Password

Only password the user remembers.

---

### Master Key

Derived from the master password.

---

### Password Hash

Used for authentication.

---

### Decryption Key

Decrypts vault contents.

---

### Zero-Knowledge

Provider cannot decrypt your vault.

---

### Passwordless

Authentication without passwords.

---

# HTB Exam Tips

✅ Password managers store passwords inside an **encrypted database (vault)**.

✅ The **Master Password** is used to derive encryption keys.

✅ Cloud password managers commonly use **Zero-Knowledge Encryption**, meaning the provider cannot access the vault contents.

✅ The Bitwarden example derives a **Master Key**, **Master Password Hash**, and **Decryption Key** from the Master Password.

✅ Local password managers keep the encrypted database on the local system, leaving storage protection and backups to the user.

✅ Password manager features include:

- 2FA
    
- Browser Extensions
    
- Password Generation
    
- Synchronization
    
- Login Autocomplete
    
- Import / Export
    

✅ Password alternatives mentioned include:

- MFA
    
- FIDO2
    
- OTP
    
- TOTP
    
- IP Restrictions
    
- Device Compliance
    

✅ Passwordless authentication replaces the **knowledge factor (password)** with **possession** or **inherence** factors.

---

# 🚀 1-Minute Revision Sheet

```text
PASSWORD MANAGER

        │

Master Password

        │

Key Derivation Function

        │

Master Key

        │

AES-256

        │

Encrypted Vault

────────────────────

Cloud

Bitwarden
1Password
Dashlane
Keeper
LastPass
NordPass
RoboForm

────────────────────

Local

KeePass
KWalletManager
Password Safe
Pleasant Password Server

────────────────────

Features

2FA

Sync

Browser Extension

Password Generator

Import

Export

Autocomplete

────────────────────

Alternatives

MFA

FIDO2

OTP

TOTP

Passwordless

────────────────────

Authentication

Know

Have

Are
```

These notes are based solely on your uploaded HTB Academy material. The explanations preserve the source's terminology and examples (such as Bitwarden's key derivation process, the cloud vs. local comparison, and passwordless authentication) while adding structured diagrams, workflows, comparison tables, and revision aids for study.