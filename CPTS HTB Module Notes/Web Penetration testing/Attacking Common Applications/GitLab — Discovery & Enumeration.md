![Image](https://images.openai.com/static-rsc-4/3I_RNggeu6O7aFDiO1nf9gnE4OgDcygFOuTrMAcql0zop2iI81hrZkKIO05u2DCRdvg2K6RFjmOzSSNukDcna2EU0_thUYeui6eFNjIAqFKb7Y-2BlTnEUuTbSUOiB8ndysWsPHHYGh4wFsgHk6n3rhPESvpcqAv3VinSGLYBq-9TiwCeSHy98fyDWX4W_SN?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/1ZSyIt9JjwGcf8AYe92kDRwn1YXudk87ng0MpWTlGzNE144_T_SLfKEy1-rkLLAr0TfI7Js9QQyj0xX_-ZUdEnaWBb3acxEpFEs27k0_dF8i_zCmyjkr60h8_TIyJObdr6aaDEReFDoQ_d3M7KBndY6pUHb9p1Ta8iWa2DNH9RS_xCRZElBmd5tDtH0mvZy1?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/jfvOZcmlqk_M9e5kHIs22w9yRlMhDHZzAk9qbDV9Jl4Y7zjGVTVh4l8jiDsClE8uKjc_DjhcHfkhL5aEpo3cnLfNli9yZ_nIhfczusucPQ6WPPNj9DB_bT__O4jSB74emCXi0ROAI6fy0AZl2PjG5Yd9mJgoIJTvMsGsbgsCJdn_epOQzFjrLvS97GCr9jC2?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Pw-ThzAUZdAU1b7V6SsI-ckwzdt_V4Gr4maGbhfQ8dg11sSTe3uV1_UsdrzW1wtDAesZIlJFpaLJSAHjLN4n5DOvrvfSWlpclcJp5pvqXPyYELe4LE7wdwt6gOh6dIQ4ffM8i_Utc_HWEjSLEkRUpmuym7SXM7JOwo5j0a5Lv_g88vUMRD4gXzN3TnEN6q1H?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/PB0OA1fwM46cX_5SQv9C9j2pkcTZpb5sqsEPbVPv4duflNmEuQIeQSYeBKjelvQrSprgj39XfntJAEmCBSE7s0xLQoXYkYNFga7qrVVrCQyfvqIKHtTDCUagtdt5P0uIfd-VHr-mDyESrD_3zyW8PhFo7uJSI_VISqdM0S0Y9K9uLkcYOm-ptT-LzzkM6Bpd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/VvIs9oL8qbp2VNvf0sGQvNwu68rh5kBxlWMYbi9IgXlWc22H2WiNDGRB1vB5LZLFeuJ3XeUlcWczR8aUXjnltQ0JpPpbo47xQvaHPgB7neKD877IQ8g77IXNcolHpyGhfyK2HvG1HBGanVDzF5232VqtT_6N40GG-PAKeY-0wPRjgr83ryuxNyoRJJpNY1pv?purpose=fullsize)

---

# 1. What is GitLab?

GitLab is a web-based Git repository hosting platform that provides:

- Git repository hosting
    
- Wiki functionality
    
- Issue tracking
    
- CI/CD pipelines
    
- Project/group management
    
- Code collaboration
    

The source describes GitLab as open-source, originally written in Ruby, with the current stack including:

- **Go**
    
- **Ruby on Rails**
    
- **Vue.js**
    

GitLab was launched in **2014** and offers both a free/open-source version and a paid enterprise version.

### GitLab vs GitHub vs Bitbucket

The module compares GitLab with:

- GitHub
    
- Bitbucket
    

All three are web-based Git repository platforms.

---

# 2. Why GitLab Is Interesting During a Pentest

This is the **most important concept of the module**.

A Git repository can contain much more than source code.

During a penetration test, repositories may contain:

```text
Source Code
     │
     ├── Configuration files
     ├── API keys
     ├── Passwords
     ├── SSH private keys
     ├── Internal hostnames
     ├── Scripts
     ├── Deployment information
     └── Other secrets
```

A developer might accidentally commit something such as:

```text
DB_USER=admin
DB_PASSWORD=SuperSecretPassword
API_KEY=xxxxxxxx
```

or even an SSH private key.

The module specifically recommends searching repositories for:

- Users
    
- Passwords
    
- Cleartext secrets
    
- SSH private keys
    
- API keys
    
- Configuration files
    
- Interesting scripts
    

GitLab repositories can have three major visibility levels:

|Repository|Access|
|---|---|
|**Public**|No authentication required|
|**Internal**|Available to authenticated users|
|**Private**|Restricted to specific users|

Therefore, **getting any legitimate GitLab account can significantly expand the attack surface**.

---

# 3. The Core GitLab Attack/Enumeration Mindset

Don't immediately think:

> "Can I exploit GitLab?"

Instead think:

> **"What information can GitLab give me?"**

A useful methodology is:

```text
GitLab discovered
       │
       ▼
Fingerprint application
       │
       ▼
Determine authentication requirements
       │
       ├── No authentication
       │       └── Explore public projects
       │
       └── Authentication required
               │
               ├── Existing credentials?
               │
               ├── OSINT credentials?
               │
               └── Registration enabled?
                       │
                       ▼
                 Create account
                       │
                       ▼
                Enumerate users
                       │
                       ▼
                Explore projects
                       │
                       ▼
              Search for secrets
                       │
                       ▼
             Pivot to other services
```

---

# 4. GitLab Authentication

GitLab can be configured with different signup and authentication restrictions.

The module highlights that organizations may:

- Disable registration
    
- Require administrator approval
    
- Restrict registration to company email addresses
    
- Configure minimum password length
    
- Configure allowed/denied email domains
    

The relevant administrative page is:

```text
/admin/application_settings/general
```

For example:

```text
http://gitlab.inlanefreight.local:8081/admin/application_settings/general
```

The important thing is **not to assume that registration is disabled simply because the UI says so**. The module demonstrates that `/users/sign_up` may still be reachable and useful for enumeration even when users cannot actually register.

---

# 5. Two-Factor Authentication

The module states:

> Two-factor authentication is disabled by default.

Therefore, if credentials are discovered through OSINT, credential dumps, password reuse, etc., they may potentially be enough to log in.

The module's example GitLab security page is:

```text
/admin/application_settings/general
```

### CPTS takeaway

When you obtain credentials:

```text
Credentials found
       ↓
Identify possible GitLab
       ↓
Attempt authentication
       ↓
Check whether 2FA blocks access
       ↓
If authenticated → enumerate repositories
```

---

# 6. Footprinting & Discovery

## Step 1 — Identify GitLab

The easiest way to determine that GitLab is running is simply to browse to the suspected URL.

Example:

```text
http://gitlab.inlanefreight.local:8081/users/sign_in
```

The login page displays the GitLab branding/logo, providing an immediate fingerprint.

### Important URL

```text
/users/sign_in
```

This is the GitLab login endpoint.

---

# 7. Version Enumeration

This is an important limitation.

The module states that the GitLab version can be fingerprinted by visiting:

```text
/help
```

**when logged in**.

So:

```text
GitLab
   │
   ├── Can register?
   │      └── Register → Login → /help
   │
   └── Cannot register?
          └── Version may be harder to determine
```

---

## Why Version Matters

GitLab has had serious vulnerabilities affecting specific versions.

The module gives historical examples involving:

```text
GitLab 12.9.0
GitLab 11.4.7
GitLab CE 13.10.3
GitLab 13.9.3
GitLab 13.10.2
```

The key lesson isn't to blindly fire exploits.

Instead:

```text
Identify version
      ↓
Research affected versions
      ↓
Determine whether target is vulnerable
      ↓
Choose appropriate low-risk validation
```

The module explicitly recommends **not launching various exploits blindly** if you cannot reliably determine the version. Instead, focus on hunting for secrets and information that can support the engagement.

### CPTS exam point ⭐

> **Version enumeration comes before version-specific exploitation.**

---

# 8. Enumeration — `/explore`

Once GitLab is identified, one of the first locations to check is:

```text
/explore
```

Example:

```text
http://gitlab.inlanefreight.local:8081/explore
```

The Explore page can reveal:

- Public projects
    
- Groups
    
- Snippets
    
- Other potentially interesting repositories
    

---

# 9. Public Projects

The example contains:

```text
Inlanefreight dev
```

A project that initially looks uninteresting should **still be investigated**.

Why?

Because a repository may contain:

```text
Source code
     │
     ├── Configuration
     ├── Credentials
     ├── API keys
     ├── SSH keys
     ├── Infrastructure information
     ├── Internal URLs
     └── Vulnerable functionality
```

The module specifically highlights that public projects can help you:

1. Learn more about infrastructure
    
2. Obtain production code
    
3. Perform code review
    
4. Find hard-coded credentials
    
5. Find credential-containing scripts/configuration
    
6. Discover SSH private keys
    
7. Discover API keys
    
8. Find other secrets
    

---

# 10. Don't Just Look at the Main Project Page

Once inside a project, investigate the available functionality.

The module specifically points toward:

```text
Groups
Snippets
Help
Search
Commits
Files
```

For example:

```text
Project
  │
  ├── Files
  ├── Commits
  ├── Groups
  ├── Snippets
  ├── Search
  └── History
```

The **commit history** is especially interesting during a real assessment because developers can accidentally commit sensitive information and later remove it from the current version while leaving it in historical commits.

The provided example shows:

```text
Inlanefreight dev
44 commits
1 branch
```

---

# 11. Search Functionality

GitLab's search functionality can potentially help locate additional projects or information.

Useful concepts to search for during an authorized assessment include:

```text
password
passwd
secret
token
api_key
apikey
private_key
ssh
credential
database
DB_PASSWORD
AWS
VPN
```

The module's broader point is that **repository enumeration can reveal information that isn't directly visible from the application's login page**.

---

# 12. Registration — Potential Attack Surface

Next, determine whether registration is possible.

Endpoint:

```text
/users/sign_up
```

Example:

```text
http://gitlab.inlanefreight.local:8081/users/sign_up
```

Potential outcomes:

```text
Registration
     │
     ├── Disabled
     │      └── Continue enumeration
     │
     ├── Enabled + company email required
     │      └── Need company email
     │
     ├── Enabled + admin approval
     │      └── Registration may require approval
     │
     └── Enabled + unrestricted
            └── Create account
```

---

# 13. Username Enumeration

This is one of the **big CPTS-relevant techniques** in this module.

The registration page can reveal whether a username already exists.

For example, attempting to register:

```text
root
```

produces:

```text
Username is already taken
```

This tells us:

```text
root = valid/existing username
```

The module states that this username enumeration technique worked against the latest GitLab version at the time of writing.

---

# 14. Email Enumeration

The same registration functionality can potentially reveal whether an email address already belongs to an account.

Example error:

```text
1 error prohibited this user from being saved: Email has already been taken
```

Therefore:

```text
Email submitted
      ↓
GitLab response
      ↓
"Email has already been taken"
      ↓
Email potentially belongs to existing account
```

Importantly, the module says this can work even when:

```text
Sign-up enabled = disabled
```

Users may still access:

```text
/users/sign_up
```

and perform enumeration, although they won't be able to complete registration.

### CPTS exam point ⭐

**Registration pages aren't only for registration.**

They can sometimes become:

- Username enumeration points
    
- Email enumeration points
    
- Authentication attack surfaces
    
- Sources for valid account names
    

---

# 15. Building a Valid Username List

Suppose you discover:

```text
root
admin
jdoe
jsmith
```

You can build a list:

```text
users.txt

root
admin
jdoe
jsmith
```

The module then discusses using valid usernames as a foundation for:

- Weak password testing
    
- Credential reuse
    
- Credentials obtained through OSINT/password dumps
    

The example references **Dehashed** as a source for credential information.

---

# 16. Registering an Account

The module demonstrates registration with:

```text
Username: hacker
Password: Welcome
```

After registration, the user is automatically logged in and brought to the projects dashboard.

This is significant because authentication changes the amount of information available.

```text
Unauthenticated
       │
       ▼
Public projects
       │
       │ register
       ▼
Authenticated user
       │
       ▼
Potential internal projects
```

---

# 17. Internal Projects

After registering, the example discovers another project:

```text
Inlanefreight website
```

This project is internal and wasn't available before authentication.

This demonstrates a very important pentesting principle:

> **Authentication can expand the attack surface dramatically.**

Before authentication:

```text
Public GitLab
    ↓
Limited information
```

After registration:

```text
Authenticated GitLab
    ↓
Internal projects
    ↓
More source code
    ↓
More configuration
    ↓
Potential credentials/secrets
    ↓
Potential attack paths
```

---

# 18. Source-Code Review

Suppose the internal project contains a PHP application.

You could potentially download the source and perform code review looking for:

```text
Hard-coded credentials
      ↓
Database credentials
      ↓
API keys
      ↓
Authentication weaknesses
      ↓
Hidden functionality
      ↓
Command execution
      ↓
File inclusion
      ↓
Other vulnerabilities
```

The module explicitly notes that source code could reveal vulnerabilities, hidden functionality, credentials, or other sensitive information.

---

# 19. GitLab as a Pivot Point

This is probably the **biggest lesson** of the entire module.

GitLab doesn't necessarily have to give you RCE.

Instead:

```text
GitLab
  │
  ├── Username
  │
  ├── Email
  │
  ├── Password
  │
  ├── SSH private key
  │
  ├── API key
  │
  ├── Internal hostname
  │
  ├── Source code
  │
  └── Configuration
          │
          ▼
     Other services
```

For example:

```text
GitLab repository
       │
       ▼
Database password
       │
       ▼
Database server
```

Or:

```text
GitLab
   │
   ▼
SSH private key
   │
   ▼
Internal Linux host
```

Or:

```text
GitLab
   │
   ▼
VPN credentials
   │
   ▼
VPN
   │
   ▼
Internal network
```

This is why enumeration is so powerful.

---

# 20. Recommended GitLab Enumeration Workflow

Here's the methodology I'd memorize for CPTS:

```text
                    ┌──────────────────┐
                    │ GitLab Discovered│
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Fingerprint      │
                    │ Login / Branding │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Determine Access │
                    └────────┬─────────┘
                             │
              ┌──────────────┴──────────────┐
              ▼                             ▼
        Unauthenticated                 Credentials
              │                             │
              ▼                             ▼
        /explore                       Login
              │                             │
              ▼                             ▼
        Public projects              /help → version
              │                             │
              └──────────────┬──────────────┘
                             ▼
                    /users/sign_up
                             │
                             ▼
                   Username / Email
                     Enumeration
                             │
                             ▼
                     Registration?
                             │
                             ▼
                    Authenticated User
                             │
                             ▼
                       /explore
                             │
                             ▼
                     Internal Projects
                             │
                             ▼
                  Repository Enumeration
                             │
                             ▼
                   Secrets / Credentials
                             │
                             ▼
                         Pivot
```

---

# 21. GitLab Enumeration Checklist

## Initial Discovery

-  Identify GitLab
    
-  Browse `/users/sign_in`
    
-  Confirm GitLab branding
    
-  Identify exposed port
    
-  Check whether authentication is required
    

## Unauthenticated Enumeration

-  `/explore`
    
-  Public projects
    
-  Groups
    
-  Snippets
    
-  Search
    
-  Project files
    
-  Commit history
    
-  Configuration files
    
-  Secrets
    

## Registration

-  `/users/sign_up`
    
-  Determine whether registration is enabled
    
-  Determine whether company email is required
    
-  Determine whether admin approval is required
    
-  Test username enumeration
    
-  Test email enumeration
    
-  Check whether an account can be created
    

## Authenticated Enumeration

-  `/help`
    
-  Determine GitLab version
    
-  `/explore`
    
-  Internal projects
    
-  Groups
    
-  Snippets
    
-  Search
    
-  Repository files
    
-  Commit history
    
-  Source code
    
-  Configuration
    
-  Credentials
    
-  API keys
    
-  SSH keys
    

## Pivoting

Ask:

> **"What can I do with every piece of information I find?"**

For every credential/key/hostname:

```text
Found secret
    ↓
Identify associated service
    ↓
Validate in authorized scope
    ↓
Determine access
    ↓
Enumerate next target
```

---

# 22. Important URLs to Memorize

|Purpose|Endpoint|
|---|---|
|Login|`/users/sign_in`|
|Registration|`/users/sign_up`|
|Explore|`/explore`|
|Version information|`/help`|
|Global application settings|`/admin/application_settings/general`|

Examples from the lab:

```text
http://gitlab.inlanefreight.local:8081/users/sign_in
```

```text
http://gitlab.inlanefreight.local:8081/users/sign_up
```

```text
http://gitlab.inlanefreight.local:8081/explore
```

```text
http://gitlab.inlanefreight.local:8081/help
```

---

# 23. Security Mitigations

The module recommends several defenses.

### Enforce 2FA

Require two-factor authentication for user accounts.

This makes stolen credentials less immediately useful.

### Fail2Ban

Use:

```text
Fail2Ban
```

to block suspicious repeated failed login attempts associated with brute-force attacks.

### Restrict Network Access

If GitLab doesn't need to be externally accessible:

```text
Internet
   X
   │
Firewall
   │
   ▼
Internal GitLab
```

Restrict access to trusted IP addresses/networks.

### Restrict Registration

Avoid:

```text
Anyone → Create account → Access internal data
```

Instead use:

```text
Company email
       +
Admin approval
       +
2FA
```

---

# 24. CPTS Exam Points ⭐⭐⭐

### ⭐ 1. GitLab is an information goldmine

Don't only search for vulnerabilities.

Look for:

- Credentials
    
- API keys
    
- SSH keys
    
- Configuration
    
- Source code
    
- Internal infrastructure information
    

---

### ⭐ 2. `/explore`

One of the first endpoints to check:

```text
/explore
```

Look for public projects.

---

### ⭐ 3. `/users/sign_up`

Potentially useful for:

```text
Registration
Username enumeration
Email enumeration
```

---

### ⭐ 4. `/help`

Authenticated users can use:

```text
/help
```

to identify the GitLab version.

---

### ⭐ 5. Authentication expands visibility

A registered account may expose:

```text
Public projects
       ↓
Authenticated access
       ↓
Internal projects
```

---

### ⭐ 6. Don't blindly exploit unknown versions

If version information isn't available:

> Don't spray exploits randomly.

Instead, prioritize:

```text
Enumeration
Secrets
OSINT
Source code
Credentials
```

This is directly emphasized by the module.

---

# 25. The Bigger Pentesting Lesson

The final section of the module is extremely important.

A target doesn't have to be **directly exploitable** to be useful.

Imagine:

```text
Target A: GitLab
        │
        │ repository
        ▼
Target B: VPN credentials
        │
        ▼
Target C: VPN access
        │
        ▼
Target D: Internal server
        │
        ▼
Target E: Domain environment
```

No direct GitLab RCE was required.

Instead, the engagement succeeded because information from multiple sources was combined.

The module explicitly emphasizes the **importance and power of enumeration**, especially during external penetration tests where the attack surface is smaller and successful attacks may require combining information from two or more sources.

---

# 🔥 GitLab Quick Cheat Sheet

```text
IDENTIFY
────────
/users/sign_in

ENUMERATE PUBLIC DATA
─────────────────────
/explore

REGISTER / ENUMERATE
────────────────────
/users/sign_up

VERSION
───────
/help          ← authenticated

ADMIN SETTINGS
──────────────
/admin/application_settings/general
```

### Think:

```text
GitLab
  ↓
Login page
  ↓
/explore
  ↓
Public repositories
  ↓
/users/sign_up
  ↓
Username/email enumeration
  ↓
Register account
  ↓
Internal repositories
  ↓
Source code + history
  ↓
Credentials / API keys / SSH keys
  ↓
Pivot
```

### **Golden CPTS Rule 🧠**

> **Don't ask only "Can I exploit GitLab?" Ask "What can GitLab reveal that lets me attack something else?"**

That is the central lesson of this module.