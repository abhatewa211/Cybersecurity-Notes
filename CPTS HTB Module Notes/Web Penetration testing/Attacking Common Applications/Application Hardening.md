# 1. Application Inventory Comes First

Before hardening anything:

```text
              Application Inventory
                       │
        ┌──────────────┴──────────────┐
        ▼                             ▼
 Internal Applications        External Applications
        │                             │
        └──────────────┬──────────────┘
                       ▼
              Identify / Classify
                       ▼
                  Harden
```

The inventory should include:

- Internal applications
    
- Internet-facing applications
    
- Versions
    
- Locations
    
- Owners
    
- Required/unused applications
    
- Security status
    

Tools such as **Nmap** and **EyeWitness** can help organizations build this inventory, particularly when resources are limited.

### Why?

Without knowing what's deployed:

```text
Unknown application
       ↓
Unknown attack surface
       ↓
Unknown vulnerability
       ↓
Unknown risk
```

Inventorying can also uncover:

- **Shadow IT**
    
- Deprecated applications
    
- Unnecessary services
    
- Forgotten trial installations
    
- Applications that changed security behavior after licensing changes
    

The module specifically gives Splunk as an example where a trial can convert to a free version that no longer requires authentication.

---

# 2. General Application Hardening

The module provides a baseline that applies across applications such as:

```text
WordPress
Drupal
Joomla
Tomcat
Jenkins
osTicket
GitLab
PRTG
Splunk
```

The main defensive categories are:

```text
Secure Authentication
        +
Access Controls
        +
Disable Unsafe Features
        +
Regular Updates
        +
Backups
        +
Security Monitoring
        +
Controlled LDAP/AD Integration
```

---

# 3. 🔐 Secure Authentication

Applications should:

### Change default passwords

Never leave:

```text
admin:admin
```

or vendor-provided credentials in production.

### Disable default administrative accounts where possible

Instead:

```text
Default admin
     ↓
Disable
     ↓
Create controlled admin account
```

### Enforce strong passwords

Especially during:

- Installation
    
- Registration
    
- Administrator creation
    

### Enable MFA / 2FA

Where supported, MFA should be mandatory at least for administrators.

---

# 4. 🚪 Access Controls

Don't expose functionality simply because the application technically allows it.

For example:

```text
Internet
   │
   ▼
/administrator
```

may be unnecessary.

Better:

```text
Internet
   │
   X
   │
Internal network / VPN
   │
   ▼
/administrator
```

The module recommends restricting login pages and controlling permissions around file uploads and application deployments.

### Principle

> **If a sensitive interface doesn't need to be Internet-accessible, don't expose it.**

---

# 5. Disable Unsafe Features

If a feature isn't required, consider disabling it.

The module specifically mentions **PHP code editing in WordPress**.

Why?

```text
Admin access
     ↓
PHP code editor
     ↓
Modify server-side code
     ↓
Code execution
```

Therefore:

```text
Unused dangerous feature → Disable
```

This is a recurring theme from the offensive modules:

> Built-in functionality can become an attack primitive.

---

# 6. 🔄 Regular Updates

Applications should be:

- Regularly updated
    
- Patched with vendor security fixes
    
- Monitored for vulnerable versions
    

The module recommends applying vendor patches as soon as possible.

Think:

```text
Inventory
   ↓
Version
   ↓
Known vulnerabilities
   ↓
Patch
   ↓
Verify
```

---

# 7. 💾 Backups

Backups aren't preventative controls, but they're critical after compromise.

The module recommends regular:

- Website backups
    
- Database backups
    
- Secondary-location backups
    

### Why secondary storage?

If the attacker compromises the application and its local storage:

```text
Server
 ├── Application
 ├── Database
 └── Local Backup ❌
```

the backup could potentially be compromised too.

Instead:

```text
Production
    │
    ▼
Secondary Backup
    │
    ▼
Recovery
```

---

# 8. 👁️ Security Monitoring

Organizations should monitor applications for:

- Suspicious activity
    
- Authentication attacks
    
- Brute forcing
    
- Vulnerability exploitation
    
- Other malicious behavior
    

A **WAF (Web Application Firewall)** can provide an additional layer of protection.

But the module explicitly warns that a WAF is **not a silver bullet**.

### Correct hierarchy

```text
Secure configuration
       ↓
Strong authentication
       ↓
Access controls
       ↓
Patching
       ↓
Monitoring
       ↓
WAF = additional layer
```

Not:

```text
Bad security
   ↓
Install WAF
   ↓
Problem solved ❌
```

---

# 9. LDAP + Active Directory

The module recommends integrating applications with **Active Directory single sign-on** where appropriate.

Potential benefits include:

- Easier access management
    
- Better auditing
    
- Centralised credential management
    
- Streamlined service accounts
    
- Fine-grained password policies
    
- Fewer credentials users need to remember
    

This connects directly to the LDAP module we just studied.

---

# 10. Principle of Least Privilege

Every application should receive **only the permissions it actually needs**.

Bad:

```text
Application
     ↓
SYSTEM / root
```

Better:

```text
Application
     ↓
Dedicated low-privileged account
     ↓
Only required resources
```

The module specifically recommends applying least privilege throughout the application environment.

This is especially important for applications such as:

- Tomcat
    
- Jenkins
    
- Splunk
    
- Monitoring platforms
    
- Database-connected applications
    

because successful RCE can otherwise immediately become a highly privileged foothold.

---

# 11. Administrative Access

Administrators are high-value targets.

The module recommends:

- MFA
    
- Changing default admin usernames
    
- Limiting the number of administrators
    
- Restricting where administrators can access the application from
    
- Avoiding administrative interfaces on the open Internet
    

### Secure architecture

```text
                    Internet
                       │
                       X
                       │
                 Admin Console
                       │
                  VPN / Internal
                       │
                 Authorized Admin
```

---

# 12. Internet Exposure

One of the most important questions:

> **Does this application actually need to be Internet-facing?**

Examples from the module:

```text
GitLab repository
```

Does it need to be public?

```text
Ticketing system
```

Does it need to be accessible outside the internal network?

If the answer is **no**:

```text
Remove Internet exposure.
```

This single architectural decision can eliminate entire classes of attacks.

---

# 13. Application-Specific Hardening

The module provides specific recommendations for the applications studied.

|Application|Key hardening|
|---|---|
|**WordPress**|Security monitoring / security plugin|
|**Joomla**|Protect admin access|
|**Drupal**|Hide/restrict admin login|
|**Tomcat**|Restrict Manager/Host-Manager|
|**Jenkins**|Proper authorization|
|**Splunk**|Change default password + proper licensing/authentication|
|**PRTG**|Stay updated + change default password|
|**osTicket**|Restrict Internet access|
|**GitLab**|Restrict registration/sign-ups|

---

# 14. WordPress

The module recommends security monitoring and gives **Wordfence** as an example.

Possible capabilities include:

- Security monitoring
    
- Suspicious-activity blocking
    
- Country blocking
    
- Two-factor authentication
    

The larger lesson:

```text
WordPress
 ↓
Plugins
 ↓
Monitoring
 ↓
MFA
 ↓
Restrict dangerous functionality
```

---

# 15. Joomla

The module recommends controlling access to the Joomla administrator interface.

An example is an extension such as **AdminExile**, which can require a secret key for the administrator login URL.

The fundamental control is:

```text
Public Internet
      ↓
/administrator
      X
```

rather than relying only on the login page's password.

---

# 16. Drupal

The recommendation is to:

> Disable, hide, or move the admin login page.

Again:

```text
Reduce exposure
       +
Strong authentication
       +
MFA
```

---

# 17. Tomcat

This one directly relates to our **Attacking Tomcat** module.

The Manager and Host-Manager applications should ideally only be accessible from:

```text
localhost
```

If external access is necessary:

- IP whitelist it
    
- Use a very strong password
    
- Use a non-standard username
    

### Why?

We saw:

```text
Tomcat Manager
      ↓
Valid credentials
      ↓
WAR deployment
      ↓
JSP
      ↓
RCE
```

So protecting Manager access is extremely important.

---

# 18. Jenkins

For Jenkins, the module recommends configuring permissions using:

**Matrix Authorization Strategy**

The principle is:

```text
Not every Jenkins user
        ↓
should have
        ↓
administrative/script/deployment permissions
```

This is particularly important because Jenkins' Script Console can lead to command execution.

---

# 19. Splunk

Hardening recommendations:

- Change the default password
    
- Ensure Splunk is properly licensed/configured to enforce authentication
    

This directly addresses the scenario we studied where a forgotten trial/free installation could become an unauthenticated service.

---

# 20. PRTG

For PRTG:

```text
Keep updated
+
Change default password
```

This directly mitigates the default/weak credential path we studied.

---

# 21. osTicket

Recommendation:

> Limit Internet access if possible.

This reduces the opportunity for attackers to:

```text
Internet
   ↓
Support portal
   ↓
Information disclosure
   ↓
Emails / usernames / credentials
   ↓
Attack another service
```

---

# 22. GitLab

The module recommends restricting registration.

For example:

```text
Anonymous user
      ↓
Sign-up
      ↓
Admin approval required
```

and configuring:

- Allowed email domains
    
- Denied email domains
    
- Registration restrictions
    

This is particularly important because GitLab can contain extremely sensitive:

```text
Source code
Credentials
SSH keys
CI/CD secrets
Internal information
```

---

# 23. Continuous Security Process

Hardening isn't:

```text
Configure once → Done
```

It should be:

```text
Inventory
   ↓
Assess
   ↓
Harden
   ↓
Monitor
   ↓
Update
   ↓
Reassess
   ↓
Repeat
```

The module recommends regularly reviewing the application inventory to identify applications that are:

- No longer needed
    
- Exposed internally/externally unnecessarily
    
- Severely vulnerable
    
- Misconfigured
    

It also recommends regular assessments for vulnerabilities, misconfigurations, and sensitive-data exposure.

---

# 24. Remediation Is Part of the Job

Finding vulnerabilities isn't enough.

Pentest:

```text
Find vulnerability
       ↓
Report vulnerability
       ↓
Recommend remediation
       ↓
Organization fixes it
       ↓
Retest
```

The module specifically stresses following through on penetration-testing remediation recommendations and checking periodically for recurrence.

---

# 🔥 Offensive ↔ Defensive Mapping

This is a **great CPTS revision table** because it connects the modules we've just studied.

|Attack|Defensive control|
|---|---|
|Default credentials|Change/disable defaults|
|Weak passwords|Strong password policy|
|Brute force|MFA + rate limiting + monitoring|
|Tomcat Manager RCE|Restrict Manager/Host-Manager|
|Jenkins Script Console|Least privilege + authorization|
|Splunk unauthenticated access|Enforce authentication|
|PRTG default credentials|Change default credentials|
|GitLab unrestricted registration|Admin approval/domain restrictions|
|osTicket information leakage|Restrict Internet access|
|LDAP injection|Validate/escape LDAP input|
|Mass assignment|Explicit allowlisting / strong parameters|
|Known CVEs|Patch/update|
|Webshell persistence|Monitoring + integrity controls|
|Sensitive data exposure|Minimize access/exposure|
|Excessive privileges|Least privilege|
|Application compromise|Tested backups|

---

# 🧠 CPTS Exam Mental Model

When thinking **defensively**, reverse the pentester's methodology:

### Attacker asks:

```text
What exists?
```

### Defender:

```text
Maintain an accurate inventory.
```

---

### Attacker:

```text
What's exposed?
```

### Defender:

```text
Minimize network exposure.
```

---

### Attacker:

```text
What's the version?
```

### Defender:

```text
Patch and maintain supported versions.
```

---

### Attacker:

```text
Are default credentials enabled?
```

### Defender:

```text
Change/disable defaults.
```

---

### Attacker:

```text
Can I reach the admin panel?
```

### Defender:

```text
Restrict administrative access.
```

---

### Attacker:

```text
Can I abuse built-in functionality?
```

### Defender:

```text
Disable unnecessary dangerous features.
```

---

### Attacker:

```text
Can I become root/SYSTEM?
```

### Defender:

```text
Least privilege.
```

---

### Attacker:

```text
Can I move somewhere else?
```

### Defender:

```text
Network segmentation + credential hygiene.
```

---

# 🎯 Final CPTS Cheat Sheet

```text
APPLICATION HARDENING
│
├── 1. INVENTORY
│      ├── Internal
│      ├── External
│      ├── Shadow IT
│      └── Deprecated apps
│
├── 2. AUTHENTICATION
│      ├── Strong passwords
│      ├── Change defaults
│      ├── Disable default admins
│      └── MFA
│
├── 3. ACCESS CONTROL
│      ├── Restrict admin panels
│      ├── IP restrictions
│      └── Least privilege
│
├── 4. FEATURES
│      └── Disable unsafe/unnecessary features
│
├── 5. PATCHING
│      └── Regular updates
│
├── 6. BACKUPS
│      └── Secondary/off-system backups
│
├── 7. MONITORING
│      ├── Authentication attacks
│      ├── Suspicious activity
│      └── WAF = additional layer
│
├── 8. EXPOSURE
│      └── Don't expose unnecessary applications
│
└── 9. CONTINUOUS REVIEW
       ├── Reassess
       ├── Remediate
       └── Retest
```

## 🔥 Golden Mental Model

> **Know what you have → minimize what is exposed → secure authentication → restrict privileges → disable dangerous features → patch → monitor → back up → continuously reassess.**

And this is the big conclusion of the entire application section: web applications represent a huge attack surface, so defenders need to understand **discovery, version fingerprinting, known vulnerabilities, built-in functionality, credentials, and sensitive-data exposure** from the attacker's perspective in order to secure them effectively.