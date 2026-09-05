The central chain is:

```text
osTicket discovered
        ↓
Enumerate functionality
        ↓
Create / access support tickets
        ↓
Obtain company information
        ↓
Discover employee emails/usernames
        ↓
Find password-reset information
        ↓
Potential credential reuse
        ↓
Access other company services
```

The uploaded material explicitly emphasizes that support portals should not be overlooked during penetration tests.

---

# 1. What is osTicket?

osTicket is an **open-source support ticketing system**.

It can be compared with:

- Jira
    
- OTRS
    
- Request Tracker
    
- Spiceworks
    

It allows organizations to consolidate inquiries coming from:

- Email
    
- Phone
    
- Web forms
    

into a web-based interface.

### Technical stack

```text
osTicket
│
├── PHP
│
├── MySQL
│
├── Windows
│
└── Linux
```

The module notes that searching for:

```text
"Helpdesk software - powered by osTicket"
```

can reveal many organizations using it.

---

# 2. Why Should Pentesters Care About Helpdesks?

This is the **big lesson** of the section.

A support portal might look harmless:

```text
"Open a ticket"
"Check ticket status"
"Contact support"
```

But support personnel routinely handle:

- Usernames
    
- Email addresses
    
- Password resets
    
- VPN problems
    
- Account information
    
- Internal system names
    
- Troubleshooting information
    

Therefore:

```text
Support Portal
      ↓
Human interaction
      ↓
Sensitive operational information
      ↓
Potential credentials
      ↓
Potential access to other systems
```

The module specifically warns that these applications should not be overlooked even when the application itself isn't obviously vulnerable.

---

# 3. Footprinting & Discovery

## EyeWitness

The module starts with an earlier **EyeWitness** scan.

The screenshot reveals an important cookie:

```text
OSTSESSID
```

This is a useful application fingerprint.

---

## Page Footer

Another useful fingerprint is the osTicket branding.

Look for:

```text
powered by
```

along with the osTicket logo.

The footer may also contain:

```text
Support Ticket System
```

So your fingerprinting checklist becomes:

```text
Possible osTicket
      ↓
Check page source/UI
      ↓
OSTSESSID cookie
      ↓
"powered by" osTicket
      ↓
"Support Ticket System"
      ↓
Confirm application
```

---

# 4. Nmap Isn't Enough

This is an important lesson from the module.

An Nmap scan may simply identify the underlying web server:

```text
Apache
IIS
```

It may **not identify osTicket itself**.

Therefore:

> **Service enumeration and application enumeration are different things.**

```text
Nmap
 ↓
Web server identified
 ↓
Browser / EyeWitness / source inspection
 ↓
Application fingerprinting
 ↓
osTicket identified
```

The module explicitly notes that Nmap alone won't necessarily help fingerprint the application.

---

# 5. Don't Depend Only on CVEs

The module points out that osTicket is highly maintained and doesn't have a huge collection of easily exploitable vulnerabilities.

That makes it a great example of this pentesting principle:

> **An application doesn't need to be vulnerable to be useful during an assessment.**

The module breaks an application's operation into:

```text
1. User Input
       ↓
2. Processing
       ↓
3. Solution
```

The interesting part is understanding how humans and systems interact with the application.

---

# 6. User Input

The core purpose of osTicket is:

```text
Customer / employee
       ↓
Problem
       ↓
Support ticket
       ↓
Company employee
       ↓
Resolution
```

Because osTicket is open source, there is plenty of documentation and examples available for understanding its functionality.

The module notes that only staff and administrators can access the admin panel.

This creates an interesting **social-engineering angle** during an authorized assessment:

```text
External tester
      ↓
Create legitimate-looking support problem
      ↓
Interact with support staff
      ↓
Gather information
```

The important lesson is that a support portal can expose information through its **normal business process**, rather than through a software vulnerability.

---

# 7. Processing

Support staff attempt to reproduce reported problems.

In a real organization, they may investigate issues in environments that closely resemble production.

This means the support conversation can potentially reveal:

- Internal system behavior
    
- Technology names
    
- Troubleshooting procedures
    
- Usernames
    
- Email addresses
    
- Account information
    

The module describes this as the **processing** stage.

---

# 8. Solution

This is where the information can become particularly valuable.

When a support issue becomes complicated, additional technical staff may join the email correspondence.

That can reveal:

```text
Support ticket
     ↓
Additional staff involved
     ↓
More email addresses
     ↓
Potential usernames
     ↓
OSINT
     ↓
Other company services
```

The module specifically notes that these usernames may be useful for OSINT or for attempting access against other company services.

---

# 9. Known osTicket Vulnerabilities

The module mentions that exploit databases contain historical issues including:

- Remote File Inclusion
    
- SQL Injection
    
- Arbitrary File Upload
    
- XSS
    

It specifically identifies:

```text
CVE-2020-24881
```

for:

```text
osTicket 1.14.1
```

and describes it as an **SSRF vulnerability**.

Potential impact of SSRF includes:

```text
External osTicket
       ↓
SSRF
       ↓
Internal resources
       ↓
Potential internal port scanning
```

### CPTS lesson

Again:

**Version → vulnerability → impact**

Don't assume every historical CVE is exploitable against the version you found.

---

# 10. The More Interesting Attack: Information Leakage

The module then moves into a much more realistic scenario.

Suppose you've found an exposed support portal.

You might be able to use it to obtain:

```text
Company email address
```

That email address can potentially be used to register for other externally accessible services requiring a company email.

This is the key pivot:

```text
osTicket
   ↓
Company email
   ↓
External service registration
   ↓
Confirmation email
   ↓
Potential access
```

---

# 11. Ticket Creation

The module demonstrates creating a ticket at:

```text
http://support.inlanefreight.local/open.php
```

The ticket is created with an issue such as:

```text
"Your site is slow"
```

The system then returns a ticket ID:

```text
940288
```

and provides an email address:

```text
940288@inlanefreight.local
```

That is a major information-disclosure pivot.

---

# 12. Ticket-Email Correlation

The module presents an important scenario.

If the support system correlates:

```text
Ticket ID ↔ Email address
```

then email sent to:

```text
940288@inlanefreight.local
```

may appear in the ticket.

Conceptually:

```text
External tester
       │
       │ email
       ▼
940288@inlanefreight.local
       │
       ▼
Support system
       │
       ▼
Ticket #940288
```

This can potentially bridge external services and internal support infrastructure.

---

# 13. Pivot to Other Services

Suppose the organization has an externally accessible:

- Wiki
    
- Slack
    
- Mattermost
    
- Rocket.Chat
    
- GitLab
    
- Bitbucket
    

that requires a valid company email.

The support portal may provide a way to obtain such an address.

The chain becomes:

```text
Support portal
      ↓
Valid company email
      ↓
External service
      ↓
Registration
      ↓
Confirmation email
      ↓
Support portal
      ↓
Confirmation visible
```

This is a **workflow abuse** technique rather than a conventional exploit.

---

# 14. Sensitive Data Exposure

The next scenario introduces credentials discovered through OSINT.

The example data contains:

```text
jclayton
JulieC8765!

kgrimes
Fish1ng_s3ason!
```

along with their associated email addresses.

The module explicitly states that these are **fictional sample credentials**.

The important takeaway is:

> **Credential leaks become much more useful when combined with application enumeration.**

---

# 15. Subdomain Enumeration

The module then shows discovered subdomains:

```text
vpn.inlanefreight.local
support.inlanefreight.local
ns1.inlanefreight.local
mail.inlanefreight.local
apps.inlanefreight.local
ftp.inlanefreight.local
dev.inlanefreight.local
ir.inlanefreight.local
auth.inlanefreight.local
careers.inlanefreight.local
portal-stage.inlanefreight.local
dns1.inlanefreight.local
dns2.inlanefreight.local
meet.inlanefreight.local
portal-test.inlanefreight.local
home.inlanefreight.local
legacy.inlanefreight.local
```

The useful discoveries are:

```text
support.inlanefreight.local
vpn.inlanefreight.local
```

The module identifies:

```text
support → osTicket
vpn     → Barracuda SSL VPN
```

and notes that the VPN does not appear to use MFA.

---

# 16. Testing Leaked Credentials

The osTicket admin login is:

```text
http://support.inlanefreight.local/scp/login.php
```

The first credential set fails:

```text
jclayton
```

The second username also initially fails:

```text
kgrimes
```

But the login page accepts **email addresses**, so the module tries:

```text
kevin@inlanefreight.local
```

and successfully authenticates.

### 🔥 Enumeration lesson

Don't assume a login form accepts only usernames.

Determine whether it accepts:

```text
username
email
employee ID
other identifiers
```

---

# 17. The Support Agent's Ticket

After logging in, the user `kevin` appears to be a support agent.

There are no open tickets, but one closed ticket is discovered.

The conversation concerns a remote employee experiencing **VPN access problems**.

The interesting part is what happens next.

---

# 18. Password Reset Information

The employee asks the support agent to reset their VPN password.

The agent responds that the password has been reset to the **standard new-joiner password**.

The employee asks the agent to call and provide it.

That would be the correct security-conscious behavior.

But then the agent makes a critical mistake:

> The password is sent directly through the support portal.

Now we have:

```text
Support ticket
      ↓
Password-reset conversation
      ↓
Standard password revealed
      ↓
Potential VPN authentication
```

This is an example of **sensitive data exposure through legitimate support functionality**.

---

# 19. Password Reuse

The module then highlights a broader organizational weakness.

Many organizations use standardized passwords for:

- New employees
    
- Password resets
    
- Temporary accounts
    

If users aren't forced to change these passwords, the same password may work against other accounts.

Conceptually:

```text
Standard new-joiner password
          ↓
User A
          ↓
Potentially User B
          ↓
Potentially User C
```

This is where **password spraying** becomes relevant during an authorized engagement.

The module mentions using tools such as `linkedin2username` to generate employee username lists and testing the standard password against a VPN endpoint.

---

# 20. Address Book Enumeration

Many support applications contain an **address book**.

Therefore, once authorized access is obtained, enumerate:

```text
Address book
     ↓
Emails
     ↓
Usernames
     ↓
Potential employee list
```

These can become useful during later authentication testing or OSINT.

The module explicitly recommends exporting emails/usernames from the address book as part of enumeration.

---

# 21. Complete Attack Chain

This is the methodology I'd memorize:

```text
                 ┌───────────────────┐
                 │ Discover osTicket │
                 └─────────┬─────────┘
                           ↓
                 ┌───────────────────┐
                 │ Fingerprint       │
                 │ OSTSESSID / footer│
                 └─────────┬─────────┘
                           ↓
                 ┌───────────────────┐
                 │ Enumerate tickets │
                 │ & functionality   │
                 └─────────┬─────────┘
                           ↓
                 ┌───────────────────┐
                 │ Obtain company    │
                 │ email information │
                 └─────────┬─────────┘
                           ↓
                 ┌───────────────────┐
                 │ Enumerate external│
                 │ services           │
                 └─────────┬─────────┘
                           ↓
                 ┌───────────────────┐
                 │ OSINT / credential│
                 │ discovery         │
                 └─────────┬─────────┘
                           ↓
                 ┌───────────────────┐
                 │ Test credentials  │
                 │ appropriately     │
                 └─────────┬─────────┘
                           ↓
                 ┌───────────────────┐
                 │ Support agent     │
                 │ access            │
                 └─────────┬─────────┘
                           ↓
                 ┌───────────────────┐
                 │ Read historical   │
                 │ tickets           │
                 └─────────┬─────────┘
                           ↓
                 ┌───────────────────┐
                 │ Sensitive info /  │
                 │ password exposure │
                 └─────────┬─────────┘
                           ↓
                 ┌───────────────────┐
                 │ Other services    │
                 │ / VPN             │
                 └───────────────────┘
```

---

# 🎯 CPTS High-Value Points

### Fingerprinting

Look for:

```text
OSTSESSID
```

and:

```text
powered by osTicket
Support Ticket System
```

### Nmap

Nmap may only reveal:

```text
Apache
IIS
```

Don't assume that means the application isn't there.

### Core lesson

```text
Application not vulnerable
        ≠
No attack path
```

### Important CVE

```text
CVE-2020-24881
```

- osTicket 1.14.1
    
- SSRF
    
- Potential internal-resource access / port scanning
    

### Support portal value

A support portal may reveal:

```text
Email addresses
Usernames
Internal systems
Password-reset information
Temporary credentials
Other employees
```

### Authentication

A login field may accept:

```text
username
OR
email address
```

Don't overlook the second option.

---

# 🧪 CPTS Enumeration Checklist

## Discovery

-  Check web applications discovered by EyeWitness
    
-  Look for `OSTSESSID`
    
-  Search for `powered by osTicket`
    
-  Look for `Support Ticket System`
    
-  Identify `/open.php`
    
-  Identify `/scp/login.php`
    

## Application Enumeration

-  Determine whether ticket creation is possible
    
-  Check ticket status functionality
    
-  Examine ticket numbering
    
-  Determine whether emails are correlated with tickets
    
-  Enumerate staff/user functionality
    
-  Check address book functionality
    

## Information Gathering

-  Look for company email addresses
    
-  Look for employee usernames
    
-  Examine historical tickets
    
-  Look for password-reset conversations
    
-  Look for internal system names
    
-  Identify external services
    

## Credential Assessment

-  Check authorized leaked credentials
    
-  Try username vs email when supported
    
-  Look for password reuse
    
-  Identify standard/reset passwords
    
-  Assess MFA on external services
    
-  Conduct password spraying only within engagement scope/rules
    

---

# 🛡️ Defensive Lessons

The module concludes with several practical mitigations.

Organizations should:

1. **Limit externally exposed applications**
    
2. **Enforce MFA on external portals**
    
3. Provide security-awareness training
    
4. Advise employees not to use corporate emails for third-party services
    
5. Enforce strong password policies
    
6. Disallow common passwords such as:
    
    - `welcome`
        
    - `password`
        
    - Company name
        
    - Seasons
        
    - Months
        
7. Require users to change their initial password after first login
    
8. Periodically expire passwords where appropriate
    

These recommendations are directly reflected in the module's closing section.

---

# ⚡ Final Cheat Sheet

```text
                 osTICKET
                     │
        ┌────────────┴────────────┐
        ↓                         ↓
  Fingerprinting             Functionality
        │                         │
   OSTSESSID               Create tickets
   osTicket footer         Check tickets
        │                         │
        └────────────┬────────────┘
                     ↓
             Information Leakage
                     │
          ┌──────────┼──────────┐
          ↓          ↓          ↓
        Emails    Usernames   Passwords
          │          │          │
          └──────────┼──────────┘
                     ↓
                Other Services
                     │
                     ↓
              Potential Access
```

### 🔥 One-line memory hook

**`osTicket → fingerprint → tickets → company emails → usernames → support-agent access → sensitive ticket data → password-reset leakage → credential reuse → other services.`**

The biggest CPTS lesson here is **think beyond CVEs**: a helpdesk can become an attack pivot simply because its normal business workflow contains information that was never meant to be exposed to an attacker.