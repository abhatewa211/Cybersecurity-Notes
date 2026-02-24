## 🔎 Information Gathering — Purpose

Once Pre-Engagement is complete and authorization is in place, Information Gathering begins.

> This phase **never really ends**. You return to it again and again during the test.

All exploitation decisions are based on what you learn here.

Penetration Testing Stages:  
**Pre-Engagement → Information Gathering → Vulnerability Assessment → Exploitation → Post-Exploitation → Lateral Movement → Proof-of-Concept → Post-Engagement**

---

## 🧱 The 4 Categories of Information Gathering

You must perform **all four** in every engagement:

1. **Open-Source Intelligence (OSINT)**
    
2. **Infrastructure Enumeration**
    
3. **Service Enumeration**
    
4. **Host Enumeration**
    

These apply **externally and internally**.

---

## 1️⃣ Open-Source Intelligence (OSINT)

OSINT = gathering publicly available information about:

- Company
    
- Employees
    
- Technology stack
    
- Code leaks
    
- Credentials
    
- Infrastructure clues
    

### Common OSINT Sources

- GitHub / GitLab repositories
    
- StackOverflow code snippets
    
- Social media (LinkedIn, Twitter)
    
- Job postings (reveal tech stack)
    
- Paste sites / breach dumps
    
- Documentation sites
    
- Public DNS records
    

### ⚠️ Critical Finds During OSINT

- SSH private/public keys
    
- API keys, tokens
    
- Passwords in code
    
- Internal URLs
    
- Credentials in commits
    

If found early → follow **RoE incident reporting procedure** before proceeding.

> Developers frequently leak secrets without realizing it.

---

## 2️⃣ Infrastructure Enumeration

Goal: **Map the company’s presence on the Internet / Intranet**

You build a map of:

- Domains & subdomains
    
- IP addresses
    
- Name servers
    
- Mail servers
    
- Web servers
    
- Cloud infrastructure
    
- Firewalls / WAF presence
    
- IDS/IPS hints
    

You compare all discovered assets against the **scoping document**.

### Why this matters

- Identifies attack surface
    
- Reveals security controls (for evasive testing)
    
- Shows network layout
    
- Provides targets for password spraying later
    

Internal vs External doesn’t matter — same goal.

---

## 3️⃣ Service Enumeration

Now you ask:

> “What services can I talk to?”

For each host:

- Open ports
    
- Service names
    
- Service versions
    
- Purpose of the service
    

### Why versions matter

Older versions often:

- Have known exploits
    
- Are unpatched because admins fear breaking things
    
- Expose legacy vulnerabilities
    

Admins often choose **functionality over security**.

Understanding _why_ a service exists gives you attack ideas.

---

## 4️⃣ Host Enumeration

Now you ask:

> “What exactly is this machine?”

For each host:

- Operating system
    
- Role (web, DB, AD, file share, etc.)
    
- Internal communications
    
- Exposed services
    
- Network relationships
    

### Important Realization

Internally accessible services are often:

> Poorly secured because “they’re not exposed to the internet.”

This is where many major findings occur.

---

## 🏴‍☠️ Internal Information Gathering (Post-Exploitation)

Once you gain access to a machine, Information Gathering continues **locally**.

This overlaps with:

- Post-Exploitation
    
- Privilege Escalation
    
- Lateral Movement
    

You now look for:

- Credentials
    
- Config files
    
- Scripts
    
- Databases
    
- Local services
    
- Stored secrets
    
- Sensitive documents
    

---

## 💰 Pillaging (Critical Concept)

Pillaging = **local information gathering on an already compromised host**

It is **not** a separate stage.

It is part of:

- Information Gathering
    
- Privilege Escalation
    
- Lateral Movement
    

You pillage to find:

- Employee data
    
- Customer data
    
- Credentials
    
- Network paths
    
- Tokens/keys
    
- Internal documentation
    

> Pillaging shows the **impact** of the breach and enables further movement.

### Where Pillaging is Taught (spread across modules)

- Network Enumeration with Nmap
    
- Password Attacks
    
- AD Enumeration & Attacks
    
- Linux/Windows Privilege Escalation
    
- Attacking Common Services/Applications
    
- Attacking Enterprise Networks
    

You will practice this on **150+ targets** in the path.

---

## 🧠 Key Mindset

Humans exchange information → so do services and hosts.

Every service communication has a purpose:

- Store data
    
- Authenticate
    
- Generate values
    
- Transfer files
    

Understanding this purpose reveals **how to abuse it**.

---

## ✅ What Good Information Gathering Gives You

- Attack surface map
    
- Technology stack
    
- Weak services
    
- Misconfigurations
    
- Credentials
    
- Internal trust relationships
    
- Paths for lateral movement
    
- Evidence for impact
    

---

## ❌ What Happens If You Rush This Phase

- You miss easy credentials
    
- You waste time exploiting wrong targets
    
- You overlook the real entry point
    
- You fail to understand the environment
    
- Exploitation becomes guessing
    

---

## 🏁 Summary

Information Gathering is:

- The most repeated phase
    
- The most important phase
    
- The foundation of every successful exploit
    

You are not “looking for vulnerabilities” yet.

You are learning:

> **How the company works, how systems talk, and where humans make mistakes.**