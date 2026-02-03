## 🎯 Purpose of the Penetration Tester Path

This path prepares you to perform **real-world penetration tests** at a **basic to intermediate professional level**, covering:

- External network penetration tests
    
- Internal network penetration tests
    
- Active Directory assessments
    
- Web application security assessments
    
- Reporting and client communication
    

> The emphasis is not on “running tools” but on understanding **why** vulnerabilities exist, **how** to exploit them, and **how** to advise clients on fixing them.

---

## 🧠 HTB Academy Learning Philosophy

**Core philosophy: _Learn by doing_**

|Principle|What it Means in Practice|
|---|---|
|Hands-on learning|Labs, mini networks, skill assessments in every module|
|Risk-based thinking|Focus on what truly impacts clients|
|Understanding the “why”|Learn root causes of vulnerabilities|
|Methodology building|Develop a repeatable testing process|
|Ethical & legal use|Practice only in authorized environments|
|Muscle memory|Repetition of real assessment tasks|
|Well-rounded mindset|Discover → Exploit → Remediate → Detect → Prevent|

> Goal: Create testers who can think, not just click tools.

---

## ⚖️ Ethical and Legal Foundations (Critical for Pentesters)

Penetration testing is **legally permitted hacking** — but **only** with:

- Signed Scope of Work (SoW)
    
- Rules of Engagement
    
- Written client authorization
    
- Defined scope (IPs, URLs, ranges, etc.)
    

### ❌ Illegal Actions

- Scanning or probing any system without permission
    
- Testing outside defined scope
    
- Using exploits that could cause damage without approval
    

### ✅ Legal Practice Environments

- HTB Academy labs
    
- HTB main platform boxes/labs
    
- Bug bounty platforms like:
    
    - HackerOne
        
    - Bugcrowd
        

> Always: **When in doubt → Ask → Get it in writing → Document everything**

---

## 🧩 The Big Picture: Phases of a Penetration Test

This entire path mirrors a real assessment against a fictional company (**Inlanefreight**).

### The core phases you will repeatedly cycle through:

1. **Reconnaissance**
    
2. **Enumeration**
    
3. **Attack Planning**
    
4. **Exploitation**
    
5. **Lateral Movement**
    
6. **Privilege Escalation**
    
7. **Post-Exploitation / Pillaging**
    
8. **Documentation & Reporting**
    

> Pillaging and lateral movement are **iterative** — you revisit them many times.

---

## 🗺️ How Each Module Maps to the Pentest Phases

### Phase 1 — Reconnaissance, Enumeration & Planning

![Image](https://www.cyberciti.biz/media/new/cms/2012/11/welcome-nmap.png)

![Image](https://www.researchgate.net/publication/338495014/figure/fig2/AS%3A845607224745985%401578619881258/Principal-OSINT-workflows-and-derived-intelligence.png)

![Image](https://miro.medium.com/v2/resize%3Afit%3A1400/1%2AULW69Pa1lukURkGNcgQiYw.png)

![Image](https://assets.sprocketsecurity.com/blog/Directory-Brute-force-at-Scale.png)

|Module|What You Learn|Why It Matters|
|---|---|---|
|Network Enumeration with Nmap|Port scanning, service detection|Identify attack surface|
|Footprinting|OSINT, domains, metadata|Map external presence|
|Information Gathering – Web|Web recon, directories, tech stack|Find web attack vectors|
|Vulnerability Assessment|Identify misconfigs & vulns|Prioritize targets|
|File Transfers|Moving tools/payloads|Required for exploitation|
|Shells & Payloads|Reverse/bind shells|Initial foothold|
|Using the Metasploit Framework|Framework-based exploitation|Speed + reliability|

---

### Phase 2 — Exploitation & Lateral Movement

![Image](https://img2.helpnetsecurity.com/posts/oclhashcat.jpg)

![Image](https://academy.hackthebox.com/storage/modules/158/PivotingandTunnelingVisualized.gif)

![Image](https://www.mdpi.com/electronics/electronics-11-02629/article_deploy/html/images/electronics-11-02629-g002-550.jpg)

![Image](https://delinea.com/hs-fs/hubfs/delinea-blog-12-privilege-escalation-example-of-the%20steps-an-attacker-will-take.jpg?name=delinea-blog-12-privilege-escalation-example-of-the+steps-an-attacker-will-take.jpg&width=750)

|Module|What You Learn|Why It Matters|
|---|---|---|
|Password Attacks|Brute force, spraying, cracking|Common initial access vector|
|Attacking Common Services|SMB, FTP, SSH, etc.|Real-world service abuse|
|Pivoting/Tunneling/Port Forwarding|Network traversal|Reach internal systems|
|Active Directory Enumeration & Attacks|AD abuse techniques|Critical for internal tests|

---

### Phase 3 — Web Exploitation
![[Pasted image 20260203204000.png]]
![[Pasted image 20260203203826.png]]



![Image](https://miro.medium.com/1%2AnBHP_IDyxI3cdKyUehpW9g.png)

|Module|What You Learn|Why It Matters|
|---|---|---|
|Using Web Proxies|Intercept/modify traffic|Understand app behavior|
|Ffuf|Directory/file brute forcing|Hidden content discovery|
|Login Brute Forcing|Auth weaknesses|Entry point|
|SQL Injection Fundamentals|Database compromise|High impact vuln|
|SQLMap Essentials|Automation of SQLi|Efficiency|
|XSS|Client-side attacks|Data/session theft|
|File Inclusion|LFI/RFI|Code execution paths|
|File Upload Attacks|Web shells|Persistent access|
|Command Injections|OS command execution|Full system compromise|
|Web Attacks & Common Apps|Real scenarios|Practical exposure|

---

### Phase 4 — Post-Exploitation & Privilege Escalation

![Image](https://delinea.com/hs-fs/hubfs/LinEnum.gif?name=LinEnum.gif&width=750)

![Image](https://delinea.com/hs-fs/hubfs/delinea-blog-12-privilege-escalation-example-of-the%20steps-an-attacker-will-take.jpg?name=delinea-blog-12-privilege-escalation-example-of-the+steps-an-attacker-will-take.jpg&width=750)

![Image](https://ars.els-cdn.com/content/image/3-s2.0-B9781597494861000048-f04-07.jpg)

![Image](https://ismg-cdn.nyc3.cdn.digitaloceanspaces.com/articles/post-exploitation-framework-targets-microsoft-servers-showcase_image-1-a-19071.jpg)

|Module|What You Learn|Why It Matters|
|---|---|---|
|Linux Privilege Escalation|Local root techniques|Full control of Linux hosts|
|Windows Privilege Escalation|SYSTEM/Admin escalation|Critical in AD environments|

> This is where **pillaging** happens: credentials, files, keys, tokens.

---

### Phase 5 — Reporting & Capstone

|Module|What You Learn|Why It Matters|
|---|---|---|
|Documentation & Reporting|Note-taking, evidence, reports|Most important client deliverable|
|Attacking Enterprise Networks|Full simulated pentest|Apply everything together|

> You are judged more by your **report** than your shell.

---

## 🔁 Iterative Concepts Revisited Throughout the Path

These are not single modules — they happen constantly:

- Lateral Movement
    
- Pillaging
    
- Credential harvesting
    
- Enumeration after each compromise
    
- Updating attack plan based on findings
    

---

## 🧭 Recommended Learning Order

1. Follow modules **in order**
    
2. Revisit this intro periodically
    
3. Practice on HTB boxes alongside modules
    
4. After completion → specialize in:
    
    - Active Directory
        
    - Web
        
    - Reverse Engineering
        

If underprepared → complete **Information Security Foundations** first.

---

## 🧑‍💼 Mindset of a Professional Pentester

You must learn to think like:

- An attacker (creativity)
    
- A defender (remediation advice)
    
- A consultant (communication)
    
- A lawyer (scope & legality)
    
- A project manager (organization)
    

---

## 🧾 Golden Rules to Remember

- Stay within scope
    
- Get everything in writing
    
- Document everything
    
- Do no harm
    
- Ask before running risky exploits
    
- Understand the root cause of every vulnerability
    
- Build your own repeatable methodology
    

---

## 🏁 Final Outcome After This Path

You will be able to:

✅ Perform external, internal, AD, and web pentests  
✅ Move laterally in networks confidently  
✅ Escalate privileges on Linux & Windows  
✅ Write professional reports clients trust  
✅ Think methodically, not randomly  
✅ Provide remediation, not just findings

---

