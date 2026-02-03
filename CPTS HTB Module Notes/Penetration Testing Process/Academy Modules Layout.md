## 🧠 Why HTB Academy Exists (Beyond CTFs)

HTB started as a **black-box CTF platform**. Great for advanced users — terrible for beginners.

HTB Academy was created to:

|CTF Style|Academy Style|
|---|---|
|No guidance|Guided learning path|
|Trial & error|Methodology-driven|
|Tool-focused|Thinking-focused|
|Point scoring|Skill building|
|Advanced-first|Fundamentals-first|

> Goal: build **analytical thinkers**, not challenge solvers.

---

## 🏗️ The Penetration Testing Process (Master Map)

This is the backbone of **every module**.

![Image](https://cdn-blog.getastra.com/2024/08/f564c76f-penetration-testing-phases-2.png)

![Image](https://images.openai.com/static-rsc-3/8BqmzCgk5Cm0lEugrjJccQ_FiuFnY3pWT8uyhHdUSALTE9_d7FN1zQH7OmnaQZ8otGSY5w6DYepW9CCsTFHqcrKnrrQCxVXrRfOsTWXBazY?purpose=fullsize)

![Image](https://cymulate.com/uploaded-files/2025/01/Cyber-Kill-chain-Diagram-1024x629.png)

![Image](https://miro.medium.com/1%2A92Oew8ey45N8rC4pD1GhCw.jpeg)

**Phases:**

1. Pre-Engagement
    
2. Information Gathering
    
3. Vulnerability Assessment
    
4. Exploitation
    
5. Post-Exploitation (Pillaging)
    
6. Lateral Movement
    
7. Proof-of-Concept (PoC)
    
8. Post-Engagement (Reporting & Cleanup)
    

You will **loop** between these constantly.

---

## 🧱 Phase 0 — Foundations Before Touching Targets

These modules exist because:

> You cannot hack what you don’t understand.

|#|Module|Why It Matters|
|---|---|---|
|1|Learning Process|How to learn efficiently|
|2|Linux Fundamentals|Most servers run Linux|
|3|Windows Fundamentals|Most companies run Windows|
|4|Introduction to Networking|How systems communicate|
|5|Introduction to Web Applications|How web apps function|
|6|Web Requests|HTTP/HTTPS internals|
|7|JavaScript Deobfuscation|Understand dynamic web logic|
|8|Introduction to Active Directory|Corporate identity backbone|
|9|Getting Started|First guided box → confidence|

> These build the mental model required for later modules.

---

## 🔎 Phase 1 — Information Gathering

> “If you skip this, exploitation will waste your time.”

![Image](https://www.cyberciti.biz/media/new/cms/2012/11/welcome-nmap.png)

![Image](https://www.osintteam.com/content/images/2024/08/0.-osint-domain-name-workflow.jpg)

![Image](https://miro.medium.com/v2/resize%3Afit%3A1400/1%2AULW69Pa1lukURkGNcgQiYw.png)

![Image](https://miro.medium.com/v2/resize%3Afit%3A1400/1%2As3xZCWUK0lXdKZ2MlmQ4ig.png)

|#|Module|Skill Gained|
|---|---|---|
|10|Network Enumeration with Nmap|Discover hosts, ports, services|
|11|Footprinting|Understand service behavior|
|12|Information Gathering – Web|Discover hidden web content|
|13|OSINT: Corporate Recon|Public data → internal access|

You are mapping:

- Hosts
    
- Services
    
- Users
    
- Web apps
    
- Technologies
    
- Attack surface
    

---

## 🧪 Phase 2 — Vulnerability Assessment

Two approaches:

1. Automated scanning (known vulns)
    
2. Human analysis (misconfigurations, logic flaws)
    

|#|Module|Purpose|
|---|---|---|
|14|Vulnerability Assessment|Using scanners intelligently|
|15|File Transfers|Move tools/payloads reliably|
|16|Shells & Payloads|Gain command execution|
|17|Metasploit Framework|Semi-automated exploitation|

> This phase prepares you for successful exploitation.

---

## 💥 Phase 3 — Exploitation (Network & Services)

![Image](https://content.pentest-tools.com/assets/content/password-auditor-vs-hydra/hydra/bitbucket-1_1.webp)

![Image](https://blog.ropnop.com/images/2016/06/metasploit_ftp.png)

![Image](https://academy.hackthebox.com/storage/modules/158/PivotingandTunnelingVisualized.gif)

![Image](https://www.thehacker.recipes/assets/Chained%20remote%20port%20forwarding%20diagram.CMq8S-Kx.png)

|#|Module|Why Critical|
|---|---|---|
|18|Password Attacks|Credentials = keys to network|
|19|Attacking Common Services|SMB, FTP, SSH, RDP abuse|
|20|Pivoting/Tunneling/Port Forwarding|Reach internal networks|
|21|Active Directory Enumeration & Attacks|Domain takeover skills|

---

## 🌐 Phase 3B — Web Exploitation (Huge Attack Surface)

![Image](https://matthewsetter.com/images/posts/burpsuite-match-and-replace/intercepting-responses-in-burp-suite.png)

![Image](https://portswigger.net/web-security/images/sql-injection.svg)

![Image](https://portswigger.net/support/images/methodology_attacking_users_xss_tag_1.png)

![Image](https://miro.medium.com/1%2AMgRnZXQA-MHIpACILtcCig.jpeg)

|#|Module|Attack Type|
|---|---|---|
|22|Using Web Proxies|Inspect/modify requests|
|23|Ffuf|Discover hidden endpoints|
|24|Login Brute Forcing|Break authentication|
|25|SQL Injection Fundamentals|Database compromise|
|26|SQLMap Essentials|Automate SQLi|
|27|XSS|Session theft, phishing|
|28|File Inclusion|Read/execute files|
|29|Command Injections|OS command execution|
|30|Web Attacks|IDOR, XXE, verb tampering|
|31|Attacking Common Applications|Real-world apps|

---

## 🧗 Phase 4 — Post-Exploitation (Privilege Escalation & Pillaging)

> You are in. Now **become root / SYSTEM** and **harvest everything**.

![Image](https://delinea.com/hs-fs/hubfs/PrivEsc-HTB-solidstate-using-wwf-to-root.gif?name=PrivEsc-HTB-solidstate-using-wwf-to-root.gif&width=750)

![Image](https://delinea.com/hs-fs/hubfs/delinea-blog-12-privilege-escalation-example-of-the%20steps-an-attacker-will-take.jpg?name=delinea-blog-12-privilege-escalation-example-of-the+steps-an-attacker-will-take.jpg&width=750)

![Image](https://cdn.prod.website-files.com/6130a9118b1be9aebe2c2837/66e42796d84d9fc93e243df2_Credential_harvesting_guide.webp)

![Image](https://cymulate.com/uploaded-files/2025/05/Credential-Dumping-Attack-Flow.png)

|#|Module|Goal|
|---|---|---|
|32|Linux Privilege Escalation|Root on Linux|
|33|Windows Privilege Escalation|SYSTEM/Admin on Windows|

You perform:

- Pillaging (files, creds, tokens)
    
- Local enumeration
    
- Preparation for lateral movement
    

---

## 🔁 Phase 5 — Lateral Movement

You use one host to access others.

Occurs inside many modules, especially:

- Getting Started
    
- Linux/Windows PrivEsc
    
- AD Attacks
    
- Pivoting module
    

---

## 🧾 Phase 6 — Proof of Concept (PoC)

Admins must **reproduce** what you did.

|#|Module|Why|
|---|---|---|
|34|Introduction to Python 3|Automate PoC steps|

PoC shows:

- Exact commands
    
- Exact path
    
- Repeatable proof
    

---

## 📝 Phase 7 — Post-Engagement (Reporting & Cleanup)

> Your report is more important than your shell.

|#|Module|Skill|
|---|---|---|
|35|Documentation & Reporting|Professional deliverables|
|36|Attacking Enterprise Networks|Seeing the big picture|

You must:

- Remove payloads/shells
    
- Document every action
    
- Provide clean, reproducible report
    

---

## 🧭 Why This Order Works

This layout trains you to:

1. Understand systems
    
2. Discover targets
    
3. Analyze weaknesses
    
4. Exploit correctly
    
5. Escalate privileges
    
6. Move through networks
    
7. Prove the impact
    
8. Communicate professionally
    

---

## 🧠 The Real Skill HTB Is Teaching

Not tools. Not tricks.

👉 **Analytical thinking**  
👉 **Methodology**  
👉 **Pattern recognition**  
👉 **Patience & organization**

Like learning guitar: knowledge ≠ ability. Practice does.

---

## 🏁 What You Become After These 36 Modules

You can confidently:

- Perform full pentests end-to-end
    
- Handle Linux, Windows, AD, and Web targets
    
- Move laterally across networks
    
- Write professional reports
    
- Think like a consultant, attacker, and defender
    

---

If you want, I can turn this into a **visual mind map** or a **printable phase → module cheat sheet** for quick revision.