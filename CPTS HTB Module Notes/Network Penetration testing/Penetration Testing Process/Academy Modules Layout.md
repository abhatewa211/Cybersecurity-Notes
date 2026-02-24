## 🧭 The Master Blueprint — Penetration Testing Lifecycle

![Image](https://www.compassitc.com/hs-fs/hubfs/Penetration%20Test%20Phases.webp?height=604&name=Penetration+Test+Phases.webp&width=610)

![Image](https://images.openai.com/static-rsc-3/8BqmzCgk5Cm0lEugrjJccQ_FiuFnY3pWT8uyhHdUSALTE9_d7FN1zQH7OmnaQZ8otGSY5w6DYepW9CCsTFHqcrKnrrQCxVXrRfOsTWXBazY?purpose=fullsize)

![Image](https://coursereport-production.imgix.net/uploads/image/file/233/NGT_Academy_Pen_Testing_infographic.png?auto=compress%2Cformat&h=1156&w=800)

**Phases you will loop through repeatedly:**

1. Pre-Engagement
    
2. Information Gathering
    
3. Vulnerability Assessment
    
4. Exploitation
    
5. Post-Exploitation (Pillaging)
    
6. Lateral Movement
    
7. Proof-of-Concept (PoC)
    
8. Post-Engagement (Reporting & Cleanup)
    

> The Academy modules are arranged to **train you along this exact loop**.

---

## 🧠 Why HTB Academy (vs. pure CTF)

HTB began as black-box CTFs. Great for experts, hard for beginners.

**Academy adds:**

|CTF|Academy|
|---|---|
|No guidance|Guided methodology|
|Tool usage|Analytical thinking|
|Random targets|Process-driven learning|
|Points|Professional skillset|

---

## 🧱 Phase 0 — Foundations (Before Touching Targets)

> You cannot assess what you don’t understand.

|#|Module|What it builds|
|---|---|---|
|1|Learning Process|How to learn efficiently|
|2|Linux Fundamentals|Server internals|
|3|Windows Fundamentals|Enterprise OS internals|
|4|Introduction to Networking|How hosts communicate|
|5|Introduction to Web Applications|Web architecture|
|6|Web Requests|HTTP/HTTPS internals|
|7|JavaScript Deobfuscation|Dynamic client logic|
|8|Introduction to Active Directory|Identity backbone|
|9|Getting Started|First guided compromise|

**Outcome:** mental models for Linux, Windows, Web, AD, and Networks.

---

## 🔎 Phase 1 — Information Gathering

> Most pentesters fail here by rushing.

![Image](https://nmap.org/book/images/zenmap-fig-tab-nmap-output.png)

![Image](https://www.researchgate.net/publication/338495014/figure/fig2/AS%3A845607224745985%401578619881258/Principal-OSINT-workflows-and-derived-intelligence.png)

![Image](https://miro.medium.com/v2/resize%3Afit%3A1400/1%2AULW69Pa1lukURkGNcgQiYw.png)

![Image](https://miro.medium.com/v2/resize%3Afit%3A1400/1%2As3xZCWUK0lXdKZ2MlmQ4ig.png)

|#|Module|Purpose|
|---|---|---|
|10|Network Enumeration with Nmap|Hosts, ports, services|
|11|Footprinting|Service behavior & misconfigs|
|12|Information Gathering – Web|Hidden apps, tech stack|
|13|OSINT: Corporate Recon|Public data → internal access|

**You map:**

- Attack surface
    
- Technologies
    
- Users
    
- Services
    
- Web apps
    

---

## 🧪 Phase 2 — Vulnerability Assessment

Two lenses:

1. Scanner-based (known vulns)
    
2. Human analysis (logic & misconfig)
    

|#|Module|Why|
|---|---|---|
|14|Vulnerability Assessment|Use scanners properly|
|15|File Transfers|Move tools/payloads|
|16|Shells & Payloads|Reliable access methods|
|17|Metasploit Framework|Faster exploitation workflow|

**Outcome:** ready to exploit with preparation, not guessing.

---

## 💥 Phase 3A — Exploitation (Network & Services)

![Image](https://www.oreilly.com/api/v2/epubs/urn%3Aorm%3Abook%3A9781838642303/files/assets/8336a925-45e9-433d-ae5e-7b330f546345.png)

![Image](https://blog.ropnop.com/images/2016/06/metasploit_ftp.png)

![Image](https://academy.hackthebox.com/storage/modules/158/PivotingandTunnelingVisualized.gif)

![Image](https://www.thehacker.recipes/assets/Chained%20remote%20port%20forwarding%20diagram.CMq8S-Kx.png)

|#|Module|Focus|
|---|---|---|
|18|Password Attacks|Credential abuse|
|19|Attacking Common Services|SMB, FTP, SSH, RDP|
|20|Pivoting/Tunneling/Port Forwarding|Reach internal hosts|
|21|AD Enumeration & Attacks|Domain takeover paths|

---

## 🌐 Phase 3B — Web Exploitation (Major External Surface)

![Image](https://portswigger.net/burp/documentation/desktop/images/getting-started/quick-start-pro-proxy-history.png)

![Image](https://cdn.acunetix.com/wp_content/uploads/2012/10/image01.png)

![Image](https://codegrazer.com/img/reflected_xss_script_src_2.png)

![Image](https://portswigger.net/support/images/methodology_attacking_users_xss_tag_1.png)

|#|Module|Attack Class|
|---|---|---|
|22|Using Web Proxies|Inspect/modify traffic|
|23|Ffuf|Endpoint discovery|
|24|Login Brute Forcing|Break auth|
|25|SQL Injection Fundamentals|DB compromise|
|26|SQLMap Essentials|Automate SQLi|
|27|XSS|Session/user attacks|
|28|File Inclusion|Read/execute files|
|29|Command Injections|OS command exec|
|30|Web Attacks|IDOR, XXE, verbs|
|31|Attacking Common Applications|Real apps in the wild|

---

## 🧗 Phase 4 — Post-Exploitation (Privilege Escalation & Pillaging)

> You’re in. Now become **root/SYSTEM** and harvest.

![Image](https://delinea.com/hs-fs/hubfs/PrivEsc-HTB-solidstate-using-wwf-to-root.gif?name=PrivEsc-HTB-solidstate-using-wwf-to-root.gif&width=750)

![Image](https://delinea.com/hs-fs/hubfs/delinea-blog-12-privilege-escalation-example-of-the%20steps-an-attacker-will-take.jpg?name=delinea-blog-12-privilege-escalation-example-of-the+steps-an-attacker-will-take.jpg&width=750)

![Image](https://cdn.prod.website-files.com/6130a9118b1be9aebe2c2837/66e42796d84d9fc93e243df2_Credential_harvesting_guide.webp)

![Image](https://cymulate.com/uploaded-files/2025/05/Credential-Dumping-Attack-Flow.png)

|#|Module|Goal|
|---|---|---|
|32|Linux Privilege Escalation|Root on Linux|
|33|Windows Privilege Escalation|SYSTEM/Admin on Windows|

Activities:

- Pillaging (creds, tokens, files)
    
- Local enumeration
    
- Prepare for lateral movement
    

---

## 🔁 Phase 5 — Lateral Movement (Happens Everywhere)

You reuse:

- Credentials
    
- Network access
    
- Trust relationships
    

Seen across:

- Pivoting module
    
- PrivEsc modules
    
- AD module
    
- Getting Started
    

---

## 🧾 Phase 6 — Proof of Concept (PoC)

Admins must **reproduce** your findings.

|#|Module|Purpose|
|---|---|---|
|34|Introduction to Python 3|Automate PoC steps|

PoC includes:

- Exact commands
    
- Exact path
    
- Repeatability
    

---

## 📝 Phase 7 — Post-Engagement (Most Important Professionally)

> Your report is more important than your shell.

|#|Module|Skill|
|---|---|---|
|35|Documentation & Reporting|Notes → client report|
|36|Attacking Enterprise Networks|Keep big picture view|

You must:

- Remove artifacts
    
- Reconcile notes
    
- Deliver clean documentation
    

---

## 🧠 What HTB Is Really Teaching

Not tools. Not tricks.

- Analytical thinking
    
- Methodology
    
- Pattern recognition
    
- Patience
    
- Organization
    
- Professional communication
    

Like learning guitar: **practice creates ability**.

---

## 🔄 How the Phases Loop in Real Tests

You never go linearly:

Information Gathering ⇄ Vulnerability Assessment ⇄ Exploitation ⇄ Pillaging ⇄ Lateral Movement ⇄ back to Information Gathering…

---

## 🏁 After All 36 Modules, You Can

✅ Perform full external, internal, AD, and web pentests  
✅ Escalate privileges on Linux & Windows  
✅ Move laterally across networks  
✅ Build professional PoCs  
✅ Write client-grade reports  
✅ Think like attacker, defender, and consultant

---

If you want, I can convert this into a **one-page phase → module cheat sheet** or a **mind map** for quick revision.