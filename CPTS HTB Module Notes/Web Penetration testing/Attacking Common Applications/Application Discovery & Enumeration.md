![Image](https://images.openai.com/static-rsc-4/VIzuSiBcuFy5sWIVFwey9mqvoPvX4OcU_HGikN4JjQXrKpNW-_mbTqEntvqNzJgTvfG2fgkyGrXDEtGGfXhSmpa04JMciAGTj-OLBkqsSV2GNj9Ayio7yH9jtBjMZJ0IutlWjrSO2-ffGhl-dnapRlW7n5q3pwJTulT556v5TTY1_4M4f0bruRIAWWbLdYcd?purpose=fullsize)
![Image](https://images.openai.com/static-rsc-4/EOCSonxg4PkZMGLGxxHD-9zguuvJrshBNlFCnTja6oJF89Uwp7wdhl76IC6GIEHW9Fpu37qHcX6M4RFUdLtqn4gIaoSYOJS_UFkDCguD0NYPeWSWXfhCTkwi2iNTyIG7VofISoMuNEYJZVnEL-2hxBGcDW9Y3Vkvgxp1OkyS8fR7Lm_WvMDEgl1xpJlfUEyx?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/7mI_ss5etemKJdYL8WVjX6laz7hEULnYyRH-6GMNTc27LlFG41fReGmzhoU6aKWHuWXVbu010K1-Wf0ygy6zi0IH4MDqGez8xqkZN25ao5vnUYgK-SpMuUA_q5pf52yPRuTI1IJ9F0xcPRSUbNXxB32ueCIfPi5BSCy8n20LlbmtxXbij75pqDlTUyqRXckQ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/1CNcv7qJI_xH9ORHoRTQBPdh158MHVSvYiQrr4jjdFyd1IlrM3vfSLFID1qEcqy4JF6QKYS2uQ_uU3oKzE9X9cVXeZdl4oO77ChkkUji18j7ol_4GqI7rvhp824Zt9PRxxb4JzuPOz5X_etR0QFzJiDd6zFbNFb-4iz7X0eztd04cj-kK95JTNSdlLqqBaTZ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/I7qIA6WZgT_3Cve6VKHAHqe_Zeq5ijIOjHUkMyW72YweBrhWZGfZTFKxa9ynaMEoXLNA0iJJSQhH3wkKbwN84w3xSuNcj2ouJ6mzkLKxkuwtBXkkP5ZQUujnRxbySPe8zsP-LJRkOoga5pDvuEuZyoy3Iz6rCbPGXbzHfndlonuzr9zwYS-Qv-p1hOV2h8yR?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/yuuVwzly9E5Q6F88gZm3KSgyC9SoiJFrPPDR5in97CWTJ3_6w9Q6wlV2kKjA_XvoXxc8lGYUpuPg3wp8a-8xSjxXqjcYvzVOfFi7yAKnRzwh85337RTR3lmOHCc2zM4hToPxU0uW3DVZy0nGYBhUJn1ylWHOTuFvmF_qvEB8as3ZFwfoVN5aiof5T2PH_gV-?purpose=fullsize)

## 1. What Is Application Discovery & Enumeration?

An organization should maintain an **asset inventory** containing:

- Network-connected devices
    
    - Servers
        
    - Workstations
        
    - Network appliances
        
- Installed software
    
- Applications used throughout the environment
    

The purpose is simple:

> **If an organization does not know what exists on its network, it cannot properly protect it.**

The inventory should ideally tell the organization:

- Which applications exist
    
- Whether applications are hosted locally or by a third party
    
- Current patch level
    
- Whether applications are approaching **end-of-life**
    
- Whether unauthorized applications or **"shadow IT"** exist
    
- Whether applications use strong, non-default passwords
    
- Whether **multi-factor authentication (MFA)** is enabled
    
- Whether administrative portals are restricted to specific IPs or **localhost**
    

---

# ⭐ 2. Why Enumeration Is Important

Many organizations have incomplete visibility into their networks.

As penetration testers, our enumeration can therefore provide significant value to the client.

During discovery, we may identify:

### Forgotten applications

Applications that were deployed years ago but are no longer actively maintained.

### Demo/trial software

For example, a demo version whose trial license expired and changed its authentication behavior.

The source specifically mentions **Splunk** as an example.

### Weak/default credentials

Examples:

```text
admin:admin
```

### Unauthorized applications

Applications installed without proper approval.

### Misconfigured applications

Applications that are exposed or configured insecurely.

### Publicly vulnerable applications

Applications affected by known vulnerabilities.

These findings can be included in the penetration-test report and supporting appendices, such as:

```text
Host → Service → Application → Version → Finding
```

Enumeration data can also help organizations establish **periodic and proactive reconnaissance** so that security gaps are found before attackers discover them.

---

# 🧭 3. Getting the "Lay of the Land"

A penetration tester may begin an assessment with:

- Very little information
    
- A set of IP addresses
    
- CIDR ranges
    
- A black-box scope
    

The objective is to gradually understand the environment.

A typical discovery process:

```text
Scope
  ↓
Identify Live Hosts
  ↓
Port Scanning
  ↓
Identify Services
  ↓
Identify Web Applications
  ↓
Screenshot / Fingerprint Applications
  ↓
Prioritize Interesting Hosts
  ↓
Detailed Enumeration
  ↓
Manual Validation
  ↓
Testing / Exploitation
```

The source describes starting with a **ping sweep** to identify live hosts, followed by targeted port scanning and then deeper scanning to identify services.

---

# 4. Initial Web Discovery with Nmap

One of the first things we want to identify is:

> **Which hosts are running web services?**

A useful initial scan targets common web ports.

### Important command

```bash
nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list
```

### Breakdown

|Option|Meaning|
|---|---|
|`-p`|Specify ports|
|`80,443,...`|Common web/application ports|
|`--open`|Show only open ports|
|`-oA web_discovery`|Save output in all major Nmap formats|
|`-iL scope_list`|Read targets from a file|

### Ports being checked

```text
80      → HTTP
443     → HTTPS
8000    → Common alternate HTTP
8080    → Common alternate web service
8180    → Alternate HTTP
8888    → Alternate web service
10000   → Often used by web-based management applications
```

---

# ⚠️ 5. Why Manual Enumeration Doesn't Scale

Imagine finding hundreds or thousands of hosts running:

```text
80/tcp
443/tcp
```

Manually opening:

```text
http://IP:80
https://IP:443
```

for every host would be extremely inefficient.

This becomes especially problematic because penetration tests usually operate under **strict time constraints**.

Therefore, we need tools that can process large amounts of enumeration data automatically.

---

# 🛠️ 6. EyeWitness & Aquatone

Two important tools highlighted in this section are:

- **EyeWitness**
    
- **Aquatone**
    

![Image](https://images.openai.com/static-rsc-4/vHF2Qb2Dpm5wfLS2yWJnpo7KA4qKLeKQYTH2yvhPFWhbC-XdG0E2nWPN67ZrKlGbNyJLv5B1i98yzevxOgl5Ri3bhmvrxFNimyTuUQRHnw1ycnEU0Rbp1g1LyzvZNmacZWku2r3tZcoIG4lTuVNkDBslZlhNM7tzy9RAe9YFTFzcgz4fVo7ttf9v8qNkihR7?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/zalBtleC2k9f31pFE5SNOiojikDSe0jYsbjA56lSHRKh8voieBx65E5noDnFo2lgK74vuhB05pluqH1OAUnk4VfUPYkqYmMvtkJ-aVEJoPCvfCqpi3GXttFdDiDZ5fjArcGIn2M5Qi6JmNjfelQYKTx6Att9BYr7CCqkgozOBtbqpdNCTNyUJ0niGYqn0e_K?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/a1ZFISUZXVC2r4tVp-Z77AC2bFWXDqmA6VMSrLqT0hkYr1ysIByH2YTKuy2VWqerLy_cw36oCn2p8LetNiS0zgJCg0WVU2a1iYgC0Mrywe-ORb5ua3qplrtjZ3itN-d_H1EO6yyOWHwStoVLAFV1cROqy--VPTxDH2OKlYkiQiAWlrHYuuwZTgL9ZWzQki9H?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/R31KW7clgFmDfeT3dTfqgc2SGuXEW92RPKL9KjQn3CiptsMuo5GMzGojjAyiR-QJ5F-xXDf_kIXFerCenAmxudw80eiZ1oDOnH_rZxocL96P-RgKn1aDQvjaQaJYWj38sAjY4WoOS4-uJAbcSLNEoW5GlDcKQvHwY2O1Wpa8H4DcuX0IaKuawkz-XzojN4ox?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/vSGy9SE3YVqmrcAnOizl654A52PnbfFefLhfLBTb8-Fkun6UWZsxwL4Q-IKgop59myTBm-0FD-dc7T-MmfLTFR4kA-uxIVYzOSjkH6j_MSlTAjvAY1WKYIMba_cSnNuHKqNWC0bAEKwkNLB26ZXjFYmhbU1YPEX7DhZl31X55GaR9FW-pSWsqEt4dGvuzt5O?purpose=fullsize)

Both can take Nmap XML output and rapidly:

- Visit discovered web services
    
- Take screenshots
    
- Identify applications
    
- Help organize the web attack surface
    

### Input support

|Tool|Nmap XML|Nessus XML|Masscan XML|
|---|--:|--:|--:|
|**EyeWitness**|✅|✅|—|
|**Aquatone**|✅|—|✅|

The resulting screenshots make it much easier to review potentially hundreds of web applications from a browser-based report.

---

# 📝 7. Getting Organized

This is **extremely important for CPTS**.

Penetration testing isn't just about technical exploitation.

You need a strong:

- Note-taking methodology
    
- Documentation process
    
- Organization system
    
- Reporting workflow
    

The source recommends setting up a dedicated **Application Discovery** section in your notebook.

Suggested structure:

```text
External Penetration Test - <Client Name>
│
├── Scope
│
├── Client Points of Contact
│
├── Credentials
│
├── Discovery/Enumeration
│   ├── Scans
│   └── Live Hosts
│
├── Application Discovery
│   ├── Scans
│   └── Interesting/Notable Hosts
│
├── Exploitation
│   ├── <Hostname or IP>
│   └── <Hostname or IP>
│
└── Post-Exploitation
    ├── <Hostname or IP>
    └── <Hostname or IP>
```

---

# ⭐ 8. What You Should Record for Every Scan

Every scan should ideally have:

### 1. Date/time

Record **when** the scan occurred.

### 2. Exact command

Don't just write:

> "Ran Nmap."

Save the actual syntax:

```bash
sudo nmap ...
```

### 3. Target

Record exactly what was scanned.

### 4. Output

Save the resulting files.

For example:

```text
web_discovery.nmap
web_discovery.gnmap
web_discovery.xml
```

### Why?

Later, the client may ask:

> "What was this activity?"

Your notes allow you to reproduce exactly what happened.

Good documentation also makes the final report significantly easier to produce.

---

# 🔥 9. The CPTS Mindset: Build Your Methodology

The source strongly emphasizes building a **repeatable methodology**.

Your process shouldn't be:

```text
Scan randomly
↓
See something interesting
↓
Attack immediately
```

Instead:

```text
Scope
↓
Discovery
↓
Enumeration
↓
Organization
↓
Prioritization
↓
Manual Validation
↓
Testing
↓
Documentation
```

This makes the assessment:

- More thorough
    
- More efficient
    
- More reproducible
    
- Less likely to miss critical vulnerabilities
    

---

# 10. Initial Scope

The example scope contains hosts such as:

```text
app.inlanefreight.local
dev.inlanefreight.local

drupal-dev.inlanefreight.local
drupal-qa.inlanefreight.local
drupal-acc.inlanefreight.local
drupal.inlanefreight.local

blog-dev.inlanefreight.local
blog.inlanefreight.local

app-dev.inlanefreight.local

jenkins-dev.inlanefreight.local
jenkins.inlanefreight.local

web01.inlanefreight.local

gitlab-dev.inlanefreight.local
gitlab.inlanefreight.local

support-dev.inlanefreight.local
support.inlanefreight.local

inlanefreight.local

10.129.201.50
```

Notice something important:

```text
-dev
-qa
-acc
```

These naming conventions can provide clues about the environment.

---

# ⭐ 11. Enumeration Is Iterative

The source doesn't recommend doing one giant scan and considering discovery finished.

Instead:

```text
Initial Scan
     ↓
Analyze Results
     ↓
Identify Interesting Hosts
     ↓
Deeper Scan
     ↓
New Services Found
     ↓
More Application Discovery
     ↓
Manual Testing
```

For example:

### Stage 1

Scan common web ports:

```bash
sudo nmap -p 80,443,8000,8080,8180,8888,10000 \
--open -oA web_discovery -iL scope_list
```

### Stage 2

Run EyeWitness/Aquatone.

### Stage 3

Review interesting hosts.

### Stage 4

Perform deeper Nmap scanning.

For example:

```bash
sudo nmap --open -sV 10.129.201.50
```

### Stage 5

Repeat screenshotting/application discovery against additional scan results.

This is why the source describes enumeration as an **iterative process**.

---

# 12. Don't Depend Entirely on Scanners

A scanner is an **input to manual testing**, not a replacement for the penetration tester.

This is one of the most important points in the section:

> **The human element in penetration testing is essential.**

Scanners can identify:

- Open ports
    
- Services
    
- Known vulnerabilities
    
- Common configurations
    

But manual testing can discover:

- Unique vulnerabilities
    
- Application logic flaws
    
- Dangerous configurations
    
- Unexpected functionality
    
- Attack chains
    

The source explicitly states that the most unique and severe vulnerabilities and misconfigurations are often found through **thorough manual testing**.

---

# 🔎 13. Reading Nmap Results

Example:

```text
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
8000/tcp open  http-alt
8080/tcp open  http-proxy
8089/tcp open  unknown
```

From this alone, we can already start building a picture of the host.

For example:

```text
80      → IIS/web server
8000    → Possible Splunk
8080    → Possible PRTG
3389    → RDP
445     → SMB
```

A deeper `-sV` scan provides additional information.

---

# 🧪 14. Nmap Service Enumeration

Command:

```bash
sudo nmap --open -sV 10.129.201.50
```

### `-sV`

`-sV` tells Nmap to perform **service/version detection**.

The result included:

```text
80/tcp   open  http          Microsoft IIS httpd 10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0
8000/tcp open  http          Splunkd httpd
8080/tcp open  http          Indy httpd 17.3.33.2830
8089/tcp open  ssl/http      Splunkd httpd
```

---

# 🧠 15. What Can We Infer?

From the service scan:

### Operating system

Nmap identifies:

```text
OS: Windows
```

### Web server

```text
Microsoft IIS 10.0
```

on:

```text
80/tcp
```

### Splunk

```text
8000/tcp
8089/tcp
```

### PRTG

```text
8080/tcp
```

This immediately gives us several applications to investigate further.

---

# 🚩 16. Pay Attention to Hostnames

Hostnames can reveal useful information.

For example:

```text
app.inlanefreight.local
```

doesn't tell us much.

But:

```text
app-dev.inlanefreight.local
```

is much more interesting.

Why?

Because **development environments** may contain:

- Untested features
    
- Debug functionality
    
- Development credentials
    
- Less restrictive configurations
    

The source specifically says hosts containing **`dev`** are worth noting because they may have untested features or debug mode enabled.

### Mental rule

```text
prod → interesting
dev  → VERY interesting
qa   → interesting
acc  → interesting
```

Not because these environments are automatically vulnerable, but because their names provide **hypotheses worth testing**.

---

# 🚩 17. GitLab-Dev — Why It's Interesting

The example identifies:

```text
gitlab-dev.inlanefreight.local
```

as an **interesting host**.

Potential areas of interest include:

- Public Git repositories
    
- Source code
    
- Credentials accidentally committed
    
- Configuration files
    
- Clues about other subdomains
    
- Additional VHosts
    
- User registration functionality
    
- Previous Git commits
    

The source notes that some GitLab instances may allow users to register without administrator approval and that additional repositories may become available after authentication.

### Important concept

A source-code repository can contain much more than source code:

```text
Repository
   │
   ├── Source code
   ├── Configuration
   ├── API keys
   ├── Credentials
   ├── Hostnames
   ├── Internal URLs
   └── Historical commits
```

---

# 👁️ 18. EyeWitness

**EyeWitness** can take:

- Nmap XML
    
- Nessus XML
    
- URL lists
    
- IP lists
    

and generate screenshots/reports of web applications.

It uses **Selenium** for web screenshots.

It can also:

- Categorize applications
    
- Fingerprint applications
    
- Suggest default credentials
    
- Perform DNS resolution
    
- Test specified ports
    
- Handle HTTP/HTTPS
    

---

# 19. Installing EyeWitness

On a Debian/Kali-style system:

```bash
sudo apt install eyewitness
```

It can alternatively be:

- Installed from the repository
    
- Run using Docker
    
- Built for Windows
    

---

# 20. EyeWitness Help

Running:

```bash
eyewitness -h
```

provides available options.

Important options include:

|Option|Purpose|
|---|---|
|`--web`|HTTP screenshot using Selenium|
|`-f`|File containing URLs|
|`-x`|Nmap XML / Nessus file|
|`--single`|Capture one URL|
|`--no-dns`|Skip DNS resolution|
|`--timeout`|Maximum request wait time|
|`--jitter`|Random delay between requests|
|`--delay`|Delay before screenshot|
|`--threads`|Number of threads|
|`--max-retries`|Retry failed requests|
|`-d`|Output directory|
|`--proxy-ip`|Proxy IP|
|`--proxy-port`|Proxy port|
|`--only-ports`|Restrict ports|
|`--prepend-https`|Add HTTPS to targets|
|`--ocr`|OCR functionality|

---

# ⭐ 21. Running EyeWitness

The source uses:

```bash
eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness
```

This means:

```text
web_discovery.xml
       ↓
   EyeWitness
       ↓
Visit discovered web services
       ↓
Take screenshots
       ↓
Categorize/fingerprint
       ↓
HTML report
```

The example processed:

```text
26 Hosts
```

and generated the report in:

```text
/home/mrb3n/Projects/inlanfreight/inlanefreight_eyewitness
```

---

# 🌊 22. Aquatone

![Image](https://images.openai.com/static-rsc-4/TbjPNlHby920IlzdrlABjpjc6Vpjt6uDkfC4r4Q7VgsituVAp-pJUN4WLbv6q15xIreY0aHoChuqm95ToytGxVfb0-VV1q0LC1fDZl38smefioD0Hm49KFXDU-IeskR4JyI2nRA51oQTtHBe8w97P_MELYGODwlWkNrU9wIa-F4j3W0o0E03qVHiB2Tf3pu5?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/zalBtleC2k9f31pFE5SNOiojikDSe0jYsbjA56lSHRKh8voieBx65E5noDnFo2lgK74vuhB05pluqH1OAUnk4VfUPYkqYmMvtkJ-aVEJoPCvfCqpi3GXttFdDiDZ5fjArcGIn2M5Qi6JmNjfelQYKTx6Att9BYr7CCqkgozOBtbqpdNCTNyUJ0niGYqn0e_K?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/a1ZFISUZXVC2r4tVp-Z77AC2bFWXDqmA6VMSrLqT0hkYr1ysIByH2YTKuy2VWqerLy_cw36oCn2p8LetNiS0zgJCg0WVU2a1iYgC0Mrywe-ORb5ua3qplrtjZ3itN-d_H1EO6yyOWHwStoVLAFV1cROqy--VPTxDH2OKlYkiQiAWlrHYuuwZTgL9ZWzQki9H?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/vSGy9SE3YVqmrcAnOizl654A52PnbfFefLhfLBTb8-Fkun6UWZsxwL4Q-IKgop59myTBm-0FD-dc7T-MmfLTFR4kA-uxIVYzOSjkH6j_MSlTAjvAY1WKYIMba_cSnNuHKqNWC0bAEKwkNLB26ZXjFYmhbU1YPEX7DhZl31X55GaR9FW-pSWsqEt4dGvuzt5O?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/R31KW7clgFmDfeT3dTfqgc2SGuXEW92RPKL9KjQn3CiptsMuo5GMzGojjAyiR-QJ5F-xXDf_kIXFerCenAmxudw80eiZ1oDOnH_rZxocL96P-RgKn1aDQvjaQaJYWj38sAjY4WoOS4-uJAbcSLNEoW5GlDcKQvHwY2O1Wpa8H4DcuX0IaKuawkz-XzojN4ox?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/F3h5Ou9xreXAh6AWmQ8nwDgC2t6I7NJCIK8EWr34cjpAacprrLb0c32Qk2GKNoO2Wd2hBl6SDyMaHu6nT38uSpH7UAFqFQsfJ2j7PY_-7A12MwRvhP3k9ZKaGi_T_AwodvPddnQ7yDxuLw0HynZcE4ZU92eRASjfYsucXv2_SSF_-CmnqhWoxhfaap8Uvop3?purpose=fullsize)

**Aquatone** is another web discovery and screenshotting tool.

It can accept:

- `.txt` host lists
    
- Nmap `.xml`
    
- Masscan XML
    

For Nmap XML, the source uses:

```bash
cat web_discovery.xml | ./aquatone -nmap
```

---

# 23. Aquatone Example Results

The tool reported targets such as:

```text
http://web01.inlanefreight.local:8000/: 403 Forbidden
http://app.inlanefreight.local/: 200 OK
http://jenkins.inlanefreight.local/: 403 Forbidden
http://app-dev.inlanefreight.local/: 200
http://10.129.201.50:8000/: 200 OK
```

Then it generated screenshots and clustered similar pages.

The final report included:

```text
Successful requests: 65
Failed requests:     0

2xx: 47
3xx: 0
4xx: 18
5xx: 0

Screenshots successful: 65
Screenshots failed:     0
```

and generated:

```text
aquatone_report.html
```

---

# 🆚 24. EyeWitness vs Aquatone

|Feature|EyeWitness|Aquatone|
|---|---|---|
|Web screenshots|✅|✅|
|Nmap XML|✅|✅|
|Nessus XML|✅|❌|
|Masscan XML|❌|✅|
|Fingerprinting|✅|✅/limited|
|Categorization|✅|✅|
|HTML report|✅|✅|

### Practical takeaway

Both tools serve a similar purpose:

> **Turn huge amounts of web enumeration data into something a human can quickly review.**

---

# 🎯 25. Interpreting the Screenshot Report

The generated reports organize targets into categories.

One particularly useful category is:

```text
High Value Targets
```

These should generally receive priority during review.

However:

> **Don't only review the first few pages.**

Large environments can produce hundreds of report pages.

An interesting application may be buried deep within the report.

---

# 🔥 26. OpManager Example

This section gives a very important real-world example.

The tester discovered:

```text
ManageEngine OpManager
```

buried inside a large EyeWitness report.

It was:

```text
Internet exposed
+
Default credentials:
admin:admin
```

The tester was able to:

1. Log in
    
2. Execute a PowerShell script
    
3. Achieve code execution
    

Most importantly, the application was running under:

```text
Domain Admin
```

This resulted in:

> **Full compromise of the internal network**

### ⭐ Lesson

Something buried deep in a huge report can become the **most important finding in the entire engagement**.

---

# 🚨 27. Tomcat — High-Value Target

The source specifically highlights **Tomcat** as an exciting discovery, particularly during an external penetration test.

The tester would investigate:

```text
/manager
```

and:

```text
/host-manager
```

and test appropriate/default credentials within the authorized assessment.

If administrative access is obtained, the source notes that a malicious **WAR file** can potentially be uploaded to achieve RCE using JSP code.

Conceptually:

```text
Tomcat
   ↓
/manager or /host-manager
   ↓
Administrative access
   ↓
WAR deployment
   ↓
JSP execution
   ↓
RCE
```

---

# 🌐 28. Custom Web Applications

The main:

```text
http://inlanefreight.local
```

website is another important target.

**Custom applications deserve special attention** because they may contain:

- Unique vulnerabilities
    
- Authentication flaws
    
- Business logic issues
    
- File handling flaws
    
- Information disclosure
    
- Custom APIs
    
- Poor security controls
    

The tester should also determine whether the site is using a popular CMS such as:

```text
WordPress
Joomla
Drupal
```

---

# 🎫 29. osTicket

The example also identifies:

```text
support-dev.inlanefreight.local
```

as running **osTicket**.

This is interesting because support ticketing systems can potentially contain:

- Customer information
    
- Internal communications
    
- Email addresses
    
- Support conversations
    
- Sensitive operational information
    

The source notes that osTicket has suffered from severe vulnerabilities historically.

It also highlights that, where social engineering is explicitly **in scope**, support systems can potentially become useful for interacting with support personnel or manipulating workflows.

---

# ⚠️ 30. Don't Attack Too Early

This is another **very important methodology point**.

During the discovery phase:

> **Do not immediately attack every interesting host.**

Instead:

```text
Discover
   ↓
Record
   ↓
Categorize
   ↓
Prioritize
   ↓
Continue Discovery
   ↓
Then Test
```

Why?

Because immediately diving down one rabbit hole can cause you to:

- Waste time
    
- Miss another critical application
    
- Miss easier attack paths
    
- Lose track of the overall attack surface
    

The source emphasizes that every small detail during information gathering can potentially make or break the assessment.

---

# 📤 31. The File Upload Example

One of the strongest examples in the section involves a file upload page.

The application displayed:

```text
"Please only upload .zip and .tar.gz files"
```

During a **client-sanctioned, in-scope penetration test**, the tester tested whether the restriction was actually enforced.

A test:

```text
.aspx
```

file was uploaded.

Surprisingly:

- Client-side validation was absent
    
- Back-end validation was absent
    
- The file successfully uploaded
    

The tester then performed directory discovery and found:

```text
/files
```

with directory listing enabled.

The uploaded file was accessible there.

The tester subsequently demonstrated the issue using an `.aspx` web shell and obtained a foothold.

### ⭐ Security lesson

Never assume that a message such as:

```text
"Only upload .zip files"
```

means the server actually enforces it.

You need to distinguish:

```text
Client-side validation
        ≠
Server-side validation
```

---

# 🧠 32. File Upload Attack-Path Concept

The example demonstrates this general chain:

```text
File Upload Function
        ↓
Weak/Missing Validation
        ↓
Unexpected File Accepted
        ↓
Predictable/Discoverable Upload Location
        ↓
Directory Listing / File Access
        ↓
Server Processes Uploaded File
        ↓
Code Execution
        ↓
Foothold
```

This is a classic example of why **application functionality itself can be an attack surface**.

---

# 🏢 33. Internal Penetration Test Applications

Internal assessments can reveal many of the same applications plus infrastructure-specific interfaces.

Examples mentioned include:

### Printers

Potentially interesting because some printer interfaces may expose:

- LDAP configuration
    
- Credentials
    
- Network information
    

### Virtualization

```text
ESXi
vCenter
```

### Server management

```text
iLO
iDRAC
```

### Network devices

Potentially:

- Routers
    
- Switches
    
- Firewalls
    
- Other network appliances
    

### IoT devices

### IP phones

### Code repositories

### SharePoint

### Custom intranet portals

### Security appliances

---

# 🌍 34. External Penetration Test — What Might You See?

The source says an external assessment may include:

```text
Custom applications
CMS platforms
Tomcat
Jenkins
Splunk
Remote Desktop Services (RDS)
SSL VPN
Outlook Web Access (OWA)
O365
Edge/network device login portals
```

This demonstrates that **application discovery isn't restricted to websites**.

Anything exposing a web interface may become part of the attack surface.

---

# 🗺️ 35. Complete Application Discovery Methodology

Here's the whole methodology condensed into one flow:

![Image](https://images.openai.com/static-rsc-4/luc3wrT4EE-7GppFzP6vlcfY-mrMM04wZzqwZ0oN8ZzPMu69RhGI6XscUiYATO3daau97_6TIktfnXu61vBeLkdTxSr5_iZqQx1TgS3DBAcIGxI0YBYXg2ip1_CmFlnJAfrYto5ukD5VsC-AR-NFkgnuYcHHsfqu79oJldbkMDu7IhrZ6nIRC0B9Zf47Iur_?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/VIzuSiBcuFy5sWIVFwey9mqvoPvX4OcU_HGikN4JjQXrKpNW-_mbTqEntvqNzJgTvfG2fgkyGrXDEtGGfXhSmpa04JMciAGTj-OLBkqsSV2GNj9Ayio7yH9jtBjMZJ0IutlWjrSO2-ffGhl-dnapRlW7n5q3pwJTulT556v5TTY1_4M4f0bruRIAWWbLdYcd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/b1aupRzGlR9gu-FEyu9sEChb3R2RM48y19ZSMKi4m30YJMqHz5icDEiDPLqUULOLq3rYoYXNEyulTw2VPAM1aHoVRsfBgz1d-Js3aQxvha2IlKZc8R9PQrCqcRxbIWOPpgZzJ3xAiCefoTclDHn1GZTrTJveoA2Yp-t3HCkqYK-7gN31EMzBUPtJB5P7YaEI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/zCbSX-oCZetwfyso7wE_UfL28HYw1fkPxVWmrf9mW4rUG3v4WjlB-3MDeXMmgOFQF9glYBYrpRmQN9GAYU2SfUPWic7CyT60Ucyy5W8eNCuyIewVKy4MWo40AKCtGxl8pYyJMA8W-6yWAIqUKaGmj28cMIk355o9a6ryYERgp20iviGYkJm1GHOlY4wtnIJs?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/kVafuXt-kq7VpCS-LvPH_V-onyDdpIYeyFArjDIBFcKbFtZWOs63sZosKn-NSYlGkzdM7v4zj_JClk_QI1WnppgQOvTyb96aj_lCfQyIa60RC1TqOR-CsD8t4VNX39tm7kUbnW5WeF_mxi4oZ1bDpmZwinBDtRuqWdPjjndQigmcfv_tpK8fiFFc1Iix3ndk?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/c0Ybwqo_kHSDNuFHMXqxuJLQw4_GH9RaAv0Mhym5KdAGJkrF9AY8CQSUtysFuDq5umX5XQyNk7YBEp1lSu8oAkRKugeV19uf__BCRvkBQWXkn5EkgXzceD-dtXO-e7AFzhtstZHys3FTehZFnjte0Igvt_UYKg_RVGOY4dQmRnAFWSF70f9Rwc1br9uXc6FS?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/CxZ1gZgZUn_QSHJlpwUG9nmSjfOg2lYTPfG8t5fgHOX8Z3yqMQv2wrghZjutUcn6at6KFiRGpf5ebKL61-sGe-N5MTCiUpXCHDxCDGIhsbQLGNHgLNuO4fGxvZ8iK9BHskURO-XBxQ56P27597zjwa55ejdpcXGAFzqCE5yncS4ES-daSiqINNZ3GreuT-GO?purpose=fullsize)

```text
                    SCOPE
                      │
                      ▼
              Identify Targets
                      │
                      ▼
                Live Hosts
                      │
                      ▼
             Initial Nmap Scan
                      │
                      ▼
            Identify Web Services
                      │
                      ▼
          ┌───────────┴───────────┐
          ▼                       ▼
      EyeWitness              Aquatone
          │                       │
          └───────────┬───────────┘
                      ▼
             Screenshot Reports
                      │
                      ▼
             Identify Applications
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
        CMS         Dev         Admin
      WordPress     Hosts       Panels
      Drupal        QA          APIs
      Joomla        Hosts       etc.
          │           │           │
          └───────────┼───────────┘
                      ▼
              Interesting Hosts
                      │
                      ▼
               Deeper Nmap
                    -sV
                      │
                      ▼
            Application Enumeration
                      │
                      ▼
             Manual Validation
                      │
                      ▼
              Prioritize Findings
                      │
                      ▼
             Exploitation / Testing
                      │
                      ▼
              Document Everything
```

---

# 🧾 36. The Most Important Commands

### Initial web discovery

```bash
sudo nmap -p 80,443,8000,8080,8180,8888,10000 \
--open -oA web_discovery -iL scope_list
```

### Service/version detection

```bash
sudo nmap --open -sV 10.129.201.50
```

### EyeWitness

```bash
sudo apt install eyewitness
```

Then:

```bash
eyewitness --web -x web_discovery.xml \
-d inlanefreight_eyewitness
```

### Aquatone

```bash
cat web_discovery.xml | ./aquatone -nmap
```

---

# 🔑 37. High-Value Things to Remember

## ⭐ Asset inventory

Organizations should know:

```text
What exists?
Where is it?
What software is running?
What version?
Is it patched?
Is it EOL?
Who owns it?
Is it authorized?
Is authentication secure?
```

---

## ⭐ Discovery ≠ Exploitation

Discovery should build your understanding of the environment before you begin extensive exploitation.

---

## ⭐ Nmap is the starting point

Use Nmap to identify:

```text
Hosts
↓
Ports
↓
Services
↓
Versions
```

---

## ⭐ EyeWitness/Aquatone reduce manual work

Instead of manually opening hundreds of URLs:

```text
Nmap XML
   ↓
EyeWitness/Aquatone
   ↓
Screenshots
   ↓
HTML report
   ↓
Human analysis
```

---

## ⭐ `dev` hosts are interesting

Examples:

```text
app-dev
gitlab-dev
jenkins-dev
drupal-dev
support-dev
```

They may contain:

- Untested functionality
    
- Debug features
    
- Different authentication
    
- Development mistakes
    

---

## ⭐ Don't ignore 403

For example:

```text
jenkins.inlanefreight.local → 403 Forbidden
```

A `403` does **not** mean:

> "Nothing interesting exists."

It means access is currently forbidden.

The application itself may still be worth investigating.

---

## ⭐ Don't ignore weird ports

Web applications don't only run on:

```text
80
443
```

Also investigate:

```text
8000
8080
8180
8888
10000
```

and any other ports discovered during broader scans.

---

# 🧠 38. CPTS-Level Mental Checklist

When you discover a web application, ask:

```text
[ ] What is the hostname?
[ ] What is the IP?
[ ] What port is it running on?
[ ] HTTP or HTTPS?
[ ] What application is running?
[ ] What version?
[ ] What technology?
[ ] Is it a CMS?
[ ] Is it a development environment?
[ ] Is authentication enabled?
[ ] Are default credentials possible?
[ ] Is there an admin portal?
[ ] Are there APIs?
[ ] Are there file upload features?
[ ] Are there file download/read features?
[ ] Is directory listing enabled?
[ ] Is there script execution functionality?
[ ] Is there exposed source code?
[ ] Are Git repositories accessible?
[ ] Are historical commits interesting?
[ ] Are there known vulnerabilities?
[ ] Is the application unnecessarily exposed?
[ ] What does the application reveal about the network?
```

---

# 🏆 39. The Biggest Lesson of This Section

The goal isn't to become someone who can run:

```bash
nmap
```

and then wait for vulnerabilities.

The goal is to develop a **repeatable discovery methodology**.

The source's final message is particularly important:

> The module cannot cover every application you will encounter. Instead, the goal is to learn prevalent applications, their common vulnerabilities, misconfigurations, and how to abuse their built-in functionality.

And just as importantly, strong penetration testers distinguish themselves through:

- Sound methodology
    
- Organization
    
- Attention to detail
    
- Communication
    
- Thorough note-taking
    
- Documentation
    
- Reporting
    

## 🔥 One-line memory trick

```text
DISCOVER → ENUMERATE → ORGANIZE → PRIORITIZE → VALIDATE → TEST → DOCUMENT
```

**Don't rush from discovery to exploitation.**

The better you understand the entire attack surface first, the more likely you are to find the **unexpected attack path** that everyone else missed.