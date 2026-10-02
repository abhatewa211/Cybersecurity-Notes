Absolutely. I’ve based these notes on the attached **HTB Documentation & Reporting → Notetaking & Organization** material, while keeping the important terminology, commands, folder structures, and key technical details intact.

![Image](https://images.openai.com/static-rsc-4/iBCalZF0QgHG8HIBQECj9s9MO75WccCRlV5WBeUBtm5Wmzmen8FnB9JgPHDTP8PDIYczTFPY2FskprXpB5xQYvNkrhiQd1SDuV9R3GJusdj41CLG_GqFKCKhs2SXKKJUP30VM-PAtYz-OxpToYRjF4-E5_vzyl7pMRo8U-M0QQuun1i2kiiyal5P83aXhF7Y?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/yohxRO0dIgGpUVtOqtSUmqqKniXod61bl_Z7SDaduCR2kRyULppL-TAOJ6T8zBWRlLee6uEUcPQfXV3Li9JHIHnrHIW9RqslzyKaDYZHT99lMl5xy6akkO_1Gu8kSqFiQEfg-uODeLsfkBV7FZxTS8CfnDz4rx3CqV11cwDaJKpvIVM9yUANyk9iUTyRDocu?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/OZgJNOwOfsB3syndoLRuu-Tbo4MGl8_xvRcsPcvac9YCl-0bhDi0P_2ZAj-6ob_fM1LfpsSqU61qW8nJ8N9Ezc6M3jbVtGx0CdkHu-jmfgAi-3sdCqJ78vybyiK99S1StqhLXxXT8zuVUK53BqBQ0AnUAhaFSNxUF8B3JxgKD-8BBbZ6GAtU6S-LjiIlH9H7?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/U6rHbnrtT1reL-5OiiLNyshDgw9jKlFj1YMqGip3hY6wmIl_NzVVBuqgYtne2bCGGK_LLkjmA-oElEjVivmW-6KmvnyTQwOpLTMFDbqTY-vVyouVY696Qx3n32u1ppBFXHXVJ4VOlqe9ECAi46p5mJCbwr_H9phpwlpuX9cl0zfIWdKmik1o-A-3KF3MqMlF?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/93rn-_p65V1XFH_tpyqWxxNtDsKzOlxZJGkrinbe5qZgvNiABWYJOYES2ENKltMzzXJ_OU05BzLCczs1ZfI-9CfJMpIN3T7w9Z5rIlmT_8C0GUjGpeGG-LpCa43sU9KspPYMODrOW47Ft8PLnBVu5trN8aVB4UtsOosfWUhvu8tUw404Qjiq563yNJea9RzU?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/dgXsh1vOub0ekby0s2StdM-EICq3FDAa37LsKNF_OKNxl4a737ZNg6NTYvikklFy8L2MT8PglkP8p1yQkix2s3xEtaZMknJGJYpbuiT4nhWZv0ERoMqqLrW3sQEPYCsXYUc0WA7xpRDxE-8_NScsHB0pqGLsWhDpmEc_AWfuGWYJ8trIeJ6fhpCva62jLQ0f?purpose=fullsize)

# 📚 Notetaking & Organization

## 1. Why Detailed Notetaking Is Critical

Thorough notetaking is **critical during any penetration-testing assessment**.

Our notes, together with:

- Tool output
    
- Command output
    
- Logs
    
- Screenshots
    
- Evidence
    
- Testing timestamps
    

become the **raw inputs for the final assessment report**. The report is often the main deliverable the client actually sees.

### Why good notes matter

Detailed notes help us:

1. Remember exactly what was tested.
    
2. Reproduce testing steps.
    
3. Answer client questions.
    
4. Troubleshoot issues that occur during testing.
    
5. Build the final report faster.
    
6. Avoid repeating the same testing.
    
7. Prove what activity was performed.
    
8. Correlate testing activity with network events.
    
9. Allow another tester to take over the engagement.
    
10. Maintain consistency across assessments.
    

> **Important:** Being overly verbose in your notes generally does not hurt. Missing important information can.

If another team member needs to cover a client meeting, your notes should allow them to understand **what was done and what was not done**.

---

# 2. Recommended Notetaking Structure

There is **no universal notetaking structure**.

The structure should be adapted according to:

- Project type
    
- Assessment scope
    
- Personal workflow
    
- Client requirements
    
- External vs. internal assessment
    
- Web vs. infrastructure assessment
    
- AD environment
    
- Wireless testing requirements
    

The following categories form a strong baseline.

---

## 2.1 Attack Path

The **Attack Path** documents the complete chain used to compromise a system, host, or environment.

For example:

```text
Initial Enumeration
        ↓
Service Discovery
        ↓
Initial Foothold
        ↓
Credential Discovery
        ↓
Privilege Escalation
        ↓
Lateral Movement
        ↓
Domain Compromise
```

Document the path using:

- Commands
    
- Screenshots
    
- Tool output
    
- Hosts involved
    
- Credentials obtained
    
- Pivoting steps
    
- Important timestamps
    

This makes it much easier to transfer the attack chain directly into the final report.

### CPTS tip

When working on a lab or assessment, maintain an **Attack Path** page from the beginning rather than trying to reconstruct the chain at the end.

---

# 2.2 Credentials

Maintain a centralized location for:

- Credentials provided by the client
    
- Credentials discovered during testing
    
- Usernames
    
- Passwords
    
- Password hashes
    
- API keys
    
- Tokens
    
- Other secrets
    

Example:

```text
Credentials
├── Domain
│   ├── username
│   └── password
├── Local
│   └── username/password
└── Web
    ├── Application A
    └── Application B
```

**Important:** Credentials and other sensitive information must be handled securely and redacted when used as report evidence.

---

# 2.3 Findings

Create a **separate folder for each finding**.

Example:

```text
Evidence/
└── Findings/
    ├── H1 - Kerberoasting
    ├── H2 - ASREPRoasting
    ├── H3 - LLMNR_NBT-NS Response Spoofing
    └── H4 - Weak Credentials
```

Each finding folder can contain:

```text
Finding/
├── Narrative.md
├── Evidence/
├── Screenshots/
├── Command_Output/
└── Remediation_Notes.md
```

The finding notes should contain:

- What happened
    
- Affected host
    
- Vulnerability
    
- Attack steps
    
- Evidence
    
- Impact
    
- Reproduction information
    
- Remediation information
    

---

# 2.4 Vulnerability Scan Research

Maintain a section for everything related to vulnerability scanning.

Record:

- Scanner used
    
- Scan configuration
    
- Targets
    
- Interesting vulnerabilities
    
- False positives
    
- Failed attempts
    
- Follow-up research
    
- Results that require manual validation
    

This prevents you from repeating research that you already performed.

---

# 2.5 Service Enumeration Research

Maintain notes for services discovered during enumeration.

Record:

- Host/IP
    
- Port
    
- Protocol
    
- Service
    
- Version
    
- Enumeration performed
    
- Vulnerabilities investigated
    
- Exploitation attempts
    
- Failed exploitation
    
- Interesting configuration
    
- Possible attack paths
    

Example:

```text
192.168.1.10
│
├── 22/tcp — SSH
│   ├── Version
│   ├── Authentication
│   └── Enumeration
│
├── 80/tcp — HTTP
│   ├── Web application
│   ├── Directories
│   └── Technologies
│
└── 445/tcp — SMB
    ├── Shares
    ├── Users
    └── Authentication
```

---

# 2.6 Web Application Research

Create a dedicated area for interesting web applications.

Record:

- Domains
    
- Subdomains
    
- Virtual hosts
    
- Web ports
    
- Technologies
    
- Login pages
    
- Default credentials tested
    
- Interesting directories
    
- Screenshots
    
- Vulnerabilities
    
- Application behavior
    

The source recommends thorough external subdomain enumeration and using tools such as **Aquatone or EyeWitness** to capture screenshots of applications.

---

# 2.7 Active Directory Enumeration Research

For internal assessments involving Active Directory, keep a dedicated section documenting:

- Domain information
    
- Users
    
- Groups
    
- Computers
    
- Shares
    
- Trust relationships
    
- Kerberos-related information
    
- Permissions
    
- Interesting accounts
    
- Potential attack paths
    
- Enumeration already completed
    

Most importantly, document **what has already been enumerated** so you know what still needs investigation.

---

# 2.8 OSINT

Maintain an OSINT section for useful information discovered externally.

Possible information:

- Domains
    
- Subdomains
    
- Public documents
    
- Usernames
    
- Email addresses
    
- Organizational information
    
- Publicly exposed information
    

---

# 2.9 Administrative Information

Keep important project administration information in one place.

Possible information:

- Project Manager
    
- Client Point of Contact (POC)
    
- Contact information
    
- Rules of Engagement (RoE)
    
- Special objectives
    
- Flags
    
- Project requirements
    
- Important reminders
    
- Testing tasks
    

It can also function as a **running TODO list**.

---

# 2.10 Scoping Information

This is one of the **most important sections**.

Store:

- In-scope IP addresses
    
- CIDR ranges
    
- Domains
    
- URLs
    
- Web applications
    
- VPN information
    
- AD credentials
    
- Web credentials
    
- Explicit exclusions
    
- Other scope restrictions
    

### Golden rule

> **Always verify the scope before testing.**

Your scope notes help prevent accidentally testing systems that are not authorized.

---

# 2.11 Activity Log

Maintain a high-level record of everything performed.

Example:

|Time|Activity|Target|Result|
|---|---|---|---|
|09:00|Nmap scan|10.10.10.10|Ports discovered|
|09:30|Web enumeration|10.10.10.10|Login page found|
|10:00|Credential testing|Web app|Successful|
|10:30|Privilege escalation|Server|Root obtained|

The Activity Log can later help correlate your testing activity with client-side events.

---

# 2.12 Payload Log

Track payloads used during testing.

Record:

- Payload name
    
- Hash
    
- Target host
    
- File path
    
- Timestamp
    
- Purpose
    
- Whether it was removed
    
- Whether the client needs to remove it
    

This becomes especially important when files are uploaded to client systems.

---

# 3. Notetaking Tools

The source lists several possible tools:

- CherryTree
    
- Visual Studio Code
    
- Evernote
    
- Notion
    
- GitBook
    
- Sublime Text
    
- Notepad++
    
- OneNote
    
- Outline
    
- Obsidian
    
- CryptPad
    
- Standard Notes
    

## Local vs Cloud Storage

This is extremely important for professional engagements.

A cloud solution may be acceptable for:

- Training
    
- CTFs
    
- HTB labs
    
- Academy modules
    

However, when dealing with **real client data**, you must consider:

- Company policy
    
- Data-storage requirements
    
- Contracts
    
- Confidentiality
    
- Compliance
    
- Client requirements
    

Always check with the manager/team lead before storing client data in a particular service.

### Obsidian

Obsidian is highlighted as an excellent solution for local storage.

Advantages:

- Local Markdown files
    
- Easy folder structure
    
- Easy organization
    
- Portable
    
- Can be exported
    
- Works well with assessment folders
    

![Image](https://images.openai.com/static-rsc-4/PtTny97JNZo5TllGmPeX6ogdks8OmQLF4FKRHF_wMfqlIOZcSrsbohaF2KL-xbZDDjgmRaj4a9tcj3y5KwFaFQyeo_Sbq7xMfGb8UGyv4g0a07O6TrM8Sgl1fRdpxAGV60DIV89tePPKAV5rKwEE6ClQgsNMyLtgRYAOj2C3da361xG1KCJc-zyqOonc90-S?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/iBCalZF0QgHG8HIBQECj9s9MO75WccCRlV5WBeUBtm5Wmzmen8FnB9JgPHDTP8PDIYczTFPY2FskprXpB5xQYvNkrhiQd1SDuV9R3GJusdj41CLG_GqFKCKhs2SXKKJUP30VM-PAtYz-OxpToYRjF4-E5_vzyl7pMRo8U-M0QQuun1i2kiiyal5P83aXhF7Y?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/-aEQKdXDp5HRLstRA2yYFRzVPAMAjFFGDnmvpFT_pIrHM8xP2hQcAJ2hHYUpH0uk9ZXdz0Dq73PJjN18Y33nz0-WGRQBJ6V6PXJ4m3QgL8N9P-CTpveP1pPBvgmbAelFlevl0EFgWImmlvUbEfV2SHIcw9_Dscv5iEt1JPXtlOlOOCKxY8CLMjsK--vM7Jip?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/9G5XjThea1cvjcI_SJBatJmGeU-pO3Y2CboMZFjxDWNZy-oAFoEUBL54gVf_iMQBMJtJ6CYyc189asFM6VOCKyTC7yfmiiZ4QuEywekICnPncdwVD4YLY6wMSoruzRllCxKbx_SOXToDjDm3-DkLb6ZMlDBSQYKQcNKD7zHqUpeYaayvXc5jGQcDURQmYWG7?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/OZgJNOwOfsB3syndoLRuu-Tbo4MGl8_xvRcsPcvac9YCl-0bhDi0P_2ZAj-6ob_fM1LfpsSqU61qW8nJ8N9Ezc6M3jbVtGx0CdkHu-jmfgAi-3sdCqJ78vybyiK99S1StqhLXxXT8zuVUK53BqBQ0AnUAhaFSNxUF8B3JxgKD-8BBbZ6GAtU6S-LjiIlH9H7?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/HAzZyVAX1nEBqHA7Xrqzb8UK7KfG5a0nq5uitGEQax5Xb5w13aH1GIyr0SbyJzmGK8UVByVkV62n1uo3rUqyGCfyk3hOKOIkLs6kxb91XE5qCcAbEUVrlKmvKSYkl9UZVeVRf09BsP6lzucuQaVp64bUjS0A52mcPk4DNP3Yu-xzP-5DIjwWWVpndMhhBAK2?purpose=fullsize)

---

# 4. Logging

Logging is essential.

You should retain **raw tool output wherever possible**.

Why?

Because your notes may accidentally miss something.

Raw logs can help with:

- Report evidence
    
- Client questions
    
- Event correlation
    
- Reproduction
    
- Troubleshooting
    
- Demonstrating testing performed
    
- Documenting unsuccessful attempts
    

---

# 5. Tmux Logging

The source recommends **Tmux + tmux-logging** for terminal logging.

Tmux logging can save everything typed into a pane to a log file.

This is particularly useful for:

- Exploitation attempts
    
- Enumeration
    
- Troubleshooting
    
- Long assessments
    
- Demonstrating activity
    
- Recording unsuccessful tests
    

## Step 1 — Install Tmux Plugin Manager

```bash
git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm
```

## Step 2 — Create `.tmux.conf`

```bash
touch .tmux.conf
```

## Step 3 — Configure Plugins

```bash
cat .tmux.conf
```

Configuration:

```bash
# List of plugins

set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
set -g @plugin 'tmux-plugins/tmux-logging'

# Initialize TMUX plugin manager (keep at bottom)
run '~/.tmux/plugins/tpm/tpm'
```

These commands and configuration should be kept **exactly as shown** when reproducing the setup.

---

# 6. Load the Tmux Configuration

Run:

```bash
tmux source ~/.tmux.conf
```

Then start a new session:

```bash
tmux new -s setup
```

---

# 7. Enable Tmux Logging

Inside the Tmux session:

```text
Ctrl + B
Shift + I
```

This installs the plugins.

To start logging:

```text
Ctrl + B
Shift + P
```

The bottom of the window should indicate that logging is enabled.

To stop logging:

```text
Ctrl + B
Shift + P
```

or exit the Tmux session.

Important:

> The log file is populated once logging is stopped or the Tmux session exits.

---

# 8. Retroactive Tmux Logging

If you forgot to enable logging before starting your work, you can save the existing pane history.

Use:

```text
Ctrl + B
Alt + Shift + P
```

However, this depends on the amount of history stored in the Tmux `history-limit`.

If the default history limit is too small, earlier commands may be lost.

## Increase History Limit

Add:

```bash
set -g history-limit 50000
```

to `.tmux.conf`.

---

# 9. Tmux Pane Capture

Tmux can also capture a pane's output.

Useful when multiple panes are running simultaneously.

Example:

```text
Pane 1 → Responder
Pane 2 → ntlmrelayx.py
```

Copying terminal output manually may accidentally include output from another pane.

Instead, capture the pane.

Shortcut:

```text
Ctrl + B
Alt + P
```

---

# 10. Useful Tmux Shortcuts

### Create a new session

```bash
tmux new -s sessionname
```

### Split vertically

```text
Ctrl + B
Shift + %
```

### Split horizontally

```text
Ctrl + B
Shift + "
```

### Move between panes

```text
Ctrl + B
O
```

### Clear pane history

```text
Ctrl + B
Alt + C
```

---

# 11. Additional Tmux Plugins

The source highlights:

### tmux-sessionist

Useful for managing sessions.

### tmux-pain-control

Provides easier pane control, resizing and movement.

### tmux-resurrect

Can restore:

- Sessions
    
- Windows
    
- Panes
    
- Pane order
    
- Running programs
    
- Vim sessions
    

---

# 12. Artifacts Left Behind

During testing, track every payload or modification.

At minimum record:

1. When the payload was used
    
2. Host where it was used
    
3. File path on the target
    
4. Whether it was cleaned up
    
5. Whether the client needs to clean it up
    
6. File hash
    

Even if you delete the payload afterward, document it.

---

# 13. Account Creation / System Modifications

If you create accounts or modify system settings, document the change.

Record:

- IP address
    
- Hostname
    
- Timestamp
    
- Description
    
- Location of modification
    
- Application/service modified
    
- Account name
    
- Password, if necessary for client handover
    

## ⚠️ Important Professional Rule

Obtain **written client approval** before:

- Creating accounts
    
- Changing system configuration
    
- Performing potentially disruptive testing
    
- Performing testing that may affect availability/stability
    

This should ideally be clarified during the project kickoff.

---

# 14. Evidence

The client ultimately needs a report that clearly communicates:

- What vulnerability exists
    
- Why it matters
    
- How it was demonstrated
    
- Evidence supporting the finding
    
- Information necessary for reproduction
    

A technically impressive exploit without good evidence is not enough.

Clear evidence helps:

- Security teams
    
- System administrators
    
- Developers
    
- IT teams
    
- Management
    

understand and reproduce the issue.

---

# 15. What Evidence Should You Capture?

Every finding should have evidence.

You should also consider documenting **unsuccessful tests** when useful, especially if the client questions the thoroughness of the assessment.

For command-line testing:

- Tmux logs can provide raw evidence.
    
- Important terminal output should be separately captured.
    
- Screenshots should be used where appropriate.
    

### Evidence hierarchy

A useful approach is:

```text
Raw command output
        ↓
Clean terminal evidence
        ↓
Screenshot when necessary
        ↓
Finding narrative
```

---

# 16. Evidence Storage Structure

A structured folder system prevents:

- Lost evidence
    
- Repeated work
    
- Scope mistakes
    
- Disorganized reports
    
- Missing scan results
    

Suggested structure:

```text
ACME-IPT/
├── Admin
├── Deliverables
├── Evidence
│   ├── Findings
│   ├── Logging output
│   ├── Misc Files
│   ├── Notes
│   ├── OSINT
│   ├── Scans
│   │   ├── AD Enumeration
│   │   ├── Service
│   │   ├── Vuln
│   │   └── Web
│   └── Wireless
└── Retest
```

---

# 17. Meaning of Each Main Folder

## `Admin`

Contains:

- Scope of Work (SoW)
    
- Kickoff notes
    
- Status reports
    
- Vulnerability notifications
    
- Administrative information
    

## `Deliverables`

Contains:

- Final report
    
- Supplemental spreadsheets
    
- Slide decks
    
- Other client deliverables
    

## `Evidence`

Contains actual testing evidence.

### `Evidence/Findings`

One folder per finding.

### `Evidence/Scans/Vuln`

Vulnerability scanner exports.

### `Evidence/Scans/Service`

Service enumeration results.

Examples:

- Nmap
    
- Masscan
    
- Rumble
    

### `Evidence/Scans/Web`

Web application evidence.

Examples:

- Burp state files
    
- ZAP files
    
- EyeWitness
    
- Aquatone
    

### `Evidence/Scans/AD Enumeration`

AD enumeration data.

Examples:

- BloodHound JSON
    
- PowerView CSV
    
- ADRecon
    
- PingCastle
    
- Snaffler
    
- CrackMapExec logs
    
- Impacket output
    

### `Evidence/Notes`

Assessment notes.

### `Evidence/OSINT`

OSINT tool output.

### `Evidence/Wireless`

Wireless testing output when applicable.

### `Evidence/Logging output`

Tmux, Metasploit and other logs.

### `Evidence/Misc Files`

Examples:

- Web shells
    
- Payloads
    
- Custom scripts
    
- Other assessment files
    

### `Retest`

Used to keep evidence from later retesting separate from the original assessment.

---

# 18. Create the Folder Structure Automatically

The source provides this command:

```bash
mkdir -p ACME-IPT/{Admin,Deliverables,Evidence/{Findings,Scans/{Vuln,Service,Web,'AD Enumeration'},Notes,OSINT,Wireless,'Logging output','Misc Files'},Retest}
```

Then verify:

```bash
tree ACME-IPT/
```

Expected structure:

```text
ACME-IPT/
├── Admin
├── Deliverables
├── Evidence
│   ├── Findings
│   ├── Logging output
│   ├── Misc Files
│   ├── Notes
│   ├── OSINT
│   ├── Scans
│   │   ├── AD Enumeration
│   │   ├── Service
│   │   ├── Vuln
│   │   └── Web
│   └── Wireless
└── Retest
```

---

# 19. Combining Obsidian With the Folder Structure

One of the major advantages of Obsidian is that the filesystem structure and notes can be combined.

Example:

```text
Inlanefreight Penetration Test/
│
├── Admin/
├── Deliverables/
│
├── Evidence/
│   ├── Findings/
│   │   ├── H1 - Kerberoasting.md
│   │   ├── H2 - ASREPRoasting.md
│   │   ├── H3 - LLMNR&NBT-NS Response Spoofing.md
│   │   └── H4 - Tomcat Manager Weak Credentials.md
│   │
│   ├── Logging output/
│   ├── Misc files/
│   ├── Notes/
│   │   ├── 1. Administrative Information.md
│   │   ├── 2. Scoping Information.md
│   │   ├── 3. Activity Log.md
│   │   ├── 4. Payload Log.md
│   │   ├── 5. OSINT Data.md
│   │   ├── 6. Credentials.md
│   │   ├── 7. Web Application Research.md
│   │   ├── 8. Vulnerability Scan Research.md
│   │   ├── 9. Service Enumeration Research.md
│   │   ├── 10. AD Enumeration Research.md
│   │   ├── 11. Attack Path.md
│   │   └── 12. Findings.md
│   │
│   ├── OSINT/
│   ├── Scans/
│   │   ├── AD Enumeration/
│   │   ├── Service/
│   │   ├── Vuln/
│   │   └── Web/
│   └── Wireless/
│
└── Retest/
```

This provides a **repeatable structure** that can be adapted from engagement to engagement.

---

# 20. Formatting and Redaction

Sensitive information must be properly protected.

### Redact:

- Credentials
    
- Passwords
    
- Password hashes
    
- Personally Identifiable Information (PII)
    
- Sensitive client information
    
- Other confidential information
    

---

# 21. Screenshot Best Practices

When using screenshots:

### 1. Highlight important information

Use:

- Arrows
    
- Boxes
    
- Annotations
    

### 2. Crop unnecessary information

Only show the relevant section.

### 3. Keep useful context

For web evidence, consider keeping:

- Address bar
    
- URL
    
- Hostname
    
- Relevant application context
    

### 4. Avoid unnecessary full-screen screenshots

A focused screenshot is easier to understand.

---

# 22. Terminal Output vs Screenshots

Whenever possible, prefer **terminal output instead of screenshots**.

Why?

Terminal output is:

- Easier to redact
    
- Easier to format
    
- Easier to highlight
    
- Easier to copy
    
- Easier for the client to reproduce
    
- Smaller than huge collections of screenshots
    

However:

> **Never modify the actual command or output.**

You may remove irrelevant sections using:

```text
<SNIP>
```

But do not change the actual result or add information that wasn't present.

---

# 23. Why You Should Not Alter Terminal Output

Suppose the original output is:

```text
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
```

You may shorten it:

```text
PORT     STATE SERVICE
22/tcp   open  ssh
<SNIP>
443/tcp  open  https
```

But you should **never change**:

```text
22/tcp open ssh
```

into something that was not actually returned.

The evidence needs to represent the actual testing activity.

---

# 24. Redacting Sensitive Information

## ❌ Avoid relying on blur/pixelation

The source specifically warns that pixelation/blurring may potentially be reversed.

## ✅ Prefer solid redaction

Use a solid black box or another opaque shape over sensitive information.

Also make sure the redaction is applied **to the actual image**, rather than simply placing an editable shape over the image inside Word.

---

# 25. Terminal Credential Redaction

Usually the primary terminal information requiring redaction is:

- Passwords
    
- Password hashes
    
- Other secrets
    

For hashes, the source suggests preserving a small portion to demonstrate that a hash existed while removing the sensitive middle portion.

Example:

```text
Original:
5f4dcc3b5aa765d61d8327deb882cf99

Redacted:
5f4d<REDACTED>cf99
```

For cleartext credentials:

```text
<REDACTED>
```

or:

```text
<PASSWORD REDACTED>
```

---

# 26. Highlighting Terminal Evidence

Color-coded terminal evidence can make reports easier to understand.

You can visually distinguish:

```text
COMMAND
   ↓
Interesting output
   ↓
Evidence supporting finding
```

This is particularly useful when dealing with:

- Long Nmap results
    
- Large LDAP output
    
- Complex web requests
    
- Large payloads
    
- Authentication results
    

The goal is to make it immediately obvious **what command was executed and what result matters**.

---

# 27. What NOT to Archive

A penetration tester is trusted to **"do no harm" wherever possible**.

Avoid:

- Bringing down hosts
    
- Affecting availability
    
- Changing passwords without authorization
    
- Significant configuration changes
    
- Difficult-to-reverse modifications
    
- Collecting unnecessary sensitive information
    
- Collecting unnecessary PII
    

---

# 28. Sensitive Files

Suppose you discover a network share containing sensitive files.

You generally don't need to open every file and copy its contents.

Instead, evidence may simply show the directory listing:

```text
SensitiveShare/
├── employee_data.xlsx
├── payroll.pdf
├── credentials.txt
└── customer_database.sql
```

This can demonstrate the exposure without unnecessarily extracting sensitive information.

Why?

Because collecting actual PII can create additional:

- Compliance obligations
    
- Storage requirements
    
- Privacy concerns
    
- Legal concerns
    

---

# 29. Module Exercise

The module provides a partially completed Obsidian notebook on a Parrot Linux host.

The source provides an RDP command:

```bash
xfreerdp /v:10.129.203.82 /u:htb-student /p:HTB_@cademy_stdnt!
```

After connecting:

1. Open Obsidian.
    
2. Browse the sample notebook.
    
3. Review the pre-populated information.
    
4. Study the organization.
    
5. Use the structure as a model for your own notes.
    

---

# 🧠 CPTS / Pentesting Quick Memory Sheet

## The 12 Important Note Sections

```text
1. Administrative Information
2. Scoping Information
3. Activity Log
4. Payload Log
5. OSINT Data
6. Credentials
7. Web Application Research
8. Vulnerability Scan Research
9. Service Enumeration Research
10. AD Enumeration Research
11. Attack Path
12. Findings
```

These categories appear in the example assessment structure.

---

# 📁 Evidence Structure — Memorize This

```text
Project/
├── Admin
├── Deliverables
├── Evidence
│   ├── Findings
│   ├── Logging output
│   ├── Misc Files
│   ├── Notes
│   ├── OSINT
│   ├── Scans
│   │   ├── AD Enumeration
│   │   ├── Service
│   │   ├── Vuln
│   │   └── Web
│   └── Wireless
└── Retest
```

---

# 🔥 Most Important Rules

### Rule 1 — Document Everything

```text
Command
+
Output
+
Timestamp
+
Target
+
Result
```

### Rule 2 — Keep Raw Logs

Always retain raw output wherever possible.

### Rule 3 — Track Failed Attempts

Failed exploitation attempts are still useful documentation.

### Rule 4 — Track Payloads

For every uploaded payload:

```text
Host
+
Path
+
Timestamp
+
Hash
+
Cleanup Status
```

### Rule 5 — Respect Scope

Know:

```text
IN-SCOPE
OUT-OF-SCOPE
EXCLUSIONS
```

before testing.

### Rule 6 — Get Written Approval

Before potentially disruptive:

- System changes
    
- Account creation
    
- Stability-impacting tests
    
- Availability-impacting tests
    

### Rule 7 — Protect Sensitive Data

Redact:

```text
Passwords
Hashes
PII
Tokens
Secrets
```

### Rule 8 — Don't Alter Evidence

You can use:

```text
<SNIP>
```

but don't fabricate or modify results.

### Rule 9 — Prefer Terminal Output

Use clean text output when possible.

### Rule 10 — Don't Collect More Data Than Necessary

Especially sensitive client information and PII.

---

# ⚡ Tmux Cheat Sheet

|Action|Shortcut|
|---|---|
|Default prefix|`Ctrl+B`|
|Start logging|`Prefix + Shift+P`|
|Stop logging|`Prefix + Shift+P`|
|Install plugins|`Prefix + Shift+I`|
|Retroactive logging|`Prefix + Alt+Shift+P`|
|Pane capture|`Prefix + Alt+P`|
|Split vertically|`Prefix + Shift+%`|
|Split horizontally|`Prefix + Shift+"`|
|Switch panes|`Prefix + O`|
|Clear pane history|`Prefix + Alt+C`|

---

# 🎯 Professional Pentester Workflow

A clean workflow should look like:

```text
1. Read Scope
       ↓
2. Create Project Structure
       ↓
3. Start Tmux Logging
       ↓
4. Begin Enumeration
       ↓
5. Save Raw Output
       ↓
6. Update Notes
       ↓
7. Record Credentials
       ↓
8. Document Attack Path
       ↓
9. Capture Evidence
       ↓
10. Record Findings
       ↓
11. Track Payloads / Modifications
       ↓
12. Clean Up
       ↓
13. Organize Evidence
       ↓
14. Write Report
       ↓
15. Retest if Required
```

---

# 🏆 Final Takeaway

The central lesson is:

> **Good penetration testing is not only about obtaining access. It is also about being able to accurately explain, prove, reproduce, and defend everything you did.**

A professional tester should therefore build the habit of:

```text
ENUMERATE
   ↓
DOCUMENT
   ↓
SAVE OUTPUT
   ↓
CAPTURE EVIDENCE
   ↓
UPDATE ATTACK PATH
   ↓
ORGANIZE
   ↓
REPORT
```

The module emphasizes that the exact folder/note structure can differ from person to person and engagement to engagement. The important qualities are **thoroughness, organization, consistency, and reproducibility**.

### CPTS mindset

When you're doing an HTB machine, Pro Lab, CPTS preparation, or authorized penetration test, don't think:

> “I'll remember this later.”

Instead think:

> **“If I had to write the report tomorrow without touching the target again, do my notes contain everything I need?”**

That mindset is the real objective of this section.

The notes above preserve the source's important commands and structures while turning the material into a **study/revision format**. I also included visual references for the Obsidian/penetration-testing workflow.