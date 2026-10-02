![Image](https://images.openai.com/static-rsc-4/9L3sFr4dvrQB5emTpngDkBttuYV-lJa-dZsPR3zC913wLchpnpTD-XW3Rcga1WLv_fEup-OYVMDHe-kyOLu8BHYy-PpDe6ADtVoTxyi3w7SbeOgC3ICqOi6WmHVtv9EJPBJ7cBU7tMVWKTsaDpnDYYryr0q5-uJ3VupreHzfHA-wa7UqpRgGq8WEBlKLbuwA?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/G53MmeDoW-QbMBFyewQTG-ym86LAPfepf0CNO7c1lo41x7Yc9t5vlVLQ7zTl-nuOqPvXxTozWNu2fsdG_MU7R5n5bB6RhD6HJd-O5v3TOTE5JG65dHjQneZ2gi2qHd2o1eE746XubHG9uFxz3CKmVDc7vsa_rRtp_DyaYjrcF3qsyXVgJMgkMN7P07f_Aoh9?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/1ezQTvnRAue4Wg8Q8PdyhSBt7nGMaHFQFevvzxGeAbNfBkHMe5NdcSk40dTlDMKzyY1049RIzSqHrCRphwVEY40YXcB9auPSA8qnUR1QcfY8581qeTqwRekkB-Cq-Ix7SPUPmRpnncvSIU3C6JYmSCv-1qbieQNwPpZG94KpV1ls5gj0H_5YrQNxCYFqb3v5?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/7NPH7aON4dOXUe1iOenZ0UAwK08KEC5PwaXsu0q-aZicokc-vALe11JK8HGre8fhWW4ktVCLUcPHJ1SQViyT72KpqX0D4xna9IrYoJ71OZBZj094Xobv3xO0FE1CHaZ-qVWQwksy14LyO7gXydXr_GFU7KK8MWJqgD93kw4-p6gpvqQdbVWt4GsqL3edDsta?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/h64QJRdXEgcGyL5pVwBV0w0PTfABU01B5l9XEUo8nfLpCDM16XWBvZxbBTp9edckdRPOdZ_aQ6P84IFPwcn4J9xxVDFTaVzMpjmV-QzFSqWoLXcq16U8WOkV2HS_lBKo5c1UhPpZb8IBpP8c2e3-CJEc01EUnBGJMAiYmXlZM2ZheaVyAKrHjYqOu-LyjMrF?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Xn5nB9mr3rRlpxIOkm3B6rsMpE0lg_nCvYn7RsL-UCl9VztLzWIYijVMuWcAKkZt_OFWkR79me_pDI49kpYIrMpuxbwD89-ao9in4llpwfDYNWCQCK7ZQNzf0SbedXv5sQaHqB_yHSzaVXy7UHxythUlcr1f06YjeJzHco5XwFYHkv8OdhQmpFhPMTzOtiHO?purpose=fullsize)

These notes are based directly on the material you provided. I’ve kept the **important concepts, terminology, stages, and key takeaways** intact while reorganizing them into a study-friendly format.

---

# 1. 🎯 Module Overview

The **Intro to Attacking Enterprise Networks** module is the culmination of the **Penetration Tester Job Role Path**.

The path consists of **27 modules** designed to simulate a penetration test against the fictional organization **Inlanefreight**.

The modules were structured around the most important stages of the penetration-testing process and the **Tactics, Techniques, and Procedures (TTPs)** required for an intermediate-level penetration tester.

### Main objective

The goal of this module is to bring **everything learned throughout the Penetration Tester path together** and apply it against a simulated corporate network.

Instead of focusing on one particular technique, you are expected to move between:

- Information gathering
    
- Web attacks
    
- Network attacks
    
- Active Directory attacks
    
- Privilege escalation
    
- Pillaging
    
- Lateral movement
    
- Pivoting
    
- Tunneling
    
- Port forwarding
    
- Post-exploitation
    
- Documentation and reporting
    

---

# 2. 🧭 Penetration Testing Lifecycle

Throughout the Penetration Tester path, the following stages were covered:

![Image](https://images.openai.com/static-rsc-4/L4E6texuNMuX49_uJddVbREzCWd_7MTd8X8NExUhaUNYLGbea1aPlVvm5vGKiw60ZfiYYP_pQc0-T7ZUhCjBCyGf_HboDNhJ8VE6h3F64ah-2nniMLA8gl79O2d3lSFmBgJBN_AOP8xS6vxXu0QipDDowiX037VVY9404wxVsmDbHPLaLTGZ-TQBGVSFaLIj?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/G53MmeDoW-QbMBFyewQTG-ym86LAPfepf0CNO7c1lo41x7Yc9t5vlVLQ7zTl-nuOqPvXxTozWNu2fsdG_MU7R5n5bB6RhD6HJd-O5v3TOTE5JG65dHjQneZ2gi2qHd2o1eE746XubHG9uFxz3CKmVDc7vsa_rRtp_DyaYjrcF3qsyXVgJMgkMN7P07f_Aoh9?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/3k8xxxfqU8quCHC1YY1btLffmlqSjOTHdQ0eGHkiyKegyjPyqQluCuHX4R6OuKgX2gDw-tABAy18fMW5QUcEyMwJ_IFJ5RiNmkflKjD3qaQHZmpTxIfkvS09NYilyuqocQ7VVb8qVpQU4zfld4GhJRxDN_tim6Op3ChWEE7QrASHb1FARAoQX_-SwlzMZjyw?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/WZR_M9_aJPV-UGSMuTCKwJDwHjUeecDgoAz1F6m5Ur_NKjaLnCWuJPCW7klWy0l-ymvswgf7Sn-6ED43hSCROQbsVTfbMFaVUtWbiockdksR1FI-3wQ8RGJMJD1mExN-qRluLdQ-HmUMsnPMoSmMfdSDUn_AvBrCFtj-Kd5w_sGv9vOvmgyCACjUFuhD7I26?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Y6_9O8170DhPGWKMqCoul2IX-HfdDEI1hCOjWv-SJ6u-CbB2aEQijLIfv8bTKED-Ygv0SSK4G1VQ9RITI2jPHZ_3tBC08-Pt4DAwnic2SRDRBM2PIsLwynOSzd87SdIsPUSk27DcH7CTuzy8yIwCdVVzDxo9pdp9r3YgxDl8iKw2Pxkq1qCb9FQgOiyYMBpU?purpose=fullsize)

### 1. Pre-Engagement

Planning and defining the penetration test before technical testing begins.

Important activities include:

- Defining scope
    
- Identifying targets
    
- Establishing rules of engagement
    
- Defining testing limitations
    
- Understanding authorization
    
- Establishing communication procedures
    

---

### 2. Information Gathering

Collecting information about the target environment.

Examples:

- Domains
    
- Subdomains
    
- IP addresses
    
- DNS information
    
- Hosts
    
- Open ports
    
- Services
    
- Technologies
    
- Employees/users
    
- Applications
    
- Network architecture
    

Typical tools may include:

```bash
nmap
dig
dnsenum
gobuster
curl
whatweb
```

The objective is to understand the **attack surface**.

---

### 3. Vulnerability Assessment

Once the attack surface has been identified, assess the discovered services and applications for weaknesses.

Examples:

- Outdated software
    
- Weak configurations
    
- Exposed services
    
- Weak authentication
    
- Web vulnerabilities
    
- Misconfigured Active Directory
    
- Excessive privileges
    

---

### 4. Exploitation

Attempt to exploit identified vulnerabilities within the agreed scope.

Possible objectives:

- Obtain initial access
    
- Execute commands
    
- Obtain a shell
    
- Access sensitive information
    
- Bypass authentication
    
- Gain a foothold
    

---

### 5. Post-Exploitation

After obtaining access, determine what can be achieved from the compromised system.

Activities can include:

- Enumeration
    
- Credential discovery
    
- Privilege escalation
    
- Configuration analysis
    
- Sensitive-file discovery
    
- Token/session discovery
    
- Network enumeration
    

---

### 6. Lateral Movement

Moving from one compromised system to another.

For example:

```text
Internet
   ↓
Web Server
   ↓
Internal Windows Host
   ↓
Domain Controller
```

Lateral movement can involve:

- Valid credentials
    
- SMB
    
- WinRM
    
- RDP
    
- WMI
    
- SSH
    
- PsExec
    
- Pass-the-Hash
    
- Other remote administration mechanisms
    

---

### 7. Proof of Concept

Demonstrating that a vulnerability or attack path is actually exploitable.

A good PoC should demonstrate:

- What was vulnerable
    
- How it was exploited
    
- What access was obtained
    
- What impact was demonstrated
    
- Evidence/screenshots
    
- Relevant commands
    
- Limitations
    

---

### 8. Post-Engagement

The final phase involves documenting the findings and communicating the results.

Typical deliverables:

- Executive summary
    
- Technical findings
    
- Evidence
    
- Attack paths
    
- Risk/impact
    
- Remediation recommendations
    
- Scope
    
- Methodology
    
- Limitations
    

---

# 3. 🏢 The Inlanefreight Scenario

The entire Penetration Tester Job Role Path uses the fictional organization:

## **Inlanefreight**

The learning environment breaks a large penetration test into smaller pieces.

The final module combines those pieces into a **simulated corporate penetration test**.

The engagement begins as an:

> **External Penetration Test**

After gaining internal access, it becomes:

> **Full-Scope Internal Penetration Test**

This means the tester must adapt their methodology once they gain access to the internal network.

---

# 4. 🔥 Why This Module Is Different

Previous modules generally focused on specific areas.

For example:

```text
Web Attacks
     ↓
Active Directory
     ↓
Shells & Payloads
     ↓
Pivoting
     ↓
Privilege Escalation
```

The final enterprise-network scenario requires combining them.

A real engagement may look more like:

```text
Reconnaissance
      ↓
External Enumeration
      ↓
Web Application Testing
      ↓
Initial Foothold
      ↓
Host Enumeration
      ↓
Credential Discovery
      ↓
Privilege Escalation
      ↓
Internal Network Enumeration
      ↓
Pivoting
      ↓
Active Directory Enumeration
      ↓
Credential Attacks
      ↓
Lateral Movement
      ↓
Privilege Escalation
      ↓
Domain-Level Access
      ↓
Pillaging
      ↓
Documentation
```

**Important:** The process is not necessarily linear.

You may have to go backward and forward between different stages.

---

# 5. 🧠 The Pentester Mindset

One of the most important lessons in this module is the ability to **adapt**.

A penetration tester cannot rely on one fixed methodology.

You might start with:

```text
Information Gathering
```

and discover something that requires:

```text
Web Attack
```

That could provide:

```text
Initial Access
```

which leads to:

```text
Network Enumeration
```

which could reveal:

```text
Active Directory
```

which then leads to:

```text
Credential Attacks
```

and eventually:

```text
Lateral Movement
```

### Core mindset

> **Constantly cycle through your knowledge and adapt to what the target environment reveals.**

Every network is different.

However, the **core penetration-testing process remains similar**.

---

# 6. 🗺️ External vs Internal Penetration Testing

![Image](https://images.openai.com/static-rsc-4/7NPH7aON4dOXUe1iOenZ0UAwK08KEC5PwaXsu0q-aZicokc-vALe11JK8HGre8fhWW4ktVCLUcPHJ1SQViyT72KpqX0D4xna9IrYoJ71OZBZj094Xobv3xO0FE1CHaZ-qVWQwksy14LyO7gXydXr_GFU7KK8MWJqgD93kw4-p6gpvqQdbVWt4GsqL3edDsta?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/9L3sFr4dvrQB5emTpngDkBttuYV-lJa-dZsPR3zC913wLchpnpTD-XW3Rcga1WLv_fEup-OYVMDHe-kyOLu8BHYy-PpDe6ADtVoTxyi3w7SbeOgC3ICqOi6WmHVtv9EJPBJ7cBU7tMVWKTsaDpnDYYryr0q5-uJ3VupreHzfHA-wa7UqpRgGq8WEBlKLbuwA?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/WuCFmLs3CSfyMhOlu9o5Tm22ovjzdcOQ-3tw0T0B_2_xc9p2idZfertRcpYscrGnCgw8h3Mcl59kDti4lMIya0E1fSLcRrrKeeFDaMZtBIwlfcydYEFWPIgXRJ9zxDTLWNik1A4zYwy_Kevr9T0_3ulYaQ5sOTCVYgFkB47D-yxLvcZ0nuybfq4egr6g8Oiz?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/PToFD9KiiXgJkFw9MOlPQAaIDM2b9nWk4vJkkfYoZjBkNaCcrjip4e8sBwCyptd_kUfclF5JSV4uTKzTHlRLFx1YIUC7-irKdy2CatF6-ua6Bh2wwM4L3VIr_GbTSsebzhd_qFn8-5Li96vw-ZI_V3FX1NvMigcWa7MhHxOYrB9dP3K8SDhNeDIbOP2y7Dqx?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/1ezQTvnRAue4Wg8Q8PdyhSBt7nGMaHFQFevvzxGeAbNfBkHMe5NdcSk40dTlDMKzyY1049RIzSqHrCRphwVEY40YXcB9auPSA8qnUR1QcfY8581qeTqwRekkB-Cq-Ix7SPUPmRpnncvSIU3C6JYmSCv-1qbieQNwPpZG94KpV1ls5gj0H_5YrQNxCYFqb3v5?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/aWagvTodHrbH5_JXOSQZsoycdBa_TDMAo-LgnSUC2tp5PigOpuYmhglkUx5qpqdnqcuyORNq4Klxh7u1EyzQbbTD2vSNyzFD1vZkmvQta1SJoRH7aIJaDQ4AEYM6vkm_ULcdwH4Rd0wvolqDXfCDl5N8RCftDKzkwjBA4aM7Meql-Z3Y4aBuiFuIjFpym8BG?purpose=fullsize)

## External Penetration Test

The tester starts from outside the organization.

Typical targets:

- Public IP addresses
    
- Public websites
    
- VPN
    
- External applications
    
- Mail servers
    
- DNS
    
- Internet-facing services
    

Example:

```text
                 INTERNET
                    │
          ┌─────────┴─────────┐
          │                   │
       Web Server          VPN Server
          │
          ↓
     Initial Access
```

---

## Internal Penetration Test

After obtaining internal access, the tester examines the internal environment.

Typical targets:

- Windows systems
    
- Linux systems
    
- File servers
    
- Databases
    
- Active Directory
    
- Domain Controllers
    
- Internal web applications
    
- Network shares
    
- Administrative services
    

Example:

```text
             INTERNAL NETWORK
                    │
       ┌────────────┼────────────┐
       ↓            ↓            ↓
   Windows       Linux       File Server
       │
       ↓
      AD
       │
       ↓
 Domain Controller
```

---

# 7. 🧩 Seven Mini Simulated Penetration Tests

By reaching this stage of the Penetration Tester path, the learner has already completed **seven mini simulated penetration tests**.

### 1. Large Pentest

The individual modules collectively represent the elements of a large penetration test.

---

### 2. Active Directory Pentest

A cross-section of an Active Directory penetration test was covered step-by-step in:

**Active Directory Enumeration & Attacks**

---

### 3 & 4. AD Skills Assessments

Two mini/simulated Active Directory penetration tests were completed through the skills assessments.

---

### 5. Shells & Payloads Assessment

One mini/simulated penetration test was completed through the **Shells & Payloads** skills assessment.

---

### 6. Pivoting Assessment

One mini/simulated penetration test focused on:

- Pivoting
    
- Tunneling
    
- Port forwarding
    

---

### 7. Documentation & Reporting

One mini/simulated **internal penetration test** was completed through the Documentation & Reporting module.

It involved:

- Exploratory learning
    
- Guided learning
    
- Internal network testing
    
- Documentation
    

---

# 8. 🌐 More Than 200 Targets

Across the different modules, learners have attacked **over 200 targets**.

These included:

- Windows targets
    
- Linux targets
    
- Web targets
    
- Active Directory targets
    

This is important because enterprise environments rarely consist of only one operating system or technology.

A real corporate network can contain:

```text
Windows
Linux
Web Applications
Databases
Active Directory
Network Services
Cloud Services
VPN
File Servers
```

A pentester must be comfortable switching between them.

---

# 9. 🔄 The Enterprise Pentest Requires Everything

This final lab combines practically **ALL** of the knowledge gained throughout the path.

You may need to move between:

### Information Gathering

↓

### Web Attacks

↓

### Network Attacks

↓

### Active Directory Attacks

↓

### Privilege Escalation

↓

### Pillaging

↓

### Lateral Movement

↓

### Pivoting

↓

### Further Enumeration

↓

### Additional Exploitation

This means you cannot approach the environment thinking:

> "I am doing only a web pentest."

or:

> "I am doing only an Active Directory pentest."

Instead:

> **You are testing the entire attack surface.**

---

# 10. 🔍 Dead Ends Are Part of Pentesting

An important aspect of the module is that it intentionally includes **dead ends**.

A penetration tester may spend time investigating something that ultimately doesn't lead anywhere.

Example:

```text
Recon
  ↓
Interesting Service
  ↓
Enumeration
  ↓
Potential Vulnerability
  ↓
Testing
  ↓
No Exploitation
  ↓
DEAD END
  ↓
Return to Enumeration
```

This is completely normal.

### Important lesson

A dead end does **not** mean the assessment failed.

It means you have eliminated one potential attack path.

Good documentation should record useful dead ends when they affect the assessment process.

---

# 11. 🧠 Constantly Cycling Through Your "Rolodex"

The material uses the concept of a pentester's **Rolodex of skills**.

Think of this as your mental toolbox.

For example:

|Situation|Skills to Consider|
|---|---|
|Open ports|Service enumeration|
|Web application|Web enumeration/attacks|
|Credentials found|Credential validation|
|Windows host|Windows enumeration|
|Linux host|Linux enumeration|
|Domain environment|AD enumeration|
|Internal network inaccessible|Pivoting|
|Low privilege shell|Privilege escalation|
|Multiple internal hosts|Lateral movement|
|Sensitive data discovered|Pillaging|
|Vulnerability confirmed|PoC + documentation|

The key skill is knowing **which tool/technique to pull out at the right moment**.

---

# 12. 🔐 Active Directory in Enterprise Testing

Active Directory can become a major part of an internal penetration test.

A simplified enterprise AD attack path could look like:

```text
External Access
      ↓
Internal Foothold
      ↓
Network Enumeration
      ↓
Domain Discovery
      ↓
User Enumeration
      ↓
Computer Enumeration
      ↓
Group Enumeration
      ↓
ACL / Relationship Analysis
      ↓
Credential Discovery
      ↓
Privilege Escalation
      ↓
Lateral Movement
      ↓
Domain-Level Impact
```

Important AD concepts from the previous modules include:

- Users
    
- Groups
    
- Computers
    
- Domains
    
- Domain Controllers
    
- LDAP
    
- Kerberos
    
- SMB
    
- NTLM
    
- ACLs
    
- SPNs
    
- Trust relationships
    
- Group memberships
    
- BloodHound relationships
    

---

# 13. 🚪 Initial Access Is Only the Beginning

Obtaining a shell or foothold is **not the end of the penetration test**.

For example:

```text
Initial Access
      ↓
"Great, I have a shell."
      ↓
Now What?
```

You should ask:

### Host questions

- Who am I?
    
- What privileges do I have?
    
- What operating system is this?
    
- What services are running?
    
- What network interfaces exist?
    
- What routes exist?
    
- What files are interesting?
    
- Are credentials stored locally?
    
- Are there other users?
    
- Can I escalate privileges?
    

### Network questions

- What other hosts can this machine communicate with?
    
- Is there an internal network?
    
- Is Active Directory present?
    
- Are there internal services unavailable externally?
    
- Can this host be used as a pivot?
    

---

# 14. 🔀 Pivoting

![Image](https://images.openai.com/static-rsc-4/b9HADZQE9DNn-8oa4TfQj9sKRnvCbYwbrT8srtRqHGQosm6fcWdyR6cgWbaaD2jRfvU3LqPPQrMAZnP1wOy1-xvLePcGNUeMfs37DQvm_nexyPSACyqCzKgqVJTbHKPxoMrBOgU6HDHryZZgC9rQpmvy4PtT9J0GIYRjHKNn0zNDwyuu_VGR5QkScxI2wbND?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/js8IpsGRxW4xksWVXTpOYoohe4o_PoWbhLaQMtIU9JnpOoIBpZY5aVo1dUM7UEFTC5iawcYJSUSVdHKCWKcTPve3XBT7UlCYSw9f3nnz4dIcidLt_FKOgbCcaleOV5dmsHL5Rg3-x5lcyi6MXOOvGe4IWpHWisplX7QlhkfESu2qItcEQFUtL2tsD-0H2wVI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/a1YB9bgdpnnId9cjdzZa_xLJpKaxjMgymyknHjKnsGuGrQVrWdey1pa9ESh4K7KsaDpdvThSrnH86pPPphF35sCgbFBssnJ1IYYOcZ5ISHETvRKw-KwCfoJPOvMhQdRZIPD8Qp1Gjao9N4Qq0SMh8GM_TpDZ6gPpiuu3F0rIpMgVEr2Izwg4P9nZFqScq9cS?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/rYEBbE__njg33VqIBbNCyKbfBffA95VXbxr0jbVnNjuGrKpssrKkEyFgjreyp8e6GNW8RhesS3F75VrBm-CbAT_Fl0yDAnFnYOvvXiMjECgVEl4vr7vF9GQ_lGHmlLeXxdkA-H-HbAZ0peW4xpSZoif4FYMrmYQn7dsMkzFEFoa7F7RsIJfr-qFp2GzBsvnU?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ogm26DQ77z4ZJSK-Yi2Vz7xTuFELj3S9ISYX-_VaTP4fICOtNwZh-H4PRZeIM9q5ASFNf1RxCR-Q0CEO8g7YQlmUJGzAOtHYQEGKP4JWTEZaI6NkssdQxICUB8zN34GAM8DAODwrtVuA-7ZhQwRp4EzoqCIqycgoA5B7O1uEaHXVaVleVDAzGC_a5VC0qcjX?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/OpBXf404GdPiqDnsEYEYFGOCrJmP_ai_eyVQpjlkskp_ZpiuCwPo-PnVP0JZxe1K7gWvZ1IzUN3wok5OsOdSg5WwAmpXY4Ph0mZs6GFoG2DKQcwg1hnMxDZyHzH3g6zLwpNFbZCBIeeFaBmWVDq2J4jBHAAJtKvcpMk-EbolazlzZY1z_nNRoSfOoMO_A0y7?purpose=fullsize)

If your compromised machine can access an internal network that your attacking machine cannot directly reach, you may need to **pivot** through the compromised host.

Example:

```text
ATTACKER
   │
   │ Internet
   ↓
COMPROMISED HOST
   │
   │ Internal Network
   ↓
INTERNAL HOST
   │
   ↓
DOMAIN CONTROLLER
```

This is where skills involving:

- Tunneling
    
- Port forwarding
    
- SOCKS proxies
    
- Routing
    

become important.

---

# 15. 🧰 Important Skill Categories

By this stage, you should be comfortable with multiple categories of penetration-testing skills.

### Reconnaissance

```text
Nmap
DNS enumeration
Subdomain enumeration
Web enumeration
Service enumeration
```

### Web Testing

```text
HTTP methods
Authentication
Authorization
IDOR
XSS
SQL Injection
XXE
File attacks
Web shells
```

### Network Testing

```text
Port scanning
Service enumeration
Credential attacks
Network protocol analysis
```

### Windows

```text
PowerShell
Windows enumeration
Services
Registry
UAC
WMI
NTFS permissions
SMB
WinRM
```

### Linux

```text
Linux enumeration
SUID
Cron
Services
Permissions
SSH
Credential discovery
```

### Active Directory

```text
LDAP
Kerberos
SMB
BloodHound
Domain enumeration
ACL analysis
Credential attacks
Lateral movement
```

### Post-Exploitation

```text
Privilege escalation
Credential harvesting
Pillaging
Lateral movement
Persistence analysis
Network discovery
```

### Network Access

```text
Pivoting
Tunneling
Port forwarding
Proxying
```

### Reporting

```text
Evidence
Screenshots
Commands
Attack paths
Impact
Remediation
Executive summary
Technical findings
```

---

# 16. 📝 Documentation Is a Core Skill

The module strongly emphasizes **documentation and reporting**.

Technical ability alone is not enough for professional penetration testing.

You need to be able to clearly explain:

> What happened?

> How did it happen?

> Why was it possible?

> What was the impact?

> How can the organization fix it?

---

## Good Evidence

Record things such as:

```text
Target IP
Hostname
Port
Service
Vulnerability
Command used
Output
Credentials discovered
Access level
Screenshot
Timestamp
Attack path
Impact
Remediation
```

Example:

```text
Target: 10.10.10.10
Port: 445
Service: SMB
Finding: Weak SMB configuration
Evidence: Nmap + SMB enumeration
Impact: Potential unauthorized access
Recommendation: Harden SMB configuration
```

---

# 17. 📑 Commercial-Grade Reporting

The module recommends completing the lab a **second time without the walkthrough**.

During the second attempt, act as the actual penetration tester.

You should:

1. Take detailed notes.
    
2. Document every important action.
    
3. Record commands.
    
4. Save screenshots.
    
5. Record discovered credentials appropriately.
    
6. Record attack paths.
    
7. Track hosts.
    
8. Document dead ends.
    
9. Record vulnerabilities.
    
10. Document exploitation steps.
    
11. Explain impact.
    
12. Provide remediation.
    
13. Create your own walkthrough.
    
14. Practice creating a **commercial-grade penetration-testing report**.
    

---

# 18. 🧪 Recommended Second-Pass Methodology

The first run:

> **Learn from the walkthrough.**

The second run:

> **Be the penetration tester.**

### Phase 1 — Recon

```text
Identify targets
      ↓
Identify services
      ↓
Identify technologies
      ↓
Map attack surface
```

### Phase 2 — Enumeration

```text
Enumerate services
      ↓
Identify versions
      ↓
Identify vulnerabilities
      ↓
Identify credentials/attack opportunities
```

### Phase 3 — Exploitation

```text
Exploit vulnerability
      ↓
Obtain initial access
      ↓
Capture evidence
```

### Phase 4 — Post-Exploitation

```text
Enumerate host
      ↓
Find credentials
      ↓
Privilege escalation
      ↓
Network discovery
```

### Phase 5 — Lateral Movement

```text
Identify additional targets
      ↓
Validate credentials
      ↓
Move between hosts
      ↓
Enumerate new systems
```

### Phase 6 — Active Directory

```text
Domain enumeration
      ↓
Users/groups/computers
      ↓
Relationships
      ↓
Attack paths
      ↓
Privilege escalation
```

### Phase 7 — Documentation

```text
Evidence
↓
Findings
↓
Impact
↓
Attack narrative
↓
Remediation
↓
Final report
```

---

# 19. 🧠 Key Lessons From the Module

### ⭐ Lesson 1 — Know the Fundamentals

You should have a strong understanding of:

- Networking
    
- Windows
    
- Linux
    
- Web applications
    
- Active Directory
    
- Authentication
    
- Enumeration
    
- Exploitation
    

---

### ⭐ Lesson 2 — Don't Depend on One Tool

Tools automate portions of the process.

A strong pentester understands **what the tool is doing**.

For example:

```text
Automated Scanner
       ↓
Potential Finding
       ↓
Manual Validation
       ↓
Confirmed Vulnerability
       ↓
Exploitation/PoC
       ↓
Evidence
```

---

### ⭐ Lesson 3 — Enumeration Is Continuous

Enumeration does not stop after obtaining a shell.

You may enumerate:

```text
External system
      ↓
Compromised host
      ↓
Internal network
      ↓
Other hosts
      ↓
Domain
      ↓
Users
      ↓
Groups
      ↓
Permissions
```

Every new piece of information can change your attack path.

---

### ⭐ Lesson 4 — Adaptability Matters

A real penetration test will not necessarily follow your preferred methodology.

You need to adapt to:

- New technologies
    
- Unexpected services
    
- Different operating systems
    
- Misconfigurations
    
- New credentials
    
- Network segmentation
    
- Dead ends
    
- Unexpected attack paths
    

---

### ⭐ Lesson 5 — Documentation Is Part of the Technical Work

Don't treat documentation as something you do only at the end.

Document **during the engagement**.

Otherwise, you may forget:

- Commands
    
- IP addresses
    
- Credentials
    
- Attack paths
    
- Evidence
    
- Important findings
    
- How you achieved access
    

---

# 20. 🎯 Final Mental Model

Remember the entire enterprise penetration test as:

```text
                    ┌──────────────┐
                    │ PRE-ENGAGE   │
                    └──────┬───────┘
                           ↓
                  ┌─────────────────┐
                  │ RECON / OSINT   │
                  └────────┬────────┘
                           ↓
                  ┌─────────────────┐
                  │ ENUMERATION     │
                  └────────┬────────┘
                           ↓
              ┌────────────┴────────────┐
              ↓                         ↓
        WEB ATTACKS                NETWORK ATTACKS
              │                         │
              └────────────┬────────────┘
                           ↓
                   INITIAL ACCESS
                           ↓
                  POST-EXPLOITATION
                           ↓
                 PRIVILEGE ESCALATION
                           ↓
                    PIVOTING
                           ↓
                 INTERNAL ENUMERATION
                           ↓
                 ACTIVE DIRECTORY
                           ↓
                 LATERAL MOVEMENT
                           ↓
                    PILLAGING
                           ↓
                 FURTHER ACCESS
                           ↓
                    PROOF OF
                    CONCEPT
                           ↓
                  DOCUMENTATION
                           ↓
                    FINAL REPORT
```

---

# 🔥 What You Should Remember for CPTS

Since this module is effectively bringing the entire penetration-testing path together, focus especially on these concepts:

|Priority|Topic|
|---|---|
|🔴 Critical|Enumeration|
|🔴 Critical|Active Directory|
|🔴 Critical|Privilege Escalation|
|🔴 Critical|Lateral Movement|
|🔴 Critical|Pivoting|
|🔴 Critical|Web Attacks|
|🟠 High|Credential Attacks|
|🟠 High|Post-Exploitation|
|🟠 High|Network Enumeration|
|🟠 High|Windows/Linux Enumeration|
|🟡 Important|Proof of Concept|
|🟡 Important|Documentation|
|🟡 Important|Reporting|

### The biggest takeaway:

> **A successful penetration tester must be able to constantly cycle through their knowledge, adapt on the fly, and move between information gathering, exploitation, post-exploitation, Active Directory attacks, privilege escalation, pillaging, lateral movement, and pivoting.**

And remember the fundamental process:

**Recon → Enumerate → Identify → Exploit → Escalate → Pivot → Move → Document → Report.**

This module is where you stop thinking about individual tools and start thinking like an **end-to-end penetration tester**.