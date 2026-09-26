This section is essentially the **defensive counterpart to Windows privilege escalation**: the same weaknesses we learned to enumerate and exploit can often be eliminated through proper hardening. The source explicitly states that proper hardening can remove most, if not all, opportunities for local privilege escalation.

---

## 1. Secure Clean OS Installation

### Core idea

Start every Windows host from a **known-good, standardized baseline** rather than a machine full of unnecessary software and inconsistent settings.

A custom enterprise image should be built from a clean Windows ISO and can be deployed using technologies such as:

- Windows Deployment Server (WDS)
    
- System Center Configuration Manager (SCCM)
    
- Equivalent deployment systems
    

The image should contain at minimum:

1. Required applications for employees.
    
2. Security/functionality configuration changes.
    
3. Tested current major and minor updates.
    

### Why this matters for pentesting

A standardized image reduces:

- Unnecessary software
    
- Bloatware
    
- Inconsistent configurations
    
- Unknown services
    
- Extra attack surface
    

It also gives administrators a consistent baseline for troubleshooting and patching.

### CPTS mental model

```text
Clean OS
   ↓
Required Software Only
   ↓
Secure Configuration
   ↓
Tested Updates
   ↓
Standard Enterprise Image
   ↓
Reduced Attack Surface
```

---

# 2. Updates and Patching

Windows Update's **Update Orchestrator** manages the update process in the background.

In an enterprise, **WSUS** can be used so that systems obtain approved updates from an internal update server rather than independently reaching Microsoft.

### Update lifecycle

```text
1. Scan
   ↓
2. Determine Applicable Updates
   ↓
3. Download
   ↓
4. Install
   ↓
5. Reboot / Finalize
```

The source describes the process as:

1. Windows Update Orchestrator checks Microsoft Update or WSUS.
    
2. It determines which updates apply to the host.
    
3. Required updates are downloaded.
    
4. The installer applies them.
    
5. A reboot finalizes changes to services and critical settings.
    

### Important enterprise point

**Do not blindly push patches everywhere.**

Recommended workflow:

```text
Patch released
     ↓
Test on development systems
     ↓
Validate applications
     ↓
Deploy to small group
     ↓
Enterprise-wide deployment
```

The source specifically recommends testing updates before enterprise-wide deployment because an update can break a critical application or function.

### Pentester perspective

When performing Windows enumeration, patch level is extremely important because missing patches can expose:

- Kernel vulnerabilities
    
- Local privilege escalation
    
- Service vulnerabilities
    
- Remote code execution vulnerabilities
    

That's why commands such as:

```cmd
systeminfo
wmic qfe list brief
```

are useful during Windows enumeration.

---

# 3. Configuration Management

Windows configuration can be centrally managed through **Group Policy**.

Group Policy allows administrators to centrally manage:

- User settings
    
- Computer settings
    
- Security settings
    
- Windows Defender
    
- Firewall configuration
    
- Browser settings
    
- Update behavior
    

It can be managed through:

- **Group Policy Management Console (GPMC)**
    
- PowerShell
    

### CPTS connection

From an attacker's perspective:

> **Group Policy = huge source of security controls and potential misconfigurations.**

For example, poorly configured policies can potentially lead to:

```text
Weak Password Policy
        ↓
Credential Attacks

Excessive User Rights
        ↓
Privilege Escalation

Weak Software Restrictions
        ↓
Execution

Poor Firewall Configuration
        ↓
Network Access
```

---

# 4. User Management

One of the most important hardening principles is **least privilege**.

Administrators should:

- Minimize unnecessary user accounts.
    
- Minimize unnecessary administrator accounts.
    
- Log and monitor login attempts.
    
- Enforce strong password policies.
    
- Use 2FA.
    
- Rotate passwords periodically.
    
- Prevent password reuse.
    
- Prevent ordinary users from receiving excessive privileges.
    
- Restrict administrator login locations/actions.
    

The source specifically highlights the danger of placing ordinary users into overly privileged groups such as **Domain Admins**.

### Password Policy location

The source gives this Group Policy path:

```text
Computer Configuration
 └── Windows Settings
     └── Security Settings
         └── Account Policies
             └── Password Policy
```

### 2FA

2FA combines:

```text
Something you know
        +
Something you have
```

Example:

```text
Password/PIN
      +
Authenticator code/token
```

This significantly reduces the ability to abuse a stolen password by itself.

---

# 5. Audit

Hardening isn't a **set-and-forget** activity.

Organizations should periodically perform:

- Security reviews
    
- Configuration reviews
    
- Vulnerability scans
    
- Compliance checks
    
- Penetration tests
    

Useful security baseline/reference frameworks mentioned by the source include:

- **DISA STIGs**
    
- **Microsoft Security Compliance Toolkit**
    
- ISO 27001
    
- PCI-DSS
    
- HIPAA
    

However, the source emphasizes that these should be treated as **reference guides**, not blindly used as the entire security program. Controls should be tailored to the organization's environment and data.

### Important distinction

```text
Configuration Audit
        ≠
Penetration Test
```

An audit checks whether specified controls/configurations are present.

A penetration test performs hands-on technical testing to determine whether security weaknesses can actually be exploited.

The source describes configuration reviews as potentially becoming a **"box-checking" exercise** when organizations only satisfy minimum controls.

### CPTS takeaway

A mature security program should combine:

```text
Configuration Auditing
        +
Vulnerability Scanning
        +
Penetration Testing
        +
Patch Management
        +
Monitoring
```

---

# 6. Logging

Logging is critical for:

- Troubleshooting
    
- Detection
    
- Threat hunting
    
- Incident response
    
- Correlation of suspicious activity
    

The source emphasizes that proper logging and **log correlation** can significantly improve visibility into what is happening on Windows hosts.

---

# 7. Sysmon

**Sysmon (System Monitor)** is a Microsoft Sysinternals tool that enhances Windows event logging.

It can provide information about:

- Process creation
    
- Network connections
    
- File reads/writes
    
- Login attempts
    
- Successful logins
    
- Other system activity
    

These logs can then be sent to a **SIEM** for correlation and analysis.

### Sysmon log location

```text
Applications and Service Logs
└── Microsoft
    └── Windows
        └── Sysmon
            └── Operational
```

### CPTS attacker's perspective

Remember the activities we've performed throughout this module:

```text
whoami
net user
net localgroup
tasklist
PowerShell execution
Service manipulation
Credential dumping
Process creation
Network connections
```

Many of these activities can leave telemetry.

So:

> **Enumeration is useful to the attacker, but enumeration itself can generate detection opportunities.**

This is why understanding logging is important for both **red team and blue team** work.

---

# 8. Network and Host Logs

Host logs alone aren't enough.

Network monitoring solutions can provide additional visibility.

The source mentions:

- PacketBeat
    
- Security Onion
    
- IDS/IPS
    
- Network monitoring systems
    
- SIEMs
    

These systems can collect and forward network traffic information for analysis.

### Mental model

```text
                 ┌── Windows Logs
                 │
Host Activity ───┼── Sysmon
                 │
                 └── Security Events

                 +
                 
Network Traffic ── IDS/IPS
                 ── PacketBeat
                 ── Security Onion

                 ↓

                SIEM
                 ↓
          Correlation / Detection
```

---

# 9. Key Hardening Measures

This is the **most important checklist** from the section.

### 1. Secure Boot + BitLocker

Use:

- Secure Boot
    
- Disk encryption with BitLocker
    

---

### 2. Audit Writable Files and Directories

Check for:

- Writable executables
    
- Writable directories
    
- Writable scripts
    
- Binaries capable of launching other applications
    

Why?

Because throughout Windows privilege escalation we repeatedly saw:

```text
Low-privileged user
       ↓
Writable file/service/script
       ↓
Privileged process executes it
       ↓
SYSTEM
```

The source explicitly recommends auditing writable files/directories and binaries capable of launching applications.

---

### 3. Secure Scheduled Tasks

Scheduled tasks running with elevated privileges should use **absolute executable paths**.

Bad conceptual example:

```text
backup.exe
```

Better:

```text
C:\Program Files\Company\backup.exe
```

Why?

Because ambiguous executable resolution can potentially create **path hijacking opportunities**.

This connects directly to the scheduled-task and path-based privilege escalation techniques studied earlier.

---

### 4. Never Store Cleartext Credentials

Avoid storing passwords in:

- World-readable files
    
- Shared drives
    
- Configuration files
    
- Scripts
    
- User-accessible locations
    

This directly connects with the **Credential Hunting/Pillaging** sections.

---

### 5. Clean User Home Directories and PowerShell History

Sensitive information can remain inside:

```text
User home directories
PowerShell history
Configuration files
Temporary files
```

The source explicitly recommends cleaning home directories and PowerShell history.

---

### 6. Protect Custom Libraries

Low-privileged users must not be able to modify custom libraries loaded by privileged applications.

Otherwise:

```text
Privileged Application
        ↓
Loads DLL
        ↓
User can modify DLL
        ↓
Malicious DLL
        ↓
Privileged execution
```

This connects directly to **DLL hijacking/injection**.

---

### 7. Remove Unnecessary Services and Packages

Every unnecessary service/application can potentially increase:

> **Attack Surface**

Therefore:

```text
Less software
     ↓
Fewer services
     ↓
Fewer exposed components
     ↓
Smaller attack surface
```

---

### 8. Device Guard + Credential Guard

The source recommends using Microsoft's:

- Device Guard
    
- Credential Guard
    

on Windows 10 and most newer Server Operating Systems.

---

### 9. Group Policy

Use Group Policy to centrally enforce required security configurations across company systems.

---

# 🔥 CPTS Master Mental Model

Think of Windows hardening as closing the exact paths we repeatedly exploited:

|Privilege Escalation Weakness|Hardening Response|
|---|---|
|Missing patches|Regular patching|
|Weak service permissions|Audit service ACLs|
|Writable service binary|Remove write access|
|Unquoted service paths|Use proper absolute paths|
|Writable scheduled-task scripts|Restrict permissions|
|DLL hijacking|Protect DLL locations|
|Cleartext credentials|Secure credential storage|
|Excessive group membership|Least privilege|
|Weak passwords|Strong password policy|
|Credential theft|Credential Guard / MFA|
|Excessive services|Remove unnecessary services|
|Poor visibility|Sysmon + SIEM|
|Weak centralized configuration|Group Policy|
|Disk/offline credential access|BitLocker|
|Legacy insecure configuration|Security baselines + auditing|

This is the key connection between the offensive and defensive portions of the module.

---

# 🧠 CPTS Exam/Viva Questions

### Q1. What is Windows hardening?

Reducing the attack surface and eliminating unnecessary opportunities for privilege escalation or compromise through secure configuration, patching, access control, monitoring, and other controls.

### Q2. Why use a custom Windows image?

To provide a standardized, tested baseline containing required applications, security configurations, and approved updates while removing unnecessary software.

### Q3. What is WSUS?

**Windows Server Update Services** — an enterprise mechanism for centrally managing Windows updates instead of having every system independently retrieve them.

### Q4. Why test patches before deployment?

Because an update can potentially break an application's functionality or another critical system component.

### Q5. What is Group Policy used for?

Centrally managing Windows user and computer configurations, especially in an Active Directory environment.

### Q6. What principle should guide user permissions?

**Least privilege** — users should receive only the permissions required for their tasks.

### Q7. What does Sysmon provide?

Enhanced Windows telemetry including process activity, network connections, file activity, and authentication-related information.

### Q8. Where are Sysmon operational logs?

```text
Applications and Service Logs
└── Microsoft
    └── Windows
        └── Sysmon
            └── Operational
```

### Q9. Why are writable directories dangerous?

A low-privileged user may be able to modify files that a privileged process later executes, potentially resulting in privilege escalation.

### Q10. Why should privileged scheduled tasks use absolute paths?

To prevent ambiguous executable resolution and reduce path-based hijacking opportunities.

---

# ⚔️ Offensive ↔ Defensive Connection

This is probably the **most important CPTS takeaway from the entire section**:

```text
OFFENSIVE
Enumeration
    ↓
Find Weakness
    ↓
Exploit Weakness
    ↓
Privilege Escalation
    ↓
SYSTEM


DEFENSIVE
Audit
    ↓
Find Weakness
    ↓
Fix Configuration
    ↓
Restrict Permissions
    ↓
Monitor Activity
    ↓
Prevent SYSTEM
```

The conclusion reinforces that Windows privilege escalation can originate from simple misconfigurations, vulnerable services, public exploits, or custom libraries/executables, and that once SYSTEM/admin access is obtained it can become a pivot point for further network exploitation.

## 🔑 One-line memory trick

**Hardening = Patch + Least Privilege + Secure Config + Remove Attack Surface + Protect Credentials + Monitor + Audit.**

And don't forget the source's final point: security controls should be adapted to the organization's actual mission and environment rather than blindly applying every hardening measure everywhere.