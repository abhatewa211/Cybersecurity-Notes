This section covers why **Hyper-V Administrators** can be extremely powerful during Windows privilege escalation and Active Directory assessments.

The two major concepts are:

1. **Virtualized Domain Controller → offline access to `NTDS.dit`**
    
2. **Hyper-V Administrator → potential local SYSTEM escalation through the Hyper-V VHDX/hard-link behavior**
    

---

## 1. What is Hyper-V Administrators?

The **Hyper-V Administrators** group has full access to Hyper-V features.

The important security implication is:

```text
Hyper-V Administrator
        ↓
Control virtual machines
        ↓
Potential access to VM disks
        ↓
If a Domain Controller is virtualized
        ↓
Clone / access its virtual disk
        ↓
Offline access to NTDS.dit
        ↓
Domain credential material
```

The source specifically states that if Domain Controllers are virtualized, virtualization administrators should be treated as highly privileged because they could create a clone of a live DC and mount its virtual disk offline to obtain `NTDS.dit`.

> **CPTS idea:** You don't always need to compromise the Domain Controller directly. **Controlling the virtualization layer can provide an indirect path to the domain's credential database.**

---

# 2. Why `NTDS.dit` Matters

You already saw this in the **Backup Operators** section.

On a Domain Controller:

```text
C:\Windows\NTDS\ntds.dit
```

contains credential information for Active Directory accounts, including password hashes.

So:

```text
Hyper-V Administrator
        ↓
Virtual machine control
        ↓
DC virtual disk
        ↓
Offline disk access
        ↓
NTDS.dit
        ↓
Credential extraction
```

This is why virtualization administrators are considered extremely sensitive roles when DCs are virtualized.

---

# 3. Second Attack Path — VHDX + SYSTEM

The source describes another local privilege-escalation path involving:

```text
vmms.exe
```

This is the **Hyper-V Virtual Machine Management Service**.

The documented behavior was that when deleting a VM, `vmms.exe` attempted to restore permissions on the corresponding:

```text
.vhdx
```

file.

The important detail is that this operation occurred as:

```text
NT AUTHORITY\SYSTEM
```

without impersonating the Hyper-V administrator.

The source then describes abusing this behavior using a **native hard link** to redirect the operation toward a protected SYSTEM file.

---

# 4. Understand the Hard-Link Concept

A hard link allows another directory entry to reference the same underlying file.

Conceptually:

```text
Normal:

VM.vhdx
   ↓
Virtual disk


Abuse concept:

VM.vhdx
   ↓
Hard link
   ↓
Protected SYSTEM file
```

If a privileged process performs an operation against the attacker-controlled filename, the operation may actually affect the protected target.

The key vulnerability is therefore not simply:

> "Hyper-V admins can access SYSTEM files."

Instead, the attack depends on a vulnerable interaction between:

```text
Hyper-V management
+
file permissions
+
hard links
+
SYSTEM service behavior
```

---

# 5. Vulnerable Windows Versions

The source references:

- **CVE-2018-0952**
    
- **CVE-2019-0841**
    

These vulnerabilities can potentially be leveraged for SYSTEM privileges in the described scenario.

The source also says that if those vulnerabilities aren't available, another possible route is an application/service installed on the server where:

```text
Service runs as SYSTEM
        +
Unprivileged user can start service
```

That combination can provide another escalation opportunity.

---

# 6. Example — Mozilla Maintenance Service

The source uses Firefox's:

```text
Mozilla Maintenance Service
```

as an example.

The target executable is:

```text
C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```

The attack concept is:

```text
Hyper-V Administrator
        ↓
Hard-link vulnerability
        ↓
Gain permissions on target executable
        ↓
Take ownership
        ↓
Replace executable
        ↓
Start SYSTEM service
        ↓
Code executes as SYSTEM
```

---

# 7. Taking Ownership

The source uses:

```cmd
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```

`takeown` changes ownership of the specified file.

This connects directly to the **SeTakeOwnershipPrivilege** material you already studied.

Remember:

> **Ownership ≠ permissions.**

Taking ownership doesn't automatically mean you've granted yourself every permission. The attack scenario assumes the previous hard-link operation has already provided the necessary access.

---

# 8. Starting the Service

The source then starts the Mozilla Maintenance Service:

```cmd
sc.exe start MozillaMaintenance
```

The conceptual chain is:

```text
maintenanceservice.exe
        ↓
Service starts
        ↓
Service runs as SYSTEM
        ↓
Modified executable executes
        ↓
SYSTEM command execution
```

---

# ⚠️ Important: This Was Patched

This is one of the most important details in the section.

The source explicitly states:

> This vector was mitigated by the **March 2020 Windows security updates**, which changed behavior relating to hard links.

So don't memorize this as:

```text
Hyper-V Admin = always SYSTEM
```

Instead:

```text
Hyper-V Admin
      ↓
Check OS/build/patch level
      ↓
Is vulnerable?
   /       \
 YES       NO
 ↓          ↓
Investigate  This specific
hard-link    vector is mitigated
path
```

---

# 🧠 CPTS Mental Model

When you discover:

```text
Hyper-V Administrators
```

think about **two separate attack surfaces**.

### Path 1 — Virtualization / AD

```text
Hyper-V Admin
      ↓
VM control
      ↓
Domain Controller VM
      ↓
Virtual disk
      ↓
NTDS.dit
      ↓
Domain credential material
```

### Path 2 — Local privilege escalation

```text
Hyper-V Admin
      ↓
Hyper-V VHDX handling
      ↓
Hard-link behavior
      ↓
SYSTEM file/service
      ↓
Potential SYSTEM
```

Don't mix these two paths.

---

# 🔥 CPTS Must-Know

### Group

```text
Hyper-V Administrators
```

### Important service

```text
vmms.exe
```

### Important virtual disk

```text
.vhdx
```

### Domain Controller database

```text
C:\Windows\NTDS\ntds.dit
```

### Example target executable

```text
C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```

### Ownership command

```cmd
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```

### Service start

```cmd
sc.exe start MozillaMaintenance
```

### Referenced vulnerabilities

```text
CVE-2018-0952
CVE-2019-0841
```

### Patch awareness

```text
March 2020 Windows security updates
        ↓
Mitigated the described hard-link vector
```

---

# 🎯 What to Remember for Your CPTS

The **most important concept isn't the exploit commands**.

It's recognizing that **privilege boundaries exist outside the operating system itself**:

```text
             Windows
                │
       ┌────────┴────────┐
       │                 │
   Local Admin       Hyper-V Admin
                         │
                         ▼
                  Virtualization
                         │
             ┌───────────┴───────────┐
             ▼                       ▼
       VM disk access          VM management
             │                       │
             ▼                       ▼
         NTDS.dit              VHDX behavior
             │                       │
             ▼                       ▼
      AD credentials          Possible SYSTEM
```

### One-line memory trick

> **Hyper-V Administrators = control the virtualization layer; if a DC is virtualized, that can expose its virtual disk, and older vulnerable systems also had a Hyper-V hard-link path to SYSTEM.**