## 1. Module Overview

### What are “Bleeding Edge” vulnerabilities?

Bleeding-edge vulnerabilities are **very recent vulnerabilities or attack techniques** that may be effective because organizations have not yet patched or mitigated them.

The module focuses on three relatively recent Active Directory attacks:

1. **NoPac / SamAccountName Spoofing**
    
    - CVE-2021-42278
        
    - CVE-2021-42287
        
2. **PrintNightmare**
    
    - CVE-2021-34527
        
    - CVE-2021-1675
        
3. **PetitPotam**
    
    - CVE-2021-36942
        

The module emphasizes that these are advanced techniques and should first be practiced in a controlled lab. Even attacks considered relatively safe can cause service disruption.

---

# 🧠 Big Picture

```text
              Bleeding Edge AD Attacks
                       │
        ┌──────────────┼──────────────┐
        │              │              │
        ▼              ▼              ▼
      NoPac       PrintNightmare   PetitPotam
        │              │              │
        ▼              ▼              ▼
 SamAccountName     Print Spooler   MS-EFSRPC
    Spoofing        vulnerability    coercion
        │              │              │
        ▼              ▼              ▼
   Kerberos /       SYSTEM/RCE     NTLM Authentication
      PAC
        │              │              │
        └──────────────┼──────────────┘
                       ▼
             Domain Compromise
```

---

# 2. Scenario Setup

The examples in the module primarily use a **Linux attack host**.

For Windows-based portions, the module uses tools such as:

- Rubeus
    
- Mimikatz
    

The module also demonstrates obtaining a certificate through `ntlmrelayx.py` and `PetitPotam`, then using that certificate for Kerberos authentication.

---

# 3. NoPac — SamAccountName Spoofing

## What is NoPac?

**NoPac** is associated with the **Sam_The_Admin** vulnerability and involves two vulnerabilities:

- **CVE-2021-42278**
    
- **CVE-2021-42287**
    

The attack can allow privilege escalation from a standard domain user toward **Domain Admin-level access** when the environment is vulnerable.

### CVE breakdown

|CVE|Main issue|
|---|---|
|**CVE-2021-42278**|SAM-related bypass / computer-account `sAMAccountName` manipulation|
|**CVE-2021-42287**|Kerberos PAC-related vulnerability|

---

## 4. NoPac Attack Concept

The important idea is:

```text
Standard Domain User
        │
        ▼
Create computer account
        │
        ▼
Change sAMAccountName
        │
        ▼
Spoof Domain Controller name
        │
        ▼
Request Kerberos ticket
        │
        ▼
Kerberos associates ticket
with DC identity
        │
        ▼
Privilege escalation
```

By default, authenticated users can potentially add up to **10 computer accounts** to a domain because of:

```text
ms-DS-MachineAccountQuota = 10
```

If this value is changed to:

```text
ms-DS-MachineAccountQuota = 0
```

the described attack path is prevented because the user cannot create the required machine account.

---

# ⭐ Important: MachineAccountQuota

### Default

```text
ms-DS-MachineAccountQuota = 10
```

Meaning a regular authenticated user may have permission to add computer accounts to the domain.

### Hardened value

```text
ms-DS-MachineAccountQuota = 0
```

This removes the ability for ordinary users to create new machine accounts through this mechanism.

### Memorize

> **MachineAccountQuota = number of computer accounts a user can add to the domain by default.**

---

# 5. NoPac Tooling

The module uses:

```text
/opt/noPac
```

The repository contains:

```text
scanner.py
noPac.py
```

The scanner checks whether the environment appears vulnerable, while `noPac.py` can perform the attack.

---

# 6. Checking for NoPac

Example from the module:

```bash
sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap
```

Important output:

```text
[*] Current ms-DS-MachineAccountQuota = 10
[*] Got TGT with PAC from 172.16.5.5. Ticket size 1484
[*] Got TGT from ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL. Ticket size 663
```

The important indicators are:

```text
MachineAccountQuota = 10
```

and successful TGT acquisition.

---

# 7. NoPac Exploitation Flow

The module demonstrates using `noPac.py` to obtain a SYSTEM-level shell.

Conceptually:

```text
Domain User
     │
     ▼
Create Computer Account
     │
     ▼
Change Computer sAMAccountName
     │
     ▼
Match DC Account Name
     │
     ▼
Obtain Kerberos Ticket
     │
     ▼
Impersonate Administrator
     │
     ▼
SYSTEM Shell
```

The example shows the temporary computer account being created, its name being manipulated, a ticket being saved, and the account subsequently restored.

---

# 8. NoPac and CCache

NoPac can save Kerberos tickets as a:

```text
.ccache
```

Example:

```text
administrator_DC01.INLANEFREIGHT.local.ccache
```

These tickets can potentially be used for subsequent Kerberos authentication and attacks.

**Important operational point:**

> Ticket files are artifacts that should be accounted for during an assessment.

---

# 9. NoPac → DCSync

The module also demonstrates a route from NoPac to DCSync.

Conceptually:

```text
NoPac
  ↓
Administrator/DC-level Kerberos access
  ↓
Domain Controller privileges
  ↓
DCSync
  ↓
NTLM hashes / Kerberos keys
```

The example uses `-dump` and retrieves the built-in Administrator credential material through the DRSUAPI mechanism.

---

# 10. Windows Defender / SMBEXEC Considerations

The module points out that `smbexec.py` can be noisy.

The technique involves creating services and temporary batch files to execute commands remotely.

Conceptually:

```text
smbexec
   │
   ├── Creates service
   │
   ├── Creates temporary .bat
   │
   ├── Executes command
   │
   └── Deletes temporary file
```

Because this behavior can be detected by Windows Defender/EDR, it may be inappropriate when stealth is an assessment concern.

### Important

```text
SMBEXEC = potentially noisy
```

Remember this for your notes.

---

# 🖨️ 11. PrintNightmare

## What is PrintNightmare?

PrintNightmare is the nickname associated with vulnerabilities affecting the Windows **Print Spooler** service.

The module covers:

- **CVE-2021-34527**
    
- **CVE-2021-1675**
    

These vulnerabilities can allow privilege escalation and, depending on the affected scenario, remote code execution.

---

# 12. PrintNightmare Attack Concept

```text
Attacker
   │
   ▼
Print Spooler
   │
   ▼
Vulnerable RPC functionality
   │
   ▼
Malicious DLL / payload
   │
   ▼
Code execution
   │
   ▼
SYSTEM
```

The module demonstrates the attack against a Domain Controller.

---

# 13. Enumerating Print Protocols

The module uses:

```bash
rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'
```

Expected relevant output:

```text
Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol
Protocol: [MS-RPRN]: Print System Remote Protocol
```

These protocols are important because PrintNightmare-related exploitation involves Windows printing RPC functionality.

---

# 14. PrintNightmare Payload Flow

The demonstrated flow is:

```text
Exploit
  │
  ▼
Malicious DLL
  │
  ▼
SMB Share
  │
  ▼
Print Spooler
  │
  ▼
Target loads DLL
  │
  ▼
Payload executes
  │
  ▼
Reverse connection
  │
  ▼
SYSTEM shell
```

The module demonstrates generating a DLL payload, hosting it through an SMB share, and configuring a handler.

---

# 15. Important PrintNightmare Detail

The payload path uses a UNC path:

```text
\\<ATTACKER-IP>\<ShareName>\<payload>.dll
```

The target accesses the SMB share and loads the payload.

The module's example ultimately obtains:

```text
nt authority\system
```

on the target.

---

# 🔐 16. PetitPotam

## What is PetitPotam?

**PetitPotam** is associated with:

```text
CVE-2021-36942
```

It is an **LSA spoofing / NTLM authentication coercion** vulnerability involving Microsoft's:

```text
MS-EFSRPC
```

The attack can cause a Domain Controller to authenticate to an attacker-controlled system using NTLM.

---

# 17. PetitPotam Attack Chain

This is one of the **most important diagrams to memorize**:

```text
             Domain Controller
                    │
                    │ NTLM authentication
                    ▼
              Attacker Host
                    │
                    ▼
              NTLM Relay
                    │
                    ▼
             AD CS Web Enrollment
                    │
                    ▼
          Certificate issued for DC
                    │
                    ▼
             Request DC TGT
                    │
                    ▼
              Domain Controller
                Kerberos TGT
                    │
                    ▼
                 DCSync
                    │
                    ▼
            Domain compromise
```

The module describes this exact chain: coercion → NTLM relay → AD CS certificate → TGT → DCSync.

---

# 18. Why AD CS Matters

**AD CS = Active Directory Certificate Services**

In the described attack, the Certificate Authority's Web Enrollment functionality is abused to obtain a certificate representing the Domain Controller.

That certificate can then be used with tools such as:

```text
Rubeus
gettgtpkinit.py
```

to request a TGT for the DC machine account.

---

# 19. NTLM Relay Component

The module demonstrates:

```text
ntlmrelayx.py
```

configured to relay authentication toward the AD CS Web Enrollment endpoint.

The important conceptual pieces are:

```text
Source:
Domain Controller

↓

Protocol:
NTLM

↓

Relay:
ntlmrelayx

↓

Destination:
AD CS Web Enrollment

↓

Certificate:
Domain Controller certificate
```

---

# 20. PetitPotam Coercion

PetitPotam abuses MS-EFSRPC functionality to trigger authentication.

The module uses:

```text
EfsRpcOpenFileRaw
```

The successful condition is represented by:

```text
ERROR_BAD_NETPATH
```

followed by:

```text
[+] Attack worked!
```

The error is significant because in this context it indicates the coercion request reached the expected stage.

---

# 21. Certificate Acquisition

When the relay succeeds, the attacker receives a certificate for the Domain Controller machine account.

The important sequence is:

```text
DC authentication
      ↓
NTLM relay
      ↓
AD CS
      ↓
CSR generated
      ↓
Certificate issued
      ↓
Base64 certificate
```

The module's output shows:

```text
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] GOT CERTIFICATE!
```

---

# 22. Certificate → TGT

The obtained certificate can be passed to:

```text
gettgtpkinit.py
```

Conceptually:

```text
DC Certificate
      ↓
PKINIT
      ↓
Kerberos AS-REQ
      ↓
TGT
      ↓
.ccache
```

The resulting TGT is stored in:

```text
dc01.ccache
```

The module then sets:

```bash
export KRB5CCNAME=dc01.ccache
```

so Kerberos-aware tools can use the ticket cache.

---

# 23. DCSync Using the DC TGT

Once a valid Domain Controller TGT is obtained, the module demonstrates using it for DCSync.

Conceptually:

```text
DC Certificate
      ↓
DC TGT
      ↓
Kerberos authentication
      ↓
DCSync / DRSUAPI
      ↓
NTLM hashes
```

The module retrieves the built-in Administrator's hash as an example.

---

# 24. `klist`

`klist` can be used to inspect cached Kerberos tickets.

Example:

```text
Ticket cache: FILE:dc01.ccache

Default principal:
ACADEMY-EA-DC01$@INLANEFREIGHT.LOCAL
```

The important thing is understanding:

```text
.ccache
   ↓
Kerberos ticket cache
   ↓
Kerberos-aware applications/tools
```

---

# 25. Alternative: Rubeus

The module also demonstrates a Windows-side approach using:

```text
Rubeus
```

The general workflow is:

```text
Base64 Certificate
       ↓
Rubeus
       ↓
Ask TGT
       ↓
Ticket imported
       ↓
PTT
       ↓
Kerberos authentication
```

The example uses:

```text
/asktgt
/certificate
/ptt
```

---

# 26. Confirming Tickets With `klist`

After performing PTT:

```powershell
klist
```

can show the imported TGT.

Important fields include:

```text
Client
Server
Encryption Type
Ticket Flags
Start Time
End Time
Renew Time
Kdc Called
```

The module shows a TGT for:

```text
ACADEMY-EA-DC01$
```

and a CIFS service ticket.

---

# 27. DCSync With Mimikatz

The module then demonstrates:

```text
mimikatz
```

with:

```text
lsadump::dcsync
```

The important concept is that a Domain Controller possesses the replication privileges required for DCSync.

Example target:

```text
inlanefreight\krbtgt
```

The resulting credential material includes an NTLM hash.

---

# 🔥 28. The Three Attack Chains — Memorize These

## NoPac

```text
Standard Domain User
        ↓
MachineAccountQuota
        ↓
Computer Account
        ↓
sAMAccountName Spoofing
        ↓
Kerberos
        ↓
Privilege Escalation
        ↓
SYSTEM / Domain compromise
```

## PrintNightmare

```text
Domain User
      ↓
Print Spooler
      ↓
MS-RPRN / MS-PAR
      ↓
Malicious DLL
      ↓
Remote Code Execution
      ↓
SYSTEM
```

## PetitPotam

```text
Unauthenticated / attacker-controlled trigger
                ↓
            PetitPotam
                ↓
          DC authentication
                ↓
            NTLM Relay
                ↓
              AD CS
                ↓
          DC Certificate
                ↓
              TGT
                ↓
             DCSync
                ↓
        Domain compromise
```

---

# 🛡️ 29. PetitPotam Mitigations

The module recommends several defenses.

### 1. Patch affected systems

Apply the patch for:

```text
CVE-2021-36942
```

### 2. Extended Protection for Authentication

Use:

```text
EPA
```

to reduce NTLM relay opportunities.

### 3. Require HTTPS

For AD CS Web Enrollment and Certificate Enrollment Web Service:

```text
Require SSL
```

### 4. Restrict NTLM

Consider disabling/restricting NTLM authentication where appropriate, particularly on:

- Domain Controllers
    
- AD CS servers
    
- IIS services hosting certificate enrollment
    

---

# 📌 30. Important Terms

|Term|Meaning|
|---|---|
|**NoPac**|SamAccountName spoofing attack chain|
|**CVE-2021-42278**|SAM-related component of NoPac|
|**CVE-2021-42287**|Kerberos PAC-related component|
|**MachineAccountQuota**|Controls how many computer accounts users can add|
|**PrintNightmare**|Print Spooler vulnerabilities|
|**CVE-2021-34527**|PrintNightmare vulnerability|
|**CVE-2021-1675**|Print Spooler vulnerability|
|**PetitPotam**|MS-EFSRPC authentication coercion|
|**CVE-2021-36942**|PetitPotam vulnerability|
|**NTLM Relay**|Relaying an NTLM authentication attempt to another service|
|**AD CS**|Active Directory Certificate Services|
|**PKINIT**|Kerberos pre-authentication using public-key cryptography|
|**TGT**|Ticket Granting Ticket|
|**TGS**|Ticket Granting Service ticket|
|**DCSync**|Abuse of AD replication functionality to obtain credential material|
|**PAC**|Privilege Attribute Certificate|
|**PTT**|Pass-the-Ticket|
|**CCache**|Kerberos credential cache|
|**Rubeus**|Windows Kerberos abuse/tooling utility|
|**Mimikatz**|Windows credential/security testing utility|

---

# 🧠 31. Exam/Assessment Memory Sheet

### NoPac

Remember:

```text
42278 + 42287
       ↓
NoPac
       ↓
sAMAccountName
       ↓
MachineAccountQuota
       ↓
Kerberos
```

### PrintNightmare

Remember:

```text
34527 + 1675
       ↓
Print Spooler
       ↓
MS-RPRN / MS-PAR
       ↓
RCE / PrivEsc
```

### PetitPotam

Remember:

```text
36942
  ↓
MS-EFSRPC
  ↓
NTLM coercion
  ↓
Relay
  ↓
AD CS
  ↓
Certificate
  ↓
TGT
  ↓
DCSync
```

---

# 🖼️ Visual Summary

![Image](https://images.openai.com/static-rsc-4/GSUZCwkEFE0Uqq1oowN22WPeY9XEzLmVCvMtJqLsLmdNPL1_IifJP_HfiwA_AXEsvkNPCz3866QS1xITghP_jqL1KFim5uzb1jCN29CsJaFiA0gH6J_9XKzm-LiciNq9ky9AnFruFMOjt-JINCrRctessZ3OdvuiJmC9zrZ0SYCpHgHjg3uiqNddA7x4LUeB?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/g7479GozsyIDSzFTVYMBOnTemoLmId8H7GqYHXxpniNRVolcrGARlyNDLgshE5OD6SZPLVh6AdmIKL37rDknb6nk5hpbKnqVraUC2hNdmCk0MjqFbCslPf7H8wi9SYGDmZw677RYP_kdFc1JHBXFsLMY__946Q1rOC07UI7X_UdlQ9WbaABLKlYkfscAP5OV?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/SUbxacMXKzk_467fgjADWYFo1euYIZ2ZfJoInclBxR3YotjkIfOx2GzTvs7c3ptzgWpDH2T-hNMZwFg13LWgEiM-zQwFo2FLxi3UHp_a4BOo4lkL1x4pDG9Rvw41alBJFcoJJB1z5D_ZhVWQfr7C372lqeGJMd2ECbrzfsVWWdQw15XAe2SlLJkXN8ypG10g?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/zM5pPC4GZVEev1xgjCGjVmnbwEHZ6itLcHV7ETfhic5olAvYnKmi02W1M9PpCOWcOoFW9ZpKEhNgMBakBwyrB6bRFirgJ0OBBdqLy13T2pGKWJG0_I9jVkuWHaAgYcBvBx0VExay6ntxYUvAh9vUmF01eoFrsdus64ZGj0sKwnTaaML1p1N6VtgVMPr-08qS?purpose=fullsize)

### Final takeaway

The module's three major topics are **NoPac, PrintNightmare, and PetitPotam**. The most important skill is not memorizing individual commands; it's recognizing the **attack chain and the underlying AD weakness**: NoPac abuses computer-account/Kerberos behavior, PrintNightmare abuses Print Spooler functionality, and PetitPotam coerces machine authentication that can become dangerous when combined with NTLM relay and AD CS.