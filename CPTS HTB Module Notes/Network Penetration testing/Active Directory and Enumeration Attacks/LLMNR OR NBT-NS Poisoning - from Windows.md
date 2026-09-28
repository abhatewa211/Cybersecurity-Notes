# 1. Module Overview

In the previous section, **Responder** was used from Linux to capture authentication hashes.

This section moves to a **Windows attack box** and introduces:

> **Inveigh**

Inveigh performs similar functionality to Responder but is written in:

- **PowerShell**
    
- **C#**
    

It can listen for and interact with several protocols, including:

- LLMNR
    
- DNS
    
- mDNS
    
- NBNS
    
- DHCPv6
    
- ICMPv6
    
- HTTP
    
- HTTPS
    
- SMB
    
- LDAP
    
- WebDAV
    
- Proxy Auth
    

The lab provides Inveigh in:

```text
C:\Tools
```

---

# 2. Inveigh vs Responder

Think of the relationship like this:

```text
                LLMNR/NBT-NS Poisoning
                         │
             ┌───────────┴───────────┐
             │                       │
           Linux                   Windows
             │                       │
             ▼                       ▼
         Responder                Inveigh
```

### Responder

Primarily used from Linux.

### Inveigh

Designed for Windows and available in:

```text
PowerShell
C#
```

The underlying purpose is similar: listen for and spoof network name-resolution/authentication traffic in an authorized assessment.

---

# 3. Inveigh PowerShell Version

The original PowerShell version can be loaded using:

```powershell
Import-Module .\Inveigh.ps1
```

Then we can inspect the available parameters:

```powershell
(Get-Command Invoke-Inveigh).Parameters
```

This is an important pentesting habit:

> **Before running a tool, inspect its available parameters.**

Don't blindly copy a command without understanding what the options control.

---

# 4. Important Inveigh Parameters

The parameter list includes options related to:

```text
ADIDNSHostsIgnore
KerberosHostHeader
ProxyIgnore
PcapTCP
PcapUDP
SpooferHostsReply
SpooferHostsIgnore
SpooferIPsReply
SpooferIPsIgnore
WPADDirectHosts
WPADAuthIgnore
ConsoleQueueLimit
ConsoleStatus
ADIDNSThreshold
ADIDNSTTL
DNSTTL
HTTPPort
HTTPSPort
KerberosCount
LLMNRTTL
```

You don't need to memorize every parameter immediately. The important skill is knowing **where to look when you need to control Inveigh's behavior**.

---

# 5. Starting Inveigh

The module demonstrates starting Inveigh with:

- LLMNR spoofing enabled
    
- NBNS spoofing enabled
    
- Console output enabled
    
- File output enabled
    

The command is:

```powershell
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

---

# 6. Understanding the Startup Output

When Inveigh starts, it reports its configuration.

Important examples from the module:

```text
Elevated Privilege Mode = Enabled
Primary IP Address = 172.16.5.25
Spoofer IP Address = 172.16.5.25

DNS Spoofer = Enabled
LLMNR Spoofer = Enabled
mDNS Spoofer = Disabled
NBNS Spoofer For Types 00,20 = Enabled

SMB Capture = Enabled
HTTP Capture = Enabled
HTTPS Capture = Enabled

HTTP/HTTPS Authentication = NTLM
WPAD Authentication = NTLM

Console Output = Full
File Output = Enabled
Output Directory = C:\Tools
```

### Important observation

The output tells you **what Inveigh is actually doing**.

Always read this before continuing.

---

# 7. LLMNR Request → Spoofed Response

The module shows an LLMNR request:

```text
LLMNR request for academy-ea-web0 received from 172.16.5.125
[response sent]
```

Conceptually:

![Image](https://images.openai.com/static-rsc-4/bREXPKv2qxiBA7xa8A97v5hXNSpkPnKjsN_mZ9RbtLdEpcRYTM32Y7nFvVgvb2GIPdQ9HJGkke2HJc7yQmMn_6vlHblWkF_O-AL7emwTq49HYHd0_upCMgRwEGt2P6lb8n2Ehuplcqngu4JVUyFyv05_AfMiRU_G2ZT0uEvLlVEBynr1Xfsh3wKtAzyVVP4k?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/0waY3qfXFuhIr6jWivfOiFmzZAfLw-IuRe74lnFSrpVfkO6KncZiw0ralwaWEnrp_KwnkOCzU8wuGkYxAOQIchOsomkJoY-C7x9IHpaOZlHA1ZMZiHV5AeN7Q1k1GXg6LxT61b9XwLIHAcQGVItGE57mBk95piCdjpLSnloirpPsPwXFjQMwQwFu-yhhg_Yi?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/BBoykOQgmefvWzLChzpfpTBxmqLA1-_d4WR_h2j6mzldH1fVYBVYUCt-mUKy6Z3Cfh8P7aDkt5bZnixCZcxKW90aALXi1lqDXK_G0s3Th0C5_6ABMN2RLSmV2uENM055KzyB38FN9kcIAho3r1YqBXov4jX3I2pNgUrRS1PilUsOWxD8L5O_jGVrsrV6xDJ4?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/sEHdC5PC00ld3s3E8HRRp-Fanq8OnmvITKPXD3Yb_SSpiZ_1SR9ZhxVyqlKvm2g3HqWTFHCSxwtHnrG1d6oSr168ndSQMjlxuWKNFJCfM2H-WUxaqAlrrHWhQKhG3g7MXJTl9ju9lVbNdNVvA6IE5Gtlr2RB2hTnA4VA46prUTqXmKI59WgQ4n8dI4rSzuUv?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Ta0zKbGyiRvPP08sJmsmmgMlzdIylJSJ3O77HZ7Rx1z159QEZbofqRgLL2LYnzkSc3rB5WM9Gu081Ss86-KgsmmxSW8K3AfalLw-CjgGfDhiTeZhYzBz5aNpMG6oKXQpV5y9JIptEHBAirCtTbpEShIqhyaBV11n6oPhq2Je9FSbEfJbCg3YkVepHEO69_q-?purpose=fullsize)

```text
Windows Client
      │
      │ "Where is academy-ea-web0?"
      ▼
   LLMNR request
      │
      ▼
    Inveigh
      │
      │ Spoofed response
      ▼
Windows Client
      │
      │ Authentication attempt
      ▼
    Inveigh
      │
      ▼
Captured authentication
```

---

# 8. SMB Authentication Capture

The module then shows SMB traffic:

```text
TCP(445) SYN packet detected
SMB(445) negotiation request detected
SMB(445) NTLM challenge ... sent
```

Port:

```text
445/TCP
```

is associated with SMB.

The important concept is:

```text
LLMNR spoofing
      ↓
Victim connects to attacker
      ↓
SMB negotiation
      ↓
NTLM authentication
      ↓
Authentication material captured
```

---

# 9. Inveigh C# Version — InveighZero

The module then introduces the C# version.

The original PowerShell version is no longer being updated. The author maintains the C# version, which combines the original proof-of-concept C# code with a C# port of much of the PowerShell functionality.

The lab provides:

```text
C:\Tools
```

with both versions.

The module also recommends understanding how to compile the tool yourself using Visual Studio.

---

# 10. Running InveighZero

The C# executable can be launched with:

```powershell
.\Inveigh.exe
```

The startup screen reports its configuration.

For example:

```text
Packet Sniffer Addresses
Listener Addresses
Spoofer Reply Addresses
Spoofer Options
```

It also shows individual protocol components.

---

# 11. Understanding `[+]`, `[ ]`, and `[-]`

This is very important when reading Inveigh's console.

### `[+]`

Generally indicates the option is:

```text
Enabled
```

### `[ ]`

Indicates the option is:

```text
Disabled
```

### `[-]`

In the running console, this can indicate an ignored/disabled request or event.

The module specifically explains that `[+]` options are enabled by default and `[ ]` options are disabled.

---

# 12. Default C# Configuration

The module's example shows:

```text
DNS Packet Sniffer       [+]
LLMNR Packet Sniffer     [+]
HTTP Listener            [+]
WebDAV                   [+]
LDAP Listener            [+]
SMB Packet Sniffer       [+]
```

while some features such as:

```text
DHCPv6
ICMPv6
mDNS
NBNS
HTTPS
Proxy
```

are shown disabled in that example.

### Important

The configuration shown by the module is an **example environment**. Don't assume every deployment will have exactly the same state.

---

# 13. HTTP Listener Error

The example shows:

```text
Failed to start HTTP listener on port 80
```

with a message indicating the socket could not be accessed because of its permissions/usage.

This doesn't mean the entire tool failed.

The other components continue operating, as shown by subsequent LLMNR activity.

### Troubleshooting mindset

When a tool reports an error:

```text
Tool started?
      ↓
Which component failed?
      ↓
Which components are still working?
      ↓
Does the failed component matter for the current objective?
```

Don't automatically assume the whole assessment is broken.

---

# 14. IPv4 vs IPv6

The C# version demonstrates both IPv4 and IPv6 activity.

For example:

```text
172.16.5.125
```

and:

```text
fe80::f098:4f63:8384:d1d0%8
```

appear in the output.

This shows that modern Windows environments can generate both IPv4 and IPv6 name-resolution traffic.

Inveigh is capable of listening to both.

---

# 15. Interactive Console

One of the useful features of Inveigh is its **interactive console**.

The module states:

```text
Press ESC to enter/exit interactive console
```

Pressing:

```text
ESC
```

allows you to interact with the console while Inveigh continues running.

---

# 16. Inveigh Console Commands

Typing:

```text
HELP
```

displays the available commands.

The important commands are:

|Command|Purpose|
|---|---|
|`GET CONSOLE`|Get queued console output|
|`GET LOG`|Get log entries|
|`GET NTLMV1`|Get captured NTLMv1 hashes|
|`GET NTLMV2`|Get captured NTLMv2 hashes|
|`GET NTLMV1UNIQUE`|One NTLMv1 hash per user|
|`GET NTLMV2UNIQUE`|One NTLMv2 hash per user|
|`GET NTLMV1USERNAMES`|NTLMv1 usernames + source information|
|`GET NTLMV2USERNAMES`|NTLMv2 usernames + source information|
|`GET CLEARTEXT`|Captured cleartext credentials|
|`GET CLEARTEXTUNIQUE`|Unique cleartext credentials|
|`HISTORY`|Command history|
|`RESUME`|Resume live console output|
|`STOP`|Stop Inveigh|

---

# 17. `GET NTLMV2UNIQUE`

This command is particularly useful:

```text
GET NTLMV2UNIQUE
```

It displays unique captured NTLMv2 hashes.

The module demonstrates captured accounts such as:

```text
backupagent
forend
```

along with their corresponding NTLMv2 authentication material.

### Why `UNIQUE` matters

If the same user authenticates multiple times, you don't necessarily want to work through duplicate hashes.

Unique output makes the captured account list easier to analyze.

---

# 18. `GET NTLMV2USERNAMES`

This command:

```text
GET NTLMV2USERNAMES
```

lists usernames and source information associated with captured NTLMv2 authentication.

The module's example shows:

|IP Address|Host|Username|
|---|---|---|
|`172.16.5.125`|`ACADEMY-EA-FILE`|`INLANEFREIGHT\backupagent`|
|`172.16.5.125`|`ACADEMY-EA-FILE`|`INLANEFREIGHT\forend`|
|`172.16.5.125`|`ACADEMY-EA-FILE`|`INLANEFREIGHT\clusteragent`|
|`172.16.5.125`|`ACADEMY-EA-FILE`|`INLANEFREIGHT\wley`|
|`172.16.5.125`|`ACADEMY-EA-FILE`|`INLANEFREIGHT\svc_qualys`|

This is useful because the usernames can become candidates for **additional enumeration and offline password-cracking analysis**.

---

# 19. Understanding the Captured NTLMv2 Format

The module shows entries such as:

```text
backupagent::INLANEFREIGHT:B5013246091943D7:...
```

and:

```text
forend::INLANEFREIGHT:32FD89BD78804B04:...
```

At a high level:

```text
username
   ↓
domain
   ↓
challenge
   ↓
response/authentication data
```

This is the material that can subsequently be analyzed or subjected to offline password cracking.

---

# 20. PowerShell Inveigh vs C# Inveigh

|Feature|PowerShell Version|C# Version|
|---|---|---|
|Language|PowerShell|C#|
|Executed as|PowerShell module|Executable|
|Example|`Invoke-Inveigh`|`Inveigh.exe`|
|Interactive console|Limited/varies|Yes|
|Maintained|Original/no longer updated|Maintained version|
|Lab location|`C:\Tools`|`C:\Tools`|

The module specifically identifies the C# version as the maintained version.

---

# 21. Remediation

The module maps the technique to:

**MITRE ATT&CK T1557.001**

> **Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay**

The primary mitigation discussed is disabling:

```text
LLMNR
NBT-NS
```

However, the module emphasizes that organizations should **test these changes carefully before deploying them broadly**, because disabling legacy functionality can affect network operations.

---

# 22. Disabling LLMNR

LLMNR can be disabled through Group Policy.

Path:

```text
Computer Configuration
    ↓
Administrative Templates
    ↓
Network
    ↓
DNS Client
    ↓
Turn OFF Multicast Name Resolution
```

Enable:

```text
Turn OFF Multicast Name Resolution
```

---

# 23. Disabling NBT-NS

NBT-NS cannot be disabled directly through Group Policy in the same manner.

The module describes the local GUI process:

```text
Control Panel
 ↓
Network and Sharing Center
 ↓
Change adapter settings
 ↓
Adapter Properties
 ↓
Internet Protocol Version 4 (TCP/IPv4)
 ↓
Properties
 ↓
Advanced
 ↓
WINS
 ↓
Disable NetBIOS over TCP/IP
```

---

# 24. Disabling NBT-NS Through PowerShell/GPO

The module provides a PowerShell approach:

```powershell
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey |foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}
```

The script can be configured as a **startup script** through Group Policy.

The module notes that systems need to be restarted or their network adapters restarted for the changes to take effect.

---

# 25. Deploying the Script Through SYSVOL

The module describes placing the script in the domain's SYSVOL share.

Example:

```text
\\inlanefreight.local\SYSVOL\INLANEFREIGHT.LOCAL\scripts
```

A GPO can then reference the script and apply it to appropriate OUs.

After affected hosts restart, the startup script can disable NBT-NS.

---

# 26. Other Mitigations

The module also identifies:

### Network traffic filtering

Block:

```text
LLMNR
NetBIOS
```

traffic where appropriate.

### SMB Signing

Enable **SMB Signing** to help prevent NTLM relay attacks.

### IDS/IPS

Network intrusion detection/prevention systems can help detect or mitigate suspicious activity.

### Network segmentation

Hosts that genuinely require LLMNR or NetBIOS can be isolated from other systems.

---

# 27. Detection

Disabling protocols isn't always possible.

Therefore, organizations also need detection mechanisms.

One technique described by the module is to deliberately generate requests for **non-existent hosts** across different network segments.

If a system responds to these fake requests, that can indicate a host is spoofing name-resolution responses.

### Concept

```text
Defender
   │
   │ Fake hostname request
   ▼
Network
   │
   ├── No legitimate host should respond
   │
   └── Attacker responds
             │
             ▼
          Alert
```

---

# 28. Network Monitoring

The module recommends monitoring traffic involving:

```text
UDP 5355
UDP 137
```

These correspond to the relevant LLMNR/NBT-NS traffic discussed in the module.

---

# 29. Windows Event IDs

The module also mentions monitoring:

```text
Event ID 4697
Event ID 7045
```

These can provide useful signals when investigating suspicious system/service activity.

---

# 30. Registry Monitoring

Another detection method is monitoring:

```text
HKLM\Software\Policies\Microsoft\Windows NT\DNSClient
```

Specifically:

```text
EnableMulticast
```

The module states that:

```text
EnableMulticast = 0
```

means LLMNR is disabled.

---

# 31. Where This Fits in an AD Attack Path

The module ends by connecting hash capture to the larger penetration-testing workflow.

The captured hashes can be analyzed with tools such as **BloodHound** to determine whether the associated accounts have useful privileges or relationships.

Potential progression:

```text
LLMNR/NBT-NS Poisoning
          ↓
NTLMv2 Capture
          ↓
Account Identification
          ↓
BloodHound / AD Enumeration
          ↓
Identify Valuable Accounts
          ↓
Offline Cracking
          ↓
Valid Credentials
          ↓
Lateral Movement
          ↓
Privilege Escalation
```

The module notes that a successfully cracked privileged account could significantly expand access, potentially even providing Domain Admin-level access. If cracking doesn't produce useful credentials, **password spraying** is another technique covered later in the material.

---

# 🧠 Important Things to Remember

### 1. Tool

```text
Windows → Inveigh
Linux   → Responder
```

### 2. Main purpose

```text
LLMNR/NBT-NS spoofing
        ↓
Capture authentication
```

### 3. PowerShell version

```powershell
Import-Module .\Inveigh.ps1
```

### 4. Start PowerShell Inveigh

```powershell
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

### 5. C# version

```powershell
.\Inveigh.exe
```

### 6. Interactive console

```text
ESC
```

### 7. View NTLMv2 hashes

```text
GET NTLMV2
```

### 8. View unique NTLMv2 hashes

```text
GET NTLMV2UNIQUE
```

### 9. View captured usernames

```text
GET NTLMV2USERNAMES
```

### 10. Stop

```text
STOP
```

### 11. Main remediation

```text
Disable LLMNR
Disable NBT-NS
Enable SMB Signing
Filter traffic
Monitor suspicious activity
Segment networks
```

---

# 🔥 Final Mental Model

Don't memorize Inveigh as just a collection of commands.

Understand the attack:

```text
             WINDOWS CLIENT
                    │
                    │ Name cannot be resolved
                    ▼
             LLMNR / NBNS
                    │
                    │ Broadcast
                    ▼
                INVEIGH
                    │
                    │ Spoofed response
                    ▼
             WINDOWS CLIENT
                    │
                    │ NTLM authentication
                    ▼
                INVEIGH
                    │
                    ▼
             NTLMv2 captured
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
     Identify user       Crack/analyze
          │                   │
          └─────────┬─────────┘
                    ▼
             Valid credentials
                    │
                    ▼
          AD enumeration /
          lateral movement
```

**Core lesson:** the interesting part isn't simply _"how to run Inveigh."_ It's understanding how a Windows host's fallback name-resolution behavior can be abused to obtain authentication material, and then understanding how defenders can disable, monitor, and detect that behavior.