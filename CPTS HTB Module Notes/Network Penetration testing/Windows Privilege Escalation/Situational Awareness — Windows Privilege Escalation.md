# 1. 🧠 What Is Situational Awareness?

After gaining access to a Windows or Linux system, **don't immediately start exploiting things**.

First determine:

```text
Who am I?
     ↓
Where am I?
     ↓
What networks can I access?
     ↓
What other hosts can I see?
     ↓
What security controls exist?
     ↓
What tools/commands can I execute?
     ↓
What should I investigate next?
```

This helps you operate **proactively instead of reactively**.

### Why does this matter?

You might discover:

- Another network interface
    
- A second network
    
- Domain controllers
    
- Other hosts
    
- Interesting routes
    
- Administrator activity
    
- RDP/WinRM connections
    
- Antivirus
    
- EDR
    
- Application whitelisting
    
- Blocked binaries
    

Any of these discoveries can completely change your attack path.

---

# 🌐 2. Network Information

Network enumeration is described as a **crucial part of enumeration**.

One of the first things you should determine is:

> **How is this machine connected to the network?**

---

# 🔀 3. Dual-Homed Hosts

A **dual-homed host** is a system that belongs to **two or more networks**.

It usually has multiple:

- Physical network interfaces
    
- Virtual network interfaces
    

### Visualize it:

![Image](https://images.openai.com/static-rsc-4/SkZr5341vLTBhcTN3cEuobZvPxITqiXAQEAb6ugk2iMKCmn2Kd6vUDaKQhXoq-lNplidOE8n9dpIrmrdgK_ln3dByWFp9IvVqZpY8-nGOlychFmRmT7Xv-dEdtC6wtqapBTdZqzWRsmNw_ZQeR5oHC4OgaRT2hHidq0UlWY8EVlNUlqYzK7XiXS4EDVGdUTy?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/-oMBR5olt5wfwHekHWnhegX_fv0hKP9aqZTl7E4HG-NxMXQVsrRcgKZdu1IqrolrgVbawDPrG8QbUjaq7JQNYW0fzztnaqMmNSYk7Bi4MzLHpbfdcjrf1gYhwXIWy0AYA3W0v5MG_C7AEt1fp_JztJ8kU1ml765VNAB-I9n9M2V9sZstEat-1LKarrngymyA?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/SIU4TVC9TQoTkhGKqW13LKon8z4QJOq1_79uZ19Ihlwjyy8dThN4e_1_-7XGW0AokfXj7qsnM_72YtNpOovb5ZJ6tcG1cDELlV1K8ofx8dPOyZosF96TNnB0RhNzuKy7aYJutdEcFGp91zqLuDQWnm-6Hk1zbTQ0Ji753mR-NYSs6fFYyPpJxs_WMcJ6UrXW?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/vB6Q9LNIIIHfDbnI7qAqnZz2DzVKjp3y6hFY336sG6BAc7O18h_8eL2OAng5K2uu6_-yiYnDKr3cOIRkv5ZXT8PuSnJdZ9pCI85UhFp00pQagOAODNtcSYYF4I_NP8U9CLpFDhtBUrmDrbHXhljudAJeSgln6CbBXnwPvBLBXC97zZtVU5ZLoBJ5WwaO7eTd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/jS3-1WFWSxnDbj3HqEV9srs4JPDNfBUDAfzWfBZ8_J7TEbp0hAFnLyMo1bb2eMtjjfDPP6HqD8rA90otBdQP4xMzL5cXKKGnAjp2ohEU1Ng44lX5CbpGkcGcQIO3tJxxgK2kQktLBkD6nXwRSmpCefs9PemMNu5HLRaUCVT8nUClVbknuOW969myvCWwjcqZ?purpose=fullsize)

```text
                Network A
              10.129.0.0/16
                    │
                    │
              ┌─────▼─────┐
              │   HOST    │
              │           │
              │ Interface │
              │     1     │
              │           │
              │ Interface │
              │     2     │
              └─────┬─────┘
                    │
                    │
                Network B
              192.168.20.0/24
```

### Why is this interesting?

Suppose your attack machine can only access:

```text
10.129.0.0/16
```

but the compromised host can also access:

```text
192.168.20.0/24
```

That host may provide a path into a network you couldn't reach directly.

The source specifically points out that compromising a dual-homed host may allow lateral movement into another part of the network.

### ⭐ CPTS takeaway

**Multiple interfaces = investigate immediately.**

---

# 💻 4. `ipconfig /all`

One of the first Windows commands to run is:

```cmd
ipconfig /all
```

The source example uses:

```cmd
C:\htb> ipconfig /all
```

This gives you a lot of useful network information.

---

# 🔎 5. What Does `ipconfig /all` Tell You?

Look for:

### 🖥️ Host Name

Example:

```text
Host Name : WINLPE-SRV01
```

This identifies the Windows machine.

---

### 🌐 IPv4 Address

Example:

```text
IPv4 Address : 192.168.20.56
```

and another interface:

```text
IPv4 Address : 10.129.43.8
```

🚨 **This is a major finding.**

The host has addresses on two different networks:

```text
192.168.20.56
       │
       ▼
192.168.20.0/24

10.129.43.8
       │
       ▼
10.129.0.0/16
```

That makes this an example of a **dual-homed host**.

---

# 🚪 6. Default Gateway

Example:

```text
Default Gateway : 192.168.20.1
```

and:

```text
Default Gateway : 10.129.0.1
```

The default gateway tells you where traffic destined for other networks can be sent.

### Concept:

```text
Your Host
   │
   ▼
Default Gateway
   │
   ▼
Other Network
```

---

# 🧭 7. DNS Information

The example shows DNS servers including:

```text
8.8.8.8
1.1.1.1
```

and a DNS suffix:

```text
.htb
```

DNS information can help you understand:

- Domain configuration
    
- Name resolution
    
- Internal naming
    
- Active Directory environment
    

The source specifically recommends gathering information about the local domain when the host is part of an Active Directory environment, including IP addresses of domain controllers.

---

# 📡 8. ARP Cache

Another extremely important command:

```cmd
arp -a
```

The source says we should use the ARP command to view the ARP cache for each interface and identify hosts the machine has recently communicated with.

---

## What is ARP?

**ARP = Address Resolution Protocol**

It maps an IP address to a MAC address on a local network.

Conceptually:

```text
IP Address
    ↓
ARP
    ↓
MAC Address
```

Example from the source:

```text
10.129.0.1       → 00-50-56-b9-4d-df
10.129.43.12     → 00-50-56-b9-da-ad
10.129.43.13     → 00-50-56-b9-5b-9f
```

---

# 🔥 9. Why Is the ARP Cache Interesting?

The ARP cache can reveal **other hosts the compromised machine has recently communicated with**.

This is valuable because the host may belong to an environment where administrators connect to other machines.

The source specifically mentions that ARP information could indicate which hosts administrators connect to using:

- RDP
    
- WinRM
    

### Think:

```text
Compromised Host
       │
       ├── Host A
       ├── Host B
       └── Host C
              │
              ▼
       Administrator activity?
              │
              ▼
       Potential lateral movement
```

---

# 🛣️ 10. Routing Table

The next major piece of network information is the **routing table**.

Windows command:

```cmd
route print
```

---

# 🧠 11. Why Do We Need the Routing Table?

The routing table tells us:

> **Which networks this host knows how to reach and through which gateway/interface.**

The source explicitly says we should always examine routing tables to understand the local network and networks around it.

---

## Example from the source

The routing table contains:

```text
10.129.0.0     255.255.0.0
192.168.20.0   255.255.255.0
```

So we can identify two major IPv4 networks:

```text
10.129.0.0/16
192.168.20.0/24
```

This matches what we saw earlier in `ipconfig /all`.

---

# 🔗 12. Connecting the Three Commands

This is an important CPTS concept.

## `ipconfig /all`

Tells you:

> **What interfaces and IP addresses do I have?**

## `arp -a`

Tells you:

> **Which nearby hosts have I recently communicated with?**

## `route print`

Tells you:

> **Which networks can I reach and through which routes?**

### Together:

```text
             Network Awareness
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
 ipconfig /all    arp -a    route print
        │           │           │
        ▼           ▼           ▼
 Interfaces      Hosts       Networks
 IP addresses    Nearby      Routes
 DNS             systems     Gateways
```

🔥 **Memorize this.**

---

# 🎯 13. Network Information Can Lead to Privilege Escalation

Network enumeration isn't necessarily separate from privilege escalation.

It can reveal another path.

For example:

```text
Current Host
     │
     ▼
Discover Second Network
     │
     ▼
Discover Other Host
     │
     ▼
Find Credentials
     │
     ▼
Access Another Host
     │
     ▼
Escalate There
```

The source explicitly notes that network information may directly or indirectly assist local privilege escalation or lead to another system where privileges can be escalated.

---

# 🛡️ 14. Enumerating Protections

Now comes another **very important CPTS topic**.

Before running tools or attempting techniques, determine:

> **What security controls are protecting this machine?**

Modern environments commonly have:

- Antivirus
    
- EDR
    
- Application whitelisting
    
- Other security controls
    

These can:

- Monitor
    
- Alert
    
- Block
    
- Detect tools
    
- Detect suspicious commands
    

---

# 🦠 15. Antivirus & EDR

### Antivirus

Traditional antivirus focuses heavily on detecting malicious files and behavior.

### EDR

**Endpoint Detection and Response** provides more extensive monitoring and detection capabilities.

The source warns that these protections can interfere with enumeration and may present challenges when using public PoCs or tools.

---

# ⭐ 16. Why Enumerate Security Controls First?

Imagine you run a commonly detected tool immediately.

```text
Run Tool
   ↓
EDR Detects
   ↓
Alert
   ↓
Defender Response
   ↓
Your Access May Be Lost
```

Therefore:

```text
Gain Access
     ↓
Enumerate Defenses
     ↓
Understand Restrictions
     ↓
Choose Appropriate Technique
```

This is especially relevant during authorized assessments.

---

# 🔐 17. Application Whitelisting

Another important security control is:

> **Application whitelisting**

The goal is to control which applications and files users are allowed to execute.

For example, an organization might prevent standard users from running:

```text
cmd.exe
powershell.exe
```

or other binaries that aren't required for their daily work.

---

# 🪟 18. AppLocker

A popular Microsoft application-whitelisting solution mentioned in the source is:

**AppLocker**

It can control what:

- Applications
    
- Executables
    
- Scripts
    
- Installer files
    

users are allowed to run.

---

# 💻 19. Checking AppLocker

The source gives:

```powershell
Get-AppLockerPolicy
```

Specifically, to enumerate effective policy:

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

---

# 🔎 20. Understanding AppLocker Rules

The example contains rules such as:

```text
All signed packaged apps
All files located in Program Files
All files located in Windows
All files
All digitally signed Windows Installer files
All Windows Installer files
All scripts located in Program Files
All scripts located in Windows
All scripts
```

The important thing isn't memorizing every GUID.

Instead, understand:

> **Which users/groups are allowed to execute which files from which locations?**

---

# 👥 21. SID — UserOrGroupSid

The example contains:

```text
S-1-1-0
```

and:

```text
S-1-5-32-544
```

The first represents the **Everyone** security principal in the example rules, while the latter corresponds to the local **Administrators** group.

For example:

```text
UserOrGroupSid : S-1-1-0
Action         : Allow
```

and:

```text
UserOrGroupSid : S-1-5-32-544
Action         : Allow
```

### CPTS point

When reading AppLocker output, pay attention to:

```text
PathConditions
PublisherConditions
HashExceptions
PathExceptions
UserOrGroupSid
Action
```

---

# 🧪 22. Testing AppLocker Policy

The source provides a particularly useful example.

```powershell
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
```

The result:

```text
FilePath                         PolicyDecision
--------                         --------------
C:\Windows\System32\cmd.exe     Denied
```

### What does this tell us?

It tells us that, under the tested policy/user context:

```text
cmd.exe
   ↓
AppLocker evaluation
   ↓
DENIED
```

That's valuable information **before** relying on `cmd.exe` during enumeration.

---

# 🛡️ 23. Windows Defender Status

The source demonstrates checking Defender with:

```powershell
Get-MpComputerStatus
```

The output contains many useful fields.

---

## Important fields

### `AMServiceEnabled`

Shows whether the antimalware service is enabled.

Example:

```text
AMServiceEnabled : True
```

### `AntivirusEnabled`

Example:

```text
AntivirusEnabled : True
```

### `BehaviorMonitorEnabled`

Example:

```text
BehaviorMonitorEnabled : False
```

### `RealTimeProtectionEnabled`

Example:

```text
RealTimeProtectionEnabled : False
```

---

# 🧠 24. Important Defender Fields to Recognize

|Field|What it tells you|
|---|---|
|`AMServiceEnabled`|Antimalware service status|
|`AntivirusEnabled`|Antivirus status|
|`BehaviorMonitorEnabled`|Behavior monitoring status|
|`IoavProtectionEnabled`|Internet/file protection status|
|`NISEnabled`|Network Inspection System status|
|`OnAccessProtectionEnabled`|On-access protection status|
|`RealTimeProtectionEnabled`|Real-time protection status|

The source's example shows several of these protections disabled, but **don't assume those values apply to every Windows system**. They are simply the values from the provided lab output.

---

# 🧩 25. Putting Situational Awareness Together

When you land on a Windows host, think in this order:

```text
                  WINDOWS HOST
                       │
          ┌────────────┴────────────┐
          ▼                         ▼
     NETWORK INFO              PROTECTIONS
          │                         │
          ▼                         ▼
    ipconfig /all             Defender
          │                    AppLocker
          ▼                       EDR
       arp -a
          │
          ▼
    route print
          │
          ▼
   Other Networks/Hosts
          │
          └─────────────┐
                        ▼
                 Plan Next Step
```

---

# 🔥 26. CPTS Enumeration Checklist

When you first land on Windows, build this habit.

### 🌐 Network

```cmd
ipconfig /all
arp -a
route print
```

Check:

-  Hostname
    
-  IP addresses
    
-  Number of interfaces
    
-  DNS
    
-  Default gateways
    
-  Other networks
    
-  ARP entries
    
-  Potential dual-homed configuration
    

---

### 🛡️ Protections

Check:

-  Windows Defender
    
-  AV
    
-  EDR
    
-  Application whitelisting
    
-  AppLocker
    
-  Blocked binaries
    
-  Suspicious command monitoring
    

---

### 🧠 Then ask

```text
What can I reach?
       ↓
What can I execute?
       ↓
What is blocked?
       ↓
What other hosts exist?
       ↓
What network can I move into?
       ↓
What enumeration method makes sense?
```

---

# ⭐ 27. Most Important Things to Memorize

### `ipconfig /all`

> **Interfaces + IP + DNS + gateway**

### `arp -a`

> **Recently observed local hosts / IP-to-MAC mappings**

### `route print`

> **Routes + networks + gateways**

### Dual-homed

> **Host connected to two or more networks**

### Defender

```powershell
Get-MpComputerStatus
```

> **Enumerate Windows Defender status**

### AppLocker

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

> **Enumerate effective AppLocker rules**

### Test AppLocker

```powershell
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
```

> **Test whether a file would be allowed/denied under the specified policy context**

---

# 🧠 28. The Big CPTS Lesson

This entire section can be reduced to one principle:

> **Don't attack blindly. Understand the environment first.**

Your initial access is only your starting point.

```text
FOOTHOLD
   ↓
SITUATIONAL AWARENESS
   ↓
NETWORK ENUMERATION
   ↓
PROTECTION ENUMERATION
   ↓
UNDERSTAND LIMITATIONS
   ↓
CHOOSE ENUMERATION / TECHNIQUE
   ↓
PRIVILEGE ESCALATION
   ↓
LATERAL MOVEMENT / OBJECTIVE
```

The source concludes that after gathering network information and enumerating protections, we can make better decisions about which tools or **manual techniques** to use during subsequent enumeration and identify additional avenues of attack.

### 🔥 If you're preparing for CPTS, memorize this trio first:

```text
ipconfig /all  → "What interfaces/networks do I have?"
arp -a         → "Who has this host recently talked to?"
route print    → "What networks can this host reach?"
```

Then:

```text
Get-MpComputerStatus
        ↓
"What defenses are active?"

Get-AppLockerPolicy
        ↓
"What execution restrictions exist?"
```

That is the **situational-awareness mindset** you want before moving deeper into Windows privilege escalation.