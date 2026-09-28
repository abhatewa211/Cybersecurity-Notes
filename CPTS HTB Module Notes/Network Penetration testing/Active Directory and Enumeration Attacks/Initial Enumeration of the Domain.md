## 1. Module Context

We are at the beginning of an **AD-focused penetration test against Inlanefreight**.

At this point, we have:

- Basic information gathered previously.
    
- An understanding of the customer's scope.
    
- An attack host placed **inside the internal network**.
    
- No detailed internal network map.
    
- No domain credentials initially.
    
- A defined internal network range: `172.16.5.0/23`.
    

The purpose of this stage is to understand the internal environment before moving deeper into the assessment.

---

# 2. Setting Up

There are several ways a client may provide access for an internal penetration test.

### Common testing setups

The module lists:

1. A penetration-testing Linux VM inside the client's infrastructure that calls back to a jump host over VPN.
    
2. A physical device connected to an Ethernet port.
    
3. Physical presence in the client's office with a laptop connected to Ethernet.
    
4. A Linux VM in Azure/AWS with internal-network access.
    
5. VPN access to the internal network.
    
6. A corporate laptop connected to the client's VPN.
    
7. A managed Windows workstation.
    
8. A VDI accessed through technologies such as Citrix.
    

### Visual model

![Image](https://images.openai.com/static-rsc-4/9sKk5ny3Y4_iIPfbq3Vy-rjhASwtUdgVvemrevKzGZbKqDuFzEZz-ad6Jf8Y7CyDEFWI7d07GCfrlf3JsOj4ZJzrOoWLF_pWVhm30DXWUfTHGRm7V1WZ5G6u9RUdyXWU9CqPMZpGg-36mziTd3fmkkGbG1iPzA49czn2XLt2acGkRDIZ0cmN5NtEwXIvw_ci?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/jYhVAIqzri0BYIwkXrkUpSDMerJNFDjhn9nd8yJmFLRWipnbDLNED3wO-E-WDKQ6Z1dlbxmsOd6i0QXE0O0wZpzeIKw5fYMV9lEGT4lHfs9PUsoAd6sVT1lTVLGWTpngga25PPKF0Cm_rWEKQRZe4M-IAcJ0AEroy5Zfy2d2y4np77tAPu9wEeE2bq8iHfl0?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/FB8eirkZxNUd3RJTUU4qu-_Fp5Wn5vAZdE7610QoPXO1gTWpXsysxtHavx3ojI6CXHXV8v84ZnSW_Ignf_tEjoDLWJ6hBmyOZBDMMbxHKFPZgF6IfyfNRi3XkBJ65T-77TfSS_KuhMdfYPUwjGIJsODgIBYQMwTYsrIwt_NrWUQwcMyGVns4UIL4A5lhUSTi?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/huHUDieYEc_cuX10tYtYmVY6NKatgCrMwYQO_pmdkKG3f37OkOsrmqvVZsiJlvdUl7iuOu3OHZ-ZXpaG_7vQt6DDFasv3LeD7r8lZysy_vUFnWODD7YQ2KAYknsHJ0Le6ELv_4-2opZg_ONlHSZ5Oj2zu-nvtIzwAsszJ9aQC7HZ5TvtpYFSA2ORj2u-zhia?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/RvrmU8JUMF6WHlOf2QceBpUDhWienM2XbfW7lslCMlk6blc0lcjZdHETlnV8-8NOErF2RitYc9X45r__WdbZy4GStoKHUpgB-Hfitoj3H3P5feE74IL4TfYdbQLqzDRwl_EPhXEhM3pcmpS8_-KUvsjVFeXwhOnieXnCNGoXaHMe18gz8au69Bhy6UOyDWqI?purpose=fullsize)

```text
                 CLIENT INTERNAL NETWORK
                         │
        ┌────────────────┼────────────────┐
        │                │                │
      Linux VM       Windows Host        VDI
        │
        ▼
   Jump Host / VPN
        │
        ▼
   Pentester
```

---

# 3. Grey Box vs Black Box

The client can choose different testing approaches.

### Grey Box

The tester receives limited information.

For example:

```text
172.16.5.0/23
```

but does not receive a detailed network map.

### Black Box

The tester has to perform discovery essentially blindly.

The module also discusses:

- **Evasive testing**
    
- **Non-evasive testing**
    
- **Hybrid evasive testing**
    

Hybrid evasive testing starts quietly and gradually increases activity to determine the detection threshold.

### Inlanefreight's chosen setup

Inlanefreight selected:

- Custom pentest VM inside the network
    
- Windows host available for tools
    
- Start from an unauthenticated standpoint
    
- Standard domain user: `htb-student` for the Windows attack host
    
- **Grey box**
    
- Network range: `172.16.5.0/23`
    
- **Non-evasive testing**
    

They did **not** provide:

- Detailed internal network map
    
- Credentials for the initial phase
    

---

# 4. Tasks

The tasks for this section are:

### 1. Enumerate the internal network

Identify:

- Hosts
    
- Critical services
    
- Potential foothold opportunities
    

### 2. Use active and passive techniques

Identify:

- Users
    
- Hosts
    
- Vulnerabilities
    

### 3. Document findings

The module explicitly emphasizes:

> **"Document any findings we come across for later use. Extremely important!"**

### Important pentesting habit

Don't rely on memory.

Create notes containing:

```text
IP
Hostname
OS
Open Ports
Services
Versions
Users
Potential Vulnerabilities
Credentials
Interesting Findings
Next Steps
```

---

# 5. Why Start Without Credentials?

Starting from an unauthenticated position can provide a realistic view of what an attacker might accomplish after gaining initial access.

Possible real-world starting points include:

- Internet-based compromise
    
- Phishing
    
- Physical access
    
- Wireless access
    
- Rogue employee
    

Depending on how successful this phase is, the client may later provide:

- A domain-joined host
    
- Credentials
    
- Additional information
    

### Attack progression

```text
Unauthenticated Position
          │
          ▼
Passive Enumeration
          │
          ▼
Active Enumeration
          │
          ▼
Find Vulnerability / User
          │
          ▼
Initial Foothold
          │
          ▼
Credentialed Enumeration
          │
          ▼
Further Access
```

---

# 6. Key Data Points

These are **very important** for this module.

|Data Point|Purpose|
|---|---|
|**AD Users**|Find valid accounts that may be targeted for password spraying|
|**AD Joined Computers**|Identify Domain Controllers, file servers, SQL servers, web servers, Exchange servers, database servers, etc.|
|**Key Services**|Kerberos, NetBIOS, LDAP, DNS|
|**Vulnerable Hosts and Services**|Identify potential quick wins / easy footholds|

### Memorize:

```text
AD USERS
    ↓
AD COMPUTERS
    ↓
KEY SERVICES
    ↓
VULNERABLE HOSTS
    ↓
FOOTHOLD
```

---

# 7. TTPs — Tactical Enumeration Methodology

AD enumeration can become overwhelming because AD contains a huge amount of information.

Therefore, don't try to enumerate everything randomly.

The module recommends developing a:

> **repeatable methodology**

### Recommended methodology

The module begins with:

> **`passive` identification**

Then:

> **`active` validation**

Then:

> Probe interesting hosts.

Then:

> Regroup and analyze the information.

### The workflow

```text
PASSIVE
   │
   ▼
Identify Hosts
   │
   ▼
ACTIVE
   │
   ▼
Validate Hosts
   │
   ▼
Enumerate Services
   │
   ▼
Identify Interesting Targets
   │
   ▼
Probe Targets
   │
   ▼
Regroup / Analyze
   │
   ▼
Credentials / Foothold
```

This is one of the most important concepts of the module.

---

# 8. Identifying Hosts

The first technique is to:

> **"put our ear to the wire"**

The module uses:

- **Wireshark**
    
- **TCPDump**
    

to observe network traffic.

This is especially useful in a **black-box** situation.

The traffic can reveal:

- Hosts
    
- IP addresses
    
- Hostnames
    
- Network protocols
    
- Broadcast traffic
    
- Multicast traffic
    

---

# 9. ARP

**ARP — Address Resolution Protocol**

ARP is used to associate IP addresses with MAC addresses on a local network.

During passive network monitoring, ARP traffic can reveal active hosts.

The module's Wireshark capture identifies:

```text
172.16.5.5
172.16.5.25
172.16.5.50
172.16.5.100
172.16.5.125
```

### Visual

![Image](https://images.openai.com/static-rsc-4/Axqb30geQDjIKv-jLNr-BA_7wQHstd6PXfW1f0hopLfuokwuMge7iANRFbKjp-7LSdvHWuh6knBi4POxhPRels0jxk80EiwYuRT7g0fS7WbnqrRfEtiRlrFgif4jhTZatRjfW0j-dSqcyWcrMVMgKg7essBndKYoyGAqUmIXEjy76XH8jIZeSudB-x1Pf_pz?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/tBqsKytDyN0siQoWsVyUYdRWPc4jMWMo7I9oAuEKosYPLXKARAyEtfAbIWd-N0-uueG-M4Aa9ySy5wpg40t78l6Kv_tguiCBrSRuYr8zRbxrmZNwIJx3-QySwWFKkjJabYZ4biQuV2zz2MNRhIAoSA4AwxjQRQi3Ue11Yfap0cWn6MTv26FA3n-NoS76FBPW?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/pTAnvIPTlWS5ncUvg7CSzvHIWV9RPX6JUoXggqJUFmdAU0tSmY_ydBNJ2pCNP4O4XtQWVRPTeNH8Oq4UB3i7VM3gdlVJA86sjXqtbacyO4jxBbFeaBWV66m-idtOJ2yRGBi760RvJds4u6MZa207hDJiloqxZh_njHHo9rZ8lq8bc-KpDgO6IZamsHrQMwY8?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/9kMxiBRvjuZsHy4OVd9bNgeNTOHcNmUp1yCMt6zUyWASWKMjMgPgByj3MXi_bos-xQRGiTvYbELP9NpoNVJY1yHgb1V-U6gDGOPMVIQ2K7O_spsoKs4GFyNKVm3y99QTmnJ3-n3bDpOZyt_wQ9jeJi37U3rIu8dq7GbhXFRaVje6m6e2mUNe6vKrWYFlNE3h?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/4bBtNkh0dTcG2YzPrm3QuNclY-HUO0D4eXAYY5iEED8EjPFeTvTYvaSwmblRfcxdNIG5aODqdQK9wB1MZAxxnYNp5ObFBiNHPIyB_bz5IYKirHQ7R_EOkfZJ00k83VWEZ8Lhox1Ir5fGfouu73T2R2aYt2VOTUvrmsRgLuND9TSbFr6sU_Q589cG1VxxeMRo?purpose=fullsize)

```text
Host A
  │
  │ ARP Request:
  │ "Who has 172.16.5.x?"
  ▼
Broadcast
  │
  ▼
Host B
  │
  │ ARP Reply:
  │ "172.16.5.x = MAC address"
  ▼
Host A
```

---

# 10. MDNS

**mDNS = Multicast DNS**

The module's Wireshark capture shows mDNS traffic identifying:

```text
ACADEMY-EA-WEB01
```

mDNS can therefore reveal useful hostname information without requiring traditional active scanning.

### Important distinction

```text
ARP
 ↓
Can reveal IP/MAC relationships

mDNS
 ↓
Can reveal hostname information
```

---

# 11. Wireshark

The module starts Wireshark with:

```bash
sudo -E wireshark
```

### What we're looking for

When capturing traffic, look for:

- ARP
    
- mDNS
    
- Other Layer 2 traffic
    
- Hostnames
    
- IP addresses
    
- Interesting protocols
    

The module notes that because we're on a switched network, visibility is generally limited to the current **broadcast domain**.

---

# 12. TCPDump

If the host doesn't have a GUI, use:

- `tcpdump`
    
- `net-creds`
    
- `NetMiner`
    

The module also explains that `tcpdump` can save traffic to a `.pcap` file, which can then be transferred and opened in Wireshark.

### Command

```bash
sudo tcpdump -i ens224
```

### Useful workflow

```text
tcpdump
   ↓
Capture traffic
   ↓
Save PCAP
   ↓
Transfer PCAP
   ↓
Open in Wireshark
   ↓
Analyze
```

---

# 13. Save Your PCAPs

The module specifically recommends saving captured traffic.

Why?

Because you can:

- Review it later.
    
- Search for additional clues.
    
- Use it while writing the report.
    
- Re-analyze traffic after discovering something new.
    

### Pentester rule

> **If the data may be useful later, save it.**

---

# 14. Responder — Passive Analysis

The module next introduces:

**Responder**

Responder can listen to, analyze, and poison:

- LLMNR
    
- NBT-NS
    
- mDNS
    

requests and responses.

However, **in this section**, Responder is being used in **Analyze mode**, meaning it passively listens and does **not** send poisoned packets.

### Command

```bash
sudo responder -I ens224 -A
```

### Why use it here?

It can identify additional:

- IP addresses
    
- Hostnames
    
- Network activity
    

The module says these newly discovered systems should be added to our target list.

---

# 15. Passive → Active Enumeration

At this point we have used:

```text
Wireshark
   +
TCPDump
   +
Responder
```

to passively discover hosts.

Now we transition to:

> **active checks**

The first active technique is an:

> **ICMP sweep**

using `fping`.

---

# 16. FPing

**fping** is similar to standard `ping`, but it is particularly useful for testing multiple hosts.

The module highlights that fping:

- Sends ICMP packets.
    
- Can query multiple hosts.
    
- Is scriptable.
    
- Works in a round-robin fashion.
    
- Can quickly identify active systems.
    

### Command

```bash
fping -asgq 172.16.5.0/23
```

---

# 17. Understanding `fping -asgq`

This is important.

```text
-a
```

Show targets that are alive.

```text
-s
```

Print statistics at the end.

```text
-g
```

Generate the target list from the CIDR network.

```text
-q
```

Quiet mode — don't display per-target results.

### Memory trick

```text
-a = alive
-s = stats
-g = generate
-q = quiet
```

---

# 18. FPing Results

The module's example identifies:

```text
172.16.5.5
172.16.5.25
172.16.5.50
172.16.5.100
172.16.5.125
172.16.5.200
172.16.5.225
172.16.5.238
172.16.5.240
```

It reports:

```text
510 targets
9 alive
501 unreachable
```

### Important

These exact results may differ in your lab because the lab network can change.

The important thing is to understand the methodology and record the hosts that are actually live in your environment.

---

# 19. Nmap Scanning

Once we have a list of live hosts, we can enumerate them further.

The objectives include identifying:

- Services
    
- Domain Controllers
    
- Web servers
    
- Potentially vulnerable systems
    
- AD-related services
    

For AD environments, pay particular attention to:

```text
DNS
SMB
LDAP
Kerberos
```

---

# 20. Nmap Command

The module gives:

```bash
sudo nmap -v -A -iL hosts.txt -oN /home/htb-student/Documents/host-enum
```

### Breakdown

```text
-v
│
└── Verbose output

-A
│
└── Aggressive scan options

-iL hosts.txt
│
└── Read targets from a file

-oN
│
└── Normal output to a file
```

The `-A` option performs several enumeration functions, including quick enumeration of well-known ports and services.

---

# 21. Identifying a Domain Controller

The module's scan of:

```text
172.16.5.5
```

reveals a large number of AD-related services.

Important ports include:

|Port|Service|
|--:|---|
|`53`|DNS|
|`88`|Kerberos|
|`135`|MSRPC|
|`139`|NetBIOS|
|`389`|LDAP|
|`445`|SMB|
|`464`|Kerberos password|
|`636`|LDAPS|
|`3268`|Global Catalog LDAP|
|`3269`|Global Catalog LDAPS|
|`3389`|RDP|

### Strong DC indicators

```text
53    DNS
88    Kerberos
389   LDAP
445   SMB
636   LDAPS
3268  Global Catalog
3269  Global Catalog SSL
```

When several of these appear together, you should strongly investigate whether the host is a **Domain Controller**.

---

# 22. Extracting Domain Information From Nmap

The scan reveals:

```text
NetBIOS Domain Name:
INLANEFREIGHT
```

```text
DNS Domain Name:
INLANEFREIGHT.LOCAL
```

```text
DNS Computer Name:
ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```

```text
NetBIOS Computer Name:
ACADEMY-EA-DC01
```

This is extremely valuable because we now know:

```text
Domain:
INLANEFREIGHT.LOCAL

Domain Controller:
ACADEMY-EA-DC01

IP:
172.16.5.5
```

---

# 23. Discovering Legacy Systems

The module also demonstrates scanning:

```text
172.16.5.100
```

The results show:

```text
Microsoft IIS 7.5
Windows Server 2008 R2
Microsoft SQL Server 2008 R2
```

and other services.

This is interesting because the host appears to be running an **older operating system and software stack**.

---

# 24. Why Legacy Systems Matter

Legacy operating systems may expose opportunities through old vulnerabilities.

The module specifically mentions examples such as:

- **EternalBlue**
    
- **MS08-067**
    
- Other older exploits
    

These could potentially result in:

> **SYSTEM level shell**

### But DON'T immediately exploit it.

The module gives an important professional warning.

Legacy systems may support:

- Production lines
    
- HVAC systems
    
- Industrial equipment
    
- Other business-critical processes
    

Taking these systems offline can cause significant operational impact.

Therefore:

> **Before exploiting legacy systems, alert the client and get approval in writing.**

The client may instead want the tester to:

```text
Observe
 ↓
Document
 ↓
Report
 ↓
Do not exploit
```

---

# 25. Nmap Output Documentation

The module recommends:

> **Use the `-oA` flag as a best practice when performing Nmap scans.**

This saves results in several formats that can be:

- Logged
    
- Reviewed later
    
- Manipulated
    
- Fed into other tools
    

### Example

```bash
nmap -A -oA scan_results 172.16.5.100
```

---

# 26. Scan Carefully

This is a **very important professional lesson**.

Some Nmap scripts perform active vulnerability checks.

These can potentially:

- Cause instability.
    
- Take systems offline.
    
- Affect customer operations.
    
- Overload sensitive devices.
    

The module specifically warns about environments containing:

- Sensors
    
- Logic controllers
    
- Industrial equipment
    

### Remember

> **Understand the scan before running it against a client's environment.**

Don't blindly run every NSE script just because Nmap provides it.

---

# 27. Current Goal: Find a Domain User

After host/service enumeration, we need to progress toward obtaining:

- A domain user account, **or**
    
- `SYSTEM` access on a domain-joined host.
    

This gives us a foothold from which deeper AD enumeration can begin.

---

# 28. Identifying Users

If the client doesn't provide a user, we need another way to obtain one.

Possible footholds include:

- Cleartext credentials
    
- NTLM password hash
    
- `SYSTEM` shell on a domain-joined host
    
- Shell in the context of a domain user
    

A valid domain user is extremely valuable even if the account has low privileges.

---

# 29. Kerbrute

## Internal AD Username Enumeration

**Kerbrute** is introduced as a stealthier option for domain account enumeration.

It takes advantage of the behavior of:

> **Kerberos pre-authentication**

The module explains that Kerberos pre-authentication failures often won't trigger logs or alerts in the same way as traditional authentication attempts.

### Wordlists

The module uses:

```text
jsmith.txt
jsmith2.txt
```

from:

**Insidetrust/statistically-likely-usernames**

These lists are useful when attempting to enumerate users from an unauthenticated perspective.

---

# 30. Kerbrute Installation

The module recommends either:

- Downloading precompiled binaries
    
- Compiling Kerbrute yourself
    

It states that compiling your own tools is generally the best practice when introducing tools into a client environment.

### Clone the repository

```bash
sudo git clone https://github.com/ropnop/kerbrute.git
```

---

# 31. Kerbrute Build Options

Run:

```bash
make help
```

The available options include:

```text
help
windows
linux
mac
clean
all
```

### `make all`

Compiles binaries for:

- Windows x86
    
- Windows x64
    
- Linux x86
    
- Linux x64
    
- Mac x86/x64
    

The resulting binaries are placed in:

```text
dist/
```

---

# 32. Compiled Kerbrute Binaries

Example:

```bash
ls dist/
```

Output:

```text
kerbrute_darwin_amd64
kerbrute_linux_386
kerbrute_linux_amd64
kerbrute_windows_386.exe
kerbrute_windows_amd64.exe
```

For the supplied Parrot Linux attack host, the module uses:

```text
kerbrute_linux_amd64
```

---

# 33. Important Kerbrute Warning

When executing Kerbrute, the module explicitly displays:

> **Warning: failed Kerberos Pre-Auth counts as a failed login and WILL lock out accounts**

### 🚨 Memorize this

Kerbrute is not something to run carelessly.

Before using authentication-related enumeration techniques in a real engagement:

```text
Check scope
     ↓
Understand lockout policy
     ↓
Understand engagement rules
     ↓
Choose appropriate technique
     ↓
Monitor results
```

---

# 34. Add Kerbrute to PATH

Check the current PATH:

```bash
echo $PATH
```

Then move the binary:

```bash
sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
```

Now `kerbrute` can be called from any directory.

---

# 35. Enumerating Users With Kerbrute

The module uses:

```bash
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users
```

### Breakdown

```text
kerbrute
    │
    ├── userenum
    │      └── Enumerate users
    │
    ├── -d
    │      └── Domain
    │
    ├── INLANEFREIGHT.LOCAL
    │
    ├── --dc
    │      └── Domain Controller
    │
    ├── 172.16.5.5
    │
    ├── jsmith.txt
    │      └── Username wordlist
    │
    └── -o
           └── Output file
```

---

# 36. Kerbrute Results

The example finds valid users such as:

```text
jjones
sbrown
tjohnson
evalentin
sgage
jshay
jhermann
whouse
emercer
wshepherd
```

The final result:

```text
Tested 48705 usernames
56 valid
```

in approximately:

```text
9.940 seconds
```

The module then explains that these validated usernames can be used to build a list for **targeted password spraying attacks** later.

---

# 37. `SYSTEM` Account

The module next discusses:

```text
NT AUTHORITY\SYSTEM
```

This is a built-in Windows account with the highest level of access to the operating system.

It is commonly used by:

- Windows services
    
- Third-party services
    

### Important concept

A `SYSTEM` account on a **domain-joined host** can enumerate Active Directory by impersonating the computer account.

Therefore:

> Having SYSTEM-level access within a domain environment is nearly equivalent to having a domain user account.

---

# 38. Ways to Gain SYSTEM

The module lists several possibilities:

### Remote Windows exploits

Examples:

- MS08-067
    
- EternalBlue
    
- BlueKeep
    

### Service abuse

Abusing services running as `SYSTEM`, including service-account `SeImpersonate` privileges with tools such as **Juicy Potato**.

### Local privilege escalation

For example, Windows local privilege escalation flaws.

### Local administrator → SYSTEM

If you gain administrator access on a domain-joined host, **PsExec** can be used to launch a SYSTEM command shell.

---

# 39. What Can SYSTEM Access Give Us?

With SYSTEM-level access on a domain-joined host, the module lists capabilities including:

### AD enumeration

Using:

- Built-in tools
    
- BloodHound
    
- PowerView
    

### Kerberos attacks

- Kerberoasting
    
- ASREPRoasting
    

### Credential/hash collection

Using tools such as:

- Inveigh
    

### SMB relay

Potentially performing SMB relay attacks.

### Token impersonation

Hijacking a privileged domain user's token.

### ACL attacks

Abusing Active Directory access-control relationships.

---

# 40. A Word of Caution

The testing methodology determines which tools and techniques are appropriate.

For a:

### Non-evasive penetration test

The customer knows the test is happening, so the amount of generated noise may be less important.

For:

### Evasive / Red Team assessment

The goal is to emulate an attacker.

Therefore:

> **Stealth is of concern.**

The module specifically warns:

> **"Throwing Nmap at an entire network is not exactly quiet"**

and notes that many common pentesting tools can trigger SOC/Blue Team alerts.

### Key principle

```text
Assessment Type
      │
      ├── Non-Evasive
      │       ↓
      │    More noise acceptable
      │
      └── Evasive / Red Team
              ↓
           Stealth matters
```

Always clarify the assessment goal with the client **in writing** before beginning.

---

# 41. Final Section — Let's Find a User

The next sections move toward obtaining a domain user account.

The module specifically says upcoming techniques include:

- **LLMNR/NBT-NS Poisoning**
    
- **Password spraying**
    

These techniques can provide a foothold but must be used carefully and with an understanding of their potential impact.

---

# 🧠 MASTER MIND MAP

![Image](https://images.openai.com/static-rsc-4/lbrS108BgPyusvbzhIgJwv4_a9SxUYy_Za_y1--dSc1FAwkHIQ3o6MNTNI_c2JDO9x0cXLst7y5_jV6381aU8ebUu64EImO1Ggh03nO98qW8Pkq1-q8v3G3N4nXEn0DuLns4ymTt4eIkni19zCtBp1hyfCdCSQp-eca7c0sLRQBB77f_7Pg_hC6Uq1qtKuhP?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/_zxx9NYv1wv9XHND7PwmHm0PvJs8xZrng4q7h_aHqqAAMpqNlmma-rlsPgJ5Ia3_Qa-eYDuDqDYZypUoJqTLWokucJ4QcT9PwE9mIdu4XKnEAC27k2iaO7kRkQoEGV4CNHKXlYUzM4q4Xnsmkq2SdQA-hbiZVXgwitfdeQT4YRC7l2hYxSFmRts1Rqft68vI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/h64QJRdXEgcGyL5pVwBV0w0PTfABU01B5l9XEUo8nfLpCDM16XWBvZxbBTp9edckdRPOdZ_aQ6P84IFPwcn4J9xxVDFTaVzMpjmV-QzFSqWoLXcq16U8WOkV2HS_lBKo5c1UhPpZb8IBpP8c2e3-CJEc01EUnBGJMAiYmXlZM2ZheaVyAKrHjYqOu-LyjMrF?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/1SuWoTDOmuNvQ1O3Rh_VmXxc9gPauU2d1qBmJY-_8wFvUcjr2yI_SlTmsvCEO63v88-BA3h0IPl1Qa989HAVpMcSbMSksSEzkS3oDoV138PyLS5eq2WHgbnPeyG4h67VpjohtoV8Qfpbv0WTr1dvT-VRqyznwNBsF8MfWupnfqGrhuHXvNt6cuyEkBTReqpI?purpose=fullsize)

```text
              INITIAL ENUMERATION
                       │
                       ▼
                DEFINE SETUP
                       │
                       ▼
               PASSIVE DISCOVERY
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
       Wireshark     TCPDump     Responder
          │            │            │
          └────────────┼────────────┘
                       ▼
                  HOST LIST
                       │
                       ▼
                ACTIVE DISCOVERY
                       │
                       ▼
                     fping
                       │
                       ▼
                 LIVE HOSTS
                       │
                       ▼
                    Nmap
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
        DNS          SMB/LDAP     Kerberos
          │            │            │
          └────────────┼────────────┘
                       ▼
                DOMAIN INFORMATION
                       │
                       ▼
                  USER ENUMERATION
                       │
                       ▼
                   Kerbrute
                       │
                       ▼
                VALID USER LIST
                       │
                       ▼
             TARGETED PASSWORD TESTING
                       │
                       ▼
                    FOOTHOLD
                       │
                       ▼
              CREDENTIAL ENUMERATION
```

---

# 🔥 Commands From This Module

Keep these in your notes **exactly**:

### Wireshark

```bash
sudo -E wireshark
```

### TCPDump

```bash
sudo tcpdump -i ens224
```

### Responder — Analyze Mode

```bash
sudo responder -I ens224 -A
```

### FPing

```bash
fping -asgq 172.16.5.0/23
```

### Nmap

```bash
sudo nmap -v -A -iL hosts.txt -oN /home/htb-student/Documents/host-enum
```

### Nmap — save multiple formats

```bash
nmap -A -oA scan_results <target>
```

### Clone Kerbrute

```bash
sudo git clone https://github.com/ropnop/kerbrute.git
```

### Build options

```bash
make help
```

### Build all

```bash
sudo make all
```

### Move Kerbrute into PATH

```bash
sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
```

### Kerbrute user enumeration

```bash
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users
```

---

# 🎯 Things You MUST Know Before the Exercises

|Concept|Remember|
|---|---|
|**Grey Box**|Limited information provided|
|**Black Box**|Discovery performed with little/no prior knowledge|
|**Passive Enumeration**|Observe without directly interacting with targets|
|**Active Enumeration**|Directly interact with hosts/services|
|**ARP**|Helps identify local IP/MAC relationships|
|**mDNS**|Can reveal hostnames|
|**Wireshark**|GUI packet analysis|
|**TCPDump**|CLI packet capture|
|**Responder Analyze Mode**|Passive network analysis|
|**fping**|Fast ICMP discovery across multiple hosts|
|**Nmap**|Service/port/OS enumeration|
|**Kerbrute**|AD username enumeration through Kerberos|
|**SYSTEM**|Highest Windows OS-level account|
|**Domain Controller**|Critical AD infrastructure|
|**Kerberos**|AD authentication protocol|
|**LDAP**|Directory access protocol|
|**SMB**|Windows file/network sharing protocol|
|**DCS / DC identification**|Important target during AD enumeration|
|**Legacy OS**|Potentially vulnerable, but exploit only with authorization|
|**`-oA`**|Save Nmap output in multiple formats|
|**Documentation**|Preserve findings and tool output|

---

# 🧠 Cybersecurity Mentor Mental Model

For this module, don't memorize commands alone.

Think like this:

```text
                    "What exists?"
                          │
                          ▼
                    Passive Recon
                          │
             ┌────────────┼────────────┐
             ▼            ▼            ▼
          Wireshark     TCPDump     Responder
             │            │            │
             └────────────┼────────────┘
                          ▼
                    "What is alive?"
                          │
                          ▼
                        fping
                          │
                          ▼
                    "What's running?"
                          │
                          ▼
                        Nmap
                          │
                          ▼
                "Who are the users?"
                          │
                          ▼
                       Kerbrute
                          │
                          ▼
                "Can I obtain access?"
                          │
                          ▼
                    Foothold
                          │
                          ▼
               "What can I enumerate
                  with this access?"
                          │
                          ▼
                   ENUMERATE AGAIN
```

### The most important lesson

**Enumeration is iterative.**

You don't do:

```text
Scan → Find one thing → Attack
```

You do:

```text
Discover
   ↓
Validate
   ↓
Enumerate
   ↓
Analyze
   ↓
Find new information
   ↓
Enumerate again
```

That mindset is what I want you to develop before we start the exercises.

**This note set is based only on the exact `Initial Enumeration of the Domain` module you provided.**