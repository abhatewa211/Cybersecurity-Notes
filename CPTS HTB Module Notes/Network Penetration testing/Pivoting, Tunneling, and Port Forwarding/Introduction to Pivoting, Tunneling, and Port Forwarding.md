# 🌐 Module Overview

![Image](https://images.openai.com/static-rsc-4/KEzi3jtLotr77UuPwTRT243vObDe87YOqcI6QzgGX3AZUyKZrLuD6DBF2lpYqEDfZ6Dh2ehE4ajVOByS3W9MitPzpKW7gSPq9ny4MBoB9KWuyE7OxkrB-cxKNPNmbi7-zKtvm8hNuoo3sy-M9q80zdlbTCpZc26DV2uSPYK6HfwkWWmS1pMISR7WED6GgjYl?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/-jvaW8CVLDzFpb8cZp0Te_blTfaKls36-Z2VMi_WCcfRk57R5c7bu0XPHR1nlAwQRzqNkawajf5R2b7JFOHOEC3OLI17IC1TTxv_XAf8xRRLS-9ugJL5gpwYFJLiRMX0OuXQ-1qyrXojeudfIPBt5JA8zcQh7r5GRtZkqH5uy65DIfCTfP69f3mq-aLdP2x5?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/MdYlP7WZj6FjEcLwBuLZoMt0WiHwwc9pD6gaF6JPi8cEP_F1o-zFCiOaV6047BUKW2EJdpXiZzPa-TYSgc7oZ0J1w7OhdewdjZrZ_zUFCaj7n64POpbIpxvG6DqGr7WjGTkEXfJjKOeG9Mi8y7v0vYBX7KYYjcXni0cYaV2NLW-8G1WTSOEz9HVbsn1fvo-k?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/FKQjGYOFnsrBklsHxc_2Rlcia2z0dcvfV8SIi310qUPLHW-Cg9AUkle3CmjIsEa2QHms2IvFAO44M_7vTRH5Xlpp9YtNW7dQqDvyNhhkbHh2uWbfvbEnUXDajwvpNZ5wzHkHKRi9gZIu9dUJj-WW8MGmj44thp57v9y2OsGBVSmT0OuMwTfBsBCB-ARWm9aK?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/oidO1DzhSenj3kccheCZraZO0WKB6x4Qgo6hQMohBg9PARRlAzUrB-6bP5DZkV6ZMdDvVUYLBICSplOFnDaD2ff2eZhBXVctp80lLOkemyP1s1blWqS5XYqH9LZfdTZeEQBzwK-WqxNMWsM6lEMw13U33wQ-ApsXql6_pXzIb94F_W53YHp8W5KmBMMct8hB?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/wm3j0YSNE47GEDJdCUWNPh0gBVru9_NIwBfkDBI8wkDNFbQRbHhGsENbbKThZ9LiK9pL57wWRH5KmMt5s0ljasB6fGk9VlGJUIgQA1rfWAzMkXOj4yezbdry0uN6nb4wea-eJ7HJcBmEnWkQPo-uM1_11-dizFv0RwpxGNMPZrKGvuLx_Efdp1Uuwc8Ohm5Y?purpose=fullsize)

During a **Red Team Engagement**, **Penetration Test**, or **Active Directory Assessment**, it is common to compromise one machine but discover that the next target cannot be reached directly from your attack machine.

Instead of attacking the target directly, you use the already compromised machine as a **bridge** to reach deeper into the network.

This process is known as **Pivoting**.

---

# Scenario Example

```
                Internet
                    │
                    │
           ┌────────▼────────┐
           │  Kali Attacker  │
           └────────┬────────┘
                    │
          Compromises Host A
                    │
           ┌────────▼────────┐
           │ Windows Server  │
           │  (Pivot Host)   │
           └────────┬────────┘
                    │
         Internal Network (Hidden)
                    │
      ┌─────────────┴─────────────┐
      │                           │
┌─────▼─────┐              ┌──────▼─────┐
│ SQL Server│              │ Domain Ctrl│
└───────────┘              └────────────┘
```

Without compromising **Host A**, the internal servers are unreachable.

After compromising Host A:

- Scan Internal Network
    
- Access Internal Services
    
- Exploit More Hosts
    
- Escalate Privileges
    

---

# Why Pivoting is Needed

Suppose your Kali machine can only reach:

```
192.168.1.10
```

After compromising it, you discover another network:

```
10.10.20.0/24
```

Your Kali cannot reach it directly.

However,

```
Host A
```

has another network adapter connected to:

```
10.10.20.0/24
```

Now Host A becomes your bridge.

---

# First Things To Check After Compromising a Host

Always perform enumeration.

### Check Privileges

Linux

```bash
whoami
id
sudo -l
```

Windows

```powershell
whoami
whoami /priv
whoami /groups
```

---

### Check Network Interfaces

Linux

```bash
ip a
ifconfig
```

Windows

```cmd
ipconfig /all
```

---

### Check Routing Table

Linux

```bash
ip route
```

Windows

```cmd
route print
```

---

### Check Active Connections

Linux

```bash
ss -tunlp
netstat -tunlp
```

Windows

```cmd
netstat -ano
```

---

### Look For

✔ VPN Clients

✔ RDP Sessions

✔ SSH Keys

✔ Saved Passwords

✔ Kerberos Tickets

✔ Mounted Shares

✔ Additional Network Interfaces

✔ SOCKS Proxies

✔ Jump Servers

---

# Dual-Homed Hosts

A dual-homed host has **two or more network interfaces**.

Example

```
NIC 1
192.168.1.25

NIC 2
10.10.20.15
```

It can communicate with BOTH networks.

This makes it the perfect pivot host.

---

# Common Names for a Pivot Host

These all refer to nearly the same concept.

|Term|Meaning|
|---|---|
|Pivot Host|Main compromised system used for pivoting|
|Proxy|Forwards traffic|
|Foothold|Initial compromised machine|
|Beach Head|First successful compromise|
|Jump Host|Used to access other systems|

Remember:

> Different companies use different terminology.

---

# What is Pivoting?

## Definition

Pivoting is the technique of using a compromised system to access another network that was previously unreachable.

---

## Simple Diagram

```
Attacker

↓

Host A (Compromised)

↓

Internal Network

↓

Target Server
```

---

## Goal

Move deeper into the environment.

---

## Primary Use

Defeat:

- Physical Segmentation
    
- VLAN Segmentation
    
- Firewall Restrictions
    
- Internal ACLs
    

---

# Physical vs Virtual Segmentation

## Physical

Separate switches

Separate cables

Separate routers

Example

Corporate Network

↓

Router

↓

Engineering Network

---

## Virtual

Using VLANs

Example

```
VLAN10
Office PCs

VLAN20
Servers

VLAN30
Engineering
```

---

# What is Tunneling?

![Image](https://images.openai.com/static-rsc-4/uiKRKWZi4wFL4a-xjWGVCrcVaaiBijA9hfLS1ftRtB7mAZweA1h5LUZkk_aMbLulReh5TFYsxfOqJRDBvDzhC22KvF7S7aqXNCcId_U0j0Z0Fvig-ltEjouTQqnI_l_e-1JwgPjOhWVixcpvcDS82zxEeqK0TXqjA4DOYif-aVJ94pc8oQC3eqQXT98xC3AX?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/F7n4NGlLUQakOrrDJoD9VTo_I8ojznErJSYph3_sgJ--gCEewB2pVOrBmEtq1R0ZxKBQnhv6-gWlhAom_3cO48hdToOacTmvudRgWe7UTa96P9pNfYaTqEkkYj92OuwQ6ogzVVrPNdb3bwcNl1HvRugwCeG8-WeMuZ_yRlEttvlrJe8To1PrwpkhZDK6NMzJ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/XQ15bZts8W0J9puLfs0smi_9Q8kcnqrzxtknNS22NFwT__wJ9ljP51wgf8RyLYmFTCon1Ho6g5Lfy3wNUuodBRfdZ6skIbw4_sQr2VC3YYrMfmaLG55a6T-RESm0Vs21d1VxEAjy4bCigllgaeU_OGDfdHTf-hQEzgLdK5RxoGXY90yUpc0FXolahl3BVsWv?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/4igMREDS6Vptxn1rHGgrC0BWdX8PCM2uZbCs2ZJFriPYUqPr0ZQazXY_kRTzDJPkBGQFFWiJqt_MZS5GkTuc9tTARNCvEmyxwJ8In8uST7YeVH70I0iVvwyb6VvN9NXyy1K89zUehW1Rqd90BFRZONAPBFNjETTHTzs2s4__R6VgwSp90oXeENHZoIEO_jwz?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/LbD5nxxfa3BdYwFk2jDTVaPq9WaaBeN4Iix_3nsp2bWaK0sHetqEp0yKCaLd7WDty-D78zh3H30julqj6PP9BbfVAILC_mIgVFi0DfnyKzkf4_tDoLMSjnOzD6gnG1Y-cu7KRL-JEY-NgBlIqm5GXJf8Kwrep3J6_j0ZuzyWF05v5HH_nHdMDpdVumITxz4s?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/0UYZowQN7qVvfFzCEQ7ZEcVWdQ3YYOHbk9JUPq4GlV33ZIRwjuBHfjbRDwXf1S4wXuh6FC8UxVf119UD1WZ0jOeG7CPwriqPYPRPDBO5CZ0aNIH_r926srPFDzUiPU1WSlTowZcv2hazsc51nO5tna2y4Hp0LhsdojlLW-szi-SPacePzSsXJK2LctlpaKT6?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/0iqyCU-1ODOGOivSlhJkjgGWLcQ0jmccClF4vpii4O-C_Nev_11cyvEEfZBWrUZnR60xXxdo_60RJrhE0WQUgKaklh5a7g7NfT7ThllbTAkwp4lpVx0LITJbvS0fyEGIk8GPqWYAHe_4R4gAhXFaq6k8vz2AbQt3n18VL91HHcZkF62nl79kRTl0uvXaXUjI?purpose=fullsize)

Tunneling is a **subset of Pivoting**.

Instead of directly forwarding traffic,

you encapsulate it inside another protocol.

Think of it as putting one packet inside another.

---

## Official Definition

> Tunneling encapsulates network traffic into another protocol and routes traffic through it.

---

# Stuffed Animal Analogy (Very Important)

Imagine:

You need to send a key.

If someone opens your package,

they'll immediately know it is a key.

Instead,

You hide the key inside a teddy bear.

Now everyone sees

```
Toy
```

instead of

```
Key
```

Only the receiver knows:

- where the key is
    
- how to retrieve it
    

Networking works the same way.

Traffic gets hidden inside another protocol.

---

# Examples

SSH Tunnel

```
TCP Traffic

↓

SSH

↓

Internet
```

---

HTTPS Tunnel

```
Malware Traffic

↓

HTTPS

↓

Firewall

↓

C2 Server
```

---

VPN

```
Your Traffic

↓

Encrypted Tunnel

↓

Remote Network
```

VPNs are one of the most common examples of tunneling.

---

# What is Lateral Movement?

![Image](https://images.openai.com/static-rsc-4/4nauahgtfDH4tgRsq9GPsiKRrbkSylMvC3Q1lF0D4ddhlklRcsGIFSkhQZ1W9kIa0TNW_NJ1ZrrAm3dWCvHuP5Cg58gnkGn-GN6CPpgKDKyp42Jh8Q6blzIMVNAC-ocwYGFm4_dJS76yZ8TlWQ8d5dz8u0tiyGcpaB3qv_z2Q8ITbm9kztEz-CEVV5J-j7el?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/b9HADZQE9DNn-8oa4TfQj9sKRnvCbYwbrT8srtRqHGQosm6fcWdyR6cgWbaaD2jRfvU3LqPPQrMAZnP1wOy1-xvLePcGNUeMfs37DQvm_nexyPSACyqCzKgqVJTbHKPxoMrBOgU6HDHryZZgC9rQpmvy4PtT9J0GIYRjHKNn0zNDwyuu_VGR5QkScxI2wbND?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/eYC-H64D2LTONw7XIKbVX2nzIBBY-lNIp__MwMgbnqtQ2mCA4bDEw2-3A2tjLJC2KQ5Xj3S--8bIjGsLiXPXRr-i6FLkFMDXrkSLWEmr1ZGNJsbC9tENigbFvPj8W8ze1xufxyinoEPuj1OPU79Fc6RFd7kkDRFfmP9Htyfj6qjvkbsKu2fmo7rUBtHnj7jY?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/US98RsPhdDms1t3-9fLIglvTX5Hz3O-ei4UM-POPiTb1lJQsJfH6QbUoDrd1P1pEq2EwQjrj-14NDRphtGG7d1vWk5KjUcsvzF-ugahKj0-0j93Ix9M7xcdBAll-ODJ3qzqF_MJvFD7GkdT13vQk4qbMIdddwM5E7UimPzOVKdN4gbOZOsu0okdjVIZJJ8ZM?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/JvrdQmASorwVdfzaiOxxk-LV3BPpZ8IwW0AivEH4407hIccwRUdukEuTiNB5AJ594fbtgL7gkHgl17ArQCpFVyb86N9YH37bHYSg6Yjl4v6P4R1otAx55WBaU2TtPMq9-B9vZQlETVwdIS5xnH9DZAkW1tAlMyDotRvP6bXqEc9Id9WA5rE2bQTuGZmq0U2C?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/TFEk29DuuM9oKRxJWgLaTwqhEEv5tQnpUn7VKdO_m9EioIr0w0ofrCkJtDp2huKh3FCb9zdqFA7adz-UH4DtEs7u9-oUBjqMgSZ-QsEPEAQPB2F-ka1SYaso0AM3KKH279wLLN70hN_CI3E5U7nSnH3Lt1aU6W5kuANg-l-9NhDjdnkIJt_bBwNaM5XSi2JA?purpose=fullsize)

Lateral movement means moving **across** systems within the same environment to expand access and privileges.

Instead of going deeper into isolated networks, you spread to additional hosts.

---

## Goal

- Gain more hosts
    
- Gain more credentials
    
- Reach Domain Admin
    
- Access critical resources
    

---

## Example

You compromise

```
PC1
```

The local administrator password works on

```
PC2

PC3

PC4
```

Now you compromise all of them.

That is

**Lateral Movement**

---

# Example From HTB

Initial Access

↓

Compromise Local Administrator

↓

Scan Network

↓

Find 3 Windows Hosts

↓

Same Administrator Password

↓

Compromise More Hosts

↓

Move Closer to Domain Controller

---

# What is Pivoting?

Pivoting is different.

Instead of spreading,

you use one machine to reach another network.

Example

```
Internet

↓

Enterprise Network

↓

Engineering Workstation

↓

Operational Technology Network
```

Without the Engineering Workstation,

you cannot reach the OT Network.

---

# Example From HTB

Company has

- Enterprise Network
    

and

- Operational Network
    

Both are separated.

The Engineering Workstation connects to BOTH.

Once compromised,

you pivot into the Operational Network.

---

# What is Tunneling?

Goal:

Hide your traffic.

Common use:

Command & Control (C2)

---

Example

Instead of

```
Custom Malware Traffic
```

Use

```
HTTPS

or

HTTP
```

Now defenders think

```
Normal Web Browsing
```

is happening.

---

# HTB Example

Attacker

↓

HTTP GET Request

↓

Firewall

↓

Web Server

↓

C2 Server

Instructions hidden inside HTTP packets.

---

# Why Attackers Use Tunneling

✔ Evade Detection

✔ Bypass Firewalls

✔ Encrypt Traffic

✔ Exfiltrate Data

✔ Maintain Command & Control

✔ Deliver Payloads

---

# Command & Control (C2)

C2 Server

↓

Encrypted HTTPS

↓

Compromised Host

↓

Execute Commands

↓

Send Results Back

---

# Comparison Table

|Feature|Lateral Movement|Pivoting|Tunneling|
|---|---|---|---|
|Purpose|Spread across hosts|Reach new networks|Hide traffic|
|Direction|Horizontal|Vertical / Deeper|Through another protocol|
|Requires Compromised Host|Yes|Yes|Usually|
|Used For|Privilege Escalation|Access Isolated Networks|Evasion & Stealth|
|Example|Same admin password on many PCs|Dual-homed workstation|SSH/HTTPS tunnel|

---

# Quick Memory Trick

```
Lateral Movement

Spread WIDE
─────────────►
```

```
Pivoting

Go DEEP
      │
      │
      ▼
```

```
Tunneling

Hide Traffic

Traffic

↓

Encrypted Wrapper

↓

Destination
```

---

# Real Penetration Testing Flow

```
Recon

↓

Initial Access

↓

Foothold

↓

Enumeration

↓

Credential Dumping

↓

Lateral Movement

↓

Privilege Escalation

↓

Pivoting

↓

Tunneling

↓

Domain Admin

↓

Objectives Complete
```

---

# Important Exam Points ⭐⭐⭐

### Pivot Host Synonyms

- Pivot Host
    
- Proxy
    
- Foothold
    
- Beach Head System
    
- Jump Host
    

---

### Always Check After Compromising a Host

- Privileges
    
- Network Interfaces
    
- Routing Table
    
- Active Connections
    
- VPN Software
    
- SSH Keys
    
- Saved Credentials
    
- Multiple NICs
    

---

### Dual-Homed Host

- Two or more NICs
    
- Connected to multiple networks
    
- Ideal pivot point
    

---

### Lateral Movement

- Move **across** systems
    
- Reuse credentials
    
- Spread within the same network
    
- Helps privilege escalation
    

---

### Pivoting

- Move **deeper** into isolated networks
    
- Cross network boundaries
    
- Defeat segmentation
    

---

### Tunneling

- Encapsulate one protocol inside another
    
- Hide malicious traffic
    
- Used for stealth, C2, and data exfiltration
    

---

# One-Line Definitions (Must Remember)

- **Lateral Movement:** Moving **across** systems in the same network to expand access and privileges.
    
- **Pivoting:** Using a compromised host to reach **previously inaccessible networks**.
    
- **Tunneling:** Encapsulating traffic inside another protocol to **hide or securely transport** it.
    

---

# HTB Exam Summary

|Topic|Key Point|
|---|---|
|Pivoting|Use a compromised host to reach isolated networks|
|Lateral Movement|Spread to additional hosts within a reachable environment|
|Tunneling|Hide traffic by encapsulating it in another protocol (e.g., SSH, HTTPS, VPN)|
|Dual-Homed Host|Host with multiple NICs connected to different networks; ideal for pivoting|
|Enumeration Priorities|Check privileges, interfaces, routes, active connections, VPNs, and credentials|
|Main Objective|Progress deeper into the target environment while maintaining access and minimizing detection|