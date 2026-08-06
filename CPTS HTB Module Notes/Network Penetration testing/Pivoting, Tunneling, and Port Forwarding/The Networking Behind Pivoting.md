# 🌐 The Networking Behind Pivoting

![Image](https://images.openai.com/static-rsc-4/He0FoLTu6k9Oj4qLTs5npZ46zf68FkYOjhqhmQWaeJn610dpdf1PdqPDuf_xWJwpqPBuyjP8FBKPKsSkz-TKLduw3Z9YnKQTictiwuUI06ANkvy7lP5Isny3bJ7Fe-XKiiab1Ha_Lsyi5RrvNmCUfj103R25Zapg48C2bUBxsX7Q4r7xM6unb2uVUhPToEAR?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/jBKDMS2-wcz4iculsgJq804x2IKwTGQhGnTiecbeGQW3xQBLtoEtJJA0j27hZaO-bLd8CZzuAYLsS5jNHlAUT3o_lr2_QQ-Jcl-5YYJHVT0f0w5_EaCFdfVQLXSpriMbGVCHix93d0aQSVhL23LUlALytFIhwSbe6j-yspSphNkg6H6RPqg7w-yVPmq69UkY?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/0UYZowQN7qVvfFzCEQ7ZEcVWdQ3YYOHbk9JUPq4GlV33ZIRwjuBHfjbRDwXf1S4wXuh6FC8UxVf119UD1WZ0jOeG7CPwriqPYPRPDBO5CZ0aNIH_r926srPFDzUiPU1WSlTowZcv2hazsc51nO5tna2y4Hp0LhsdojlLW-szi-SPacePzSsXJK2LctlpaKT6?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/tD_V2tQuui4QS3AbuPFwz4hnA50dlGMhql1rXoflWMIwsxoAJC4JR_2gkYaxSqdIwiRfmndT_y2HHpQgtpdLEvjumjdU6w5pQmWaeamEOSHxxV23sXLRSXCbZq51KiINwHqkbf5-baaIsC9uCVQwQa-v_ZjM5ibngRngMHLXltjbm6xpKivt1VaqsPVEv2vV?purpose=fullsize)

---

# 📖 Introduction

To become good at **Pivoting**, you first need a strong understanding of networking fundamentals.

Pivoting is impossible without understanding:

- IP Addressing
    
- Network Interface Cards (NICs)
    
- Routing
    
- Routing Tables
    
- Gateways
    
- Protocols
    
- Ports
    
- VPN Interfaces
    

These networking concepts determine **where a compromised machine can communicate** and **which additional networks you can reach** after gaining access.

---

# 1️⃣ IP Addressing & NICs

## What is an IP Address?

Every device communicating on a network **must have an IP address**.

Without an IP address:

❌ The device cannot communicate on the network.

An IP address is usually assigned by:

- DHCP (Automatic)
    
- Static Assignment (Manual)
    

---

## Devices That Usually Have Static IP Addresses

According to HTB:

- Servers
    
- Routers
    
- Switch Virtual Interfaces (SVIs)
    
- Printers
    
- Critical Network Devices
    

These devices rarely change addresses because other systems depend on them.

---

# What is a NIC?

NIC = **Network Interface Controller**

Also called:

- Network Interface Card
    
- Network Adapter
    

A NIC allows a computer to communicate on a network.

---

## One Computer Can Have Multiple NICs

Example

```text
Windows Workstation

NIC 1 → 192.168.1.25

NIC 2 → 10.10.20.15

VPN Adapter → 10.10.15.20
```

This means the machine belongs to **three different networks**.

This is exactly what creates pivoting opportunities.

---

# Why Multiple NICs Matter

Suppose you compromise this machine.

Your Kali only reaches:

```text
192.168.1.0/24
```

But this machine also reaches

```text
10.10.20.0/24
```

Now you can pivot into:

```text
10.10.20.0/24
```

This is why HTB says:

> Always check for additional NICs.

---

# Commands to View Network Interfaces

## Linux

```bash
ifconfig
```

or

```bash
ip addr
```

---

## Windows

```cmd
ipconfig
```

These commands reveal:

- Network Interfaces
    
- IP Addresses
    
- Subnet Masks
    
- IPv6 Addresses
    
- Interface Status
    

They help identify networks the compromised host can access.

---

# Understanding the HTB ifconfig Output

HTB shows several interfaces:

```text
eth0
eth1
lo
tun0
```

Let's understand each one.

---

## eth0

```text
134.122.x.x
```

Public IP

Connected to the Internet.

---

## eth1

```text
10.106.x.x
```

Private Internal Network

Used inside the organization.

---

## lo

```text
127.0.0.1
```

Loopback Interface

Only communicates with itself.

---

## tun0

```text
10.10.x.x
```

VPN Tunnel Interface

Created after connecting to HTB VPN.

This interface allows access to HTB lab networks.

Without **tun0**, the HTB machines are unreachable.

---

# Public vs Private IP Addresses

|Public IP|Private IP|
|---|---|
|Reachable over the Internet|Internal network only|
|Assigned by ISP|Assigned inside LAN|
|Globally unique|Reused in many networks|

Examples

Public

```text
134.122.100.200
```

Private

```text
10.x.x.x

172.16.x.x

192.168.x.x
```

---

# VPN Tunnel (tun0)

![Image](https://images.openai.com/static-rsc-4/0UYZowQN7qVvfFzCEQ7ZEcVWdQ3YYOHbk9JUPq4GlV33ZIRwjuBHfjbRDwXf1S4wXuh6FC8UxVf119UD1WZ0jOeG7CPwriqPYPRPDBO5CZ0aNIH_r926srPFDzUiPU1WSlTowZcv2hazsc51nO5tna2y4Hp0LhsdojlLW-szi-SPacePzSsXJK2LctlpaKT6?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/TeYjUnRb_Pjqo0nyEpegZO76HTdsS0fjHxrRAuwLXpM6Z43RLZmZAD-sXTNJgJyul5DnBCCSs1kzuALxYiGIH3iLcD5rOr0WvRRCmVQUsK6TCkHQIQJNy7eIQ_5-9Y5ljmm3_GiTEsrsGk-FbuAFsKiwYeApSXTxXCVajJuQ2K7G_hdDw2HQAmazbE0itbTM?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/w8KgcU2_ozsYfGBM1-WUf0mLtEMFJqrB0j4KOQLu_sRta9HgP4uMLM5T4zKTGXAaMxkbISYeDFtPARfKw1r0WxDVMlVq48frQr5bMZhk3HoV__1XtlBAyjUOmePUDvncU_GkB7pB3RJCH3yrNT0oii8bPTZK2lhoa2c6dbXYXIabqfIQAyvgObsVG39Ps-8N?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/TPUJOb6HRLMSDy2R1KJWN6DK2vAX8roGWI9E4o_p-F80Jv82IkKHSK-dPfpl0faCNveV1mldOfpAh91Bub8fSUxewG9dpIvg_nUpanyvn7cKTDJheI-IEEAFCUXaTOW4q8aCWaXtsRWIVRSDVgxkTdJR0x_MZOMhbAJVHiFT3a_HLKf4-YOZlh5A7HidAHI7?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ve7vfOPONIDloPBsO0hRndM5H4d6jGotQCXWP0cac1e2iKCn6LQJu9V0OZO6aCeWXDS48IJftISDEWZUKCaJFiU9akMJ_rGCT58VwdT2GzWVd8y5PpGHwItVB-6xH4z0BCY5kLtJqTF4cH1mcahFtNeVoaijk4e1sfPlNE5ItAGc9W_V2Bj7Af3YS-GGALK-?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/hgVti3aj_esdA7Km12DeFRqRk7hGA_xCmUD4KlrBz5Kwd85SIiu4Bd9W2h1SZ8bhExl_1J-1Ul-2wtGmtBMcE0UJTE6qQZcslRumS_QoCkHvLx5RcIhJZly2HdcxgR_Cm5xpqgpVD6Ord98EiDEti-rJ_kNC4s42TmjiS-53uH4opD5aJyKLLXEfuMc5hh5N?purpose=fullsize)

VPN creates

```text
Encrypted Tunnel

Your PC

↓

Internet

↓

VPN Server

↓

Private Network
```

The VPN:

- Encrypts traffic
    
- Creates a tunnel interface (`tun0`)
    
- Allows access to otherwise unreachable private lab networks.
    

---

# IPv4 vs IPv6

HTB mainly focuses on IPv4 because it is still the most common in enterprise LANs.

However, Windows systems often have both:

- IPv4
    
- IPv6
    

This is called:

## Dual Stack Networking

A host can communicate over either protocol depending on the destination.

---

# Subnet Mask

Think of it like:

Phone Number → IP Address

Area Code → Subnet Mask

Example

```text
IP Address

10.129.221.36

Subnet Mask

255.255.0.0
```

The subnet mask identifies:

- Network Portion
    
- Host Portion
    

It determines whether traffic is local or must be sent to the gateway.

---

# Default Gateway

When a destination is on another network, traffic is sent to the **Default Gateway**.

```text
PC

↓

Default Gateway

↓

Router

↓

Destination Network
```

Usually, the default gateway is the router interface connected to the LAN.

---

# 2️⃣ Routing

![Image](https://images.openai.com/static-rsc-4/lFjTXu-3iB9QmbMU3UGwf7-kZX_0u4vn_AaaQV4SCW4NirSdUQ6uDWvXGqt-Li916zSvKxSrLBDZYXE94EFqSTnxDelQFad8RyRWMcpgPDojWcqM3k7plZuGBz1uVR2Mr9C6XMnMX4GB9s0F2b3gKGrcjNIKgSYRZa_21aOs1iaMNrv5cb6NLyVc_bj3_wWP?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/UwlkTJREJJemhKMvdcUUkV1_7lQD-uRlQh1sWarF_Ex4p7tIcH0bvlmI-vN6rvE3EQIfUe4lKz-bg4OGi04icGbRco-dwmbzBCvAxpFtmNtexkXZHgADLjeDclrh3-l0QYo0dbTK9lnGfmjPfcu3aLty3BZCDvnsjmNJgslVdh7XBIEUCjEgXe11tSsRCPLZ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Yf6f_gPKKMkczhJHEUWgqBdlGZVBcO7-xVB9cGmsMIeuj24cN99wj__DjzMYcYB7ShkwE2sjnWrpLGh6Y1aa7b1BSGDAD9Hf0WFcBzZC6UAKtvz7v4xfFsBLOeGu4Umb9xvIMKqfYAZ7KL2EqNqFyDeYGF8SrY8X3vjzFn7SE7c7XphuI1HPr5sJyYTa_ALE?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/uIxXaT7hgSAUUSFQUAzoGKRVrdLYPib8yMTfn1e0GByG-QYR6wMz5RjRl8khfdoGGquX2LKDgjEayGxBR13ByNGa9b6i76HnqGIflponjbr5JQYWyiSyXnHTCY4Jtg-6PDgYAhg7k5Dfos8HnXzH9f_vmfxSqrIBn2sIPdUR85SkLUBjkhyTRyZkTWa448SX?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/YjIQUKutT2Y0BIbgK3soFycJVluNEUebgYEvfBZOFfOlP8kPu_sdZIUYo4R-eHbTgTYCLapPmeOmBL8i7YRhrd-D8uANe7Kft7Bu4u2dOXXdHXpNNYcGynU8Kvsc8-TkloT1q8JiaM38oRXUe357tGCg2E0fkJ4Xi4yiz2dH4UT3_yYdtNzZ2OWG760S7iiz?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Co9MOslo9XBVWgDqHk4peafC6sp5c1Z8OxyE3MEv3GMN70qUiCkGwWggyDbx1tczTLR2CyBjI8AkN3H7mXyMDGwAaVJZZD3c2tuxN4Cy2iJk6RtvjIkCRHutpA9jIbBRqhNOJa7p9UWLuqLaoNdaSIqe61agdQQtG5mS7E85nI5uG8J-9HzGpp8Nh1FjzUPV?purpose=fullsize)

## What is Routing?

Routing is deciding where packets should go.

Every operating system has a routing table.

Examples:

- Linux
    
- Windows
    
- macOS
    
- Routers
    

All use routing tables to forward packets.

---

# Viewing the Routing Table

Linux

```bash
netstat -r
```

or

```bash
ip route
```

Windows

```cmd
route print
```

---

# Routing Table Example

```text
Destination

Gateway

Interface
```

Example

```text
10.129.0.0

↓

10.10.14.1

↓

tun0
```

Meaning:

Packets for the **10.129.0.0** network are forwarded through the VPN interface (`tun0`).

---

# Why Routing Tables Matter During Pivoting

After compromising a host, inspect its routing table to learn:

- Which networks are reachable
    
- Which interface reaches each network
    
- Whether new routes must be added (e.g., AutoRoute)
    

This helps identify pivot opportunities.

---

# AutoRoute

HTB mentions **AutoRoute**.

Purpose:

Automatically add routes through a compromised pivot host.

Example

```text
Kali

↓

Pivot Host

↓

10.10.20.0/24
```

Instead of routing manually, AutoRoute creates the necessary route so your attack machine can reach the internal network.

---

# Default Route

If no specific route exists, packets follow the:

- Default Route
    
- Default Gateway
    
- Gateway of Last Resort
    

These all refer to the path used when the destination network is unknown.

---

# 3️⃣ Protocols, Services & Ports

![Image](https://images.openai.com/static-rsc-4/DxQSMQ6QvkSUQW0yEDQw5KUwvkz2wVjU8YcaYncipcwqLwK4imhRuNOj8VvyJIrwrBuDXpMxPb-lx_D5QY5UPBeIv98W7tVcQ7OYRVg7fE088myi9LGgNQ1wcloKdufjLRRs2iF5nqGyPOY7Yn00vCijrGqD6tZlUe6FEHEnMmt_48n6zmzuJuBwzKGncleg?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/wJ6LbCvkhb2e2oH1Te_B6poggli-d7D8k_uXMqsqu4Qzt9ZthP8OQwzNT2aW8CgVnP1g8NuCoMtfdTD74bC7XGx5e0A4SV5LV02BPuO9vLh1bnqqkszI_sOxHeLyAZ4V0q7A9X97ylM6yf-l_GPCGpDpOYix2COiJaOPIUKYrYOerWZRzLvtpVIf9mQhaJsd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/KVr6ZA3roC9lu4NSRVx0LUhRRDGGol2iQD7yzvUtu4k1WsS7f82bMbIJq5U5iptHjkhaIZ5nu6pebIQoOCK6K4PTWRQMFN0B0FJl0RW8tMjsPbfRyU42ViGiRElyNE0umd8Rz12tcGWnT4om5GCO7FaDdtc-7Z_3WQeQxa0poiwldIhDVayE_vCe_z1IgJy9?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/BK_kAUnZSjsdRI2p_GV0HNOMmN1-kDtBE2J37UdhiD2Z3Uvthm4Rb7rCkp7R7djlgX_brJ_4rT9lZvxjVbv18X6RbeVUIOjhWwtef3RW_iEBrkh3-koDBLtv7Rwg-EUTlGI4-GxA0aw4d41XpIe4Yjm-Ix8Csctk6Ddb90VcZgAP_hohInREGTuE7Ekmj0cm?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/1gnjXqSpdvodaaziw_IUrJAbLcrbfVtKynxP_qOkWfqCZQoWTKqYp-SeKwtkWfhqO1UoxxUjeGGinM8oJE2GG0NveK5PFw5ycIOz_boPQJbQjMESMVbr3IAkp7_Yh9icjx61v2vYwzm_3XrJtADOPtlP9-IBtyVPAufm_ktQxsV-SdLQj2kRRbrhGMgTFPom?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/opuPJ3E5YJO7JwXI1KwC3UAQH3m33ldi5SaUvhui7pk4Ox6XfgrVUVO7T6DBpftTeW2JUD78tf9b1y26XS9j2ed_EKmemTTu-47Zu6DJzMAqQaLuGsP914a-YVnsJGF8RaqD7reSKnw0zo6m1ld0C_FANc0i4SaUjZFnfTDQVnli7Ehw7u65F96elumuoj5v?purpose=fullsize)

## What is a Protocol?

Protocols are the rules that define how network communication works.

Examples:

- HTTP
    
- HTTPS
    
- SSH
    
- FTP
    
- SMB
    
- DNS
    

---

# What is a Port?

Ports are software identifiers used by applications.

An IP identifies **which computer**.

A port identifies **which application** on that computer.

Example

```text
192.168.1.15

↓

Port 80

↓

Apache Web Server
```

---

# Example

Website

```text
IP

↓

80

↓

HTTP
```

Because users need to access the website, administrators typically allow inbound traffic to port 80.

Attackers often exploit services exposed on these allowed ports to gain an initial foothold.

---

# Source Port vs Destination Port

Every connection has:

### Destination Port

The service being contacted.

Example:

```text
80
443
22
3389
```

### Source Port

A temporary port chosen by the client to track the connection.

Understanding both becomes important when configuring reverse shells, listeners, and payloads.

---

# HTB Tip ⭐

The HTB author recommends drawing the network topology while pivoting.

Tools such as **Draw.io** help visualize:

- Compromised hosts
    
- Reachable networks
    
- Routers
    
- Routes
    
- Firewalls
    
- Pivot paths
    

Good documentation makes complex engagements much easier to understand and execute.

---

# 🎯 Important Exam Points

### Always Check After Compromising a Host

- IP Address
    
- Multiple NICs
    
- VPN Interfaces
    
- Routing Table
    
- Default Gateway
    
- Reachable Networks
    

---

### Remember

- `eth0` → Public interface
    
- `eth1` → Internal interface
    
- `lo` → Loopback
    
- `tun0` → VPN tunnel
    

---

### Key Commands

```bash
ifconfig
ip addr
ipconfig
ip route
netstat -r
route print
```

---

### Pivoting Checklist

✔ Identify all NICs  
✔ Record IP addresses and subnet masks  
✔ Note VPN interfaces (`tun0`)  
✔ Check routing table  
✔ Identify default gateway  
✔ Map reachable networks  
✔ Draw the network topology

---

# 📌 Quick Revision Table

|Concept|Key Point|
|---|---|
|IP Address|Required for communication on a network|
|NIC|Network interface that holds an IP address|
|Multiple NICs|Indicates access to multiple networks; potential pivot opportunity|
|`tun0`|VPN tunnel interface created by HTB/OpenVPN|
|Public IP|Routable on the Internet|
|Private IP|Used only inside internal networks|
|Subnet Mask|Defines network and host portions of an IP address|
|Default Gateway|Sends traffic destined for other networks|
|Routing Table|Determines where packets are forwarded|
|AutoRoute|Adds routes through a compromised pivot host|
|Protocol|Rules for communication (HTTP, SSH, SMB, etc.)|
|Port|Software endpoint for a service (e.g., 80, 443, 22)|
|HTB Recommendation|Document and diagram the network to identify pivot paths clearly|
