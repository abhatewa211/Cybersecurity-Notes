# 1. 🧠 What Is Sshuttle?

**Sshuttle** is a Python-based tool that allows us to route traffic through a remote host over **SSH**.

Its major advantage is that it can automate the routing process, so we don't have to configure **Proxychains** for every application.

The key idea is:

```text
Attack Host
     │
     │ SSH
     ▼
Ubuntu Pivot
     │
     ▼
Internal Network
```

Sshuttle configures local firewall/NAT rules so that traffic destined for a specified internal network is redirected through the SSH connection.

---

# 2. 🎯 What Problem Does Sshuttle Solve?

With some pivoting techniques, we might need:

```text
Application
     ↓
Proxychains
     ↓
SOCKS Proxy
     ↓
Pivot
     ↓
Internal Target
```

Sshuttle simplifies this.

Instead:

```text
Nmap
Firefox
SSH
Other tools
     │
     ▼
Local routing rules
     │
     ▼
Sshuttle
     │
     ▼
SSH Pivot
     │
     ▼
Internal Network
```

So we can use many tools **directly**, without explicitly running them through Proxychains.

---

# 3. 🖼️ Sshuttle Architecture

![Image](https://images.openai.com/static-rsc-4/brukUnDUfdPplUBZZ2pmD-9rgVjEnhMbw1XpEe4VGrD-NUt1c85-49skwx0pMWoDqWDGvphs-Raw3bZBZ13f8Oqn-dAJVgjSkVQpehuLxEkXa2o5hFgRNJqOiGFfQXz9stMTYcH51IQvXlXMFNOl7nkgb9CKhm4zCu6xNXp1fNrfia0woBpE4c0INhIdgrZw?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/F9y4WJJMcF_caHrbbUUFZcfyGT-XyVM4kilBKPo8MkDYKRWSv0833advo0TDNK8Xsvgu8td4c8CMLgkf93fJ6j38GewltoVr6d8h7ZC4059rJoXky7X0_V0VNdTaABcYHUMjV_ICfR1NjjfuVYqVHFa97TMLet3vz3fuWZlFlPl9sbtb7Gj-Sm281Ml5tL1a?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Hq2r-gf6v7NNRkPuYe42mbs5LYXxu3xDcsO_pDs65DmYXS3bqahcfbDttmCSytL2CTacFitn1lcYvscC1U7mDQRQwWuZGBihfaqUdgImhFFrL-oufa0ufBb-a0vJ1qp3TKtrgWu6ZohgGk6y9jK-r8A_EE11SuNgdWY6Wyxhn3pAM7jm8F5FdNaf70pU4WXm?purpose=fullsize)

The architecture from the supplied scenario:

```text
                    ATTACK HOST
                         │
                         │ SSH
                         ▼
                  Ubuntu Pivot
                  10.129.202.64
                         │
                         │
                         ▼
                 Internal Network
                    172.16.5.0/23
                         │
                         ▼
                  Windows Target
                   172.16.5.19
                      TCP/3389
```

---

# 4. 🔑 The Important Concept

The most important thing to understand is:

> **Sshuttle uses SSH as the transport and creates local routing/firewall rules that redirect traffic destined for the specified internal network through the SSH pivot.**

In this example:

```text
Internal network:
172.16.5.0/23
```

So traffic intended for that network is routed through:

```text
Ubuntu Pivot
```

---

# 5. 🆚 Sshuttle vs Proxychains

This is an important distinction.

### Proxychains

You explicitly launch a program through Proxychains:

```bash
proxychains <program>
```

Example from the previous Rpivot section:

```bash
proxychains firefox-esr 172.16.5.135:80
```

### Sshuttle

After Sshuttle establishes the routing rules, you can run tools normally:

```bash
nmap ...
```

rather than:

```bash
proxychains nmap ...
```

Therefore:

```text
Proxychains:
Application → Proxychains → Proxy

Sshuttle:
Application → Routing Rules → Sshuttle/SSH → Pivot
```

---

# 6. 🧠 What Makes Sshuttle Different?

The supplied material specifically states that Sshuttle:

- Is written in Python.
    
- Works for pivoting over SSH.
    
- Removes the need to configure Proxychains.
    
- Can automate execution of `iptables`.
    
- Adds pivot rules for the remote host.
    
- Can route tools such as Nmap through the pivot.
    

One important limitation mentioned in the source:

> Sshuttle only works for pivoting over SSH and does not provide other options for pivoting over TOR or HTTPS proxy servers.

---

# 7. 🛠️ Step 1 — Install Sshuttle

The supplied installation command:

```bash
sudo apt-get install sshuttle
```

The installation output shows:

```text
The following NEW packages will be installed:
  sshuttle
```

After installation:

```text
Setting up sshuttle
```

---

# 8. 🔍 Why Do We Need `sudo`?

Sshuttle needs to manipulate local firewall/NAT rules.

The supplied output demonstrates operations involving:

```text
iptables
ip6tables
```

Therefore, administrative privileges are required for the firewall configuration.

---

# 9. 🛠️ Step 2 — Run Sshuttle

The supplied command is:

```bash
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v
```

This is the most important command in this section.

---

# 10. 🔍 Breaking Down the Command

```bash
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v
```

### `sudo`

Runs Sshuttle with elevated privileges.

This allows it to configure firewall/NAT rules.

---

### `sshuttle`

Runs the Sshuttle program.

---

### `-r`

Specifies the remote SSH connection.

Here:

```text
ubuntu@10.129.202.64
```

means:

```text
Username = ubuntu
Remote host = 10.129.202.64
```

---

### `172.16.5.0/23`

This specifies the network that should be routed through the SSH pivot.

So:

```text
172.16.5.0/23
```

is the target internal network.

---

### `-v`

Enables verbose output.

This is useful for understanding what Sshuttle is doing.

---

# 11. 🧠 What Does `172.16.5.0/23` Mean?

The supplied target network is:

```text
172.16.5.0/23
```

The important point isn't just the individual Windows target.

Sshuttle is configured to route traffic for the **network**:

```text
172.16.5.0/23
```

Therefore, the pivot can potentially provide access to hosts within that specified network.

---

# 12. 🔄 Connection Flow

Once Sshuttle is running:

```text
Attack Host
    │
    │ SSH connection
    ▼
10.129.202.64
Ubuntu Pivot
    │
    │ Internal routing
    ▼
172.16.5.0/23
```

For example:

```text
Nmap
  │
  ▼
172.16.5.19
  │
  ▼
Sshuttle routing
  │
  ▼
SSH tunnel
  │
  ▼
Ubuntu
  │
  ▼
172.16.5.19
```

---

# 13. 🧠 Understanding the Sshuttle Output

The supplied output starts with:

```text
Starting sshuttle proxy (version 1.1.0).
```

This indicates that Sshuttle has started.

Then:

```text
c : Starting firewall manager
```

Sshuttle is preparing its local firewall configuration.

---

# 14. 🔥 Firewall Manager

The output shows:

```text
fw: Starting firewall
```

and:

```text
fw: ready method name nat.
```

This tells us that Sshuttle is using the **NAT** method in the supplied example.

---

# 15. 🌐 IPv4 and IPv6

The output contains:

```text
c : IPv4: on
c : IPv6: on
```

So both IPv4 and IPv6 support are enabled in this instance.

However:

```text
c : UDP : off
```

The supplied output indicates UDP forwarding is unavailable with the selected NAT method.

---

# 16. 🎯 The Important Routing Entry

The output says:

```text
c : Subnets to forward through remote host
```

and then:

```text
172.16.5.0
```

This is the key part.

Sshuttle has been instructed:

> Traffic destined for the `172.16.5.0/23` network should be forwarded through the remote SSH host.

---

# 17. 🔀 TCP Redirector

The output contains:

```text
c : TCP redirector listening on ('::1', 12300, 0, 0).
c : TCP redirector listening on ('127.0.0.1', 12300).
```

So Sshuttle creates a local TCP redirector on:

```text
127.0.0.1:12300
```

The port:

```text
12300
```

is part of Sshuttle's internal operation in this example.

---

# 18. 🔐 SSH Authentication

The output then shows:

```text
c : Connecting to server...
ubuntu@10.129.202.64's password:
```

The SSH connection is established using the supplied Ubuntu credentials.

Then:

```text
s: Running server on remote host
```

This indicates that Sshuttle starts its server component on the remote pivot host.

---

# 19. ✅ Connection Established

The important output is:

```text
c : Connected to server.
```

At this point:

```text
Attack Host
     │
     │ SSH
     ▼
Ubuntu Pivot
```

has successfully been established.

---

# 20. 🔥 iptables Configuration

The supplied output then shows Sshuttle configuring:

```text
iptables
ip6tables
```

For example:

```text
iptables -w -t nat -N sshuttle-12300
```

and:

```text
iptables -w -t nat -I OUTPUT 1 -j sshuttle-12300
```

and:

```text
iptables -w -t nat -I PREROUTING 1 -j sshuttle-12300
```

---

# 21. 🧠 What Is Sshuttle Doing With iptables?

The supplied explanation is:

> Sshuttle creates an entry in our `iptables` to redirect all traffic to the `172.16.5.0/23` network through the pivot host.

Conceptually:

```text
Application
     │
     ▼
Local Network Stack
     │
     ▼
iptables rule
     │
     │ Destination = 172.16.5.0/23
     ▼
Sshuttle
     │
     ▼
SSH Pivot
     │
     ▼
Internal Network
```

---

# 22. 🧩 Why This Is Powerful

Before Sshuttle:

```text
Attack Host ───X───► 172.16.5.19
```

After Sshuttle:

```text
Attack Host
     │
     ▼
SSH
     │
     ▼
Ubuntu Pivot
     │
     ▼
172.16.5.19
```

The application doesn't necessarily need to know about the pivot.

The local routing/firewall layer handles the redirection.

---

# 23. 🛠️ Step 3 — Use Nmap Normally

The supplied command is:

```bash
sudo nmap -v -A -sT -p3389 172.16.5.19 -Pn
```

Notice something important:

There is **no `proxychains`**.

That's one of the main advantages demonstrated by this section.

---

# 24. 🔍 Breaking Down the Nmap Command

```bash
sudo nmap -v -A -sT -p3389 172.16.5.19 -Pn
```

### `sudo`

Runs Nmap with elevated privileges.

### `-v`

Verbose output.

### `-A`

Enables aggressive detection features such as:

- OS detection
    
- Version detection
    
- Script scanning
    
- Traceroute
    

### `-sT`

TCP connect scan.

### `-p3389`

Scan TCP port:

```text
3389
```

which is associated with RDP.

### `172.16.5.19`

The internal Windows target.

### `-Pn`

Treats the host as up without relying on host discovery.

---

# 25. 🎯 Nmap Result

The supplied output shows:

```text
PORT     STATE SERVICE
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```

Therefore:

```text
Target:
172.16.5.19

Port:
3389/tcp

State:
open

Service:
ms-wbt-server

Service:
Microsoft Terminal Services
```

---

# 26. 🧠 What Did We Prove?

The important result isn't just that port `3389` is open.

We proved that:

```text
Nmap
 ↓
Local routing
 ↓
Sshuttle
 ↓
SSH
 ↓
Ubuntu Pivot
 ↓
Internal Network
 ↓
172.16.5.19:3389
```

works.

This demonstrates successful network pivoting.

---

# 27. 🔎 RDP Information From Nmap

The supplied scan also identified:

```text
Target_Name: INLANEFREIGHT
NetBIOS_Domain_Name: INLANEFREIGHT
NetBIOS_Computer_Name: DC01
DNS_Domain_Name: inlanefreight.local
DNS_Computer_Name: DC01.inlanefreight.local
Product_Version: 10.0.17763
```

This provides additional information about the internal Windows system.

---

# 28. 📋 Important Target Information

Keep this section intact for revision:

```text
IP Address:
172.16.5.19

Port:
3389/tcp

Service:
Microsoft Terminal Services

NetBIOS Domain:
INLANEFREIGHT

Computer Name:
DC01

DNS Domain:
inlanefreight.local

DNS Computer:
DC01.inlanefreight.local

Product Version:
10.0.17763
```

---

# 29. 🖼️ Complete Sshuttle Flow

```text
                         ATTACK HOST
                              │
                              │
                       sudo sshuttle
                              │
                              │ SSH
                              ▼
                    ┌──────────────────┐
                    │ Ubuntu Pivot     │
                    │ 10.129.202.64    │
                    └────────┬─────────┘
                             │
                             │ Route
                             ▼
                    172.16.5.0/23
                             │
                             ▼
                    ┌──────────────────┐
                    │ Windows Target   │
                    │ 172.16.5.19      │
                    │ TCP/3389         │
                    └──────────────────┘
```

---

# 30. 🔄 The Difference From Rpivot

You've just studied **Rpivot**, so this comparison is important.

### Rpivot

```text
Application
     ↓
Proxychains
     ↓
SOCKS :9050
     ↓
Rpivot
     ↓
Internal Network
```

### Sshuttle

```text
Application
     ↓
Local routing / iptables
     ↓
Sshuttle
     ↓
SSH
     ↓
Internal Network
```

The major advantage demonstrated by Sshuttle is:

> **You don't need to prepend `proxychains` to every command.**

---

# 31. 🆚 Rpivot vs Sshuttle

|Feature|Rpivot|Sshuttle|
|---|---|---|
|Main mechanism|Reverse SOCKS proxy|SSH-based routing|
|Requires SSH|No|**Yes**|
|Proxychains|Typically used|**Not required**|
|SOCKS proxy|Yes|Not the focus|
|Routing rules|Proxy-based|`iptables`/NAT|
|Example|Firefox through SOCKS|Nmap directly|
|Internal network access|Via SOCKS|Via routing|

---

# 32. 🧠 Sshuttle Mental Model

Think of Sshuttle as:

> **"Make my local machine behave as if traffic to this internal network should go through my SSH pivot."**

For example:

```text
Destination:
172.16.5.0/23
```

Sshuttle creates the necessary local rules.

Then:

```text
nmap 172.16.5.19
```

can be routed through the SSH pivot.

---

# 33. 📌 Important Commands

### Install

```bash
sudo apt-get install sshuttle
```

### Start Sshuttle

```bash
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v
```

### Scan internal RDP

```bash
sudo nmap -v -A -sT -p3389 172.16.5.19 -Pn
```

---

# 34. 🔥 Important Command to Memorize

```bash
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v
```

Break it down:

```text
sudo
 │
 └── administrative privileges

sshuttle
 │
 └── pivoting tool

-r
 │
 └── remote SSH connection

ubuntu@10.129.202.64
 │
 └── SSH pivot

172.16.5.0/23
 │
 └── network to route through pivot

-v
 │
 └── verbose output
```

---

# 35. 🧠 Why `iptables` Is Important

The output shows rules such as:

```text
iptables -w -t nat -N sshuttle-12300
```

and:

```text
iptables -w -t nat -I OUTPUT 1 -j sshuttle-12300
```

Sshuttle uses these rules to intercept and redirect appropriate traffic.

Conceptually:

```text
Outgoing Traffic
       │
       ▼
iptables
       │
       ├── Destination isn't internal
       │       ↓
       │    Normal route
       │
       └── Destination = 172.16.5.0/23
               ↓
            Sshuttle
               ↓
            SSH Pivot
```

---

# 36. 🧠 What Does `/23` Tell Us?

The network is:

```text
172.16.5.0/23
```

The `/23` is the CIDR prefix length.

For this lab, the important conceptual point is that the routing rule targets the **specified internal subnet**, rather than only:

```text
172.16.5.19
```

So the pivot configuration is network-oriented.

---

# 37. ⚠️ Important Lab Note

The supplied material specifically says:

> When spawning the target, wait **3–5 minutes** until the whole lab with all the configurations is set up so that the connection to your target works flawlessly.

The provided SSH credentials are:

```text
Username:
ubuntu

Password:
HTB_@cademy_stdnt!
```

These are **lab credentials from your supplied material**, not general credentials.

---

# 38. 📝 Viva Questions

### Q1. What is Sshuttle?

A Python-based SSH pivoting tool that can route traffic through a remote host using SSH.

### Q2. What is its main advantage over Proxychains?

It can configure routing/firewall rules so applications can be used directly without explicitly running them through Proxychains.

### Q3. What protocol does Sshuttle require?

**SSH.**

### Q4. What option specifies the remote SSH host?

```text
-r
```

### Q5. What network is routed in this example?

```text
172.16.5.0/23
```

### Q6. What is the pivot host?

```text
10.129.202.64
```

with:

```text
ubuntu
```

as the SSH user.

### Q7. What firewall technology does Sshuttle configure?

The supplied output shows:

```text
iptables
ip6tables
```

### Q8. What NAT method is shown?

```text
nat
```

### Q9. What internal host is scanned?

```text
172.16.5.19
```

### Q10. What port is scanned?

```text
3389
```

### Q11. What service is running on 3389?

```text
Microsoft Terminal Services / RDP
```

### Q12. Why is `-Pn` used in the Nmap command?

It tells Nmap to treat the target as up rather than relying on host discovery.

### Q13. Do we use Proxychains with the supplied Nmap example?

**No.**

That is one of the key advantages demonstrated by Sshuttle.

---

# 39. ⚡ One-Minute Revision

```text
                 SSH PIVOTING
                      │
                      ▼
                  SSHUTTLE
                      │
                      ▼
             SSH → Ubuntu Pivot
                      │
                      ▼
              172.16.5.0/23
                      │
                      ▼
                Windows Host
                 172.16.5.19
                      │
                      ▼
                    :3389
```

### Installation:

```bash
sudo apt-get install sshuttle
```

### Pivot:

```bash
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v
```

### Test:

```bash
sudo nmap -v -A -sT -p3389 172.16.5.19 -Pn
```

### Key concept:

```text
Sshuttle
   ↓
SSH transport
   ↓
iptables/NAT rules
   ↓
Internal network routing
   ↓
Use tools directly
```

---

# 🏆 40. Ultimate Memory Trick

Remember the difference between the three pivoting techniques you've covered:

```text
SOCAT
"Redirect this connection."
        ↓
A ──► Socat ──► B
```

```text
RPIVOT
"Give me a SOCKS tunnel."
        ↓
Application
     ↓
SOCKS
     ↓
Internal Network
```

```text
SSHUTTLE
"Route this network through SSH."
        ↓
Application
     ↓
iptables/NAT
     ↓
SSH
     ↓
Pivot
     ↓
Internal Network
```

### The one sentence to remember:

> **Sshuttle uses an SSH connection to a pivot host and automatically configures local routing/firewall rules so traffic destined for the specified internal network travels through that pivot, allowing tools such as Nmap to be used directly without Proxychains.**