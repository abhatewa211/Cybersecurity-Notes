# 1. 🔹 What Is ICMP Tunneling?

**ICMP tunneling** encapsulates traffic inside **ICMP packets**, specifically:

- ICMP Echo Requests
    
- ICMP Echo Responses
    

Normally, ICMP is associated with:

```text
ping
```

However, an ICMP tunnel can carry other traffic inside those packets.

### Basic concept

```text
Normal ICMP:

Host A ───── ICMP Echo Request ─────> Host B
Host A <──── ICMP Echo Response ───── Host B
```

With tunneling:

```text
Application Data
      ↓
ICMP Tunnel
      ↓
ICMP Echo Request/Response
      ↓
Network
```

---

# 2. 🎯 Why Is ICMP Tunneling Useful?

ICMP tunneling can be useful when a firewall permits **ping/ICMP traffic** while restricting other protocols.

The supplied material describes this scenario:

```text
Internal Host
     │
     │ ICMP allowed
     ▼
External Server
```

Traffic can be encapsulated inside ICMP packets and transported through the permitted path.

This can potentially be used for:

- **Data exfiltration**
    
- **Pivoting**
    
- **Creating tunnels**
    
- Transporting other network traffic
    

---

# 3. 🖼️ ICMP Tunnel Architecture

![Image](https://images.openai.com/static-rsc-4/jufPwatCnCyFwOhb_lTF1mODCQValhR-UmMwjP1yhwYkTIAtRJyQLn0fjr_JhOdFsp9Dm4cZ_ccVE7VZxm_6ae7Ru5VfyfXqrX6Gz-r1KYVHvzssdCd0mUXf1X9zzBD82dm6RCgDCH4Znce394dfuYYtZ__2QUOLp9BbS0deaEvRulGGgx3p1T6yJYHIFkey?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/e2Avq4c4nRG7m-cUKY67vCqgWQizno3i7gBBpljSah_eczM5LRDBfuQ48Gf31kc-cutopBgstYX9GyMq7zbcawcnosu-c_ru8ar23ycIuItw5h5QCqedBn3J9ocIUBCbGhIXBMNoFBzq0OcaiHUteDX20LpHjByxtoE9iUD_hVjdGX_KhQ8m5E0ajXTkjcTA?purpose=fullsize)

The basic architecture from the lab is:

```text
                    ATTACK HOST
                    10.10.14.18
                         │
                         │ ICMP
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
                  Internal Target
```

The important idea is:

> **The application traffic is transported through an ICMP tunnel rather than directly over the original network path.**

---

# 4. 🧰 Tool Used — ptunnel-ng

The material uses:

**ptunnel-ng**

Repository:

[ptunnel-ng GitHub repository](https://github.com/utoni/ptunnel-ng?utm_source=chatgpt.com)

It creates an ICMP-based tunnel between two systems.

The basic architecture is:

```text
ptunnel-ng Client
        │
        │ ICMP
        ▼
ptunnel-ng Server
        │
        ▼
TCP Service
```

In this lab, the TCP service is:

```text
SSH
TCP/22
```

---

# 5. 🏗️ Setting Up ptunnel-ng

First, clone the repository:

```bash
git clone https://github.com/utoni/ptunnel-ng.git
```

Move into the directory:

```bash
cd ptunnel-ng
```

---

# 6. 🔨 Building ptunnel-ng

The supplied method uses:

```bash
sudo ./autogen.sh
```

After running `autogen.sh`, ptunnel-ng can be used on the client and server sides.

---

# 7. 🧱 Alternative — Static Binary

The source also gives an alternative approach for building a **static binary**.

Install:

```bash
sudo apt install automake autoconf -y
```

Enter the directory:

```bash
cd ptunnel-ng/
```

Then modify `autogen.sh`:

```bash
sed -i '$s/.*/LDFLAGS=-static "${NEW_WD}\/configure" --enable-static $@ \&\& make clean \&\& make -j${BUILDJOBS:-4} all/' autogen.sh
```

Then:

```bash
./autogen.sh
```

### Why is this useful?

The material later emphasizes **GLIBC compatibility**.

A static binary can help avoid some dependency problems because more of the required functionality is included in the binary.

---

# 8. ⚠️ GLIBC Compatibility

This is an important point from the material.

The target and attack system may have different:

```text
GLIBC versions
```

This can cause the compiled binary to fail.

Therefore:

```text
ptunnel-ng doesn't run
        ↓
Check GLIBC
        ↓
Compare target/workstation
        ↓
Use compatible build/version
```

The lab specifically reminds you:

> Consider the versions of GLIBC and make sure you are on par with the one on the target.

---

# 9. 🚚 Transfer ptunnel-ng to Pivot

The supplied command:

```bash
scp -r ptunnel-ng ubuntu@10.129.202.64:~/
```

### `-r`

Means recursively copy the directory and its contents.

The pivot host is:

```text
10.129.202.64
```

---

# 10. 🖥️ Starting the ptunnel-ng Server

On the target/pivot host:

```bash
sudo ./ptunnel-ng -r10.129.202.64 -R22
```

Important parameters:

```text
-r10.129.202.64
-R22
```

---

# 11. 🔍 Understanding `-r`

The material explains that the IP following `-r` should be the IP of the **jump-box that ptunnel-ng should accept connections on**.

In this example:

```text
10.129.202.64
```

The important thought process is:

```text
Which IP can my attack host reach?
             ↓
Use that reachable IP
             ↓
ptunnel-ng server
```

---

# 12. 🔍 Understanding `-R22`

The example specifies:

```text
-R22
```

This corresponds to the TCP service being forwarded:

```text
TCP/22
SSH
```

So the tunnel ultimately allows an SSH connection to travel through the ICMP tunnel.

---

# 13. 📋 Server Output

The supplied output:

```text
[inf]: Starting ptunnel-ng 1.42.
[inf]: Forwarding incoming ping packets over TCP.
[inf]: Ping proxy is listening in privileged mode.
[inf]: Dropping privileges now.
```

The key line is:

```text
Forwarding incoming ping packets over TCP.
```

This describes the central function of ptunnel-ng.

---

# 14. 🧠 Privileged Mode

ICMP packet handling requires elevated privileges.

The output shows:

```text
Ping proxy is listening in privileged mode.
```

Then:

```text
Dropping privileges now.
```

So the program initially obtains the required privileges and then drops them where possible.

---

# 15. 🔗 Connecting from Attack Host

On the attack host:

```bash
sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22
```

This establishes the client side.

Important values:

```text
Target:
10.129.202.64

Local port:
2222

Remote service:
22
```

---

# 16. 🔍 Understanding the Client Command

```text
-p10.129.202.64
```

Connect to the ptunnel-ng server at:

```text
10.129.202.64
```

---

```text
-l2222
```

Create the local listening port:

```text
2222
```

This is extremely important because we will later connect to:

```text
127.0.0.1:2222
```

---

```text
-r10.129.202.64
```

Remote/jump-box address.

---

```text
-R22
```

Remote TCP service:

```text
22
```

---

# 17. 🖼️ Complete ptunnel-ng Flow

```text
                    ATTACK HOST
                    10.10.14.18
                         │
                         │
                 localhost:2222
                         │
                         ▼
                 ptunnel-ng Client
                         │
                         │
                    ICMP Tunnel
                         │
                         ▼
                 ptunnel-ng Server
                         │
                         ▼
                 10.129.202.64:22
                         │
                         ▼
                       SSH
```

The important transformation is:

```text
SSH Traffic
    ↓
ptunnel-ng
    ↓
ICMP
    ↓
ptunnel-ng
    ↓
SSH
```

---

# 18. 🔐 Tunneling SSH Through ICMP

Once the tunnel is established:

```bash
ssh -p2222 -lubuntu 127.0.0.1
```

This command appears to connect to:

```text
127.0.0.1:2222
```

But the traffic is actually being transported through the ICMP tunnel to the remote SSH service.

---

# 19. 🧠 Why `127.0.0.1`?

Because the ptunnel-ng client creates a local listener.

```text
127.0.0.1:2222
```

acts as our local entry point.

Therefore:

```text
SSH
 ↓
127.0.0.1:2222
 ↓
ptunnel-ng
 ↓
ICMP
 ↓
Pivot
 ↓
SSH :22
```

---

# 20. 📋 Successful SSH Session

The supplied example shows:

```text
Welcome to Ubuntu 20.04.3 LTS
```

and:

```text
IPv4 address for ens192: 10.129.202.64
IPv4 address for ens224: 172.16.5.129
```

This is particularly useful because it confirms the Ubuntu system has connectivity to both:

```text
10.129.202.64
```

and:

```text
172.16.5.129
```

So it can function as a pivot into the internal network.

---

# 21. 📊 Confirming Tunnel Traffic

ptunnel-ng provides session statistics.

The supplied output:

```text
Incoming tunnel request from 10.10.14.18.
Starting new session to 10.129.202.64:22 with ID 20199
```

This confirms:

```text
Attack Host
     ↓
ptunnel-ng
     ↓
10.129.202.64:22
```

---

# 22. 📈 Session Statistics

Example:

```text
Session statistics:
I/O:   0.00/  0.00 mb
ICMP I/O/R: 248/22/0
Loss: 0.0%
```

These statistics provide information about traffic flowing through the tunnel.

The important concepts are:

```text
ICMP packets
Traffic
Packet loss
Session ID
```

---

# 23. 🔄 Dynamic Port Forwarding Over the ICMP Tunnel

The material introduces another useful technique:

> We can use this tunnel and SSH to perform dynamic port forwarding.

Command:

```bash
ssh -D 9050 -p2222 -lubuntu 127.0.0.1
```

---

# 24. 🧠 What Does `-D 9050` Do?

The SSH option:

```text
-D
```

creates a **dynamic application-level port forwarding/SOCKS proxy**.

Here:

```text
9050
```

is the local SOCKS port.

So we now have:

```text
127.0.0.1:9050
```

---

# 25. 🖼️ ICMP + SSH + SOCKS

This is the complete chain:

```text
                  ATTACK HOST
                       │
                       │
                SOCKS :9050
                       │
                       ▼
                  SSH Client
                       │
                       │
                Local :2222
                       │
                       ▼
                 ptunnel-ng
                       │
                       │
                      ICMP
                       │
                       ▼
                 Ubuntu Pivot
                       │
                       │
                Internal Network
                       │
                       ▼
                  172.16.5.x
```

This is one of the most important concepts in the section.

---

# 26. 🧅 Proxychains Through the ICMP Tunnel

Once the SOCKS proxy is available on:

```text
127.0.0.1:9050
```

Proxychains can route supported TCP connections through it.

The supplied example:

```bash
proxychains nmap -sV -sT 172.16.5.19 -p3389
```

---

# 27. 🔍 Important Nmap Options

### `-sV`

Service/version detection.

### `-sT`

TCP Connect scan.

### `-p3389`

Scan only:

```text
TCP/3389
```

which is commonly associated with:

```text
RDP
```

### `172.16.5.19`

Target internal host.

---

# 28. 📋 Result

The supplied output shows:

```text
PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```

Therefore:

```text
172.16.5.19
      ↓
TCP/3389
      ↓
OPEN
      ↓
RDP
```

This confirms that the internal RDP service is reachable through the tunnel.

---

# 29. 🧠 Complete Traffic Path

When running:

```bash
proxychains nmap -sV -sT 172.16.5.19 -p3389
```

the conceptual traffic path is:

```text
Nmap
 ↓
Proxychains
 ↓
SOCKS :9050
 ↓
SSH Dynamic Forwarding
 ↓
127.0.0.1:2222
 ↓
ptunnel-ng Client
 ↓
ICMP Packets
 ↓
ptunnel-ng Server
 ↓
Ubuntu Pivot
 ↓
172.16.5.19:3389
```

🔥 **This is the core concept of the entire section.**

---

# 30. 🛰️ Why ICMP Is Interesting for Tunneling

The supplied material emphasizes the firewall situation.

Suppose:

```text
TCP/22 ❌
TCP/80 ❌
TCP/443 ❌
ICMP ✅
```

A direct SSH connection may fail.

But if ICMP communication is permitted, an ICMP tunnel may provide another communication path.

Conceptually:

```text
Firewall
┌──────────────────────┐
│ TCP/22       BLOCKED │
│ TCP/80       BLOCKED │
│ TCP/443      BLOCKED │
│ ICMP         ALLOWED │
└──────────────────────┘
             │
             ▼
       ICMP Tunnel
             │
             ▼
       Encapsulated
       Application Traffic
```

---

# 31. ⚠️ Important Limitation

The source explicitly states:

> ICMP tunneling would only work when ping responses are permitted within a firewalled network.

Therefore, it is **not guaranteed to work everywhere**.

The required conditions depend on the network's ICMP filtering and routing behavior.

---

# 32. 🔬 Network Traffic Analysis with Wireshark

A very important learning point from this section is **traffic analysis**.

The material recommends using:

**Wireshark**

to confirm that the tunneling tool is actually behaving as expected.

![Image](https://images.openai.com/static-rsc-4/Mu3x2t3W4C7euereNiOqb1VXNG9k5ziRya46dAWPLyrx7WSb7PY8MYFuRf9Ns2fWM5V2OaUj6FTdKnzQQp0tqfNWhK2kW_fMijX4OriiXiYs43PGaAIDEFvE9PPUdpbt4kqD14mJW6ISG6QM3A8KOW1shtzK6ky_hpMb2J0PBfoQcPCyChQQCls5KC4duFi-?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/mbCYP9M8AM9u2xbHAKWSBtT7WYuvpiqIxZCqZq0Fb4qNTFji4m-1K09n287Cr7YqzxUIqYtr86np-bFEJXa9QWU0raWPnRI4ov5AOybtD2I17NR9gHVjzbUzPkpRcWbcpl-ErMFZxif-OqnEIklX_n9XhO6LK1_T_W80AuaqLSwJXmHEUfSA1U3PRTacErs4?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/2n9_r3ndV4YaR_XoVpX9IlSZ3bp9W4txZELQnoBychylMSy4Hz-lHxQIDGMBTj2w_HNjtu0jKkb2FHvfcgw9ySO4Neah7jRqjXC4nsq1jwnoS5A8vAIcmhRo-zg2t7UxtJY6PuN9uD1W6hHea8F-ymx-0L4d8Trb8QY-P7Hq5BnrOXGXpyOlkQlGRFDeMMl9?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/lCb_iWQpDiHnM3t3NMYyGgtX6g99VcbJ08iT_HtSogYPWbSZ0oldKiDj6ojMk0ZnN1AByGt0MuxjQokRRwSlLm7NX6KYBx3PhWV7wkH1BQ6wH-G_1FR1qVoRLoryLtNIbra3R2NJjTLBCcVzTFYSE1MBMT0lDjV5GXkoPlMXuAhoaVVtQLwQSO8iYOmqzE1g?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/I6Kqb4klXSu_Xr-waguThB0TPi0p8slhkRY2IZ7F3jkfxswms7x7cmLYYH4vLpQMpvrD7ocb4UvuUxF1wVIktVova6qXnxzrhqGXncdJT-ntNnSxR2hZ1ZTi_YDu5Aa2NMgxuXtZ-NJr7FHSuI6aW78G9uJxMt-wCrpu3GF6QfFNj9lhteLTVJ61vt9_1fFC?purpose=fullsize)

---

# 33. 🧪 Comparing Normal SSH vs ICMP-Tunneled SSH

## Normal SSH

Command:

```bash
ssh ubuntu@10.129.202.64
```

The source states that Wireshark should show traffic associated with:

```text
TCP
+
SSHv2
```

Conceptually:

```text
SSH
 ↓
TCP
 ↓
Network
```

---

# 34. 🛰️ SSH Through ICMP

Command:

```bash
ssh -p2222 -lubuntu 127.0.0.1
```

This time the SSH connection enters:

```text
127.0.0.1:2222
```

and ptunnel-ng transports it through ICMP.

Conceptually:

```text
SSH
 ↓
ptunnel-ng
 ↓
ICMP
 ↓
Network
```

Therefore, packet analysis allows us to distinguish the network behavior of the two approaches.

---

# 35. 🔥 Normal SSH vs ICMP Tunnel

|Feature|Normal SSH|SSH through ICMP|
|---|---|---|
|Application|SSH|SSH|
|TCP|Direct|Encapsulated/transported through tunnel|
|ICMP|Not required|Required|
|Local entry|Remote IP|`127.0.0.1:2222`|
|Tunnel tool|None|ptunnel-ng|
|SOCKS possible|Yes, with SSH|Yes, using SSH `-D`|
|Wireshark|TCP/SSHv2|ICMP-based tunneling traffic|

---

# 36. 🧠 Key Commands to Memorize

### Clone

```bash
git clone https://github.com/utoni/ptunnel-ng.git
```

### Build

```bash
sudo ./autogen.sh
```

### Transfer

```bash
scp -r ptunnel-ng ubuntu@10.129.202.64:~/
```

### Start server

```bash
sudo ./ptunnel-ng -r10.129.202.64 -R22
```

### Start client

```bash
sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22
```

### SSH through ICMP

```bash
ssh -p2222 -lubuntu 127.0.0.1
```

### SSH dynamic forwarding

```bash
ssh -D 9050 -p2222 -lubuntu 127.0.0.1
```

### Proxychains

```bash
proxychains nmap -sV -sT 172.16.5.19 -p3389
```

---

# 37. 🧩 Important Ports

From this lab:

|Port|Purpose|
|--:|---|
|**53**|DNS|
|**22**|SSH|
|**2222**|Local ptunnel-ng listener|
|**9050**|SSH SOCKS proxy|
|**3389**|RDP|

The two most important for this specific technique are:

```text
2222 → ptunnel-ng local entry
9050 → SOCKS proxy
```

---

# 38. 🎯 Important IP Addresses

```text
Attack Host
10.10.14.18

Pivot / Ubuntu
10.129.202.64

Ubuntu internal interface
172.16.5.129

Internal target
172.16.5.19
```

---

# 39. 🧠 The Whole Technique in One Diagram

```text
                    ATTACK HOST
                    10.10.14.18
                         │
                         │
                  ┌──────▼──────┐
                  │ Proxychains │
                  └──────┬──────┘
                         │
                    SOCKS :9050
                         │
                         ▼
                    SSH -D
                         │
                    Local :2222
                         │
                         ▼
                 ┌──────────────┐
                 │ ptunnel-ng   │
                 │   CLIENT     │
                 └──────┬───────┘
                        │
                        │ ICMP
                        │ Tunnel
                        ▼
                 ┌──────────────┐
                 │ ptunnel-ng   │
                 │   SERVER     │
                 └──────┬───────┘
                        │
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
                 172.16.5.19
                     TCP/3389
                        │
                        ▼
                       RDP
```

---

# 40. 🏆 Exam/Viva Questions

### Q1. What is ICMP tunneling?

ICMP tunneling is a technique where traffic is encapsulated inside ICMP packets such as echo requests and responses.

### Q2. Which tool is used in this lab?

```text
ptunnel-ng
```

### Q3. What protocol carries the tunnel?

```text
ICMP
```

### Q4. Why might ICMP tunneling work when other connections don't?

Because some firewalls permit ICMP/ping traffic while restricting other protocols.

### Q5. What local port does the ptunnel-ng example use?

```text
2222
```

### Q6. What remote service is forwarded?

```text
SSH / TCP 22
```

### Q7. How do you connect to SSH through the tunnel?

```bash
ssh -p2222 -lubuntu 127.0.0.1
```

### Q8. How do you create a SOCKS proxy over the tunneled SSH connection?

```bash
ssh -D 9050 -p2222 -lubuntu 127.0.0.1
```

### Q9. What port does the SOCKS proxy listen on?

```text
9050
```

### Q10. How can Proxychains use this SOCKS proxy?

Configure:

```text
socks5 127.0.0.1 9050
```

### Q11. What does `-sT` mean in the Nmap example?

TCP Connect scan.

### Q12. What does `-sV` do?

Service/version detection.

### Q13. What internal port is being tested?

```text
3389
```

### Q14. What service normally uses TCP/3389?

RDP.

### Q15. How can you verify the tunnel at the packet level?

Use **Wireshark** or another packet analyzer and inspect the generated traffic.

---

# 41. ⚡ One-Minute Revision

Remember:

```text
ICMP TUNNEL
     ↓
ptunnel-ng
     ↓
SSH
     ↓
-D 9050
     ↓
SOCKS
     ↓
Proxychains
     ↓
Internal Network
```

### Main workflow:

```text
1. Clone ptunnel-ng
        ↓
2. Build it
        ↓
3. Transfer to pivot
        ↓
4. Start ptunnel-ng server
        ↓
5. Start ptunnel-ng client
        ↓
6. Local :2222 becomes the tunnel entry
        ↓
7. SSH through :2222
        ↓
8. Optionally create SOCKS :9050
        ↓
9. Use Proxychains
        ↓
10. Access internal TCP services
```

---

# 🔥 42. The Most Important Concept

The easiest way to remember this module is:

> **We're not making SSH itself become ICMP. We're creating an ICMP tunnel and then sending TCP/SSH traffic through that tunnel.**

So:

```text
                 APPLICATION
                     │
                   SSH
                     │
                     ▼
              ptunnel-ng
                     │
                     ▼
                    ICMP
                     │
             ───────────────
                NETWORK
             ───────────────
                     │
                     ▼
              ptunnel-ng
                     │
                     ▼
              TCP/22 → SSH
```

And when SOCKS is added:

```text
Application
    ↓
Proxychains
    ↓
SOCKS :9050
    ↓
SSH Dynamic Forward
    ↓
ptunnel-ng :2222
    ↓
ICMP Tunnel
    ↓
Pivot
    ↓
Internal Network
```

**Core takeaway:** **ICMP provides the transport path, ptunnel-ng creates the tunnel, SSH provides the session/dynamic SOCKS capability, and Proxychains lets other tools use that SOCKS path.**