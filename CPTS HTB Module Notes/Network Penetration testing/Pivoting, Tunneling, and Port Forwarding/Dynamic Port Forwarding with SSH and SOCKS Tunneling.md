# 🌐 Dynamic Port Forwarding with SSH & SOCKS Tunneling

![Image](https://images.openai.com/static-rsc-4/9OiqsFzpkfEDBsYlzdu0m_k4oyz9r1X2lTht5aYyNBeq48GIGWPgwE8_Ve_7u-WM6hUFHxiR1kaAnCw2hoLhMGirDZniPcE1Ftb5NkmWqfyBVeXN7lypndm8XXZGmxwZ-A1VPYIFd2IH2of82eGtuLIp74ZQOQ3AvflY3Kz_3fkUEoO2VMk0W9CpGSs3Q3Zb?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/kQ4lyW8KE9lRohhjvRTwYTPDtvWM1oe9-bhfrMw8u1jSIg91u9BQMm1VOpJABhiyDB4PmO8B3hiSg8_yXi5qSrGeP3rh1zQyiA-vxv__UJQaUQZekEzBKoCh3mNlvrdSXrCFdHlvJNSRtcdAwurb8TCVg6-kIqEZj_SUvgMX8Ql2iXDvmWnt8lZwsGAQtrni?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/JsMiMwUuyNqE7zaenkWWOUOebgJ0IWuW6wx4ehf-wGAYe2g8V4Az63ZGQxw9OlvVgvTPbRNKST7Ss263zEDV-0tArJx1IxXXHmsayqm-ft5zeCtkm0NaWe59wrS3uB1yd_BRik93oWJhv2MLbGnmFQW2Yf500T66AdWRgtlVmbq7ccdxkX3cr7HTJWIf3zVk?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/wKCzkswieVg7zx6AS_2aGWliVaAR9XMY8sZUNZW4KEx8PnQGUJD-nPW4V0f_VxOjLziOf-_UDdi03ZPnBhRBH6dc8KLg5BjtzjqJ88lCk2WlKr7Q8dx7eOK5tGrefV136zXvqkuH5_Ic4rRjVlEL50DLf29GtzQ0UUw3r2RZQIersEI2Uxcxip_LUXpYkbIe?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/gnjz99_aWs1xsaectQeBUUw2QZO-4jLrGVltvmTsdVq4etJ1T4n-sF9_lADXYN5UakaBfJaRcTmUKnwy3mUlpN530Oi2l74vFTH7XSi3hROPr4LVbPpWUV7BCwol4GSJxEHcQrJ5aopVWKNsWitVX-ciINtJs0bGw-LfGGcERUK6vo5kro4vsHDq7bKzLVo8?purpose=fullsize)

---

# 📖 What is Port Forwarding?

**Port Forwarding** is a technique used to **redirect network traffic from one port to another**.

Instead of communicating directly with a remote service, your traffic is forwarded through another host.

HTB Definition:

> Port forwarding redirects communication requests from one port to another. It primarily uses TCP and can encapsulate traffic using protocols such as **SSH** or **SOCKS**, making it useful for bypassing firewalls and pivoting into internal networks.

---

# Why Use Port Forwarding?

Suppose you compromise a Linux server.

The server has:

```text
SSH → Open
MySQL → Only listening on localhost
```

Your Kali cannot directly access MySQL.

Instead of logging into SSH every time,

you forward the MySQL port to your own machine.

---

# Network Topology

```text
                 Internet

                     │

          Kali (10.10.15.5)

                     │
                 SSH (22)

                     │

        Ubuntu Pivot Server
        10.129.202.64
        172.16.5.129

                     │

             MySQL
        localhost:3306
```

Your attack machine cannot reach MySQL directly.

SSH forwards it.

---

# SSH Local Port Forwarding

![Image](https://images.openai.com/static-rsc-4/nzlY8t0oxWbFsQJmpBGChDPzotmlgyEtSwaAJtNuVAoOKZanO5_fT0viUzv4-HDyiGu0j8QWKjhUQgwlPiTa7e2bcMkERtRmlAu_Ro79YJoteixyzXPIpVbfQeZj-epUtbAh9RQWHv6aRMdUJbT5gINVXcBpaIlfEm9ojdR-gATHH4por8WousZgdpJyQyAP?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/wsLO_0bxDCy2lqlXqqTLbtin39lzJJeUgSGOOZv-w912s3KfW2PfGQ2mrqXtB6ecaruUgxp-VzbBJr2OWaur5OHm1jtDmpimzTIYdi_7Mdyy1pNjCTbvuvAVbt9gwjKY7_3wD2ajCdaG3quI1MnroSvmAUSrHmKnxaki8Ggs1sY_GB6eF7HLgPIXborT0Y_p?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/BnZ473Zuypi4t9jYPbudwRloTSmNSRJTRJYFditKHdoSi5A7Sz7CpajzhpqpmIUvt2gnpDwUy6xiIR2v8hxhU7JWvx-fyCtWIr2p3-2sdAhRMm0Dx1i-hod5qFjWereFRDngvXf3Qt2ELYeSO8r6137Flly-JhVAkirXsS8WC_3rKcU_jfVeo3LcjH5Lpbkq?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/GEuohXfEBVL7Rhp3w8vMLl7rZIUWg4-nq1Wsarlx_RU7puqHAFtMz395p5O5v1GMqzte9jW_geWszV8n1rFpUvfGBsAhCQ59dqlXYRIhTDaY5VB7CCK_b2amVTJBKXp3exrVTgm9fG1qn7oAcs-M7cW1Q5yV2UzClV0e0qyrh6IekRUEJoGbdQEbTWoYHkNv?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/nPBBanDzW1HcvCJ83cBlaHDMqE2sxQF-EtN1m1KOnlKNbiIUFNFdgxXymoH5rZ-45V8sN-qYo54s1eWinhJ9qF0dadX8xrYwZOPQBjN9HsD0EswZaCaa4Ar3uiMAm9fMGFjtgoWk-1PehNMf_DSDYwcy0eMXqtcYvOmjw41vTIpx0Y3oWS005bSdmypGTdtI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/8q9Wc8U5Awcr_qY466S9OZJg1BB1oK5VBdHuyh5kS_Xe528d536nHOVodwjfRxeg6SqgiLk91pChEnI2yK1cf_GbFjzxL4gaXx1HPhNuxaVbi3FSWPG-46nbWY5xvf4vlILBY0b7oDKkQQWel_LF4v1zIxNgkWqbRqFZVtQlU3pEQc5gppD5dgw87mSBZJjj?purpose=fullsize)

---

## Goal

Forward

```text
Local Port 1234

↓

Remote MySQL Port 3306
```

---

# Initial Scan

```bash
nmap -sT -p22,3306 10.129.202.64
```

Result

```text
22/tcp Open

3306 Closed
```

Why?

Because MySQL only accepts **localhost connections**.

It is **not exposed externally**.

---

# Creating the Tunnel

```bash
ssh -L 1234:localhost:3306 ubuntu@10.129.202.64
```

---

## Understanding the Command

```text
ssh

-L

1234

localhost

3306

ubuntu@10.129.202.64
```

Meaning:

|Part|Purpose|
|---|---|
|ssh|Start SSH session|
|-L|Local Port Forwarding|
|1234|Local listening port|
|localhost|Remote server's localhost|
|3306|MySQL port|
|ubuntu@IP|SSH login|

Traffic flow:

```text
127.0.0.1:1234

↓

SSH Tunnel

↓

Ubuntu

↓

localhost:3306
```

---

# Verifying the Tunnel

Check with:

```bash
netstat -antp | grep 1234
```

Output

```text
127.0.0.1:1234

LISTEN
```

Meaning:

SSH is now listening locally.

---

# Verify with Nmap

```bash
nmap -sV -p1234 localhost
```

Result

```text
1234/tcp

mysql

MySQL 8.0
```

Although MySQL is remote,

it appears local because of the SSH tunnel.

---

# Forwarding Multiple Ports

SSH allows multiple **-L** options.

Example

```bash
ssh \
-L 1234:localhost:3306 \
-L 8080:localhost:80 \
ubuntu@10.129.202.64
```

Now

|Local Port|Remote Service|
|---|---|
|1234|MySQL|
|8080|Apache Web Server|

---

# Discovering Pivot Opportunities

After SSH access,

always inspect interfaces.

```bash
ifconfig
```

HTB machine contains:

```text
ens192

↓

10.129.x.x

Attack Network
```

```text
ens224

↓

172.16.5.x

Internal Network
```

```text
lo

↓

127.0.0.1
```

This is a **dual-homed host**, making it an ideal pivot.

---

# Why Normal Scanning Fails

Your Kali only knows

```text
10.129.x.x
```

It does **not** know

```text
172.16.5.0/23
```

No route exists.

Therefore:

❌ Direct Nmap scan fails.

Need:

✔ Pivoting

✔ SOCKS Tunnel

---

# Dynamic Port Forwarding

![Image](https://images.openai.com/static-rsc-4/fjlOqoQhgoAe28jyxFGXSwiaClK6ps9rOQosGmDJSRwMuD_8TmHTOuqVK_PZK1jGa8y4_3vQZLrPqzu9oWF93WYhQEW7FIJNsxbAuYPkd__NCCCaEr-ziKh8pKaVW6ypt6rq1GtMS9cpjcM2UguxbDBGFznEZRc51WK6zwN2fH5V8HQ0QPcv48OSwT695YHY?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/JdNBTxLfGrsfKXFNr61ik_Ns0EM6rO0MQrVDgDWNc9tm_tSNxkgaXUAt40Ll0twSj3kUjaCe1gBy2sfBoPgXWAJM1BYE__YDFyQ2jxlv-IBfPvSAGghkeICo3p-h1qpkxzm0cPVL-WlxASk-6ZhQNBKMfKn-ldmYQ8PzZlB62-Z3ZdIggzVU3XbSIFYK8ax8?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/sYh9zCoVEZCXLn52sNPNlJuORTRe70gzXM63ER9tkLK90G7M0LVbIZCIqIoakXWnY2VGsIireZf7tE29Ssie-fTgaRBUu2rsL6PEcR6vVXT8vQzm_vZp2fPBxe5k15PiWaYoI_fBrddFhy8It6tkYW0qVFdlTPMv7p4qoUs5D3u1273oiVEPDHxPhkoDz9KS?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/OpBXf404GdPiqDnsEYEYFGOCrJmP_ai_eyVQpjlkskp_ZpiuCwPo-PnVP0JZxe1K7gWvZ1IzUN3wok5OsOdSg5WwAmpXY4Ph0mZs6GFoG2DKQcwg1hnMxDZyHzH3g6zLwpNFbZCBIeeFaBmWVDq2J4jBHAAJtKvcpMk-EbolazlzZY1z_nNRoSfOoMO_A0y7?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/v1ZaiQsH3NyGmrcYpfgxAkGUBbfugyFZxfuFBS4om9O46mYIXwyodcfbFxzbs44h5RMvIuJZiwbT7pYQrsIzIHecxHKqpXiIX3h7Ol9RzES6zXDslmOWqIQTYddvrxJaf43lf6qwnzDz_06FaZPfiHaiwtP7OX-UStL5LqbKQCWcWPqNNt1JCNk0pGUUgrEa?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/gnjz99_aWs1xsaectQeBUUw2QZO-4jLrGVltvmTsdVq4etJ1T4n-sF9_lADXYN5UakaBfJaRcTmUKnwy3mUlpN530Oi2l74vFTH7XSi3hROPr4LVbPpWUV7BCwol4GSJxEHcQrJ5aopVWKNsWitVX-ciINtJs0bGw-LfGGcERUK6vo5kro4vsHDq7bKzLVo8?purpose=fullsize)

Instead of forwarding **one port**,

Dynamic Port Forwarding forwards **entire TCP connections** through SSH.

HTB calls this:

> **SSH Tunneling over a SOCKS Proxy**.

---

# SOCKS Proxy

SOCKS = **Socket Secure**

Purpose

- Forward arbitrary TCP traffic
    
- Bypass firewall restrictions
    
- Reach internal networks
    
- Hide the attacker's IP behind the pivot host
    

Unlike local forwarding, SOCKS lets **many different applications** use the tunnel.

---

# SOCKS4 vs SOCKS5

|SOCKS4|SOCKS5|
|---|---|
|No authentication|Authentication supported|
|TCP only|TCP + UDP|
|Simpler|More features|

HTB notes that SOCKS5 adds authentication and UDP support.

---

# Enable Dynamic Forwarding

```bash
ssh -D 9050 ubuntu@10.129.202.64
```

Meaning

```text
SSH

↓

Create SOCKS Listener

↓

127.0.0.1:9050
```

Everything sent to

```text
localhost:9050
```

is forwarded into the internal network through the pivot host.

---

# ProxyChains

ProxyChains forces applications to use the SOCKS proxy.

Configuration

```bash
tail -4 /etc/proxychains.conf
```

Important entry

```text
socks4 127.0.0.1 9050
```

This tells ProxyChains to route traffic through the SSH-created SOCKS listener.

---

# Scanning Through the Tunnel

Example

```bash
proxychains nmap -v -sn 172.16.5.1-200
```

Traffic flow

```text
Nmap

↓

ProxyChains

↓

127.0.0.1:9050

↓

SSH Tunnel

↓

Ubuntu Pivot

↓

172.16.5.0/23
```

---

# Important Limitation

HTB points out:

**ProxyChains only supports full TCP connect scans.**

Use:

```bash
-sT
```

Do **not** use:

```bash
-sS
```

Reason:

ProxyChains cannot process partial TCP packets used by SYN scans.

---

# Recommended Scan

```bash
proxychains nmap -Pn -sT 172.16.5.19
```

Options

|Option|Meaning|
|---|---|
|`-Pn`|Skip host discovery (no ICMP ping)|
|`-sT`|Full TCP Connect Scan|

Windows Defender commonly blocks ICMP, so `-Pn` is recommended.

---

# Ports Found

The scan discovers:

```text
135

139

445

3389
```

Important services:

|Port|Service|
|---|---|
|135|RPC|
|139|NetBIOS|
|445|SMB|
|3389|RDP|

These indicate a Windows target.

---

# Metasploit Through ProxyChains

Launch Metasploit

```bash
proxychains msfconsole
```

Every connection from Metasploit now travels through the SSH SOCKS tunnel.

---

# RDP Scanner Module

Search

```bash
search rdp_scanner
```

Use

```bash
use auxiliary/scanner/rdp/rdp_scanner
```

Run

```bash
set rhosts 172.16.5.19
run
```

Result

```text
Detected RDP

Windows Server

No NLA Required
```

---

# RDP Login Through the Tunnel

Command

```bash
proxychains xfreerdp \
/v:172.16.5.19 \
/u:victor \
/p:pass@123
```

Traffic

```text
xfreerdp

↓

ProxyChains

↓

SOCKS

↓

SSH Tunnel

↓

Ubuntu

↓

Windows RDP
```

After accepting the certificate, an RDP session is established through the pivot host.

---

# 📌 SSH Port Forwarding vs Dynamic Port Forwarding

|Feature|Local Port Forwarding (`-L`)|Dynamic Port Forwarding (`-D`)|
|---|---|---|
|Purpose|Access one remote service|Access an entire internal network|
|Protocol|SSH|SSH + SOCKS|
|Example|MySQL, Web Server|Nmap, Metasploit, RDP, SMB|
|Local Listener|Specific port (e.g., 1234)|SOCKS proxy (e.g., 9050)|
|Best Use|One application|Multiple tools and services|

---

# 🔥 Important Commands

```bash
# Scan SSH server
nmap -sT -p22,3306 <target>

# Local port forwarding
ssh -L 1234:localhost:3306 ubuntu@<target>

# Verify forwarding
netstat -antp | grep 1234
nmap -sV -p1234 localhost

# Forward multiple ports
ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@<target>

# Create SOCKS proxy
ssh -D 9050 ubuntu@<target>

# Configure ProxyChains
tail -4 /etc/proxychains.conf

# Scan through SOCKS tunnel
proxychains nmap -Pn -sT 172.16.5.19

# Start Metasploit through the tunnel
proxychains msfconsole

# Connect to RDP
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

---

# ⭐ HTB Exam Notes (Must Remember)

- **Port Forwarding** redirects traffic from one port to another.
    
- **SSH Local Port Forwarding (`-L`)** forwards a **specific remote service** (e.g., MySQL) to your local machine.
    
- **Dynamic Port Forwarding (`-D`)** creates a **SOCKS proxy** that allows many applications to pivot through a compromised host.
    
- **ProxyChains** forces applications such as Nmap, Metasploit, and xfreerdp to use the SOCKS tunnel.
    
- **Use `-sT` instead of `-sS`** with ProxyChains because SOCKS proxies cannot forward partial TCP packets.
    
- **Use `-Pn`** when scanning Windows hosts through ProxyChains because ICMP echo requests are often blocked by Windows Defender Firewall.
    
- A **dual-homed pivot host** (multiple NICs) is essential for reaching otherwise inaccessible internal networks.