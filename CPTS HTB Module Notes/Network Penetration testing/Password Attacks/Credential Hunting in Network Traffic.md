# What is Credential Hunting in Network Traffic?

Credential Hunting in Network Traffic is the process of **capturing and analyzing network packets** to discover:

- Usernames
    
- Passwords
    
- Session Tokens
    
- Authentication Headers
    
- NTLM Hashes
    
- Kerberos Hashes
    
- SNMP Community Strings
    
- API Keys
    
- Credit Card Numbers
    

Unlike credential hunting on disk, this technique focuses on **credentials traveling across the network**.

---

# Why is Network Traffic Valuable?

Whenever two systems communicate,

credentials may travel through the network.

If encryption is missing,

an attacker can read them directly.

```text
            User Login
                 │
                 ▼
        Username + Password
                 │
        ┌────────┴────────┐
        │                 │
        ▼                 ▼
   HTTPS/TLS         HTTP (Plaintext)
        │                 │
        ▼                 ▼
 Encrypted Data      Readable Credentials
```

---

# Why Does This Still Matter?

Today most organizations use:

✔ HTTPS

✔ SSH

✔ SFTP

✔ IMAPS

✔ LDAPS

However,

many organizations still have

- Legacy applications
    
- Old printers
    
- Network devices
    
- Internal applications
    
- Test environments
    

using plaintext protocols.

These become excellent targets during internal penetration tests.

---

# Common Plaintext Protocols

|Plaintext Protocol|Secure Version|Purpose|
|---|---|---|
|HTTP|HTTPS|Web Traffic|
|FTP|FTPS / SFTP|File Transfer|
|SNMP|SNMPv3|Network Device Management|
|POP3|POP3S|Email Retrieval|
|IMAP|IMAPS|Email Access|
|SMTP|SMTPS|Sending Email|
|LDAP|LDAPS|Directory Services|
|RDP|RDP with TLS|Remote Desktop|
|DNS|DoH|Name Resolution|
|SMB|SMB over TLS|File Sharing|
|VNC|TLS Enabled VNC|Remote Desktop|

---

# Plaintext vs Encrypted

```text
              Authentication
                     │
      ┌──────────────┴───────────────┐
      │                              │
      ▼                              ▼
 HTTP Login                     HTTPS Login
      │                              │
username=test                 TLS Encryption
password=test                      │
      │                             ▼
Visible in Packets            Cannot Read Directly
```

---

# Credential Hunting Workflow

```text
Network Access
      │
      ▼
Capture Packets
      │
      ▼
Open Wireshark
      │
      ▼
Apply Filters
      │
      ▼
Find Authentication Packets
      │
      ▼
Extract Credentials
```

---

# Wireshark

Wireshark is one of the most popular packet analyzers.

Capabilities

✔ Live Capture

✔ Offline PCAP Analysis

✔ Protocol Analysis

✔ Packet Filtering

✔ Stream Reconstruction

---

# Wireshark Architecture

```text
Network Interface
        │
        ▼
Packet Capture
        │
        ▼
Wireshark
        │
 ┌──────┼──────────────┐
 │      │              │
 ▼      ▼              ▼
Filters Streams   Packet Decode
        │
        ▼
Credential Hunting
```

---

# Important Wireshark Filters

---

## Filter by IP Address

```wireshark
ip.addr == 56.48.210.13
```

Shows all packets involving this IP.

---

## Filter HTTP

```wireshark
http
```

Displays only HTTP traffic.

---

## Filter Port

```wireshark
tcp.port == 80
```

Shows traffic on TCP port 80.

---

## DNS

```wireshark
dns
```

Useful for discovering

- Hostnames
    
- Internal Servers
    
- Domains
    

---

## ICMP

```wireshark
icmp
```

Useful for

- Ping Sweeps
    
- Host Discovery
    

---

## SYN Packets

```wireshark
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

Useful for detecting

- Port Scans
    
- New TCP Connections
    

---

## POST Requests

```wireshark
http.request.method == "POST"
```

One of the most important filters.

Why?

Most login forms use

```text
POST
```

instead of

```text
GET
```

Meaning usernames and passwords may appear inside POST requests.

---

## TCP Stream

```wireshark
tcp.stream eq 53
```

Displays one complete TCP conversation.

Very useful for

- Login Sessions
    
- FTP
    
- HTTP Authentication
    

---

## MAC Address

```wireshark
eth.addr == 00:11:22:33:44:55
```

Filters packets involving a specific network card.

---

## Source & Destination

```wireshark
ip.src == 192.168.24.3 && ip.dst == 56.48.210.3
```

Shows communication between two hosts.

---

# Wireshark Filter Summary

|Filter|Purpose|
|---|---|
|ip.addr|Specific IP|
|tcp.port|Port Filtering|
|http|HTTP Traffic|
|dns|DNS Queries|
|icmp|Ping|
|tcp.flags.syn|Connection Attempts|
|POST|Login Forms|
|tcp.stream|Entire Conversation|
|eth.addr|MAC Address|
|ip.src/ip.dst|Host Communication|

---

# Searching Inside Packets

Wireshark supports searching packet contents.

Example

```wireshark
http contains "passw"
```

This searches packets containing

```text
passw
```

which commonly matches

```text
password

passwd

passw
```

---

# Search Workflow

```text
Captured Packets
        │
        ▼
Search

"passw"

        │
        ▼
HTTP POST
        │
        ▼
Username

Password
```

---

# Example Login Packet

```text
POST /login HTTP/1.1

username=test

password=Password123
```

Since HTTP is plaintext,

everything is visible.

---

# Following TCP Stream

Instead of viewing individual packets,

Wireshark allows

```text
Follow

↓

TCP Stream
```

Diagram

```text
Client
     │
     ▼
HTTP Request
     │
     ▼
HTTP Response
     │
     ▼
Entire Conversation
```

---

# Credential Hunting Process

```text
HTTP Traffic
      │
      ▼
POST Requests
      │
      ▼
username=
password=
      │
      ▼
Recovered Credentials
```

---

# Pcredz

Pcredz is an automated credential extraction tool.

Instead of manually searching,

Pcredz parses PCAP files automatically.

---

# What Can Pcredz Extract?

✔ Credit Card Numbers

✔ POP Credentials

✔ SMTP Credentials

✔ IMAP Credentials

✔ FTP Credentials

✔ HTTP Basic Authentication

✔ HTTP Forms

✔ SNMP Community Strings

✔ NTLMv1

✔ NTLMv2

✔ Kerberos Hashes

✔ SMB Credentials

✔ LDAP Authentication

✔ MSSQL Authentication

---

# Pcredz Workflow

```text
PCAP File
     │
     ▼
Pcredz
     │
 ┌───┼──────────────────────┐
 │   │                      │
 ▼   ▼                      ▼
FTP HTTP              Kerberos
 │                      │
 ▼                      ▼
Credentials         Hashes
```

---

# Running Pcredz

Command

```bash
./Pcredz -f demo.pcapng -t -v
```

---

# Command Breakdown

|Option|Meaning|
|---|---|
|-f|PCAP File|
|-t|Parse Traffic|
|-v|Verbose Output|

---

# Example Output

SNMP

```text
Found SNMPv2 Community string:

s3cr...
```

---

FTP

```text
FTP User:

admin

FTP Pass:

Password123
```

---

# Why SNMP Matters

Many organizations still use

```text
SNMPv2
```

Community Strings

Examples

```text
public

private

admin

network

secret
```

If recovered,

they may allow monitoring or configuration of network devices.

---

# FTP Credentials

FTP sends

```text
USER admin

PASS Password123
```

without encryption.

Wireshark or Pcredz can recover them immediately.

---

# HTTP Basic Authentication

HTTP Basic Auth

```text
Authorization:

Basic YWRtaW46UGFzc3dvcmQ=
```

Base64 is **NOT encryption**.

It can be decoded easily.

---

# NTLM Hashes

Pcredz can recover

✔ NTLMv1

✔ NTLMv2

These can later be used for

- Password Cracking
    
- Relay Attacks
    
- Pass-the-Hash
    

---

# Kerberos

Pcredz also extracts

```text
AS-REQ

etype 23
```

These hashes can be cracked offline.

---

# Complete Attack Flow

```text
Network Access
      │
      ▼
Capture Traffic
      │
      ▼
Wireshark
      │
      ▼
Apply Filters
      │
      ▼
Search "passw"
      │
      ▼
Find Login Request
      │
      ▼
Recover Credentials

──────────────

OR

──────────────

PCAP File
      │
      ▼
Pcredz
      │
      ▼
Automatic Extraction
```

---

# Wireshark vs Pcredz

|Wireshark|Pcredz|
|---|---|
|Manual Analysis|Automatic Extraction|
|Protocol Analysis|Credential Recovery|
|Live Capture|PCAP Parsing|
|Stream Analysis|Hash Extraction|
|Search Packets|Search Credentials|

---

# Important Commands

### Filter HTTP

```wireshark
http
```

---

### Filter POST

```wireshark
http.request.method == "POST"
```

---

### Search Password

```wireshark
http contains "passw"
```

---

### Filter Stream

```wireshark
tcp.stream eq 53
```

---

### Filter IP

```wireshark
ip.addr == 56.48.210.13
```

---

### Run Pcredz

```bash
./Pcredz -f demo.pcapng -t -v
```

---

# Memory Tricks

### Plaintext Protocols

```text
HTTP

FTP

POP3

IMAP

SMTP

LDAP

SNMP

↓

Credentials May Be Visible
```

---

### Wireshark Formula

```text
Capture

↓

Filter

↓

Search

↓

Credentials
```

---

### Pcredz Formula

```text
PCAP

↓

Pcredz

↓

Passwords

Hashes

Community Strings

Credit Cards
```

---

# HTB / Exam Questions

### Which protocol is the encrypted version of HTTP?

✅ **HTTPS**

---

### Which Wireshark filter displays only HTTP traffic?

```wireshark
http
```

---

### Which filter shows only HTTP POST requests?

```wireshark
http.request.method == "POST"
```

---

### Which filter searches HTTP packets containing the word "passw"?

```wireshark
http contains "passw"
```

---

### Which Wireshark filter follows a specific TCP conversation?

```wireshark
tcp.stream eq <number>
```

---

### Which tool automatically extracts credentials from PCAP files?

✅ **Pcredz**

---

### Which protocol commonly exposes usernames and passwords in plaintext?

✅ **FTP** (when unencrypted)

---

### Which authentication hashes can Pcredz extract?

✅ **NTLMv1**, **NTLMv2**, and **Kerberos (AS-REQ etype 23)**

---

### Which protocol may reveal community strings?

✅ **SNMPv2**

---

# 🔥 1-Minute Revision Sheet

```text
Credential Hunting (Network)

          │
          ▼
Capture Packets
          │
          ▼
Wireshark

Important Filters
─────────────────
http
http.request.method=="POST"
http contains "passw"
tcp.stream
dns
icmp

Protocols
─────────
HTTP
FTP
POP3
IMAP
SMTP
LDAP
SNMP

Tool
────
Pcredz

Extracts
────────
FTP Credentials
HTTP Credentials
SMTP
POP
IMAP
SNMP Strings
NTLMv1/v2
Kerberos
Credit Cards

Workflow
────────
Capture
→ Filter
→ Search
→ Recover Credentials
```

These notes preserve the important protocols, Wireshark filters, Pcredz usage, commands, and concepts from your HTB material while adding structured explanations, diagrams ("pics"), workflows, comparisons, memory tricks, and HTB/interview-focused summaries.