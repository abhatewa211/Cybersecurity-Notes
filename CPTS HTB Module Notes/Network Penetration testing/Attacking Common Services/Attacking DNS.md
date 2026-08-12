# 1. 🌐 What Is DNS?

**DNS — Domain Name System** translates human-readable domain names into numerical IP addresses.

For example:

```text
hackthebox.com
       ↓
104.17.42.72
```

DNS is fundamental because almost every network application relies on name resolution.

### Default DNS ports

```text
UDP/53  → Normal DNS queries
TCP/53  → Used when required, including larger transfers
```

DNS has always supported both UDP and TCP, but **UDP is normally the default**. DNS can fall back to TCP when the response cannot fit appropriately into a UDP packet.

---

# 2. 🧠 DNS in Simple Terms

Think of DNS as the Internet's phonebook:

```text
User enters:
www.example.com
        │
        ▼
      DNS
        │
        ▼
IP Address
        │
        ▼
Web Server
```

Without DNS, users would need to remember IP addresses instead of domain names.

---

# 3. 🔥 Why Is DNS Important During Pentesting?

DNS can reveal a surprising amount of information about an organization.

It may help identify:

- Internal/external hosts
    
- Subdomains
    
- DNS servers
    
- Mail servers
    
- Cloud services
    
- Third-party providers
    
- Infrastructure naming conventions
    
- Potentially forgotten systems
    
- CNAME relationships
    
- Internal services
    

The source emphasizes that DNS information can help us understand how an organization operates and what services it provides.

---

# 4. 🔎 DNS Enumeration

The first step is generally to identify whether DNS is available and determine what software/version is running.

The source recommends:

```bash
nmap -p53 -Pn -sV -sC <TARGET>
```

Example:

```bash
nmap -p53 -Pn -sV -sC 10.10.110.213
```

Example output:

```text
PORT    STATE  SERVICE     VERSION
53/tcp  open   domain      ISC BIND 9.11.3-1ubuntu1.2
```

---

# 5. 🧰 Nmap Command Breakdown

```bash
nmap -p53 -Pn -sV -sC <TARGET>
```

|Option|Meaning|
|---|---|
|`-p53`|Scan port 53|
|`-Pn`|Treat host as online; skip host discovery|
|`-sV`|Version detection|
|`-sC`|Default Nmap scripts|

### Important

```text
DNS
 ↓
Port 53
 ↓
Nmap -sC -sV
 ↓
Service + Version + Basic Enumeration
```

---

# 6. 🗺️ DNS Attack / Enumeration Map

![Image](https://images.openai.com/static-rsc-4/TNsBeRxbxTzZo0LUBO6h8C0FrLbIaIlFBFVG602iHjgHxheSGJA95MV56y2erE1ytkJtENPG-l9T9XOOGSu63ruY67PvBBZyOlTLTY3Ibgl_LxTtTnS-7lz1Wo4dsRxVjkdxpH0hS0a-njmqup_B87PkkjDCyFvEHt5jgGy50oR63HjB9hMAJLKp04zRxAb-?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/H5CcUTjQtRy-eaOqfanBbXCR7JVzgzzJ56XWy9MHsLiZHL-6cWvlXbr5kklQSLctsHI_B0AaZb252zCgIlCHpaueYF8dlw8Ho8_IZ3Wh1Hwjl5kkcmobRxXn-GQhMn95AEZf0rCLbyIgWdnAPVnChPTw3xctWFBZzA5_4sZ7Th3YizQvAAfZ3SNpFU7eafmi?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/RUBhl4wpLy1N_cPL--w239q6YpC-4iZ0_LS9vFm57Rg6PgTBG4SYNStGip7kHJfMpNFaLSuki2nKOMY6gzCQze9PFJ485p2kg-StXfErP43NoLxg6hUF4GtuuaSJuEiNrtONkTkh4xP8c2VtlEg4pII_aV27BFqAUMvl71IkWMskIPh4oEuaK6lE_7ZucrrQ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/aZiywHB0QS_QjUMJA5G7GPFlt6eS7dXgbzssyY7t3tnPzvputHbBjFKi71b5jf342o3PG_EH1p3HJi8e6KDZOvkfh9-V4WWhBCwjit3OxoMCB27n0DP_0oJWFRrcuNdAu1pUEEite7GIrm0nT3tPZKio2Nfd_Lhr1SbErFV_9_1LPwyPcEjd3qViRB1H9HqH?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Zen8nwQLkpyyvBHfxzFKSfLDBbDg64K7Ei31bs7C6iU5YFweBRckm6czcxj5IJhjGeMoT9Xtbvt_aU-2BfGy-TULj_sN7QcIwtpouCHNdEAVXs1Wd9DZN6I5MY2CpSZLJje4nRsloiCGxW3cmBg9-E5CShaw60nKfqGI1Zik4Y7y2Ieop59O1GWbXffiZl9T?purpose=fullsize)

```text
                         DNS
                          │
          ┌───────────────┼────────────────┐
          │               │                │
          ▼               ▼                ▼
     Enumeration     Zone Transfer    Subdomains
          │               │                │
          │               ▼                ▼
          │             AXFR         CNAME Records
          │                                │
          │                                ▼
          │                         Subdomain Takeover
          │
          ▼
    DNS Information
          │
          ▼
     Attack Surface
          │
          ├───────────────┐
          ▼               ▼
     DNS Spoofing     Further Attacks
```

---

# 7. 🔥 DNS Zone Transfer

A **DNS zone** is a portion of the DNS namespace managed by a particular organization or administrator.

For example:

```text
example.com
 ├── www.example.com
 ├── mail.example.com
 ├── vpn.example.com
 ├── support.example.com
 └── internal.example.com
```

DNS servers can use **zone transfers** to copy zone information between DNS servers.

---

# 8. ⚠️ Why Can Zone Transfer Be Dangerous?

A properly configured DNS server should restrict which systems are allowed to perform a zone transfer.

If improperly configured, an unauthorized user may request the zone information.

The source emphasizes that DNS zone transfers traditionally do not require authentication themselves, so **access control must be configured correctly**.

---

# 9. 🧠 Zone Transfer Concept

```text
DNS Server
    │
    │ Zone Transfer
    ▼
Entire DNS Zone
    │
    ├── www
    ├── mail
    ├── admin
    ├── support
    ├── hr
    └── internal hosts
```

Instead of discovering hosts individually, an exposed zone transfer can reveal a large portion of the organization's DNS namespace at once.

---

# 10. 📡 UDP vs TCP During Zone Transfer

Normal DNS:

```text
Client
  │
  │ UDP/53
  ▼
DNS Server
```

Zone transfer:

```text
DNS Server
    │
    │ TCP/53
    ▼
Other DNS Server
```

The source specifically notes that zone transfers use **TCP** for reliable data transmission.

### ⭐ Memorize

```text
Normal DNS → UDP/53
Zone Transfer → TCP/53
```

---

# 11. 🧰 `dig` — AXFR

The source demonstrates the `dig` utility with the:

```text
AXFR
```

query type.

Example:

```bash
dig AXFR @ns1.inlanefreight.htb inlanefreight.htb
```

### What does AXFR mean?

```text
AXFR
 ↓
Full Zone Transfer
```

If the DNS server incorrectly permits the request, the result can contain numerous DNS records.

---

# 12. 📋 Example Zone Transfer Information

The supplied example reveals records such as:

```text
admin.inlanefreight.htb
hr.inlanefreight.htb
support.inlanefreight.htb
```

along with associated IP addresses.

Conceptually:

```text
Zone Transfer
      │
      ▼
DNS Records
      │
      ├── admin → IP
      ├── hr → IP
      ├── support → IP
      └── other records
```

This can significantly expand the attack surface.

---

# 13. 🔎 Why Zone Transfers Matter

Suppose an organization has:

```text
www.example.com
```

but the zone transfer reveals:

```text
admin.example.com
hr.example.com
support.example.com
vpn.example.com
dev.example.com
internal.example.com
```

Now the attacker has additional systems and services to investigate.

Therefore:

> **DNS enumeration is often information gathering rather than exploitation itself.**

---

# 14. 🦊 Fierce

The source also introduces:

# **Fierce**

Fierce can be used to enumerate DNS information and look for possible zone-transfer opportunities.

Example:

```bash
fierce --domain zonetransfer.me
```

The example demonstrates that Fierce can retrieve a large number of DNS records when the target permits it.

---

# 15. 🧠 Important Information in a Zone

Zone information can contain many different record types.

Examples from the supplied output include:

```text
SOA
NS
A
AAAA
MX
TXT
CNAME-related information
SRV
PTR
```

### Important record types

|Record|Purpose|
|---|---|
|`A`|IPv4 address|
|`AAAA`|IPv6 address|
|`NS`|Name server|
|`SOA`|Start of Authority|
|`MX`|Mail server|
|`TXT`|Text information|
|`SRV`|Service location|
|`PTR`|Reverse DNS|
|`CNAME`|Alias to another domain|

---

# 16. 🎯 DNS Information Can Reveal More Than Expected

The Fierce example contains interesting information such as:

```text
MX records
TXT records
Internal-looking names
Office names
Service records
Mail information
```

The important lesson is:

> **Don't ignore DNS records just because they aren't directly an IP address.**

A TXT record, MX record, or CNAME can reveal information useful for understanding the organization's infrastructure.

---

# 17. 🏴 Domain Takeover

The source next discusses:

# **Domain Takeover**

A domain takeover involves registering a domain that has expired or otherwise become available, thereby obtaining control over that domain.

Conceptually:

```text
Old Domain
     │
     ▼
Expires
     │
     ▼
Becomes Available
     │
     ▼
Attacker Registers It
     │
     ▼
Attacker Controls Domain
```

This could potentially allow malicious content hosting or phishing using the claimed domain.

---

# 18. 🔥 Subdomain Takeover

A related attack is:

# **Subdomain Takeover**

This is especially important when organizations use third-party services.

Examples mentioned in the source include:

- AWS
    
- GitHub
    
- Akamai
    
- Fastly
    
- Other CDNs/cloud services
    

---

# 19. 🧩 CNAME Records

A DNS **CNAME** maps one domain name to another.

Example from the source:

```text
sub.target.com
       │
       │ CNAME
       ▼
anotherdomain.com
```

---

# 20. 🚨 Subdomain Takeover Scenario

Imagine:

```text
support.target.com
        │
        │ CNAME
        ▼
target-service.example.com
```

The target service expires or is deleted.

But the organization's DNS record remains:

```text
support.target.com
        │
        ▼
target-service.example.com
```

If someone else can legitimately claim the abandoned destination, they may gain control over the content served through the organization's subdomain.

Conceptually:

```text
Company DNS
     │
     ▼
support.target.com
     │
     │ CNAME
     ▼
Abandoned Third-Party Resource
     │
     ▼
Claimed by Attacker
     │
     ▼
Potential Subdomain Takeover
```

The source describes this as allowing control over the subdomain until the DNS record is corrected.

---

# 21. 🔎 Subdomain Enumeration

Before assessing a possible subdomain takeover, we need to discover the organization's subdomains.

The source introduces:

# **Subfinder**

Subfinder can gather subdomains from open sources.

Example:

```bash
./subfinder -d inlanefreight.com -v
```

---

# 22. 🧰 Subfinder

Conceptually:

```text
Target Domain
     │
     ▼
Subfinder
     │
     ├── Public Sources
     ├── DNS-related sources
     └── Other sources
     │
     ▼
Subdomain List
```

Example results in the source include:

```text
www.inlanefreight.com
ns1.inlanefreight.com
ns2.inlanefreight.com
support.inlanefreight.com
```

---

# 23. 🧰 Sublist3r

The source also mentions:

# **Sublist3r**

It can be used for subdomain enumeration and can perform brute-force-style discovery using a wordlist.

Conceptually:

```text
Wordlist
   │
   ▼
Sublist3r
   │
   ▼
Potential Subdomains
   │
   ▼
DNS Resolution
```

---

# 24. 🐍 Subbrute

Another tool introduced is:

# **Subbrute**

Subbrute is particularly useful for internal penetration tests because it can:

- Use self-defined DNS resolvers
    
- Perform DNS brute forcing
    
- Work in environments without Internet access
    

---

# 25. Subbrute Example

The source demonstrates:

```bash
git clone https://github.com/TheRook/subbrute.git
cd subbrute
echo "ns1.inlanefreight.com" > ./resolvers.txt
./subbrute.py inlanefreight.com -s ./names.txt -r ./resolvers.txt
```

The resulting enumeration discovers names such as:

```text
inlanefreight.com
ns2.inlanefreight.com
www.inlanefreight.com
ms1.inlanefreight.com
support.inlanefreight.com
```

---

# 26. 🔗 CNAME Enumeration

Once subdomains are identified, we can investigate their DNS records.

The source uses:

```text
nslookup
host
```

For example:

```bash
host support.inlanefreight.com
```

Result:

```text
support.inlanefreight.com is an alias for inlanefreight.s3.amazonaws.com
```

---

# 27. ☁️ Cloud Service Takeover Scenario

Here the important relationship is:

```text
support.inlanefreight.com
            │
            │ CNAME
            ▼
inlanefreight.s3.amazonaws.com
```

The source then describes a situation where the target service returns:

```text
NoSuchBucket
```

This can indicate that the referenced cloud resource may no longer exist and therefore warrants investigation for potential subdomain takeover.

### Important pentesting mindset

A dangling CNAME does **not automatically prove** a takeover.

It should be:

```text
CNAME Found
    ↓
Target Resource Identified
    ↓
Resource Exists?
    ↓
Service-Specific Verification
    ↓
Potential Takeover?
```

---

# 28. 📚 can-i-take-over-xyz

The source recommends:

**can-i-take-over-xyz**

as a reference for determining whether particular third-party services are potentially vulnerable to subdomain takeover.

It provides:

- Service information
    
- Vulnerability conditions
    
- Assessment guidance
    

---

# 29. 🧠 Subdomain Takeover Attack Chain

```text
Target Domain
      │
      ▼
Subdomain Enumeration
      │
      ▼
Find CNAME
      │
      ▼
Identify Third-Party Service
      │
      ▼
Check Whether Resource Exists
      │
      ▼
Resource Missing / Abandoned?
      │
      ▼
Service-Specific Verification
      │
      ▼
Potential Subdomain Takeover
```

---

# 30. 🧪 DNS Spoofing

The next major attack discussed is:

# **DNS Spoofing**

DNS spoofing is also commonly called:

# **DNS Cache Poisoning**

The basic idea is to cause legitimate DNS information to be replaced or supplemented with false information so that traffic is redirected to an attacker-controlled destination.

---

# 31. 🎭 DNS Spoofing Concept

Normally:

```text
victim
  │
  │ DNS query
  ▼
DNS Server
  │
  │ Legitimate response
  ▼
Correct IP
  │
  ▼
Legitimate Website
```

With DNS spoofing:

```text
victim
  │
  │ DNS query
  ▼
Fake / manipulated DNS response
  │
  ▼
Attacker IP
  │
  ▼
Fake / malicious destination
```

---

# 32. 🕵️ DNS Spoofing Attack Paths

The source identifies two broad scenarios.

### 1. MITM

An attacker intercepts communication between:

```text
User
  ↕
DNS Server
```

and provides false DNS information.

### 2. DNS Server Compromise

If an attacker gains control over a DNS server, they may modify DNS records directly.

---

# 33. 🏠 Local DNS Cache Poisoning

The source focuses on a local-network scenario.

Tools mentioned include:

```text
Ettercap
Bettercap
```

These can be used in MITM scenarios to manipulate DNS responses.

---

# 34. 🧰 Ettercap DNS Spoofing Concept

The source demonstrates configuring:

```text
/etc/ettercap/etter.dns
```

with mappings such as:

```text
inlanefreight.com      A   192.168.225.110
*.inlanefreight.com    A   192.168.225.110
```

Conceptually:

```text
inlanefreight.com
       │
       │ Fake DNS Response
       ▼
192.168.225.110
       │
       ▼
Attacker-Controlled Host
```

---

# 35. 🖼️ DNS Spoofing Visualization

![Image](https://images.openai.com/static-rsc-4/1moIGxHaeVL8NNmFHmSoedI85H8Vtuy5cWZAovKnrmH1c_MfYkO2XTmFETQqwc3Hia9GVZ3LYSKizZWGURZKNDyqvD_sXDDMPerb4TZtHvI5KL8Ofy5G6JeNdRKZWR8ItYg-EbRW7nDB-plDOEvA7N-0u2KsJE2E_l8QYABubKGeVY8Nj2vwyqmqlInGBGlP?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Mw_TVuX_C6CVvPIMap3WUI3zncM-CKRhAVP5XfCYaAHcjZcVTev9LnoA8iXYmHUep3y67_BEgjKofcNTGIji7B1t-BSX7h3onoq9AZY9zWPPS-1DRUiN66qDltc1IvDheYzq0UwZ2WPrXKgAVECcUGmkPs2j16RkLL1NJO2Dttrbbdh7av9obw7zr4ipISq-?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/5dFLyrxn5RDqJyIzXZ3-IX235ik-3TgR5_hfgif-PMzs-vKuRuYmh8nYOAY-y5Bni8srIoo7cKJSSAqXeG1lyXThFBrloC5AfMK0lmTV1M5FahmKhleRJIuyWA9eN6DunIbgk5fuiJLCSG2TZ4rDvfGR4Yz2cA6H15f4eYZVds4usv0PSRwn-PnFlBaxOEN7?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/0YGbbw6_FOTc4PuZYtpt8RaNYUtt3d0qCdZT6zFls3kBQ2iQGUQUzPNpWFqcDDgbVJLDYrF9yMKlpbWwzYk1s3_72RqxpyxrBm7DyeOECflKOghu1n3PoO4PHroW7vUqmtWPHZs4hAnu91NPUw3S8XfhZLX5KdCPz_c0XfQgiAfqmGcyXH2AepgRpwh61Mby?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/nm1iwQzkAXlhXT41QDzFIjdpamsDY39rc4PkHLo254Ouz-lDChSsOm6hyFpxN6Wno7DrikJDmPSEIKjg916iYJxT6vhHZP1dfc-O9voKp1qUG81JkJdTBDYjaH-wyIlYlGn4zJ-glebwnUModtXb0_Y7J63ihPCd7NYbw0A3ViWmPd119Mw6N_8_etAcbEf7?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/U0mpXRi5FTdKC9RjNJ3eyZIC0IX7ZZw3-fRyFNKDcVcrgkAfwDHGulQUeIAT9dCI5A4bzqU3WOfQRo58BKbxOm9UhYq8A912kJJcGDriy_iZw-i9aJ0C_zQ_hBDAtHPIIwGasNRoa61XsyZPow_4SUwwg9NSZJ53J51X56P9uLUpQuML44OKc8iTTevJ55Tk?purpose=fullsize)

```text
                 ┌──────────────┐
                 │    Victim    │
                 └──────┬───────┘
                        │
                 DNS Request
                        │
                        ▼
                ┌───────────────┐
                │    Attacker   │
                │     MITM      │
                └──────┬────────┘
                       │
             Fake DNS Response
                       │
                       ▼
              Attacker IP Address
                       │
                       ▼
                Fake Web Server
```

---

# 36. 🎯 Ettercap Targeting Concept

The source describes using Ettercap to:

1. Scan for live hosts.
    
2. Identify the victim.
    
3. Identify the default gateway.
    
4. Assign the victim as **Target 1**.
    
5. Assign the gateway as **Target 2**.
    
6. Activate the `dns_spoof` plugin.
    

Conceptually:

```text
Victim
  │
  │
  ▼
Attacker / MITM
  │
  │
  ▼
Gateway
```

The attacker positions themselves in the communication path and provides fraudulent DNS responses.

---

# 37. 🧪 DNS Spoof Result

If successful, a victim attempting to visit:

```text
inlanefreight.com
```

could be directed to:

```text
192.168.225.110
```

instead of the legitimate server.

The source describes the victim being redirected to a fake page hosted at the attacker-controlled IP.

---

# 38. 🔎 Verifying DNS Spoofing

The source demonstrates checking the result with:

```cmd
ping inlanefreight.com
```

The expected spoofed resolution becomes:

```text
Pinging inlanefreight.com [192.168.225.110]
```

Conceptually:

```text
DNS Query
   ↓
inlanefreight.com
   ↓
192.168.225.110
   ↓
Attacker Host
```

---

# 39. ⚠️ DNS Spoofing vs DNS Zone Transfer

Don't confuse these.

### Zone Transfer

```text
DNS Server
    ↓
Information Disclosure
    ↓
DNS Records
```

Goal:

> **Learn information**

---

### DNS Spoofing

```text
DNS Request
    ↓
False DNS Response
    ↓
Wrong IP
    ↓
Traffic Redirection
```

Goal:

> **Redirect traffic**

---

# 40. ⚠️ DNS Spoofing vs Subdomain Takeover

These are also different.

|Attack|Main Idea|
|---|---|
|**Zone Transfer**|Obtain DNS zone information|
|**Subdomain Enumeration**|Discover subdomains|
|**Subdomain Takeover**|Gain control of an abandoned third-party resource referenced by a subdomain|
|**DNS Spoofing**|Redirect DNS resolution to a false destination|
|**Domain Takeover**|Register an expired/available domain|

---

# 41. 🧠 Complete DNS Attack Map

```text
                         DNS
                          │
         ┌────────────────┼─────────────────┐
         │                │                 │
         ▼                ▼                 ▼
   Enumeration       Zone Transfer     Subdomains
         │                │                 │
         ▼                ▼                 ▼
       Nmap             AXFR          Subfinder
                                         │
                                         ▼
                                     Sublist3r
                                         │
                                         ▼
                                      Subbrute
                                         │
                                         ▼
                                     CNAME Check
                                         │
                                         ▼
                                  Subdomain Takeover

                         DNS
                          │
                          ▼
                    DNS Spoofing
                          │
                          ▼
                         MITM
                          │
                          ▼
                  False DNS Response
                          │
                          ▼
                   Traffic Redirect
```

---

# 42. 🧰 DNS Tool Cheat Sheet

|Tool|Purpose|
|---|---|
|`nmap`|DNS service/version enumeration|
|`dig`|DNS queries and AXFR testing|
|`fierce`|DNS enumeration / zone-transfer discovery|
|`subfinder`|Subdomain enumeration|
|`Sublist3r`|Subdomain discovery/brute forcing|
|`Subbrute`|DNS brute forcing with custom resolvers|
|`host`|DNS record/CNAME lookup|
|`nslookup`|DNS lookup|
|`Ettercap`|MITM/DNS spoofing in the supplied scenario|
|`Bettercap`|MITM/DNS spoofing capabilities|

---

# 43. 📌 Important Commands

### DNS Enumeration

```bash
nmap -p53 -Pn -sV -sC <TARGET>
```

### AXFR

```bash
dig AXFR @<DNS_SERVER> <DOMAIN>
```

### Fierce

```bash
fierce --domain <DOMAIN>
```

### Subfinder

```bash
subfinder -d <DOMAIN> -v
```

### Subbrute

```bash
./subbrute.py <DOMAIN> -s ./names.txt -r ./resolvers.txt
```

### CNAME Lookup

```bash
host <SUBDOMAIN>
```

or:

```bash
nslookup <SUBDOMAIN>
```

---

# 44. 🔍 DNS Enumeration Methodology

When you find DNS:

```text
             DNS FOUND
                 │
                 ▼
          Identify Version
                 │
                 ▼
        Check DNS Configuration
                 │
        ┌────────┴─────────┐
        ▼                  ▼
  Zone Transfer       Subdomains
        │                  │
        ▼                  ▼
      AXFR             Enumeration
                           │
                 ┌─────────┴─────────┐
                 ▼                   ▼
             CNAMEs              IP Records
                 │
                 ▼
         Third-Party Services
                 │
                 ▼
       Potential Takeover?
```

---

# 45. 🧠 What Information Should You Look For?

When examining DNS, don't only look for IP addresses.

Look for:

### Infrastructure

```text
www
mail
vpn
admin
support
dev
test
internal
```

### DNS infrastructure

```text
NS
SOA
```

### Email

```text
MX
```

### Service discovery

```text
SRV
```

### Additional information

```text
TXT
PTR
CNAME
```

---

# 46. 🎯 Why Subdomains Matter

A company might have:

```text
example.com
```

but its actual attack surface could include:

```text
www.example.com
mail.example.com
vpn.example.com
dev.example.com
test.example.com
admin.example.com
support.example.com
api.example.com
```

Therefore:

> **The root domain is only the beginning of DNS reconnaissance.**

---

# 47. 🛡️ Defensive Perspective

## Zone Transfer

Restrict zone transfers to authorized DNS servers.

```text
❌ Anyone → AXFR
```

should become:

```text
✅ Authorized DNS Server → AXFR
```

---

## Subdomain Takeover

Organizations should:

- Remove unused DNS records.
    
- Remove dangling CNAMEs.
    
- Track third-party cloud resources.
    
- Decommission DNS records when services are removed.
    

---

## DNS Spoofing

Defensive controls include:

- Secure DNS infrastructure
    
- Network segmentation
    
- Proper DNS configuration
    
- Monitoring unexpected DNS responses
    
- Protecting against MITM attacks
    
- Using secure DNS technologies where appropriate
    

---

# 48. 📝 Viva / Exam Questions

### Q1. What is DNS?

DNS translates domain names into IP addresses.

### Q2. Which ports does DNS use?

```text
UDP/53
TCP/53
```

### Q3. What is the default DNS transport?

Usually:

```text
UDP/53
```

### Q4. Why is TCP used?

Among other cases, DNS uses TCP when responses or operations require reliable transmission, including zone transfers.

### Q5. What is a DNS zone?

A portion of the DNS namespace managed by a particular organization or administrator.

### Q6. What is a DNS zone transfer?

A mechanism used to copy DNS zone information between DNS servers.

### Q7. What is AXFR?

```text
Full DNS Zone Transfer
```

### Q8. Which tool can perform AXFR queries?

```text
dig
```

### Q9. What can an improperly configured zone transfer reveal?

DNS records, hosts, subdomains, IP addresses, mail information, and other namespace information.

### Q10. What is a CNAME?

A DNS record that maps one domain name to another domain name.

### Q11. What is subdomain takeover?

A situation where an organization's subdomain points to an abandoned/claimable third-party resource that can potentially be claimed by another party.

### Q12. Name tools for subdomain enumeration.

```text
Subfinder
Sublist3r
Subbrute
```

### Q13. What is DNS spoofing?

Manipulating DNS resolution so that a domain resolves to a fraudulent or attacker-controlled destination.

### Q14. What is another name for DNS spoofing?

```text
DNS Cache Poisoning
```

### Q15. What is the role of MITM in DNS spoofing?

The attacker intercepts communication and attempts to provide false DNS responses.

### Q16. Name two tools mentioned for local DNS spoofing.

```text
Ettercap
Bettercap
```

### Q17. What command can be used to inspect a CNAME?

```bash
host <DOMAIN>
```

or:

```bash
nslookup <DOMAIN>
```

---

# 49. ⚡ Quick Comparison Table

|Attack|What happens?|Main goal|
|---|---|---|
|**DNS Enumeration**|Gather DNS information|Reconnaissance|
|**Zone Transfer**|Retrieve DNS zone|Information disclosure|
|**Subdomain Enumeration**|Discover subdomains|Expand attack surface|
|**Domain Takeover**|Register abandoned domain|Gain domain control|
|**Subdomain Takeover**|Claim abandoned third-party resource|Control subdomain|
|**DNS Spoofing**|Return false DNS information|Redirect traffic|

---

# 50. 🏆 One-Minute Revision

```text
                         DNS
                          │
                     UDP/TCP 53
                          │
                          ▼
                    ENUMERATION
                          │
                          ▼
                  Nmap -sC -sV
                          │
            ┌─────────────┴─────────────┐
            ▼                           ▼
      Zone Transfer               Subdomains
            │                           │
            ▼                           ▼
          AXFR                     Subfinder
            │                     Sublist3r
            │                     Subbrute
            │                           │
            ▼                           ▼
      DNS Information                 CNAME
                                      │
                                      ▼
                              Third-Party Service
                                      │
                                      ▼
                             Potential Takeover

                          DNS
                           │
                           ▼
                     DNS Spoofing
                           │
                           ▼
                          MITM
                           │
                           ▼
                    Fake DNS Response
                           │
                           ▼
                    Traffic Redirect
```

## 🔥 The key things to memorize

```text
DNS              → UDP/53 + TCP/53

Zone Transfer    → AXFR
                  → TCP
                  → Information disclosure

Subdomain Enum   → Subfinder
                  → Sublist3r
                  → Subbrute

CNAME            → Alias to another domain

Subdomain
Takeover         → Dangling/abandoned third-party resource

DNS Spoofing     → False DNS response
                  → Traffic redirection

Tools            → dig, fierce, host, nslookup,
                  → subfinder, sublist3r, subbrute,
                  → Ettercap, Bettercap
```

### 🧠 Ultimate memory chain

> **Find DNS → Enumerate → Check AXFR → Discover subdomains → Inspect CNAMEs → Identify third-party dependencies → Assess takeover possibilities → Understand DNS spoofing/MITM.**

The uploaded material closes by noting that these are only a few examples of common DNS attacks, with more advanced attacks covered in later modules.