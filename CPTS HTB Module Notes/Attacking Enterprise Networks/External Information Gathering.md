![Image](https://images.openai.com/static-rsc-4/2cKcxYwODMGH4q2RyI2InWKcFobP-XMLg-fkmqArkh5qFusKOl_eKm2VnBkERD7EjL7WQuSMoiFxd-YyeWM-Qqv1Z0fNGfT3ALdaFNnFOBrBv7uO8jbPYmm0j03jrLzdEgqanXcVPPqytkuDJcKHi6_-WcTqPlxzXXHuXn2D7ilQrD07OlhQ5eRisFRGf88B?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/rUjMY9eorMtjzc1nH_bUbuwiPRtpCef2vPc1x0VvAGUKDcGMguSLFqJwCcynGVYQM_uVTuiEj-atUSEi6Ssl_M0Hoo9Moc2pZ6QMWCIxIUyfozNmVLPjgLp9D2VKv_FPzBuqU27q6bEAjXjCBv_kjTI8apr8IJtqPhKxqTn4fUEv-eBn7eMVb6nTQ4kecvcL?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/zxqfkxV_rvNEM_Ezl_K3HPIqwZWxVgxcDr_E-GFrL7aH2UfqbyUQrmsLrbfGGVG1FmwGaDGKKN40c2ipPVP2tYPhwbrkDkILDGyjyfQm6C4Wm9nj0fxGO3mSF4XYOhWzawTfn6Ogop5qH3ohoalcyB4pSHG3bln3QuGg4t8cH5EtPDEZumYKV7HqObha9FGv?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/4HF7c_69Acu4NXrh1vYW0Wt7ly8LHbpUWUWgspmHThkZ8HxFoutPRmklHobfAmU2WNsxyTx6nApeXN2N5ugcMioLCP6SC9WkY02FgsClKzwFwjWfzMHynpIy8iaMOrFVD0XzJ2iqSY2w6MqiDecSeeg_aOHCkdjJXuruLdRb9kX9wyrJr-epDC06k99hRrwa?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/w8XR5VSt-XckEVD8EKtsknhRXuqm8AUHk2oqN0aaHntLDQILkCN0lJF8lmqmRt0Z73DXRMkyTn7qsKJtuNzKfvL1DhWyaJFqJ80BmOXbtkfoJxAMjDy-UcEkKGHdQEoacZbAEq63Fqbf3n9bPxLDjCuVNBsxEFayYrcDiLnTRaj0mKhNzJbqRWi2l2rk_aZJ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/yd6AaSNu0G5YNqlRF8dNuquANdyYqK6NckDkEgg7LTF33bE5IQTNX3KCv46QAcN_SLZytk2wmhrzEXJV2ND0YkbHY7IURXS70RbnfRmRmFW5XHTRy5QD7tvZRCHGXmi_u5d0qV7rwHoP9YsT3SyWRk66ZsBDXMi52vc43Ji0RcSp_RFRYKHHoHXfbNgEbYNM?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/NSrP5M-HvYpbqI74Nc2zkrpK7RTARlEG6ROZRlFOelkLCm-gRaV6R10NDTQswRHks238-kbmjXgvoVoLCD5zXARPGalo6J6zOnWXHGH7hLQbv0rz6QkyRXyZr1uOVWmzqiwahpsnmj3f6zkBnsqJ8kRY2jIRhGyv1H9scXznmzuNf4mFDghVzyn-W_H8rsvp?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/GI9sVPBIpuf1quOOn1pU3eObPbwLWrPSzfdhurL8s1elD1cjEfQ8Avh6x3q4sSZto2N9EGNx2Zj8XvWG4aPlVz08YxWwtNXe-9rai-WDtIi9d9FP63OOKP6NIReMHhOV174_vBc6CMK7EORLnnAO-Iojb8x5_UVHgilya1JgD_q2r4q0fP_MT3cjAo0MI5y6?purpose=fullsize)

These notes are based on the provided **HTB “External Information Gathering” material**. I’ve kept the important commands, findings, terminology, and methodology intact, while reorganizing them into a detailed study format.

---

# 1. 🎯 Objective of External Information Gathering

The first stage of the external penetration test is to understand what is exposed to an attacker.

The initial goals are:

- Identify live hosts.
    
- Discover open ports.
    
- Identify running services.
    
- Determine service versions.
    
- Identify the operating system where possible.
    
- Enumerate DNS.
    
- Discover subdomains.
    
- Discover virtual hosts.
    
- Identify potentially interesting or misconfigured services.
    
- Save all results for later investigation and reporting.
    

The methodology starts broad and progressively becomes more specific:

```text
Target IP
   ↓
Port Discovery
   ↓
Service Enumeration
   ↓
Version Detection
   ↓
OS Detection
   ↓
DNS Enumeration
   ↓
Subdomain Enumeration
   ↓
VHost Enumeration
   ↓
Service-Specific Enumeration
   ↓
Potential Attack Surface
```

---

# 2. 🗺️ Initial Nmap Scan

The first action is a **quick initial Nmap scan** against the target.

The purpose is to:

> **“get a lay of the land and see what we're dealing with.”**

The scan output is also saved into the appropriate project directory.

### Command

```bash
sudo nmap --open -oA inlanefreight_ept_tcp_1k -iL scope
```

### Important options

|Option|Meaning|
|---|---|
|`sudo`|Run Nmap with elevated privileges|
|`--open`|Show only open ports|
|`-oA`|Save output in all major Nmap formats|
|`inlanefreight_ept_tcp_1k`|Output filename prefix|
|`-iL scope`|Read target(s) from the `scope` file|

The `-oA` option is especially useful during a professional assessment because it creates reusable scan output rather than relying only on terminal output.

---

# 3. 📊 Initial Scan Results

The initial scan identified:

```text
10.129.203.101
```

The host was:

```text
Host is up
```

The quick scan identified **11 open TCP ports**.

|Port|Service|
|--:|---|
|21/tcp|FTP|
|22/tcp|SSH|
|25/tcp|SMTP|
|53/tcp|DNS|
|80/tcp|HTTP|
|110/tcp|POP3|
|111/tcp|RPCbind|
|143/tcp|IMAP|
|993/tcp|IMAPS|
|995/tcp|POP3S|
|8080/tcp|HTTP Proxy / HTTP|

### Initial interpretation

This appears to be a **web server** running several additional services:

- FTP
    
- SSH
    
- SMTP
    
- POP3
    
- IMAP
    
- DNS
    
- HTTP
    
- Another HTTP-related service on port `8080`
    

---

# 4. 🧠 Why the Initial Scan Is Important

At this point, we don't immediately exploit anything.

Instead, we build an attack-surface inventory.

For example:

```text
21  → FTP
22  → SSH
25  → SMTP
53  → DNS
80  → Web
110 → POP3
111 → RPC
143 → IMAP
993 → Secure IMAP
995 → Secure POP3
8080 → Web/Proxy
```

Each service represents a potential avenue for further enumeration.

### Mental model

> **Every open port is a question, not automatically a vulnerability.**

For example:

```text
21/tcp
 ↓
What FTP software?
 ↓
What version?
 ↓
Anonymous login?
 ↓
Readable files?
 ↓
Writable directories?
 ↓
Known vulnerabilities?
```

---

# 5. 🔥 Full Port Scan + Aggressive Enumeration

While the initial scan gives us the basic picture, a **full TCP port scan** is also performed.

The material uses:

```bash
sudo nmap --open -p- -A -oA inlanefreight_ept_tcp_all_svc -iL scope
```

### Important flags

|Option|Purpose|
|---|---|
|`--open`|Display open ports|
|`-p-`|Scan all TCP ports, `1-65535`|
|`-A`|Enable aggressive detection features|
|`-oA`|Save output in multiple formats|
|`-iL scope`|Read targets from scope file|

---

# 6. ⚠️ Important: `-A` Is More Intrusive

The material specifically warns that:

> `-A` is more intrusive than simply using `-sV`.

Aggressive scanning can include:

- OS detection
    
- Version detection
    
- Script scanning
    
- Additional enumeration
    

Therefore, scripts should be considered carefully because some NSE scripts can potentially cause issues on fragile services.

### Remember

```text
-sV
 ↓
Version detection

-A
 ↓
More aggressive enumeration
 ↓
OS detection
 ↓
Version detection
 ↓
Script scanning
 ↓
Additional detection
```

For a real engagement, always consider the **Rules of Engagement** before using intrusive scanning.

---

# 7. 🖥️ Detailed Nmap Results

The full scan found the following services.

![Image](https://images.openai.com/static-rsc-4/hiOoH9xprzxezNRyqUAQ41pZ_euJp5JuSi8sgc-0m2uJuV9HBCkQpOMbeHevfIJvzG2Jk2dF7Vxvnur6Lv2vAkQvBP5DLynBaUkFvq4YrQZRdl6lNbacKHEaHov94cd3f8BhWw9tPPqi6ti2W2mRN03OOqBHFdSYI4c92zo5KDV6rpCLNwmowWujxSRHriLc?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/2cKcxYwODMGH4q2RyI2InWKcFobP-XMLg-fkmqArkh5qFusKOl_eKm2VnBkERD7EjL7WQuSMoiFxd-YyeWM-Qqv1Z0fNGfT3ALdaFNnFOBrBv7uO8jbPYmm0j03jrLzdEgqanXcVPPqytkuDJcKHi6_-WcTqPlxzXXHuXn2D7ilQrD07OlhQ5eRisFRGf88B?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/6gwcrfIPGMW4MkknggHmESqOyTvRCark2vC0muCEa2JRGNUAChXbjXlYT2YKS2YY4ZfVAlGCtBIvZPgrD1DOERkd4WUAREVbsUoc5NJkfc1oHKLscQXJm0v9gunxcaFybUq7vb7XNQXLEOnTO2vSwZAWZI_m4cPCud4pYisphFYMGTaho9ihMVxi5mw809Iz?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/sXZBJek5lKlib5CMB3zgdYooThmAUK9ZxjKtdxp3nOhGm-pMBp2F3vwC4dE-RFQ_RdkT_YStNkXkAoI4omppKiKn9JqrWQjyxUog6xowaldKmbZwSUJI4Khii0dbVDRzL3kE7ENXH-7WxmSf3t7WaLec4PVjbPiFSbYft25n6zV2WskH6bC3FSwT9wpleZJl?purpose=fullsize)

---

## Port 21 — FTP

```text
21/tcp open ftp vsftpd 3.0.3
```

The service is:

> **vsFTPd 3.0.3**

Most importantly, Nmap discovered:

```text
ftp-anon: Anonymous FTP login allowed
```

and:

```text
-rw-r--r-- 1 0 0 38 May 30 17:16 flag.txt
```

### Important finding

**Anonymous FTP access is enabled.**

This immediately becomes an interesting avenue for manual investigation.

There is also a file:

```text
flag.txt
```

---

# 8. 🔐 Port 22 — SSH

```text
22/tcp open ssh
OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
```

The service is running:

> **OpenSSH 8.2p1**

The scan also retrieved SSH host keys including:

- RSA
    
- ECDSA
    
- ED25519
    

### Enumeration questions

At this stage, consider:

```text
What version?
 ↓
Is password authentication enabled?
 ↓
Are usernames discoverable?
 ↓
Are credentials found elsewhere?
 ↓
Can discovered credentials be validated here?
```

Don't automatically perform password attacks without considering scope and authorization.

---

# 9. 📧 Port 25 — SMTP

```text
25/tcp open smtp Postfix smtpd
```

The server is running:

> **Postfix smtpd**

Nmap identified SMTP capabilities including:

```text
PIPELINING
SIZE
VRFY
ETRN
STARTTLS
ENHANCEDSTATUSCODES
8BITMIME
DSN
SMTPUTF8
CHUNKING
```

### Interesting capability

The presence of:

```text
VRFY
```

is noteworthy because SMTP enumeration may potentially reveal whether specific mailboxes/users exist, depending on server configuration.

---

# 10. 🌐 Port 53 — DNS

```text
53/tcp open domain
```

DNS is particularly interesting because the assessment involves:

```text
*.inlanefreight.local
```

and the exact subdomains were not initially provided.

Therefore:

> **DNS may help expand our understanding of the attack surface.**

This leads to the DNS Zone Transfer test.

---

# 11. 🌍 Port 80 — HTTP

```text
80/tcp open http
Apache httpd 2.4.41 ((Ubuntu))
```

The HTTP server is:

> **Apache/2.4.41 (Ubuntu)**

The page title is:

```text
Inlanefreight
```

### Initial web information

```text
Web Server: Apache
Version: 2.4.41
OS: Ubuntu
Title: Inlanefreight
```

This should immediately become another enumeration target.

---

# 12. 📬 Port 110 — POP3

```text
110/tcp open pop3 Dovecot pop3d
```

The server is running:

> **Dovecot pop3d**

The scan identified capabilities such as:

```text
SASL
TOP
PIPELINING
STLS
RESP-CODES
AUTH-RESP-CODE
CAPA
UIDL
```

---

# 13. 🔧 Port 111 — RPCbind

```text
111/tcp open rpcbind 2-4
```

Nmap identified:

```text
RPC #100000
```

The scan showed both TCP and UDP RPC information.

### Enumeration thought process

RPCbind often deserves additional enumeration because it can reveal additional RPC services.

Mental model:

```text
111/tcp
 ↓
RPCbind
 ↓
What RPC programs are registered?
 ↓
What services are exposed?
 ↓
Can they provide additional attack surface?
```

---

# 14. 📧 Port 143 — IMAP

```text
143/tcp open imap Dovecot imapd (Ubuntu)
```

The service is:

> **Dovecot IMAP**

The scan identified capabilities including:

```text
LOGIN
STARTTLS
SASL-IR
IMAP4rev1
```

---

# 15. 🔐 Port 993 — IMAPS

```text
993/tcp open ssl/imap Dovecot imapd
```

This is IMAP over SSL/TLS.

The same Dovecot service is exposed through the encrypted service.

---

# 16. 🔐 Port 995 — POP3S

```text
995/tcp open ssl/pop3 Dovecot pop3d
```

This is the encrypted POP3 service.

Nmap identified:

```text
SASL(PLAIN)
TOP
PIPELINING
CAPA
RESP-CODES
AUTH-RESP-CODE
USER
UIDL
```

---

# 17. 🚨 Port 8080 — HTTP / Potential Proxy

```text
8080/tcp open http Apache httpd 2.4.41 ((Ubuntu))
```

The server header again identifies:

```text
Apache/2.4.41 (Ubuntu)
```

But this port is especially interesting because Nmap reports:

```text
http-open-proxy: Potentially OPEN proxy.
```

and:

```text
Methods supported: CONNECTION
```

The HTTP title is:

```text
Support Center
```

### Important finding

Port `8080` deserves further investigation because Nmap has identified a:

> **Potentially open HTTP proxy**

This could become an important attack path.

---

# 18. 🐧 Operating System Identification

Nmap was not able to produce an exact OS match:

```text
No exact OS matches for host
```

However, service information suggests:

```text
Host: ubuntu
OSs: Unix, Linux
```

The CPE reported:

```text
cpe:/o:linux:linux_kernel
```

### Working conclusion

The target appears to be:

> **Ubuntu / Linux**

But remember the distinction:

```text
Nmap exact OS match
        ↓
Not available

Service information
        ↓
Ubuntu / Linux indication
```

Don't confuse an inference with a confirmed OS fingerprint.

---

# 19. 🛰️ Network Distance & Traceroute

Nmap reported:

```text
Network Distance: 2 hops
```

Traceroute:

```text
1   116.63 ms   10.10.14.1
2   117.72 ms   10.129.203.101
```

Simplified:

```text
Attacker
   │
   ↓
10.10.14.1
   │
   ↓
10.129.203.101
```

---

# 20. 📋 Service Inventory

After the detailed scan, we can summarize the attack surface:

|Port|Service|Version / Information|Interest|
|--:|---|---|---|
|21|FTP|vsftpd 3.0.3|🔴 Anonymous access|
|22|SSH|OpenSSH 8.2p1|🟠 Remote access|
|25|SMTP|Postfix|🟠 Mail enumeration|
|53|DNS|DNS service|🔴 Zone transfer|
|80|HTTP|Apache 2.4.41|🔴 Web enumeration|
|110|POP3|Dovecot|🟠 Mail service|
|111|RPCbind|RPC 2–4|🟠 RPC enumeration|
|143|IMAP|Dovecot|🟠 Mail service|
|993|IMAPS|Dovecot|🟠 Encrypted mail|
|995|POP3S|Dovecot|🟠 Encrypted mail|
|8080|HTTP|Apache 2.4.41|🔴 Potential open proxy|

This table is a useful **working attack-surface map**.

---

# 21. 🧹 Cutting Through Nmap Output

The full Nmap output contains a lot of information.

Instead of manually reviewing hundreds of lines every time, we can extract the most useful service information.

The material uses:

```bash
egrep -v "^#|Status: Up" inlanefreight_ept_tcp_all_svc.gnmap | cut -d ' ' -f4- | tr ',' '\n' | \
sed -e 's/^[ \t]*//' | awk -F '/' '{print $7}' | grep -v "^$" | sort | uniq -c \
| sort -k 1 -nr
```

### Output

```text
2 Dovecot pop3d
2 Dovecot imapd (Ubuntu)
2 Apache httpd 2.4.41 ((Ubuntu))
1 vsftpd 3.0.3
1 Postfix smtpd
1 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
1 2-4 (RPC #100000)
```

---

# 22. 🧠 Why Parse Scan Results?

This is a valuable professional habit.

Instead of looking at:

```text
hundreds/thousands of lines
```

we reduce it to:

```text
FTP
SSH
SMTP
DNS
Apache
Dovecot
RPC
```

Then investigate each service individually.

### Workflow

```text
Raw Nmap Output
       ↓
Extract Useful Data
       ↓
Build Service Inventory
       ↓
Prioritize Interesting Services
       ↓
Manual Enumeration
```

---

# 23. 🌐 DNS Zone Transfer

Because DNS is exposed on port `53`, the next logical step is to test whether a **DNS Zone Transfer** is possible.

The purpose is to discover valid subdomains.

The known primary domain is:

```text
INLANEFREIGHT.LOCAL
```

The command used is:

```bash
dig axfr inlanefreight.local @10.129.203.101
```

---

# 24. 🔥 What Is AXFR?

`AXFR` refers to a DNS **zone transfer**.

A legitimate DNS zone transfer allows DNS servers to synchronize zone information.

If improperly configured to allow unauthorized clients, it can disclose DNS records.

Conceptually:

```text
DNS Server
    │
    │ AXFR
    ↓
Complete Zone Information
    │
    ├── Hostnames
    ├── Subdomains
    ├── DNS records
    └── Infrastructure information
```

This is why unauthorized zone transfers can provide valuable reconnaissance information.

---

# 25. 📜 Zone Transfer Results

The transfer succeeds.

The output contains:

```text
inlanefreight.local
```

and multiple subdomains.

Discovered names include:

```text
blog.inlanefreight.local
careers.inlanefreight.local
dev.inlanefreight.local
gitlab.inlanefreight.local
ir.inlanefreight.local
status.inlanefreight.local
support.inlanefreight.local
tracking.inlanefreight.local
vpn.inlanefreight.local
```

The material notes that the zone transfer reveals:

> **9 additional subdomains.**

---

# 26. 🧭 Why DNS Enumeration Is Valuable

Originally, the exact subdomains were unknown.

After the successful zone transfer:

```text
Unknown Attack Surface
        ↓
DNS AXFR
        ↓
Known Subdomains
        ↓
More Hosts/Applications to Investigate
```

For example:

```text
blog
careers
dev
gitlab
ir
status
support
tracking
vpn
```

Each one potentially represents a different application or service.

---

# 27. 🔄 What If Zone Transfer Fails?

The material explains that in a real-world engagement, if DNS Zone Transfer isn't possible, there are other approaches.

Examples mentioned include:

### Passive Subdomain Enumeration

Using publicly available information.

### Active Subdomain Enumeration

Directly interacting with the target infrastructure.

The material also mentions:

> **DNSDumpster.com**

as one quick option.

---

# 28. 🌐 Virtual Host Enumeration

DNS is not the only way to discover web applications.

The material also demonstrates:

> **Virtual host (vhost) enumeration**

using:

```text
ffuf
```

Why?

Because a web server can host multiple applications based on the HTTP:

```text
Host:
```

header.

Example:

```text
Host: blog.inlanefreight.local
Host: gitlab.inlanefreight.local
Host: support.inlanefreight.local
```

The same IP address can serve different applications.

---

# 29. 🧠 Why VHost Enumeration?

Imagine:

```text
10.129.203.101
        │
        └── Web Server
              │
              ├── blog
              ├── careers
              ├── gitlab
              ├── support
              └── unknown
```

The IP remains the same, but the application returned by the web server changes depending on the `Host` header.

Therefore:

> **IP enumeration alone may not reveal every web application.**

---

# 30. 🧪 Finding the Invalid VHost Response

Before fuzzing virtual hosts, we first need to understand what the web server returns for a **non-existent** virtual host.

The material deliberately chooses:

```text
defnotvalid.inlanefreight.local
```

and sends:

```bash
curl -s -I http://10.129.203.101 \
-H "HOST: defnotvalid.inlanefreight.local" | grep "Content-Length:"
```

The response:

```text
Content-Length: 15157
```

---

# 31. 🎯 Why Determine the Baseline Response?

This is an important fuzzing technique.

If invalid virtual hosts all produce:

```text
Content-Length: 15157
```

then we can tell `ffuf`:

> Ignore responses with that size.

Otherwise, the output may contain many false positives.

### Concept

```text
Invalid VHost
     ↓
Response Size = 15157
     ↓
Tell ffuf to ignore size 15157
     ↓
Anything different becomes interesting
```

---

# 32. 🔥 Fuzzing VHosts With ffuf

The material uses:

```bash
ffuf -w namelist.txt:FUZZ \
-u http://10.129.203.101/ \
-H 'Host:FUZZ.inlanefreight.local' \
-fs 15157
```

### Important options

|Option|Meaning|
|---|---|
|`-w`|Wordlist|
|`FUZZ`|Fuzzing keyword|
|`-u`|Target URL|
|`-H`|Custom HTTP header|
|`Host:FUZZ...`|Fuzz the virtual hostname|
|`-fs 15157`|Filter response size 15157|

The wordlist used is:

```text
/opt/useful/seclists/Discovery/DNS/namelist.txt
```

on the Pwnbox.

---

# 33. 📊 VHost Enumeration Results

The scan discovers several valid virtual hosts:

```text
blog
careers
dev
gitlab
ir
<REDACTED>
status
support
tracking
vpn
```

The interesting observation is:

> **One vhost was not present in the DNS Zone Transfer results.**

This is a very important reconnaissance lesson.

---

# 34. 🔥 DNS Enumeration vs VHost Enumeration

The two techniques complement each other.

```text
                 TARGET
                   │
          ┌────────┴────────┐
          ↓                 ↓
       DNS AXFR          VHost Fuzzing
          │                 │
          ↓                 ↓
    DNS Records       HTTP Host Headers
          │                 │
          └────────┬────────┘
                   ↓
             Combined Results
                   ↓
           Larger Attack Surface
```

### Key takeaway

> **Never assume one enumeration method gives you complete visibility.**

The zone transfer missed a virtual host that `ffuf` discovered.

---

# 35. 📝 Updating `/etc/hosts`

After discovering the subdomains/vhosts, the testers add them to:

```text
/etc/hosts
```

The material uses:

```bash
sudo tee -a /etc/hosts > /dev/null <<EOT

## inlanefreight hosts 
10.129.203.101 inlanefreight.local blog.inlanefreight.local careers.inlanefreight.local dev.inlanefreight.local gitlab.inlanefreight.local ir.inlanefreight.local status.inlanefreight.local support.inlanefreight.local tracking.inlanefreight.local vpn.inlanefreight.local
EOT
```

---

# 36. 🧠 Why `/etc/hosts`?

Adding the names locally allows the tester to access the applications using their intended hostnames.

For example:

```text
10.129.203.101 blog.inlanefreight.local
```

Then:

```bash
curl http://blog.inlanefreight.local
```

or a browser can resolve:

```text
blog.inlanefreight.local
```

to:

```text
10.129.203.101
```

without requiring a public DNS resolver.

---

# 37. 🗂️ Enumeration Results

At the end of this phase, we have:

### Target

```text
10.129.203.101
```

### Operating System indication

```text
Ubuntu / Linux
```

### Open Services

```text
21  FTP
22  SSH
25  SMTP
53  DNS
80  HTTP
110 POP3
111 RPCbind
143 IMAP
993 IMAPS
995 POP3S
8080 HTTP / potential proxy
```

### Interesting findings

```text
Anonymous FTP
DNS Zone Transfer
Multiple subdomains
Multiple virtual hosts
Potential open proxy
Apache web server
Multiple mail services
RPCbind
```

---

# 38. 🎯 Attack Surface Map

![Image](https://images.openai.com/static-rsc-4/MjP24Mrt2yenGj03ierjmyzaDUnx_3931RanQS9HREDHXjsRbT1u1lMxhsO5eOpwPgubnH_M0iENPDrMKfdYzXd4QKIYY-57c0JX3vUxwptSaMMvY_nUNqIhldQ257oTuTtC9RMB2tXpdwhiYlXhUeWPp2lZZkxInlNRK4tiJkhLWbYFa0gAi82ukjYqICHx?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/VIzuSiBcuFy5sWIVFwey9mqvoPvX4OcU_HGikN4JjQXrKpNW-_mbTqEntvqNzJgTvfG2fgkyGrXDEtGGfXhSmpa04JMciAGTj-OLBkqsSV2GNj9Ayio7yH9jtBjMZJ0IutlWjrSO2-ffGhl-dnapRlW7n5q3pwJTulT556v5TTY1_4M4f0bruRIAWWbLdYcd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/keju1GCrPxSgvA3JVZ_ZRDEHBOAQmtfeEE7OnJYOjmP9-WvBgKJaavj5Kh1gYXhNBN4t4JIyUvHcb4rfi_hrQI6JCqskbaj_Eu-GkxJk6q7M6qIHG-awpgzydp0czzy20cJ_a_BUZEZpSkQZ4cI6GUifAt81q3khDzby39rP8gE4NxNc9ZmJlcD3jW-qL91E?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/pTBB1ozf31Oc_mEm7eo_ev-9snmmlzAjXiDzAktsx76ezCxGcSqdjnxWh8mdAuHVk7Z018FAH-LLPqIeksGSpVaG4OmuGGJSj0BHhYwLmiwxLL_oPIPDm6DeJBNlEmwzlYvZiHRUqX2uJjMUFNo_w8Ow_MNurlO0f93rskk2cyKYoc974XHBWT7CXO8tQgNg?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/b1aupRzGlR9gu-FEyu9sEChb3R2RM48y19ZSMKi4m30YJMqHz5icDEiDPLqUULOLq3rYoYXNEyulTw2VPAM1aHoVRsfBgz1d-Js3aQxvha2IlKZc8R9PQrCqcRxbIWOPpgZzJ3xAiCefoTclDHn1GZTrTJveoA2Yp-t3HCkqYK-7gN31EMzBUPtJB5P7YaEI?purpose=fullsize)

A useful mental model is:

```text
                         10.129.203.101
                                │
        ┌───────────────┬───────┼───────────────┐
        ↓               ↓       ↓               ↓
      FTP             SSH      DNS             WEB
       │                        │                │
 Anonymous                  AXFR          Port 80 / 8080
       │                        │                │
       ↓                        ↓                ↓
   flag.txt              Subdomains          VHosts
                                                │
                         ┌──────────────────────┼───────┐
                         ↓                      ↓       ↓
                       blog                  dev     gitlab
                       careers               ir      support
                       status              tracking   vpn
```

Alongside these:

```text
SMTP
POP3
IMAP
RPCbind
```

also require service-specific investigation.

---

# 39. 🔥 Prioritization

Not every discovery has the same immediate value.

Based strictly on the observations in this stage, particularly interesting items include:

### 🔴 Anonymous FTP

```text
21/tcp
Anonymous login allowed
flag.txt available
```

### 🔴 DNS Zone Transfer

```text
53/tcp
AXFR successful
9 additional subdomains
```

### 🔴 Potential Open Proxy

```text
8080/tcp
Potentially OPEN proxy
```

### 🔴 Web Applications

```text
80/tcp
8080/tcp
Multiple vhosts
```

### 🟠 Mail Infrastructure

```text
25
110
143
993
995
```

### 🟠 RPC

```text
111
```

### 🟠 SSH

```text
22
```

The next step is to investigate these services individually rather than blindly attacking everything.

---

# 40. 🧪 Methodology Used in This Section

The complete workflow is:

```text
                 START
                   │
                   ↓
             Initial Nmap
                   │
                   ↓
           Identify Open Ports
                   │
                   ↓
            Full Port Scan
                   │
                   ↓
       Service + Version Detection
                   │
                   ↓
             OS Enumeration
                   │
                   ↓
          Extract Service List
                   │
                   ↓
             DNS Enumeration
                   │
                   ↓
             AXFR Attempt
                   │
             ┌─────┴─────┐
             ↓           ↓
          Success      Failure
             ↓           ↓
       Subdomains    Other Methods
             │
             └─────┬─────┘
                   ↓
            VHost Enumeration
                   │
                   ↓
             Compare Results
                   │
                   ↓
             Update Hosts File
                   │
                   ↓
       Investigate Interesting
              Services
```

---

# 41. 🧠 Important Lessons

## Lesson 1 — Start Broad

Don't immediately focus on one service.

First determine:

> **What is exposed?**

---

## Lesson 2 — Scan All Ports

A quick top-1000 scan is useful for speed, but it doesn't guarantee complete visibility.

The full scan:

```bash
-p-
```

checks all TCP ports.

---

## Lesson 3 — Be Careful With Aggressive Scanning

`-A` provides additional information but is more intrusive.

Always consider:

- Scope
    
- Rules of Engagement
    
- Service stability
    
- Potential impact
    

---

## Lesson 4 — DNS Can Reveal the Attack Surface

A successful AXFR can reveal multiple internal application names.

Here:

```text
AXFR
 ↓
9 additional subdomains
```

---

## Lesson 5 — Don't Depend on One Enumeration Technique

DNS enumeration found one set of names.

VHost fuzzing found an additional vhost.

Therefore:

> **Use multiple complementary enumeration techniques.**

---

## Lesson 6 — Establish a Baseline Before Fuzzing

Before using `ffuf`, determine the response behavior for an invalid hostname.

Here:

```text
Invalid vhost
 ↓
Content-Length: 15157
 ↓
-fs 15157
```

This significantly reduces false positives.

---

## Lesson 7 — Save Your Results

The material consistently saves Nmap output using:

```text
-oA
```

This is important for:

- Later analysis
    
- Evidence
    
- Reporting
    
- Reproducibility
    
- Documentation
    

---

# 42. 📌 CPTS-Focused Cheat Sheet

### Initial scan

```bash
sudo nmap --open -oA inlanefreight_ept_tcp_1k -iL scope
```

### Full TCP scan + aggressive enumeration

```bash
sudo nmap --open -p- -A -oA inlanefreight_ept_tcp_all_svc -iL scope
```

### DNS AXFR

```bash
dig axfr inlanefreight.local @10.129.203.101
```

### Determine invalid vhost response

```bash
curl -s -I http://10.129.203.101 \
-H "HOST: defnotvalid.inlanefreight.local" | grep "Content-Length:"
```

### VHost fuzzing

```bash
ffuf -w namelist.txt:FUZZ \
-u http://10.129.203.101/ \
-H 'Host:FUZZ.inlanefreight.local' \
-fs 15157
```

### Add discovered hosts

```bash
sudo tee -a /etc/hosts > /dev/null <<EOT

## inlanefreight hosts 
10.129.203.101 inlanefreight.local blog.inlanefreight.local careers.inlanefreight.local dev.inlanefreight.local gitlab.inlanefreight.local ir.inlanefreight.local status.inlanefreight.local support.inlanefreight.local tracking.inlanefreight.local vpn.inlanefreight.local
EOT
```

---

# 43. 🏆 Final Revision Summary

Remember this chain:

```text
NMAP
 ↓
11 OPEN PORTS
 ↓
SERVICE ENUMERATION
 ↓
VERSION DETECTION
 ↓
UBUNTU/LINUX INDICATION
 ↓
ANONYMOUS FTP
 ↓
DNS
 ↓
AXFR
 ↓
9 SUBDOMAINS
 ↓
VHOST FUZZING
 ↓
ADDITIONAL VHOST
 ↓
/etc/hosts
 ↓
DEEPER SERVICE ENUMERATION
```

### Most important discoveries from this section

|Discovery|Why it matters|
|---|---|
|`21/tcp`|Anonymous FTP|
|`53/tcp`|Successful DNS Zone Transfer|
|`80/tcp`|Apache web application|
|`8080/tcp`|Potential open proxy|
|DNS AXFR|Revealed 9 additional subdomains|
|VHost enumeration|Found a vhost missed by AXFR|
|`111/tcp`|RPC service exposed|
|Mail ports|SMTP/POP3/IMAP infrastructure exposed|
|`/etc/hosts`|Enables local hostname-based investigation|

> **Core methodology:** **Enumerate broadly → identify services → extract useful information → enumerate each service → use multiple discovery techniques → combine results → expand the attack surface → document everything.**

The next section naturally follows from this point: **digging deeper into the discovered services to identify directly exploitable or misconfigured services.**