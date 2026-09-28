# LLMNR/NBT-NS Poisoning - from Linux — Detailed Notes

## 1. Module Objective

At this stage, initial AD enumeration has already been completed.

We have:

- Basic user and group information.
    
- Enumerated hosts.
    
- Identified important services.
    
- Identified roles such as the Domain Controller.
    
- Learned the domain's naming scheme.
    

The goal now is to obtain **valid cleartext credentials for a domain user**, giving us a foothold from which we can perform credentialed enumeration.

The module focuses on two techniques:

1. **Network poisoning**
    
2. **Password spraying**
    

This particular section focuses on **LLMNR/NBT-NS poisoning from Linux**.

---

# 2. LLMNR & NBT-NS Primer

## LLMNR

**LLMNR = Link-Local Multicast Name Resolution**

LLMNR is a Windows name-resolution mechanism used when normal DNS resolution fails.

It allows systems on the same local network to ask other systems:

> "Do you know the address of this hostname?"

LLMNR uses:

```text
UDP 5355
```

---

## NBT-NS

**NBT-NS = NetBIOS Name Service**

NBT-NS is another Windows mechanism for resolving names when DNS/LLMNR don't provide the answer.

It identifies systems using their **NetBIOS names**.

NBT-NS uses:

```text
UDP 137
```

---

# 3. DNS → LLMNR → NBT-NS

A simplified resolution process is:

![Image](https://images.openai.com/static-rsc-4/48eEmHM3thQj_xnNsOZy8IAzKWUA_5_eVrwhx7MYLBA3IfvALGZ76vI0cOO-zTluaRlW4P4afcP34R39jKdsH_cesz3hE7rn6EbSgWmG-_Tyr3TScljyNmCYbZQRUXVoTya-E92rkv8vDa-a39PJOdr4ShLXjMYq7VjVReXlGsieVcL3wCreBiDvuUh1YoUC?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/sEHdC5PC00ld3s3E8HRRp-Fanq8OnmvITKPXD3Yb_SSpiZ_1SR9ZhxVyqlKvm2g3HqWTFHCSxwtHnrG1d6oSr168ndSQMjlxuWKNFJCfM2H-WUxaqAlrrHWhQKhG3g7MXJTl9ju9lVbNdNVvA6IE5Gtlr2RB2hTnA4VA46prUTqXmKI59WgQ4n8dI4rSzuUv?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/bREXPKv2qxiBA7xa8A97v5hXNSpkPnKjsN_mZ9RbtLdEpcRYTM32Y7nFvVgvb2GIPdQ9HJGkke2HJc7yQmMn_6vlHblWkF_O-AL7emwTq49HYHd0_upCMgRwEGt2P6lb8n2Ehuplcqngu4JVUyFyv05_AfMiRU_G2ZT0uEvLlVEBynr1Xfsh3wKtAzyVVP4k?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/yypg44alVJE5UOUxWfXrpHM42Sf_ltkMarEZFQfNk3_1xG-0rME64jJoC8-o6I1J8X8EKWO1BrFp2yVoPQSX343SxtpQQuPjj8tq9KZaQUs7MWi7uMQ_JZLP34UGrbCZ6SRu2qAMFkoZJz5NJ-oYmYSu_2sA6kjzGVSbFzFGbfhBR6JX3P2j4_w4nIF755Al?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/GI5QtNpCswZ0OTF6vhiFWu0F86zjr1X_W5SQA0WpWdtCHPqa0EmF1bb2HmwrADY-NlR_lThOnbWlchyTylBEBoCy0TAjCF4-yLrn0tyTdatF0leHQE-2nPYcI_2KXQRUpaio1dLX7vN16pqH3w6rM1qLjaWDRsrveYTZ1YLXq1zxS0zeVE6uOtiH7KUtbAx3?purpose=fullsize)

```text
User requests hostname
        │
        ▼
       DNS
        │
        │ DNS fails
        ▼
      LLMNR
   UDP 5355
        │
        │ LLMNR fails
        ▼
      NBT-NS
    UDP 137
        │
        ▼
   Local network
```

The security problem is that **any host on the network can respond** to LLMNR/NBT-NS requests.

That is the fundamental weakness exploited by poisoning.

---

# 4. What Is LLMNR/NBT-NS Poisoning?

An attacker running a tool such as **Responder** can pretend to be the system that a victim is trying to locate.

The attacker effectively tells the victim:

> "I am the host you're looking for."

If the victim then attempts authentication against the attacker-controlled machine, the attacker may capture a **NetNTLM hash**.

### High-level attack flow

```text
Victim
  │
  │ "Where is printer01?"
  ▼
DNS
  │
  │ Not found
  ▼
LLMNR / NBT-NS broadcast
  │
  ▼
Attacker / Responder
  │
  │ Fake response:
  │ "printer01 = me"
  ▼
Victim connects to attacker
  │
  ▼
Authentication request
  │
  ▼
NetNTLM hash captured
  │
  ├───────────────┐
  ▼               ▼
Offline cracking   Relay
```

The module notes that captured authentication can potentially be:

- Cracked offline.
    
- Relayed to another host/protocol under appropriate conditions.
    

---

# 5. Why Is This Useful?

The goal isn't simply to collect hashes.

The actual objective is to obtain credentials that can provide an **initial foothold**.

The chain is:

```text
LLMNR/NBT-NS weakness
        ↓
Poison request
        ↓
Capture NetNTLM
        ↓
Offline password cracking
        ↓
Cleartext password
        ↓
Domain authentication
        ↓
Initial foothold
        ↓
Credentialed enumeration
```

The module also notes that LLMNR/NBNS spoofing combined with a lack of **SMB signing** can potentially lead to administrative access through SMB relay techniques.

---

# 6. Quick Example

The module provides a very important example.

### Step 1 — User makes a typo

A user tries to access:

```text
\\print01.inlanefreight.local
```

but accidentally enters:

```text
\\printer01.inlanefreight.local
```

### Step 2 — DNS fails

DNS says the requested host doesn't exist.

### Step 3 — Broadcast

The machine asks the local network:

> Does anyone know where `printer01.inlanefreight.local` is?

### Step 4 — Responder answers

The attacker has Responder running and claims:

> "I am `printer01.inlanefreight.local`."

### Step 5 — Authentication

The victim trusts the response and sends an authentication request containing the username and NTLMv2-derived authentication material.

### Step 6 — Attacker receives it

The captured hash can potentially be:

- Cracked offline.
    
- Used for relay if the required conditions exist.
    

---

# 7. TTPs

The module focuses on collecting:

- NTLMv1 authentication information
    
- NTLMv2 authentication information
    

The captured material can then be subjected to offline password cracking using:

- **Hashcat**
    
- **John the Ripper**
    

The objective is to obtain the cleartext password.

### Why crack the hash?

Because a recovered password can potentially provide:

```text
Valid credentials
      ↓
Domain authentication
      ↓
Further enumeration
      ↓
Lateral movement
      ↓
Privilege escalation
```

---

# 8. Tools

The module identifies three tools:

|Tool|Purpose|
|---|---|
|**Responder**|Purpose-built for poisoning LLMNR, NBT-NS and mDNS|
|**Inveigh**|Cross-platform MITM/spoofing/poisoning platform|
|**Metasploit**|Provides scanners and spoofing modules|

---

# 9. Responder

**Responder** is the primary Linux tool used in this section.

It is:

- Written in Python.
    
- Commonly used from Linux.
    
- Also available as a Windows executable.
    

The module describes Responder as a tool capable of establishing an initial foothold that can later be expanded through further enumeration and attacks.

---

# 10. Protocols Supported

Responder/Inveigh can interact with numerous protocols.

The module lists:

```text
LLMNR
DNS
MDNS
NBNS
DHCP
ICMP
HTTP
HTTPS
SMB
LDAP
WebDAV
Proxy Auth
```

Responder additionally supports:

```text
MSSQL
DCE-RPC
FTP
POP3
IMAP
SMTP authentication
```

### Important

Don't memorize this as merely a list of protocols.

Understand the bigger idea:

> **Responder can abuse multiple network services/protocols to induce or capture authentication.**

---

# 11. Responder: Analyze vs Poisoning Mode

This distinction is **extremely important**.

Earlier in the previous enumeration module, Responder was used in:

### Analyze mode

```bash
sudo responder -I ens224 -A
```

In this mode it:

- Listens.
    
- Observes requests.
    
- Does **not** respond.
    
- Does **not** poison requests.
    

The module compares this to being:

> **"a fly on the wall"**

---

## Poisoning mode

Now we're moving beyond passive analysis.

With normal Responder operation, it can:

- Listen for requests.
    
- Answer requests.
    
- Poison name-resolution traffic.
    
- Attempt to induce authentication.
    

This is the key difference.

```text
Analyze Mode
    ↓
Listen only
    ↓
No poisoning

Poisoning Mode
    ↓
Listen
    +
Respond
    ↓
Attempt to capture authentication
```

---

# 12. Responder Help

Run:

```bash
responder -h
```

The module shows:

```bash
responder -I eth0 -w -r -f
```

or:

```bash
responder -I eth0 -wrf
```

---

# 13. Important Responder Options

## `-A`

```text
-A
```

Analyze mode.

It allows you to see:

- NBT-NS requests
    
- BROWSER requests
    
- LLMNR requests
    

without responding to them.

---

## `-I`

```text
-I eth0
```

Specifies the network interface.

Example:

```bash
responder -I ens224
```

---

## `-f`

```text
-f
```

Attempts to fingerprint the host making the NBT-NS or LLMNR request.

---

## `-w`

```text
-w
```

Starts the WPAD rogue proxy server.

The module notes that this can be effective in larger organizations where browser auto-detection is enabled.

---

## `-v`

```text
-v
```

Increases verbosity.

Useful for troubleshooting, but produces considerably more console output.

---

# 14. Important Responder Warning

Some options can affect the network.

For example:

```text
-r
-d
```

The module specifically warns that answering certain NetBIOS requests can potentially **break things on the network**.

### Professional rule

Never blindly enable every Responder option during a real engagement.

Always consider:

```text
Scope
  ↓
Rules of Engagement
  ↓
Potential impact
  ↓
Required technique
  ↓
Execute
```

---

# 15. Starting Responder

The module provides:

```bash
sudo responder -I ens224
```

The important part is:

```text
-I ens224
```

because Responder needs to know which network interface to use.

---

# 16. Captured Hashes

If Responder successfully captures authentication material, it:

- Displays the hash on screen.
    
- Writes it to a log file.
    
- Organizes logs by host/protocol.
    

The logs are located under:

```text
/usr/share/responder/logs
```

The module gives an example:

```text
SMB-NTLMv2-SSP-172.16.5.25
```

---

# 17. Responder Log Files

Example files include:

```text
Analyzer-Session.log
Responder-Session.log
Config-Responder.log
Poisoners-Session.log

SMB-NTLMv2-SSP-172.16.5.200.txt
SMB-NTLMv2-SSP-172.16.5.25.txt
SMB-NTLMv2-SSP-172.16.5.50.txt

HTTP-NTLMv2-172.16.5.200.txt
Proxy-Auth-NTLMv2-172.16.5.200.txt
```

### Why this matters

When performing a real assessment, organization matters.

You should be able to determine:

```text
Which host?
     ↓
Which protocol?
     ↓
Which account?
     ↓
Which authentication type?
     ↓
Which captured hash?
```

---

# 18. Required Privileges

Responder should be run:

```text
as root
```

or using:

```bash
sudo
```

The module also lists ports that should be available for Responder to function effectively.

Important ones include:

```text
UDP 137
UDP 138
UDP 53

TCP/UDP 389
TCP 1433
UDP 1434

TCP 80
TCP 135
TCP 139
TCP 445

UDP 5355
UDP 5353
```

---

# 19. Responder Configuration

Rogue servers can be disabled in:

```text
Responder.conf
```

This is useful when you want to limit the services Responder provides during an engagement.

### Pentesting principle

**Only enable what you need.**

More enabled services can mean:

- More network noise.
    
- More unexpected behavior.
    
- Greater chance of disrupting legitimate traffic.
    

---

# 20. Running Responder During Enumeration

The module recommends starting Responder and allowing it to run while performing other enumeration tasks.

For example:

```text
Terminal 1
    │
    └── Responder
           │
           └── Wait for authentication

Terminal 2
    │
    └── Enumeration

Terminal 3
    │
    └── Other testing
```

This maximizes the opportunity to capture authentication requests.

The module specifically mentions using a **tmux** window for this purpose.

---

# 21. NetNTLMv2

A key concept in this module is **NetNTLMv2**.

When Responder captures an authentication exchange, it commonly obtains a NetNTLMv2 challenge-response hash.

These are useful for offline cracking.

However:

> **NetNTLMv2 cannot simply be used for Pass-the-Hash.**

The module explicitly states that these hashes need to be cracked offline when the goal is to recover the actual password.

### Remember

```text
NetNTLMv2 captured
        ↓
Offline cracking
        ↓
Cleartext password
        ↓
Use credentials
```

Not:

```text
NetNTLMv2
   ↓
Pass-the-Hash
```

---

# 22. Hashcat

The module uses **Hashcat** to crack a captured NTLMv2 hash.

The relevant hash mode is:

```text
5600
```

for:

```text
NetNTLMv2
```

The module's command is:

```bash
hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt
```

### Command breakdown

```text
hashcat
   │
   ├── -m 5600
   │      └── NetNTLMv2
   │
   ├── forend_ntlmv2
   │      └── captured hash file
   │
   └── rockyou.txt
          └── password wordlist
```

---

# 23. Hashcat Result

The example produces:

```text
Hash.Name........: NetNTLMv2
Status............: Cracked
```

The module demonstrates that the account:

```text
FOREND
```

was successfully cracked and the password was recovered.

### Important lesson

A captured authentication hash is **not automatically equivalent to a password**.

You need to consider:

- Hash type
    
- Hash strength
    
- Password complexity
    
- Wordlist quality
    
- Cracking speed
    
- Available computing resources
    
- Time available during the assessment
    

---

# 24. Password Complexity Matters

The module highlights an important real-world observation.

The example password was relatively weak, allowing the NetNTLMv2 hash to be cracked.

However, stronger passwords can make cracking:

- Much slower.
    
- More computationally expensive.
    
- Potentially infeasible within the assessment timeframe.
    

### Security lesson

LLMNR poisoning becomes much more dangerous when combined with:

```text
Weak passwords
+
Legacy protocols
+
Poor network configuration
```

---

# 25. Complete Attack Chain

This is the **most important diagram to remember** from this module.

![Image](https://images.openai.com/static-rsc-4/0waY3qfXFuhIr6jWivfOiFmzZAfLw-IuRe74lnFSrpVfkO6KncZiw0ralwaWEnrp_KwnkOCzU8wuGkYxAOQIchOsomkJoY-C7x9IHpaOZlHA1ZMZiHV5AeN7Q1k1GXg6LxT61b9XwLIHAcQGVItGE57mBk95piCdjpLSnloirpPsPwXFjQMwQwFu-yhhg_Yi?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/bQC2gXbzichRWy-5pAb0cBDfB_mkiI6PusXdKPiAy86ruzIPuxl0mzqREe3qboMf-cgV7gdsyOOJJHS9H4fmTP4thnTB5MLJKdcA6MI0_Ek3gGGwutTcbDSlcG9335J6Sb45uwiOnxrxf_LYhFL3JCq43meJOfx7UD-11EwwbE06WNSfBnvkgqEVWgofskps?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Be6I4VPORUZASfMICpWaSYQ6C8Juy6T-hVnk97eZKYUPPzZ-P8pM4W4PQQdOqi5JCU4Okrm7q76FCNBar7wJuYauS6RsZt92ZEFWfk6PybsRZISeijIaG4j-s8p4rVR-bHJpSpoS0z1yE8ZuqIGUR5PVa21DVYFM0DZg75zW4DoX0YU8jZVYT9aSyzqhHaX5?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/BBoykOQgmefvWzLChzpfpTBxmqLA1-_d4WR_h2j6mzldH1fVYBVYUCt-mUKy6Z3Cfh8P7aDkt5bZnixCZcxKW90aALXi1lqDXK_G0s3Th0C5_6ABMN2RLSmV2uENM055KzyB38FN9kcIAho3r1YqBXov4jX3I2pNgUrRS1PilUsOWxD8L5O_jGVrsrV6xDJ4?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/TehFFzzTpLfu65-DYtUHcyiz8Ott_rPOINo52ie140I6oXlyauOD81-qWH8tjn0i7unE9RKGt6H_k0DITdGj_cgCDjq6mAWuG0RwBD26HTcu9Fbvr6qaa7BsqRT-5mJaz1sQF144oLzTepvrRCkLr3hya3J-M_r1nuKUmAmSu2Vt2irhxbFtm5HcY4QqRzGI?purpose=fullsize)

```text
             VICTIM
                │
                │ Incorrect hostname
                ▼
              DNS
                │
                │ Resolution fails
                ▼
          LLMNR / NBT-NS
                │
                │ Broadcast
                ▼
           RESPONDER
                │
                │ Fake response
                ▼
             VICTIM
                │
                │ Authentication
                ▼
        NetNTLMv2 Hash
                │
                ▼
          Save the hash
                │
                ▼
            Hashcat
                │
          -m 5600
                │
                ▼
       Cleartext Password
                │
                ▼
       Domain Credentials
                │
                ▼
     Credentialed Enumeration
                │
                ▼
      Further Attack Paths
```

---

# 26. What You Should Understand — Not Just Memorize

### LLMNR

Fallback name resolution.

```text
UDP 5355
```

### NBT-NS

Legacy NetBIOS name resolution.

```text
UDP 137
```

### Responder

Can listen for and poison name-resolution/authentication traffic.

### NetNTLMv2

Challenge-response authentication material that can be captured and potentially cracked offline.

### Hashcat

Password-cracking tool.

```text
-m 5600
```

→ NetNTLMv2.

### Initial Foothold

Valid credentials can allow us to move from:

```text
Unauthenticated
       ↓
Authenticated
       ↓
Credentialed AD enumeration
```

---

# 27. Important Commands From This Module

Keep these commands in your notes.

### Responder help

```bash
responder -h
```

### Passive analysis

```bash
sudo responder -I ens224 -A
```

### Responder poisoning

```bash
sudo responder -I ens224
```

### Hashcat — NetNTLMv2

```bash
hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt
```

---

# 28. Quick Revision Table

|Topic|Key Point|
|---|---|
|**LLMNR**|Windows fallback name resolution|
|**LLMNR Port**|UDP `5355`|
|**NBT-NS**|NetBIOS name resolution|
|**NBT-NS Port**|UDP `137`|
|**Responder**|Poisoning/capture tool|
|**Analyze Mode**|Listen without responding|
|**`-A`**|Responder analyze mode|
|**`-I`**|Select network interface|
|**`-f`**|Fingerprint requesting host|
|**`-w`**|WPAD rogue proxy|
|**`-v`**|Verbose output|
|**NetNTLMv2**|Common captured authentication material|
|**Hashcat mode**|`5600`|
|**Main objective**|Obtain valid credentials / foothold|
|**SMB Relay**|Possible under appropriate conditions|
|**Password cracking**|Offline|
|**Final outcome**|Valid domain credentials|

---

# 🧠 Cybersecurity Mentor Mindset

Don't memorize this as:

> `Responder → Hashcat → Password`

Understand the vulnerability:

```text
Windows needs name resolution
             ↓
DNS doesn't know the answer
             ↓
Windows asks the local network
             ↓
Attacker is allowed to answer
             ↓
Victim trusts attacker
             ↓
Authentication material is exposed
```

**The vulnerability is fundamentally a trust problem in fallback name resolution.**

That's the important concept you should carry into the exercises.

And remember the professional distinction:

```text
Responder -A
     ↓
Observe only

Responder normally
     ↓
Actively respond / poison
     ↓
Potentially capture authentication
```

The next exercises should therefore be approached by asking **what protocol is failing, what fallback occurs, why the victim trusts the response, and what authentication material is exposed**—rather than blindly running commands.