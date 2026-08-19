# 1. 🧠 What Is `netsh`?

`netsh` is a **Windows command-line tool** used for configuring and managing networking-related settings on a Windows system.

Microsoft's `netsh` provides different networking contexts that can be used to inspect or modify network configuration.

In the supplied material, important uses include:

- **Finding routes**
    
- **Viewing firewall configuration**
    
- **Adding proxies**
    
- **Creating port forwarding rules**
    

The particularly important capability for this section is:

> **Creating port forwarding rules**

---

# 2. 🎯 Why Is Windows `netsh` Useful for Pivoting?

Imagine we compromise a Windows workstation belonging to an IT administrator.

The workstation has access to:

```text
10.129.15.150
```

and:

```text
172.16.5.19
```

The Windows workstation can therefore act as a **pivot host** between different network segments.

Conceptually:

```text
┌──────────────────┐
│   Attack Host    │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Windows Pivot    │
│ 10.129.15.150    │
│ 172.16.5.19      │
└────────┬─────────┘
         │
         ▼
   Internal Network
```

---

# 3. 🧠 Pivoting Concept

The general idea is:

```text
Attack Host
     │
     │ Connect
     ▼
Windows Pivot
     │
     │ Forward
     ▼
Internal Target
```

The attack host doesn't necessarily need direct access to the internal target.

Instead, the compromised Windows machine forwards traffic on our behalf.

---

# 4. 🖼️ Network Diagram

![Image](https://images.openai.com/static-rsc-4/AmNbZFNczlqz8mw0HlO1IHcvBApwm6MfrJ6Yh__ktWjib1v7CXnoIBdLb9pZPlogfZ19t-uKENdD_95_PHDbyKE5TqcGcoOe2d7C1m5wsyA95MAmHz4bZScb21UyvpEk_AbrgP9MFSbjffINbLDuInMZrpFmhuIVn-D1wyDw9MbLLm218iApFcmtfYGKsfXH?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/dZpN_5Gi4UotazoqXzGpvrmIzquckmNP-v-SsBiZhXzs65LoIg6Ca_YyBSBkeHwHJlrECeRa-JD_uV8zJ7W497VJixZnxor61YAFyOI99adb0gl-7yDAYofKLmz42paYIp8WXYt6Qc1h_6A6cF3aSA91I8NaJLs9p1BeYaTFo33iBTS8yXHpV-8dri4gXIGT?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/dKMOoxQsGhgBVGQWCFBMDagAVPTNhGbdSET3njylG0f7fZ4-QqUKAmPQfJGadmCBnNMv75hpuwchZNWGd-YkDjfUe8QVXJJVwDVLzM2w55j-4HVO6Nz9cVB_HV2uhO2OpeJ-0g5hLE6N8hXCCPyi-wnZ36SKH6685fQwD0P0e6fl7rwKO5KqM9krdP1xt25p?purpose=fullsize)

For the supplied scenario:

```text
                      ATTACK HOST
                           │
                           │
                           ▼
                 Windows Pivot Host
                  10.129.15.150
                    Listen :8080
                           │
                           │ netsh portproxy
                           ▼
                  Internal Windows Host
                    172.16.5.25
                       RDP :3389
```

---

# 5. 🔑 The Core `netsh` Feature

The feature used here is:

```text
netsh interface portproxy
```

`portproxy` allows Windows to listen on one address/port and forward traffic to another address/port.

In this example:

```text
LISTEN
10.129.15.150:8080
```

is forwarded to:

```text
CONNECT
172.16.5.25:3389
```

---

# 6. 🔄 Port Forwarding Concept

The mapping is:

```text
10.129.15.150:8080
          │
          │ netsh
          ▼
172.16.5.25:3389
```

So when a connection reaches:

```text
10.129.15.150:8080
```

the Windows pivot forwards the traffic toward:

```text
172.16.5.25:3389
```

---

# 7. 🛠️ Creating the Port Forward

The supplied command is:

```cmd
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```

This is the **most important command** from this section.

---

# 8. 🔍 Breaking Down the Command

```text
netsh.exe
```

Windows networking configuration utility.

```text
interface portproxy
```

Accesses the port-proxy configuration.

```text
add
```

Creates a new forwarding rule.

```text
v4tov4
```

Specifies:

```text
IPv4 → IPv4
```

---

## `listenport=8080`

The Windows pivot listens on:

```text
8080
```

---

## `listenaddress=10.129.15.150`

The listening address is:

```text
10.129.15.150
```

Therefore:

```text
10.129.15.150:8080
```

is the entry point to the forwarding rule.

---

## `connectport=3389`

The destination port is:

```text
3389
```

which, in this scenario, is the RDP service.

---

## `connectaddress=172.16.5.25`

The destination host is:

```text
172.16.5.25
```

Therefore the final destination is:

```text
172.16.5.25:3389
```

---

# 9. 📊 Command Breakdown Table

|Parameter|Meaning|Value|
|---|---|---|
|`netsh.exe`|Windows network configuration tool|—|
|`interface portproxy`|Port forwarding functionality|—|
|`add`|Add a rule|—|
|`v4tov4`|IPv4 → IPv4|—|
|`listenport`|Local listening port|`8080`|
|`listenaddress`|Local listening address|`10.129.15.150`|
|`connectport`|Destination port|`3389`|
|`connectaddress`|Destination IP|`172.16.5.25`|

---

# 10. 🧠 Remember `LISTEN` vs `CONNECT`

This is extremely important.

### LISTEN side

```text
listenaddress=10.129.15.150
listenport=8080
```

Together:

```text
10.129.15.150:8080
```

### CONNECT side

```text
connectaddress=172.16.5.25
connectport=3389
```

Together:

```text
172.16.5.25:3389
```

So:

```text
LISTEN
10.129.15.150:8080
       │
       │
       ▼
CONNECT
172.16.5.25:3389
```

---

# 11. 🔎 Step 2 — Verify the Port Forward

After creating the rule, the supplied command is:

```cmd
netsh.exe interface portproxy show v4tov4
```

This displays the configured IPv4-to-IPv4 port-proxy rules.

---

# 12. 📋 Supplied Verification Output

```text
Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
10.129.15.150   8080        172.16.5.25     3389
```

This confirms:

```text
10.129.15.150:8080
        ↓
172.16.5.25:3389
```

---

# 13. 🧠 Reading the Verification Table

The first pair:

```text
10.129.15.150   8080
```

means:

> Windows listens on `10.129.15.150:8080`.

The second pair:

```text
172.16.5.25   3389
```

means:

> Traffic is forwarded to `172.16.5.25:3389`.

---

# 14. 🔄 Complete Traffic Flow

Once the forwarding rule is configured:

```text
Attack Host
     │
     │ Connection to :8080
     ▼
10.129.15.150:8080
     │
     │ netsh portproxy
     ▼
172.16.5.25:3389
     │
     ▼
    RDP
```

This is a **port-forwarding pivot**.

---

# 15. 🎯 Why Port 3389?

The destination is:

```text
172.16.5.25:3389
```

Port `3389` is associated with:

```text
RDP
Remote Desktop Protocol
```

Therefore, the example demonstrates forwarding access to an internal RDP service.

---

# 16. 🖥️ Connecting Through the Forward

The supplied material states that after configuring the `portproxy`, we can connect to:

```text
10.129.15.150:8080
```

from the attack host using **xfreerdp**.

The important idea is that we connect to the **pivot's listening port**, not directly to the internal RDP host.

Conceptually:

```text
xfreerdp
    │
    ▼
10.129.15.150:8080
    │
    ▼
netsh portproxy
    │
    ▼
172.16.5.25:3389
```

---

# 17. 🧠 Why Does This Work?

The Windows pivot has connectivity to the internal system:

```text
Windows Pivot
      │
      ▼
172.16.5.25
```

The attack host can reach the pivot:

```text
Attack Host
      │
      ▼
10.129.15.150
```

Therefore, the pivot connects the two sides:

```text
Attack Host
     │
     ▼
Windows Pivot
     │
     ▼
Internal RDP Server
```

---

# 18. 🖼️ Full Pivot Diagram

```text
                    ATTACK HOST
                         │
                         │
                         │ Connect :8080
                         ▼
              ┌─────────────────────┐
              │ Windows Pivot       │
              │                     │
              │ 10.129.15.150:8080 │
              │         │           │
              │     netsh.exe       │
              │    portproxy        │
              │         │           │
              └─────────┼───────────┘
                        │
                        │ Forward
                        ▼
              ┌─────────────────────┐
              │ Internal Host       │
              │ 172.16.5.25:3389    │
              │                     │
              │        RDP          │
              └─────────────────────┘
```

---

# 19. 🔥 Key Concept: Port Forwarding

The entire technique can be reduced to:

```text
External Access
      │
      ▼
Pivot:8080
      │
      │ Port Forward
      ▼
Internal:3389
```

The pivot essentially exposes a reachable port that represents an internal service.

---

# 20. 🆚 `netsh` vs Sshuttle

You just studied Sshuttle, so this comparison is important.

### `netsh`

Specific port forwarding:

```text
10.129.15.150:8080
        ↓
172.16.5.25:3389
```

### Sshuttle

Network-level routing:

```text
172.16.5.0/23
        ↓
SSH Pivot
```

So:

||`netsh`|Sshuttle|
|---|---|---|
|Platform|Windows|Primarily Linux/client-side|
|Transport|Windows portproxy|SSH|
|Main purpose|Port forwarding|Network routing|
|Scope|Specific forwarding rule|Network/subnet|
|Example|`8080 → 3389`|`172.16.5.0/23 → pivot`|
|Proxychains required|No|No|

---

# 21. 🆚 `netsh` vs Socat

These are also conceptually similar.

### Socat

```text
Listener
   ↓
Socat
   ↓
Destination
```

Example:

```text
Ubuntu:8080
    ↓
172.16.5.19:8443
```

### Windows `netsh`

```text
Listener
   ↓
netsh portproxy
   ↓
Destination
```

Example:

```text
10.129.15.150:8080
    ↓
172.16.5.25:3389
```

The major difference here is that `netsh` provides a **native Windows mechanism** for port forwarding.

---

# 22. 🧠 Why Use `netsh`?

In a Windows environment, we may not have:

- Socat
    
- SSH
    
- Rpivot
    
- Other third-party pivoting tools
    

But we may already have:

```text
netsh.exe
```

because it is a Windows networking utility.

This can make it useful as a native Windows port-forwarding mechanism.

---

# 23. 📌 Important Commands

### Add port forwarding

```cmd
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```

### Show IPv4 → IPv4 forwarding rules

```cmd
netsh.exe interface portproxy show v4tov4
```

---

# 24. 🧠 Command to Memorize

```cmd
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```

Think of it as:

```text
ADD
 │
 ├── LISTEN
 │     ├── Address = 10.129.15.150
 │     └── Port    = 8080
 │
 └── CONNECT
       ├── Address = 172.16.5.25
       └── Port    = 3389
```

---

# 25. 📝 Viva Questions

### Q1. What is `netsh`?

A Windows command-line networking configuration tool.

### Q2. What functionality is used for port forwarding?

```text
interface portproxy
```

### Q3. What does `v4tov4` mean?

IPv4-to-IPv4 port forwarding.

### Q4. What is the listening address?

```text
10.129.15.150
```

### Q5. What is the listening port?

```text
8080
```

### Q6. What is the destination address?

```text
172.16.5.25
```

### Q7. What is the destination port?

```text
3389
```

### Q8. What service is associated with port 3389 in this lab?

RDP / Remote Desktop Protocol.

### Q9. How do you verify the configured IPv4-to-IPv4 proxy?

```cmd
netsh.exe interface portproxy show v4tov4
```

### Q10. What is the basic traffic flow?

```text
10.129.15.150:8080
        ↓
netsh portproxy
        ↓
172.16.5.25:3389
```

### Q11. What tool is mentioned for connecting to the forwarded RDP service?

`xfreerdp`.

---

# 26. ⚡ One-Minute Revision

```text
              WINDOWS PIVOT
                   │
                   │ netsh
                   ▼
          LISTEN : 8080
                   │
                   │
                   ▼
        CONNECT : 3389
                   │
                   ▼
        172.16.5.25 (RDP)
```

### Create:

```cmd
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```

### Verify:

```cmd
netsh.exe interface portproxy show v4tov4
```

### Mapping:

```text
10.129.15.150:8080
        ↓
       netsh
        ↓
172.16.5.25:3389
```

---

# 🏆 27. Ultimate Memory Trick

Think of `netsh portproxy` as:

> **"Listen here, forward there."**

```text
LISTEN HERE
     ↓
10.129.15.150:8080
     │
     │ netsh
     ▼
FORWARD THERE
     ↓
172.16.5.25:3389
```

And remember the three pivoting approaches you've covered:

```text
SOCAT
Specific TCP redirection
        ↓
A → Socat → B
```

```text
RPIVOT
SOCKS-based reverse pivot
        ↓
Application → SOCKS → Internal Network
```

```text
SSHUTTLE
Network-level SSH routing
        ↓
Traffic → iptables → SSH → Internal Network
```

```text
NETSH
Native Windows port forwarding
        ↓
Pivot:8080 → Internal:3389
```

### ⭐ The core lesson

**`netsh interface portproxy` allows a Windows pivot host to listen on one IPv4 address/port and forward incoming traffic to another IPv4 address/port, making it possible to reach an internal service through the compromised Windows system.**