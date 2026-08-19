# 1. 🔹 Why SocksOverRDP?

During a penetration test, we may encounter a situation where:

- Our pivoting environment is primarily **Windows**
    
- SSH is unavailable
    
- We already have an **RDP connection**
    
- We need to access another internal network/service through that RDP connection
    

In such a situation, SSH-based pivoting techniques may not be available.

This is where **SocksOverRDP** becomes useful.

---

# 2. 🧠 What Is SocksOverRDP?

![Image](https://images.openai.com/static-rsc-4/OVW22dA38V9n1gHmnWbxZWWGdPIVaL-bCgKvIqQPlrCjDqQCatbQRyHBDIwppNBgwLq-ZS_JcHOzKlDUpCHXkTZONBX2ZCVUmb_YzgMpDW-KJOh_V8Ufy70PPMh4GTB_WtVQ8AwlexldUVeMEJ_ChrFyI0NOPAqD9Br4afQAREqaMz7vb1Br1XLO91vzBzeE?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/_B_dQ-gXW4teenSq-95sgPAkUV0wjc0vLEkmYSrPLNSwRl-mjp38uLr8-d8SNuBPQRVUU1LxUueE8dqu8shav6A8dOMq0_oT37_TISJBRNKOkb1sECg5Aqa7869zo00l-xZ0QphewBAXkvShSZaEbQ5AUAZR5-Dz8h6TtNL1ixGJNaRVXkeMLB_dRtRn0uAF?purpose=fullsize)

**SocksOverRDP** is a tool that uses **Dynamic Virtual Channels (DVC)** provided by Windows Remote Desktop Services.

The important idea is:

```text
SOCKS traffic
      ↓
Dynamic Virtual Channel
      ↓
RDP connection
      ↓
Internal Windows network
```

---

# 3. 🔹 Dynamic Virtual Channels (DVC)

**Dynamic Virtual Channels** are a feature of Remote Desktop Services.

They allow different types of data to be transported over an RDP connection.

Examples mentioned in the material include:

- Clipboard data transfer
    
- Audio sharing
    

But DVC can also be used to transport **arbitrary packets**.

This is what SocksOverRDP takes advantage of.

---

# 4. 🎯 Core Concept

Normally:

```text
Attack Host
     │
     │ RDP
     ▼
Windows Target
```

With SocksOverRDP:

```text
Attack Host
     │
     │ RDP
     ▼
Windows Pivot
     │
     │ SocksOverRDP
     ▼
Internal Network
```

The RDP connection effectively becomes the transport channel for the SOCKS traffic.

---

# 5. 🧩 Tools Required

The source identifies two primary tools:

### 1. SocksOverRDP

You need the:

```text
SocksOverRDP x64 Binaries
```

### 2. Proxifier

You need:

```text
Proxifier Portable Binary
```

The source specifically mentions:

```text
ProxifierPE.zip
```

---

# 6. 🖥️ Overall Architecture

The lab can be visualized as:

```text
                    ATTACK HOST
                 10.129.x.x Network
                         │
                         │
                    Proxifier
                         │
                         │ SOCKS
                         ▼
                  127.0.0.1:1080
                         │
                         ▼
                  RDP Connection
                         │
                         ▼
                  Windows Pivot
                         │
                         │ SocksOverRDP
                         ▼
                  RDP DVC Channel
                         │
                         ▼
                   DC / Internal
                   172.16.5.19
                         │
                         ▼
                  172.16.6.155
```

---

# 7. 📦 Step 1 — Obtain Required Binaries

The source says to obtain:

```text
SocksOverRDP x64 Binaries
```

and:

```text
Proxifier Portable Binary
```

The binaries should initially be available on the attack host so that they can be transferred to the required Windows systems.

---

# 8. 🚚 Step 2 — Transfer SocksOverRDP

The source describes connecting to the target using:

```text
xfreerdp
```

and copying:

```text
SocksOverRDPx64.zip
```

to the Windows target.

After extracting the files, the directory contains:

```text
SocksOverRDP-Plugin.dll
```

and the relevant server binary.

---

# 9. 🔧 Step 3 — Load the SocksOverRDP DLL

On the Windows target, use:

```cmd
regsvr32.exe SocksOverRDP-Plugin.dll
```

The supplied example:

```cmd
C:\Users\htb-student\Desktop\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

---

# 10. 🧠 What Does `regsvr32.exe` Do Here?

In this lab, `regsvr32.exe` is used to register/load:

```text
SocksOverRDP-Plugin.dll
```

The important sequence is:

```text
SocksOverRDP DLL
       ↓
regsvr32.exe
       ↓
Plugin available to RDP
```

---

# 11. 🖥️ Step 4 — Connect to the Internal Target Using MSTSC

The material then uses:

```text
mstsc.exe
```

to connect to:

```text
172.16.5.19
```

using:

```text
victor:pass@123
```

The important difference is that the source specifically uses **`mstsc.exe`** at this stage.

---

# 12. 🔔 Plugin Activation

When connecting to:

```text
172.16.5.19
```

over RDP, the source says that we should receive a prompt indicating that the **SocksOverRDP plugin is enabled**.

The plugin will listen on:

```text
127.0.0.1:1080
```

This is one of the most important values in the entire technique.

---

# 13. ⭐ Important Port — 1080

The SOCKS listener is:

```text
127.0.0.1:1080
```

Think:

```text
127.0.0.1
    +
1080
    ↓
SOCKS
```

This becomes the local entry point for traffic that needs to be tunneled.

---

# 14. 🚚 Step 5 — Transfer SocksOverRDP Server

The source says we need to transfer either:

```text
SocksOverRDPx64.zip
```

or simply:

```text
SocksOverRDP-Server.exe
```

to:

```text
172.16.5.19
```

The server should then be started with:

> **Administrator privileges**

---

# 15. 🖥️ SocksOverRDP Server

The architecture now looks like:

```text
Windows Target
      │
      │
      ▼
SocksOverRDP-Server.exe
      │
      ▼
SOCKS traffic
      │
      ▼
RDP Dynamic Virtual Channel
```

The server component is responsible for handling the SOCKS traffic on the internal Windows side.

---

# 16. 🔍 Step 6 — Verify the SOCKS Listener

Back on the foothold Windows target, check the listener using:

```cmd
netstat -antb | findstr 1080
```

Expected output:

```text
TCP    127.0.0.1:1080    0.0.0.0:0    LISTENING
```

---

# 17. 🧠 Understanding the `netstat` Output

The important section:

```text
127.0.0.1:1080
```

means:

```text
Address:
127.0.0.1

Port:
1080

State:
LISTENING
```

Therefore:

```text
SOCKS listener
      ↓
127.0.0.1:1080
      ↓
Ready for traffic
```

---

# 18. 🔄 Complete SocksOverRDP Flow

At this stage:

```text
┌───────────────────────┐
│ Attack / Foothold     │
│ Windows Host           │
└──────────┬────────────┘
           │
           │ Proxifier
           ▼
    127.0.0.1:1080
           │
           ▼
    SocksOverRDP Plugin
           │
           ▼
       RDP DVC
           │
           ▼
     RDP Connection
           │
           ▼
   172.16.5.19
           │
           ▼
 SocksOverRDP Server
           │
           ▼
    172.16.6.155
```

---

# 19. 🧰 Step 7 — Configure Proxifier

Now we need a way to make applications send their traffic through:

```text
127.0.0.1:1080
```

The material uses:

**Proxifier**

Proxifier routes application traffic through a specified proxy host and port.

In this lab:

```text
Proxy Host:
127.0.0.1

Proxy Port:
1080
```

---

# 20. 🧠 Why Do We Need Proxifier?

Without Proxifier:

```text
mstsc.exe
   │
   └──── Direct connection
```

With Proxifier:

```text
mstsc.exe
   │
   ▼
Proxifier
   │
   ▼
127.0.0.1:1080
   │
   ▼
SocksOverRDP
   │
   ▼
RDP DVC
```

So Proxifier acts as the traffic-routing layer.

---

# 21. 🎯 The Important Relationship

Remember these three components:

### SocksOverRDP

Creates/handles the SOCKS-over-RDP mechanism.

### RDP

Provides the transport through the Dynamic Virtual Channel.

### Proxifier

Forwards application traffic to the SOCKS listener.

Therefore:

```text
Proxifier
    ↓
SOCKS :1080
    ↓
SocksOverRDP
    ↓
RDP DVC
    ↓
Internal Network
```

---

# 22. 🖼️ Full Network Diagram

![Image](https://images.openai.com/static-rsc-4/cVclG1YrjcurjdjPRHqa730tdPEdu1PUYuuFht2wdTjq15oGnHK_NvTsgVksU19STUgW9vQ7GUrMYZyz7rK8yGlBaFC5zLUtqvgLN4gTlMPf2FcrZYSrPFmBqAjxbUFhBuLo-lY1CIZ_vBKp0Qr6fCUVsCHF1hpQDp3fq-GavIEiTum9btYUK7evTMUwJx8o?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/QVjC9a_kCNOymtOL0qSHTXEKIJzQBCKOdhg6Q_JjI7TjBlE3k4_6fmfUE_QBIwO7_0wvnnFqNq9Uk_0BHOxVsvSBYaxfyEN7Q4P2WI9Y81g02afqjwXTY3EPQKKmza_NgQsYEy_VVT6E5upENSas5pxRtplcm0X_fdbE8F_JP4Wdv4v-2Wb6HEcM-OmjqFR7?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/js8IpsGRxW4xksWVXTpOYoohe4o_PoWbhLaQMtIU9JnpOoIBpZY5aVo1dUM7UEFTC5iawcYJSUSVdHKCWKcTPve3XBT7UlCYSw9f3nnz4dIcidLt_FKOgbCcaleOV5dmsHL5Rg3-x5lcyi6MXOOvGe4IWpHWisplX7QlhkfESu2qItcEQFUtL2tsD-0H2wVI?purpose=fullsize)

```text
                    ATTACK HOST
                         │
                         │ RDP
                         ▼
                ┌─────────────────┐
                │ Windows Foothold│
                │                 │
                │   Proxifier     │
                │       │         │
                │       ▼         │
                │ 127.0.0.1:1080  │
                └────────┬────────┘
                         │
                         │ SOCKS
                         ▼
                  SocksOverRDP
                    Plugin/DVC
                         │
                         │
                    RDP Channel
                         │
                         ▼
                ┌─────────────────┐
                │ 172.16.5.19     │
                │ Windows Target   │
                │                 │
                │ SocksOverRDP     │
                │ Server           │
                └────────┬────────┘
                         │
                         ▼
                    172.16.6.155
```

---

# 23. 🚀 Step 8 — Use MSTSC Through Proxifier

Once Proxifier is configured and running, the source says we can start:

```text
mstsc.exe
```

Proxifier will intercept/reroute the relevant traffic through:

```text
127.0.0.1:1080
```

The traffic then travels through the RDP connection using the SocksOverRDP mechanism.

---

# 24. 🧠 Traffic Flow in One Line

This is the line worth memorizing:

```text
mstsc.exe
 ↓
Proxifier
 ↓
127.0.0.1:1080
 ↓
SocksOverRDP
 ↓
RDP Dynamic Virtual Channel
 ↓
172.16.5.19
 ↓
SocksOverRDP-Server.exe
 ↓
172.16.6.155
```

---

# 25. 🔑 Important Credentials From the Lab

The supplied material gives:

```text
Username:
victor

Password:
pass@123
```

Target:

```text
172.16.5.19
```

SOCKS:

```text
127.0.0.1:1080
```

Internal destination mentioned:

```text
172.16.6.155
```

---

# 26. 📊 Important Values Table

|Item|Value|
|---|---|
|RDP target|`172.16.5.19`|
|RDP client|`mstsc.exe`|
|RDP protocol|RDP|
|SOCKS listener|`127.0.0.1:1080`|
|SOCKS tool|SocksOverRDP|
|Proxy tool|Proxifier|
|Windows plugin|`SocksOverRDP-Plugin.dll`|
|Server|`SocksOverRDP-Server.exe`|
|DLL loader|`regsvr32.exe`|
|Internal destination|`172.16.6.155`|
|Username|`victor`|
|Password|`pass@123`|

---

# 27. ⚙️ Important Commands

### Load the plugin

```cmd
regsvr32.exe SocksOverRDP-Plugin.dll
```

### Verify SOCKS listener

```cmd
netstat -antb | findstr 1080
```

Expected:

```text
TCP    127.0.0.1:1080    0.0.0.0:0    LISTENING
```

---

# 28. 🧠 What Is DVC?

**DVC = Dynamic Virtual Channel**

It is an RDP feature that allows additional data to be transported through an RDP connection.

The source gives examples:

```text
Clipboard
Audio
```

But the important concept here is:

```text
DVC
 ↓
Can transport arbitrary packets
 ↓
SocksOverRDP
 ↓
SOCKS tunnel
```

---

# 29. 🆚 SSH Pivoting vs SocksOverRDP

|Feature|SSH Pivoting|SocksOverRDP|
|---|---|---|
|Primary environment|Linux/Unix|Windows|
|Main transport|SSH|RDP|
|Tunnel mechanism|SSH forwarding|RDP DVC|
|SOCKS possible|Yes|Yes|
|Requires SSH|Yes|No|
|Uses existing RDP connection|No|Yes|
|Proxy tool in this example|Proxychains|Proxifier|

### Key idea:

If:

```text
SSH available
```

SSH tunneling can be convenient.

If:

```text
Windows-only environment
+
RDP available
+
SSH unavailable
```

**SocksOverRDP** can provide another pivoting mechanism.

---

# 30. 🐌 RDP Performance Considerations

The source highlights another practical issue:

> RDP sessions can become slow, particularly when managing multiple RDP sessions simultaneously.

This can affect the usability of the assessment environment.

---

# 31. ⚡ Improving RDP Performance

The material recommends going to:

```text
mstsc.exe
    ↓
Experience tab
    ↓
Performance
    ↓
Modem
```

Setting the performance level to:

```text
Modem
```

can reduce the amount of graphical data being transmitted.

This can be useful when:

- Network latency is high
    
- Multiple RDP sessions are running
    
- The pivot connection is slow
    

---

# 32. 🧠 Why Performance Matters

Remember that you're effectively stacking communication layers:

```text
Application
   ↓
Proxifier
   ↓
SOCKS
   ↓
SocksOverRDP
   ↓
RDP
   ↓
Network
```

Every additional layer can introduce overhead.

Therefore, RDP optimization can make the environment more usable.

---

# 33. 🔥 Complete Workflow

## Phase 1 — Prepare

```text
1. Obtain SocksOverRDP x64 binaries
2. Obtain Proxifier Portable
```

↓

## Phase 2 — Windows Pivot

```text
3. RDP to the Windows target
4. Transfer SocksOverRDP files
5. Register SocksOverRDP-Plugin.dll
```

↓

## Phase 3 — Internal RDP

```text
6. Connect to 172.16.5.19 using mstsc.exe
7. Use victor:pass@123
8. Verify SocksOverRDP plugin
```

↓

## Phase 4 — SOCKS Server

```text
9. Transfer SocksOverRDP-Server.exe
10. Run it with Administrator privileges
11. Verify 127.0.0.1:1080
```

↓

## Phase 5 — Proxy

```text
12. Transfer Proxifier
13. Configure proxy:
       127.0.0.1:1080
14. Start Proxifier
```

↓

## Phase 6 — Pivot

```text
15. Start mstsc.exe
16. Traffic is routed through Proxifier
17. SOCKS traffic travels over RDP DVC
18. SocksOverRDP server forwards toward:
       172.16.6.155
```

---

# 34. 🎓 Viva Questions

### Q1. What is SocksOverRDP?

A tool that uses **Dynamic Virtual Channels in Remote Desktop Services to tunnel SOCKS traffic over an RDP connection**.

### Q2. What does DVC stand for?

**Dynamic Virtual Channel.**

### Q3. What protocol provides the underlying connection?

**RDP.**

### Q4. What local SOCKS port does the plugin use?

```text
1080
```

### Q5. What is the listener address?

```text
127.0.0.1
```

### Q6. What tool is used to route application traffic through the SOCKS proxy?

**Proxifier.**

### Q7. What Windows utility is used to load the DLL?

```text
regsvr32.exe
```

### Q8. What DLL is loaded?

```text
SocksOverRDP-Plugin.dll
```

### Q9. What command verifies the SOCKS listener?

```cmd
netstat -antb | findstr 1080
```

### Q10. What should the output show?

```text
127.0.0.1:1080
LISTENING
```

### Q11. What is the difference between the plugin and server?

The **SocksOverRDP plugin** participates in the RDP-side channel, while **SocksOverRDP-Server.exe** handles the SOCKS traffic on the internal Windows target.

### Q12. Why is Proxifier needed?

To route application traffic through the SOCKS listener at:

```text
127.0.0.1:1080
```

### Q13. Why might RDP performance become poor?

Because the pivot may involve multiple RDP sessions and additional tunneling layers, increasing network/processing overhead.

### Q14. What can be changed in `mstsc.exe` to improve performance?

The source recommends:

```text
Experience → Performance → Modem
```

---

# 35. ⚡ One-Minute Revision

Memorize this:

```text
RDP
 ↓
DVC
 ↓
SocksOverRDP
 ↓
SOCKS :1080
 ↓
Proxifier
 ↓
Internal Network
```

### Three things to remember:

**1️⃣ SocksOverRDP**

```text
SOCKS over RDP
```

**2️⃣ DVC**

```text
Dynamic Virtual Channel
```

**3️⃣ Proxifier**

```text
Application → SOCKS :1080
```

---

# 🏆 Final Mental Model

The entire technique is basically:

```text
             WINDOWS-ONLY PIVOT
                    │
                    ▼
             Existing RDP
                    │
                    ▼
             Dynamic Virtual
                Channel
                    │
                    ▼
             SocksOverRDP
                    │
                    ▼
             SOCKS :1080
                    │
                    ▼
              Proxifier
                    │
                    ▼
             Internal Target
              172.16.6.155
```

> **Core takeaway:** When SSH-based pivoting isn't available in a Windows environment, **SocksOverRDP can use RDP's Dynamic Virtual Channels to transport SOCKS traffic. Proxifier then directs application traffic to the local SOCKS listener (`127.0.0.1:1080`), allowing that traffic to travel through the existing RDP connection toward the internal network.**