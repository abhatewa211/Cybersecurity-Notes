# 1. 🌍 Real-World Application

As a penetration tester, the techniques covered throughout this module can become **everyday tasks**.

The exact level of independence depends on:

- Your skill level
    
- Your role on the engagement
    
- The assessment methodology
    
- The supervision provided by senior testers
    

A major reason these skills matter is that your actions can affect the work of the rest of your team.

For example:

```text
Pentester A
    │
    │ discovers internal network
    ▼
Pivot established
    │
    ├──────────────► Pentester B
    │                 performs enumeration
    │
    └──────────────► Pentester C
                      performs exploitation
```

Your teammates may base their next actions on the results you provide.

Therefore, understanding **what a pivot actually does** is just as important as knowing the command used to create one.

---

# 2. 🔑 Core Skills From This Module

The source highlights five major areas:

### ① Pivoting

Using a compromised or accessible host as a connection point to reach another network or system.

### ② Tunneling

Encapsulating traffic through another protocol or connection.

### ③ Port Forwarding

Redirecting traffic from one host/port to another.

### ④ Lateral Movement

Moving from one compromised system to another system within the environment.

### ⑤ Tools & Techniques

Understanding the different technologies used to accomplish the above.

---

# 3. 🧩 What Can Happen After Establishing a Pivot?

Once a tunnel or pivot exists, it can become a foundation for additional operations.

The source identifies several possibilities.

### Exploitation & Lateral Movement

Previously established tunnels and pivot points can be used for:

- Additional exploitation
    
- Lateral movement
    
- Accessing systems that weren't directly reachable
    

### Persistence

An attacker may attempt to establish persistence mechanisms across different network segments.

### Command & Control

Tunnels can provide channels for:

> **Command & Control (C2)**

inside and throughout enterprise environments.

### Security-Control Bypass

Tunnels may also be used to bypass certain security controls when:

- Bringing tools into an environment
    
- Moving data
    
- Exfiltrating information
    

---

# 4. 🧠 Why Networking Knowledge Is So Important

A strong understanding of networking is a **core skill** for both:

- Penetration testers
    
- Defenders
    

You need to understand what's happening underneath the tool.

For example, don't just memorize:

```bash
ssh -D 9050 ...
```

Understand the underlying concept:

```text
Application
     ↓
SOCKS Proxy
     ↓
SSH Tunnel
     ↓
Pivot Host
     ↓
Internal Network
     ↓
Target
```

That understanding allows you to adapt when the environment changes.

---

# 5. 🌐 Networking Foundation

If concepts such as:

- Subnetting
    
- Layer 2
    
- Layer 3
    
- Addressing
    
- Routing
    
- Network tools
    

are confusing, the module recommends revisiting **Introduction to Networking**.

This is important because pivoting ultimately depends on understanding **how traffic gets from one network to another**.

---

# 6. 🗺️ Recommended Learning Path

The source suggests several areas that build upon the skills from this module.

![Image](https://images.openai.com/static-rsc-4/iTAXjl3-KQdXuChRn3Sau-xVqm01tLi8G8Fu2jWP_zvWIS2nY2KfYK02uLSI1f_WfXcrrHVouuzokihPKLpZWpJeKptrZTgYyZSC3EBL7xnGirtSTCSFWsIg0Jhi6JM3QwHtV3oTbiMObWSnG4pBcSt8_iqhvH3q26kwgExTdyj5TZHlr0BQ7RuJVdHEdv4J?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/_zxx9NYv1wv9XHND7PwmHm0PvJs8xZrng4q7h_aHqqAAMpqNlmma-rlsPgJ5Ia3_Qa-eYDuDqDYZypUoJqTLWokucJ4QcT9PwE9mIdu4XKnEAC27k2iaO7kRkQoEGV4CNHKXlYUzM4q4Xnsmkq2SdQA-hbiZVXgwitfdeQT4YRC7l2hYxSFmRts1Rqft68vI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/k7iFSxmLct2vqJ3ZFidBwOPsWYuDmOCFzNbOGuCd6CCURx4ATfTIQrSMXdLRuiQ9cvCagmcHDz_A1i13atKC-uJ4bbLCqQm8GzP-a0-mES6dQcb0-DaY_tT81vQLUGKzzbMj1_THM1zMl_HpreNb2GmMcvon6egHHHTp_C5BxlFAQoM9XySeKeOuZ_9XBnKZ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/KmVbXBSSy_HHsyUg1JfYQlGs17P7X76B59GPHzryAgAZ0InigpeCGp98bPDsMNgMNPuK25WHIgvkmncVx3dOLaLOt7uagT4aEbuwyRJIKTSHl7ZTWAKkVFmi3o7o4m642SHQIZApAdWuw0vLPlKDrZvzsHz0Wv6XgwgSVxSGvv65Iu0OMFhAA0oXBHY8WSO2?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/6omONQdKlENIVkgtX5FtAmGBfmT__uLDe6nRZnH-ztGtg1uTVG6XptP_2BdT0vk-lYPgg0_CBf8aG1yR32W_NHhjzmUmsUMj2er0wkxuaj-txuxzIVeZ2ABtSRHZ1gL3Blrq8AdsV19Jza1Asr4VP-5gmlFS3uK8kkzB7qecN8-f-d3VP0ZG018DOGOT8dw-?purpose=fullsize)

## 🔵 Networking

Build a strong foundation in:

- Subnetting
    
- Layer 2/3 technologies
    
- Routing
    
- Addressing
    
- Networking tools
    

---

## 🟣 Active Directory

The source recommends:

### Introduction to Active Directory

Useful for understanding:

- AD architecture
    
- Domains
    
- Domain Controllers
    
- Enterprise Windows environments
    

### Active Directory Enumeration and Attacks

Builds on that foundation and focuses on:

- Enumeration
    
- Attacking AD environments
    
- Enterprise attack paths
    

---

## 🔴 Shells & Payloads

This helps improve:

- Exploitation skills
    
- Understanding of payloads
    
- Understanding how shells work
    
- Understanding payloads used across target networks
    

This connects directly with the reverse-shell and tunneling concepts covered earlier.

---

# 7. 🌐 Web Application Skills

If the webserver-shell and pivoting portions were difficult, the source recommends:

### Introduction to Web Applications

Useful for understanding the underlying web architecture.

### File Upload Attacks

Useful because compromised web applications can sometimes become the initial foothold from which further pivoting occurs.

---

# 8. 🧪 Starting Point

The source specifically recommends **Hack The Box Starting Point** as a practical way to apply skills learned throughout Academy.

![Image](https://images.openai.com/static-rsc-4/byE7CRGZx8niPgf-3GCgvPPPd2BJjNsSzYjdvtbFTNcTsA911QXpaWTEJ7GhRmcvYV9QpViq-BDt2PAFrySch1hEeZ73uPO3GOPwJo5ZNPh_lP5nqBYDoalCYYCcQuL2GM3eJYwZ8CZJjiG26Iwf8V-6d2pwry5jvBgUHW1E8UyFpU947UrAOCgJJynNQSFA?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/2r6VFu9ErSmYjEW6rXpQluGf223LOsqYHAnZbuiTm3DgF-vJ5WzqBRLukKIvUGwRs3D8qESnGR29NP9xgwDa3UhICLWp1pdt6HPzx5wC76Vc3WERyMbDAe3ODp2L5jzsGNmBnGKUmCzH2Slj4Mqs-2W2klI_hZwq6TQFrp4Vnunfl5QETKrp4ww2FzVr1x68?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/r8XIN55kP70SuXJx_i3BU2Sf6QDSQ8IEa8fnsRVn34vYdnrc1JJyI-AeOJWedi5KaRnOJ3UqW91aLpQK-ZgzOuAMJllvJlQQaOSDWtyvq9uXHb5hb-YF357zT9OYlRkXmA_r0RPluSTmlCLmWtB6hCpD2saOY5y2iM8WKrJXnEyzscBvQ2zVbxEytftAa1-g?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/yaXlNK39WhSUJ0vUZeSeiiwdOHZcx_icKuNZP6Szo_6HjSwf4wr7lE_HXqbO7fU9am5VZmFRVg96Eb9AbkChOdXYNBJhJhdrCz21xD2rjjFDmvM8VWDUFGtsNp4fOkI-BVxmWpSW8Z7cqxn_fgkuZ3OwtcQX6BBJGYyerCoPfua6Yr9C_2PJN20Vz2cX3WfI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/nhDfPJzacuxvjWpMiaNd3-E63u59fISHrCWXtXonByXZpwTuu6kWhgX3wnDxIueMES4_Z1vfaFZ43JfEIOLcrWjvam46qkqxlEHRvGP4FQaM3H5Hmf4jIuOCLzX602HrRUcQNEbNoj2Gz7FOsc1Adl4AZspgYDJ1GieVtzk3jQ1OPyWKtlSXGk3Jrru47qZ2?purpose=fullsize)

The important lesson is:

> **Don't only learn the commands—practice applying the concepts to actual targets.**

---

# 9. 🏴‍☠️ Boxes to Practice Pivoting & Tunneling

The module recommends several Hack The Box machines.

## Enterprise

A machine useful for practicing enterprise-style concepts and pivoting.

## Inception

Another target recommended for practicing these skills.

## Reddish

The source specifically notes that:

> **This host is quite a challenge.**

It is particularly relevant to the concepts of:

- Pivoting
    
- Tunneling
    
- Network traversal
    

---

# 10. 🎥 IppSec as a Learning Resource

**IppSec** is highlighted as an especially useful resource.

His content can help you understand:

```text
Enumeration
     ↓
Initial Access
     ↓
Foothold
     ↓
Pivot
     ↓
Internal Enumeration
     ↓
Lateral Movement
     ↓
Privilege Escalation
     ↓
Objectives
```

The source recommends using walkthroughs or videos when you're stuck.

The important idea isn't simply copying the solution.

Instead, pay attention to:

- **Why** the pivot was necessary
    
- **Why** a particular tunnel was selected
    
- **What network path** was created
    
- **What became reachable afterward**
    

---

# 11. 🏢 Pro Labs

![Image](https://images.openai.com/static-rsc-4/6Sek9l1jAKRScsPraOniueANL6gB52RZbtbTWnANTHo4Obf0aBmg8_DuidkMtucwgmtdxJBOxz11CBpV_dtrn2awxkZ6yR-evBS6OFeeA7DaEWip3Y-k1FbJqeiqdtTPsjMVg8O5W36TV2GwP1vlsqu0EmVBenVgGrp0v6zW72Mdyc__UpA98UhhJo5EqRIB?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/JvI5cP7Qur0LCSR27bBuYnrF9uAGgwppgoxfRzv782ycFcERmAmLIr0GLMAvCqywR6372uVzzyomCLpeAK8nCQcxRrdJuXzrI6U55g0_qya_KeNqQde3nDe3hFvhorkCGFDIkpTTni8JMP8eelYJ1euhgJJn8pzF9eykEL3-eqvmH4cciQta771S46oXfD_P?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/0-tyf1s7cp56Id4QR4v-3T7dZwsrRWgZisS9UY1QqGeFb7VJnNi5NpczbxXe5Rb_oqIaTz3nWbVvsRhhXmdrDJhlAsuZks_k77Y7ZgoIbegOu3JJ8JQqMZyJ-wn7DD-585X2XKQblTdCeamAN93GykeIXijaR28aJ_BGb--5ifY4UoEBFAepblUP7ytkbWsW?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/kAABmmhUaw3h3yJ00YWIokP8Gy-IdmHil-2eKMqNxxhEzF8ftsIgmaJWafp18dTq8FadZAQud8QnTZKzK6sqmtse1mrB1Fi_9C2YqN3KUB8CKHDXugPrviP6NKHQf2guPolwLD5FeXpsTOTHUTpQ6DWF6g1gPz-B0Nj4GWXw4nsM-ozrctEESdGLwk8Btojt?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/rm3RYbpR00vbC02W7JkHy8BHt7EgN4g2H-e4Q2_vWRYoIGoYA1P-W0ECvuFZPlQV2IqddJK85a1tJANhRziVbYnenkqvS1L5n6IAG0MccT8QrhQZTJuu9evFv4T2AZbVV6iZIJ9cmZ2B5JwPpgaaR6mOf7owgxMKxf2RJHYbylWsvHKNBiUhyeYiWwU3K10Z?purpose=fullsize)

**Pro Labs** simulate large corporate environments.

The module describes them as:

> Large simulated corporate networks that teach skills applicable to real-life penetration testing engagements.

These are particularly valuable because they allow you to chain multiple techniques together rather than solving an isolated machine.

---

# 12. 🔥 Dante

**Dante Pro Lab** is specifically highlighted as an excellent environment for practicing:

- Pivoting
    
- Enterprise attacks
    
- Chaining multiple pivot points
    
- Combining network access with other offensive techniques
    

Think:

```text
Foothold
   ↓
Pivot #1
   ↓
Internal Network
   ↓
Pivot #2
   ↓
Another Segment
   ↓
Target
```

This is much closer to the type of complexity encountered in enterprise environments.

---

# 13. 🟠 Offshore & RastaLabs

The source identifies:

### Offshore

An intermediate-level Pro Lab containing opportunities to practice pivoting through networks.

### RastaLabs

Another intermediate-level environment with substantial opportunities for:

- Pivoting
    
- Enterprise attack paths
    
- Network traversal
    

---

# 14. ⚔️ Mini Pro Lab — Ascension

For a significantly challenging environment, the source recommends:

### Ascension

The lab features:

- **Two different AD domains**
    
- AD enumeration
    
- AD attacks
    
- Multiple opportunities to practice enterprise attack techniques
    

This makes it useful after developing a solid understanding of the fundamentals.

---

# 15. 📚 Writers, Creators & Blogs

The module recommends continuing education through:

- HTB Discord
    
- HTB Forums
    
- Security blogs
    
- Walkthroughs
    
- Technical write-ups
    
- Video content
    

The objective is to expose yourself to different ways of solving similar problems.

---

# 16. 📝 0xdf

**0xdf's walkthroughs** are highlighted as an excellent resource.

The value of these walkthroughs isn't just the commands.

They help connect:

```text
Tool
 ↓
Technique
 ↓
Concept
 ↓
Attack Path
```

This makes it easier to understand how individual skills combine into a complete attack.

---

# 17. 🐭 RastaMouse

RastaMouse is highlighted for content involving:

- Red Teaming
    
- C2 infrastructure
    
- Pivoting
    
- Payloads
    

The source also notes that RastaMouse created a Pro Lab to showcase related concepts.

---

# 18. 🔐 SpecterOps

The source highlights SpecterOps' material on:

> **SSH tunneling and proxies**

This is particularly useful for developing deeper understanding of:

- SSH tunnels
    
- Proxies
    
- Different tunneling mechanisms
    

---

# 19. 📰 HTB Blog

The **Hack The Box Blog** is recommended for keeping up with:

- Current threats
    
- TTPs
    
- How-to content
    
- Security techniques
    

---

# 20. 🎓 SANS

SANS provides:

- Information-security education
    
- Webcasts
    
- Technical material
    

The source specifically mentions material covering:

> **Pivoting tools and avenues of use.**

---

# 21. 🎥 Plaintext's Pivoting Workshop

The source highlights **Plaintext's Pivoting Workshop**.

It was created to help prepare participants for **Cyber Apocalypse CTF 2022**.

It focuses heavily on pivoting and is recommended as another way to reinforce the concepts learned in this module.

---

# 22. 🧠 The Most Important Concept: Chain Your Skills

The entire module ultimately leads toward this idea:

```text
        INITIAL ACCESS
              │
              ▼
          FOOTHOLD
              │
              ▼
         ENUMERATION
              │
              ▼
          PIVOTING
              │
              ▼
          TUNNELING
              │
              ▼
       INTERNAL ACCESS
              │
              ▼
      LATERAL MOVEMENT
              │
              ▼
        EXPLOITATION
              │
              ▼
          OBJECTIVE
```

The individual techniques are useful, but **chaining them together** is where they become powerful.

---

# 23. 🛡️ Defender Perspective

These techniques aren't only important for attackers.

A defender needs to recognize:

### Compromised pivot hosts

A host might suddenly begin forwarding or proxying traffic between network segments.

### Non-standard traffic routes

Traffic may travel through unexpected:

- Hosts
    
- Ports
    
- Protocols
    

### Tunneling

Traffic may be encapsulated inside:

- SSH
    
- DNS
    
- ICMP
    
- HTTP
    
- Other protocols
    

### Lateral Movement

A compromised workstation shouldn't suddenly communicate with systems it normally never accesses.

---

# 24. 🔍 What Should a Defender Ask?

When investigating suspicious pivoting activity:

### Host

- Why is this host communicating with this network?
    
- Is this host dual-homed?
    
- Was a new tool installed?
    
- Is a new listener running?
    

### Network

- Is traffic crossing network segments unexpectedly?
    
- Is an unusual port being used?
    
- Is a known protocol being used in an unusual way?
    

### User

- Does this user normally perform this activity?
    
- Was the account recently compromised?
    
- Is the account authorized for remote administration?
    

### Infrastructure

- Are firewalls allowing unnecessary traffic?
    
- Are internal networks properly segmented?
    
- Are management networks isolated?
    

---

# 25. 🏆 Closing Thoughts

The module's final message is extremely important:

> **Pivoting, Tunneling, and Port Forwarding are foundational concepts that should be in every pentester's toolbox.**

But they are equally important from the defensive perspective.

A defender should be able to recognize when:

- A host has been compromised
    
- That host is being used as a pivot point
    
- Traffic is being tunneled
    
- Traffic is taking a non-standard route
    
- An attacker is moving laterally through the environment
    

---

# 🧠 Final Revision Sheet

|Concept|What to Remember|
|---|---|
|**Pivoting**|Using an accessible host to reach another network/system|
|**Tunneling**|Carrying traffic through another communication channel/protocol|
|**Port Forwarding**|Redirecting traffic between ports/hosts|
|**Lateral Movement**|Moving between systems after initial access|
|**C2**|Command & Control communication|
|**Persistence**|Maintaining access after initial compromise|
|**SOCKS**|Proxy mechanism useful for routing application traffic|
|**Enterprise Pentesting**|Requires chaining multiple techniques|
|**Networking**|Foundation for understanding all pivoting techniques|
|**AD**|Major next area for enterprise pentesting|
|**Pro Labs**|Practice complex multi-host enterprise environments|
|**Defensive View**|Detect compromised pivots, tunneling, unusual routes and lateral movement|

---

# 🔥 The Big Picture

If you remember **only one thing from the entire module**, remember this:

```text
                    PENTEST
                       │
              ┌────────┴────────┐
              ▼                 ▼
          ATTACK HOST         TARGET
                                │
                         Initial Access
                                │
                                ▼
                           Foothold
                                │
                                ▼
                          Pivot Point
                                │
                    ┌───────────┼───────────┐
                    ▼           ▼           ▼
                 SSH        SOCKS       Port Forward
                    │           │           │
                    └───────────┼───────────┘
                                ▼
                       Internal Network
                                │
                                ▼
                       Lateral Movement
                                │
                                ▼
                         New Targets
                                │
                                ▼
                         Final Objective
```

And from the **defender's side**:

```text
Visibility
    ↓
Baseline
    ↓
Detect Anomaly
    ↓
Investigate
    ↓
Contain
    ↓
Eradicate
    ↓
Recover
    ↓
Improve Controls
```

### 🎯 Core takeaway

**Networking → Pivoting → Tunneling → Port Forwarding → Internal Access → Lateral Movement → Enterprise Pentesting**

That chain is the real skill this module is trying to build.