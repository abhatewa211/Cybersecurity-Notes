## 1. 🎯 Why Detection & Prevention Matters

Throughout the module, we have focused on techniques from an **offensive perspective**.

As penetration testers, however, we also need to understand:

- How attacks can be **detected**
    
- How attacks can be **prevented**
    
- What **mitigations** can be implemented
    
- What recommendations should be provided to customers after an assessment
    

The material identifies three broad areas where defensive changes may be required:

- **Physical hardware changes**
    
- **Changes to the network infrastructure**
    
- **Modifications to host baselines**
    

### Pentester mindset

A good penetration test should not end with:

> "We found a vulnerability."

It should also answer:

> **"How can the organization prevent or detect this attack in the future?"**

---

# 2. 🧱 Setting a Baseline

![Image](https://images.openai.com/static-rsc-4/ISQHFWqp4UbMe8edyBEZTplfZi_dWjluuh4DnfVz4Er4Mfa7rG5W4itjVe9-QONMKGXOZeO8Cikb96GUxGOPZRbiZyOIigr5S5_Q6VuobxiL7XDl_dYWIwcLDNwilA0g2qbLbd0iGLzl1cS3k1SakrLoRUHCIGA6Fo1r2Mb-JkodPKJGghm-GgHc9DBWtGn5?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/gBq5i2QPPgNqbkq9Hs7CdSEqs0ZytU1Q5oKt2EJApsRpkhxgH-hdCG8oFvty5xy7vtHyLxE7dgF6RhF9aUOgsn1sSxuEiLryKbH9V56UbJMSC7qikxZiKAGDAN1W2RJOSmc3oHi1G2mc4HDlqRW933tQEtqjIgCl2WL8Vog-XxOnWwHBK1b9XuTlzppznL-g?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Iaz1VzT5Y2EcfjpBCgCh_1fp901OudAd9DbVxcNfB0v9czGAX-AFGgZhG0TteOehhvYl5BdTBbd7VBC_rj-erWJlhmPY5TLhFIQsgNNkm8HHo38TjL_XJ7--FYCfO4UsPLF8f6kzRs4DyS2R91qZG2ty7YwTElarzDX_H2bggDrjOYNKHPpT15iNxugkupih?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/OCDOj-L_U8UWv2_0bC58ec-FzSuVTA28wRZZVFruBVjDigpY3QRc-SGziJtqHkyvqRF0fuGmcqyUnmF9e-S8rA1N6WTLcVmb-3RUvV6dfq-OZMC03j32btO91AeBU0fx0ssFLorTN0Roz6NrKhw3Ko7Q5gmduc7vKSfm1CttvbQIH_Z0Uggzu6LWVjXdX1yh?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/QjcaDj1YI7242uZJWk2b_YRASncGF5cKcWJE5He6XWSgLTTWLZ5gVmA63b0BZGk3DnRdbZkn-6XmkjjhsDUO1VuvkrlPo7BL1QNtvv_frhpmSJy-qt2z7IBJ9tq4LSFb429LELft4f1hhJ4CcJcYJZ65wSJsPpv7dSgi_gVOwryHHYteqCcmvINTFx25IxNt?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/CplXsX_YqzPtzrduFTVDc7hdMwm-YzV4pAJuajMYpFdfU8LSp4jmRnZWKsZC-JWmtPuYX2r5rCd3xxvqzfL4-42AercODALSes9mfZ83dr_0LQl5hzsm2KSJJlze_jSd7JQ_HF67maiAvFeKgCCJ9AEYDiXmZQstjhdSp7hlHv871XWyAsCaXCl-eAjxebg-?purpose=fullsize)

A **baseline** is an understanding of what normally exists and happens within an environment.

This is extremely important because defenders need to quickly identify:

- New hosts appearing on the network
    
- New tools being installed
    
- Applications outside the approved application catalog
    
- New or unusual network traffic
    
- Changes to existing infrastructure
    

The material recommends auditing this information **annually, if not every few months**, to keep records current.

---

## 3. 📋 Things to Document and Track

The source specifically identifies:

### 1. DNS records

Maintain current:

- DNS records
    
- Network-device backups
    
- DHCP configurations
    

### 2. Application inventory

Maintain a **full and current application inventory**.

This helps identify unauthorized software.

### 3. Enterprise hosts

Maintain:

- List of enterprise hosts
    
- Their locations
    

### 4. Elevated users

Track users who have:

- Administrator privileges
    
- Other elevated permissions
    

### 5. Dual-homed hosts

A **dual-homed host** has more than one network interface.

These systems are particularly important to track because they can potentially provide connectivity between different network segments.

### 6. Network diagram

Maintain a **visual network diagram** of the environment.

---

# 4. 🗺️ Network Diagrams

A current network diagram can be extremely useful for:

- Troubleshooting
    
- Incident response
    
- Understanding network architecture
    
- Identifying segmentation
    
- Identifying pivot points
    
- Understanding critical infrastructure
    

The source mentions:

- **NetBrain** as an example of a tool for interactive network diagrams
    
- **diagrams.net** as a free option for visually documenting networks
    

Most importantly, organizations should identify their **critical assets** and continuously monitor them.

---

# 5. 👥 People, Processes, and Technology

Network hardening can be divided into three major categories:

```text
        SECURITY HARDENING
               │
       ┌───────┼───────┐
       ▼       ▼       ▼
     PEOPLE  PROCESS TECHNOLOGY
```

This approach considers:

- **Human factors**
    
- **Policies and procedures**
    
- **Technical controls**
    

---

# 6. 👤 People

Even in highly hardened environments, **users are often considered the weakest link**.

Organizations should:

- Enforce security best practices
    
- Educate users
    
- Educate administrators
    
- Maintain security awareness
    
- Reduce opportunities for attackers to gain easy access
    

The goal is to prevent the "easy wins" available to penetration testers and malicious attackers.

---

# 7. 💻 BYOD — Bring Your Own Device

**BYOD = Bring Your Own Device**

This refers to employees using personally owned:

- Laptops
    
- Smartphones
    
- Other devices
    

for work-related activities.

![Image](https://images.openai.com/static-rsc-4/1uLlMgTpiCfH-zTOCPTHJx4nKLmJFx9w1WKTTjK1MtMmKxBNdWhKrD1OW3M8IBkcB12cuUg3s0rb3mV5aC7du8Is3wEBmRa-s5TtrN9hDV7uTyqRRm0H1UikKAWJaxlKltkUVJjTNW43VS9jdskn6c1EF08gW7KEm7mrvGHWdbA4cXgxnwGnoA0mMdJjOEKv?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/lOIuWdMSmyHty65It5ENrOpnF-3EFwJVBSNj0ldmkIjbMf7NuH9S217es_RNEskz6cSGXe-UuPyWF5_H7kJhYQnnS_khsmoJifhUxNUzRbjsJBJvwDR9r-Q4H1V9hQm2fQYNyUBcuWjCPmOvol63W3V3QnTvm9JTSkNyQh-QQ_Db31wb_ne8dAT3esfZZrYn?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/zvoHvS8D350Sgxsa1dMkZSO0WCHHB3_vzlgj3iD_KnVg_kx2ETgwq_WVEgCz8wjdzzlKhLiBubLpaFJMoAeUCV-aVClUMxPc0WBW0BPXfcVG5UWkcGS_PbKFCspHo5DsjdSUbAQC81iAIdITgOshDsPHjonrMUbcz1sDQKCzpgaAAF_doS8vhTIS3XHKWCGH?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/enhK8b_kd246Jdbq7pZPCaT1dc45b7mlnxjFQTCpPXZcowDgUk-rrNPQ_GGHVWuzwcRc5-vAIb-_nwouq5zqjcA2fQdbmCyvwMkVvPKRLy6J-mcBA9P6VULB92Ijcdo7lKA6j1YHA9Nrmmc3JFy9uTEODH1UjnyvLVGzrAg8aUEZ9l0Dbs3Osv-oV-0gwrt1?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/-O796jWEAJlILyiGcWY7irsw7RaDgyKeORIQGtF2pcRWoRQx7p2ZCj9OEGcT0NK17SALc7SousNFN-rP7O3JZbhW-RbSsHC245DQEYUXk62eoDwrzuVznOUsqjqauy13vJQPzC3cyqxh1pIzQUbB4w2v4yFJBw5T7LXd4X7A6JTRnZlTAapOukQZwFc6BHLt?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/fwFvKaE7njcMwBIFakbNM0WLjpPG2-RpPemYmc4938OSs30LFKbVSzFGIK19GwGq1BDr6yltX7qXyTOLRG26E3T1ugaptbiygIEw67tbQJ8YV0BTx9VcKLdHJdHtlCxkeN0trAgD9qkfnVGeFpwOKDMuU93ceMArQHXYv34VOwH8fiOQOf932F3CDwcGbk2N?purpose=fullsize)

---

## Why BYOD Is Dangerous

An organization has limited control over personally owned devices.

For example:

```text
Employee Personal Laptop
          │
          │ Malware
          ▼
     Corporate Wi-Fi
          │
          ▼
   Internal Network
          │
     ┌────┼────┐
     ▼    ▼    ▼
    DC   File  Printers
         Shares
```

If the personal device is compromised, an attacker may potentially gain access to resources available to that device.

---

# 8. 📌 Nick Scenario

The source provides a scenario involving **Nick**, a logistics manager.

Nick:

- Works from home
    
- Uses his personal computer for work
    
- Uses the corporate Wi-Fi
    
- Has malware installed on his laptop
    

The malware gives an attacker remote access to the laptop.

When Nick connects the compromised personal system to the corporate network, the attacker may potentially reach resources such as:

- Domain Controllers
    
- File Shares
    
- Printers
    
- Other internal network resources
    

This creates an opportunity for **pivoting/lateral movement** across the organization's network.

### Key lesson

> **A compromised endpoint can become an entry point into the corporate network.**

---

# 9. 🔐 Multi-Factor Authentication

The source recommends **multi-factor authentication (MFA)** as an important authentication control.

Authentication factors can include:

- **Something you have**
    
- **Something you know**
    
- **Something you are**
    
- Location
    
- Other applicable factors
    

Using two or more factors makes it harder for an attacker to gain complete account access after compromising a password or hash.

### Especially important for:

- Administrative accounts
    
- Remote access
    
- Sensitive systems
    

---

# 10. 👀 SOC and Incident Response

Organizations should consider:

### SOC

**SOC = Security Operations Center**

A SOC can continuously monitor the environment.

Organizations can either:

- Build an internal SOC
    
- Use **SOC as a Service**
    

The source emphasizes that modern defensive technologies still require human operators to ensure they work correctly.

---

## Incident Response

Incident response cannot be completely automated.

Therefore, organizations should maintain a proper:

> **Incident Response Plan**

This prepares the organization to respond when a security breach occurs.

---

# 11. ⚙️ Processes

Policies and procedures have a major impact on security posture.

Without defined processes, it becomes difficult to:

- Hold employees accountable
    
- Manage assets
    
- Respond to incidents
    
- Recover from disasters
    
- Control access
    

The source specifically highlights the importance of practiced procedures such as a:

> **Disaster Recovery Plan**

---

# 12. 📋 Important Security Processes

### Asset Monitoring & Management

Implement:

- Host audits
    
- Asset tags
    
- Periodic asset inventories
    

These help ensure hosts aren't lost or forgotten.

### Access Control

Define processes for:

- User provisioning
    
- User de-provisioning
    
- MFA
    

### Host Provisioning & Decommissioning

Use:

- Baseline security hardening guidelines
    
- Gold images
    

### Change Management

Formally document:

> **Who did what and when they did it.**

This creates accountability and makes unauthorized changes easier to identify.

---

# 13. 🖥️ Technology

Organizations should periodically check their networks for:

- Legacy misconfigurations
    
- Emerging threats
    
- Newly introduced vulnerabilities
    
- Misconfigurations caused by new tools/applications
    

When changes are made to an environment, administrators should ensure that new vulnerabilities or security weaknesses are not accidentally introduced.

---

# 14. ⚖️ CIA Triad & Risk Acceptance

Security decisions involve balancing the:

- **Confidentiality**
    
- **Integrity**
    
- **Availability**
    

This is the **CIA triad**.

Sometimes completely eliminating a vulnerability may not be practical.

Therefore, organizations may have to decide whether to:

- Patch
    
- Mitigate
    
- Accept the risk
    

The source specifically notes that **risk acceptance may sometimes be the best option**, depending on the environment.

---

# 15. 🌐 From the Outside Moving In

A useful defensive strategy is to assess the environment:

> **From the outside moving inward.**

The goal is to understand how an external attacker might approach the organization.

---

# 16. 🛡️ Perimeter First

Important questions include:

### Assets

- **What exactly are we protecting?**
    
- **What are the most valuable assets the organization owns?**
    

### Network perimeter

- **What can be considered the perimeter of our network?**
    
- **What devices and services are accessible from the Internet?**
    

### Detection

- **How can we detect and prevent an attack?**
    
- **How do we ensure the correct team receives alerts quickly?**
    
- **Who is responsible for monitoring alerts?**
    

### Trust

- **Do we have external trusts with outside partners?**
    

### Authentication

- **What authentication mechanisms are we using?**
    

### Management

- Do we require **Out-of-Band (OOB) management**?
    
- Who has access to it?
    

### Recovery

- Do we have a **Disaster Recovery plan?**
    

---

# 17. ☁️ Hybrid Cloud

Modern organizations often operate **hybrid-cloud infrastructures**.

This means infrastructure can be divided between:

```text
On-Premises
     +
Cloud
```

The source gives examples of cloud providers:

- AWS
    
- Azure
    
- GCP
    

Some systems may therefore be owned and managed directly by the organization, while others are hosted by third-party cloud providers.

---

# 18. 🔥 Firewall / External Interface

The source highlights:

### Next-Generation Firewall capabilities

A firewall can help with:

- Blocking suspicious connections based on IP
    
- Ensuring only approved individuals connect to VPNs
    
- Quickly disconnecting suspicious connections
    
- Minimizing disruption to legitimate business functions
    

---

# 19. 🏢 Internal Considerations

External security isn't enough.

Organizations must also examine the internal network.

Important questions include:

### DMZ

Are Internet-exposed hosts:

- Properly hardened?
    
- Located in a **DMZ**?
    

### IDS/IPS

Are **Intrusion Detection and Prevention Systems** deployed?

### Network segmentation

Are different teams separated into different network segments?

### Production vs Management

Are production and management networks separated?

### Remote administration

Are approved employees tracked when accessing:

- Administrative networks
    
- Management networks
    

### Security correlation

Can infrastructure and endpoint security data be correlated?

### Host monitoring

Are organizations using:

- Host-based IDS
    
- Host-based IPS
    
- Event logs?
    

---

# 20. 🧱 Network Segmentation

![Image](https://images.openai.com/static-rsc-4/ObmgU0pcQYjeK-ADbTQrLqqg7JpBiQttpT9ymtAO2EJAYsXTJ7EiCy1AyYKYlFXIlJjXBLk6rKfBzQYKZxn720vUe8VNKnni-xsLf2QnaN_Ip3ccovHuq84yXq8L1D2Ws1aRp0fd-VGLgwx9SOVVaHcNusqTpjd3dhDuUY2BTq60uG9uE-VnbrjL1_GQAW5i?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/DxqS_6ahj6goyp_RFn5Q1_mCCEVTrbO5rnt767t4e_-1UOa7TaH_GLs-P3zvJa7Z1sXNbtd2uotlJ5m8_NKy8r7rqOToUF3u42xQvHJgipMLG9lmW7lrFCd1qfvpmv4Yl5WqHx9HcdDhpnapbhDJwgUrh0jdNkbUs28cnivfH0oIP8yQv5ujou3PXSz11E6K?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/0dz2LrVnKCu1bufa2E0dgS_sealmb2B6UmBJI3q4EuNbqIMMXFdKM502YmYYd12RzVa50QjGRFeHi1twKSUG0We6JtOnr7f6kMMq7HziTZcs20b6Ej80tYsB-l8deH4AuZf5FnZQ1kk5I6lIHcbgKAikoyNOWrTZBuwOazalaYPoW_Tv4X-MJVuoqH2QMt8d?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/h_o8JfhBjb4tDDqNVliYO6LYWkuNZHZJFR_vT4PS0Lt74uboOPaong2_h-01jtsW1ScwfFiQLWEa4CU_ocJjV9rIx3_SNGPt_kf3Vv-M9VQRmEpRodjpRijvHNKD1yMYv2Mj7hvb7zll-x9437lWHi8-1Z7E0pVWJExY8cZTC4R7LF_cZV7ZqfUPqOroEizB?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/96eM17i_mEByY_p5ZEqqvwbA9_I3q4Wg46uEr298qc8JxCtjo5qqOfhemOGjuKgepxXe3HppPKR_w2ofxiMg6-lvd_60z1oLeR23b8UGcLMflyGHMPp9Ad4_28o-G9e7m8MQEuDJZPN8EXGJ-jTxChmxhU_a9KDXwFwGVIWmrUXhlymbvXq6YIgFDRa6NwIO?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/inOGBSto8qxzPR_lORdPG5sjdhQoHJD38hoAVktGXsNy6HzZBJpY1CCCnW3uKdfAL23Cc8myqtVs6xeQk4WqmiUxfBHxpAqnRhU4vGOhboEVv1VudohtIq7qRiVYpt1uUdekQYMtdcczLYS04bjNvfar1pmijNtBrJmaBXAVesSGr_5nBPSfP7UUJU9sz1E3?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/COsP5ZqUUyO8a_I3BmXr2spnRHBoEq49lepy3DjnWz1RdKsafDVllC8QH5ixpUuAXbRyXlHry2U5XIZO6rWjsMkK0M8tw3qsabY1_rsslJX1IG_tNL5Ui9iD_FXhK5iM9eQ3eff7vhGyajDpw_FeogDWStNiiz2mBG_cGNjtQNLvaYawFwHgmJUE4uLoDF9n?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/iBpOaQ_hMQ1WEqCE8OT9T7h800IPgeM3ldfh6jy9EfE7a_C9ey2L6B4ONLs2slf1QEvJI8vnu1QGRIjTpyECedytlOFFibrTAHfm3Zs5bzkb9dDBQY_enV2hBwuBl5EunbYH1j4J6APWqYVcumMo8u1ew3ST3zTwMjO0LFpNcMiaH-CH26nv09dLIDy61TBD?purpose=fullsize)

Network segmentation is one of the major defensive concepts in this section.

Instead of:

```text
Everyone
   ↓
Everything
```

use:

```text
           NETWORK
              │
       ┌──────┼──────┐
       ▼      ▼      ▼
      HR    Server   Admin
             Zone     Zone
```

The source gives the example that a standard HR user should not be able to access infrastructure such as:

- Switches
    
- Routers
    
- Internal website administration panels
    

This limits opportunities for **lateral movement**.

---

# 21. 📊 SIEM

**SIEM = Security Information and Event Management**

A proper SIEM can:

- Collect logs
    
- Correlate events
    
- Analyze activity
    
- Help identify attacks
    
- Improve visibility
    

The source emphasizes that maintaining visibility throughout the environment is one of the best ways to detect and potentially prevent attacks.

---

# 22. 🔎 Why Visibility Matters

Think of the defensive chain:

```text
Logs
 ↓
Monitoring
 ↓
Correlation
 ↓
Detection
 ↓
Alert
 ↓
Investigation
 ↓
Response
```

Without visibility:

```text
Attack
 ↓
No logs
 ↓
No alert
 ↓
No investigation
```

---

# 23. 🧠 MITRE ATT&CK Breakdown

The source maps several techniques practiced in the module to **MITRE ATT&CK**.

Important distinction:

- `TA` = overarching tactic
    
- `T###` = technique
    

The source references the **Enterprise ATT&CK Matrix**.

---

# 24. 🔴 External Remote Services — T1133

**MITRE Technique: T1133**

### Prevention

The source recommends:

1. Proper firewall segmentation
    
2. Controlling Internet traffic
    
3. Blocking unnecessary internal protocols from reaching the Internet
    
4. Using VPN or another mechanism that logically places the host inside the network before accessing services
    

### Key idea

```text
Internet
   │
Firewall
   │
VPN / Controlled Access
   │
Internal Service
```

---

# 25. 🔵 Remote Services — T1021

**MITRE Technique: T1021**

Examples include remote services such as:

- SSH
    
- RDP
    

### Defensive controls

**MFA**

MFA makes stolen credentials less useful.

**Restrict remote-access accounts**

Only appropriate accounts should be allowed remote access.

**Separate duties**

Users should only remotely access the portions of the network they actually require.

**Network firewalls**

Limit incoming and outgoing connections.

**Host firewalls**

Restrict unauthorized remote-service connections.

**OOB management**

For infrastructure such as:

- Routers
    
- Switches
    

remote management should ideally only be exposed through an **Out-of-Band network**.

---

# 26. 🟡 Use of Non-Standard Ports — T1571

**MITRE Technique: T1571**

This can be difficult to detect.

Attackers may use familiar protocols such as:

```text
HTTP
HTTPS
```

but place them on unusual ports.

Example:

```text
HTTPS normally → 443

Suspicious example:
HTTPS → 444
```

The important detection principle is:

> **Know what normal looks like.**

Maintain a baseline of:

- Common ports
    
- Common protocols
    
- Normal protocol/port combinations
    

Then unusual combinations become easier to identify.

### Useful defensive technology

- Network IDS
    
- Network IPS
    
- Traffic monitoring
    

---

# 27. 🟣 Protocol Tunneling — T1572

**MITRE Technique: T1572**

Protocol tunneling involves hiding communications or transporting one type of traffic through another protocol.

Examples from the module include:

- SSH tunneling
    
- DNS-based tunneling
    

![Image](https://images.openai.com/static-rsc-4/RevyuQwryHXKtrVFIuBNUQKlf0mJTzB_KHvm27JJA0FFPPMP2nosVO3aXF1IZFyBmDaOABcQGGeb_Oyva3vnD6tJ7E23Lc-o7Jxcxuum0flsWWRA3ragcZ2Lyri7qNuArozWTWYxuRlWCx9sf89Ptm0ctY5R__EOjHFH6sjRpKM2a2xI5fwhuyw2MMCj9d-U?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/_rSuf7nAVIqPCTR3dEiZYQwZGcG-lkOamRLREfz8maKh0lovQSNKJ9MmoEzSH6kECCFnI1mAszn13JFPS_2hsZw5hquLYaMLThqEglU8PlYqYLfL5erS00Clnn7O4mD3a-_p7XELbSRNLnTZYcdM9PDsmwDh7w4p5o6LV9hPjMBY43GzAQ36sOPULPREu79C?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/wKCzkswieVg7zx6AS_2aGWliVaAR9XMY8sZUNZW4KEx8PnQGUJD-nPW4V0f_VxOjLziOf-_UDdi03ZPnBhRBH6dc8KLg5BjtzjqJ88lCk2WlKr7Q8dx7eOK5tGrefV136zXvqkuH5_Ic4rRjVlEL50DLf29GtzQ0UUw3r2RZQIersEI2Uxcxip_LUXpYkbIe?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/k2wSwvAaCoX-2ilKIuIp8tJ8VT2RokPtPjKU2u3aygiMvqKOMb_tmj5e9_XY8o_aOUp2Y8Av6nknIKbm_5ZPZqv5pD9eDhqjJt79nZsW_OQyuvneXmVJvaOf5gp2S2ZJhju5jSiMVWtPHExfaU1qKydIwbrt3WHtvChzE28BtsW8k9dLf3z5VhFgpCsAK1ky?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/oidO1DzhSenj3kccheCZraZO0WKB6x4Qgo6hQMohBg9PARRlAzUrB-6bP5DZkV6ZMdDvVUYLBICSplOFnDaD2ff2eZhBXVctp80lLOkemyP1s1blWqS5XYqH9LZfdTZeEQBzwK-WqxNMWsM6lEMw13U33wQ-ApsXql6_pXzIb94F_W53YHp8W5KmBMMct8hB?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/pFDXn65_RP_yd0c-7vufAsHpuL5r7DWHo_qJrMG_cIGWDvnLTPMK9JZVIm-7hAHpi9PJgq00fLfg_vwTXcMUoVoo_dY-tWv7PtlzlEA1BC74KJvJDCpeOyoYobBNDIxhvPvSzDQ6fGH_cknJavtJghuSDBckaZzX7C8dipkm2-dXJ3GokTzf2zXQApDqnuF7?purpose=fullsize)

### Defensive strategy

Organizations should strictly control:

- Which ports can communicate
    
- Which protocols can communicate
    
- Which hosts are allowed to communicate externally
    

---

## 🔥 Important DNS Security Point

If an organization has:

```text
Domain Controller
+
Internal DNS Server
```

internal hosts generally shouldn't need to perform unrestricted external DNS resolution themselves.

The source recommends restricting DNS resolution and preventing unnecessary direct external DNS access, while allowing appropriate DNS servers to perform external resolution.

This can help mitigate DNS-based tunneling.

---

# 28. 📡 Beaconing

Even when traffic is encrypted, defenders may still identify **patterns**.

For example:

```text
Connection
   ↓
wait
   ↓
Connection
   ↓
wait
   ↓
Connection
   ↓
wait
```

Repeated periodic communication can resemble **C2 beaconing**.

Therefore, defenders should monitor:

- Traffic frequency
    
- Destination patterns
    
- Repeated connections
    
- Unusual external communications
    

The source specifically identifies **Beaconing** as a useful traffic pattern to monitor.

---

# 29. 🟤 Proxy Use — T1090

**MITRE Technique: T1090**

Attackers may use proxy points to:

- Hide their infrastructure
    
- Distribute traffic across multiple hosts
    
- Avoid directly exposing their attack infrastructure
    

### Why detection is difficult

Proxy detection requires strong knowledge of:

> **Normal network flow within the environment.**

### Defensive strategy

Maintain lists of:

- Allowed domains
    
- Allowed IP addresses
    
- Blocked domains
    
- Blocked IP addresses
    

The source recommends an **allow-listing mindset**:

> Anything not explicitly allowed can be blocked until approved.

---

# 30. ⚫ LOTL — Living off the Land

The source lists:

```text
LOTL
```

with:

```text
MITRE:
N/A
```

**Living off the Land** means an attacker uses resources already available within the environment rather than necessarily introducing obvious external tools.

This makes detection harder.

---

## Why LOTL Is Difficult

If an attacker uses normal:

- Commands
    
- System utilities
    
- Existing applications
    
- Network functionality
    

their activity can resemble legitimate administration.

Therefore, defenders need a strong baseline of:

### Network behavior

What traffic is normal?

### User behavior

What do users normally do?

### Host behavior

What processes and commands are normally executed?

The source recommends monitoring for:

- Command shells
    
- Suspicious behavior
    
- Network activity
    

and using properly configured:

- EDR
    
- Antivirus
    
- Network monitoring
    
- Logging
    
- SIEM
    

---

# 31. 🧠 Complete MITRE Revision Table

|Technique|MITRE ID|Main Defensive Idea|
|---|---|---|
|**External Remote Services**|`T1133`|Firewall segmentation, VPN, restrict external access|
|**Remote Services**|`T1021`|MFA, restrict accounts, firewall controls, OOB management|
|**Use of Non-Standard Ports**|`T1571`|Establish port/protocol baselines and monitor anomalies|
|**Protocol Tunneling**|`T1572`|Restrict protocols/ports, monitor tunneling and beaconing|
|**Proxy Use**|`T1090`|Understand normal network flow; allow/deny domains and IPs|
|**LOTL**|`N/A`|Baseline user/host behavior, EDR, AV, logging, SIEM|

---

# 32. 🔥 Most Important Defensive Concepts

If you're studying this for a **pentesting exam/viva**, prioritize these:

### 1. Baseline

Know what is normally present.

```text
Normal → Easy to identify abnormal
```

### 2. MFA

Protect accounts even when passwords/hashes are compromised.

### 3. Network Segmentation

Limit lateral movement.

```text
HR ≠ Admin ≠ Production ≠ Management
```

### 4. SIEM

Centralize and correlate security logs.

### 5. IDS/IPS

Detect and potentially prevent malicious network activity.

### 6. EDR/AV

Provide endpoint visibility and protection.

### 7. OOB Management

Keep infrastructure management isolated from normal enterprise networks.

### 8. DNS Control

Restrict unnecessary external DNS resolution to reduce opportunities for DNS tunneling.

### 9. Port/Protocol Baselines

An unusual protocol on an unusual port can be an important indicator.

### 10. Incident Response

Detection is only useful if the organization knows what to do after an alert.

---

# 🧩 Final Mental Model

```text
                 DEFENSE
                    │
       ┌────────────┼────────────┐
       ▼            ▼            ▼
     PEOPLE       PROCESS     TECHNOLOGY
       │            │            │
       ▼            ▼            ▼
     Training     Policies      Firewall
     MFA           Access       IDS/IPS
     Awareness     Change Mgmt  EDR/AV
                                SIEM
                                Segmentation
                                Logging
                    │
                    ▼
               BASELINE
                    │
                    ▼
              DETECTION
                    │
                    ▼
             INVESTIGATION
                    │
                    ▼
              RESPONSE
                    │
                    ▼
              PREVENTION
```

### 🏆 One-line takeaway

> **Strong defense comes from knowing what your environment normally looks like, controlling who and what can access it, segmenting critical resources, collecting and correlating telemetry, and having people/processes ready to respond when something abnormal occurs.**