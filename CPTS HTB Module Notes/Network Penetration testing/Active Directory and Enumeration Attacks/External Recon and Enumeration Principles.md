# Scenario

![Image](https://images.openai.com/static-rsc-4/1kapF7Ri3Ump8OZ4Auy8Hsa52Cv1ke4vWRKj22R5ZcKjDo4y6ZbpOX0Osf7gHAWkzMOUoDstL45ZuFvP5xeNhNehAM9pVjO2tV6Ny8NvKn56kuzPpBHDKVm8AyN43L3bMYR3HlxpSw5cBiAFC9k8WMAu4nIcwi7Ri6_bAGUgFgxhbYvPRnsJZ0WwlUR7OcXS?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/-WFaeKRhCbNIm7hxXRWk1lw20yoEkcDuixNplZdzjs5YPYmid4hrM-9RfIfyGmMCXmh7cQFlXCCRC-V_wQTZwPKbLHgRtOSxROPMKyVRXa8oXHAu9ymjWrF1j1NQ0Y9QcMFtOql0wAwEcIKNJ4mTApy6LHAXUjGta2HWFpUGMv-n0-fRWrQNfyp_5eZDsClx?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/5p79M9-yMLUAptOPSKPA9Xgpqj77uIjhh38SG9QTdEH4vMpX0UTeO8tmrBXxsCj6E0IpHWwJtDGJgf_ccPT49j8I1d8zHi0WzgxSU79E0gwo6tRj8R2x4UUNBexYCR31YeZK3crtP9LjoxfQ5CRoo3rt9qlmVu-3R0zJCZ4rmcGAV-_dRe0Lrx8s2y7RlIKX?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/sJJItLup4ItHOJGEpkM_vw6RlbYgwn6zDiU9OYV1wmGY2kc4rnpioWTFVRgLdPXD03Hduy8xyPdoxnz3DKSaumUcnEl58mqnic2ZGB6NCug6uI4R7ctC0iDIdamTtWCaM7dSd3DWWhhKiIxgWWbusdHlraxefFA0shJVSAKKPNeClln7p6nmAWGS_H4Szx3B?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/d9vpmkwL-8rRwoBvk1GCG0SE2kxT9UZRHqh-rMAwThZ9bLTp03mr1l4_tfP2vGXGhN73j_H4z8coW-FBeKFvAFuTj6ZKvecyHRt2K4_y1OcfEdp9OBWojIL9_V1RnWcMJAlNHp2A_3AwuTSgIJ_Sn1KmPQQuDNnujsn_p-J09i7K0wuDyCoOpN2iXwHeI3Vy?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/4vDXBm2dFwkUuz39WEDJhT9OrK5KdZLgRetA75rwNuQY15B6K6yq5UvjgUgyi_bChk74R21Tsnsmb6YBCqaBWhZY7vHBKpoqfiI0DXrt-AfKQO6h-bXjKLvf9K4D_kAML7mu57Hvafek4ORu4cXreU13wWEikQtvjYxnnSVTyDJ14oqQ2nmFCLa_4gyOV7xr?purpose=fullsize)

## 1. Assessment Background

The scenario places us in the role of **Penetration Testers working for `CAT-5 Security`**.

After successfully shadowing senior members of the penetration-testing team, the senior members now want to determine whether we can begin an assessment independently.

The target organization for this engagement is:

```text
Inlanefreight
```

The team lead, **Jack Smith**, sends a tasking email to the penetration-testing interns describing what needs to be accomplished.

### Main tasks mentioned in the tasking email

The assessment involves:

- **Domain enumeration**
    
- **Credential discovery**
    
- **Lateral movement**
    
- **Privilege escalation**
    
- **Acquiring Domain Admin credentials**
    

The information discovered during the assessment will be used to determine the next actions.

---

# 2. Purpose of the Module

This module is designed to provide practical experience with an internal penetration test against an **Active Directory environment**.

The final assessment consists of:

> **two internal penetration tests against the company Inlanefreight.**

The two tests start from different positions.

### First assessment

The first assessment simulates:

> **starting from an external breach position**

### Second assessment

The second assessment begins with:

> **an attack box inside the internal network**

This is important because real customers may request penetration tests from different starting positions.

For example, a customer may want to understand:

- What happens if an external attacker gets inside?
    
- What could an attacker do after already obtaining internal network access?
    

---

# 3. Skills Covered by the Module

The module is intended to demonstrate a strong understanding of:

### Automated Active Directory enumeration

Using tools to gather information about an AD environment automatically.

### Manual Active Directory enumeration

Manually investigating the environment and interpreting the information discovered.

### Active Directory attack concepts

Understanding common attack techniques against AD environments.

### Tool usage

The module exposes us to:

- A wide range of security tools
    
- Automated enumeration techniques
    
- Manual enumeration techniques
    

### Decision-making

One of the most important skills is:

> **Interpreting data gathered from an AD environment to make critical decisions to advance the assessment.**

This means the objective isn't simply to collect information.

We must understand what the information means and determine what action should come next.

---

# 4. Core Focus of the Module

The content is intended to cover:

> **core enumeration concepts necessary for anyone to be successful in performing internal penetration tests in Active Directory environments.**

The module also covers:

- Common attack techniques
    
- Attack techniques in greater depth
    
- More advanced concepts
    
- Foundational knowledge for later AD-focused modules
    

### Important

This module acts as a foundation.

The concepts introduced here will help prepare us for more advanced Active Directory material later.

---

# Assessment Scope

Before performing any testing, the customer provides a **scoping document**.

The scope defines the:

- IPs
    
- Hosts
    
- Domains
    

that are authorized for the assessment.

This is extremely important in a real penetration test because the tester must know exactly what they are authorized to test.

---

# 5. In Scope For Assessment

|**Range/Domain**|**Description**|
|---|---|
|`INLANEFREIGHT.LOCAL`|Customer domain to include AD and web services|
|`LOGISTICS.INLANEFREIGHT.LOCAL`|Customer subdomain|
|`FREIGHTLOGISTICS.LOCAL`|Subsidiary company owned by Inlanefreight. External forest trust with `INLANEFREIGHT.LOCAL`|
|`172.16.5.0/23`|In-scope internal subnet|

---

## 5.1 `INLANEFREIGHT.LOCAL`

This is the primary customer domain.

The scope specifically states that the domain includes:

- **Active Directory**
    
- **Web services**
    

Therefore, it is explicitly included in the assessment.

---

## 5.2 `LOGISTICS.INLANEFREIGHT.LOCAL`

This is a customer subdomain.

It is specifically listed in the scope and therefore is included in the assessment.

Important distinction:

```text
INLANEFREIGHT.LOCAL
        │
        └── LOGISTICS.INLANEFREIGHT.LOCAL
```

The module explicitly identifies this subdomain rather than giving permission to test every possible subdomain.

---

## 5.3 `FREIGHTLOGISTICS.LOCAL`

This represents a subsidiary company owned by Inlanefreight.

The important information provided by the scope is:

> **External forest trust with `INLANEFREIGHT.LOCAL`**

Conceptually:

```text
INLANEFREIGHT.LOCAL
        ▲
        │
        │ External Forest Trust
        │
        ▼
FREIGHTLOGISTICS.LOCAL
```

The existence of this trust is specifically mentioned in the assessment scope and will be relevant when understanding the environment.

---

## 5.4 `172.16.5.0/23`

This is the internal network range included in the assessment.

The exact scope provided by the customer is:

```text
172.16.5.0/23
```

Therefore, this internal subnet is authorized for testing.

---

# Out Of Scope

The customer has also explicitly defined what **must not be tested**.

This is just as important as knowing what is in scope.

---

## 6. Other Subdomains of `INLANEFREIGHT.LOCAL`

The scope specifically excludes:

> **Any other subdomains of `INLANEFREIGHT.LOCAL`**

The only subdomain explicitly included is:

```text
LOGISTICS.INLANEFREIGHT.LOCAL
```

Therefore, discovering another subdomain does not automatically make it authorized for testing.

### Key principle

> **Finding something does not automatically place it in scope.**

---

# 7. Subdomains of `FREIGHTLOGISTICS.LOCAL`

The scope explicitly excludes:

> **Any subdomains of `FREIGHTLOGISTICS.LOCAL`**

The parent domain itself is listed as in scope:

```text
FREIGHTLOGISTICS.LOCAL
```

But its subdomains are not.

---

# 8. Phishing and Social Engineering

The assessment explicitly excludes:

> **Any phishing or social engineering attacks**

Therefore, these techniques are not part of this engagement.

The assessment must rely on the authorized technical and information-gathering methods described in the scope.

---

# 9. Other IPs / Domains / Subdomains

The scope states:

> **Any other IPs/domains/subdomains not explicitly mentioned**

are out of scope.

This is a critical professional penetration-testing rule.

For example, if during enumeration we discover another domain that wasn't listed in the scope, we should **not assume permission to attack it**.

---

# 10. Real-World `inlanefreight.com`

The scope specifically restricts activity against the real-world website:

```text
https://www.inlanefreight.com
```

The restriction states that:

> **Any types of attacks against the real-world inlanefreight.com website outside of passive enumeration shown in this module**

are out of scope.

Therefore, the module allows passive information gathering but does **not** authorize active attacks against the real-world website.

---

# Methods Used

The scope defines the methods authorized for assessing Inlanefreight.

There are three important areas in this section:

1. **External Information Gathering**
    
2. **Internal Testing**
    
3. **Password Testing**
    

---

# 11. External Information Gathering (Passive Checks)

External information gathering is authorized to demonstrate the risks associated with information that can be gathered about the company from the internet.

The assessment is designed to simulate a real-world attacker.

Therefore, CAT-5 and its assessors will perform external information gathering from:

> **an anonymous perspective on the internet**

This means that no additional information is provided in advance about Inlanefreight beyond what is included in the assessment documentation.

---

# 12. Passive Enumeration

The testers will conduct:

> **passive enumeration**

The purpose is to uncover information that may:

- Help understand the organization
    
- Provide information useful to the internal testing phase
    
- Identify publicly accessible information that could assist an attacker
    

The module specifically mentions using:

> **open-source resources**

for this information gathering.

---

# 13. External Testing Restrictions

The scope clearly states:

> **No active enumeration, port scans, or attacks will be performed against internet-facing "real-world" IP addresses or the website located at `https://www.inlanefreight.com`.**

This is an important restriction.

### Allowed

```text
Passive enumeration
        ↓
Open-source information
        ↓
Publicly accessible data
```

### Not allowed

```text
Active enumeration
Port scanning
Attacks
```

against the real-world internet-facing infrastructure.

---

# Internal Testing

The internal assessment is designed to demonstrate the risks associated with vulnerabilities on:

- Internal hosts
    
- Internal services
    
- **Active Directory specifically**
    

The goal is to emulate attack vectors originating from inside Inlanefreight's environment.

---

# 14. Purpose of Internal Testing

The internal assessment allows Inlanefreight to understand:

- Internal vulnerabilities
    
- Possible attack paths
    
- Potential impact of successfully exploiting a vulnerability
    

The test is therefore intended to answer a practical question:

> **What could an attacker accomplish after gaining a position inside the organization?**

---

# 15. Untrusted Insider Perspective

The assessment is conducted from an:

> **untrusted insider perspective**

This means the tester is simulating an attacker who has obtained internal network access but does not automatically receive trusted administrative information.

The testers begin with:

> **no advance information outside of what's provided in this documentation and discovered from external testing.**

This makes enumeration particularly important.

---

# 16. Internal Testing Starting Position

Testing starts from:

> **an anonymous position on the internal network**

The objective is then to discover enough information to progress through the environment.

The module specifies the following goals:

```text
Anonymous Internal Position
          ↓
Domain User Credentials
          ↓
Internal Domain Enumeration
          ↓
Gaining a Foothold
          ↓
Lateral Movement
          ↓
Vertical Movement
          ↓
Compromise of In-Scope Internal Domains
```

---

# 17. Domain User Credentials

One of the objectives is:

> **obtaining domain user credentials**

The tester needs to discover credentials that can potentially provide additional access within the environment.

This becomes an important part of progressing through the assessment.

---

# 18. Internal Domain Enumeration

After obtaining useful information or credentials, the tester performs:

> **internal domain enumeration**

The purpose is to understand the internal Active Directory environment and identify information that can help advance the assessment.

---

# 19. Gaining a Foothold

The assessment aims to:

> **gain a foothold**

A foothold represents a useful initial position inside the target environment from which further assessment activities can be performed.

The module's progression is therefore:

```text
Internal Position
       ↓
Credentials
       ↓
Enumeration
       ↓
Foothold
```

---

# 20. Lateral Movement

The assessment then involves:

> **moving laterally**

This means progressing through the internal environment rather than remaining limited to the original system or position.

The objective is to determine how far an attacker could move through the authorized environment.

---

# 21. Vertical Movement

The scope also mentions:

> **moving laterally and vertically**

Vertical movement refers to progressing toward higher levels of access or privilege.

The overall assessment therefore examines both:

```text
Lateral = movement through the environment
Vertical = movement toward higher privileges
```

---

# 22. Domain Compromise

The ultimate internal-testing goal is to:

> **achieve compromise of all in-scope internal domains.**

The emphasis here is on the domains explicitly included within the assessment scope.

The tester must not extend the assessment into domains that are outside the authorized scope.

---

# 23. Operational Safety

The scope contains an important operational requirement:

> **Computer systems and network operations will not be intentionally interrupted during the test.**

This means the assessment should be conducted without intentionally disrupting normal operations.

The purpose of penetration testing is to demonstrate security weaknesses and their potential impact—not to unnecessarily interrupt business operations.

---

# Password Testing

The final method described in this section is:

> **Password Testing**

---

# 24. Password Files

Password files may be:

- Captured from Inlanefreight devices, or
    
- Provided by the organization
    

These files may be loaded onto:

> **offline workstations for decryption**

The resulting credentials may then be used to:

- Gain further access
    
- Continue the assessment
    
- Accomplish the assessment goals
    

---

# 25. Password Confidentiality

The scope contains an important security requirement:

> **At no time will a captured password file or the decrypted passwords be revealed to persons not officially participating in the assessment.**

This means credentials discovered during the engagement must remain confidential.

---

# 26. Secure Storage

All password-related data must be:

- Stored securely
    
- Kept on CAT-5-owned and approved systems
    
- Retained for the period defined in the official contract between CAT-5 and Inlanefreight
    

This demonstrates an important professional responsibility:

> **Sensitive information discovered during a penetration test must itself be protected.**

---

# Scoping Documentation

The module explains that this documentation style is something penetration testers will commonly encounter during their careers.

Especially on the offensive-security side, testers may receive:

- **Scoping documents**
    
- **Rules of Engagement (RoE) documents**
    
- Tasking information
    

These documents define the boundaries and requirements of an engagement.

---

# 27. Why Scoping Documents Matter

A penetration tester must understand the scope before performing testing.

The scope establishes:

```text
WHAT can be tested
        +
WHAT cannot be tested
        +
WHERE testing can occur
        +
WHAT methods are authorized
```

This protects both:

- The customer
    
- The penetration-testing team
    

---

# 28. The Stage Is Set

At this point, the module has established:

### Scope

What systems and domains can be assessed.

### Methods

How the assessment can be performed.

### Restrictions

What activities are prohibited.

### Objectives

What the testers need to accomplish.

The module then transitions into the technical portion.

The next stage is:

> **performing passive external enumeration against Inlanefreight.**

---

# 🧠 Key Information to Memorize

## In Scope

```text
INLANEFREIGHT.LOCAL
LOGISTICS.INLANEFREIGHT.LOCAL
FREIGHTLOGISTICS.LOCAL
172.16.5.0/23
```

## Out Of Scope

```text
Any other INLANEFREIGHT.LOCAL subdomains
Any subdomains of FREIGHTLOGISTICS.LOCAL
Any phishing or social engineering attacks
Any other IPs/domains/subdomains not explicitly mentioned
Attacks against the real-world inlanefreight.com website
```

## Main Assessment Goals

```text
Domain Enumeration
        ↓
Credential Discovery
        ↓
Internal Domain Enumeration
        ↓
Foothold
        ↓
Lateral Movement
        ↓
Vertical Movement
        ↓
Compromise of In-Scope Internal Domains
```

## External Testing

**Passive enumeration only** against the real-world environment.

## Internal Testing

Begins from an:

> **Anonymous position on the internal network**

and uses an:

> **Untrusted insider perspective**

## Password Testing

Password files may be processed on:

> **Offline workstations for decryption**

but captured/decrypted credentials must remain confidential and securely stored.

---

# 🔥 Module Takeaways

1. **Always understand the scope before testing.**
    
2. `INLANEFREIGHT.LOCAL`, `LOGISTICS.INLANEFREIGHT.LOCAL`, `FREIGHTLOGISTICS.LOCAL`, and `172.16.5.0/23` are explicitly in scope.
    
3. Other domains/subdomains are **not automatically authorized**.
    
4. Phishing and social engineering are explicitly prohibited.
    
5. Real-world `inlanefreight.com` may only undergo the passive enumeration described by the module.
    
6. The internal assessment simulates an **untrusted insider**.
    
7. The internal starting position is **anonymous**.
    
8. The assessment focuses specifically on **Active Directory**.
    
9. The progression includes credential discovery, domain enumeration, foothold, lateral movement, and vertical movement.
    
10. Password material may be processed offline, but credentials must be securely handled.
    
11. **Computer systems and network operations will not be intentionally interrupted during the test.**
    
12. The next section begins with **passive external enumeration against Inlanefreight**.
    

This is the complete set of notes for the **Scenario** section you provided, without pulling in later-module concepts.