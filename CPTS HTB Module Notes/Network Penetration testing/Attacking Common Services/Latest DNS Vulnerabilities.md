# 1. 🔥 What Is a Subdomain Takeover?

A **Subdomain Takeover** occurs when an organization's subdomain still points through a DNS **CNAME** record to a third-party service/resource that is no longer active or controlled by the organization.

Common third-party providers mentioned in the material include:

- AWS
    
- GitHub
    
- Other cloud/hosting providers
    

The basic problem is:

```text
Company cancels third-party service
            ↓
Third-party resource disappears
            ↓
DNS CNAME is NOT deleted
            ↓
Subdomain still points to old resource
            ↓
Resource may become claimable
            ↓
Attacker may gain control
```

---

# 2. 🧠 The Core Idea

Imagine:

```text
customer-drive.inlanefreight.com
             │
             │ CNAME
             ▼
     old S3 resource
             │
             ▼
       No longer exists
```

The company may have forgotten to remove the DNS record.

If the third-party provider allows someone else to register/claim the abandoned resource, the attacker can potentially control what the company's subdomain serves.

---

# 3. 🖼️ Subdomain Takeover Visualization

![Image](https://images.openai.com/static-rsc-4/IC2p-_EtHkpsfEcDgc0cdI4b1kT0nRr0XIBYZOOfqlbvSL4CIhonf1p9ExGkvfp8f4hb8BcALDaOmrRt0SBGEjMT932HEkfDAAW4kk-yGvEL7KVHFBcPqLZFZ3qz_8h_02M8mgNLA1rhIulCzEzSg0XFHXEp29qj2mbWo1B65mUL_gjMp1QBtILu0Q3En96w?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/2RDfzDY4_8eFqMN5rN665MHUU3IVxkfAosUdeXQLQP-6Md3cHesRCn1lNbEvzSHFSrbdSOT_-UONF9OSzLBJjtoJGQFx-8GSfpSP9L8z8oDTEJ_foEVMCCMgNCHqZ3WYIIzo-IHEXwRoQgQUWDnwV3pJ3aqJ-4kyFAqp1zRet94ODbKS2mkP_3qTI-jUZ0o7?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/XJN6u0hpThhKYsaAZ_LyYtnKrpXpHd-wEubGP91tGNpVf74d5MHhH1fqmSQgk5FFpyEe_nWxNHDZ4l3bUX_eB864TuuH75fXqvw4t3ZGE99hremLOIbiNoGFWY7Ta20BzP_6Wiu36I5_RNRCG0X7DS2E6PvSVNcYeeenBfyhsJ2uFgFvHzRcLkNJG--tJ63s?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/jCUkaZN3Ty7Y_2HoB1OjlP1fDDxTxqvIbWEkk9oF5ot055HFsDL1BAAdoZdyluqZzT7pk9VQ5Ln7GF36D74bEi9kiBX-nMfvWLgoH4zjPP5vlRfYE2MyQr8EcHCTSISPvbbpW-WFhVCdU4DaQjpH3NpkdzC3jq5MhHYjxz1tlsdF84a6HuBws8a8iBpLpC8G?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/XJOO_lljY8lMgyKAY5u4WiBbI8JEeGZSX-DoK3mDJo8l06tufsppKEkI9k_iEvW_bXu_WbZh9VypkKi7IzqNVtDUnjB8ujL4loaj1MgfC-UvMLBSz3GsZ1kEXAfq2OlxmiU2KNrPZMtc71eITSUxYOVzdnukimFedcayenhgpphkNlt3UPtHDHu_chnkuzPU?purpose=fullsize)

```text
                COMPANY
                   │
                   │ DNS
                   ▼
        customer.example.com
                   │
                   │ CNAME
                   ▼
         Third-Party Service
                   │
             Service deleted
                   │
                   ▼
            Resource abandoned
                   │
                   ▼
          Attacker claims resource
                   │
                   ▼
          Attacker-controlled site
                   │
                   ▼
      customer.example.com
```

---

# 4. 🚨 Why Does This Vulnerability Exist?

The main reason is **orphaned DNS records**.

Companies frequently use third-party services and later discontinue them.

However:

```text
Third-party service → Deleted
DNS record          → Forgotten
```

DNS records themselves generally don't incur an additional service cost, so organizations may leave them behind.

This creates a **dangling DNS reference**.

---

# 5. 🔗 CNAME — The Important DNS Record

A CNAME record creates an alias from one domain to another.

Example:

```text
customer-drive.inlanefreight.com
                │
                │ CNAME
                ▼
     abandoned-service.example
```

The company owns:

```text
inlanefreight.com
```

but the CNAME points somewhere else.

If that destination becomes claimable, the subdomain may become vulnerable.

---

# 6. 🎯 Typical Attack Scenario

The source gives the following conceptual scenario:

```text
customer-drive.inlanefreight.com
             │
             │
             ▼
      Non-existing AWS S3 bucket
             │
             ▼
          HTTP 404
```

The important observation is that the company's subdomain still exists while the referenced third-party resource does not.

---

# 7. ⚠️ Important: 404 ≠ Automatic Takeover

A particularly important pentesting lesson:

> An `HTTP 404` response can be an **indicator**, but it does not by itself prove that a subdomain is takeoverable.

The actual third-party service needs to be checked to determine whether the abandoned resource can legitimately be claimed.

The source describes a 404 from the referenced service as an indication that the subdomain **can most likely** be taken over through the relevant third-party provider.

---

# 8. 🧩 Subdomain Takeover Attack Chain

```text
             CNAME FOUND
                  │
                  ▼
       Third-Party Resource
                  │
                  ▼
       Resource No Longer Exists
                  │
                  ▼
       Service-Specific Error
             (e.g. 404)
                  │
                  ▼
        Potentially Claimable
                  │
                  ▼
        Attacker Claims Resource
                  │
                  ▼
        Attacker Controls Content
                  │
                  ▼
       Original Company Subdomain
                  │
                  ▼
           Victim Visits It
```

---

# 9. 🕵️ Why Subdomain Takeover Is Dangerous

One of the biggest dangers described in the material is **phishing**.

Consider:

```text
customer-drive.inlanefreight.com
```

A customer sees:

```text
inlanefreight.com
```

in the browser.

Because the subdomain appears to belong to the legitimate company, the customer may trust it.

But if the underlying resource has been taken over:

```text
Official-looking subdomain
          ↓
Attacker-controlled content
          ↓
Fake login page
          ↓
Victim enters credentials
```

---

# 10. 🎭 Phishing Scenario

```text
Victim
  │
  │ Visits:
  │ customer-drive.inlanefreight.com
  ▼
Company DNS
  │
  │ CNAME
  ▼
Attacker-controlled resource
  │
  ▼
Fake Company Login Page
  │
  ▼
Victim Trusts Domain
```

The dangerous part is that the attacker isn't necessarily using an obviously suspicious domain.

Instead, the victim sees a **legitimate company's subdomain**.

---

# 11. 🧠 Why Trust Is the Main Issue

Compare:

### Obvious phishing

```text
inlanefreight-login-random.com
```

Victim may be suspicious.

### Subdomain takeover

```text
customer-drive.inlanefreight.com
```

The domain appears to be:

```text
inlanefreight.com
```

Therefore, the attack can abuse the trust associated with the organization's legitimate domain.

---

# 12. 🔄 Initiation of Subdomain Takeover

The source divides the attack into:

```text
1. Source
2. Process
3. Privileges
4. Destination
```

Let's break it down.

---

# 13. Step 1 — Source

The source is:

> **The subdomain name that is no longer used by the company.**

Example:

```text
customer-drive.inlanefreight.com
```

The attacker discovers that the subdomain still exists in DNS but its underlying third-party service is no longer active.

---

# 14. Step 2 — Process

The attacker attempts to register/claim the corresponding resource with the third-party provider and links it to their own resources.

Conceptually:

```text
Abandoned Resource
        │
        ▼
Attacker registers it
        │
        ▼
Attacker-controlled resource
```

The exact registration process depends on the third-party provider.

---

# 15. Step 3 — Privileges

This part is subtle.

The source describes the relevant privileges as belonging to:

> **The primary domain owner and its DNS entries.**

The company's DNS server still contains the CNAME record.

The third-party provider may not know—or care—that the DNS record still exists.

Therefore:

```text
Company DNS
    │
    ▼
Still trusts CNAME
    │
    ▼
Still points to third-party destination
```

---

# 16. Step 4 — Destination

The destination is:

> **The attacker's server/resource.**

Once the attacker successfully claims the abandoned third-party resource:

```text
Company Subdomain
        │
        │ CNAME
        ▼
Attacker-controlled Resource
```

The first attack cycle is complete.

---

# 17. 🔄 Second Cycle — Trigger the Forwarding

Now the attacker waits for someone to visit the subdomain.

The source again uses:

```text
Source
Process
Privileges
Destination
```

---

# 18. Step 5 — Source

The source is the:

> **Visitor requesting the company's subdomain.**

For example:

```text
https://customer-drive.inlanefreight.com
```

The visitor's request reaches the company's DNS infrastructure.

---

# 19. Step 6 — Process

The DNS server checks its records.

It still has:

```text
customer-drive.inlanefreight.com
        │
        │ CNAME
        ▼
attacker-controlled resource
```

Because the DNS record has not been removed, the visitor is directed toward the CNAME destination.

---

# 20. Step 7 — Privileges

The source explains that the DNS administrators have authority over the company's domain and DNS records.

Because the stale CNAME remains in the DNS configuration, the DNS system continues to treat the mapping as valid.

Conceptually:

```text
DNS Record Still Exists
          ↓
DNS Resolver Uses Record
          ↓
Visitor Gets Destination
```

---

# 21. Step 8 — Destination

The destination is the resource/server that the visitor is directed toward.

In the vulnerable scenario:

```text
Visitor
   │
   ▼
Company Subdomain
   │
   │ CNAME
   ▼
Attacker's Resource
```

The attacker can now control the content associated with the subdomain.

---

# 22. 📊 Complete Source → Process → Privileges → Destination

## Cycle 1 — Takeover

|Step|Category|Concept|
|---|---|---|
|**1**|Source|Abandoned company subdomain|
|**2**|Process|Attacker registers/links the abandoned third-party resource|
|**3**|Privileges|Company's DNS still contains the CNAME|
|**4**|Destination|Attacker-controlled resource/server|

## Cycle 2 — Forwarding

|Step|Category|Concept|
|---|---|---|
|**5**|Source|Visitor requests the company's subdomain|
|**6**|Process|DNS uses the outdated CNAME|
|**7**|Privileges|Existing DNS record remains trusted/valid|
|**8**|Destination|Visitor reaches the attacker-controlled resource|

---

# 23. 🖼️ Full Attack Flow

```text
                COMPANY
                   │
                   ▼
       customer-drive.company.com
                   │
                   │ CNAME
                   ▼
          old-third-party-service
                   │
             Service removed
                   │
                   ▼
             DNS left behind
                   │
                   ▼
             Attacker discovers
                   │
                   ▼
       Attacker claims resource
                   │
                   ▼
       Attacker-controlled server
                   │
                   ▲
                   │
             Victim visits
                   │
                   │
       customer-drive.company.com
```

---

# 24. 🎯 Impact Beyond Phishing

The source specifically mentions that subdomain takeover can potentially be used for more than phishing.

Examples include:

### 🍪 Cookie Theft

If cookies are scoped broadly enough and other security conditions permit, an attacker-controlled subdomain may create opportunities to interfere with or obtain sensitive browser data.

---

### 🔄 CSRF

Potentially abusing:

> **Cross-Site Request Forgery (CSRF)**

depending on the application's cookie and origin configuration.

---

### 🌐 CORS Abuse

A compromised subdomain can become particularly interesting where an application's CORS configuration trusts that subdomain.

Conceptually:

```text
Trusted Origin
      ↓
Compromised Subdomain
      ↓
Potential CORS Abuse
```

---

### 🛡️ CSP Bypass

The source also mentions:

> **Content Security Policy (CSP)**

A compromised trusted subdomain can potentially become relevant to CSP bypass scenarios when CSP trusts that domain.

---

# 25. 🔥 Why Subdomain Takeover Can Become More Serious

The basic vulnerability:

```text
Dangling CNAME
```

may initially appear to be only:

```text
Content Control
```

But depending on the company's architecture, the impact can potentially expand into:

```text
Subdomain Takeover
       │
       ├── Phishing
       ├── Cookie-related attacks
       ├── CSRF
       ├── CORS abuse
       └── CSP-related attacks
```

The exact impact depends heavily on the target application's configuration.

---

# 26. 🧠 Important Bug Bounty Perspective

The source notes that **Subdomain Takeover** is explicitly listed as a bounty category by major bug bounty platforms such as HackerOne.

This makes it a useful area to understand during authorized bug bounty testing.

The source also mentions that GitHub contains tools that can automate:

- Discovery of potentially vulnerable subdomains
    
- Proof-of-Concept creation
    

---

# 27. 📈 RedHuntLabs Study

The material cites a **2020 RedHuntLabs study**.

According to the figures provided in the source:

```text
220 million subdomains examined
          ↓
400,000+ potentially vulnerable
          ↓
62% belonged to e-commerce
```

These figures are **historical study results from the supplied material**, not a current measurement of the Internet in 2026.

---

# 28. 🔍 How to Find a Potential Subdomain Takeover

A simplified authorized-testing methodology:

```text
1. Enumerate subdomains
          ↓
2. Identify CNAME records
          ↓
3. Identify third-party providers
          ↓
4. Determine whether destination exists
          ↓
5. Inspect provider-specific error
          ↓
6. Determine whether resource is claimable
          ↓
7. Verify safely
          ↓
8. Document impact
```

---

# 29. 🧰 Useful Tools

From the material you've studied:

|Tool|Purpose|
|---|---|
|**Subfinder**|Subdomain enumeration|
|**Sublist3r**|Subdomain discovery|
|**Subbrute**|DNS brute forcing|
|**host**|DNS/CNAME lookup|
|**nslookup**|DNS lookup|
|**dig**|DNS queries|
|**Fierce**|DNS enumeration|
|**can-i-take-over-xyz**|Reference for takeover conditions|

---

# 30. 🔗 Connection With Previous DNS Notes

You should connect this topic with the previous **Attacking DNS** chapter.

### Previous topic:

```text
Subdomain Enumeration
        ↓
Find subdomains
```

### Current topic:

```text
Subdomain
    ↓
Check CNAME
    ↓
Third-party service
    ↓
Resource missing?
    ↓
Potential takeover
```

So the complete methodology becomes:

```text
DNS Enumeration
      ↓
Subdomain Enumeration
      ↓
CNAME Enumeration
      ↓
Third-Party Identification
      ↓
Dangling Resource Detection
      ↓
Takeover Assessment
```

---

# 31. 🧪 Example — AWS S3

The source gives an AWS-related scenario.

Conceptually:

```text
customer-drive.inlanefreight.com
             │
             │ CNAME
             ▼
      old S3 bucket
             │
             ▼
        Bucket deleted
             │
             ▼
      DNS record remains
             │
             ▼
      Potential takeover
```

The key observation is:

> The **subdomain belongs to the company**, but its DNS destination belongs to a third-party service.

---

# 32. ⚠️ What Makes a CNAME Suspicious?

A potentially interesting record may look like:

```text
support.company.com
       │
       ▼
third-party-service.example
```

Then:

```text
third-party-service.example
        ↓
Doesn't exist / resource deleted
        ↓
Provider gives an error
        ↓
Resource may be claimable
```

That is when further investigation becomes worthwhile.

---

# 33. ❌ What Is NOT Enough to Prove Takeover?

Don't report:

```text
CNAME exists
```

as a confirmed takeover.

Also don't automatically assume:

```text
HTTP 404
```

means takeover.

You need to establish that:

```text
CNAME
  +
Abandoned Resource
  +
Provider-Specific Claimability
  +
Successful/Safe Verification
```

supports the finding.

---

# 34. 🛡️ Defensive Mitigation

Organizations can reduce the risk by maintaining DNS hygiene.

### When removing a third-party service:

```text
Remove service
      ↓
Remove DNS record
      ↓
Verify DNS propagation
      ↓
Check for dangling CNAMEs
```

### Regularly:

- Inventory subdomains.
    
- Review CNAME records.
    
- Track third-party resources.
    
- Remove unused DNS entries.
    
- Monitor abandoned cloud resources.
    
- Include DNS cleanup in service decommissioning procedures.
    

---

# 35. 🔐 Security Team Checklist

```text
☐ Enumerate all subdomains
☐ Inventory CNAME records
☐ Identify third-party dependencies
☐ Identify decommissioned resources
☐ Check provider-specific takeover conditions
☐ Remove dangling records
☐ Monitor DNS changes
☐ Review cloud resource ownership
☐ Include DNS in asset-management processes
```

---

# 36. 📝 Viva / Interview Questions

### Q1. What is subdomain takeover?

A vulnerability where an organization's subdomain points to an abandoned or claimable third-party resource, allowing another party to potentially control the resource associated with that subdomain.

### Q2. What DNS record is commonly involved?

```text
CNAME
```

### Q3. Why does subdomain takeover happen?

Usually because an organization removes/decommissions a third-party service but forgets to remove the corresponding DNS record.

### Q4. Give an example of a third-party service.

The material mentions:

```text
AWS
GitHub
Akamai
Fastly
```

### Q5. Why is a 404 interesting?

It can indicate that the third-party resource no longer exists, making the CNAME worth investigating.

**It does not alone prove takeover.**

### Q6. What is the biggest impact discussed?

```text
Phishing
```

because the attacker can potentially serve content from an apparently legitimate company subdomain.

### Q7. What other attacks are mentioned?

```text
Cookie-related attacks
CSRF
CORS abuse
CSP bypass
```

### Q8. What should you check first?

```text
Subdomain
   ↓
CNAME
   ↓
Third-party destination
```

### Q9. Why can customers trust the compromised subdomain?

Because the URL still uses the organization's legitimate parent domain.

### Q10. How can organizations prevent this?

Remove unused DNS records when third-party services are decommissioned and regularly audit DNS/CNAME records.

---

# 37. 🔥 Quick Comparison

|Concept|Meaning|
|---|---|
|**DNS Enumeration**|Collect DNS information|
|**Subdomain Enumeration**|Discover subdomains|
|**CNAME**|Alias pointing one name to another|
|**Dangling CNAME**|CNAME pointing to an unavailable/abandoned resource|
|**Subdomain Takeover**|Claiming the abandoned resource and gaining control associated with the subdomain|
|**DNS Spoofing**|Manipulating DNS responses|
|**Phishing**|One possible impact of a compromised subdomain|

---

# 38. 🧠 One-Minute Revision

```text
                 SUBDOMAIN TAKEOVER
                         │
                         ▼
                 Company Subdomain
                         │
                         │ CNAME
                         ▼
                Third-Party Service
                         │
                  Service Removed
                         │
                         ▼
                DNS Record Remains
                         │
                         ▼
                Resource Abandoned
                         │
                         ▼
                Provider-Specific
                Takeover Possible
                         │
                         ▼
                  Attacker Claims
                    Resource
                         │
                         ▼
                Attacker Controls
                     Subdomain
                         │
            ┌────────────┼────────────┐
            ▼            ▼            ▼
         Phishing       CSRF      CORS/CSP
```

---

# 🏆 39. The Ultimate Memory Trick

Remember:

> **CNAME → Dead Resource → Claim Resource → Control Subdomain → Potential Impact**

Or even shorter:

```text
CNAME
 ↓
Dangling
 ↓
Claim
 ↓
Control
 ↓
Impact
```

### And remember the attack's 8-step structure:

```text
1. Find abandoned subdomain
2. Claim third-party resource
3. Existing DNS gives the relationship
4. Attacker's resource becomes destination

5. Victim visits subdomain
6. DNS follows old CNAME
7. Existing DNS record remains trusted
8. Victim reaches attacker-controlled destination
```

**Core concept:** the vulnerability isn't that the attacker directly changes the company's DNS. The critical mistake is that the company **left an old CNAME pointing to a third-party resource that can subsequently be claimed**, allowing the attacker-controlled resource to become reachable through the company's legitimate subdomain.