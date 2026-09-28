## 1. External Reconnaissance

Before beginning a penetration test, it is beneficial to perform **external reconnaissance** against the target.

The module identifies three major purposes:

- **Validating information provided to you in the scoping document from the client**
    
- **Ensuring you are taking actions against the appropriate scope when working remotely**
    
- **Looking for any information that is publicly accessible that can affect the outcome of your test, such as leaked credentials**
    

### The "Lay of the Land"

The module describes external reconnaissance as getting the:

> **“lay of the land”**

The objective is to build as comprehensive a picture of the target as possible.

This can include:

- Discovering username formats
    
- Identifying information on the company's website
    
- Examining social-media information
    
- Searching GitHub repositories
    
- Looking for credentials accidentally committed to code
    
- Examining public documents
    
- Finding links to intranet sites
    
- Finding remotely accessible sites
    
- Identifying information that reveals how the enterprise environment is configured
    

### Reconnaissance mindset

```text
                 TARGET
                    │
                    ▼
          External Reconnaissance
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
      Scope       Public      Leaked
    Validation    Data        Data
        │           │           │
        └───────────┼───────────┘
                    ▼
             Better Target
             Understanding
                    │
                    ▼
             Internal Testing
```

---

# What Are We Looking For?

During external reconnaissance, we are looking for several important **data points**.

The module specifically identifies:

1. **IP Space**
    
2. **Domain Information**
    
3. **Schema Format**
    
4. **Data Disclosures**
    
5. **Breach Data**
    

These may not always be publicly available, but it is worthwhile to determine what information exists.

Passive reconnaissance can also become useful later if the penetration test gets stuck. For example, breach data might provide credentials that could potentially work against a VPN or another externally facing service.

---

## 2. IP Space

The module defines **IP Space** as information such as:

- Valid ASN for the target
    
- Netblocks used by public-facing infrastructure
    
- Cloud presence
    
- Hosting providers
    
- DNS record entries
    

### Why it matters

Understanding IP space helps us determine:

```text
Who owns the infrastructure?
        ↓
Which networks belong to the organization?
        ↓
Where is the infrastructure hosted?
        ↓
Which systems may belong to the target?
```

It also helps prevent accidentally interacting with infrastructure that isn't part of the engagement.

---

## 3. Domain Information

Domain information can be obtained from:

- IP data
    
- DNS
    
- Site registrations
    

The module suggests looking for:

- Who administers the domain
    
- Subdomains
    
- Publicly accessible domain services
    
- Mail servers
    
- DNS servers
    
- Websites
    
- VPN portals
    
- Potential security defenses
    

Examples of defenses mentioned in the module include:

- SIEM
    
- AV
    
- IPS/IDS
    

### Think of it as:

```text
Domain
  │
  ├── Subdomains
  ├── Mail Servers
  ├── DNS
  ├── Websites
  ├── VPN Portals
  └── Security Infrastructure
```

---

## 4. Schema Format

The module uses **Schema Format** to refer to patterns that can help us understand how an organization structures things such as:

- Email accounts
    
- AD usernames
    
- Password policies
    

This information can potentially be used to build a valid username list for testing externally facing services.

The module explicitly mentions:

- Password spraying
    
- Credential stuffing
    
- Brute forcing
    

### Example

If publicly available information shows:

```text
john.smith@company.com
jane.doe@company.com
```

we may infer:

```text
first.last
```

as a possible naming convention.

That can help construct a username list for later authorized testing.

---

# 5. Data Disclosures

Data disclosures refer to publicly accessible files that may contain information useful to a penetration tester.

The module specifically mentions:

- `.pdf`
    
- `.ppt`
    
- `.docx`
    
- `.xlsx`
    

Potential information inside those documents includes:

- Intranet listings
    
- User metadata
    
- Shares
    
- Software information
    
- Hardware information
    
- Credentials accidentally pushed to GitHub
    
- Internal AD username formats contained in document metadata
    

### Important idea

A seemingly harmless public document can reveal internal information.

```text
Public Document
      ↓
Metadata / Links / Names
      ↓
Internal Information
      ↓
Better Understanding of Environment
```

---

# 6. Breach Data

**Breach Data** refers to publicly released information such as:

- Usernames
    
- Passwords
    
- Other critical information
    

that could potentially help an attacker gain a foothold.

The module specifically emphasizes that passive recon can sometimes provide the information needed to move forward when an assessment becomes difficult.

---

# Where Are We Looking?

The module identifies several resources that can provide the data points above.

|Resource|Examples / Purpose|
|---|---|
|**ASN / IP registrars**|IANA, ARIN, RIPE, BGP Toolkit|
|**Domain Registrars & DNS**|DomainTools, PTRArchive, ICANN, DNS requests|
|**Social Media**|LinkedIn, Twitter, Facebook, news|
|**Public-Facing Company Websites**|About Us, Contact Us, embedded documents|
|**Cloud & Dev Storage Spaces**|GitHub, AWS S3, Azure storage, Google dorks|
|**Breach Data Sources**|Have I Been Pwned, Dehashed|

![Image](https://images.openai.com/static-rsc-4/7JGEOqDydb6S2NOMipa1nUVURvZU87Sy7nwIJjTGJrKQG2vQBrkKtYlAAJC6Cl-UKX_xFskQHX9TuF7H0ZEevyCDyOLlpSNz-jWlPgt0X3im_oCM2TSQO4XAkViBb9rSe3C2BFUIhjPutoP8qn3oO0F8bohJu9zwXgO6AScOSAr6E24kIu3TzwhYoQm4I-2v?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ieYCGAceBqXmpVS79GEQtKC2Ml-ykFbliZTqcOHxQ6XYIJDuSJBHiP4oCaPj53FWLKnMNpJx00JAOz5-r3TcedhC6RVBm7irrokHOBGgLWmadg8cxFhzfXdeNXscdz8IH_KAhy4pIs-CDxnueEPZ9EX2PJxxK8cSLcClDbas0yyu-btD70PQY4LZTE0qvk6C?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/keju1GCrPxSgvA3JVZ_ZRDEHBOAQmtfeEE7OnJYOjmP9-WvBgKJaavj5Kh1gYXhNBN4t4JIyUvHcb4rfi_hrQI6JCqskbaj_Eu-GkxJk6q7M6qIHG-awpgzydp0czzy20cJ_a_BUZEZpSkQZ4cI6GUifAt81q3khDzby39rP8gE4NxNc9ZmJlcD3jW-qL91E?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/MrHLmJBvKlLq_hq98zhIjwqlQiNNxJC2SnNZdd0MYkvTJ2fp2ShNcSb0zuvdPZnADSvKsSir1kvYSjILxiBVgGg_SWQshEn9r3DVeXWL55Pjysq_DHX2xIy3J9JCt8Ji2hZAzZe3_UIHVLHytldeWnCAckpJNV3xgevuW5IdvpGRX7Hz8PmWjlbMA7VgUATy?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/asrasATx_9CFWJLiwaszZa-FDmvXglbjWe017aoxDmG11ZjZlYKlsQd7MHRXwiNgzfwM9T-fkT3BbJCfOYsp9lHJ9wlWuk1RwIX7khvFPTRBTMFyuxe6hAcfKqFXKaQ33w6h1bna9AMdJG48P4ESrUeZcZGIpwFcifuiUb6vGHfTrC4nNVjR6xzL5C6srOZP?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/psk2VXvuMYGyWFNBr_GdKtBNK0kJazGT0-wUAFXHd71qOfj0rw6WhIVQ58EO5hKXYq15PwMEc-XN9MNCbUdAS-4tbMx16J6wsJlNa2d7F53thnjbPCgomx0s_1a8hSDX5xfHa-R1VSWzpZVf1LWWG92ApQpcN5JuKrBY9sPoMTkJstGHn0oBDEgz5QyhHtJd?purpose=fullsize)

---

# Finding Address Spaces

## BGP-Toolkit

The module introduces the **BGP-Toolkit hosted by Hurricane Electric**.

It can be used to research:

- Address blocks assigned to an organization
    
- ASNs associated with those address blocks
    

The basic workflow is:

```text
Domain / IP
    ↓
BGP Toolkit
    ↓
ASN / Address Information
    ↓
Infrastructure Understanding
```

The module explains that large organizations may have their own ASN because they self-host a large amount of infrastructure.

Smaller organizations may instead use infrastructure belonging to providers such as:

- Cloudflare
    
- Google Cloud
    
- AWS
    
- Azure
    

---

# ⚠️ Scope Awareness When Finding Infrastructure

This is one of the **most important concepts in the section**.

If a company uses infrastructure hosted by another provider, other organizations may share that infrastructure.

Therefore, we must make sure we are not accidentally interacting with:

- Out-of-scope infrastructure
    
- Other customers
    
- Hosting providers' systems
    

The module states that the agreement is with the customer—not with other organizations sharing the same server or provider.

### Remember

> **Finding an IP does not automatically mean you are authorized to attack it.**

Questions about:

- Self-hosted infrastructure
    
- Third-party infrastructure
    
- Cloud-hosted infrastructure
    

should be handled during the **scoping process**.

---

# Third-Party Hosting Permissions

In some situations, the customer may need written approval from a third-party hosting provider before testing.

The module gives examples:

- AWS has specific penetration-testing guidelines.
    
- Oracle may require a **Cloud Security Testing Notification**.
    
- Other providers may have their own requirements.
    

These matters should be handled by:

- Company management
    
- Legal team
    
- Contracts team
    

If you are unsure whether an external-facing service can be attacked:

> **Escalate before attacking it.**

The module emphasizes that explicit permission is required to attack hosts, both internal and external.

---

# DNS

DNS is described as an excellent way to:

- Validate scope
    
- Discover reachable hosts
    
- Find systems not disclosed in the original scoping document
    

The module mentions:

- DomainTools
    
- ViewDNS.info
    
- Manual DNS queries
    
- DNS resolution
    
- DNSSEC information
    
- Geographic accessibility information
    

![Image](https://images.openai.com/static-rsc-4/RhcuxhtzYrQjOKPgkBzkvsqgspx78E417apu3Oq3vkRoHNmHHw4Y1NNfVK-g-_U9t_ZHR7x4LwRTCgfDRDusV3lgRFRJXAvmbpn7XieJsRIVlP3hvS0coMxi7HZpUMa9dwPxspQwONLYQudDTA_LdAa2wAPgATOph_DvDmJNbd8_t7UdlHzrOlI_PwP5LfbC?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/hKuV0dD0rCITZwaBKQHzr11v7A1bvpz3m3KOPSsrsK7RcjiZ_Eyo7m4QEt2Mknbk8MulH7AKjk90tyxHJN8SwuysvZvCIDKkyiSngZLaEaYpuPuWl9VnapyzjjXtPlxX4f5pc9civf-KbNtKzY8QEp_gSvsCgu5ZpmMLixqSzqfKcX6dl5oXhhlcSLEKoVFh?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/1kkC4oKsncMBRXs1reZuo-1qW3Kl1b2ePFa6myfEDLDbhcKhSDZlKnHkfGuw_lPzPDwYVVHyCCIgZWjipX9j3SOuSztFSZDTraon3VbslgdnnqkC1qFdxwgPqnUUZdVG5ggIvN9U3P3By_-AQ75oefcBa6KRGNB_1EaC2u6GhkC0xJCXDjXxuUFzmByN1pK-?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/3ZJLs-rXDf_96j-IqHxTaRajJ0aeM7phiNBBcItwCqoD4M0WZMcxQcGyXBr77X2UKM_4ddYtrCLPr-Zbz75ezhFEEtU2AOu2-6QMwJjjM31swoeNUwtT7koxgn25arT5jcIFUno2syzh-4l5CYC-LmR5RFoPTOIALWuKXzYJ4nfNBWq7B0LKP7ZCmfA2suKH?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/jAT2hL8mc5NcjgJyPKbu6riElFE7WQzt_723OF2_ZLnUmt1Q3KTDYqGQKeqgbom3-9FMQJVcjx7NOOMutg5nXpuP0BB23iHhcRzk7sYiZoH0nnnhncJWMQkcfmbByGRSE1nrWrR3YeTQzOH5Wou3lUybZUDGQzSB3BJ7FxdXdB2qm_4cwqqKE63gNjayi_5h?purpose=fullsize)

---

# Important DNS Scope Concept

DNS enumeration may reveal additional hosts.

Suppose:

```text
Customer Scope
       ↓
Domain
       ↓
DNS Enumeration
       ↓
Additional Host
```

That host might be:

### Out of scope

In which case it should not be tested.

### Or

It could reside on an **in-scope IP address**, meaning the module explains that it may be fair game.

The module specifically says that interesting out-of-scope hosts can be brought to the client for clarification, while interesting subdomains residing on in-scope IP addresses may be considered in scope.

### Key lesson

**Always correlate discovered information with the actual scope.**

---

# ViewDNS.info

The module uses **ViewDNS.info** to validate information discovered during IP/ASN research.

It provides tools such as:

- Reverse IP Lookup
    
- Reverse Whois Lookup
    
- IP History
    
- DNS Report
    
- Reverse MX Lookup
    
- Reverse NS Lookup
    
- IP Location Finder
    
- DNS Propagation Checker
    
- Domain/IP Whois
    

The module emphasizes validation because information discovered through external sources may not always be current.

### Recon principle

```text
Source A
   ↓
Information
   ↓
Source B
   ↓
Validation
   ↓
Higher confidence
```

---

# Public Data

Publicly available information can reveal significant information about an organization.

The module specifically highlights:

- Social media
    
- LinkedIn
    
- Indeed
    
- Glassdoor
    
- Job postings
    
- Public company websites
    
- Embedded documents
    
- GitHub
    
- AWS cloud storage
    
- Other web-hosted platforms
    

---

# Social Media & Job Postings

Social media can reveal information about:

- Organization structure
    
- Equipment
    
- Software
    
- Security implementations
    
- Organizational schema
    

Job postings can be particularly useful.

### Example from the module

A **SharePoint Administrator** job listing can reveal that an organization uses SharePoint.

The example indicates that the organization may be using:

```text
SharePoint 2013
SharePoint 2016
```

This can potentially tell a penetration tester that different versions may exist within the environment.

### Why this matters

A job description can reveal technology without the tester directly probing the target.

```text
Job Posting
     ↓
Technology Identified
     ↓
Potential Version Identified
     ↓
Better Understanding of Environment
```

---

# Public-Facing Company Websites

Company websites can reveal:

- Contact emails
    
- Phone numbers
    
- Organizational charts
    
- Published documents
    
- Internal infrastructure references
    
- Intranet links
    

Embedded documents are particularly useful because they may contain information that isn't immediately visible from the main website.

---

# Cloud & Development Storage

The module warns that information can be unintentionally leaked through:

- GitHub
    
- AWS cloud storage
    
- Other web-hosted platforms
    

For example, a developer might accidentally leave:

- Credentials
    
- Notes
    
- Sensitive configuration information
    

hardcoded in a code release.

The module mentions:

> **Trufflehog**

and:

> **Greyhat Warfare**

as resources for finding these types of breadcrumbs.

---

# Overarching Enumeration Principles

This is a **very important section**.

The goal of enumeration is to understand the target better and identify every possible avenue that could potentially provide a route inside.

### Enumeration is iterative.

The module explicitly states that enumeration is:

> **an iterative process we will repeat several times throughout a penetration test.**

The process is not:

```text
Enumerate once → Done
```

Instead:

```text
Enumerate
   ↓
Analyze
   ↓
Discover Something
   ↓
Enumerate Again
   ↓
Analyze
   ↓
Discover More
   ↓
Repeat
```

---

# Passive → Active Enumeration

The module provides a specific methodology.

### Step 1 — Start passive

Begin with:

> **`passive` resources**

Start:

> **wide in scope and narrowing down**

### Step 2 — Exhaust initial passive enumeration

Collect and analyze what you can find without actively probing the target.

### Step 3 — Examine the results

Determine what the information tells you.

### Step 4 — Move to active enumeration

Once the passive phase has been sufficiently explored, move into:

> **active enumeration**

### Core methodology

```text
             PASSIVE
                │
        Start WIDE
                │
                ▼
          Gather Data
                │
                ▼
            Analyze
                │
                ▼
        Narrow the Scope
                │
                ▼
       ACTIVE ENUMERATION
```

---

# Example Enumeration Process

The module now puts the concepts together using:

```text
inlanefreight.com
```

The exercise specifically avoids heavy scanning.

The module says that heavy scans such as:

- Nmap
    
- Vulnerability scans
    

are **out of scope** for this portion.

The first step is:

> **checking our Netblocks data**

---

# Check for ASN/IP & Domain Data

The BGP information provides:

```text
IP Address:
134.209.24.248

Mail Server:
mail1.inlanefreight.com

Nameservers:
NS1.inlanefreight.com
NS2.inlanefreight.com
```

These are the specific results shown by the module.

### Interpretation

At this point, we have learned:

```text
inlanefreight.com
       │
       ├── IP
       │    └── 134.209.24.248
       │
       ├── Mail Server
       │    └── mail1.inlanefreight.com
       │
       └── Nameservers
            ├── NS1.inlanefreight.com
            └── NS2.inlanefreight.com
```

The module notes that Inlanefreight is not a large corporation, so it was not expected to have its own ASN.

The next step is **validation**.

---

# Viewdns Results

The module uses `viewdns.info` to validate the target's IP address.

The results match, which increases confidence in the information discovered.

The module then validates the two nameservers using `nslookup`.

---

# `nslookup`

The exact commands shown in the module are:

```bash
nslookup ns1.inlanefreight.com
```

Result:

```text
Name:   ns1.inlanefreight.com
Address: 178.128.39.165
```

Then:

```bash
nslookup ns2.inlanefreight.com
```

Result:

```text
Name:   ns2.inlanefreight.com
Address: 206.189.119.186
```

### Important discovery

We now have **two new IP addresses**:

```text
178.128.39.165
206.189.119.186
```

However, the module immediately emphasizes:

> **Before taking any further action with them, ensure they are in-scope for your test.**

For this specific exercise, those actual IP addresses are not in scope for scanning, but websites on them could be passively browsed for interesting information.

---

# Publicly Available Information

Because Inlanefreight is fictional for this module, it doesn't have a real social-media presence.

In a real engagement, the module says we would investigate sites such as:

- LinkedIn
    
- Twitter
    
- Instagram
    
- Facebook
    

for useful information.

The module then moves to:

```text
inlanefreight.com
```

---

# Hunting For Files

The first website check is looking for publicly accessible documents.

The exact Google dork used is:

```text
filetype:pdf inurl:inlanefreight.com
```

The purpose is to locate PDF documents associated with the domain.

![Image](https://images.openai.com/static-rsc-4/sDh5WER6RK0ejCz4pyBval_fL-1AcC3iF2LdCa-2Kkg-sOwPeIBGs3sLGrTsN7GzpVLLDeeMnFhY8zG3niXQ-CiltIpylKVr6FDfoXuDAlH4bfkER0Vw2bXsshClYq-MCdb4e0F9nyzVsXgfIt3kzdSwA3diwrHw8J7I0oMsFZJX7lpOdVY1vHN-BGfMomth?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/GFkZ9HjT1mY5Sr5ughtt1eFZ1ovtOo0NFJ0MJRqIW1ldInLq-SFsMLhVKZGZbmiN0Fw9pamwRgrBHbyyu1K30WDsER5IlrIO-Kx28UENxsy2yXjq76Fn6dOkcodnmCLQyJS2JoSQ-kJ2jUqe-iKmzPcxoS9vsAWnb03LHN8b5bRXzRgOyUa9dZiJ4dd2oXtf?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/a8aUmP5VA4KQAFLga-HPgghDVnRjkZkHkiwjFjWYu37b0QtNqAnIJvpqtrhBOfltQaOI2flGqSL8qpnqW-OhHwC-Ctn8HhcaEq1mEh9f5qkHdObv-kKYWNT-7byAYytxRKUT3ryaXCzmK6megdtvgEViHncFpPxQoH4-QhYalPQNCU7-t12PJBr5GOO4_UWR?purpose=fullsize)

### Documentation principle

When a useful document is discovered, the module recommends:

- Note the document
    
- Record its location
    
- Download a local copy
    
- Preserve screenshots
    
- Preserve scan output
    
- Preserve tool output
    

The reason is to maintain a comprehensive record and avoid losing important information.

### Pentest documentation mindset

```text
Discover
   ↓
Record
   ↓
Save
   ↓
Analyze
   ↓
Reference Later
```

---

# Hunting E-mail Addresses

The module next searches for email addresses.

The exact Google dork is:

```text
intext:"@inlanefreight.com" inurl:inlanefreight.com
```

The purpose is to locate instances containing text resembling an email address on the website.

The search reveals a contact page containing employee contact information.

This gives us information about:

- Employees
    
- Contact information
    
- Potentially active users
    

---

# E-mail Dork Results

The contact page reveals multiple employee email addresses.

The module identifies an apparent email naming convention:

```text
first.last
```

This is valuable because it can help build potential usernames for later authorized testing.

The module specifically mentions potential use in:

> **later password spraying attacks**

and notes that social engineering/phishing would only be relevant if those activities were part of the engagement scope.

---

# Username Harvesting

The module introduces:

**linkedin2username**

It can be used to scrape information from a company's LinkedIn page and generate possible username formats such as:

```text
flast
first.last
f.last
```

These can be added to a list of potential password-spraying targets.

### Concept

If we know:

```text
John Smith
```

possible username formats could include:

```text
jsmith
john.smith
j.smith
```

The important point is that the tool can generate candidate formats from publicly available information.

---

# Credential Hunting

The module introduces:

> **Dehashed**

as a resource for searching breach data for:

- Cleartext credentials
    
- Password hashes
    

The module explains that many passwords found may be old and may no longer work against external or internal AD-authenticated services.

However, some may still be useful.

Breach data can therefore also help create:

> **a user list for external or internal password spraying.**

---

# Dehashed Example

The module explicitly notes:

> **For our purposes, the sample data below is fictional.**

The example command is:

```bash
sudo python3 dehashed.py -q inlanefreight.local -p
```

The sample output contains fields such as:

```text
id
email
username
password
hashed_password
name
address
phone
database_name
```

For example, the fictional data includes:

```text
email : roger.grimes@inlanefreight.local
username : rgrimes
password : Ilovefishing!
```

and:

```text
email : jane.yu@inlanefreight.local
username : jyu
password : Starlight1982_!
```

### Important

These credentials are **fictional sample data from the module**.

Do not treat them as real credentials.

---

# Dehashed Script

The module notes that the script used in the example is available through a GitHub repository.

It also warns that:

> **Due to changes in the API structure of DeHashed, modifications may be necessary.**

An alternative script is also mentioned.

The module emphasizes:

> **Before executing the script, it is crucial to become familiar with its functionality.**

This is an important professional lesson:

**Don't blindly execute tools/scripts you haven't reviewed.**

---

# Final Lessons From This Section

The module ends by encouraging further searching for information related to:

```text
inlanefreight.com
```

The goal is to discover:

- Other useful files
    
- Other pages
    
- Information embedded in the site
    
- Additional information that could help the assessment
    

But the module repeatedly emphasizes the constraints:

> **Stay in scope.**

> **Do not test anything you are not authorized to test.**

> **Stay within the time constraints of the engagement.**

---

# The Importance of External Recon

The module provides a practical example from previous assessments where the tester had difficulty gaining a foothold from an anonymous internal position.

External sources were used to create a wordlist from:

- Google
    
- LinkedIn scraping
    
- Dehashed
    
- Other outside sources
    

This was then used for targeted internal password spraying to obtain valid credentials for a standard domain user account.

The module then makes an important observation:

> **The vast majority of internal AD enumeration can be performed with just a set of low-privilege domain user credentials.**

It also states that many attacks can be performed with such credentials.

---

# 🔥 Complete Enumeration Methodology From This Module

This is the methodology you should memorize **from this module**:

```text
                    SCOPE
                      │
                      ▼
              EXTERNAL RECON
                      │
                      ▼
              PASSIVE RESOURCES
                      │
                      ▼
              START WIDE
                      │
                      ▼
              IP / ASN DATA
                      │
                      ▼
                 DNS DATA
                      │
                      ▼
             PUBLIC INFORMATION
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
       Documents    Emails     Social Media
          │           │           │
          └───────────┼───────────┘
                      ▼
               Username Formats
                      │
                      ▼
                Breach Data
                      │
                      ▼
                Analyze Results
                      │
                      ▼
              ACTIVE ENUMERATION
```

This directly follows the module's principle of starting with **passive resources**, starting **wide in scope and narrowing down**, examining the results, and then moving into active enumeration.

---

# 🧠 Important Things to Memorize

### Core principle

> **Enumeration itself is an iterative process we will repeat several times throughout a penetration test.**

### Start with

> **`passive` resources**

### Method

> **starting wide in scope and narrowing down**

### Then

> **examine the results and move into our active enumeration phase.**

### Important data points

```text
IP Space
Domain Information
Schema Format
Data Disclosures
Breach Data
```

### Important resources

```text
BGP Toolkit
DomainTools
PTRArchive
ICANN
ViewDNS
LinkedIn
Public company websites
GitHub
Have I Been Pwned
Dehashed
```

### Important commands / searches from the module

```bash
nslookup ns1.inlanefreight.com
```

```bash
nslookup ns2.inlanefreight.com
```

```text
filetype:pdf inurl:inlanefreight.com
```

```text
intext:"@inlanefreight.com" inurl:inlanefreight.com
```

```bash
sudo python3 dehashed.py -q inlanefreight.local -p
```

### Critical operational lesson

> **Ensure discovered hosts are in scope before taking further action.**

### Final progression

```text
External Recon
      ↓
Passive Enumeration
      ↓
IP / ASN
      ↓
DNS
      ↓
Public Data
      ↓
Documents
      ↓
Email Addresses
      ↓
Username Harvesting
      ↓
Breach Data
      ↓
Analyze
      ↓
Active Enumeration
      ↓
Internal AD Enumeration
```

The module itself concludes by transitioning into **internal enumeration of `INLANEFREIGHT.LOCAL`**, both passively and actively, according to the assessment's scope and Rules of Engagement.

**These notes cover the entire `External Recon and Enumeration Principles` material you provided.** We can now move to its exercises one at a time, with **Cybersecurity Mentor Mode**: I'll make you reason through the enumeration rather than simply handing you the answer.