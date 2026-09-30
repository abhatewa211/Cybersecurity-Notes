Absolutely. I read the **Hardening Active Directory** module from your saved module content first. I’ll keep these notes **strictly according to that module**, preserve the important commands/terms, and won’t mix in unrelated AD topics.

![Image](https://images.openai.com/static-rsc-4/VxGBz4C07iDn8EJxphTUOkulec0p_F8uzcm66qVvWYnP8u-bHbtzA0jyqz11UeWhri-tuMw5-ADok52q3tbjvet1n8s7uAYGnvNwBen84M5TJX0lwbBH-c28Hgq1hteXoTQy83ZVzdByHTyqjqGULj0Dqh1yOeP_JHRyvXXLrce2ZCSkIsQh4XqS06W2czGi?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/0moKOsEFdpFEbXiriw7kOpeWiEDhWk7AruqoLJhkqEgJBWiYwvIE5ayt2tPm-qVLYH5sU0ZEM2B_UZhskcpzbxksE0ZkUI5IAzVEVBfAWDcj_Al5oITWklyfkYbzlkDVTUWR1dFVQLRdmhg0QzmIPat_65IIOGWTE22CfXSkIWqriYgcm48aM_Y_fBozxQhM?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Gbj3puue7yFGsFYyesdWOKl2Qj25IxuQ1kkGz9OOs0S96-srtoWit9qs9-3OtOcyvfuN9i3bxlyvw4X-neF5BnKI58svduMgVYxR_DSUQ7dG6qo1pE14go-cueKRcYV7jnQQQlSIWUdt1c9gsIt0OCyldCk_kI7pzvPsWQ18976qGCMrHxMA1JTmVVdbWfTW?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/MiBANY_ZVPCBDcKigGAdNJ012i_ilQ7Gl_zmOU2bWsQaDSWuryoMPTNldJtHHE3umXhX16WqvhEKsFdm7Tg97eDJB5IfQAU4VQTENUMGV5E2oZKLHZvPf3nbsS4LMCXND9RSwJLzXIwIDPBb1-Cg0KU7SG9-s8D0M9FNV4S9SJxc9LiZwsCqi_26a4F3YHbF?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/rZqYP8WB2M_L4ineSlnGZacpQIZluSyBgLY3uPZzZy5wKG6lqmq6WtNMk-Hoi305AQLRdgKcBpz_zfjy5KFJ_X6nNEY7lpU7N3-o115hZyufAnYhnGrP0rMuGBPmJLtckgOFCTM-5ObsPOIznfSWzTh9_37aZDmjqqJevONZC-RFz0652NXSFlt0iDjthrkX?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/2CM1X7B-mU15TaKo2VefA8s6EXbXJ0S7aaBZtbSkEvbIb-h-QhGPXj0XDbksKd0quBOR8OPw2BTMFFKZdcIKUzyUBLUMbIMokqWD6TbBCg0cDXZ0bxSVBf5L98u3HXYQEl4ac7TJxx_5gCpTX5z4pweor3RA2M34QLFpJm7TUHLQUwCeCUnGmJ1wdAThGkg2?purpose=fullsize)



## 1. Introduction

Active Directory (AD) hardening is the process of implementing security controls that make common attacker techniques less effective.

The purpose of hardening is to:

- Prevent or limit **lateral movement**
    
- Reduce opportunities for **privilege escalation**
    
- Protect **sensitive data and resources**
    
- Reduce the usefulness of common attacker TTPs
    
- Improve the organization's overall security posture
    
- Give defenders better visibility into what is happening inside the network
    

A strong baseline security posture is more important than simply purchasing additional security products such as an EDR or SIEM.

Security technologies are much more useful when the organization already has:

- Proper logging
    
- Good documentation
    
- Accurate asset tracking
    
- Defined security procedures
    
- Proper access controls
    

The module emphasizes that penetration testers should understand defensive controls because this helps them provide defenders with a better operational picture of the environment.

---

# 2. Step One: Document and Audit

One of the most important parts of AD hardening is **knowing exactly what exists inside the environment**.

An organization should perform an AD audit **annually, or preferably every few months**, so that documentation remains current.

## Things to Document and Track

### 1. Naming conventions

Document naming conventions for:

- OUs
    
- Computers
    
- Users
    
- Groups
    

### 2. DNS, Network, and DHCP

Maintain documentation of:

- DNS configuration
    
- Network configuration
    
- DHCP configuration
    

### 3. Group Policy Objects

Maintain an understanding of:

- All GPOs
    
- Where they are linked
    
- Which objects they affect
    

### 4. FSMO Roles

Document the assignment of:

- FSMO roles
    
- Which Domain Controllers hold those roles
    

### 5. Application Inventory

Maintain a complete and current inventory of applications.

### 6. Enterprise Hosts

Maintain a list of:

- All enterprise hosts
    
- Their locations
    

### 7. Trust Relationships

Document all trust relationships with:

- Other domains
    
- Other forests
    
- External entities
    

### 8. Elevated Users

Maintain a list of users who have:

- Administrative privileges
    
- Elevated permissions
    
- Membership in highly privileged groups
    

**Key idea:** You cannot properly secure an AD environment if you do not know what is inside it.

---

# 3. People, Processes, and Technology

The module divides AD hardening into three major areas:

```text
              AD HARDENING
                   |
       +-----------+-----------+
       |           |           |
     PEOPLE      PROCESSES   TECHNOLOGY
       |           |           |
     Users       Policies     Security
     Admins      Procedures   Controls
     Accounts    Auditing     Configuration
```

These three areas cover the human, procedural, hardware, and software aspects of an AD environment.

---

# 4. PEOPLE

Users remain one of the weakest parts of an environment.

Strong security practices for both standard users and administrators can prevent many easy wins for attackers.

Organizations should also educate users about security threats.

## 4.1 Strong Password Policy

Organizations should implement:

- Strong password policies
    
- Password filtering
    
- Protection against common passwords
    

The password filter should prevent common words such as:

- `welcome`
    
- `password`
    
- Names of months
    
- Names of days
    
- Names of seasons
    
- Company names
    

An enterprise password manager can also help users create and manage stronger passwords.

---

## 4.2 Rotate Service Account Passwords

Passwords should be periodically rotated for:

> **ALL service accounts**

This is especially important because service accounts can contain valuable privileges and may expose the environment to attacks such as Kerberoasting.

---

## 4.3 Restrict Local Administrator Access

Users should not have local administrator privileges on their workstations unless there is a specific business requirement.

Why?

Excessive local administrator privileges can make it easier for an attacker who compromises a standard workstation account to perform further actions.

---

## 4.4 RID-500 Local Administrator

The module recommends:

- Disable the default `RID-500 local admin` account
    
- Create a new administrative account
    
- Use LAPS password rotation for the administrative account
    

### Important

`RID-500` refers to the built-in Administrator account.

LAPS helps rotate local administrator passwords instead of leaving the same password across systems.

---

## 4.5 Split Administrative Tiers

Administrative users should use **separate administrative tiers**.

A common security problem is an administrator using the same privileged account on:

- Domain Controllers
    
- Administrative systems
    
- Normal workstations
    
- Daily-use computers
    

If an attacker compromises the administrator's normal workstation, privileged credentials may become exposed.

Therefore:

```text
Normal Work
     ↓
Standard User Account

Administrative Work
     ↓
Dedicated Administrative Account
```

The module specifically highlights the risk of obtaining Domain Administrator credentials from a computer that an administrator uses for normal work.

---

## 4.6 Clean Up Privileged Groups

Organizations should regularly review highly privileged groups.

Ask:

> **Does the organization need 50+ Domain/Enterprise Admins?**

Membership should be restricted to users who genuinely require the privileges for their duties.

Important groups include:

- Domain Admins
    
- Enterprise Admins
    
- Other highly privileged administrative groups
    

---

# 5. Protected Users Group

The **Protected Users** security group was introduced with Windows Server 2012 R2.

It provides additional protections against authentication-related credential attacks.

Adding appropriate accounts to this group can prevent credentials from being abused when they are left in memory on a host.

## Viewing Protected Users

The module uses:

```powershell
Get-ADGroup -Identity "Protected Users" -Properties Name,Description,Members
```

Example:

```text
Description       : Members of this group are afforded additional protections against authentication security threats.
DistinguishedName : CN=Protected Users,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
GroupCategory     : Security
GroupScope        : Global
Members           : {CN=sqlprod,..., CN=sqldev,...}
Name              : Protected Users
ObjectClass       : group
SamAccountName    : Protected Users
```

---

## 5.1 Protected Users Protections

Members of the Protected Users group receive several important protections.

### 1. Delegation Protection

Members cannot be delegated using:

- Constrained delegation
    
- Unconstrained delegation
    

### 2. CredSSP Protection

CredSSP will not cache plaintext credentials in memory even when the relevant Group Policy setting is enabled.

### 3. Windows Digest Protection

Windows Digest will not cache the user's plaintext password.

### 4. NTLM / DES / RC4 Restrictions

Members cannot authenticate using:

- NTLM
    
- DES
    
- RC4 keys
    

### 5. Credential Caching Protection

After acquiring a TGT, the user's long-term keys or plaintext credentials are not cached.

### 6. TGT Lifetime

Members cannot renew a TGT beyond the original **4-hour TTL**.

### ⚠️ Important Warning

Do **not** blindly place every privileged user into Protected Users.

The module warns that it can cause unexpected authentication problems and account lockouts.

Organizations should use **staged testing** before deploying it broadly.

---

# 6. Kerberos Delegation for Administrators

Administrative accounts should have Kerberos delegation disabled where possible.

The module specifically recommends:

> Disable Kerberos delegation for administrative accounts.

Protected Users also provides delegation-related protections, but organizations must understand the authentication impact before deployment.

---

# 7. PROCESSES

Security is not only about technical controls.

Organizations need clearly defined policies and procedures.

Without defined procedures:

- Employees are harder to hold accountable
    
- Security incidents become harder to handle
    
- Disaster recovery becomes less predictable
    
- Old accounts and systems may remain in the environment
    

---

## 7.1 AD Asset Management

Organizations should maintain proper AD asset-management procedures.

These can include:

- AD host audits
    
- Asset tags
    
- Periodic asset inventories
    

The goal is to ensure that hosts do not become lost or forgotten inside the environment.

---

## 7.2 Access Control Policies

Organizations should have processes for:

- User account provisioning
    
- User account de-provisioning
    
- Access control
    
- MFA implementation
    

When employees join or leave the organization, their access should be managed properly.

---

## 7.3 Host Provisioning and Decommissioning

Organizations should establish procedures for:

- Provisioning hosts
    
- Security hardening
    
- Decommissioning hosts
    

Examples include:

- Baseline security hardening guidelines
    
- Gold images
    

---

## 7.4 AD Cleanup Policies

Organizations should define procedures for removing stale AD objects.

Important questions:

> Are accounts for former employees removed or just disabled?

> What is the process for removing stale records from AD?

Old accounts and objects can create unnecessary attack paths.

---

## 7.5 Legacy Systems and Services

Organizations should have procedures for decommissioning:

- Legacy operating systems
    
- Legacy services
    
- Unused applications
    

The module gives the example of properly uninstalling Exchange when migrating to Microsoft 365.

---

## 7.6 Regular Audits

Organizations should maintain a schedule for auditing:

- Users
    
- Groups
    
- Hosts
    

---

# 8. TECHNOLOGY

Organizations should periodically review AD for:

- Legacy misconfigurations
    
- New threats
    
- Emerging vulnerabilities
    
- Misconfigurations introduced by changes
    

Every modification to AD should be reviewed so that new security weaknesses are not accidentally introduced.

---

## 8.1 Use Security Assessment Tools

The module recommends periodically using:

- **BloodHound**
    
- **PingCastle**
    
- **Grouper**
    

These tools can help identify AD misconfigurations and weaknesses.

---

## 8.2 Do Not Store Passwords in AD Descriptions

Administrators should not store passwords inside:

- AD account descriptions
    
- Other easily accessible account fields
    

This can expose credentials during enumeration.

---

## 8.3 Review SYSVOL

Review `SYSVOL` for:

- Scripts
    
- Passwords
    
- Sensitive information
    

Scripts stored in SYSVOL can sometimes expose credentials.

---

# 9. Service Accounts and Kerberoasting

Organizations should avoid using ordinary user accounts as service accounts where possible.

Instead, use:

- **Group Managed Service Accounts (gMSA)**
    
- **Managed Service Accounts (MSA)**
    

This reduces the risk associated with Kerberoasting.

### Important

```text
Normal Service Account
        ↓
Potential Kerberoasting Risk

gMSA / MSA
        ↓
Reduced Kerberoasting Risk
```

The module identifies gMSAs as one of the strongest defenses against Kerberoasting.

---

# 10. Disable Unconstrained Delegation

Where possible:

> **Disable Unconstrained Delegation**

Unconstrained delegation can create significant credential exposure opportunities.

The module specifically lists disabling it as an important technology-level hardening measure.

---

# 11. Protect Domain Controllers

Avoid allowing administrators to directly access Domain Controllers from normal workstations.

Instead:

```text
Administrator
     ↓
Hardened Jump Host
     ↓
Domain Controller
```

The module recommends using **hardened jump hosts** for direct Domain Controller access.

---

# 12. ms-DS-MachineAccountQuota

Consider setting:

```text
ms-DS-MachineAccountQuota = 0
```

This prevents ordinary users from adding machine accounts.

The module states that this can prevent several attacks, including:

- noPac
    
- Resource-Based Constrained Delegation (RBCD)
    

---

# 13. Disable Print Spooler

Where possible:

> **Disable the Print Spooler service**

The module recommends this because the Print Spooler can be involved in several attacks.

---

# 14. Disable NTLM on Domain Controllers

Where possible:

> **Disable NTLM authentication for Domain Controllers**

Reducing NTLM usage helps reduce exposure to attacks that rely on NTLM authentication.

---

# 15. Certificate Services Protection

The module recommends:

- Extended Protection for Authentication
    
- Require SSL
    
- HTTPS-only connections
    

These controls should be considered for:

- Certificate Authority Web Enrollment
    
- Certificate Enrollment Web Service
    

---

# 16. SMB Signing and LDAP Signing

Enable:

```text
SMB Signing
LDAP Signing
```

These protections help defend against authentication-related attacks and relay scenarios.

The module specifically lists both SMB signing and LDAP signing as hardening measures.

---

# 17. Reduce BloodHound Enumeration

Organizations should take steps to prevent unnecessary AD enumeration.

The goal is to reduce how much useful relationship and permission information an attacker can gather.

The module specifically recommends taking steps to prevent enumeration using tools such as BloodHound.

---

# 18. Penetration Testing and AD Assessments

The module recommends:

### Ideal

```text
Quarterly AD Security Assessment
```

### Minimum when budget is limited

```text
Annual AD Security Assessment
```

Regular assessments help identify:

- New misconfigurations
    
- Newly introduced attack paths
    
- Changes in privilege assignments
    
- Emerging weaknesses
    

---

# 19. Backup and Disaster Recovery

Organizations should:

- Test backups
    
- Confirm backups are valid
    
- Review disaster recovery plans
    
- Practice disaster recovery procedures
    

Having a backup is not enough; the organization should know whether the backup can actually be restored.

---

# 20. Restrict Anonymous Access

Organizations should restrict anonymous access and prevent null-session enumeration.

The module specifically mentions setting:

```text
RestrictNullSessAccess = 1
```

This restricts null-session access to unauthenticated users.

---

# 21. Protections by Attack Technique

The module maps several common attacker TTPs to defensive measures and MITRE ATT&CK techniques.

---

## External Reconnaissance

### MITRE

```text
T1589
```

External reconnaissance is difficult to detect because attackers may not directly interact with the organization's infrastructure.

### Defensive measures

Control the information released publicly.

Pay attention to:

- Job postings
    
- Public documents
    
- Document metadata
    
- BGP information
    
- DNS records
    
- Technology information
    

Documents should be properly cleaned before being published.

Avoid unnecessarily revealing:

- Internal naming conventions
    
- User naming structures
    
- Security technologies
    
- Network technologies
    

---

# 22. Internal Reconnaissance

Internal reconnaissance is more detectable because it can generate network traffic.

### Defensive measures

Monitor for:

- Large bursts of traffic
    
- Network scanning
    
- Suspicious packet patterns
    

Security controls can include:

- Firewalls
    
- Network Intrusion Detection Systems (NIDS)
    
- SIEM
    
- Network monitoring
    

Windows Firewall and EDR configurations can also be used to reduce unnecessary information exposure.

MITRE tag listed by the module:

```text
T1595
```

---

# 23. Poisoning / Man-in-the-Middle

### MITRE

```text
T1557
```

Important defenses include:

- SMB message signing
    
- Strong traffic encryption
    

SMB signing uses hashed authentication codes to verify the identity of the sender and recipient.

This can help prevent relay attacks because the attacker is attempting to spoof or manipulate traffic.

---

# 24. Password Spraying

### MITRE

```text
T1110.003
```

Password spraying can be detected through proper logging and monitoring.

The module specifically mentions monitoring:

```text
Event ID 4624
Event ID 4648
```

along with invalid authentication attempts.

### Defensive measures

- Strong password policies
    
- Account lockout policies
    
- Two-factor authentication
    
- Multi-factor authentication
    
- Authentication monitoring
    

---

# 25. Credentialed Enumeration

### MITRE

```text
TA0006
```

Credentialed enumeration is difficult to completely prevent once an attacker possesses valid credentials.

A valid account can generally perform actions allowed to that account.

### Detection

Look for unusual activity such as:

- Unexpected CLI usage
    
- Multiple RDP connections
    
- Host-to-host movement
    
- Unusual file transfers
    
- Abnormal administrative activity
    

### Defensive measures

- Monitoring
    
- Network segmentation
    
- Behavioral analysis
    
- Network heuristics
    

---

# 26. Living off the Land (LOTL)

Attackers may use legitimate tools already available within the operating system.

This can make detection more difficult.

### Defensive strategy

Establish a baseline of:

- Normal network traffic
    
- Normal user behavior
    
- Normal administrative activity
    

Then look for deviations from the baseline.

Additional controls include:

- Monitoring command shells
    
- Properly configured AppLocker policies
    

---

# 27. Kerberoasting

### MITRE

```text
T1558.003
```

Kerberoasting is a major AD credential-access technique.

### Main defenses

#### 1. Use stronger Kerberos encryption

Prefer stronger encryption instead of:

```text
RC4
```

#### 2. Strong password policies

Strong service account passwords make offline cracking more difficult.

#### 3. Use Group Managed Service Accounts

**gMSA** is highlighted by the module as probably the strongest defense because it makes Kerberoasting no longer possible in the intended scenario.

#### 4. Audit privileged permissions

Regularly review user permissions and excessive group memberships.

---

# 28. MITRE ATT&CK Breakdown

MITRE ATT&CK organizes attacker behavior into:

```text
Tactics
   ↓
Techniques
   ↓
Sub-techniques
```

For the module's Kerberoasting example:

```text
TA0006
Credential Access
       ↓
T1558
Steal or Forge Kerberos Tickets
       ↓
T1558.003
Kerberoasting
```

The module explains that:

- `TA0006` = **Credential Access tactic**
    
- `T1558` = **Steal or Forge Kerberos Tickets technique**
    
- `T1558.003` = **Kerberoasting sub-technique**
    

T1558 contains sub-techniques such as:

- Golden Ticket
    
- Silver Ticket
    
- Kerberoasting
    
- AS-REP Roasting
    

![Image](https://images.openai.com/static-rsc-4/SaV6x1APlcyq1uomFplI65y87ih0tNuBm8t_Dj9LlATTgCI91i0RMIW8o5N0vWdfmlOp5mXifqhCTF6I58DMCC-39g4gVVWSMkzyZAg9zHNYqIQBekKhqHMWkf4tkASw_e6g8rI3xKaUAv-gVAzqIqf89uQPHQFBUA-WEHgAJmceLOpYXtlCLOIng3D7GzOb?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Gbj3puue7yFGsFYyesdWOKl2Qj25IxuQ1kkGz9OOs0S96-srtoWit9qs9-3OtOcyvfuN9i3bxlyvw4X-neF5BnKI58svduMgVYxR_DSUQ7dG6qo1pE14go-cueKRcYV7jnQQQlSIWUdt1c9gsIt0OCyldCk_kI7pzvPsWQ18976qGCMrHxMA1JTmVVdbWfTW?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/5Uq-ORVXr5CaQQqObf0dhCDqy2Oj-ReeJlS2xh-b1VePRjhNv6mtBhZl8b6Vv7Ez5SwTJM09B9JCiewEV9BcaiCy68xjNxUn0yUlgBgUCTk1oF-E0kJ6U06RnaHgEVZ6VFoKVzP7hKnK6DFFEfnvGA8S6pUlBgFMb1040xNG_Zvu779STLOrD8w-o5nz_h5b?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/2CM1X7B-mU15TaKo2VefA8s6EXbXJ0S7aaBZtbSkEvbIb-h-QhGPXj0XDbksKd0quBOR8OPw2BTMFFKZdcIKUzyUBLUMbIMokqWD6TbBCg0cDXZ0bxSVBf5L98u3HXYQEl4ac7TJxx_5gCpTX5z4pweor3RA2M34QLFpJm7TUHLQUwCeCUnGmJ1wdAThGkg2?purpose=fullsize)

---

# 29. Quick Hardening Checklist

## Documentation

-  Document OU naming conventions
    
-  Document computer/user/group naming
    
-  Document DNS
    
-  Document network configuration
    
-  Document DHCP
    
-  Document GPOs
    
-  Document FSMO roles
    
-  Maintain application inventory
    
-  Maintain enterprise host inventory
    
-  Document trust relationships
    
-  Track privileged users
    

## People

-  Strong password policy
    
-  Password filtering
    
-  Rotate service account passwords
    
-  Restrict local administrator access
    
-  Disable default RID-500 local admin
    
-  Use LAPS
    
-  Separate administrative accounts
    
-  Clean up privileged groups
    
-  Use Protected Users where appropriate
    
-  Disable Kerberos delegation for administrative accounts
    

## Processes

-  AD asset management
    
-  Account provisioning/de-provisioning
    
-  MFA
    
-  Secure host provisioning
    
-  Secure host decommissioning
    
-  Remove stale accounts
    
-  Remove stale AD records
    
-  Decommission legacy systems
    
-  Regular user/group/host audits
    

## Technology

-  Periodically run BloodHound
    
-  Periodically run PingCastle
    
-  Periodically run Grouper
    
-  Do not store passwords in account descriptions
    
-  Review SYSVOL
    
-  Use gMSA/MSA
    
-  Disable Unconstrained Delegation
    
-  Use hardened jump hosts
    
-  Consider `ms-DS-MachineAccountQuota = 0`
    
-  Disable Print Spooler where possible
    
-  Disable NTLM on Domain Controllers where possible
    
-  Use Extended Protection for Authentication
    
-  Require SSL for applicable certificate services
    
-  Enable SMB signing
    
-  Enable LDAP signing
    
-  Reduce unnecessary BloodHound enumeration
    
-  Conduct regular AD security assessments
    
-  Test backups
    
-  Practice disaster recovery
    
-  Restrict anonymous/null-session access
    

---

# 30. Important Values to Remember

|Item|Important Value|
|---|---|
|RID-500|Built-in Administrator account|
|Protected Users|Additional authentication protections|
|Protected Users TGT renewal|Maximum original 4-hour TTL|
|ms-DS-MachineAccountQuota|Consider setting to `0`|
|RestrictNullSessAccess|Set to `1`|
|Password Spraying|`T1110.003`|
|Credential Access|`TA0006`|
|Kerberos Ticket Attacks|`T1558`|
|Kerberoasting|`T1558.003`|
|External Reconnaissance|`T1589`|
|Internal Reconnaissance|`T1595`|
|Poisoning|`T1557`|
|Kerberoasting defense|Strong encryption + strong passwords + gMSA|

---

# 31. Final Takeaways

The module's hardening strategy can be remembered as:

```text
DOCUMENT
    ↓
AUDIT
    ↓
CONTROL PEOPLE
    ↓
CONTROL PROCESSES
    ↓
HARDEN TECHNOLOGY
    ↓
MONITOR
    ↓
TEST
    ↓
IMPROVE
```

The most important lesson is that **AD security is not achieved through one security product or one configuration**.

A strong AD security posture requires:

- Accurate documentation
    
- Proper access control
    
- Strong authentication
    
- Privilege management
    
- Secure service accounts
    
- Delegation controls
    
- Network protections
    
- Logging and monitoring
    
- Regular security assessments
    
- Tested recovery procedures
    

The module also emphasizes that the listed protections are **not exhaustive**, but they provide a strong starting point for improving an organization's Active Directory security posture.

## ⭐ Exam/Interview Memory Line

> **Document → Audit → Least Privilege → Protect Credentials → Harden AD → Monitor → Test Regularly**

These notes stay within the **Hardening Active Directory** module you asked me to use; I have not mixed in the Cross-Forest Trust module or unrelated material.