## 1. What is the Kerberos Double Hop Problem?

The **Kerberos Double Hop** problem occurs when Kerberos authentication is used across **two or more network hops**.

A common example is:

```text
Attack Host
     |
     | First Hop
     v
   DEV01
     |
     | Second Hop
     v
   DC01
```

The important issue is that Kerberos tickets are issued for **specific resources**.

> **Kerberos tickets should not be viewed as passwords.**

They are signed pieces of data issued by the **KDC (Key Distribution Center)** that specify what resources an account can access.

When Kerberos authentication is performed, we receive a ticket that permits access to the requested resource, such as a particular machine.

With password-based authentication, credentials can potentially be reused for another authentication request because the relevant authentication material may be available to the session.

---

# 2. Why Does the Double Hop Happen?

The Double Hop problem commonly occurs when using:

- WinRM
    
- PowerShell remoting
    
- `Enter-PSSession`
    
- Evil-WinRM
    
- PowerView from a remote PowerShell session
    

The default authentication mechanism gives the remote session a ticket that allows access to the **first resource**, but it does not automatically provide the credentials/ticket material necessary to authenticate to a **second resource**.

For example:

```text
Attack Host
     |
     | Kerberos authentication
     v
   DEV01
     |
     | Attempt to access
     v
   DC01
```

The user may have sufficient permissions on DC01, but the request can still fail because the user's authentication information was not delegated from DEV01 to DC01.

This is why we can sometimes successfully execute commands on the first host but fail when attempting to access:

- Active Directory
    
- Domain Controllers
    
- SMB shares
    
- Other domain resources
    

The module describes this as:

```text
First Hop  = Attack Host → DEV01
Second Hop = DEV01 → DC01
```

---

# 3. Kerberos Tickets — Important Concept

Two important ticket types to understand are:

### TGT — Ticket Granting Ticket

The **TGT** is used to request service tickets from the KDC.

Think of it as the ticket that allows the user to request additional tickets for services.

### TGS — Ticket Granting Service / Service Ticket

A **TGS/service ticket** is used to access a particular service/resource.

Simplified:

```text
User
 |
 | Authentication
 v
KDC
 |
 | TGT
 v
User
 |
 | Request service ticket
 v
KDC
 |
 | TGS
 v
Specific Service
```

The key problem during the Double Hop is that the **TGS for the first service is available**, but the user's **TGT is not available in the remote session for obtaining tickets for subsequent services**.

The module explains that the TGS is sent to the remote service, allowing command execution, while the user's TGT is not sent to the remote session.

---

# 4. WinRM and the Double Hop

The problem is particularly common with WinRM/PowerShell.

Example:

```powershell
PS C:\htb> Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm
```

After authentication:

```text
[DEV01]: PS C:\Users\backupadm\Documents>
```

We are now operating on DEV01.

However, if we attempt to access the Domain Controller using PowerView:

```powershell
get-domainuser -spn
```

we can receive:

```text
Exception calling "FindAll" with "0" argument(s):
"An operations error occurred."
```

The problem isn't necessarily that `backupadm` lacks permission.

The problem is that the authentication information required for the **second hop** isn't available.

---

# 5. Why Credentials Aren't Available

When connecting using WinRM, authentication is performed over the network.

The user's password is not simply cached in the remote session so it can be reused for another authentication request.

The module demonstrates this with Mimikatz.

Example:

```powershell
PS C:\htb> Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm

[DEV01]: PS C:\Users\backupadm\Documents> cd 'C:\Users\Public\'

[DEV01]: PS C:\Users\Public> .\mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit
```

The important observation is that the `backupadm` Kerberos credentials show:

```text
Username : backupadm
Domain   : INLANEFREIGHT.LOCAL
Password : (null)
```

The module uses this to demonstrate that the user's password isn't available in the WinRM session for reuse on another resource.

---

# 6. Checking the Session with `klist`

Another important command is:

```powershell
klist
```

`klist` displays cached Kerberos tickets.

In the initial remote WinRM session, the module shows only a ticket associated with the current server.

Example:

```text
Cached Tickets: (1)

#0> Client: backupadm @ INLANEFREIGHT.LOCAL
    Server: academy-aen-ms0$
```

This is an important indication of the Double Hop problem.

We have a ticket allowing interaction with the current server, but we don't have the necessary ticket situation to directly authenticate to another domain resource.

---

# 7. Example Attack Path

The module uses this scenario:

```text
                FIRST HOP                 SECOND HOP

Attack Host  ---------------->  DEV01  ---------------->  DC01
                                  |
                                  |
                              PowerView
                                  |
                                  v
                              Active Directory
```

The Attack Host is a Parrot system that is not joined to the domain.

We have valid domain credentials:

```text
INLANEFREIGHT\backupadm
```

and the user has access to DEV01 through Remote Management.

We connect:

```text
Attack Host → DEV01
```

Then attempt:

```text
DEV01 → DC01
```

The second authentication fails because the user's authentication information isn't automatically delegated.

---

# 8. Important Example: `tasklist /V`

The module demonstrates that processes are running under the `backupadm` context:

```powershell
[DEV01]: PS C:\Users\Public> tasklist /V |findstr backupadm
```

Example:

```text
wsmprovhost.exe    1844    Services    0    85,212 K
                   INLANEFREIGHT\backupadm

tasklist.exe       6532    Services    0     7,988 K
                   INLANEFREIGHT\backupadm

conhost.exe        7048    Services    0    12,656 K
                   INLANEFREIGHT\backupadm
```

`wsmprovhost.exe` is the process spawned for a Windows Remote PowerShell session.

This shows that the remote PowerShell process is operating under the user's context, but that does **not** mean the user's credentials can automatically be delegated to another host.

---

# 9. Unconstrained Delegation

The module also discusses **unconstrained delegation**.

If unconstrained delegation is enabled on a server, the normal Double Hop problem may not occur.

The simplified process is:

```text
User
 |
 | TGS + TGT
 v
Delegated Server
 |
 | TGT available in memory
 v
KDC
 |
 | Request another TGS
 v
Next Resource
```

With unconstrained delegation, the target server can receive and cache the user's TGT.

The server can then use the TGT to request additional service tickets on behalf of the user.

Therefore:

```text
TGT cached on delegated server
        ↓
Can request additional TGS tickets
        ↓
Can access subsequent resources
```

The module notes that landing on a system with unconstrained delegation can effectively eliminate this particular Double Hop problem.

---

# 10. Workarounds

The module covers two primary workarounds:

### Workaround #1

Use a **PSCredential object** and explicitly pass credentials with subsequent requests.

### Workaround #2

Use **Register-PSSessionConfiguration** with a `RunAsCredential`.

---

# Workaround #1 — PSCredential Object

## 11. Why PSCredential Works

Instead of expecting the remote session to automatically delegate credentials:

```text
Attack Host
     |
     v
  DEV01
     |
     X
     DC01
```

we explicitly provide credentials again:

```text
Attack Host
     |
     v
  DEV01
     |
     | Credentials supplied again
     v
  DC01
```

This allows the second authentication request to use the credentials explicitly.

The module describes this as sending credentials with every request.

---

# 12. Create a Secure Password

Example from the module:

```powershell
$SecPassword = ConvertTo-SecureString '!qazXSW@' -AsPlainText -Force
```

Then create the credential object:

```powershell
$Cred = New-Object System.Management.Automation.PSCredential(
    'INLANEFREIGHT\backupadm',
    $SecPassword
)
```

The resulting `$Cred` object contains the username and secure representation of the password.

---

# 13. Use the Credential Object

Without credentials:

```powershell
get-domainuser -spn
```

can fail because of the Double Hop.

With credentials:

```powershell
get-domainuser -spn -credential $Cred
```

the command succeeds.

The module demonstrates:

```powershell
get-domainuser -spn -credential $Cred | select samaccountname
```

Example result:

```text
samaccountname
--------------
azureconnect
backupjob
krbtgt
mssqlsvc
sqltest
sqlqa
sqldev
mssqladm
svc_sql
sqlprod
sapsso
sapvc
vmwarescvc
```

---

# 14. Important Difference

### Without `-Credential`

```powershell
get-domainuser -spn
```

Result:

```text
Exception calling "FindAll" with "0" argument(s):
"An operations error occurred."
```

### With `-Credential`

```powershell
get-domainuser -spn -credential $Cred
```

Result:

```text
SPN accounts successfully enumerated
```

Therefore:

```text
No credential delegation
        ↓
Second hop fails

Explicit PSCredential
        ↓
Credentials supplied again
        ↓
Second hop succeeds
```

---

# 15. RDP as Another Solution

The module also demonstrates that if we **RDP to the same host**, the Double Hop issue can be avoided in this scenario.

After RDP:

```cmd
C:\htb> klist
```

the session contains multiple Kerberos tickets.

Important entries include:

```text
Client: backupadm @ INLANEFREIGHT.LOCAL
Server: krbtgt/INLANEFREIGHT.LOCAL
```

and:

```text
Client: backupadm @ INLANEFREIGHT.LOCAL
Server: cifs/DC01.INLANEFREIGHT.LOCAL
```

This provides the authentication material necessary to interact directly with other domain resources.

The module explains that this works because the password is stored in memory in the interactive RDP session and can therefore be used for subsequent requests.

---

# 16. Workaround #2 — Register-PSSessionConfiguration

The second method is useful when:

- We have a Windows attack host
    
- We have GUI access
    
- We are on a domain-joined Windows system
    
- We want to establish a PowerShell remoting session where the remote credentials can be used appropriately
    

The important cmdlet is:

```powershell
Register-PSSessionConfiguration
```

Example:

```powershell
Register-PSSessionConfiguration -Name backupadmsess -RunAsCredential inlanefreight\backupadm
```

This creates a new PowerShell session configuration.

---

# 17. Restart WinRM

After creating the session configuration:

```powershell
Restart-Service WinRM
```

This disconnects existing WinRM sessions.

The module specifically warns that restarting WinRM will kick us out of the current PSSession.

We then reconnect using the new configuration.

---

# 18. Connect Using the New Configuration

Use:

```powershell
Enter-PSSession -ComputerName DEV01 `
    -Credential INLANEFREIGHT\backupadm `
    -ConfigurationName backupadmsess
```

Then:

```powershell
klist
```

The important difference is that we now see a Kerberos ticket for:

```text
krbtgt/INLANEFREIGHT.LOCAL
```

Example:

```text
Cached Tickets: (1)

#0>
Client: backupadm @ INLANEFREIGHT.LOCAL
Server: krbtgt/INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL

KerbTicket Encryption Type:
AES-256-CTS-HMAC-SHA1-96

Ticket Flags:
0x40e10000 -> forwardable renewable initial
pre_authent name_canonicalize
```

---

# 19. PowerView After Fixing the Double Hop

Once the new session is established, PowerView can be used without explicitly creating a new `PSCredential` object for every command.

Example:

```powershell
get-domainuser -spn | select samaccountname
```

Example result:

```text
samaccountname
--------------
azureconnect
backupjob
krbtgt
mssqlsvc
sqltest
sqlqa
sqldev
mssqladm
svc_sql
sqlprod
sapsso
sapvc
vmwarescvc
```

---

# 20. Important Limitation — Evil-WinRM

The module specifically states that:

```powershell
Register-PSSessionConfiguration
```

cannot be used from an Evil-WinRM shell in the same way.

Reasons include:

- The credentials popup cannot be used from Evil-WinRM.
    
- `RunAs` requires an elevated PowerShell terminal.
    
- The method requires GUI access.
    
- The module's testing found limitations when attempting this from PowerShell on Parrot or Ubuntu with Kerberos credentials.
    

Therefore, this method is more appropriate when:

```text
Windows Attack Host
        +
GUI access
        +
Valid credentials
```

or when using a compromised Windows host as a jump host through RDP.

---

# 21. Other Methods Mentioned

The module briefly mentions other approaches:

- CredSSP
    
- Port forwarding
    
- Injecting into a process running in the context of the target user
    
- Sacrificial processes
    

These methods are **not covered in this module**.

---

# 22. Quick Comparison

|Situation|Result|
|---|---|
|WinRM → current host|Works|
|WinRM → another domain resource|May fail|
|TGS for current WinRM service|Available|
|User TGT in normal remote session|Not available for the second hop|
|`klist`|Useful for identifying available tickets|
|PowerView without credentials|Can fail|
|PowerView + `-Credential $Cred`|Can work|
|RDP session|Can provide required cached tickets|
|Unconstrained delegation|Can eliminate the normal Double Hop limitation|
|`Register-PSSessionConfiguration`|Another workaround|
|Evil-WinRM + `Register-PSSessionConfiguration`|Not suitable according to module|
|CredSSP|Mentioned but not covered|
|Port forwarding|Mentioned but not covered|

---

# 23. Commands to Remember

## Establish WinRM session

```powershell
Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm
```

## Check Kerberos tickets

```powershell
klist
```

## Check processes running as the user

```powershell
tasklist /V | findstr backupadm
```

## Create SecureString password

```powershell
$SecPassword = ConvertTo-SecureString '!qazXSW@' -AsPlainText -Force
```

## Create PSCredential

```powershell
$Cred = New-Object System.Management.Automation.PSCredential(
    'INLANEFREIGHT\backupadm',
    $SecPassword
)
```

## Use credentials with PowerView

```powershell
get-domainuser -spn -credential $Cred | select samaccountname
```

## Register a PSSession configuration

```powershell
Register-PSSessionConfiguration `
    -Name backupadmsess `
    -RunAsCredential inlanefreight\backupadm
```

## Restart WinRM

```powershell
Restart-Service WinRM
```

## Connect using the custom configuration

```powershell
Enter-PSSession `
    -ComputerName DEV01 `
    -Credential INLANEFREIGHT\backupadm `
    -ConfigurationName backupadmsess
```

---

# 24. Exam / Lab Cheat Sheet

```text
                 KERBEROS DOUBLE HOP
                         |
          +--------------+--------------+
          |                             |
      FIRST HOP                     SECOND HOP
          |                             |
 Attack Host ───────> DEV01 ─────────> DC01
                          |
                          X
                    Authentication
                     not delegated
```

### Normal WinRM

```text
Attack Host
     |
     | TGS for WinRM service
     v
   DEV01
     |
     X
   DC01
```

### PSCredential workaround

```text
Attack Host
     |
     v
   DEV01
     |
     | Explicit credentials
     v
   DC01
```

### RDP / interactive logon

```text
Attack Host
     |
     v
   RDP
     |
     v
   DEV01
     |
     | Kerberos tickets available
     v
   DC01
```

### Session Configuration

```text
Windows Attack Host
        |
        | RunAsCredential
        v
  Custom PSSession
        |
        v
      DEV01
        |
        v
      DC01
```

---

# 25. Key Things to Memorize

### 1. Double Hop

```text
Attack Host → Host A → Host B
```

The problem occurs because authentication doesn't automatically carry over to the second resource.

### 2. TGS vs TGT

```text
TGS = access to a specific service
TGT = used to request service tickets
```

### 3. `klist`

Always remember:

```powershell
klist
```

It helps determine what Kerberos tickets are actually available in the current session.

### 4. PSCredential

When the second hop fails:

```powershell
$SecPassword = ConvertTo-SecureString 'PASSWORD' -AsPlainText -Force

$Cred = New-Object System.Management.Automation.PSCredential(
    'DOMAIN\USER',
    $SecPassword
)
```

Then explicitly pass:

```powershell
-Credential $Cred
```

### 5. RDP

An interactive RDP session can provide the necessary cached Kerberos tickets and avoid the normal WinRM Double Hop limitation described in the module.

### 6. Unconstrained Delegation

If a server has unconstrained delegation enabled, the user's TGT can be cached on that server, allowing additional service tickets to be requested.

### 7. Register-PSSessionConfiguration

Important command:

```powershell
Register-PSSessionConfiguration
```

It can create a session configuration using:

```text
-RunAsCredential
```

### 8. Limitation

The module specifically notes that the custom PSSession configuration approach requires an elevated, GUI-capable Windows PowerShell environment and is not suitable from an Evil-WinRM shell.

---

# 26. Final Takeaway

The **Kerberos Double Hop** problem is fundamentally an **authentication delegation problem**.

The important mental model is:

```text
                  KDC
                 /   \
                /     \
              TGT     TGS
               |       |
               |       +------> Specific service
               |
               +------> Request additional TGS
```

During a normal WinRM remote session:

```text
Attack Host
     |
     | TGS
     v
   DEV01
     |
     | TGT unavailable
     X
   DC01
```

Therefore, when a second-hop operation fails, don't immediately assume the user lacks permissions.

First ask:

1. **What authentication method was used?**
    
2. **What Kerberos tickets are available?**
    
3. **Does `klist` show a TGT?**
    
4. **Can credentials be explicitly supplied using a `PSCredential`?**
    
5. **Would an interactive RDP session provide the required tickets?**
    
6. **Is delegation configured?**
    

The module's central lesson is that understanding **Kerberos tickets, WinRM authentication, and credential delegation** lets us recognize and troubleshoot the Double Hop problem rather than mistaking it for an authorization failure.