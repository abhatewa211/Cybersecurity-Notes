## 1. What Is Credentialed Enumeration?

After obtaining a valid low-privileged domain account, we can see considerably more of the Active Directory environment.

The goal is to enumerate:

- Domain users
    
- Computers
    
- Groups
    
- Group membership
    
- Group Policy Objects (GPOs)
    
- Permissions
    
- ACLs
    
- Shares
    
- User sessions
    
- Trusts
    
- Privileged accounts
    
- Local administrator access
    
- Potential attack paths
    

The important point is that **most of these tools require valid domain credentials**. A cleartext password, NTLM hash, or `SYSTEM` access on a domain-joined host may be sufficient depending on the technique.

### Mental model

![Image](https://images.openai.com/static-rsc-4/MqBeK8MQ4ly_vym3GqEeRwZmOQ3Z0h-EnPfk3J2nSJuNJxWTc2PlsYkT-D1GW7qFeJG30CSvwI7hU9kL3h0LYYNF1sIZUj0ASz8L4I33TcVKOgq0swCys-KETSpcNCQuycjr2gd7KTDFT5Jo2d4nHyZ1ldzhYqCKnC-dlanEKBoKBuq__SHhAeqYrZ_rKQTO?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/KcxpcjvX1BJwJmhpcXiD1JrmXwiHOFxtHvAlkkQnY23o2V_YP3JRyAbuRncHg4gPCkKTqR1szVSkOWu-oa_zY2wf1OXi4U1VeX8LlJJMUnoE3HohJZP9ehRVyU4kB8mTnz5s393rO51LGakKpiBBYfoLvNtLoOHIrv6z1aoRk-3jrV7GKL2OiQjXOLCUa87w?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/1SuWoTDOmuNvQ1O3Rh_VmXxc9gPauU2d1qBmJY-_8wFvUcjr2yI_SlTmsvCEO63v88-BA3h0IPl1Qa989HAVpMcSbMSksSEzkS3oDoV138PyLS5eq2WHgbnPeyG4h67VpjohtoV8Qfpbv0WTr1dvT-VRqyznwNBsF8MfWupnfqGrhuHXvNt6cuyEkBTReqpI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/098fuxyqQX3p74jqTumrzuupQ8J8MDkLnoNd4hLO8Mtz8pnDUrsSFb0WGf7tPB-HYAuWVVAba5EWbz6kWtlXEdcEyTiJvzMplz0cX279PUvwBflElbkQ1oSJOyis2_I1_xeSxJ10dGyF3sInjYzP2cn0-Xc1xG1fRiy40RG4rzmrWvlSZD-jv-fEwdP46-UU?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/eBE9gXt0LXEiuIUv7qjYk9F_y4bX3vjESUnO3xIX0y06lLZBrDSXNo09ti522eTw_CVi-62LZ_B_skDir2LzPY1Ywswh0b3TttPHeFBBgSMCUldinq8ni5qhTqn_HIUF9WmqT3p42EpFGsuKiwlG95zouybsGXaRdLJuPgpGwt3nktJYBrzOIT9OXWgW74wa?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/cQ4Xzy9oac14LUZSxikcS3I5zVICU199Djx_J3PKrTplhhQAF_CkR6K83HVl7uSAEQqEeGYAxdLZeN0z8cexBpaQSf3VZKMu6FYng3t58aTkn-DMd_7FDpnCIlbGnXGSlnCg9PQ1914Rwpz9gqCRceyt2m89thG3DmWfYCMiz2ggPuXDop_I0ebCUlQJVT-S?purpose=fullsize)

```text
                 Valid Domain Credentials
                          |
                          v
              +-----------------------+
              | Credentialed          |
              | Enumeration           |
              +-----------------------+
                 /    |    |    \
                /     |    |     \
               v      v    v      v
            Users   Groups Hosts  Shares
               \      |     |      /
                \     |     |     /
                 v    v     v    v
              ACLs / GPOs / Sessions
                       |
                       v
                 Trusts / Paths
                       |
                       v
              Lateral Movement
                       |
                       v
                Privilege Escalation
```

---

# 2. Tools Covered

This section introduces several important Linux-based AD enumeration tools:

|Tool|Primary purpose|
|---|---|
|**CrackMapExec / NetExec**|SMB-based enumeration and remote interaction|
|**SMBMap**|SMB shares, permissions and files|
|**rpcclient**|MS-RPC / AD enumeration|
|**Impacket**|Windows protocol interaction and remote execution|
|**Windapsearch**|LDAP-based AD enumeration|
|**BloodHound.py**|Graph-based AD relationship and attack-path analysis|

---

# 🔥 3. CrackMapExec

**CrackMapExec (CME)** is described by HTB as a powerful toolkit for assessing Active Directory environments. It uses functionality from projects such as **Impacket** and **PowerSploit**. The project is now commonly associated with **NetExec**.

![Image](https://images.openai.com/static-rsc-4/-na-hRAZt1jMESvFyY_I1HNv2LnjAdnj7Ol6LYifw9BTUVQBbbPRY4rQtbAKMtVJDjRz_XtmV76F_AotYPpuEV9lfwmUiFRzaMaEBGtNM1vaQ9f566a0LgDsiSG44Rnvcf0Y-MH8NhRTpYHeQAgVPNflDp-AmVAndt_P5upiM9b1xh9IOYe1F6PnUUIM2Y8K?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Z1GMtLerHxgshoDKbeM5ntHrbxB--9IRvmffB6gdnoc601Egt_wvOyFLVdpaL394uugMHB0T4M9084Pz9Taq9_dHEFYAriZt5iRLjAa0yQmg6N5BhY7yMMo1dlfPp3tm8xrhTvF85wuhw9NlbxCC8_mGEynkv55gzvkVskfe_YwvSZnn2Tm3b1SOFQajFAAh?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ouHqfXCGkkPalrKgVKNKKBUvAfJwRkUwGXFCIQfZZciose3wIsNPpBHYlJkoJzIzGtsMv1J3RzGUDjp7R3OrcFhmBBSym9TAGHU5SCJaWT8rpwkPiQ0WkTgyU2xkLBo3VfroxA_-wybpHBXdw8-5nSCGPaZxS059aaoT1oOS3Xf5h50AlqGWipJHGvpHggEe?purpose=fullsize)

### Protocols shown in the module

```text
MSSQL
SMB
SSH
WinRM
```

---

# 4. CME Important Options

For SMB enumeration, remember these:

```text
-u              Username
-p              Password
--users         Enumerate domain users
--groups        Enumerate domain groups
--loggedon-users
                Enumerate logged-on users
--shares        Enumerate SMB shares
```

The module also shows authentication using:

```text
-k              Kerberos
-H              NTLM hash
-d              Domain
--local-auth    Local authentication
```

### Easy memory trick

```text
CME
 |
 +-- --users
 |
 +-- --groups
 |
 +-- --loggedon-users
 |
 +-- --shares
```

---

# 5. Enumerating Domain Users

The module uses:

```bash
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users
```

This queries the Domain Controller for domain users.

Example output contains:

```text
INLANEFREIGHT.LOCAL\administrator
INLANEFREIGHT.LOCAL\guest
INLANEFREIGHT.LOCAL\lab_adm
INLANEFREIGHT.LOCAL\krbtgt
INLANEFREIGHT.LOCAL\htb-student
INLANEFREIGHT.LOCAL\avazquez
```

and importantly:

```text
badpwdcount
```

---

# 🧠 6. Understanding `badPwdCount`

`badPwdCount` indicates failed password attempts associated with the account.

For example:

```text
administrator    badpwdcount: 0
avazquez         badpwdcount: 3
```

The module points out that this is particularly useful when performing **targeted password spraying**, because accounts with existing failed attempts may deserve extra caution.

### Important

```text
badpwdcount: 0
        ↓
No recorded bad-password attempts in this context

badpwdcount: 3
        ↓
Account already has failed attempts
        ↓
Potential lockout concern
```

---

# 7. Domain Group Enumeration

Command:

```bash
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups
```

This enumerates domain groups and their member counts.

Example:

```text
Administrators        membercount: 3
Users                 membercount: 4
Guests                membercount: 2
Backup Operators      membercount: 1
Domain Admins         membercount: 19
Contractors           membercount: 138
Accounting             membercount: 15
Engineering            membercount: 19
Executives             membercount: 10
Human Resources        membercount: 36
```

---

# 🎯 8. Groups Worth Paying Attention To

Not every group is equally interesting.

During an assessment, pay particular attention to groups such as:

```text
Administrators
Domain Admins
Backup Operators
Executives
IT / administrative groups
```

The reason is simple:

```text
Group
  ↓
Members
  ↓
Privileges
  ↓
Potential attack paths
```

The module specifically recommends noting groups that may contain privileged IT administrators or other elevated users.

---

# 👤 9. Logged-On User Enumeration

CME can also identify users currently logged onto a host.

Command:

```bash
sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users
```

Example:

```text
clusteragent
lab_adm
svc_qualys
wley
```

---

# 🧠 Why Are Logged-On Users Interesting?

Imagine you discover:

```text
File Server
     |
     +-- normal users
     +-- service accounts
     +-- administrators
     +-- Domain Admin
```

A server with privileged users logged in may deserve additional investigation during an authorized assessment.

The module specifically highlights a scenario where `svc_qualys` was previously identified as a Domain Admin and was logged onto the file server.

### Important concept

```text
Host
  ↓
Logged-on users
  ↓
Identify privileged sessions
  ↓
Understand potential privilege relationships
```

BloodHound can later perform this type of user-session hunting at a much larger scale.

---

# 📂 10. SMB Share Enumeration

CME's:

```text
--shares
```

option enumerates SMB shares and the access level of the authenticated account.

Command:

```bash
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares
```

Example:

```text
ADMIN$             Remote Admin
C$                 Default share
Department Shares  READ
IPC$               READ
NETLOGON           READ
SYSVOL             READ
User Shares        READ
ZZZ_archive        READ
```

---

# 🔑 11. Important SMB Shares

### `ADMIN$`

Administrative share.

### `C$`

Default administrative drive share.

### `IPC$`

Used for inter-process communication and certain remote operations.

### `NETLOGON`

Domain logon-related share.

### `SYSVOL`

Contains domain-related Group Policy and other replicated domain information.

### Custom shares

Examples:

```text
Department Shares
User Shares
ZZZ_archive
```

These are often worth examining because they may contain organizational files and potentially sensitive information.

The module specifically highlights these non-standard shares for further investigation.

---

# 🕷️ 12. CME `spider_plus`

CME can recursively examine readable shares using the:

```text
spider_plus
```

module.

Example:

```bash
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
```

The output is stored under:

```text
/tmp/cme_spider_plus/
```

For example:

```text
/tmp/cme_spider_plus/172.16.5.5.json
```

### What does it do?

Conceptually:

```text
SMB Share
   ↓
Enumerate directories
   ↓
Enumerate readable files
   ↓
Create JSON inventory
   ↓
Review interesting files
```

The module mentions files such as:

```text
web.config
scripts
```

as examples of files that may deserve attention because configuration files or scripts can sometimes contain sensitive information.

---

# 🗺️ 13. SMBMap

**SMBMap** is another Linux tool for enumerating SMB shares.

It can help determine:

- Available shares
    
- Permissions
    
- Directory contents
    
- File contents
    
- Read/write access
    

It can also recursively list directories and search shares.

---

# 14. SMBMap — Check Access

Command:

```bash
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5
```

Example:

```text
ADMIN$             NO ACCESS
C$                 NO ACCESS
Department Shares  READ ONLY
IPC$               READ ONLY
NETLOGON           READ ONLY
SYSVOL             READ ONLY
User Shares        READ ONLY
ZZZ_archive        READ ONLY
```

---

# 15. CME vs SMBMap

|CME|SMBMap|
|---|---|
|Broad AD/Windows toolkit|Focused on SMB|
|Users|Shares|
|Groups|Permissions|
|Logged-on users|Directory enumeration|
|Shares|File/share access|
|Remote interaction|File operations|

### Easy memory

```text
CME = Swiss-army knife
SMBMap = SMB specialist
```

---

# 📁 16. Recursive Directory Enumeration

SMBMap can recursively enumerate a share.

Command:

```bash
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only
```

The:

```text
-R
```

means recursive enumeration.

The:

```text
--dir-only
```

option limits output to directories.

Example structure:

```text
Department Shares
│
├── Accounting
├── Executives
├── Finance
├── HR
├── IT
├── Legal
├── Marketing
├── Operations
├── R&D
├── Temp
└── Warehouse
```

---

# 🛰️ 17. rpcclient

`rpcclient` is a Samba utility that provides functionality through **MS-RPC**.

It can be used to:

- Enumerate users
    
- Enumerate groups
    
- Query objects
    
- Work with AD-related information
    

The module emphasizes that `rpcclient` is highly versatile and that its manual page is useful:

```bash
man rpcclient
```

---

# 18. SMB NULL Session

If the target permits SMB NULL sessions, an unauthenticated connection can be attempted with:

```bash
rpcclient -U "" -N 172.16.5.5
```

Conceptually:

```text
No username
     +
No password
     ↓
SMB NULL Session
     ↓
RPC connection
     ↓
Potential enumeration
```

Whether this works depends on the target's configuration.

---

# 🆔 19. SID vs RID

This is **very important for AD fundamentals**.

### SID

A **Security Identifier (SID)** identifies a security principal.

Example domain SID:

```text
S-1-5-21-3842939050-3880317879-2865463114
```

### RID

A **Relative Identifier (RID)** is appended to the domain SID to identify an object within that domain.

Example:

```text
Domain SID
S-1-5-21-3842939050-3880317879-2865463114

        +

RID
1111

        ↓

Full SID
S-1-5-21-3842939050-3880317879-2865463114-1111
```

The module gives `htb-student` as an example with:

```text
RID = 0x457
```

which is:

```text
0x457 = 1111 decimal
```

---

# 🔥 20. Important Built-In RID

The built-in Administrator account normally has:

```text
RID = 500
```

Hexadecimal:

```text
0x1f4
```

So:

```text
Administrator
RID = 0x1f4
       ↓
     500
```

The module emphasizes that the built-in Administrator's RID remains `500`.

### Memorize

```text
Administrator → RID 500 → 0x1f4
```

---

# 21. `queryuser`

If you know a user's RID, `rpcclient` can query the account.

Example:

```text
rpcclient $> queryuser 0x457
```

The output can include:

```text
User Name
Full Name
Profile Path
Logon Time
Password last set Time
Password can change Time
Password must change Time
user_rid
group_rid
bad_password_count
logon_count
```

This demonstrates how much information can potentially be retrieved from AD objects.

---

# 22. `enumdomusers`

To enumerate all domain users and their RIDs:

```text
rpcclient $> enumdomusers
```

Example:

```text
user:[administrator] rid:[0x1f4]
user:[guest]         rid:[0x1f5]
user:[krbtgt]        rid:[0x1f6]
user:[lab_adm]       rid:[0x3e9]
user:[htb-student]   rid:[0x457]
user:[avazquez]      rid:[0x458]
```

### Workflow

```text
enumdomusers
      ↓
Username + RID
      ↓
queryuser <RID>
      ↓
Detailed user information
```

---

# 🧰 23. Impacket Toolkit

**Impacket** is a Python toolkit containing many tools for interacting with Windows protocols.

The module introduces:

```text
psexec.py
wmiexec.py
```

![Image](https://images.openai.com/static-rsc-4/XDoBk1DZcDs4YcSpvn9dpvjXSdflxyKNKQlMjOXqt_y21XSvBFenawIc_kuS0-ZLmrapXiWTTQmh6yVgPeD0xn8-QFSqaNuuWeflbrjQn2Hd8uSZir9TXYFL7AGQ0C0SbG2NxmMG_U256nBqZmAOlBivBTbmVREp_D2esXuqnHs9bRRZv4TZvph-FjHv3K7l?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Ymw5OK2CenTwMKzleDsrzkikPvNzJKi3ba95llWY3f0RnDaN6tM8HsH1Uju2JroKTQua7w2NkhHOd057vwVO8v6uQsOLwDNRizDXh8d1Dk2MRHqtmfG4i3xrXL8gb4TVFEG7fRt1SV289hvny2zFjsXDqpL9qOp8Ua28Za58S9PjdIr2f3fkuQXAZZx202wH?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/bWUp0ka_98bCO714kHq39UCxqNP5I2vPijrGR2rjwDkoDFOCCTCxDdcYUA6FaGHRBUIk47Bzm0C0v0_JL3G6kAn_htiJiw_LsRerbSfmJCuGKf7SGWPfNCcOS2pST4dq1cskDNXw8zKPhFDMbmLykL4-UhCkB7TYaDInMdPAT_ig8Epsa3nusgDI1HsB6rKI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/XI2fMDky3uIeBx9paHssqpgaPEulbYqERAKpMbQ_GaYDc3hy5pv4WmYMlApxZ2LtNaSd1b2Kg4u_dhcimUHvOM1FJqsN5vkoB0s1jXok_4GP_qqWoW9k6jHra1SZ9TkZMfKIuqwEHlc-q1zXzBCkqydJvHI1k3RbdVnGRnDV48CvUY63qM2alRF47n56oh1V?purpose=fullsize)

---

# 24. `psexec.py`

`psexec.py` is based on the concept of Sysinternals PsExec.

The module explains that it:

1. Uploads a randomly named executable to `ADMIN$`
    
2. Creates/registers a Windows service
    
3. Uses RPC and the Service Control Manager
    
4. Communicates through a named pipe
    
5. Provides a remote shell as `SYSTEM`
    

### Conceptual workflow

```text
Local machine
      |
      | credentials
      v
Remote Windows host
      |
      +--> ADMIN$
      |
      +--> Service creation
      |
      +--> RPC
      |
      +--> Named pipe
      |
      v
   SYSTEM shell
```

---

# 25. `psexec.py` Requirements

The module explicitly notes that you need credentials for a user with **local administrator privileges**.

Example:

```bash
psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125
```

After connection, the example verifies the context using:

```bash
whoami
```

and gets:

```text
SYSTEM
```

---

# ⚙️ 26. `wmiexec.py`

`wmiexec.py` uses:

> **Windows Management Instrumentation (WMI)**

Unlike `psexec.py`, the module explains that it does not drop an executable onto the target in the same way.

It provides a semi-interactive shell and executes commands through WMI.

Example:

```bash
wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5
```

---

# 27. PsExec vs WMIExec

|Feature|`psexec.py`|`wmiexec.py`|
|---|---|---|
|Technology|Windows service|WMI|
|Shell|Interactive-style|Semi-interactive|
|Drops executable|Yes, according to module workflow|No executable dropped in same way|
|Context|`SYSTEM`|Connecting user's context|
|Example|Local admin required|Local admin required|
|Detection|Can generate service/process artifacts|Can generate process events|

The module notes that `wmiexec.py` may generate fewer logs than some other methods, but modern AV/EDR can still detect it.

---

# 🚨 28. Event ID 4688

The module highlights:

```text
4688
```

Meaning:

> **A new process has been created**

When using WMI execution, a defender may see a new process such as `cmd.exe` being spawned.

### Memorize

```text
4688 → New process created
```

This connects your offensive tooling knowledge with Windows detection.

---

# 🔎 29. Windapsearch

**Windapsearch** is a Python script for enumerating:

- Users
    
- Groups
    
- Computers
    
- Domain functionality
    
- Privileged users
    
- Domain Admins
    
- Other LDAP information
    

It uses **LDAP queries** against the Domain Controller.

---

# 30. Windapsearch Important Options

```text
-d / --domain
--dc-ip
-u / --user
-p / --password

-G / --groups
-U / --users
-C / --computers
-PU / --privileged-users
--da
```

### Easy memory

```text
U → Users
G → Groups
C → Computers
PU → Privileged Users
DA → Domain Admins
```

---

# 👑 31. Enumerating Domain Admins

Command:

```bash
python3 windapsearch.py --dc-ip 172.16.5.5 \
-u forend@inlanefreight.local \
-p Klmcargo2 \
--da
```

The module's output identifies:

```text
Domain Admins
```

and enumerates members.

The example finds:

```text
28 Domain Admins
```

The module recommends paying attention to previously discovered accounts that may already have credentials or hashes.

---

# 🧬 32. Privileged Users and Nested Groups

Command:

```bash
python3 windapsearch.py --dc-ip 172.16.5.5 \
-u forend@inlanefreight.local \
-p Klmcargo2 \
-PU
```

`-PU` searches for privileged users, including users whose privilege comes from **nested group membership**.

---

# 🧠 Why Nested Groups Matter

Consider:

```text
User
 ↓
Group A
 ↓
Group B
 ↓
Domain Admins
```

The user might not directly appear to be a Domain Admin.

But through nested membership:

```text
User
   ↓
Group A
   ↓
Group B
   ↓
Domain Admins
   ↓
High privilege
```

This is one reason simple group-member enumeration isn't always enough.

The module specifically highlights the danger of nested group membership.

---

# 🧠 33. BloodHound.py

This is one of the **most important tools in the entire AD section**.

BloodHound uses **graph theory** to represent relationships within Active Directory.

Instead of looking at hundreds of disconnected pieces of information:

```text
Users
Groups
Computers
ACLs
GPOs
Sessions
Trusts
```

BloodHound turns them into a relationship graph.

![Image](https://images.openai.com/static-rsc-4/6H0tAcHWatXzMDK9jr644zXdF-8s7XTrE1YONjcWIu_kPifepXOaA8_4lrnRSIE1m93QhF4OPrMH8JT5eoZ57ssYqhn_pG3LNUS_9ecKN0njcaWFluBoDQb9G-OkoqNy3e-_JsT2bbJrtxWQdeNSroRfdMT70XFKv5E0bxlEiDWsYI-11faBgJ_nArlZUskd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/o6ECvmCYfTTExAgepi1PKiEQcmttIEspsiXp9sJDMhPeLwS8Siyv_RF7i7svfS2k9h5SZID3EzsF2YcsHtOnsF0kYNKLFuWkrwYarXi8HZpf88ySjkI5CiKoj10Bl0XZUGwP1fM9NQG0QJfym7Pwwmdm1_UaeRlFQkf4Hk4oztyAdcskdLyXPXHheWdY4yni?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/m93MyWW37SwJGu14bpXY_aDFYnO35ZxpgeiaLsR5bWr_18yX3uL64Er7mE6cna9s2nzVt5eikFg0km2cCn5EwXPLb55ioz-o8Po0-U_T_Uc6093QrPWKQ6YDcGa5NJi1efyc5CUVTaWqwx2SLWVXXQsV2E9l3_X-OH-eeFD0_55lnF13PJ7d-8dcBaDXVsyV?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/YgU1urZ2YMb92CBQ_6T_foG4_ju_JjVW-1DKHH_6qvb9kPtHUb08S3AQmsT2Xi0faOvSVZhDo6CtRWMhrWakRiykL3hEIbr3H529exj4DpOH-pneJT-TRyYGqIiBDy0-FzP-eRoEOYhdfl_aS1jYG5iMEP1LwQQz7rHrGIOsz67DbjmN8yVwuzO_ZyF4mjum?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Krs7gGC6KWsVS4zBNL0FmvK-bWmtANwZFok0-RmGl26XnVIg-KD__kTFk3lrxPx-wzZYKUzzrwMLzd582LqnhdseMcN2VgdSkl8i9GkDMLsR1YlcQHQRD3Ng3ffBhL8R8th5JQKnoYoTTBxjq2jqmyi58OuaLcyMwfQ2XUxYC8t4mfcz4iBu1QI8fQnbTAFx?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/cNEkgM03hcFy7wGZERA5AwLTBkrkUGYxeTQM64_AxANk53tu9iRiCk_yoIf_g_eh0SY8NxTMgpg7_dmcQh9aWcPfnMnpd90JDQIuK7CQ1S8v9uyp48iPxcbV-_r8QcZypNBlxLO8PnsOnulDUXS3T6wg2TJIONUztX8X-58DdKCrvDcdnigOf01BBAv7LKeR?purpose=fullsize)

---

# 34. What BloodHound Collects

The module lists information including:

```text
Users
Groups
Computers
Group membership
GPOs
ACLs
Domain trusts
Local administrator access
User sessions
Computer properties
User properties
RDP access
WinRM access
```

---

# 35. BloodHound Architecture

Understand these two components:

```text
              BloodHound
                  |
        +---------+---------+
        |                   |
        v                   v
   Data Collector        GUI
        |                   |
        v                   v
 BloodHound.py        Graph analysis
 SharpHound            Cypher queries
```

### `SharpHound`

C# collector designed primarily for Windows.

### `BloodHound.py`

Python-based collector that can be run from a Linux attack host.

### BloodHound GUI

Used to:

- Import data
    
- Visualize relationships
    
- Run built-in queries
    
- Run custom Cypher queries
    

---

# 36. BloodHound Collection Methods

The module shows:

```text
Group
LocalAdmin
Session
Trusts
Default
DCOnly
DCOM
RDP
PSRemote
LoggedOn
ObjectProps
ACL
All
```

### Important distinction

```text
-c all
```

means collect a broad set of available information.

---

# 37. Running BloodHound.py

The module's example:

```bash
sudo bloodhound-python \
-u 'forend' \
-p 'Klmcargo2' \
-ns 172.16.5.5 \
-d inlanefreight.local \
-c all
```

Let's understand the arguments:

|Argument|Meaning|
|---|---|
|`-u`|Username|
|`-p`|Password|
|`-ns`|Nameserver|
|`-d`|Domain|
|`-c all`|Broad collection|

---

# 38. Example BloodHound Results

The module's example discovers:

```text
1 domain
2 domains in forest
564 computers
2951 users
183 groups
2 trusts
```

This demonstrates how much information can be gathered from one authenticated collection.

---

# 📦 39. Output Files

After collection, the module shows JSON files such as:

```text
20220307163102_computers.json
20220307163102_domains.json
20220307163102_groups.json
20220307163102_users.json
```

These files contain the collected AD relationship data.

---

# 🗄️ 40. Neo4j

BloodHound uses a graph database.

The module demonstrates starting Neo4j with:

```bash
sudo neo4j start
```

Then the BloodHound GUI can be launched.

Conceptually:

```text
BloodHound.py
      |
      v
   JSON data
      |
      v
    Neo4j
      |
      v
BloodHound GUI
      |
      v
Graph analysis
```

---

# 🔍 41. BloodHound Analysis

After importing the data, the GUI's **Analysis** section can run queries.

One important built-in query mentioned by HTB is:

```text
Find Shortest Paths To Domain Admins
```

This analyzes relationships through:

```text
Users
Groups
Hosts
ACLs
GPOs
Sessions
etc.
```

and helps identify logical paths toward privileged access.

---

# 🧠 42. The Big Picture

All these tools answer different questions.

```text
                 VALID CREDENTIALS
                        |
          +-------------+-------------+
          |             |             |
          v             v             v
        CME          SMBMap       rpcclient
          |             |             |
     Users/Groups    Shares       Users/RIDs
     Sessions        Files        Object info
          |             |             |
          +-------------+-------------+
                        |
                        v
                  Windapsearch
                        |
                 LDAP enumeration
                        |
                 Privileged users
                        |
                        v
                  BloodHound.py
                        |
                 Relationships
                        |
                        v
                  Attack Paths
```

---

# 🔥 43. Tool Comparison Cheat Sheet

|Tool|Main strength|
|---|---|
|**CrackMapExec**|Broad Windows/SMB enumeration|
|**SMBMap**|SMB shares and permissions|
|**rpcclient**|MS-RPC / users / RIDs|
|**psexec.py**|Remote service-based execution|
|**wmiexec.py**|WMI-based remote execution|
|**Windapsearch**|LDAP enumeration|
|**BloodHound.py**|AD relationship mapping|

---

# 🧩 44. Important Commands

### CME — users

```bash
sudo crackmapexec smb <DC> -u <user> -p <password> --users
```

### CME — groups

```bash
sudo crackmapexec smb <DC> -u <user> -p <password> --groups
```

### CME — logged-on users

```bash
sudo crackmapexec smb <HOST> -u <user> -p <password> --loggedon-users
```

### CME — shares

```bash
sudo crackmapexec smb <HOST> -u <user> -p <password> --shares
```

### SMBMap

```bash
smbmap -u <user> -p <password> -d <domain> -H <host>
```

### SMBMap recursive

```bash
smbmap -u <user> -p <password> -d <domain> -H <host> -R '<share>' --dir-only
```

### rpcclient

```bash
rpcclient -U "" -N <DC>
```

### RPC user enumeration

```text
enumdomusers
```

### RPC query by RID

```text
queryuser <RID>
```

### Windapsearch — Domain Admins

```bash
python3 windapsearch.py --dc-ip <DC-IP> -u <user>@<domain> -p <password> --da
```

### Windapsearch — privileged users

```bash
python3 windapsearch.py --dc-ip <DC-IP> -u <user>@<domain> -p <password> -PU
```

### BloodHound.py

```bash
sudo bloodhound-python -u '<user>' -p '<password>' -ns <DC-IP> -d <domain> -c all
```

---

# 🧠 45. Critical AD Concepts to Memorize

### SID

```text
Security Identifier
```

Identifies a security principal.

### RID

```text
Relative Identifier
```

Identifies an object within the domain's SID namespace.

### Administrator RID

```text
500
0x1f4
```

### LDAP

Directory protocol used by tools such as:

```text
Windapsearch
BloodHound.py
```

### SMB

Network file-sharing protocol heavily used by:

```text
CME
SMBMap
```

### RPC

Remote Procedure Call mechanism used by:

```text
rpcclient
```

### WMI

Windows Management Instrumentation used by:

```text
wmiexec.py
```

---

# 🚨 46. Detection Knowledge

You should not study these tools only from an offensive perspective.

### WMI execution

Potentially relevant:

```text
Event ID 4688
```

because process creation can be logged.

### SMB enumeration

Defenders may observe:

```text
SMB authentication
SMB share access
Large-scale enumeration
```

### LDAP enumeration

Potentially generates:

```text
LDAP queries
Authentication events
Directory-service activity
```

### BloodHound

Large-scale collection can generate a noticeable amount of directory and host enumeration traffic.

The module itself notes that even collection from an attack host may trigger alerts in well-protected environments.

---

# 🎯 47. Mentor Workflow — How You Should Think

Don't memorize 50 commands separately.

Think in questions.

### Question 1

**Who exists?**

```text
CME --users
rpcclient enumdomusers
Windapsearch --users
```

### Question 2

**Who has privilege?**

```text
CME --groups
Windapsearch --da
Windapsearch -PU
```

### Question 3

**Who is logged in?**

```text
CME --loggedon-users
BloodHound Session
```

### Question 4

**What can I access?**

```text
CME --shares
SMBMap
```

### Question 5

**What objects exist?**

```text
rpcclient
Windapsearch
```

### Question 6

**How are the objects related?**

```text
BloodHound.py
```

### Question 7

**Is there a path to higher privilege?**

```text
BloodHound
    ↓
Attack-path analysis
```

---

# 🏆 48. Final Revision Map

```text
                    CREDENTIALS
                         |
                         v
                Credentialed Access
                         |
       +-----------------+-----------------+
       |                 |                 |
       v                 v                 v
      CME              SMBMap          rpcclient
       |                 |                 |
 Users / Groups      Shares / Files     RIDs / Users
 Sessions / Shares       |                 |
       |                 |                 |
       +-----------------+-----------------+
                         |
                         v
                    Windapsearch
                         |
                  LDAP Enumeration
                         |
              +----------+----------+
              |                     |
              v                     v
        Domain Admins       Privileged Users
              |                     |
              +----------+----------+
                         |
                         v
                    BloodHound.py
                         |
                         v
                Graph Relationships
                         |
                         v
                  Attack Paths
                         |
                         v
             Lateral / Vertical Movement
```

## 🔥 The 7 Things I Want You to Remember

1. **CME** → broad AD/SMB enumeration.
    
2. **SMBMap** → SMB shares, permissions and files.
    
3. **rpcclient** → RPC, users and RIDs.
    
4. **RID 500 / `0x1f4`** → built-in Administrator.
    
5. **Impacket** → Windows protocol interaction and remote execution.
    
6. **Windapsearch** → LDAP-based user/group/computer/privilege enumeration.
    
7. **BloodHound.py** → turn AD relationships into a graph and identify attack paths.
    

The overall progression is:

> **Credentials → Enumerate → Understand relationships → Identify privilege → Map attack paths.**

That is the core skill this section is teaching.