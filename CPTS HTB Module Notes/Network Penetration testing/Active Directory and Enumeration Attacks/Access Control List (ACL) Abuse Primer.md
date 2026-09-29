## 1. What is an ACL?

In an Active Directory (AD) environment, not every user or computer should have access to every object or file. **Access Control Lists (ACLs)** are used to control these permissions. A small ACL misconfiguration can unintentionally give a user permissions over objects they should not control.

### Simple definition

> **ACL = A list that defines who can access an object/resource and what they are allowed to do with it.**

An ACL contains individual **Access Control Entries (ACEs)**.

Think of it like:

```text
Object
   │
   └── ACL
        │
        ├── ACE → User A → Read
        ├── ACE → User B → Write
        └── ACE → Group C → Full Control
```

---

# 2. ACL Overview

An ACL answers two fundamental questions:

1. **Who has access?**
    
2. **What level of access do they have?**
    

The individual permission entries inside an ACL are called **ACEs**.

An ACE maps a permission to a **security principal**, such as:

- User
    
- Group
    
- Process
    

Every AD object has an ACL and can contain multiple ACEs because multiple security principals may have permissions over the same object. ACLs can also be used for auditing access within AD.

---

# 3. Two Types of ACLs

There are **two major types of ACLs** in the module:

## 3.1 DACL — Discretionary Access Control List

A **DACL** determines which security principals are:

- Allowed access
    
- Denied access
    

A DACL is composed of ACEs that either allow or deny access.

When someone attempts to access an object, the system checks the DACL to determine the permissions available to them.

### Important behavior

According to the module:

- **No DACL exists** → access attempts are granted full rights.
    
- **DACL exists but contains no ACE entries specifying permissions** → access is denied.
    

### Remember

```text
DACL
 │
 ├── Allow
 └── Deny
```

**DACL = controls access.**

---

## 3.2 SACL — System Access Control List

A **SACL** is used by administrators to **log access attempts** made against secured objects.

In other words:

```text
DACL → "Can you access it?"
SACL → "Should this access attempt be logged?"
```

The module shows SACL entries through the **Auditing** tab in Active Directory Users and Computers (ADUC).

---

# 4. ACL vs ACE

This distinction is extremely important.

### ACL

The **ACL is the overall permission list** for an object.

### ACE

An **ACE is an individual permission entry inside the ACL**.

Example:

```text
User: forend
        │
        └── ACL
             │
             ├── ACE → Angela Dunn → Allow → Read
             ├── ACE → Help Desk → Allow → Write
             └── ACE → Everyone → Deny
```

So:

> **ACL = collection of ACEs**

The module describes ACEs as entries that identify a user/group and the level of access they have over a securable object.

---

# 5. Types of ACEs

The module identifies **three main ACE types**:

|ACE Type|Purpose|
|---|---|
|**Access denied ACE**|Explicitly denies a user/group access to an object|
|**Access allowed ACE**|Explicitly grants a user/group access to an object|
|**System audit ACE**|Generates audit logs when a user/group attempts access|

These correspond to DACL and SACL functionality.

### Easy memory trick

```text
DACL
 ├── Allow ACE
 └── Deny ACE

SACL
 └── Audit ACE
```

---

# 6. Four Components of an ACE

Each ACE contains **four important components**:

### 1. Security Identifier — SID

Identifies the user or group receiving the permission.

### 2. ACE Type

Specifies whether the ACE is:

- Allow
    
- Deny
    
- System Audit
    

### 3. Inheritance Flags

Determine whether the ACE can be inherited by:

- Child containers
    
- Child objects
    

### 4. Access Mask

A **32-bit value** defining the rights granted to the object.

### Visual model

```text
                 ACE
                  │
       ┌──────────┼──────────┐
       │          │          │
      SID       Type    Inheritance
                  │
             Access Mask
```

---

# 7. Viewing ACLs in ADUC

ACLs can be viewed graphically using:

**Active Directory Users and Computers (ADUC)**

For a user/object:

```text
Object
  ↓
Properties
  ↓
Security
  ↓
Advanced
  ↓
Permission Entries
```

The module's example uses the `forend` user account. Each item under **Permission entries** represents part of the object's DACL.

SACL entries can be viewed under:

```text
Advanced Security Settings
        ↓
     Auditing
```

---

# 8. Understanding an ACE Example

The module gives an example involving the `forend` object and the principal:

```text
adunn@inlanefreight.local
```

The example demonstrates four important pieces:

1. **Security principal** → Angela Dunn
    
2. **ACE type** → Allow
    
3. **Inheritance** → applies to the object and descendant objects
    
4. **Rights** → the permissions granted to the principal
    

### Important

ACL permissions can therefore apply not only to the object itself but potentially to objects underneath it through inheritance.

---

# 9. ACL Evaluation Order

When access-control lists are checked, they are evaluated **from top to bottom until an access denied is found**.

Conceptually:

```text
ACE #1
  ↓
ACE #2
  ↓
ACE #3
  ↓
Access Denied?
  ├── YES → Access denied
  └── NO  → Continue evaluation
```

This is why understanding the ordering and inheritance of ACEs matters during an assessment.

---

# 10. Why Are ACEs Important for Penetration Testing?

ACL/ACE misconfigurations can provide attackers with unexpected permissions.

The module highlights that attackers can use ACEs to:

- Gain further access
    
- Establish persistence
    
- Move laterally
    
- Escalate privileges
    
- Potentially achieve full domain compromise
    

These permission relationships can be difficult to identify with traditional vulnerability scanners and may remain unnoticed in large AD environments.

### Important pentesting concept

```text
Low privilege account
        │
        ▼
Misconfigured ACE
        │
        ▼
Additional AD permissions
        │
        ▼
Privilege escalation / lateral movement
        │
        ▼
Potential domain compromise
```

---

# 11. Important ACE Permissions

The module lists several AD permissions that can be abused during an authorized assessment:

|Permission|Example abuse/tool|
|---|---|
|`ForceChangePassword`|`Set-DomainUserPassword`|
|`Add Members`|`Add-DomainGroupMember`|
|`GenericAll`|`Set-DomainUserPassword` / `Add-DomainGroupMember`|
|`GenericWrite`|`Set-DomainObject`|
|`WriteOwner`|`Set-DomainObjectOwner`|
|`WriteDACL`|`Add-DomainObjectACL`|
|`AllExtendedRights`|`Set-DomainUserPassword` / `Add-DomainGroupMember`|
|`AddSelf`|`Add-DomainGroupMember`|

---

# 12. ForceChangePassword

`ForceChangePassword` gives a principal the ability to **reset another user's password without first knowing the existing password**.

The module specifically notes that this should be used cautiously and that testers should generally consult the client before resetting passwords.

### Attack concept

```text
Compromised User
       │
       ▼
ForceChangePassword
       │
       ▼
Target User
       │
       ▼
Password reset
       │
       ▼
Potential access as target
```

### Tool mentioned

```text
Set-DomainUserPassword
```

---

# 13. GenericWrite

`GenericWrite` provides the ability to write to **non-protected attributes** of an object.

Its impact depends on the object type.

### Against a user

The module notes that an attacker could assign an **SPN** to the user and potentially perform **Kerberoasting**, assuming the target account has a weak password.

```text
GenericWrite
     │
     ▼
User object
     │
     ▼
Assign SPN
     │
     ▼
Kerberoasting
     │
     ▼
Potential password recovery
```

### Against a group

It may allow adding yourself or another security principal to the group.

```text
GenericWrite
     │
     ▼
Group object
     │
     ▼
Modify group-related attributes
```

### Against a computer

The module notes that GenericWrite can potentially be used for a **resource-based constrained delegation** attack, which is outside the scope of this module.

---

# 14. AddSelf

`AddSelf` identifies security groups where a user has the ability to **add themselves**.

Conceptually:

```text
Current User
     │
     │ AddSelf
     ▼
AD Group
     │
     ▼
User becomes member
```

The module identifies this as an important BloodHound relationship to enumerate.

---

# 15. GenericAll

`GenericAll` is particularly powerful because it provides **full control over the target object**.

The exact impact depends on what type of object is controlled.

### User object

Possible actions include:

- Modify the password
    
- Perform targeted Kerberoasting
    

### Group object

Possible action:

- Modify group membership
    

### Computer object

The module notes that if **LAPS** is being used, control over a computer object may allow reading the LAPS password and potentially gaining local administrator access.

### Mental model

```text
GenericAll
    │
    ├── User → Password / Kerberoasting
    │
    ├── Group → Membership modification
    │
    └── Computer → Potential LAPS abuse
```

---

# 16. BloodHound and ACL Enumeration

**BloodHound** is particularly useful for visualizing AD relationships and identifying potentially abusable permissions.

The module specifically states that permissions such as those above can be enumerated and visualized using BloodHound.

### General workflow

```text
Enumerate AD
      ↓
Collect BloodHound data
      ↓
Analyze relationships
      ↓
Find interesting ACE
      ↓
Identify controlled object
      ↓
Determine possible abuse
      ↓
Validate in authorized lab
```

---

# 17. PowerView

The module also mentions **PowerView** as a tool that can be used to enumerate and abuse several AD permissions.

Examples from the module include:

```text
Set-DomainUserPassword
Add-DomainGroupMember
Set-DomainObject
Set-DomainObjectOwner
Add-DomainObjectACL
```

The important skill is not memorizing every command. Instead, understand:

> **Permission → Object → Possible impact → Appropriate tool**

---

# 18. ACL Attack Methodology

A useful methodology is:

```text
                 START
                   │
                   ▼
          Enumerate AD objects
                   │
                   ▼
          Enumerate ACL / ACEs
                   │
                   ▼
       Identify interesting rights
                   │
                   ▼
       ┌───────────┴───────────┐
       │                       │
   User object             Group object
       │                       │
       ▼                       ▼
 Password / SPN          Membership control
       │                       │
       └───────────┬───────────┘
                   ▼
            Gain more access
                   │
                   ▼
          Continue enumeration
```

The module emphasizes that the same methodology can help when encountering less common AD privileges that you have not previously seen.

---

# 19. Other Interesting BloodHound Edges

Not every useful AD permission is one of the common ACEs listed above.

The module gives **ReadGMSAPassword** as an example.

If a user you control has permission to read the password of a **Group Managed Service Account (gMSA)**, tools such as `GMSAPasswordReader` can potentially be used to obtain the service-account password.

Other examples mentioned include:

- `Unexpire-Password`
    
- `Reanimate-Tombstones`
    

### Key lesson

Don't limit yourself to only memorized ACE names.

```text
Unknown BloodHound edge
          ↓
Understand what permission it represents
          ↓
Identify affected object
          ↓
Research its security impact
          ↓
Determine whether it can be leveraged
```

---

# 20. ACL Attacks in the Wild

The module identifies three major uses of ACL attacks:

### 1. Lateral Movement

Moving from one compromised account/system to another.

### 2. Privilege Escalation

Obtaining permissions greater than those initially available.

### 3. Persistence

Maintaining access through modified permissions or relationships.

---

# 21. Common ACL Attack Scenarios

## Scenario 1 — Abusing Forgotten Password Permissions

Help Desk and IT personnel may receive permissions to perform password resets.

If an attacker compromises an account with those permissions, they may potentially reset the password of a more privileged account.

```text
Compromise Help Desk account
          ↓
Password-reset permission
          ↓
Privileged target
          ↓
Password reset
          ↓
Potential privileged access
```

---

# 22. Scenario 2 — Abusing Group Membership Management

Some users may have permission to add or remove members from a particular AD group.

An attacker controlling such an account could potentially add a controlled account to a privileged group or another group that grants useful privileges.

```text
Compromised Account
        │
        ▼
Can modify group membership
        │
        ▼
Privileged / useful group
        │
        ▼
Additional permissions
```

---

# 23. Scenario 3 — Excessive User Rights

Objects can sometimes have more permissions than intended.

The module notes that this can happen because of:

- Software installations
    
- Exchange-related ACL changes
    
- Legacy configurations
    
- Accidental configuration
    
- Permissions granted for convenience
    

### Important pentesting lesson

An account doesn't have to be a Domain Admin to be dangerous.

A low-privileged account with the **right ACL relationship** can potentially have a path toward much greater access.

---

# 24. ACL Attack Graph — Big Picture

![Image](https://images.openai.com/static-rsc-4/5UXD1QX_-aQVb1hoz10GcTGKDKcEgq8zxcd14l4yvR-OxXWb5p4-3Hi0frkzIUTtSC4T1_kaOQ0rZO9Gk1csHZ8rlKEoMe_sxkz2Cr7I89h438z6nxzEqLp4K0uGkcLhyUO19khSOzLkPjH6bMipdH3qVzXAkF9kmVqGSvBnV1kXfrjnKh_wLzuI8nW2yZB6?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/YgU1urZ2YMb92CBQ_6T_foG4_ju_JjVW-1DKHH_6qvb9kPtHUb08S3AQmsT2Xi0faOvSVZhDo6CtRWMhrWakRiykL3hEIbr3H529exj4DpOH-pneJT-TRyYGqIiBDy0-FzP-eRoEOYhdfl_aS1jYG5iMEP1LwQQz7rHrGIOsz67DbjmN8yVwuzO_ZyF4mjum?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/J1dmXNFbZCxNaoBJdGzxIpcDeJHN8-N15GSypbwfcgN4d32d6Sq78riMwSNWMAQunP2UtdPK2Yus1UjeAvl0HmX_Z_mvyd4AZe1YHoE6dk-Pe9f4ouclNP138pZm5ZCcpUniBW7bnMkQ08TwzGSE74Vl82tbbILJ6_nvRm0Xb_MeEpfdWpy31jsNmVcklDjo?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/MVq1HJQUQMVFG7d9ZRmY4qr_EhDTD51nTDQt5c1BGfsDWi0cO2G_--XgG47S2Aio56MlYvT6p8_-mI4UWxh2yaJFo-6Ng2V2ZcXvH8GRhWzCCy66MGrTjgtI2t8zgfebmmM97IxpPLcz3dC3jST1Ql9LoUyeA4SzPj0XeL-ExuQN-0alqerspxy94iLrQFzH?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ewx8CWN4GSPayW6nVIf8RlGzQGzR-wJx3zAbJ-pA9BQI2zLyuhaT24GbnKBaE0he31oW-gj_X-ZBfIQ878vLDE07Csqv9OgFcP_7E7Ev-vGb-Y2591SLEMBSKst4JsFFK3nlEmV9b72Ce2B_ds46F-HSZwOvNFJ2nFLiOqQbCQsiAIjgojebad_VLtmB7utB?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/SudGmvs34SqfMNxXOGPDHda0sO6QBKw6BmaTPADxfY8kLXbQF9PTON_2XBQJcVmkXoPL5EibhAlESeZcqi2IbYSDfHCO1KSgiWMnVJHJ3ToNuFG6KPSD2VOzb8I38O4R3zxuPlIBmqdWxFbVXmAuttGL-2crSo45Ai9QnAUbemESCD_BHIfCZBpBElaMC_NO?purpose=fullsize)

Think of an AD ACL attack as a permissions graph:

```text
                  DOMAIN
                    │
        ┌───────────┼────────────┐
        ▼           ▼            ▼
      Users       Groups      Computers
        │           │            │
        └───────────┼────────────┘
                    │
                  ACLs
                    │
                   ACEs
                    │
        ┌───────────┼────────────┐
        ▼           ▼            ▼
   GenericAll   GenericWrite   WriteDACL
        │           │            │
        ▼           ▼            ▼
   More control  Attribute     Permission
                 changes         changes
        │           │            │
        └───────────┼────────────┘
                    ▼
              More privileges
                    │
                    ▼
           Lateral movement /
           Privilege escalation /
               Persistence
```

The uploaded module itself includes an ACL attack graphic showing relationships involving permissions such as `WriteDACL`, `WriteOwner`, `GenericWrite`, and group membership, with Windows/Linux tooling.

---

# 25. Important Terms to Memorize

|Term|Meaning|
|---|---|
|**ACL**|Overall list of access permissions|
|**ACE**|Individual permission entry inside an ACL|
|**DACL**|Defines allowed/denied access|
|**SACL**|Defines auditing of access attempts|
|**SID**|Security identifier for a security principal|
|**Access Mask**|32-bit value representing rights|
|**Inheritance**|Determines whether permissions propagate to child objects|
|**Security Principal**|User, group, or process associated with permissions|
|**GenericAll**|Full control over the target object|
|**GenericWrite**|Write access to non-protected attributes|
|**WriteDACL**|Ability to modify the target object's DACL|
|**WriteOwner**|Ability to modify object ownership|
|**ForceChangePassword**|Ability to reset a user's password without knowing the old password|
|**AddSelf**|Ability for a user to add themselves to a group|
|**AllExtendedRights**|Extended rights over an object|
|**BloodHound**|Tool for visualizing AD relationships|
|**PowerView**|PowerShell toolkit for AD enumeration/interaction|
|**gMSA**|Group Managed Service Account|
|**LAPS**|Local Administrator Password Solution|

---

# 26. High-Value Exam/Viva Questions

### Q1. What is an ACL?

An **Access Control List** defines who can access an object/resource and what level of access they have.

### Q2. What is an ACE?

An **Access Control Entry** is an individual permission entry within an ACL.

### Q3. What is the difference between DACL and SACL?

**DACL** controls whether access is allowed or denied, while **SACL** is used to audit/log access attempts.

### Q4. What are the three main ACE types?

1. Access denied ACE
    
2. Access allowed ACE
    
3. System audit ACE
    

### Q5. What are the four components of an ACE?

1. SID/security principal
    
2. ACE type
    
3. Inheritance flags
    
4. Access mask
    

### Q6. Why are ACLs important during AD penetration testing?

Misconfigured ACLs can provide unintended permissions that may enable lateral movement, privilege escalation, persistence, or potentially domain compromise.

### Q7. What is GenericAll?

It grants full control over the target object.

### Q8. What is GenericWrite?

It allows writing to non-protected attributes of an object.

### Q9. What is ForceChangePassword?

It allows a principal to reset another user's password without knowing the existing password.

### Q10. What is AddSelf?

It identifies groups where a user can add themselves.

### Q11. What tools are highlighted for ACL enumeration?

The module specifically mentions **BloodHound**, **PowerView**, and built-in AD management tools.

---

# 27. Pentester's Mental Model

When you encounter an ACL during an AD assessment, think:

```text
WHO?
 │
 └── Which user/group has the permission?
 
WHAT?
 │
 └── What object is controlled?
 
WHICH RIGHT?
 │
 └── GenericAll / GenericWrite / WriteDACL / etc.
 
IMPACT?
 │
 └── What can that permission actually change?
 
PATH?
 │
 └── Does it lead to another account, group, computer,
     privilege, or credential?
 
VALIDATION?
 │
 └── Can it be safely demonstrated in the authorized lab?
```

This is more useful than simply memorizing ACE names.

---

# 28. Important Lab Safety / Professional Practice

Some ACL attacks modify Active Directory objects and can therefore be **destructive**.

The module specifically warns that changing a user's password or making other AD modifications should be handled carefully. During a client assessment, testers should obtain appropriate authorization, document changes, and revert modifications.

### Professional workflow

```text
Authorization
     ↓
Enumeration
     ↓
Identify ACL weakness
     ↓
Assess impact
     ↓
Obtain approval if modification is destructive
     ↓
Perform controlled validation
     ↓
Document everything
     ↓
Revert changes
     ↓
Verify cleanup
```

---

# 29. Final Cheat Sheet

```text
ACL
│
├── DACL
│    ├── Allow ACE
│    └── Deny ACE
│
└── SACL
     └── Audit ACE
```

```text
ACE =

SID
+
ACE Type
+
Inheritance Flags
+
Access Mask
```

### Important permissions

```text
ForceChangePassword
        ↓
Reset password

GenericWrite
        ↓
Modify non-protected attributes

GenericAll
        ↓
Full control

WriteDACL
        ↓
Modify DACL

WriteOwner
        ↓
Modify ownership

AddSelf
        ↓
Add yourself to group

AllExtendedRights
        ↓
Extended object rights
```

### Main attack objectives

```text
ACL Abuse
   │
   ├── Lateral Movement
   ├── Privilege Escalation
   └── Persistence
```

### Core tools

```text
BloodHound → Discover/visualize AD relationships
PowerView  → Enumerate/interact with AD
ADUC       → Graphical AD management and ACL inspection
```

**Core takeaway:** In Active Directory, **ownership and group membership are not the only things that matter**. A seemingly low-privileged account can become highly valuable if it possesses an unexpected ACE over a sensitive user, group, computer, or other AD object. The key skill is learning to trace **principal → permission → target object → impact → attack path**.