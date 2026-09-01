## 1. Overview

IDOR vulnerabilities can sometimes be **chained together** to bypass multiple access-control mechanisms.

In this scenario, two vulnerabilities are combined:

1. **IDOR Information Disclosure** → retrieve another user's details.
    
2. **IDOR Insecure Function Calls** → use the leaked information to modify another user's account or perform privileged actions.
    

### Core Attack Chain

```text
IDOR Information Disclosure
          ↓
Retrieve another user's UID / UUID / Role
          ↓
Use leaked UUID in API request
          ↓
Modify another user's details
          ↓
Discover privileged role
          ↓
Assign privileged role to attacker
          ↓
Perform administrative actions
```

> **Important:** Information obtained through one vulnerability can provide the missing information needed to exploit another vulnerability.

---

# 2. Testing the API with GET

A `GET` request to the API should normally return the details of the requested user.

The application itself uses a `GET` request after the profile page loads to retrieve user information.

The request contains:

```text
Cookie: role=employee
```

Interestingly, there is no other obvious user-specific authorization mechanism in the request, such as a JWT.

Even if a token were present, it would not necessarily prevent IDOR if the server failed to compare the authenticated user against the requested object's ownership.

### Key Point

Authentication and authorization are different:

```text
Authentication → Who are you?
Authorization  → Are you allowed to access this object?
```

A valid authenticated session does **not** automatically mean the user should be allowed to access every object.

---

# 3. IDOR Information Disclosure

Try requesting another user's information by changing the `uid`.

For example:

```text
GET /profile/api.php/profile/2
```

The API returns another user's information:

```json
{
    "uid": "2",
    "uuid": "4a9bd19b3b8676199592a346051f950c",
    "role": "employee",
    "full_name": "Iona Franklyn",
    "email": "i_franklyn@employees.htb",
    "about": "It takes 20 years to build a reputation and few minutes of cyber-incident to ruin it."
}
```

This confirms:

> **IDOR Information Disclosure Vulnerability**

The attacker can retrieve information belonging to another user.

---

## 4. Why the UUID Is Important

Previously, attempts to modify another user's profile failed because the correct `uuid` was unknown.

The server returned:

```text
uuid mismatch
```

Now, the GET request has disclosed the victim's UUID:

```text
4a9bd19b3b8676199592a346051f950c
```

Therefore, information disclosure has provided the missing parameter required for the next attack.

This demonstrates the importance of **chaining vulnerabilities**.

---

# 5. Modifying Another User's Details

With the victim's:

```text
uid
uuid
```

we can send a `PUT` request to the corresponding API endpoint:

```text
/profile/api.php/profile/2
```

with the correct UUID and modified profile information.

Conceptually:

```json
{
    "uid": 2,
    "uuid": "4a9bd19b3b8676199592a346051f950c",
    "role": "employee",
    "full_name": "Modified Name",
    "email": "modified@example.com",
    "about": "Modified information"
}
```

This time, the server does not return an access-control error.

A subsequent `GET` request confirms that the victim's details have been changed.

Therefore:

> The application has an **IDOR Insecure Function Call** vulnerability in addition to the information-disclosure IDOR.

---

# 6. Impact of Modifying User Details

Being able to modify another user's profile can lead to additional attacks.

### A. Account Takeover Through Email Modification

An attacker may be able to:

```text
Change victim's email
        ↓
Request password reset
        ↓
Reset link goes to attacker's email
        ↓
Potential account takeover
```

This is particularly dangerous because the IDOR becomes a stepping stone toward account compromise.

---

### B. Stored XSS

An attacker may place an XSS payload in a field such as:

```text
about
```

If that value is later displayed without proper output encoding, the payload may execute when the victim views their profile.

Conceptually:

```text
IDOR
 ↓
Modify victim's profile
 ↓
Insert malicious content
 ↓
Victim views profile
 ↓
Potential XSS execution
```

> **Important:** The danger of an IDOR is not limited to the immediate action it permits. Its real impact depends on what can be chained afterward.

---

# 7. Enumerating Users

Once the GET endpoint is confirmed vulnerable, we can enumerate different user IDs.

Conceptually:

```text
/profile/api.php/profile/1
/profile/api.php/profile/2
/profile/api.php/profile/3
/profile/api.php/profile/4
...
```

The goal is to identify:

- Valid user IDs
    
- UUIDs
    
- Roles
    
- Names
    
- Email addresses
    
- Other sensitive information
    

The leaked information may then be used in further attacks.

---

# 8. Discovering an Administrative Role

During enumeration, an administrator account is eventually discovered:

```json
{
    "uid": "X",
    "uuid": "a36fa9e66e85f2dd6f5e13cad45248ae",
    "role": "web_admin",
    "full_name": "administrator",
    "email": "webadmin@employees.htb",
    "about": "HTB{FLAG}"
}
```

The important discovery is:

```text
role = web_admin
```

Previously, attempts to change the role failed because the correct privileged role name was unknown.

Now the role name has been obtained through the IDOR Information Disclosure vulnerability.

---

# 9. Privilege Escalation Through Role Manipulation

The attacker can attempt to modify their own profile and change:

```json
"role": "employee"
```

to:

```json
"role": "web_admin"
```

The server accepts the change.

A subsequent GET request shows:

```json
{
    "uid": "1",
    "uuid": "40f5888b67c748df7efba008e7c2f9d2",
    "role": "web_admin",
    "full_name": "Amy Lindon",
    "email": "a_lindon@employees.htb",
    "about": "A Release is like a boat. 80% of the holes plugged is not good enough."
}
```

This proves that the application does **not properly enforce which roles a user is allowed to assign to themselves**.

---

# 10. Updating the Authorization Cookie

After changing the role, the application can update the user's cookie after refreshing the page.

The request may then contain:

```text
Cookie: role=web_admin
```

The application now treats the attacker as a web administrator.

This demonstrates a serious design flaw:

> **The server is trusting a client-controlled role value instead of independently determining the user's privileges.**

---

# 11. Creating New Users

Previously, attempting to create a user resulted in:

```text
Creating new employees is for admins only
```

After obtaining the `web_admin` role, the same operation succeeds.

A `POST` request can therefore be used to create a new employee.

A subsequent GET request confirms that the new account exists.

---

# 12. Deleting Users

The same privilege escalation can potentially be used for administrative operations such as:

```text
DELETE /profile/api.php/profile/<uid>
```

Because the attacker now possesses the privileged role, the previous:

```text
Deleting employees is for admins only
```

restriction can potentially be bypassed.

---

# 13. Complete Vulnerability Chain

The entire attack can be represented as:

```text
                    ┌──────────────────────┐
                    │ IDOR Information     │
                    │ Disclosure           │
                    └──────────┬───────────┘
                               │
                               ▼
                     Obtain victim UUID
                               │
                               ▼
                    ┌──────────────────────┐
                    │ IDOR Insecure        │
                    │ Function Call        │
                    └──────────┬───────────┘
                               │
                               ▼
                   Modify another user's data
                               │
                               ▼
                     Enumerate all users
                               │
                               ▼
                     Discover web_admin
                               │
                               ▼
                    Change own role to
                       "web_admin"
                               │
                               ▼
                    Administrative access
                               │
                    ┌──────────┴──────────┐
                    ▼                     ▼
               Create users          Delete users
```

---

# 14. Mass Assignment

Once the attacker has elevated privileges, they may potentially perform **mass assignments**.

For example, changing a particular field for many users:

```text
User 1 → modified
User 2 → modified
User 3 → modified
User 4 → modified
...
```

Potential targets include:

- Email addresses
    
- Profile information
    
- Other modifiable fields
    

The module specifically demonstrates that the attacker could retrieve users' UUIDs and then send `PUT` requests to modify their email addresses.

---

# 15. Key Takeaways

### IDOR Information Disclosure

Allows an attacker to retrieve information belonging to another user.

```text
GET → Unauthorized user data
```

### IDOR Insecure Function Calls

Allows an attacker to perform actions they should not be allowed to perform.

```text
PUT / POST / DELETE → Unauthorized action
```

### Chaining

The most important concept is that vulnerabilities can work together:

```text
Information Disclosure
        +
Insecure Function Call
        ↓
More powerful attack
```

### Critical Security Lessons

- APIs must perform **server-side authorization** for every requested object.
    
- Never trust client-controlled role values.
    
- Knowing a valid UID or UUID must not grant access to another user's data.
    
- Sensitive API endpoints should verify ownership and privileges.
    
- `GET` endpoints must be tested separately from `PUT`, `POST`, and `DELETE`.
    
- Information disclosure can reveal the exact parameters needed for further attacks.
    
- A vulnerability that appears low-impact by itself can become critical when **chained with another vulnerability**.
    
- Client-side restrictions are not security controls; the **back-end must enforce authorization**.