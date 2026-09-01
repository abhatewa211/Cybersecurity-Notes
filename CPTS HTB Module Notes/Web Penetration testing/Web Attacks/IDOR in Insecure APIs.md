## 1. Overview

IDOR vulnerabilities are not limited to accessing files or resources. They can also exist in **function calls and APIs**.

Two major types:

- **IDOR Information Disclosure Vulnerabilities** → allow unauthorized users to **read** another user's information.
    
- **IDOR Insecure Function Calls** → allow unauthorized users to **perform actions** as another user.
    

### Possible Impact

An insecure API may allow an attacker to:

- Change another user's private information
    
- Reset another user's password
    
- Modify user accounts
    
- Create or delete users
    
- Change user roles
    
- Perform administrative actions
    
- Potentially take over the entire application
    

> **Important:** Information disclosure and insecure function calls can sometimes be chained together. Information obtained through one IDOR can provide the parameters needed to exploit another.

---

# 2. Identifying Insecure APIs

The example uses an **Employee Manager** web application.

The application contains an **Edit Profile** functionality where a user can modify:

- Full Name
    
- Email
    
- About Me
    

The page is:

```text
/profile/index.php
```

When the profile is updated, the request can be intercepted using **Burp Suite**.

The application sends a:

```text
PUT /profile/api.php/profile/1
```

### Why PUT?

Common API conventions:

|HTTP Method|Typical Purpose|
|---|---|
|`GET`|Retrieve information|
|`POST`|Create a resource|
|`PUT`|Update a resource|
|`DELETE`|Delete a resource|

Therefore, using `PUT` for updating a profile is expected.

---

## 3. Important JSON Parameters

The intercepted request contains:

```json
{
    "uid": 1,
    "uuid": "40f5888b67c748df7efba008e7c2f9d2",
    "role": "employee",
    "full_name": "Amy Lindon",
    "email": "a_lindon@employees.htb",
    "about": "A Release is like a boat. 80% of the holes plugged is not good enough."
}
```

The important parameters are:

```text
uid
uuid
role
```

The normal profile form only exposes:

```text
full_name
email
about
```

Therefore, `uid`, `uuid`, and `role` are **hidden parameters** being sent by the client.

---

# 4. Client-Side Authorization Problem

The application also appears to specify the user's role through the client-side request, such as:

```text
Cookie: role=employee
```

This is a potential security problem.

### Why?

If authorization information is controlled by the client, an attacker may attempt to modify it.

For example:

```text
role=employee
```

could potentially be changed to:

```text
role=admin
```

However, this only works if the **back-end fails to properly enforce authorization**.

> **Important:** Authorization must ultimately be enforced on the server side. Client-controlled values should never be trusted as proof of privileges.

---

# 5. Potential Attack Paths

Once we discover hidden API parameters, several possibilities should be considered:

### 1. Change `uid`

Change:

```json
"uid": 1
```

to:

```json
"uid": 2
```

Potential goal:

- Access another user's account
    
- Modify another user's information
    

### 2. Modify another user's details

Attempt to target another user's API endpoint and modify their:

- Name
    
- Email
    
- About
    
- Other profile information
    

### 3. Create or delete users

Try different HTTP methods such as:

```text
POST
DELETE
```

Potential impact:

- Create arbitrary accounts
    
- Delete existing accounts
    

### 4. Change the user's role

Attempt to modify:

```json
"role": "employee"
```

to a more privileged role such as:

```text
admin
administrator
```

If successful, this could result in **privilege escalation**.

---

# 6. Testing `uid`

First, change:

```json
"uid": 1
```

to:

```json
"uid": 2
```

The server responds:

```text
uid mismatch
```

### What does this tell us?

The API appears to compare:

```text
JSON uid
```

with:

```text
UID in API endpoint
```

For example:

```text
/profile/api.php/profile/1
```

must correspond to:

```json
"uid": 1
```

This indicates that the application has some **back-end validation**.

---

# 7. Testing Another User's Profile

Next, change the endpoint:

```text
/profile/api.php/profile/1
```

to:

```text
/profile/api.php/profile/2
```

and change:

```json
"uid": 1
```

to:

```json
"uid": 2
```

The server now responds:

```text
uuid mismatch
```

### Meaning

The application is also checking whether the supplied:

```text
uuid
```

matches the UUID associated with the targeted user.

Since we are still using our own UUID, the request fails.

This demonstrates another back-end access-control check.

---

# 8. Testing User Creation

The next test is changing the request method to:

```text
POST
```

and attempting to create a new user with a new `uid`.

The application responds:

```text
Creating new employees is for admins only
```

This indicates that the application is checking authorization before allowing employee creation.

---

# 9. Testing User Deletion

Similarly, sending a:

```text
DELETE
```

request results in:

```text
Deleting employees is for admins only
```

Therefore, normal employees cannot directly create or delete users.

---

# 10. Testing Role Manipulation

Another possibility is changing:

```json
"role": "employee"
```

to:

```json
"role": "admin"
```

or:

```json
"role": "administrator"
```

The application responds:

```text
Invalid role
```

Therefore, the guessed role name is not accepted.

At this stage:

- ❌ Cannot change `uid`
    
- ❌ Cannot modify another user's details
    
- ❌ Cannot create users
    
- ❌ Cannot delete users
    
- ❌ Cannot change to a guessed privileged role
    

It may initially appear that the application is secure against IDOR **function-call** attacks.

---

# 11. The Important Missing Test

The previous tests focused on:

> **IDOR Insecure Function Calls**

But there is another important category:

> **IDOR Information Disclosure**

The API should also be tested with:

```text
GET
```

requests.

### Why?

Even if the application prevents us from modifying another user's account, it may still allow us to **retrieve their information**.

For example:

```text
GET /profile/api.php/profile/2
```

could potentially return another employee's:

- UID
    
- UUID
    
- Name
    
- Email
    
- Role
    
- Other private information
    

if the back-end lacks proper access control.

---

# 12. Chaining IDOR Vulnerabilities

This is one of the most important concepts from this section.

An attacker may first exploit:

```text
IDOR Information Disclosure
```

to obtain information about another user.

That information can then potentially be used against:

```text
IDOR Insecure Function Calls
```

### Conceptual attack chain

```text
GET request
     ↓
Discover another user's information
     ↓
Obtain UID / UUID / other parameters
     ↓
Use information in API request
     ↓
Attempt unauthorized function
     ↓
Potential account modification / privilege escalation
```

Therefore:

> **A failed IDOR function-call test does not necessarily mean the API is secure.**

Information disclosure should always be tested separately.

---

# 13. Key Takeaways

### IDOR in APIs

- IDOR can affect **APIs and function calls**, not just files.
    
- `GET` requests can expose unauthorized information.
    
- `PUT`, `POST`, and `DELETE` requests may expose unauthorized functionality.
    
- Hidden parameters in JSON should be carefully examined.
    
- Client-controlled authorization values such as `role` are dangerous if trusted by the server.
    
- Back-end authorization must verify the user's identity and permissions.
    
- Testing only visible form fields is insufficient.
    
- API endpoints should be tested independently with different HTTP methods.
    
- **Information disclosure IDORs can be chained with insecure function-call IDORs.**
    

### Most Important Principle

> **Never rely on client-side controls for authorization. The back-end must verify that the authenticated user is authorized to access or modify the requested object.**