![Image](https://images.openai.com/static-rsc-4/eT9Vrh0Vh5ZTwj-QFspHyMHorRgPktsl_oOMzKgcp4L_EbI6ueGPgvdkP7vppZJNT_9_nqrIVVb_KBzz2lmBcRY9Q8mf7IS5frlA70cXux2UEfJjPyzAExptWZ8SQPN-Gk2MBYVwcfz4YWkhy0rLLi6tQ1ViGl1Pp3c_ZunoZK0zK_nmhu-kmpn74fSLBWyL?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/wFQGEgzCc1XM-abiqrfam968D5czXV_9YlSJm004kfwYmJyrx28tRaREgE3d7vYd3cYjZ1LdI-j1_VE21bm9_V5_m3M7wqMJkyHtdrLhB5AHVZWYX1d_w4Ji0gvfYbGydCdgBipB4iSR08DN-b5fizew4KrKw2WF99bP10SJ4zBokNoolzJ0G1SmwJapnXed?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/HMttYbCjGsQpZfGc2RPapw299FrO8MkVMcIncADZrDB1jWL_W4rQ-j6sW2qB3m4B-5tFo2FxFc0Gx-Lnvlwkpa0n_kpuvUlth6gJqra52h_6KbN03bxD6UMCjs00IuHDZHxTnE15TGOQRMJu2QoQuX6wLyN_LSjqQruUEP5z8dPjno-UkUq_vHBrDG5f6shW?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/J3NExPMoxGHOsLMgQ7K5pl_p3dtO9BorN5mk6mb4JL_NfuQuFvMnO_qwxUchWbFKQFtDZY4R0AKSwOJW3ZQlktF_dnZXEqTknvm9d0rGrzdRdf6r1ixjOJw8lYH2VVlVBYgOaV9YUVUtnsLnYBOLcgog8V1wJU6XT1TTf3jhULYRs42pVHd-klI1NaqARRYQ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/CF6cm7wTgLMOGZQ62nwEvMXzCSAToI2T5Jz2tckk7L3XasepR88-pdYLC9bTOkiA9Zx_0K2Z7eoJ9qRwNIWHwlHkpa0PbWaBZoJt9xpJNKDEPX5IObtSCKqxxxmLLe1DF6T9PdGMhKYA8jz8yIEUy2ZHujocw4zS3UPKRL9UzCbtDZDTQcHUq3cfEnb86cRn?purpose=fullsize)

# 1. Overview

The **first step in identifying an IDOR vulnerability is finding the Direct Object Reference (DOR).**

Remember:

> **A Direct Object Reference is an identifier that points to a specific object/resource.**

Examples:

```text
?uid=1
?file_id=123
?filename=file_1.pdf
/user/42
/document/9001
```

Finding such a reference **does not automatically mean IDOR exists**.

The real question is:

> **Can we manipulate the reference and access an object that the current user is not authorized to access?**

---

# 2. IDOR Identification Methodology

A useful workflow is:

```text
        Find a resource
              │
              ▼
       Inspect HTTP request
              │
              ▼
      Find object reference
              │
              ▼
      Modify the reference
              │
              ▼
     Send request again
              │
              ▼
    Compare the response
              │
       ┌──────┴──────┐
       ▼             ▼
  Unauthorized     Authorized
     object           object
       │
       ▼
 Potential IDOR
```

---

# 3. Where to Look for Direct Object References

Direct references are commonly found in:

### URL parameters

```text
download.php?file_id=123
```

### Path parameters

```text
/users/123
/files/456
```

### APIs

```json
{
  "user_id": 123
}
```

### Form parameters

```text
filename=file_123.pdf
```

### Cookies / HTTP headers

Some applications may place identifiers inside cookies or other HTTP headers.

For example:

```text
Cookie: user_id=123
```

Therefore:

> **Don't restrict IDOR testing to URLs. Inspect the entire request.**

---

# 4. URL Parameter Testing

Suppose the application provides:

```text
download.php?file_id=123
```

This tells us that:

```text
file_id
```

is likely being used to identify a particular file.

In an authorized lab/test environment, we can test whether changing the object reference changes the accessed resource.

For example:

```text
123 → 124
```

Conceptually:

```text
Original:
file_id=123
     ↓
Your file


Modified:
file_id=124
     ↓
Another resource?
```

If the application returns another user's resource without appropriate authorization, that's strong evidence of IDOR.

---

# 5. Sequential Object IDs

A common pattern is:

```text
1
2
3
4
5
...
```

or:

```text
file_1.pdf
file_2.pdf
file_3.pdf
```

This can make references easy to predict.

For example:

```text
?uid=1
?uid=2
?uid=3
```

However, remember:

> **Predictable IDs alone are not an IDOR vulnerability.**

The vulnerability requires **missing/weak authorization**.

### Important equation

```text
Predictable reference
        +
Missing authorization
        =
Potential IDOR
```

---

# 6. Fuzzing Object References

If object references follow a predictable pattern, authorized testers can use fuzzing to test many candidate references.

Conceptually:

```text
file_id=1
file_id=2
file_id=3
...
file_id=N
```

Then responses can be compared to identify valid resources.

![Image](https://images.openai.com/static-rsc-4/eT9Vrh0Vh5ZTwj-QFspHyMHorRgPktsl_oOMzKgcp4L_EbI6ueGPgvdkP7vppZJNT_9_nqrIVVb_KBzz2lmBcRY9Q8mf7IS5frlA70cXux2UEfJjPyzAExptWZ8SQPN-Gk2MBYVwcfz4YWkhy0rLLi6tQ1ViGl1Pp3c_ZunoZK0zK_nmhu-kmpn74fSLBWyL?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/xJELp4vuFXZgg5hUZemSP2Gqw7L3q1BYrjQVg4uhuZ2amfYwqt4KZ_5oMHZJI7YX1b-y3fDgoE4Io7vaw-0xPSJ75lHfLwFQPcoRdveCMEIoQNOWlE9tIyFOaIWbpx9Ht1LaXS52AVgqmIjk9HFpk4ywsqyks-V3iaGDbwU-S1-Xa315-P3RjWWbmdhqWmx5?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/wFQGEgzCc1XM-abiqrfam968D5czXV_9YlSJm004kfwYmJyrx28tRaREgE3d7vYd3cYjZ1LdI-j1_VE21bm9_V5_m3M7wqMJkyHtdrLhB5AHVZWYX1d_w4Ji0gvfYbGydCdgBipB4iSR08DN-b5fizew4KrKw2WF99bP10SJ4zBokNoolzJ0G1SmwJapnXed?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/-cdxhwYt_aJ1ITGjCNkgfOOnQ4oNMApOkWNXFKx4Cv-OpcUv7ac8VZeLsMuBsxmEyFx7r-z6B_PiLsn4hajtRGtn2c59L8WHwf360yBScThvi7ThfQ9wcvGGw0mhGDFlXuU1OXdVM5ASk7F3m9U9URBWP8uKTb-if0pSmfL0m9Kj9c2JBjIDUjKzoLBDU7JN?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Ye7OzH1ofwuP5QPCCmJjhe8WWI5Zh-hh8OINikyLw_60-Q4lFt2MZBVR0Ct5fKLdLqR2R6-1CKHHNOIZWeFuyBBHBBxz89Um_YTzaLkqvMd5CGjhY0LbZoGErpVzKLE1F6fHszEMLlVUGdsQLuIll93Be0mJzEa_tVai22v8boBN0vBr686p5pb0A_NKN2Rm?purpose=fullsize)

### ⚠️ Important

In a real assessment, fuzzing should be performed only against systems you are authorized to test and at a rate that won't disrupt the application.

The goal is not simply to find valid IDs.

The important question is:

> **Do any valid IDs return resources belonging to another user?**

---

# 7. AJAX Calls

Another major place to find IDORs is **front-end JavaScript**.

Modern applications frequently use:

```text
JavaScript
   ↓
AJAX request
   ↓
API endpoint
   ↓
Backend
```

Some functionality may never appear during normal interaction with the application.

This is especially important for:

- Admin functionality
    
- Hidden features
    
- Disabled UI elements
    
- User-management functions
    
- API endpoints
    
- Internal application functions
    

---

# 8. Why Front-End JavaScript Matters

Consider a normal user account.

The interface might show:

```text
Dashboard
Profile
My Files
Settings
```

but not:

```text
Admin Panel
Change User Password
Delete User
Change Role
```

A developer may simply disable those functions in the frontend.

However, the JavaScript may still contain the API calls.

For example:

```text
Frontend JavaScript
       │
       ├── User functions
       │
       └── Admin functions
```

The browser may simply avoid calling the admin function for a normal user.

That does **not** guarantee the backend will reject the request.

---

# 9. AJAX Example

The module provides:

```javascript
function changeUserPassword() {
    $.ajax({
        url:"change_password.php",
        type: "post",
        dataType: "json",
        data: {uid: user.uid, password: user.password, is_admin: is_admin},
        success:function(result){
            //
        }
    });
}
```

Let's identify the important pieces.

### Endpoint

```text
change_password.php
```

### HTTP method

```text
POST
```

### Parameters

```text
uid
password
is_admin
```

The particularly interesting parameter is:

```text
uid
```

because it identifies **which user** the operation applies to.

---

# 10. Why an Unused AJAX Function Matters

Suppose a normal user never calls:

```text
changeUserPassword()
```

during normal use.

A tester inspecting the JavaScript might still discover:

```text
change_password.php
```

and:

```text
uid
```

That gives us a potentially interesting endpoint to investigate.

The key question becomes:

> **Does the backend independently verify that the current user is allowed to change the target user's password?**

If it doesn't, this could represent an **IDOR Insecure Function Call** and potentially a serious privilege escalation issue.

---

# 11. Frontend Security ≠ Backend Security

This is one of the most important concepts in the entire IDOR section.

### ❌ Insecure

```text
Normal user
    │
    ▼
Frontend hides admin button
    │
    ▼
Backend accepts admin API anyway
```

The application is only **hiding** the functionality.

### ✅ Secure

```text
Normal user
    │
    ▼
Calls admin API directly
    │
    ▼
Backend authorization check
    │
    ▼
DENIED ❌
```

The backend must enforce authorization regardless of what the frontend displays.

---

# 12. Search JavaScript for Interesting References

When examining frontend code during an authorized assessment, look for:

```text
/api/
.php
/user/
uid=
user_id=
file_id=
document_id=
account_id=
```

Also look for function names related to:

```text
delete
update
change
download
view
edit
admin
role
password
```

These can reveal APIs or parameters that aren't obvious from normal application use.

---

# 13. Hashing and Encoding

Not every application uses:

```text
file_id=123
```

Some applications encode or hash object references.

For example:

```text
filename=ZmlsZV8xMjMucGRm
```

At first glance, this may appear difficult to understand.

But it could simply be:

```text
Base64
```

encoding.

---

# 14. Base64-Encoded References

Suppose we have:

```text
?filename=ZmlsZV8xMjMucGRm
```

The encoded value corresponds to:

```text
file_123.pdf
```

So the application is effectively doing:

```text
file_123.pdf
      │
      ▼
   Base64
      │
      ▼
ZmlsZV8xMjMucGRm
```

If another file is:

```text
file_124.pdf
```

its Base64 representation can similarly be calculated.

The important point is:

> **Encoding does not provide access control.**

---

# 15. Encoding ≠ Security

This is extremely important.

Developers sometimes assume:

```text
123
```

is insecure but:

```text
Encoded(123)
```

is secure.

That's incorrect.

Encoding is generally reversible.

Therefore:

```text
Direct ID
   ↓
Base64
   ↓
Still represents the same ID
```

If the backend doesn't perform authorization, encoding doesn't solve the IDOR.

### ⭐ Remember

> **Obscuring an object reference is not a replacement for authorization.**

---

# 16. Hashed References

Applications may also use hashes.

Example:

```text
download.php?filename=c81e728d9d4c2f636f067f89cc14862c
```

This doesn't immediately look like:

```text
file_123.pdf
```

because it is a hash-like value.

At first glance, it might appear much more secure.

But the key question is:

> **How was the hash generated?**

---

# 17. Inspecting Front-End Code

Suppose the JavaScript contains:

```javascript
$.ajax({
    url:"download.php",
    type: "post",
    dataType: "json",
    data: {filename: CryptoJS.MD5('file_1.pdf').toString()},
    success:function(result){
        //
    }
});
```

Now we know:

```text
file_1.pdf
      │
      ▼
    MD5
      │
      ▼
Hash
      │
      ▼
download.php
```

Therefore, if the application simply uses a deterministic hash of the filename as the object reference, a tester may be able to calculate the corresponding reference for another known test file.

---

# 18. Hashing Does Not Automatically Prevent IDOR

This is another major lesson.

```text
Sequential ID
     ↓
123
```

might be easy to recognize.

But:

```text
Hash(123)
     ↓
c81e...
```

only changes the representation.

If the backend says:

```text
"Valid hash = access resource"
```

without checking authorization, the application may still be vulnerable.

### The real security control is:

```text
Object reference
      +
Backend authorization
```

not:

```text
Object reference
      +
Obfuscation
```

---

# 19. How to Identify the Hashing Method

If source code isn't available, a tester may attempt to determine the algorithm from:

- Hash length
    
- Character set
    
- Application source
    
- Frontend JavaScript
    
- Documentation
    
- Known values
    
- Appropriate hash-identification tools
    

For example, MD5 hashes are commonly represented as 32 hexadecimal characters.

But:

> **Hash identification alone doesn't prove an IDOR.**

The objective is to understand how the application generates the reference and then determine whether access control is properly enforced.

---

# 20. Compare User Roles

For more advanced IDOR testing, using multiple authorized test accounts can be extremely useful.

For example:

```text
User 1
User 2
```

Each account has its own resources.

You can compare their requests.

---

# 21. Why Multiple Accounts Help

Suppose User 1 makes:

```text
GET /services/data/salaries/users/1
```

and receives salary information.

User 2 should not be able to access User 1's information.

A tester can then determine whether the backend properly enforces that distinction.

Conceptually:

```text
User 1
  │
  ▼
/salaries/users/1
  │
  ▼
Allowed ✓


User 2
  │
  ▼
/salaries/users/1
  │
  ▼
Should be denied ❌
```

If User 2 receives User 1's information, that's strong evidence of broken object-level authorization.

---

# 22. Module Example

The API response for User 1 contains:

```json
{
  "attributes": {
    "type": "salary",
    "url": "/services/data/salaries/users/1"
  },
  "Id": "1",
  "Name": "User1"
}
```

Several interesting pieces appear here:

```text
type
url
Id
Name
```

The URL contains:

```text
/users/1
```

This is a direct reference to User 1's salary resource.

---

# 23. Cross-User Testing

Now imagine User 2 is logged in.

The tester can determine whether User 2 can access:

```text
/services/data/salaries/users/1
```

If the backend only checks:

```text
"Is this a logged-in user?"
```

instead of:

```text
"Is this user authorized to access User 1's salary?"
```

then the application may be vulnerable.

---

# 24. Authentication vs Authorization Again

This example demonstrates the distinction perfectly.

### Authentication check

```text
Is User 2 logged in?
       │
       ▼
YES ✓
```

### Authorization check

```text
Is User 2 allowed to access User 1's salary?
       │
       ▼
NO ❌
```

A vulnerable application might perform only the first check.

```text
Logged in ✓
Authorization ❌
      ↓
IDOR
```

---

# 25. Even If You Can't Calculate Other IDs...

An interesting point from the module:

Suppose you discover an API reference, but you can't figure out how to generate references for other users.

You may still have discovered something valuable:

> **The backend access-control system deserves further investigation.**

For example:

```text
Known object reference
        ↓
Cross-user request
        ↓
Unexpected response
        ↓
Evidence of weak authorization
```

You can then look for other object references that are easier to manipulate.

---

# 26. Complete IDOR Identification Workflow

![Image](https://images.openai.com/static-rsc-4/rpWH5icq9MeFGxQbdYPk8RyKeE-hADVuT_NRAQsByxMJoz3Rku0dF4rKZ2MEcYeaMK3H2oVZn6bvdVHzwFWL4dRaZVCjSzcdjQ6H2ptBjwrrFg7YZLNDSDjNODU6MVGLxM49H6bAK0aN_l-qnrwtrmQfr48e-zlABv0K17sWFLhKriXSKCTEvuIQ7GZQJy6z?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/CF6cm7wTgLMOGZQ62nwEvMXzCSAToI2T5Jz2tckk7L3XasepR88-pdYLC9bTOkiA9Zx_0K2Z7eoJ9qRwNIWHwlHkpa0PbWaBZoJt9xpJNKDEPX5IObtSCKqxxxmLLe1DF6T9PdGMhKYA8jz8yIEUy2ZHujocw4zS3UPKRL9UzCbtDZDTQcHUq3cfEnb86cRn?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/6lwKwf3MFl5PObSTlVP7tfSbPc9emtgJDo0V8-zRUy4qttfmdJRkrwKnG0ItZ7OBP6i16-iz0j8tbD8qzz5T7C20N8MDOGkpNK4O_RzHkVeuSv85v_Xd8JNGQkkM8P47m3aKrfRlMIY6yJ-AzYmGbQa_uBbv6Kl2hD8YBTIs3Liqnb3hfy6r8oXHD4g_q5st?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Ymm4uMdxaWaCp_P2v7Z_QVonB8qrUyjYKaJ9c-LSdiQfkwHp9WNYuCvBGyP63lFcjhKpFXDvYKmd7vtKl2_SAk3LW3DhheLpleEjP6NVc5PnTdOIJCo-NzCaebqlgeNBK24ckMw_eCLBuLYdJhusHrBY1yEK0PWu71W8Exy4ZsAQPa7WN2nE2XGrh5LU313q?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/HlizUR0Z5oWCgvO0lABPgmRfYHyMSUtpou5CIu_vD1sPfVGt3qz7YQ7Y5MKa1D2Npdf1hCbaZbR-03t7o8prhSL4L4CXRGHfLvDObhOLQVrwXR0LxoWQLKamqEiX0hFXJm0iZNuBj8ezRxWETOqvaURopgQJMbgFqycOqahD6kipOkFWLFAQyOUU7FuLDGyh?purpose=fullsize)

```text
                 START
                   │
                   ▼
          Find interesting resource
                   │
                   ▼
          Inspect HTTP requests
                   │
        ┌──────────┼───────────┐
        ▼          ▼           ▼
      URLs        APIs       Headers
        │          │           │
        └──────────┼───────────┘
                   ▼
          Find object reference
                   │
                   ▼
        Is it encoded/hashed?
             │           │
            YES          NO
             │           │
             ▼           │
       Understand        │
       transformation   │
             │           │
             └─────┬─────┘
                   ▼
          Compare test users
                   │
                   ▼
       Modify object reference
                   │
                   ▼
         Send authorized test
              request
                   │
                   ▼
       Does another user's
       object become accessible?
             │           │
            YES          NO
             │           │
             ▼           ▼
         Potential     Continue
           IDOR        testing
```

---

# 27. What to Look For

### 🔍 URLs

Look for:

```text
?id=
?uid=
?user_id=
?file_id=
?document_id=
?account_id=
?filename=
```

### 🔍 API requests

Look for:

```json
{
  "id": 123
}
```

or:

```json
{
  "user_id": 42
}
```

### 🔍 JavaScript

Look for:

```text
AJAX
fetch()
XMLHttpRequest
API endpoints
hidden functions
admin functions
```

### 🔍 Cookies / headers

Look for identifiers such as:

```text
user_id
account_id
document_id
```

### 🔍 Encoded values

Consider:

```text
Base64
URL encoding
Hex
```

### 🔍 Hashed values

Investigate:

```text
MD5
SHA-family hashes
other deterministic transformations
```

---

# 🧠 28. Important Distinctions

|Observation|Is it automatically IDOR?|
|---|---|
|URL contains `id=123`|❌ No|
|ID is sequential|❌ No|
|ID is Base64 encoded|❌ No|
|ID is hashed|❌ No|
|Hidden API exists|❌ No|
|Different user can access another user's object|✅ Potential IDOR|
|Different user can modify another user's object|🔴 Serious IDOR|
|Normal user can invoke unauthorized admin function|🔴 Potential privilege escalation|

---

# 🎯 29. Practical Mental Checklist

Whenever you encounter an object reference, ask:

```text
┌─────────────────────────────────────┐
│ 1. What object does this reference? │
└──────────────────┬──────────────────┘
                   ▼
┌─────────────────────────────────────┐
│ 2. Can the reference be changed?    │
└──────────────────┬──────────────────┘
                   ▼
┌─────────────────────────────────────┐
│ 3. Is it encoded or hashed?         │
└──────────────────┬──────────────────┘
                   ▼
┌─────────────────────────────────────┐
│ 4. Can I compare two test accounts? │
└──────────────────┬──────────────────┘
                   ▼
┌─────────────────────────────────────┐
│ 5. Does backend check ownership?   │
└──────────────────┬──────────────────┘
                   ▼
┌─────────────────────────────────────┐
│ 6. Can unauthorized data/action     │
│    be accessed?                     │
└─────────────────────────────────────┘
```

---

# 🔥 30. Golden Rules

### Rule 1

> **Always inspect HTTP requests when receiving or manipulating resources.**

### Rule 2

> **Look beyond URLs — check APIs, JavaScript, cookies, and headers.**

### Rule 3

> **Sequential IDs are worth investigating, but they aren't automatically vulnerable.**

### Rule 4

> **Encoding is not authorization.**

### Rule 5

> **Hashing is not authorization.**

### Rule 6

> **Frontend restrictions are not backend authorization.**

### Rule 7

> **Use multiple authorized test accounts to compare access where possible.**

### Rule 8

> **The key test is whether one user can access or manipulate another user's resource without authorization.**

---

# 📌 One-Page Revision

```text
                 IDOR IDENTIFICATION
                         │
                         ▼
             Find Direct References
                         │
       ┌─────────────────┼─────────────────┐
       ▼                 ▼                 ▼
      URL               API          JavaScript
       │                 │                 │
       └─────────────────┼─────────────────┘
                         ▼
                Object Reference
                         │
                         ▼
             Sequential / Encoded /
                    Hashed?
                         │
                         ▼
               Understand Reference
                         │
                         ▼
                Compare Test Users
                         │
                         ▼
               Modify Reference
                         │
                         ▼
             Check Backend Response
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
       Unauthorized object      Proper denial
              │                     │
              ▼                     ▼
        Potential IDOR          Continue testing
```

## ⭐ Final Takeaway

**Finding the ID is only step one.**

The complete IDOR thought process is:

> **Find the object reference → understand how it is generated → compare requests between authorized test users → manipulate the reference → determine whether the backend independently verifies authorization.**

And remember the most important point from the entire topic:

**`123`, Base64, MD5, random-looking IDs, URLs, APIs, and hidden JavaScript are merely ways of identifying an object. None of them replace backend authorization.**