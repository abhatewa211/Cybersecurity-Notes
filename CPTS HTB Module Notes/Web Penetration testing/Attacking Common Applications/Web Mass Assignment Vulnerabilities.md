# 1. What is Mass Assignment?

Many web frameworks provide **mass-assignment** functionality to make development easier.

Instead of assigning every field individually:

```text
username = input.username
email    = input.email
```

an application can take a whole set of submitted parameters and assign them to an object/database model.

The problem occurs when the application accepts **more fields than the user is supposed to control**.

### Vulnerable concept

```text
User input
    │
    ▼
HTTP parameters
    │
    ▼
Mass assignment
    │
    ▼
Application object
    │
    ▼
Database
```

If sensitive attributes aren't protected:

```text
username
email
admin
confirmed
role
approved
```

the attacker may be able to submit:

```text
admin=true
```

even though the normal interface never displays an `admin` field.

---

# 2. Why Mass Assignment Happens

The basic problem is:

> **The application trusts client-controlled parameters when assigning model attributes.**

The developer expects:

```text
username
email
```

but the attacker sends:

```text
username
email
admin
```

If `admin` is accepted by the backend, the attacker may alter functionality or privileges.

---

# 3. Ruby on Rails Example

The module gives this example:

```ruby
class User < ActiveRecord::Base
  attr_accessible :username, :email
end
```

The intention is that:

```text
username
email
```

are the fields that can be mass-assigned.

But the attacker submits:

```javascript
{ "user" => { "username" => "hacker", "email" => "hacker@example.com", "admin" => true } }
```

The important idea is that **the attacker is adding an unexpected parameter to the HTTP request**.

### CPTS mental model

Never assume:

> "The form doesn't have an `admin` field, so the user can't submit `admin`."

The browser is only a client.

An attacker can construct the HTTP request manually.

---

# 4. The Real Asset Manager Scenario

The module then demonstrates a practical application.

After registration:

```text
Success!!
```

the user attempts to log in but receives:

```text
Account is pending approval
```

Normally, an administrator would have to approve the account.

The interesting part is the source code.

---

# 5. Understanding the Login Logic

The application contains:

```python
for i,j,k in cur.execute('select * from users where username=? and password=?',(username,password)):
  if k:
    session['user']=i
    return redirect("/home",code=302)
  else:
    return render_template('login.html',value='Account is pending for approval')
```

There are three database values:

```text
i → user information/identifier
j → password
k → confirmation/approval state
```

The important check is:

```python
if k:
```

If `k` evaluates as true:

```text
Login allowed
```

Otherwise:

```text
Account is pending
```

So the next question becomes:

> **Can we control the value that becomes `k` during registration?**

---

# 6. Finding the Mass Assignment Bug

The registration code contains:

```python
try:
  if request.form['confirmed']:
    cond=True
except:
  cond=False
```

This is the critical logic.

If the request contains:

```text
confirmed
```

then:

```python
cond=True
```

Otherwise:

```python
cond=False
```

The value is then inserted into the database:

```python
cur.execute('insert into users values(?,?,?)',(username,password,cond))
```

So the flow becomes:

```text
HTTP POST
   │
   ├── username
   ├── password
   └── confirmed
          │
          ▼
     cond = True
          │
          ▼
       Database
          │
          ▼
    confirmed = True
          │
          ▼
       Login
          │
          ▼
      k = True
          │
          ▼
    Access granted
```

---

# 7. The Vulnerable Parameter

The normal registration form probably only exposes:

```text
username
password
```

But the backend accepts:

```text
confirmed
```

That's the key vulnerability.

The attacker doesn't need the UI to expose the field.

They can add it directly to the HTTP request.

---

# 8. Exploitation with Burp Suite

Capture the registration request in **Burp Suite**.

The module modifies the request parameters to:

```text
username=new&password=test&confirmed=test
```

The important addition is:

```text
confirmed=test
```

The exact value isn't important here; the application only checks whether the parameter exists/truthily evaluates.

Because:

```python
if request.form['confirmed']:
    cond=True
```

the application stores the new account as confirmed.

---

# 9. Login

Now use:

```text
username: new
password: test
```

Instead of:

```text
Account is pending approval
```

the account is treated as approved.

The module confirms that the mass-assignment vulnerability is successfully exploited and the attacker can log in without waiting for administrator approval.

---

# 🔥 Complete Attack Chain

```text
        Registration Page
               │
               ▼
       Normal parameters
       username + password
               │
               │ attacker adds
               ▼
          confirmed=test
               │
               ▼
       request.form['confirmed']
               │
               ▼
            cond=True
               │
               ▼
       Insert into database
               │
               ▼
       confirmed/approval = True
               │
               ▼
          Login attempt
               │
               ▼
             k=True
               │
               ▼
          /home access
```

---

# 10. Why Source Code Review Is Powerful

This example demonstrates why source-code access can dramatically simplify a pentest.

Without source:

```text
Registration
     ↓
Account pending
     ↓
What can I manipulate?
```

With source:

```text
Registration
     ↓
request.form['confirmed']
     ↓
cond=True
     ↓
Database
     ↓
Login checks k
     ↓
Approval bypass
```

The code exposes the exact relationship between the HTTP parameter and the security-sensitive database value.

---

# 11. Mass Assignment vs Parameter Tampering

They're related, but don't confuse the concepts.

### Parameter tampering

An attacker modifies an existing parameter:

```text
role=user
```

to:

```text
role=admin
```

### Mass assignment

The application automatically maps a collection of client-controlled parameters to model/object attributes, allowing an attacker to supply **unexpected attributes**.

Example:

```text
Expected:
username
email

Attacker adds:
admin=true
```

### Easy distinction

```text
Parameter tampering
    = modify parameter values

Mass assignment
    = exploit automatic assignment of parameters
      to sensitive model attributes
```

---

# 12. High-Value Attributes to Look For

During a source-code review, pay special attention to attributes such as:

```text
admin
is_admin
role
confirmed
approved
verified
active
status
privilege
permissions
user_type
```

The exact names depend on the application.

The important question is:

> **Can a client-controlled parameter modify a security-sensitive attribute?**

---

# 13. What to Look for in Source Code

Search for patterns where request parameters are passed directly into models/objects.

Conceptually:

```text
request parameters
       ↓
model/object constructor
       ↓
database
```

Potentially dangerous behavior:

```text
User.new(all_request_parameters)
```

or similar framework-specific automatic mapping.

Then identify:

```text
Which fields are accepted?
Which fields are security-sensitive?
Are they explicitly whitelisted?
```

---

# 14. Prevention

The module recommends two major approaches:

### 1. Explicitly assign allowed attributes

Only copy the fields the user is actually allowed to modify.

### 2. Use framework whitelisting

Explicitly permit safe fields.

This creates:

```text
HTTP request
     │
     ▼
Parameter filtering
     │
     ├── username ✅
     ├── email ✅
     └── admin ❌
             │
             ▼
          ignored
```

---

# 15. Ruby on Rails Strong Parameters

The module provides:

```ruby
class UsersController < ApplicationController
  def create
    @user = User.new(user_params)
    if @user.save
      redirect_to @user
    else
      render 'new'
    end
  end

  private

  def user_params
    params.require(:user).permit(:username, :email)
  end
end
```

The important part is:

```ruby
params.require(:user).permit(:username, :email)
```

Only:

```text
username
email
```

are permitted.

If the attacker submits:

```text
username=hacker
email=hacker@example.com
admin=true
```

the application should only use:

```text
username
email
```

and ignore the unexpected `admin` attribute.

---

# 16. Secure vs Vulnerable Flow

### ❌ Vulnerable

```text
User
 │
 │ username
 │ email
 │ admin=true
 ▼
Mass assignment
 │
 ▼
User object
 │
 ▼
admin=True
```

### ✅ Secure

```text
User
 │
 │ username
 │ email
 │ admin=true
 ▼
Whitelist
 │
 ├── username ✅
 ├── email ✅
 └── admin ❌
 │
 ▼
User object
```

---

# 🧠 CPTS Exam Points

### ⭐ Mass Assignment

A vulnerability where attackers can manipulate **model attributes through parameters sent to the server**.

### ⭐ Root cause

The application accepts user-controlled parameters and automatically assigns them to model/object attributes without properly restricting sensitive fields.

### ⭐ Important attack idea

**The field doesn't need to exist in the HTML form.**

The attacker can manually add it to the HTTP request.

### ⭐ Security-sensitive fields

Remember examples:

```text
admin
role
confirmed
approved
verified
permissions
```

### ⭐ Burp Suite

Useful for intercepting and modifying HTTP requests.

Example from the module:

```text
username=new&password=test&confirmed=test
```

### ⭐ Source-code clue

Look for:

```text
request parameters
       ↓
automatic object/model assignment
```

### ⭐ Prevention

Use:

```text
Explicit assignment
+
Whitelisting
+
Strong parameters
```

---

# 🔎 Pentesting Checklist

```text
[ ] Identify registration/profile/update functionality
[ ] Capture requests with Burp Suite
[ ] Inspect all submitted parameters
[ ] Review source code if available
[ ] Identify model/object attributes
[ ] Look for security-sensitive attributes
[ ] Check whether unexpected parameters are accepted
[ ] Test whether sensitive attributes can be modified
[ ] Determine whether the modification changes authorization
[ ] Document the resulting impact
```

---

# ⚡ Quick Revision

```text
MASS ASSIGNMENT
│
├── Framework convenience feature
│
├── User submits parameters
│
├── Application automatically assigns them
│   to an object/model
│
├── Vulnerability occurs when sensitive
│   attributes aren't protected
│
├── Common targets
│   ├── admin
│   ├── role
│   ├── confirmed
│   ├── approved
│   └── permissions
│
├── Testing
│   ├── Source-code review
│   └── Burp Suite parameter manipulation
│
└── Prevention
    ├── Explicit assignment
    ├── Attribute whitelisting
    └── Strong parameters
```

## 🔥 Golden Mental Model

> **Mass assignment = "I wasn't supposed to be able to set this field, but the backend automatically trusted the parameter I sent."**

The most important CPTS workflow is:

```text
Find interesting functionality
        ↓
Capture HTTP request
        ↓
Understand backend parameter handling
        ↓
Find sensitive model attribute
        ↓
Add/modify that parameter
        ↓
Check whether authorization/functionality changes
        ↓
Prove impact
        ↓
Recommend strict allowlisting
```