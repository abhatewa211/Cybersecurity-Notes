

![Image](https://images.openai.com/static-rsc-3/xjX9aQRFwhpUKGWRuolzVxy71oXe8vFE26CeayIvQcDTWDuNrtgH-Bgag7f7ES3gguFCx1svlt7I4XFgGymRl0h8mKp17XSuGcn85HJ_v1I?purpose=fullsize&v=1)

![Image](https://cf-assets.www.cloudflare.com/slt3lc6tev37/5aYOr5erfyNBq20X5djTco/3c859532c91f25d961b2884bf521c1eb/tls-ssl-handshake.png)

![Image](https://pbs.twimg.com/media/F2iER3UWkAAW7Xa.jpg)

![Image](https://static.semrush.com/blog/uploads/media/e7/a1/e7a1b33235f6d87837b0f0bd5966c83b/cd52ac337f7949da4d9205b3d762acf9/QusW5uZaKZm9amx_80uLemrejiHJnIFllq2RMUOCfwgLpJ9phRYkiHGz1YOWDEGrAyBMalvmS0Bf_hBouksrdmftfDm__o4Gq2AK04xtF6zgENfA4C_fEFuPIJPCf7kXEFh5iTW05fA22hSdqe9b394.png)

---

# 1. Introduction to HTTPS

In the previous section, HTTP requests were discussed. However, **HTTP has a major security problem**:

**All data in HTTP is transferred in clear-text.**

This means:

- Anyone between the **client and server** can intercept traffic.
    
- Attackers can perform a **Man-in-the-Middle (MiTM) attack**.
    
- Sensitive information like **usernames, passwords, cookies, tokens, etc.** can be stolen.
    

### Example Problem with HTTP

If someone intercepts an HTTP request, they can see the **entire request in plaintext**.

Example HTTP login request:

```
POST /login.php HTTP/1.1
Host: example.com
username=admin
password=password
```

Anyone monitoring the network (e.g., on **public Wi-Fi**) could easily capture these credentials.

---

# 2. What is HTTPS?

**HTTPS (Hypertext Transfer Protocol Secure)** was created to solve the security problems of HTTP.

HTTPS works by **encrypting communication between the client and the server** using:

- **SSL (Secure Sockets Layer)** — older
    
- **TLS (Transport Layer Security)** — modern
    

### Key Idea

Instead of sending readable data like this:

```
username=admin&password=password
```

HTTPS sends encrypted data like:

```
16 03 01 02 00 01 00 01 FC 03 03 ...
```

Which appears as **random encrypted bytes** to anyone intercepting the traffic.

---

# 3. Why HTTPS is Important

HTTPS provides three critical security properties.

### 1️⃣ Encryption

Data is encrypted so attackers cannot read it.

Example protected data:

- Login credentials
    
- Payment information
    
- Cookies
    
- Session tokens
    

---

### 2️⃣ Integrity

Prevents attackers from **modifying data during transmission**.

Example attack prevented:

```
Original:
Transfer $10

Modified by attacker:
Transfer $1000
```

HTTPS ensures the message **cannot be altered without detection**.

---

### 3️⃣ Authentication

The server proves its identity using **SSL/TLS certificates**.

This prevents attackers from impersonating legitimate websites.

---

# 4. Identifying HTTPS Websites

Websites using HTTPS can be identified by:

### 1️⃣ URL Prefix

```
https://example.com
```

Instead of:

```
http://example.com
```

---

### 2️⃣ Lock Icon in Browser

Browsers display a **lock icon** in the address bar indicating:

- The connection is encrypted
    
- The certificate is valid
    

Example:

```
🔒 https://www.google.com
```

---

# 5. HTTP vs HTTPS Traffic

### HTTP Traffic

HTTP packets contain **readable data**.

Example captured in **Wireshark**:

```
POST /login.php HTTP/1.1
username=admin
password=password
```

Attackers can easily steal credentials.

---

### HTTPS Traffic

HTTPS packets appear as encrypted TLS data.

Example capture:

```
TLSv1.2 Encrypted Application Data
Source: 216.58.197.36
Destination: 192.168.0.108
Port: 443
```

All the application data becomes **encrypted binary data**.

---

# 6. HTTPS Flow (How It Works)

When visiting a secure website, the following process occurs.

---

## Step 1 — HTTP Request

User types:

```
http://example.com
```

The browser sends a request to:

```
Port 80 (HTTP)
```

---

## Step 2 — Server Redirect

The server forces HTTPS using a **301 redirect**.

```
HTTP/1.1 301 Moved Permanently
Location: https://example.com
```

The browser is redirected to:

```
Port 443 (HTTPS)
```

---

## Step 3 — TLS Handshake

The browser and server establish a secure connection.

### Client Hello

The browser sends information including:

- TLS version
    
- Supported cipher suites
    
- Random key
    

Example:

```
Client Hello
Supported TLS versions
Cipher suites
Random number
```

---

### Server Hello

The server responds with:

- Selected TLS version
    
- Selected cipher suite
    
- SSL/TLS certificate
    

Example:

```
Server Hello
Certificate
Public key
```

---

### Certificate Verification

The client verifies the server certificate by checking:

- Certificate Authority (CA)
    
- Expiration date
    
- Domain match
    

If the certificate is valid, communication continues.

---

### Key Exchange

Both sides establish a **shared encryption key**.

This key will encrypt the communication.

---

### Encrypted Communication Begins

After the handshake finishes:

- Normal **HTTP communication continues**
    
- But it is **fully encrypted with TLS**
    

---

# 7. Important Ports

|Protocol|Port|
|---|---|
|HTTP|80|
|HTTPS|443|

---

# 8. DNS and HTTPS

Even though HTTPS encrypts the **content**, the **DNS query may still be visible**.

Example DNS query:

```
What is the IP of google.com?
```

This request might still be sent in **plaintext DNS**.

This reveals:

- Which websites you visit.
    

---

### Recommended Solutions

Use **encrypted DNS**:

Examples:

|DNS Provider|IP|
|---|---|
|Google DNS|8.8.8.8|
|Cloudflare DNS|1.1.1.1|

Or use:

- **DNS over HTTPS (DoH)**
    
- **DNS over TLS (DoT)**
    
- **VPN**
    

---

# 9. HTTP Downgrade Attack

An attacker may attempt to downgrade HTTPS to HTTP.

This is called:

**HTTP Downgrade Attack**

Method:

1. Attacker performs **Man-in-the-Middle attack**
    
2. Forces the browser to use HTTP instead of HTTPS
    
3. Data becomes **plaintext again**
    

Example tool used in attacks:

- **SSLstrip**
    

---

### Modern Protection

Most browsers prevent downgrade attacks using:

- **HSTS (HTTP Strict Transport Security)**
    

HSTS forces browsers to **always use HTTPS**.

---

# 10. cURL and HTTPS

`cURL` automatically handles HTTPS communication.

It performs:

1. TLS handshake
    
2. Certificate verification
    
3. Encrypted communication
    

---

### Example HTTPS Request

```bash
curl https://inlanefreight.com
```

---

### SSL Certificate Error Example

If the certificate is invalid:

```bash
curl https://inlanefreight.com
```

Output:

```
curl: (60) SSL certificate problem: Invalid certificate chain
More details here: https://curl.haxx.se/docs/sslcerts.html
```

cURL refuses the connection to protect against **MITM attacks**.

---

# 11. Ignoring SSL Certificate Verification

When testing **local or lab servers**, certificates may be invalid.

To bypass SSL verification use:

```
-k
```

or

```
--insecure
```

Example:

```bash
curl -k https://www.inlanefreight.com
```

Response:

```html
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html>
<head>
...
```

The request succeeds even though the certificate is invalid.

⚠️ This should **only be used for testing**.

---

# 12. Key Takeaways (Important)

### HTTP Problems

- Data sent in plaintext
    
- Vulnerable to MiTM attacks
    
- Credentials can be stolen
    

---

### HTTPS Advantages

- Encrypts communication
    
- Prevents eavesdropping
    
- Protects sensitive data
    
- Authenticates servers
    

---

### Important Technologies

- TLS
    
- SSL Certificates
    
- HSTS
    
- DNS over HTTPS
    

---

### Important Commands

```
curl https://site.com
```

```
curl -k https://site.com
```

---

Exercises