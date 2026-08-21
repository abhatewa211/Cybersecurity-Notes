![Image](https://images.openai.com/static-rsc-4/CZbNi45G8TXyTwyrDyt6ikvp8EZbbEJMdSzzjbhcM6Buj9PXw1SLctG3Cf_m6tAqjFVPmVp_8GqXBVdHfE6reSrBuB56ILQV54UXLUU-LVzKR2TA193WOsYe_5np-cBi7ZR94Z_g9KCp38tLzA7Q6_P9jR3X42Cne6GAV0AZoXhqSwqU04W5S4fX2D9mUz77?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/yv97vP9nf38a2iBhylaaXgRVrV-0OibIqsg1k317AOkRiwWN77GoRImvSyYw7Kl2S-rwHsd-wKRmxf74VOJ5YFMKtEpQmqzAWiXeqR5175QcI_PkadcyUAXIqlwnEeRSOhIh9MhmXB8PckHjiw8GO26WwK3xh3p2FI9khZmddYrlVjQXt8xikBcUfzHar5Z2?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/lNiQ1Ui7Oue59NkfTKKl6yQP3OKw6nSclotaB5IgVDt0y8pLJ-CDKCx7Iozb5F3ly8ho9mnWYE8LtwhFOoboS9wSdgGrJqOq9StfHKzqgeAJndjep6sKNe8uuErw_4GqSihxZ-bD3jN87W3owJsjM6WgyeXC5Cq5e7tuNpoQTFSnlEc2krNA7BdHfY-pdNdK?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/V30yF6nzC-e2w-QMRlSSleZokxpUUl2bNQMHkd3FhOIgxIEth8vz-vAV9FjUZVvJcZaNP0MnzXEt00Wll1YHGa2VXmCm6-ZD5GrwSVOOdjCtUA4zoHYjcbgwArRbqsf9z-lJ7nV1sNUTutK8dtzD7L3pHn-RTrFLTHaAShz-uHN5qcFH5Eu6i64lgfsFPVVe?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/v4qthCQtAO672M8YQHuhntxXSwPFjvnaZu0N1mQ5_Y6BLROh8ntcuAMjGPvE1UKdpv7V7q-GgHiLbDPhcJhGaEYCp7g3iAVr95l4HhZHcZEZmCI7cNrI_zO_D4exHGJ9RjO382OlJBFXgfH8jg605aZ9W6Lz03TlvX-rE9UZQWh7J1D8D-RY2uAgwdVbxmh1?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/73PsyHZSkupamrDMAHzgVgNZZfeiIbJXbqFLqZbGym171ZlZ_tLd0fyqsAftdEoIMiACfigZmMOa5CLOhrnIApqwtmykQTxvVmcBeg7AY2ffsIoMmRY3gSVaNL4jMvih3bJgUEIMKklSny765Nac6Ih65SVuRIzCnoN_bOzsnCZ0oK7GRQSTBvo7AanRgavd?purpose=fullsize)

## 1. Why Web Proxies Matter

Modern **web and mobile applications** continuously communicate with **back-end servers**.

The basic communication flow is:

```text
User
  ↓
Browser / Mobile Application
  ↓
Web Proxy
  ↓
Back-End Server
  ↓
Database / Internal Services
```

The application sends requests to the server, and the server processes those requests and sends responses back.

For example:

```http
GET /profile HTTP/1.1
Host: example.com
Cookie: session=abc123
```

The server may respond with:

```http
HTTP/1.1 200 OK

{
    "username": "arjun",
    "role": "user"
}
```

During a **Web Application Penetration Test**, we need to understand and test these requests and responses.

This is where **Web Proxies** become extremely important.

---

# 2. What Is a Web Proxy?

A **Web Proxy** is a specialized security/testing tool positioned between a client and a server.

It allows a penetration tester to:

- Capture HTTP/HTTPS requests
    
- View requests and responses
    
- Modify requests
    
- Forward modified requests
    
- Replay requests
    
- Analyze parameters
    
- Analyze headers
    
- Inspect cookies
    
- Test application behavior
    

The proxy essentially acts as an intermediary.

### Normal communication

```text
Browser ───────────────→ Server
        HTTP Request

Browser ←─────────────── Server
        HTTP Response
```

### Communication through a proxy

```text
             Web Proxy
          ┌─────────────┐
          │ Burp / ZAP  │
          └─────────────┘
             ↑       ↓
             │       │
Browser ─────┘       └──── Server
```

This gives the penetration tester visibility into the application's communication.

---

# 3. Web Proxy vs Network Sniffer

It's important to distinguish a **web proxy** from tools such as **Wireshark**.

### Network Sniffers

Tools such as Wireshark generally analyze network traffic at a broader level.

They can inspect:

- TCP
    
- UDP
    
- DNS
    
- ARP
    
- ICMP
    
- HTTP
    
- TLS
    
- And many other protocols
    

### Web Proxies

Web proxies are primarily designed around **web application traffic**.

Common ports include:

|Protocol|Common Port|
|---|--:|
|HTTP|80|
|HTTPS|443|

The key difference is:

> **Wireshark observes network traffic, while a web proxy is designed to intercept, inspect, modify, and replay web application traffic.**

---

# 4. Why Web Proxies Are Essential for Pentesting

Web application penetration testing involves understanding how an application communicates with its back-end.

A proxy makes this much easier.

Without a proxy:

```text
Browser → Server
```

You have limited visibility into what the browser is doing.

With a proxy:

```text
Browser
   ↓
┌──────────────┐
│ Web Proxy    │
│              │
│ Inspect      │
│ Modify       │
│ Replay       │
│ Analyze      │
└──────────────┘
   ↓
Server
```

You can therefore examine the exact HTTP requests being generated.

---

# 5. Request Interception

One of the most important features of a web proxy is **interception**.

Suppose an application sends:

```http
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=arjun&password=test123
```

A proxy can pause the request before it reaches the server.

You can inspect or modify values such as:

```text
username
password
cookies
headers
parameters
JSON values
HTTP methods
URLs
```

For example:

```http
username=arjun&password=test123
```

could be changed during an authorized test to:

```http
username=test&password=test123
```

Then the modified request can be forwarded to the server.

This allows us to determine how the application responds to unexpected or manipulated input.

---

# 6. Request and Response Analysis

A web proxy lets us examine both sides of the communication.

### Request

```http
GET /dashboard HTTP/1.1
Host: target.htb
Cookie: session=123456
User-Agent: Mozilla/5.0
```

### Response

```http
HTTP/1.1 200 OK
Content-Type: text/html

<html>
    ...
</html>
```

A penetration tester can analyze:

### Request

- HTTP method
    
- URL
    
- Parameters
    
- Headers
    
- Cookies
    
- Authorization tokens
    
- Request body
    
- Content type
    

### Response

- Status code
    
- Response headers
    
- Cookies
    
- Response body
    
- Redirects
    
- Error messages
    
- Security headers
    
- Application behavior
    

---

# 7. Common HTTP Methods Seen in Web Proxies

|Method|Purpose|
|---|---|
|`GET`|Retrieve data|
|`POST`|Submit/create data|
|`PUT`|Replace/update data|
|`PATCH`|Partially update data|
|`DELETE`|Delete a resource|
|`HEAD`|Retrieve headers without normal body|
|`OPTIONS`|Discover supported methods/features|

Example:

```http
GET /users/123
```

could retrieve a user.

While:

```http
POST /login
```

could submit login credentials.

---

# 8. Uses of Web Proxies

The primary purpose of web proxies is to **capture and replay HTTP requests**, but they provide many additional capabilities.

The important uses mentioned in the module are:

### 🔹 1. Web Application Vulnerability Scanning

Proxies can assist in identifying vulnerabilities in web applications.

Examples include testing for:

- Injection vulnerabilities
    
- Authentication weaknesses
    
- Access-control issues
    
- Security misconfigurations
    
- XSS
    
- CSRF
    
- SSRF
    

The exact attacks are covered in dedicated web-security modules.

---

### 🔹 2. Web Fuzzing

**Fuzzing** involves sending many different inputs to an application to discover unexpected behavior.

For example:

```text
/test?id=1
/test?id=2
/test?id=3
...
```

or testing different parameter values:

```text
id=admin
id=test
id=0
id=-1
id=NULL
```

Web proxies can automate or assist with this process.

---

### 🔹 3. Web Crawling

A proxy can observe the application's links and requests and help map the application.

Example:

```text
/
├── login
├── register
├── dashboard
│   ├── profile
│   ├── settings
│   └── billing
├── api
└── logout
```

This helps a penetration tester understand the application's attack surface.

---

### 🔹 4. Web Application Mapping

Mapping means building an understanding of:

- Pages
    
- Endpoints
    
- Parameters
    
- APIs
    
- Forms
    
- Authentication mechanisms
    
- Application functionality
    

This is extremely important during reconnaissance.

---

### 🔹 5. Web Request Analysis

This is one of the most common uses.

A tester can inspect:

```text
URL
HTTP method
Headers
Cookies
Parameters
Request body
Response
Status code
```

For example:

```http
GET /api/user?id=100
```

Immediately tells us that:

```text
Endpoint = /api/user
Parameter = id
Value = 100
```

---

### 🔹 6. Web Configuration Testing

Proxies can help identify security-related configuration issues.

Examples include:

```text
Missing security headers
Weak cookie configuration
Unexpected HTTP methods
Improper redirects
Information disclosure
Incorrect CORS configuration
```

---

### 🔹 7. Code Reviews

Proxy traffic can also help developers and security testers understand how front-end applications communicate with back-end APIs.

This can reveal:

- API endpoints
    
- Parameters
    
- Authentication mechanisms
    
- Sensitive data exposure
    
- Unexpected client-side behavior
    

---

# 9. Burp Suite

![Image](https://images.openai.com/static-rsc-4/gK60DMmw4foqE5p_G-OLGIUQI81cFjlqphXYdkYc9ilFa5v1Aw87dZ7iu9NzT_aSWUy2fLxIoQ1t8SaYVaoOVJDcYpbWAjiyozo35DtgyoVj4TJXWlFB0fXDPqxRDI_Q5y0EHa8cVgKsbIhaS_F6DL3SwhZJbCUUbOyt4jwt6VVvwPrnd3ZHUAu_cE7wxuZW?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/qeRTgiNF8uhQRa9dJ1BEIJH03dB5tW9WAEi5noy1O2ordt_pawkRT_srCJCX2hamPeQfYAuQ05e-BZrdGPaXz0Sgv9GLUOM_Ex8HaaSN6p9dE7vCQXd9ITtjnAK7mGCiB0uvORGOaZmXMJQX4qf4wlbIdXHW1q402lGtFH6EhSQe3jEnHCiQ8pbMHDPrQjXW?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/pGMHOjzpdY4UdpxZOx1uxbsDGXyAV1NMPshdsDVCY_qqIaw3Cbncbf0LyZWyRd7teVA3mmVOStsi5jb8SUAi0D7cbzTBhkOp5MWo3JpO95SBTnzfbsuzOwMRMhUeK0eN8DAYfdtOa0SCPZbfvlHsdjrAyufslZeLF7l26aG4lLxCYIHaOCTB_Ej34bwlVASn?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/O5w_e3gnWBnh-peKBPoeBAsr3-fPU1YFlj2EyFV9hJT3diHIv2381qu1GPRy0tZwYoy4CEDQedBSrzp7FIUvxG0imEMuugxdN7KdlRQaneibJqEmJUbHz1MMI_qUSUpG2P_IGwKHvI8LX4jmn-9ecAvlvb0rzUyCIbSx6TWTFE7M6ZqOiq787ZYKNTIu23HC?purpose=fullsize)

**Burp Suite**, commonly called **Burp**, is one of the most widely used web proxies for penetration testing.

It is developed by **PortSwigger**.

[Official Burp Suite website](https://portswigger.net/burp?utm_source=chatgpt.com)

Burp provides a graphical interface containing numerous tools for web application testing.

It also includes a built-in Chromium-based browser, making it convenient to test applications through the proxy.

---

# 10. Burp Suite Editions

There are different Burp editions.

The two important concepts are:

### Burp Suite Community Edition

Free version.

It provides many important capabilities required for learning and penetration testing.

### Burp Suite Professional

Paid version with additional capabilities.

The module specifically highlights paid features such as:

- **Active web application scanner**
    
- **Faster Burp Intruder**
    
- Ability to load certain Burp extensions
    

> The Community Edition is still an extremely powerful tool and is sufficient for learning many web penetration-testing techniques.

---

# 11. Important Burp Components

Although we'll cover these in greater depth later, you should recognize the major components.

|Component|Main Purpose|
|---|---|
|**Proxy**|Intercept and inspect HTTP requests|
|**Repeater**|Manually modify and resend requests|
|**Intruder**|Automate customized request attacks/testing|
|**Scanner**|Automated vulnerability scanning|
|**HTTP History**|View captured requests|
|**Decoder**|Encode/decode data|
|**Comparer**|Compare requests/responses|
|**Extensions**|Extend Burp functionality|

### ⭐ Remember

For manual web pentesting, **Proxy + Repeater** are especially important.

---

# 12. OWASP ZAP

![Image](https://images.openai.com/static-rsc-4/CYVRDMTnmnf9Q5sdYHxzIDo6esDTQAeR18dTHrvubDyMxe64WpJeDpnTfBE5lYj9yJLw89rKh5lRZY0RZ3XPCp_08lojERGZMRP3rikejQ-YDcstjsmGHqC4QztRlkylDtvjIooSLHJorw-o8k2IYLTKQSz49JJK0RlJKGBG9EciYpB_pcJEdFbCw_AcfUCL?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/WhSBL8vmCItUMtSbYAViTy_ToDMFUkFDPLx7bZZJjNcBRKaIFkeEFNtXd0lE4A3-OMuXXXd_Oo5NIDDeWSjztlC-XkwYDEdFKWiPfjQZ0YjM4_EbksVSscnLUXCY7cjBiDZR6wvk0GKVoWoylPMBwi2oCJ1Vc0F-pW98bjE9XlP_AhrFkkTLVuwJ_AGT5WYT?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/c-VUC4PRTXl92tXxoBLtV6-rgvBf-8BfYCVkRv_qJGcC4G6g0ewIyMMW6N57nKqQSoxmity4Kq1RH2E8J-s64c1pFF8_bDxJWO-oLQYrl1dw8cvtsqDfza5Z_VojhuO0K6OSuOM0oL8uOUVE_axYgTakQim4YOGvJUMKTurAhTyhiyW1jN_NGNe0eMaF4CCg?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/XE5ZiMNRgd_XYkCnRM9C5vLOmF9OwtRrDCWHxD_X5Ptce5nEYzb7jcF-iVr1mQVUdBDOwxtiOb7or_mDIdmz1G1iQu4JxjIbQ03zdKcB_Iw1LOn3qdGigmKyGJcVPzq5rbXYNcFxGh_OTEisMkAALcnf-nNuvNoVddDXV3c997C7n3GgWEakSJGJm5wmKVgN?purpose=fullsize)

**OWASP Zed Attack Proxy (ZAP)** is another major web proxy used for web application security testing.

It is:

- Free
    
- Open-source
    
- Community maintained
    
- Developed under the OWASP project
    

[Official OWASP ZAP website](https://www.zaproxy.org/?utm_source=chatgpt.com)

[OWASP official website](https://owasp.org/?utm_source=chatgpt.com)

ZAP provides many capabilities similar to Burp.

---

# 13. Why ZAP Is Important

The major advantage of ZAP is that it is **free and open source**.

This means users don't need to purchase a commercial license to access its core functionality.

ZAP provides features for:

- Proxying
    
- Request inspection
    
- Crawling
    
- Scanning
    
- Fuzzing
    
- Application mapping
    
- Automated testing
    

It has also continued to gain features and community support over time.

---

# 14. Burp Suite vs ZAP

This is an important comparison to remember.

|Feature|Burp Suite|OWASP ZAP|
|---|---|---|
|Web proxy|✅|✅|
|HTTP interception|✅|✅|
|Request modification|✅|✅|
|Replaying requests|✅|✅|
|Crawling|✅|✅|
|Fuzzing|✅|✅|
|Automated scanning|Some features paid|✅|
|Open source|❌|✅|
|Free version|✅|✅|
|Commercial version|✅|❌|
|Large security community|✅|✅|

### Burp's major strengths

- Mature ecosystem
    
- Excellent user interface
    
- Extremely popular among professional pentesters
    
- Strong manual testing workflow
    
- Powerful extensions
    
- Professional edition provides additional automation
    

### ZAP's major strengths

- Completely free and open source
    
- No commercial license required
    
- Strong automation capabilities
    
- OWASP ecosystem
    
- Good choice for users who want an entirely free solution
    

---

# 15. Burp vs ZAP — Which Should You Learn?

The best answer isn't necessarily **one or the other**.

The module's recommendation is essentially:

> **Learn both.**

Why?

Because the fundamental concepts are very similar.

If you understand:

```text
HTTP
   ↓
Proxy
   ↓
Intercept
   ↓
Inspect
   ↓
Modify
   ↓
Forward
   ↓
Replay
```

then switching between Burp and ZAP becomes much easier.

---

# 16. Web Proxy in a Penetration Testing Workflow

A simplified web pentest workflow might look like:

```text
                    Web Application
                          │
                          ▼
                    ┌───────────┐
                    │   Proxy   │
                    │ Burp/ZAP  │
                    └─────┬─────┘
                          │
             ┌────────────┼────────────┐
             ▼            ▼            ▼
          Capture      Modify       Replay
             │            │            │
             └────────────┼────────────┘
                          ▼
                    Analyze Response
                          │
                          ▼
                    Identify Behavior
                          │
                          ▼
                  Security Assessment
```

This makes the proxy one of the central tools in web application testing.

---

# 17. Important Terminology

### Client

The application making the request.

Examples:

```text
Browser
Mobile application
Desktop application
API client
```

### Server

The system receiving and processing requests.

### HTTP Request

Data sent from the client to the server.

### HTTP Response

Data returned by the server to the client.

### Proxy

An intermediary between client and server.

### Intercept

Stopping a request before it reaches its destination so it can be inspected or modified.

### Replay

Sending a previously captured request again.

### Fuzzing

Sending many variations of input to test application behavior.

### Crawling

Automatically discovering application resources and links.

### MITM

**Man-in-the-Middle** — positioning an intermediary between two communicating parties.

---

# 18. Key Concept — HTTP Request Manipulation

This is one of the most important concepts to understand.

Suppose the application sends:

```http
GET /account?id=10 HTTP/1.1
Host: target.htb
Cookie: session=abc123
```

The proxy allows us to inspect it.

We may then change:

```text
id=10
```

to:

```text
id=11
```

and observe the server's response.

The purpose during a penetration test is not simply to "change values."

The goal is to understand:

> **How does the server respond when client-controlled data is manipulated?**

This principle appears throughout web application security testing.

---

# 19. Why Server-Side Testing Is Important

Modern applications often depend heavily on back-end servers.

The client may contain a user interface, but the server frequently handles critical operations such as:

```text
Authentication
Authorization
Data processing
Database operations
File operations
Payment processing
API requests
Session management
```

Therefore, testing only the visible front-end is insufficient.

A web proxy helps us observe the communication between the client and back-end.

---

# 20. Important Exam/Viva Points ⭐

### Q1. What is a web proxy?

A web proxy is an intermediary tool placed between a client and server to capture, inspect, modify, and replay web traffic.

### Q2. Why are web proxies important in penetration testing?

They provide visibility and control over HTTP/HTTPS requests and responses, making web application testing significantly easier.

### Q3. What ports are commonly associated with web traffic?

```text
HTTP  → 80
HTTPS → 443
```

### Q4. What is the difference between Wireshark and Burp?

Wireshark is primarily a network traffic analyzer, while Burp is specifically designed for intercepting and manipulating web application traffic.

### Q5. Name two popular web proxies.

```text
Burp Suite
OWASP ZAP
```

### Q6. Is Burp Suite free?

**Burp Suite Community Edition is free**, while Burp Professional provides additional paid features.

### Q7. Is ZAP free?

Yes. ZAP is a free and open-source web application security testing tool.

### Q8. What is interception?

Stopping a request so that it can be inspected or modified before forwarding it.

### Q9. What is request replay?

Sending a previously captured request again, usually after inspecting or modifying it.

### Q10. What is fuzzing?

Testing an application by automatically sending many different inputs or input variations.

---

# 🧠 Final Mental Model

Remember the entire topic like this:

```text
                 WEB APPLICATION
                        │
                        ▼
               ┌─────────────────┐
               │   BROWSER / APP │
               └────────┬────────┘
                        │
                        ▼
               ┌─────────────────┐
               │   WEB PROXY     │
               │                 │
               │ Capture         │
               │ Inspect         │
               │ Modify          │
               │ Replay          │
               │ Fuzz            │
               │ Crawl           │
               └────────┬────────┘
                        │
                        ▼
               ┌─────────────────┐
               │ BACK-END SERVER │
               └─────────────────┘
                        │
                        ▼
                    DATABASE
```

### 🔥 The core idea

> **A web proxy gives a penetration tester visibility and control over the communication between an application and its back-end server.**

And the two tools you should know from this section are:

**Burp Suite → Most commonly used commercial/community web proxy**

**OWASP ZAP → Free, open-source alternative**

These concepts are foundational. Once you understand **capture → inspect → modify → forward → replay**, the later Burp/ZAP features become much easier to understand.