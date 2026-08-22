![Image](https://images.openai.com/static-rsc-4/GtvJJKocWUn3Zgla6d7rKO9NI_rDrdEsM4nHQ-OSwXPujHa62BcmN6Sp30eEj1RDVQWWI3_x-Zx0Kz6kozsCV7cmplAR6TAnMhJZZ7SV4_iXDTPDBL1Huyi_Nu-Q8l5JouCCdK8wQx3myY0WE5Rr-4GVVLpQiYqCP7KlnTXnX-8HWUta3IOC13cFRJ2rrZkL?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/vX2mVP3iV0HpWxvxJwaMGAbtyNtx0y67ETPiCNcGMclUKXH4g656RvLSe7VDX752Y75WzQnLVB9j4sX91WGAJQZ0QzBhAgq9Jp2vzLgGRtBKxGiWbjvH92iTTRNWF8f6TB1shZej0bByeKaKTMnUpNpkArcplrlIVDrZgMEUQ1f9qB5e6KRIDTXk2UsUCUM4?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/TW6ixwBSwv6G6xupLEUBnWlOclVk6zOJXoZSWHrIYGUs9tVplhhOg6P1oCVYdz0TGcEWof8UrSyOPD98gglKXYJIwwN2Yd1e4FOOpYIB8JDBJmGDuoIruJBzDNjfCExmQfLY8O4mrBvo2WHPqsOEwIPO2ek0gMecBU_SMpEZ2cawKPuaVla-fnmYehcIsEPq?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/NuH9e8uLQQ0CIyt_b-djNKqDbgihDiHIyzVPCIzZBsWQ0D8EctSAME7mETN2vC44mNJCHZPfe5IwmKyLVwOXkonGZ6Gq8-KylFJppu1MIrbrwGkeqsV4x8mR45Qe22PUyMeAMdOLUvhtF25_MEL-AKNZ4B8vkNoPcqV26rqPczrbD-g_Q-1KkqDp-wfDZYmv?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Uzhuqn1kwts56heiWvAJbziskqp2cHCKUMEOt5jHJ_EyQu7BWUHGC5ZM15PNssfa2XmhN1NSxlKU8ZU6D8MxZ2D5ULEgW6wLIkn4hkfuiB6RyJReIFxwxtzabV3Kp7EvTgffitHM_Ap5Au5rOA0dXKkJ-9o4kNoxKJxVxZP-cRYK4mBWXP3ZtLwLU2Dmw5Tx?purpose=fullsize)

## 1. What Is Request Repeating?

In the previous sections, we learned how to:

- Intercept requests
    
- Modify requests
    
- Forward requests
    
- Intercept responses
    
- Modify responses
    
- Automate modifications
    

But manually intercepting a request every time we want to test a different input is inefficient.

For example:

```text
Create request
      ↓
Intercept
      ↓
Modify
      ↓
Forward
      ↓
Wait for response
      ↓
Check browser
      ↓
Repeat
```

Doing this repeatedly would take a lot of time.

**Request repeating** solves this problem.

---

# 2. What Is Request Repeating?

Request repeating allows us to take a request that has already passed through the proxy and **send it again**, after making whatever changes we want.

Conceptually:

```text
Original Request
       ↓
Proxy History
       ↓
Repeater / Request Editor
       ↓
Modify
       ↓
Send
       ↓
Response
```

We don't need to intercept a completely new browser request every time.

### ⭐ Core definition

> **Request repeating allows a previously captured HTTP request to be resent after modifying it.**

This is one of the most useful features for manual web application testing.

---

# 3. Why Is Request Repeating Useful?

Imagine we have one request:

```http
POST /ping HTTP/1.1

ip=1
```

During testing, we may want to send different inputs.

Instead of:

```text
Browser
 ↓
Intercept
 ↓
Modify
 ↓
Forward
 ↓
Browser
 ↓
Repeat everything
```

we can do:

```text
Captured Request
       ↓
Repeater
       ↓
Change Input
       ↓
Send
       ↓
Response
       ↓
Change Input
       ↓
Send Again
```

This is **much faster**.

---

# 4. Proxy History

Before repeating a request, we first need to locate it.

Both Burp and ZAP maintain a history of HTTP traffic that has passed through the proxy.

---

# 5. Burp HTTP History

In Burp:

```text
Proxy
   ↓
HTTP History
```

You can see requests such as:

```text
GET  /
GET  /index.html
POST /login
GET  /dashboard
POST /ping
```

The history typically contains information such as:

- HTTP method
    
- URL
    
- Status code
    
- MIME type
    
- IP address
    
- Request/response details
    

---

# 6. Why HTTP History Is Important

HTTP History acts like a record of the traffic observed by Burp.

Instead of having to remember what requests the browser generated, you can go back and inspect them.

For example:

```text
HTTP History
│
├── GET /
├── GET /style.css
├── GET /script.js
├── POST /login
├── GET /dashboard
└── POST /ping  ← Interesting request
```

You can select the request you're interested in.

---

# 7. ZAP History

ZAP also keeps request history.

You can access it from:

```text
History
```

in the ZAP interface.

The ZAP HUD also provides a History pane.

You can select individual requests to inspect their:

- Request
    
- Response
    
- Method
    
- URL
    
- Headers
    
- Body
    
- Status code
    

---

# 8. Filtering and Sorting History

Both Burp and ZAP provide filtering/sorting functionality.

This becomes important when an application generates hundreds or thousands of requests.

For example:

```text
500 Requests
     ↓
Filter
     ↓
POST requests
     ↓
Filter
     ↓
/api/
     ↓
Interesting request
```

Useful filters can include:

- HTTP method
    
- Status code
    
- URL
    
- MIME type
    
- Search terms
    
- Request/response content
    

### ⭐ Practical principle

> **The larger the application, the more important request filtering becomes.**

---

# 9. WebSockets History

Both Burp and ZAP can also maintain **WebSocket history**.

WebSockets allow applications to maintain persistent communication with a server.

Unlike traditional HTTP requests:

```text
Request
   ↓
Response
   ↓
Connection ends
```

WebSockets can maintain:

```text
Browser
   ═══════════════
   Persistent
   Connection
   ═══════════════
   Server
```

They can be used for:

- Real-time updates
    
- Chat applications
    
- Notifications
    
- Live dashboards
    
- Asynchronous data
    
- Real-time application functionality
    

The module notes that advanced WebSocket testing is **outside the scope of this module**.

---

# 10. Burp — Original vs Edited Request

An especially useful Burp feature is the ability to distinguish between the:

```text
Original Request
```

and:

```text
Edited Request
```

If you modified a request before sending it, Burp can allow you to examine both versions.

For example:

### Original

```http
POST /ping HTTP/1.1

ip=1
```

### Edited

```http
POST /ping HTTP/1.1

ip=modified-value
```

This is useful when you want to understand exactly what changed.

---

# 11. Burp Repeater

![Image](https://images.openai.com/static-rsc-4/DuBdv8NEnrrPJFI5N_iM4bdON9JPt8_ltULTb-w2BiY6bf-eAM0tOP9d0o-NFM2D6-OLNWY-iaEXQgcA-708YmWF_t0CeD81873th446APO9tbTtcqsapCNvXmGanSr5IFoM3QFNqlsF8CWbj4QUp343OVurPTiTHIT9oVIzX5A0W_AMWApetEFKIPZRTt0X?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/yRAA059Pr7Dkyhn3gf-o8KkTjln2-oUppNHybK6pPXP_9edZRYnAuOKk80iPY1PulpBQylX1YEW85MIusw9KBPzx0AzNb8ou6SoEclnjz991yL8Z1R07aO-ayhSuEEp9Mx2aRli993Ok90esOsQZWt9E-AwRYu6-_Gy0FhTSIai8MXEq7GvPkm_CQAtcXAiP?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/0Un0Q6CiWvy_01Ku80sfyApKnljbGob5cDxx8KhyjtvfwTlcQ50HV19JuYE-FvEp86bL3HQ9Ia6khwuisaWsVwy6AGY5mMMEDoWeuPjD9hM15krxNbb9M7Ew6jLfuAx6WMPENUaLWKoYGS1zmj4SXn-8S9AFafKZMwoj7W3qSN7ga9f81INmqLZBfRhPPLHx?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/LsPpT-Wsh035qfeBKzvbgUt2_iJOEnAlfS0-QPqXMKgKM1oTnRzSMc2BV7jC2KC7qMVQA7saDiJC2HjKLBZh-wp9G8PXj_8nbl2ysz2Jhlvz1c-ZdXuPqw6wAixcy7GFloBEcF88UAHkXl1EQjVqEVtuaagEfA9wFj3ZSp88WM3lshHej7AYDn0D96tBKxJX?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/lrvjWni_XToTDpcsVi6quB2q_XfAP5LZ8A2dDI6aIXBROkvW38yuN95RMj3kcLPVf1Yav95gt2EGGFKbZSnmbcGfcsWW8iBQ_RGd2Z-EsoSVyYM2mqVWnHybUZsPiIo48ft5DcshHEztx-8UW1sqtVyZzA8SgPNaU93EIA4IaktSV-nwf8cFDpX6bdjfxJEw?purpose=fullsize)

The Burp feature specifically designed for repeating requests is:

> **Repeater**

Once you locate a request in HTTP History, you can send it to Repeater.

The shortcut is:

```text
CTRL + R
```

Then you can open the:

```text
Repeater
```

tab.

---

# 12. Sending a Request to Burp Repeater

Basic workflow:

```text
Proxy
 ↓
HTTP History
 ↓
Select Request
 ↓
CTRL + R
 ↓
Repeater
 ↓
Modify
 ↓
Send
```

Once the request is in Repeater, you can modify it without needing the browser.

---

# 13. Sending the Request

In Repeater, click:

> **Send**

The request is sent immediately.

The response is displayed inside Repeater.

Therefore:

```text
Request
   │
   ▼
Repeater
   │
  Send
   │
   ▼
Server
   │
   ▼
Response
```

This is significantly faster than repeatedly going back to the browser.

---

# 14. Repeater's Main Advantage

The biggest advantage is the ability to **modify → send → analyze → modify → send again** very quickly.

For example:

```text
Request
  ↓
Send
  ↓
Response
  ↓
Change parameter
  ↓
Send
  ↓
Response
  ↓
Change parameter
  ↓
Send
```

You can perform this entire cycle within Repeater.

---

# 15. Changing HTTP Methods in Burp

Burp also provides a convenient option to change the HTTP method.

Right-click the request and choose:

```text
Change Request Method
```

This can switch between methods such as:

```text
GET
POST
PUT
PATCH
DELETE
```

without manually rewriting the entire request.

### Example

Original:

```http
POST /ping HTTP/1.1
```

Can be changed to:

```http
GET /ping HTTP/1.1
```

The server's response can then be observed.

---

# 16. ZAP — Request Editor

ZAP provides similar functionality through:

> **Request Editor**

Find a request in the history, right-click it, and select:

```text
Open/Resend with Request Editor
```

The Request Editor allows you to:

- Modify requests
    
- Send requests
    
- Change HTTP methods
    
- Examine responses
    

---

# 17. ZAP Request Editor Workflow

```text
ZAP History
    ↓
Select Request
    ↓
Right-click
    ↓
Open/Resend with Request Editor
    ↓
Modify
    ↓
Send
    ↓
View Response
```

---

# 18. ZAP HTTP Method Dropdown

ZAP's Request Editor provides a **Method** dropdown.

This allows you to quickly switch between HTTP methods.

For example:

```text
POST
 ↓
GET
```

or:

```text
POST
 ↓
PUT
```

without manually reconstructing the request.

---

# 19. ZAP Request/Response Display

By default, ZAP may display the request and response in separate tabs.

You can change the display arrangement using the interface/display controls.

This is primarily a UI preference.

The important functionality remains:

```text
Edit Request
      ↓
Send
      ↓
Inspect Response
```

---

# 20. ZAP HUD Replay

ZAP's HUD provides another way to repeat requests.

From the HUD:

```text
History
   ↓
Select Request
   ↓
Request Editor
```

You can then choose:

### Replay in Console

The response is shown inside the ZAP HUD.

### Replay in Browser

The response is rendered in the browser.

This gives you flexibility depending on what you're trying to examine.

---

# 21. Console vs Browser Replay

### Replay in Console

```text
Request
   ↓
ZAP
   ↓
Replay in Console
   ↓
Response shown in ZAP
```

Useful when you're primarily interested in the raw HTTP response.

### Replay in Browser

```text
Request
   ↓
ZAP
   ↓
Replay in Browser
   ↓
Rendered page
```

Useful when you want to see how the response is actually rendered.

---

# 22. Modifying Repeated Requests

One of the most important parts of Repeater/Request Editor is that the request remains editable.

Suppose we have:

```http
POST /ping HTTP/1.1

ip=value1
```

Change it to:

```http
POST /ping HTTP/1.1

ip=value2
```

Then:

```text
Send
```

The response appears immediately.

You can then change it again.

---

# 23. Repeating the HTB Lab Request

The previous lab request looked like:

```http
POST /ping HTTP/1.1
Host: target

ip=...
```

Once it has been captured, we can move it into Repeater.

Then the workflow becomes:

```text
Captured Request
      ↓
Burp Repeater
      ↓
Modify Input
      ↓
Send
      ↓
Read Response
      ↓
Modify Input Again
      ↓
Send Again
```

This eliminates the need to repeatedly:

```text
Open browser
→ Enter value
→ Intercept
→ Modify
→ Forward
→ Check browser
```

---

# 24. Why Repeater Is So Important

Repeater is one of the most important tools for **manual web application penetration testing**.

It lets you study how an endpoint behaves when you systematically change its inputs.

For example:

```text
Parameter
   ↓
Change value
   ↓
Send
   ↓
Observe response
   ↓
Change value
   ↓
Send
```

You can investigate:

- Parameter behavior
    
- Error handling
    
- Authentication behavior
    
- Authorization behavior
    
- Input validation
    
- HTTP methods
    
- Headers
    
- Cookies
    
- API responses
    
- Application logic
    

---

# 25. Repeater vs Intercept

This distinction is extremely important.

### Intercept

Used when you want to catch a **new request generated by the application**.

```text
Browser
   ↓
Request
   ↓
⏸ Proxy
   ↓
Modify
   ↓
Forward
```

### Repeater

Used when you already have a request and want to **send it repeatedly**.

```text
Saved Request
   ↓
Repeater
   ↓
Modify
   ↓
Send
   ↓
Modify
   ↓
Send
```

### ⭐ Easy memory trick

> **Intercept = Catch**

> **Repeater = Re-send**

---

# 26. Repeater vs Intruder

Don't confuse these.

### Repeater

Designed primarily for **manual, controlled repetition**.

```text
Change
 ↓
Send
 ↓
Analyze
```

### Intruder

Designed for more automated request manipulation/testing.

```text
Payload 1
Payload 2
Payload 3
Payload 4
...
```

Repeater gives you granular manual control.

---

# 27. URL Encoding

The module ends by highlighting an important concept:

> The data in the POST request is **URL-encoded**.

For example, certain characters need to be represented differently when transmitted in HTTP form data.

A simple example:

```text
space
```

can be represented as:

```text
%20
```

And special characters may also have encoded representations.

Understanding encoding becomes very important when creating custom HTTP requests.

---

# 28. Why Encoding Matters

Suppose you see:

```http
parameter=value
```

You shouldn't always assume the value is being transmitted exactly as it appears.

The request may contain:

```text
URL encoding
HTML encoding
Base64
JSON escaping
Unicode encoding
```

depending on the application and context.

Therefore, when using Repeater, always understand the encoding format being used by the application.

---

# 29. Burp vs ZAP

|Feature|Burp|ZAP|
|---|---|---|
|HTTP History|✅|✅|
|Request replay|Repeater|Request Editor|
|Modify request|✅|✅|
|Modify HTTP method|✅|✅|
|Request/response view|✅|✅|
|Browser replay|—|✅ HUD|
|Console replay|—|✅ HUD|
|WebSocket history|✅|✅|
|Filtering|✅|✅|
|Sorting|✅|✅|

---

# 🧠 30. Exam / Viva Questions

### Q1. What is request repeating?

Resending a previously captured HTTP request after modifying it.

### Q2. Why is request repeating useful?

It eliminates the need to repeatedly intercept new browser requests when testing different inputs.

### Q3. What is Burp's request-repeating tool called?

**Repeater.**

### Q4. What is the shortcut for sending a request to Burp Repeater?

```text
CTRL + R
```

### Q5. What does Burp Repeater's Send button do?

It sends the current request and displays the resulting response.

### Q6. How do you open a request in ZAP's Request Editor?

Right-click the request and choose:

```text
Open/Resend with Request Editor
```

### Q7. What can you change in Repeater?

Almost any part of the HTTP request, including:

- Method
    
- URL
    
- Parameters
    
- Headers
    
- Cookies
    
- Body
    

### Q8. What is the difference between Intercept and Repeater?

**Intercept** catches requests as they're generated by the client.

**Repeater** resends requests that have already been captured.

### Q9. Why is HTTP History useful?

It allows you to locate previously captured requests and inspect their request/response data.

### Q10. What is WebSocket history?

A record of WebSocket connections/messages associated with the application. Advanced WebSocket testing is outside this module's scope.

---

# 🔥 31. Final Mental Model

```text
                    BROWSER
                       │
                       ▼
                ┌─────────────┐
                │ BURP / ZAP  │
                └──────┬──────┘
                       │
                       ▼
                  HTTP HISTORY
                       │
              ┌────────┴────────┐
              │                 │
           Burp              ZAP
              │                 │
          Repeater        Request Editor
              │                 │
              └────────┬────────┘
                       │
                    Modify
                       │
                       ▼
                     SEND
                       │
                       ▼
                    SERVER
                       │
                       ▼
                   RESPONSE
                       │
                       ▼
                    ANALYZE
```

## ⭐ The key workflow

**Capture → History → Repeater/Request Editor → Modify → Send → Analyze → Repeat**

The most important thing to internalize is that **Repeater separates request generation from request testing**. Once you have an interesting request, you don't need the browser to generate it again—you can work directly with the captured HTTP message and rapidly test how the server responds to controlled changes.