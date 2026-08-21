![Image](https://images.openai.com/static-rsc-4/YqL3eragaqgMxI7TiMKMqn6BX-jDQ4W0hVdOWvGoM1n1rFs2JRGwFLYkhSvR0655acGzR7ZNsnCbeSK8wyj4hWqtCEcd0tMctRoasfCm7OR2vbU_EJrtbfj-LkhBfzaaLXzBsJF0iYF-xPBBd-IZV_hfcaj2ddqH4laH1pUUB0Vwaom5gPu94AvD4fYPTQ4n?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/73PsyHZSkupamrDMAHzgVgNZZfeiIbJXbqFLqZbGym171ZlZ_tLd0fyqsAftdEoIMiACfigZmMOa5CLOhrnIApqwtmykQTxvVmcBeg7AY2ffsIoMmRY3gSVaNL4jMvih3bJgUEIMKklSny765Nac6Ih65SVuRIzCnoN_bOzsnCZ0oK7GRQSTBvo7AanRgavd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/fCwEzvd411qS-m9i7G7Y6Rc14K2iw7nZ96XcLvQQJ2OVpVGdJi5vpL8dxIhH3WbB-SEjDeHfeXP3ZfuQncPo9KHCsQqf-yaXNbCELiTSjEGXtlUaaGR9-279wjjnssJzv2JNKOkgbOX8Ia9t5zXqSaxCA5RVVboRyB71crwRH22YcUtvQBhvHC4wn92E-YRD?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ygcdyOviKHIQoduURm4F2ndfn6xYAZovvqt9iQPs70HzYXcAdvVIZqo2rC867iDlFh68scyPnjTAOjWkZq9XWQZdppB4fmC5Wy4kzog24-LFfNIb3Op8INup4SRt18BwTJyXRgI8iJqO9uCyjUUCyOlDGIubcVRhLm-u7tX-PAXRx0b9ciQW4caiinoxh-15?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/KwgX_Af6c-_iUvPi9vedd_BLYMYLiCO8CoFFnTql1dXnrgbetKHxKUJQE7BzqLBsP8Xo0yyJwKbWEJkU8vftp9LiXMuFsOHN5bXpEBc-AurhtUTuBag-0t9w7N_GLfh99TXadCcqumjmQTmPGUqyt8ACrghRbbszR5rGrlrJdLSxbAjfCAgbfY9K1ROrj5Nf?purpose=fullsize)

## 1. What Is Proxy Setup?

After installing Burp Suite or ZAP, the next step is to configure a browser so that its web traffic passes through the proxy.

### Without a proxy

```text
Firefox
   │
   │ HTTP/HTTPS
   ▼
Web Server
```

### With Burp/ZAP

```text
Firefox
   │
   │ HTTP/HTTPS
   ▼
┌───────────────┐
│ Burp / ZAP    │
│ Web Proxy     │
└───────┬───────┘
        │
        ▼
   Web Server
```

This allows us to:

- Capture requests
    
- Inspect requests
    
- Inspect responses
    
- Modify requests
    
- Forward requests
    
- Replay requests
    
- Understand application behavior
    

This is one of the **most important foundations of web application penetration testing**.

---

# 2. Pre-Configured Browser

Both Burp and ZAP provide a browser that is already configured to communicate through the proxy.

This is the easiest method when learning.

## Burp Suite

Go to:

```text
Proxy
  ↓
Intercept
  ↓
Open Browser
```

Burp's embedded browser automatically:

- Uses Burp as its proxy
    
- Has the appropriate proxy settings
    
- Has the required CA certificate configured
    

Therefore, there is normally **no manual browser configuration required**.

---

## ZAP

ZAP also provides a pre-configured browser.

You can click the **Firefox/browser icon** in ZAP's toolbar.

The browser is configured to send its traffic through ZAP.

### ⭐ For HTB Academy

The pre-configured browser is generally enough for the exercises in this module.

---

# 3. Using a Real Firefox Browser

Sometimes you don't want to use the embedded browser.

For example, you may prefer:

- Your normal Firefox profile
    
- Your own browser extensions
    
- Your own bookmarks
    
- Your preferred browser settings
    

In that case, Firefox needs to be manually configured to use Burp or ZAP.

The important information is:

```text
Proxy IP:   127.0.0.1
Proxy Port: 8080
```

Both Burp and ZAP use **8080 by default**.

---

# 4. Understanding `127.0.0.1`

`127.0.0.1` is the **localhost/loopback address**.

It refers to the same computer running the proxy.

Therefore:

```text
Firefox
   │
   │ 127.0.0.1:8080
   ▼
Burp/ZAP
```

means:

> Firefox is connecting to a proxy running locally on the same machine.

---

# 5. Understanding Port `8080`

Burp and ZAP commonly listen on:

```text
127.0.0.1:8080
```

Think of this as:

```text
127.0.0.1 = Which computer?
8080       = Which port?
```

So:

```text
127.0.0.1:8080
```

means:

> Connect to port 8080 on the local machine.

---

# 6. Proxy Port Must Match

This is **very important**.

Suppose Burp is listening on:

```text
127.0.0.1:8080
```

Firefox must also be configured to use:

```text
127.0.0.1:8080
```

If Firefox uses:

```text
127.0.0.1:8081
```

while Burp is listening on `8080`, the connection won't work.

### Correct

```text
Firefox
Proxy → 127.0.0.1:8080
             │
             ▼
Burp → Listening on 8080
```

### Incorrect

```text
Firefox
Proxy → 127.0.0.1:8081
             │
             X
Burp → Listening on 8080
```

---

# 7. Changing Burp's Proxy Port

If you want Burp to listen on a different port:

```text
Proxy
  ↓
Proxy Settings
  ↓
Proxy Listeners
```

You can configure the listener there.

For example:

```text
127.0.0.1:8081
```

Then Firefox must also use:

```text
127.0.0.1:8081
```

### ⚠️ Important

If the selected port is already being used by another application, Burp may fail to start its listener.

---

# 8. Changing ZAP's Proxy Port

In ZAP, proxy/network settings can be configured under:

```text
Tools
  ↓
Options
  ↓
Network
  ↓
Local Servers/Proxies
```

Again, the browser's proxy configuration must use the **same IP and port**.

---

# 9. FoxyProxy 🦊

![Image](https://images.openai.com/static-rsc-4/NWl9kiPrWC_bNKhSzqYvdyd379i0sT97tSf4BAo158EOmNhom2uCc9mwZErYwZVU5433O30viIzKPvpobDTGyX_5DLkPHEtvCu3iDAhZWeZV_PKNEHOX6kN2eU4m0o5dD9CntmT44IpbHFloyOandOtvmOkSG1w-N2STTGvIwcbKw344Dk0rUVX1ddme8Ed7?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/l3ycz7_y-bBEXcAl2tBI3kLNxsjch-xaMQYqrJuYlA_hV0iJpZNi4nK06vXZQ9TsfxeQsh036YH9ePcoBc7fGPxzQM-kSn48by4Axa7ex7aA7yGdP2tAx2SSU6LmBb7Vpb1HxIJ5sYrpWKxxhqc9xo0BB_nVUSE2QOJsQeFN48VGJ6mZPaugYvdXnmAF_pTD?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/fCwEzvd411qS-m9i7G7Y6Rc14K2iw7nZ96XcLvQQJ2OVpVGdJi5vpL8dxIhH3WbB-SEjDeHfeXP3ZfuQncPo9KHCsQqf-yaXNbCELiTSjEGXtlUaaGR9-279wjjnssJzv2JNKOkgbOX8Ia9t5zXqSaxCA5RVVboRyB71crwRH22YcUtvQBhvHC4wn92E-YRD?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/tuaPZgY6USVzDVIzL89k6fHH3P-3CwDjr4mqYIUb8S0egd-SepsBGo81h8Zf4wiyhAsBnK3ffy8TBUWZbat0jaQjsqal7AOqSC-BTj5BmKhVjxos8uS0BULVAqZL0_O7ly9z0bwyUvFzWolKGiII4HCoJfH9y3B1ZZvEK7y68hQ2Fua3AUgK6a9w96glWmyy?purpose=fullsize)

Manually changing Firefox's proxy every time can become annoying.

A convenient solution is the **FoxyProxy** browser extension.

[FoxyProxy for Firefox](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/?utm_source=chatgpt.com)

FoxyProxy allows you to quickly switch between different proxy configurations.

For example:

```text
Firefox
   │
   ├── Direct Internet
   │
   ├── Burp → 127.0.0.1:8080
   │
   └── ZAP  → 127.0.0.1:8080
```

This is extremely convenient when switching between Burp and ZAP.

---

# 10. Creating a FoxyProxy Configuration

Open the FoxyProxy extension and choose:

```text
Options
```

Then:

```text
Add
```

Create a proxy configuration with:

|Setting|Value|
|---|---|
|Name|Burp / ZAP|
|Proxy Type|HTTP|
|IP Address|`127.0.0.1`|
|Port|`8080`|
|Username|Leave empty|
|Password|Leave empty|

Then save the configuration.

---

# 11. Example: Burp Profile

You can create:

```text
Name:
Burp

Address:
127.0.0.1

Port:
8080
```

Then:

```text
Firefox
   ↓
FoxyProxy
   ↓
Burp
   ↓
Target
```

---

# 12. Example: ZAP Profile

You can similarly create:

```text
Name:
ZAP

Address:
127.0.0.1

Port:
8080
```

Then:

```text
Firefox
   ↓
FoxyProxy
   ↓
ZAP
   ↓
Target
```

If both applications are configured to use the same port, **only one should be actively listening on that port at a time**.

---

# 13. Using FoxyProxy

Once the profiles are configured:

```text
FoxyProxy icon
      ↓
Select Burp
```

or:

```text
FoxyProxy icon
      ↓
Select ZAP
```

The browser will then route its traffic through the selected proxy.

### ⭐ This is much easier than repeatedly changing Firefox's native proxy settings.

---

# 14. PwnBox

HTB's **PwnBox** already has the relevant FoxyProxy configuration.

Therefore, when using PwnBox, you generally don't need to manually create the Burp/ZAP proxy profiles described above.

You can simply select the appropriate profile.

---

# 🔐 15. Why Do We Need a CA Certificate?

This is one of the **most important concepts** in proxy setup.

HTTP is relatively straightforward:

```text
Firefox
   ↓
Burp
   ↓
Server
```

But HTTPS is encrypted.

```text
Firefox
   ═══════════════════
        HTTPS
   ═══════════════════
        Server
```

If Burp/ZAP needs to inspect HTTPS traffic, it needs to act as a trusted intermediary.

This is where a **CA certificate** comes in.

---

# 16. HTTPS Through Burp/ZAP

Conceptually, the connection becomes:

```text
                 HTTPS
Firefox ═══════════════════► Burp
                              │
                              │ HTTPS
                              ▼
                           Server
```

Burp establishes a connection to the server while presenting a certificate to Firefox that Burp generated/signed using its own CA.

For Firefox to trust this certificate, Firefox needs to trust the proxy's **CA certificate**.

---

# 17. What Happens Without the CA Certificate?

Without installing the proxy's CA certificate, Firefox may display certificate/security warnings for intercepted HTTPS connections.

You may encounter certificate errors instead of seamlessly browsing the application.

The CA certificate solves this by telling Firefox:

> Trust certificates generated by this proxy CA.

### ⭐ Important

The certificate is **not the target website's normal certificate**.

It is the certificate authority certificate used by the proxy to establish trusted interception for HTTPS testing.

---

# 18. Getting Burp's CA Certificate

First make sure Firefox is using Burp as its proxy.

Then browse to:

```text
http://burp
```

Burp provides a page from which you can download:

> **CA Certificate**

Download that certificate.

---

# 19. Burp CA Certificate Flow

```text
Select Burp in FoxyProxy
          ↓
Open Firefox
          ↓
Visit http://burp
          ↓
Click CA Certificate
          ↓
Download Certificate
          ↓
Import into Firefox
```

---

# 20. Getting ZAP's CA Certificate

In ZAP, navigate to:

```text
Tools
  ↓
Options
  ↓
Network
  ↓
Server Certificates
```

Then click:

```text
Save
```

This saves ZAP's CA certificate.

ZAP also provides a:

```text
Generate
```

option, which can be used to generate a new certificate.

---

# 21. Installing the CA Certificate in Firefox

Open Firefox settings.

You can navigate to:

```text
about:preferences#privacy
```

Then find the certificate settings.

Choose:

```text
View Certificates
```

---

# 22. Firefox Certificate Manager

Inside the Certificate Manager:

```text
Authorities
    ↓
Import
```

Then select the downloaded Burp or ZAP CA certificate.

---

# 23. Trusting the CA

Firefox will ask what the imported CA should be trusted for.

The module specifies selecting:

```text
Trust this CA to identify websites
```

and:

```text
Trust this CA to identify email users
```

Then click:

```text
OK
```

### 🔥 For web pentesting, the important concept is trusting the CA for website identification.

---

# 24. Complete Burp + Firefox Setup

Here's the entire process:

```text
                    ┌─────────────┐
                    │   Firefox   │
                    └──────┬──────┘
                           │
                    FoxyProxy
                           │
                    127.0.0.1:8080
                           │
                           ▼
                    ┌─────────────┐
                    │    Burp     │
                    └──────┬──────┘
                           │
                      HTTPS/TLS
                           │
                           ▼
                    ┌─────────────┐
                    │ Web Server  │
                    └─────────────┘
```

And the setup sequence:

```text
1. Start Burp
       ↓
2. Start Proxy Listener
       ↓
3. Configure Firefox/FoxyProxy
       ↓
4. Use 127.0.0.1:8080
       ↓
5. Download Burp CA
       ↓
6. Import CA into Firefox
       ↓
7. Trust CA
       ↓
8. Browse target
       ↓
9. Inspect traffic in Burp
```

---

# 25. Complete ZAP + Firefox Setup

```text
                    ┌─────────────┐
                    │   Firefox   │
                    └──────┬──────┘
                           │
                    FoxyProxy
                           │
                    127.0.0.1:8080
                           │
                           ▼
                    ┌─────────────┐
                    │     ZAP     │
                    └──────┬──────┘
                           │
                      HTTPS/TLS
                           │
                           ▼
                    ┌─────────────┐
                    │ Web Server  │
                    └─────────────┘
```

Setup:

```text
1. Start ZAP
       ↓
2. Start ZAP proxy
       ↓
3. Configure Firefox/FoxyProxy
       ↓
4. Use 127.0.0.1:8080
       ↓
5. Export ZAP CA
       ↓
6. Import CA into Firefox
       ↓
7. Trust CA
       ↓
8. Browse target
       ↓
9. Inspect traffic in ZAP
```

---

# 26. HTTP vs HTTPS Through the Proxy

### HTTP

```text
Firefox
   ↓
Burp/ZAP
   ↓
HTTP Server
```

The proxy can directly inspect the HTTP traffic.

### HTTPS

```text
Firefox
   ↓
Burp/ZAP
   ↓
HTTPS Server
```

The proxy needs its CA certificate trusted by Firefox to properly perform HTTPS interception.

---

# 27. Common Setup Problems

## ❌ Problem 1 — Browser Can't Connect

Check:

```text
Proxy IP
Proxy Port
```

Usually:

```text
127.0.0.1:8080
```

---

## ❌ Problem 2 — Burp/ZAP Isn't Receiving Traffic

Check whether the proxy is actually listening.

Also make sure Firefox/FoxyProxy is configured to use the correct proxy.

---

## ❌ Problem 3 — HTTPS Certificate Errors

Usually check whether the correct **Burp/ZAP CA certificate** has been imported and trusted by Firefox.

---

## ❌ Problem 4 — Port Already in Use

If Burp/ZAP can't bind to port `8080`, another process may already be using it.

You can either:

```text
Stop the conflicting service
```

or:

```text
Choose another available proxy port
```

Then configure Firefox/FoxyProxy to use the new port.

---

# 28. ⭐ Important Values to Memorize

|Item|Default|
|---|---|
|Local proxy IP|`127.0.0.1`|
|Burp proxy port|`8080`|
|ZAP proxy port|`8080`|
|Burp CA location|`http://burp`|
|Firefox certificate settings|`about:preferences#privacy`|
|Burp listener settings|`Proxy → Proxy settings → Proxy listeners`|
|ZAP listener settings|`Tools → Options → Network → Local Servers/Proxies`|

---

# 🧠 29. Exam / Viva Questions

### Q1. What is the default Burp proxy port?

**8080**

### Q2. What is the default ZAP proxy port?

**8080**

### Q3. What does `127.0.0.1` represent?

The local/loopback address of the current machine.

### Q4. Why do we configure Firefox to use Burp?

So Firefox's web requests pass through Burp and can be captured, inspected, modified, and replayed.

### Q5. Why is a CA certificate required?

To allow the proxy to perform trusted HTTPS interception without constant browser certificate warnings.

### Q6. What is FoxyProxy?

A Firefox extension that makes it easier to configure and switch between proxy configurations.

### Q7. Where can you get Burp's CA certificate?

After routing traffic through Burp, visit:

```text
http://burp
```

and download **CA Certificate**.

### Q8. Where is ZAP's CA certificate?

```text
Tools
→ Options
→ Network
→ Server Certificates
```

### Q9. What happens if Firefox uses port 8081 while Burp listens on 8080?

Firefox won't communicate with Burp because the proxy settings don't match.

### Q10. What is the easiest way to start testing in HTB?

Use the **pre-configured browser** supplied by Burp/ZAP/PwnBox.

---

# 🔥 Final Mental Model

The entire lesson can be reduced to:

```text
                WEB PENTESTING
                      │
                      ▼
                  Browser
                      │
                      ▼
             ┌────────────────┐
             │ FoxyProxy       │
             │ or Native Proxy │
             └───────┬────────┘
                     │
               127.0.0.1:8080
                     │
                     ▼
             ┌────────────────┐
             │   BURP / ZAP   │
             └───────┬────────┘
                     │
              Inspect / Modify
                     │
                     ▼
                Web Server
```

### ⭐ The 5 things you absolutely need to remember

**1.** Burp/ZAP act as the intermediary between browser and server.

**2.** Default proxy address is usually **`127.0.0.1:8080`**.

**3.** The browser's proxy configuration must match the proxy listener.

**4.** For HTTPS interception, install and trust the proxy's **CA certificate**.

**5.** **FoxyProxy** makes switching between Burp, ZAP, and direct browsing much easier.

Once these are correctly configured, **every request generated by the browser can flow through Burp/ZAP**, giving you the visibility needed for actual web application testing.