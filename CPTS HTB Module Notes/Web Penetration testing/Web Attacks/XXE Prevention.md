## 1. Why XXE Happens

- XXE mainly occurs when unsafe XML input can reference **external entities**.
    
- Exploitation can allow:
    
    - Reading sensitive files
        
    - Data exfiltration
        
    - Other malicious actions
        
- XXE is often caused by **outdated XML libraries/components**.
    

---

## 2. Avoid Outdated Components

- XML is usually processed by built-in XML libraries rather than manually by developers.
    
- Therefore, XXE is often caused by an **outdated XML parser/library**.
    

### PHP Example

`libxml_disable_entity_loader()` is deprecated since **PHP 8.0**.

- It can enable external entity loading in an unsafe way.
    
- Developers should avoid relying on deprecated/unsafe XML functions.
    
- Use updated XML libraries and secure configurations instead.
    

### Other Components to Update

Update **all components that parse XML**, including:

- XML libraries
    
- SOAP/API libraries
    
- SVG processors
    
- PDF/document processors
    
- Other XML-processing components
    
- Outdated packages such as Node modules
    

**Key point:** Keeping XML libraries and related web components updated significantly reduces XXE risk.

---

## 3. Safe XML Configurations

In addition to updating libraries, configure XML parsers securely.

Recommended protections:

- Disable custom **DTD** support.
    
- Disable **External XML Entities**.
    
- Disable **Parameter Entity** processing.
    
- Disable **XInclude** support.
    
- Prevent **Entity Reference Loops**.
    

These configurations provide an additional security layer if an outdated library is still present.

---

## 4. Error Handling

XXE can sometimes be exploited through **error-based exfiltration**.

Therefore:

- Implement proper exception/error handling.
    
- Do **not display runtime errors** to users.
    
- Disable detailed PHP/web-server error output in production.
    

This prevents attackers from obtaining sensitive information through parser errors.

---

## 5. Consider Alternatives to XML

Because XML introduces several security risks, applications can consider using formats such as:

- **JSON**
    
- **YAML**
    

For APIs:

- Avoid XML-dependent standards such as **SOAP** when possible.
    
- Prefer JSON-based APIs such as **REST**.
    

---

## 6. WAF as an Additional Layer

A **Web Application Firewall (WAF)** can provide another layer of protection against XXE attacks.

However:

- A WAF should **not** be the primary defense.
    
- WAF rules can potentially be bypassed.
    
- The backend XML parser must still be properly secured.
    

---

## ⭐ Key Takeaways

> **XXE prevention = Updated components + Safe XML configuration + Proper error handling**

1. Keep XML libraries/components updated.
    
2. Disable external entities and DTDs when unnecessary.
    
3. Disable parameter entities and XInclude.
    
4. Prevent entity reference loops.
    
5. Hide runtime errors from users.
    
6. Prefer JSON/YAML where XML is unnecessary.
    
7. Use WAFs only as an additional security layer.
    
8. **Never rely solely on a WAF to protect a vulnerable backend.**