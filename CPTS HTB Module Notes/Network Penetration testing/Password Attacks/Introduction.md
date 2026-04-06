# 🔐 **Authentication & Password Security Notes**

## 📌 Core Security Principles (CIA Triad)

At the foundation of cybersecurity are three essential principles:

- **Confidentiality** → Protect data from unauthorized access
    
- **Integrity** → Ensure data is not altered or tampered
    
- **Availability** → Ensure systems/data are accessible when needed
    

👉 Most security breaches happen due to failure in one of these.

---

## 🔑 **Authentication Overview**

Authentication = **Verifying identity before access is granted**

It uses **four main factors**:

---

### 🔍 Authentication Factors

![Image](https://www.researchgate.net/publication/371165301/figure/fig3/AS%3A11431281209622987%401701805984550/Venn-diagram-of-current-authentication-factors-components-in-multi-factor-authentication.tif)

![Image](https://miro.medium.com/0%2ABO1Wcv6XjT5qimVB.jpg)

![Image](https://cdn.prod.website-files.com/61845f7929f5aa517ebab941/633a9b5af75e01462f02e885_Optical%20fingerprint%20scanners%20by%20Aratek%20Biometrics.jpg)

![Image](https://m.media-amazon.com/images/I/61u4-khnkzL.jpg)

1. **Something you know**
    
    - Password, PIN, passphrase
        
2. **Something you have**
    
    - ID card, smart card, mobile device
        
3. **Something you are**
    
    - Biometrics (fingerprint, face, retina, voice)
        
4. **Somewhere you are**
    
    - Location, IP address
        

---

### 🧠 Important Concept

- Authentication → Verifies identity
    
- Authorization → Grants permissions after authentication
    

✔ Example:

- Login with password → Authentication
    
- Access files after login → Authorization
    

---

## 🔐 **Multi-Factor Authentication (MFA)**

- Combines multiple factors for stronger security
    
- Example:
    
    - Password + OTP + Fingerprint
        

✔ Used in:

- Banking systems
    
- Medical systems (e.g., CAC + PIN)
    

---

## 🔑 **Passwords**

### 📌 Definition

A password is:

> A combination of letters, numbers, and symbols used to verify identity

---

### 🔢 Password Complexity Example

- 8-character password (uppercase + numbers)
    
- Total combinations:
    

👉 **36⁸ = 208,827,064,576 possible passwords**

---

### 🧠 Key Insight

Passwords don’t need to be random:

- Can be:
    
    - Song lyrics
        
    - Passphrases
        
    - Random word combinations
        

✔ Example:

- `TreeDogEvilElephant`
    

---

## ⚖️ **Security vs Usability**

- Strong security = More complexity
    
- More complexity = Worse user experience
    

✔ Example:

- Online shopping:
    
    - Account login → easier checkout
        
    - Manual entry every time → inconvenient
        

👉 Balance is critical in real-world systems

---

## 📊 **Password Statistics (Important for Exams/Interviews)**

![Image](https://secureframe.com/_next/image?q=75&url=https%3A%2F%2Fimages.prismic.io%2Fsecureframe-com%2FZ08rs5bqstJ97_uz_PasswordStatisticsfor2025_Page_3.jpg%3Fauto%3Dformat%2Ccompress&w=3840)

![Image](https://www.securitymagazine.com/ext/resources/images/Screenshot-208.png)

![Image](https://resources.enzoic.com/hs-fs/hubfs/password%20reuse.jpg?height=328&name=password+reuse.jpg&width=500)

![Image](https://cdn.sanity.io/images/a3jopls3/testdataset/ba3df37e943dab3aaed6d6f2de06314f1f64c7e4-1264x848.jpg)

### 🔥 Common Weak Passwords

- `123456`
    
- `qwerty`
    
- `password`
    

---

### 📉 Key Findings

- **24%** used weak passwords (Google 2019)
    
- **66%** reuse passwords across accounts
    
- **22%** use their own name
    
- **33%** use pet/child names
    

---

### 📊 Updated Trends (2025)

- `123456` still most common (4.5M breaches)
    
- **23% reuse passwords across 3+ accounts**
    
- **36% use password managers** (↑ improvement)
    

---

### ⚠️ Critical Risk

👉 If one password is compromised:

- **66% chance** attacker can access other accounts
    

---

## 🚨 **User Behavior After Breach**

- Only **45% change passwords after breach**
    
- **55% continue using compromised passwords**
    

👉 Major security risk!

---

## 🔎 **Checking Breaches**

You can check if your email is leaked using:

- HaveIBeenPwned
    

✔ It shows:

- Which breaches affected your email
    
- What data was leaked
    

---

## 🧠 **Key Takeaways**

✔ Authentication is the **first line of defense**  
✔ Passwords are still the **most common method**  
✔ Weak passwords + reuse = **major vulnerability**  
✔ MFA significantly improves security  
✔ User behavior is often the **weakest link**

---

## 📌 Final Note (From Your File)

> “This module focuses on attacking and bypassing authentication by compromising user passwords.”

👉 Meaning:

- Passwords are a **primary target in penetration testing**
    
- Understanding them = **essential for both defense & attack**
    

---

