## 📌 What is Sensitive Data Exposure?

![Image](https://images.openai.com/static-rsc-4/Q9xd3U8dSHFhl9BeMQ3L2Yumd0oU5WoOmsKjusWiUE6yspGqIoYMk7xJaPiEmY41FYYquSzAMH6VWaRqIRA5ds3PbY3h42VrTHqlFwoVD0UHuQu_Sy2gYfUrFHy1Yu9e4jeYdrxXg5lr_055ft-xid72nTonEJhUPxE5ZDfHv6XZFSw3hcKJTbLsRi-nue1c?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/p9TXQ7b8CXaExgEYVvV4BbPrnOBpaj5Y3M-arCru6zQx7D0TgL-VD456-iDHk93tVzpEGKfjSPyHr80J7Tbxv8OLAKAAksVo5ED7D2RFCeTWz_LI51y-edfb1jdaTQMSCBmMDjwvSVfJPwh2T8hMqrsGgBuEKkhy0k2x9aFACBZyAfU-CcdqdoyeyntTswTA?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/RaeLfKfae5hg20x59tcRBk9J12LzbPgSRc3nisfUJCbRbApzMuLAOpNYEhBBuLu0qvgJ1rDNuMhFnbTRKp8uMS1lDTyWcAwUqMEji7-BGP3XMHKZIihjI50Q6KnQ1qsbSQsVx5arhrfWrXqvOTVaKW_mnToOmiCxzE9ekeonMOhiJDYaD0JcxpEfCWhBlJ4n?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/YhMuf36KdLqX4U2bL-PU9WejLw41K01NtN88lK03l7UNalUa7V0s7Bmpno2d3wNzHnet1MpBHNDWjLdXjPvSEJrB9A9RymoDs97CQeZvWBwWYGMkDHwFVmAEpbpSNnCPoYRSEQuvheiEpNE3Y8QAXglKDUShjZziU6zKC93bjOfetokdWi1RV48LNo7RHAO7?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/3S5U7UQKZnXLvd8Wjaqw7YhkQXRa_W6VbqUhsfB8XyF1dSiDqb67SfbsQ28akFd6fecwkmO5S9PayaZ1zWCVQQ-KvxBurdLXWkrRcA5qPtHBnGPlf8GvYbDVdtEz-JsXslVYQQPufcRzACKkXyZjbSoy31YWL5kjL30P6qmHusORAnaP2xbwnV8OijrXaOt5?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/_ZqB1Rqv4TK4dWFy0n5Mv2cY5x2fqWRV0BN8DLC940HtUn8hZsydGrsJy_zsyGUS5bLmDsZNILIvT5A46bfQyFikyANqWpNgRPGwnB_KiickkLo1B-5cREwsYK-H0dM55Rov9cfnsz-W05JAAeSJ2eDYED9941ojZnI12fc8AR5JHVEznWit0mRxU0pP1cVB?purpose=fullsize)

- **Sensitive Data Exposure** refers to **sensitive data being available in clear-text to the end-user**.
    

✔ Typically found in:

- HTML source code
    
- JavaScript files
    
- Front-end components
    

---

## ⚠️ Key Concept

- Front-end components run on **client-side**
    
- They usually **do NOT directly affect back-end systems**
    

👉 BUT:

- They can expose **sensitive information**
    
- Can lead to:
    
    - Unauthorized access
        
    - Data leakage
        
    - Admin compromise
        

---

## 🌐 Why It Matters in Pentesting

- Most pentesting focuses on **back end**
    
- BUT front end vulnerabilities can:
    
    - Reveal hidden functionality
        
    - Leak credentials
        
    - Help attack backend
        

✔ Often considered **“low-hanging fruit”**

---

# 🔍 Viewing Page Source

![Image](https://images.openai.com/static-rsc-4/J4GNhn0Nu6DJEJbfbaJyv4nAcFWDeeuPCYdiGiGjJKLf4aUkojdC_Yh31vnbTvayqIrACB9k9rOaP2JFyrh5-Z2CVHF55McznZNnEtVV7X2hS8ZeLMZulGEsB1vG9NjMwrNvk8WzJN7FujZxhHzHo8vdipGdorx40yFARCcMoyQ4oCG21OlHA0MNLy5scjy0?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/FUycmoWmpmSh5NUdfLf6qe7GeQ18M3yDyZiPi2ocVg-ipW0uA1LMPJXkqc7HBGirvbeFVAjdG82JeDAxCqFoRVGfytsN628hEZeN0NVavBJHvLMCNE45Zme0wS692K8LVrkL8rU0nVRiCfi_Yt7W8RMl20D35GbT4xpjO8-GvcksWC0JWNBbktZN_9eOmJbG?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/J3kv9R6amUddkNUTRNegKAert5vL-vxBhqoMEMosh1QCLLpOdebizliMulHFnQq_bz_RtqAeX4Wh5GblCY817nOnsLcLHVAV8uJNXy3UMYc6v6jP6vtVdM_5kUVxLZt0N0f6Ss4QxikeZh2LxLIgTvulgqW6LQ6M7FpTIJymSN5iSNK8u7hzmEI-LE6jjHEo?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/cc1qF-3pXpB2JQz5bX_zh4GWFysKmApFCKntbbmKR9Je3HFv26_5T_EPbzv0L9ZwYCT2HvtJHHuANPlV8OE41VFC3VMwAQmRuUp-59b5Kx7SP1OiH5J_16nBmJ63dr3uDndf6gpp2RozWUUL_Ce6iEHcr47u3sE2dNgWg6KNbH7oR6gMn8bhnwY9qvK8vVeG?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/e4-RNTDwBgvhKPis7cROeKPLzSRWmK1kFRXTrU1kn-Oew1LJbCg-0wSAl2pFcZLzUZ_lFY84K2O4y3gv-NxWCY7L_-S4vRge9-n5m1-1aypfm_NBngdxQ_yfnXyjS3096GzM03crH8IGbz1gVjxEoWVWLVMsAy3se9RhcCqZlXUINVKYsGi8iv9Q2vdIHGLv?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/daxoYYh8vIyGM0rPLpALJDeYvCy9_iGFpYkvq1x7gRvFw8lzrHoxiM3syMt69bEcGWXS3ByPWU2zfhw336nzMX4fc1CcQEtfbQFE8w1wmvQOzcw5dYjtjeGXLcBBNuRcda2Ky0AwQc_udSntaZ1jM4rdR1bOY9nk0lz466iDWCFiVTNV7qYS6zKtiBvpoYD_?purpose=fullsize)

### 📌 How to View:

- Right-click → **View Page Source**
    
- Shortcut → `CTRL + U`
    
- Use tools like:
    
    - Burp Suite
        

✔ Even if right-click is disabled → still accessible

---

## 📄 What You Can See:

- HTML
    
- JavaScript
    
- External resources
    
- Comments
    

---

# 🚨 Sensitive Data in Source Code

![Image](https://images.openai.com/static-rsc-4/Q9xd3U8dSHFhl9BeMQ3L2Yumd0oU5WoOmsKjusWiUE6yspGqIoYMk7xJaPiEmY41FYYquSzAMH6VWaRqIRA5ds3PbY3h42VrTHqlFwoVD0UHuQu_Sy2gYfUrFHy1Yu9e4jeYdrxXg5lr_055ft-xid72nTonEJhUPxE5ZDfHv6XZFSw3hcKJTbLsRi-nue1c?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/z5LPOqtffFzqgTyvj1Zxz3o0JtWD74NrshHXt54mb4ISwZhiC5FvGhqS-qAWt0GHGOtaztgIAnlR5ph7t1UMZ3f7VqOwZqMrpJdFBY_2geNK9yf94oOM4ZC8jIuBX9nE9P5Sf_Jk3fDEpEr9_BgA21ux6q-Ng9Uxmko6cYa5HB8_inbx3e8ouznMeY5JNLWI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/oJVINfBao63Dl2FEYRWGZo6BeJn8xWWAE6tVGbRs34s5MXDlTFkuz6puuaqlUxi13VYZzIQBfmL2iZEyL_7toT4VcCJcDgyPmvY9YpapmwJ4G0kOEKNvoV5scZR353RGC5J9k8cpKql_ziffxgJk2GpENH11S8Pb2CaMfWVKkrh0g-6UVfrcaufqf4wzvdNn?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/E6l9MCEzXFd_QZp66dPWqdIO1TxaLBe5UYREWVmaJrI3iBXZhcM8IAvLHIdcfTQRDuO0YrnxIopHpgMQaRpsIHy1U3sL9jVFnaPhghfw8a-BwL2_DmVpdQe9vaIH7xVO-gy55l58XKu3FEBNeZr0bhsot3oJ1t1-zsCPd9jLcHunnZBGfcWM4AZ7bHVEvj2p?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/sMIjrrSgPaJsnoEqQw-klXE0lWfbS4IBFYPqkHM66Eje0s-lmOf9zqf4_tWlZ--8w4ViaTaAFV7CxQb2VhOFKD4FN0fvj0SydHdr1mCDT2NM9zeguFVqSIheuWHYTg-EnhR8vghOgW4lTIey5QbIeI7H1RRKGU3R8zLP61Lio3acDpew_Xv295edtAwiWzaV?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/2mN_wnv3hBpBhOherwOl2T2XQ4dFi3vHMJC-qdas9BFPajMbNheNUXS5pjjhVCE4WloKSSjvSKApSfDBarKUSKCrCEn-TElXNMRDK3WW15PPweHt0GE-77aILpHV0iOB-mO-ETSxvr_8piQzi51BBVnzv3802LircjkwM6Dw76yCYccQikjWfQFkVDOWopy3?purpose=fullsize)

### 🔥 Possible Exposures:

- Login credentials
    
- Password hashes
    
- Hidden links
    
- API endpoints
    
- User data
    
- Debug information
    

✔ Often found in:

- Comments
    
- JS files
    
- Hidden fields
    

---

# 💻 Real Example

```html
<form action="action_page.php" method="post">

    <div class="container">
        <label for="uname"><b>Username</b></label>
        <input type="text" required>

        <label for="psw"><b>Password</b></label>
        <input type="password" required>

        <!-- TODO: remove test credentials test:test -->

        <button type="submit">Login</button>
    </div>
</form>
```

### 🚨 Vulnerability:

```html
<!-- TODO: remove test credentials test:test -->
```

✔ Developer forgot to remove test credentials  
✔ Credentials may still be valid

---

## 🎯 Key Insight:

- Even **small comments** can lead to:
    
    - Full account access
        
    - Privilege escalation
        

---

# ⚔️ Exploitation Impact

- Gain login access
    
- Discover hidden endpoints
    
- Access admin panels
    
- Move deeper into infrastructure
    

✔ Can lead to:

- Server compromise
    
- Database access
    

---

# 🛡️ Prevention

![Image](https://images.openai.com/static-rsc-4/RcdjPRxIrQOSkRIwy1qvjG4G8dkid8aiVNEE7iaODKhYl-2Fm8wxVcMSrkXBKFEWIeLE9Mz-Fr3_5sFmdU5qL0Lw9a5GuLEfGem6ek4r2mAchM-9fN9Ve1euHmR44kcwwoRH-DCUDJHAxs98EBL2Ejv2dPSuP3bninvScgbdDh2ddubfiPDnbwjigIYF_Gk8?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/RLKfGLrZ4pPVXROCpyCTt9mtWokOsYZuG-ULx_OaaBPQiWJEa-QGiMCwG6LvHXopRaAohwRQe2EdFYLuEqZmFD3e54o3mxZTy1vw5eW56cupMHT0WcKDqCD93l9LuzDnS0RSZAf7fqfozsoJOcM2lSjtqIW7QTacDMMbwU3wNxhJ8zCxjW9oXG2_RFm5Cja0?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ooJ4JLCqBElPXuswUMOXl54Gd1j6uNrlUhlcz4odgDL_njRInf9x5k9BxhJAq0MW3sJ1cLA0X8JFNpHHGANFBlcSYUlQKWVM9YUVhrdGyY2QlLFDgj8UfNZFkmh1xvvDO9ogY-_3chgkM9STDiESq7CWZaX0ID-LuIVHCvHfvrIctiNCvBkf8qHFgaTAZVQf?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/aqPbzycZRBNJ6wjQBNT7NVYc2A8tdFHBKEsLtAHHk3O6qLrym5mHa293d8foRSlKZNcDikaXSmmJ9y0lkncpqESfNjevkVpmit8youpPQdw8GsS1RbEr862JYmn2LIqRvF_RhIdlXtYK-5cg4xYwy9ygBv5kjKWPy-hQ67bZ3NoUtDyU3rU5Jl71-EXnYg4h?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/0B0YhHjoMLFhKaID7Pos3fET7bkw8l6diAPQzgJvFt5-Hk5HmS63r6G6SMY-2kdoAISU6rXSieTIcmXsHAPszFet-Sb9zjspwX0fuW9oMJr_f5BvUAO9XmjXewOvmRNufwQP_2tNF43NIPTgMi3yFz03cGWz6l3RFCHXTKcT5MvyrD7pZo8BuxgLBk5XCECs?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/QlY98bsSfLCUjM3W5HsAQAqbPjP-XGh-vjp6R9PETF20qLcz-FetzMi6TMehl0AVyDjv3j2S28riF2_wZ5RzHYLzwhruxzAhoGcy-jKh5Ma7iGsc8EPcN-swtd8vSwKnscDQSEasJUl2eCt9dBg9zn3c9I0cTrZaGOrehOV-S6ABIHPz0uWHWCTTF66BD-nb?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/g52uMyY8Dc7RNcbAIQLLL0LQwpTdg5elXd-VPahqI3iPO0R-pKGAiZe-oyT0VSCPMhS1aXnR0p_FO8VNDmzyyCbpkmf83vBWQioetJ2hkpdzsnGDP7SgAjjWBJH99njf4pDsePiJNiQFqitj4wAb8dGLPn1SlxzV02GOT-6SiQKNfHWdEdZ4BibGM0VC3_kO?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/HajRX2Fa1uErrvbFBczlGVbe8tWF2ROrOSqHS9T_eY1NVNqt6KhtxMR6SnRXJpy4dsYISkYsLKaBgF3Cxc7y1Fo4mAiON2-r_E-0kF0e1GVtAPWDLekYTDZYYDqVRdmsQ_U1NL4GP1DQRTEsMp8PhABMD6ehk8IEYr52aufJqaBeiB-GmU57CWnjiqeIZC_R?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/qhIIoa18F20a6ixVobagR2pQ0CiNWPNuM6UtdFznB_uye9Jxbm2b1n9FFCdbS6AXEqmeFM1VP4aM9iINREtQO1E0_eduWCKoYDR7m5d_TfElT_v1sLt_pAcM13AKDQ5RZYcQXBpO0t6cy4-D4Eh9onUkpK8YTord_7FVY3quKb7MwS5zX1lysaQl3GdLhcOM?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/AfKyzjtGbSHpenV-Gur6So73esLheYsEw1xlCn5Te4zDnephUyR1CjVSy2GgZd31ucZI1_jAK9AIXzd1IHNd66IdZAso3pLy76Jpl0wqheA-lAwHjfWkQBA8GTWm_YLVuuWWqBGJ3xm9w7CuGk6vSwzQt_PKyO-rOQrsE-_oqMEoEPznQ5jVQ5W_tesvy207?purpose=fullsize)

## 🔐 Best Practices:

### 1. Clean Source Code

- Remove:
    
    - Comments
        
    - Test credentials
        
    - Debug data
        

---

### 2. Data Classification

- Identify sensitive data
    
- Restrict exposure to client-side
    

---

### 3. Code Review

- Review all front-end code before deployment
    

---

### 4. Obfuscation / Packing

- Minify JavaScript
    
- Obfuscate sensitive logic
    

✔ Makes it harder for attackers

---

### 5. Limit Client-Side Data

- Only include **necessary code**
    
- Avoid exposing:
    
    - APIs
        
    - Keys
        
    - Secrets
        

---

# 🧠 Key Takeaways

- Sensitive Data Exposure = **data leaked in front-end**
    
- Easily accessible via **page source**
    
- Often overlooked but **highly valuable**
    
- First step in pentesting = **check source code**
    
- Prevention = **clean + secure + minimal code**
    
---

### Exercises

![[Pasted image 20260410175207.png]]

