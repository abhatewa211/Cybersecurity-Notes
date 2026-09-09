# 1. The Big Lesson 🧠

You will **not** always encounter:

```text
WordPress
Tomcat
Jenkins
GitLab
Splunk
```

You may encounter:

```text
Custom application
Unknown web server
Internal monitoring software
Repository manager
Enterprise management platform
Old forgotten application
```

The module's core message is:

> **Learn the methodology, not just the applications.**

Large assessments can produce enormous amounts of data—for example, the module describes an engagement producing an EyeWitness report of more than 500 pages.

---

# 2. The Pentester Mindset

A common mistake is:

```text
Scan
 ↓
No obvious exploit
 ↓
Give up
```

The correct mindset is:

```text
Scan
 ↓
Collect information
 ↓
Filter the noise
 ↓
Identify applications
 ↓
Fingerprint versions
 ↓
Research functionality
 ↓
Check authentication
 ↓
Check default/weak credentials
 ↓
Understand built-in features
 ↓
Look for known vulnerabilities
 ↓
Look for information leakage
 ↓
Chain findings
```

The module specifically highlights that scan data can contain things scanners don't necessarily turn into an obvious vulnerability—for example, weak/default Tomcat credentials or an exposed Git repository containing an SSH key/password useful elsewhere.

---

# 3. The Most Important Concept: Chain Findings

A single finding may look harmless.

For example:

```text
Open Git repository
```

By itself:

```text
Git repo → interesting
```

But investigation could reveal:

```text
Git repo
   ↓
Source code
   ↓
Password
   ↓
SSH access
   ↓
Internal host
   ↓
Lateral movement
```

Similarly:

```text
Tomcat
   ↓
Default credentials
   ↓
Manager access
   ↓
WAR deployment
   ↓
RCE
```

This is why **enumeration and curiosity** matter more than simply running scanners.

---

# 4. General Application Attack Methodology

Here's the mental framework I would memorize for CPTS:

```text
┌──────────────────────────┐
│ 1. DISCOVER              │
│ What is running?         │
└────────────┬─────────────┘
             ↓
┌──────────────────────────┐
│ 2. FINGERPRINT           │
│ Product/version/tech     │
└────────────┬─────────────┘
             ↓
┌──────────────────────────┐
│ 3. ENUMERATE             │
│ Pages/users/features     │
└────────────┬─────────────┘
             ↓
┌──────────────────────────┐
│ 4. AUTHENTICATION        │
│ Default/weak/no auth     │
└────────────┬─────────────┘
             ↓
┌──────────────────────────┐
│ 5. BUILT-IN FUNCTIONALITY│
│ Upload/API/scripts/etc.  │
└────────────┬─────────────┘
             ↓
┌──────────────────────────┐
│ 6. KNOWN VULNERABILITIES │
│ CVEs / public exploits   │
└────────────┬─────────────┘
             ↓
┌──────────────────────────┐
│ 7. DATA LEAKAGE          │
│ Credentials/config/code  │
└────────────┬─────────────┘
             ↓
┌──────────────────────────┐
│ 8. CHAIN                 │
│ Pivot / lateral movement │
└──────────────────────────┘
```

---

# 5. Honorable Mentions

The module lists several applications worth recognizing during engagements.

## ① Axis2

![Image](https://images.openai.com/static-rsc-4/BrRy7opKQ2iQRl1rFjWZMmi1jgTzBGxlBf1MRmkEbyto54jmX-G0ozfWCewEuf6nRUsCpTU3ycRL2sGRrADAcL6RI6Ga40bP9WXtlVPlhngS9uf8DMFHbX_X8unJwdz7gt2W41Ly7_0zW6x1o7Rlmr1AW4k3xQ8HojjoDgDPM7GXr7-So2e-w_zvOVtaDIze?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/05AWmXMguoKGpcpHeCULluDaVSjHcxPtSFksZTrU8UEfQ_xarz96PV8c1R0YuD0cHr9cjMzu2BONRvEhJeJpm9fiEkUfubELKK4Unc2aqco92yzTAQ24bAk6ZSVffWQo5NdBPNnlmtzu-wiPAWxBSbparbx0iHp1FrhSDlPam-GoFL4lGyRdazlCa3XGaBY4?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/n8Pb9DW0m9zlDXkIbMK6Q5Y3TiIIDi7kWcXf7-clkVtvRB5BDGDVzcHcu5UDaQo43OCTajo53HtHZ5SYN_V-Fq2BD0JE5nqKfp_RILF9AwYtCP_TZjz2JEc11XHWzBEOlnpMMJ5u2Z-J7yYCVIqINMinADjDbYeX1VV8DAMgONqq7n3Sp7aTcNXSe94lkEgM?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/8G8hwLoUso7AuZv8x-lVEu-sysQuGggcbZOxu8RzvQcMnToyJ8p3NyqKdXK1RpUqM7c-H0oByKSdhyaSQX26KCkxfqOgVltA8eHb7ggMCt1hWNFCWn-MPUR5W-hLMzV97n4Do7mXARLygp14DOxpxB86jEt2FP6n4sQagShJSlhC8RiRYWcD0RlZuC2hxAuX?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/TkyRk_0_UvygyJ93Pw8jPdbzQU3pDefjHyAttXHjmutbKe3OZ2p0ki7XjRGiVpHkYqJAcPildISVfmbSST6S7xmPXvz89LH92iAR-gUz1jHKsqpAPV7VCChq0lr0NLD_uQe4_QmrICYv2RZujRMPdfDqkNL0RZCzEsqiOoJmYA_jpq-A9yBfV24XQ1bQ8_-E?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/LCByjC7PUA1fPvolR_t5_04j91ZFJNnR3F-ET0jhiZp8FB_3c2wlpc6I1198vTeUO8yJs2boI8zRyM6PRkHMUML9LW_0yr2JZ6qpiuDxJpP_9NOMHH8GcSqOsQRvVyH1tNJS-XLYoIuCxZ92iWlYyNrEmfDGLDcEXtBxIRsdfC9xnVVyht3RPWI86BdlPxIu?purpose=fullsize)

**Axis2** is a Java web-services framework.

Important points from the module:

- Can be encountered on top of Tomcat
    
- Similar attack considerations to Tomcat
    
- Check for weak/default administrative credentials
    
- Administrative access can expose functionality for deploying services
    
- AAR files are Axis2 service archives
    

The key lesson:

```text
Tomcat
  ↓
Axis2
  ↓
Check admin access
  ↓
Investigate deployment functionality
```

The module specifically mentions an AAR webshell scenario and a Metasploit module.

---

# 6. WebSphere

![Image](https://images.openai.com/static-rsc-4/CB_0PdcmsuiRTroQX50zXwSWuWqfFpROEHEQNLanbXgBYu9yaI-bxMr7PK_R6heFt1-5D3e-RYCt08ncoT2iAmmiljHTTOpNt_QNguWtTk0qqxKqYVHI3ahoGhYDdeemHAirjXQP1b19E--LYc05T6TBiizvcF_b219jshPZINrm9hg8GuOt3X-hUoK1CXEM?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/3Gr_9euci5ZWAsDfUvWXJZjqqAPnPnvLNH_rQbVlAzZ6b81rlomIhHz-g-kmpLE9mPqD9Nd95kQFe52JKm9mv5s7FmsqmRimGjeDWd2t7EleX5pPBf9oVRLg6_O3GOMrAFLrNtDzlxIovVkC14PO9H1HN3G-C3_XYVZvOY0sbc2uIiCr6ZX3X1ax2VEt397b?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/OhzWNZjHURVNxn_ivFrS5InQWJ9qPRirgv-e3UFC1YCsiVVhKy6u5UA6IKHymB64tRKjVMOW3oOGPEVaqkbjO-5BgXfmGCqGiV2-QiWG7hwgFrX_CRSFRSXhhmAWdtjxKMtjOh5r0iHcomucQE2Vt7OD9KT1j80rxPJBCDBXy6EK8sW1-O8szdSmgSSjTI3r?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/0zJUHMQQvM5FobBbyM-xOju0W_fFx2BhYKrNOLF-GJyzZ6NdW2Jmvob9pSu4DWzEpjfQMvRPZlZkhl7C3H_1eJdCfYbR4Mig0iH8ZsfzpL0LOGpsgeaQ_0FGWZ5kUpphdoRhGScHG8Ahw6oWbWqtSPmCfqIlw37Pi5VS8XQ62FfT7Ju37IOLeVUbjtsHDFCc?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Jnn1WKjptZM0KXil7WSZcaWCaynlzkvnMqsqeTe0IBqTL8-8OG1nuqejQnh0i4rINGVa23Di0BM6KaW5cqn7o0Ha3ZY5YBw9sN8yyYI4Sa7pUqHJymFeRyhgixOQ4GDdOxOSl50XqsO3F8SmPWzncSVNw03QPQRA80OUDSYNL4egNPCaTNiyZA2Un5l2ufcS?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ktNiKN2tVwMa0yiX7v3MYhdaryLqUuHXC41nCw_IlT3cyQF7m0BMTPlZL41gDkNh1SoAw67iPqZ-BT512X3Uex0hHoQ82gqZ5-AHMT-COWDSdGQ-XM_NoUdwOWJnpyl3mLj_wd4CnoyamF5FeVcuXfvnWvpk8ZhDacWf_yr2rt9HViqTzE8-ra-Q_LbYOr0_?purpose=fullsize)

**IBM WebSphere Application Server** is another enterprise Java application server.

The module highlights:

```text
Default credentials
        ↓
Administrative console
        ↓
Application deployment
        ↓
WAR
        ↓
Potential RCE
```

An example credential pair mentioned by the module is:

```text
system:manager
```

### CPTS lesson

If you find an enterprise application server:

**Don't just look for CVEs.**

First check:

```text
Authentication
Administration interface
Default credentials
Deployment functionality
```

---

# 7. Elasticsearch

![Image](https://images.openai.com/static-rsc-4/H-kYDY8GNQrfy6avV0929OJ7psfR4TKVdu7rAHAO62wwnwHe-9h92FdLxjXK0RaJZALUFW2DGikfMsEWZL-pAmfdctp1q9Gk34u9r762VAj0c-AmCpRurwiDtmb7lpnzblEcjwX7npMAR8DWH8YP8l3PW5Ij1Tsk27031gmqgtBuVAauKOxzBahsg6WleCO3?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/UdagHApbPHyVaPfYF5RBJaKF60q12yga3wMrXtoVRkeb7ylmGnuvGl8yCp2JoTAhOj-W_2y-ghpGmzVngM7RFEw5upIahU4yKe4Vozg1__I3VfQW7VZ1n4BnPIL6Rr8PeCuB0HvH72Hwvfw4wHVJZ_4BsEit56bvekmo-RsptproGubx6CfAhap1dcJNfHsz?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/1J76Im2a_pbqNl9duEr1iyzMPjPxf8SqNlYjx3SfnFeo-zsy4DgPiV0Z9Ca1vOBVVFepaFKYjK45ekfk6daICbIUv3A8NxS-82T3GqJUY70l1WaQ2RBN0u0HNcGbDIPHQRC0L-ejSnZRVRmctlXBpgCP0L6oeSqt9ZwiGopi3oF_BOH1loj143LZX5uN8Xg1?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/iwJSVhCifAvSU2d_N8_hDeRjhnHsd1PcC616pV0YCSDkFdX8lPNBKQwL6AQg14-HAxqGrYnjPTwtTGqClL0SxPwEBwxHFjKqF0W2AuYVZOKre3tvcF5tpJWpg-MlucUBRivWYS4K7yhjnRWKqr8Gnu6hXqDdn9AlcGv_gi9kNuF-ozjnQFNsglCLMqTHFooS?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/DfT4WM4JCXLnURiGA-PGE95rivUspBjH6OFbXuEsd186D596_AYwTq9Birxkw4WKBRvMs9xDbUrXDVUVqhZjayPskddhCraRYAPtwZnlE8ew2Wb5N5QhSpAnlKwek5txYbutPI3E4vEAEgynJ-aaGxSnukfDaJET3bx9BB5zq77DaPwlQfnaCR9camluHw42?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/IbDn3__jVxRXPD_XLt79CyFKuFnAzvqodvIkr12m0SxL-tzdjN7mj8Gh0uYO6C8gqnkRxiVFn4LPTYm6jpp1AouSzuIXBljHz4oSoAssxXhedeK8tXcDGYWdqJmtpE_Tg6pdOCSHVWxm6W9xJrkZ7k8Uyu1P5phb4na6b7sRLXWNo62a3VaQ0069Z_ciBpf8?purpose=fullsize)

The module mentions **Elasticsearch** as another application encountered during assessments.

An important practical lesson here is that **old/forgotten installations can remain in enterprise environments**.

The module describes finding an older Elasticsearch installation while working through a very large EyeWitness output.

### Mental model

```text
Huge environment
      ↓
Hundreds/thousands of web interfaces
      ↓
Old forgotten service
      ↓
Fingerprint
      ↓
Research version/configuration
      ↓
Investigate vulnerabilities/access
```

---

# 8. Zabbix

![Image](https://images.openai.com/static-rsc-4/w4k1leLv_t0tsJOJIfTw5d4fiKVskMqNedwwppoi15p8dY1bKXUAt1wkF6pZpA8y_k9PahMUPHzs3m-Hz015BC8XrubzEhKv9tKMAxyzJXOogkKVOP1PrZqbB2UmNT3An_O1acJmNeVepwrqqJI7r5O2nnajRIhLPXwXPt2o8wiTW9BU1L5IHKtSUBxcdvXe?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/FiyUlpVGMlaVnHE4Z4_hU9SdtV90GGyCnSjDwoj2IH-DYr87qTWaWW33nSufzI5MDxC2DZikD9OTYAz-lhJlUlcPofPaOAjobAMnF-Rnqo75HS7ARa9OGNTgYYFchXrq9VngAp9xiUX6O9XJZBTnxCrL02VneYSbvibx7FmgK7EDL3KsmuSCjAhHVRIvSDLv?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/o2skavNuY0HoB_j7C7-Hzo5ZXyUKUodnXwMo8zB4Xr-7T8tPqqtjYANeIlna31iPHBBQgG_YbkNANE9HXG__FywzVgV4lj0ZxjTgP8hA4bYRZIDFssOdPbPD5o8-NtMJVg8Ff-U86e_NuE-FwyQ8cNxXEDw3iIHEH2tZ8hSL547a8YbhxPp3t6Vm1KvbqmXa?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/DrNGzbEVGVw0hbxUF99lvJLMGKAG8Gl4O9qnt9ScnLUJgqsatzv_YhrMeI2cDVhy8RQy34wBdU7UX2JhBLn-X0lcxdak4RDwK0qL4GeISZubwGqeFjCJK42t_7dj1Et62wHv7aSawx2myQmIJMQPm_lWd6Se4MyS1mkhFUdZ5aNwbJmR22DpIFhYtbR8XtJs?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/sbci-_Oi13LAwTdYw7--WdinXvGVuO2WnAR9IP2RKsGQUpyPnYM2fuC-eUfDVuoDniLufOBwlVWt0-9kVc-hppfmHYG3vn8FWpurdpvExtrq9EbuYjE_JflB7zfZcKF-pW56nF4FhZGpg0Y1wbljh2kpdqsH8Jx3UskDozFupm0KOVdh-w2AAInOWT4cfxWi?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/KDJAUpaX9LdqQotb5SyKoA5I1eIyiFZeNaeenSmyyipTHJNWl25rOXnBaD2IB-BOQmQhXIlVtVOVQVZzZckMotFONXKJB9ugZeEGBe1lTe_X2qjm9oz8FaK8KAIZyy4f_mg_xje94RSAoUnNQhYi7j5xEI64N94w7lpxfwYuayd-vAlb1rwgcf-FlIAROvTo?purpose=fullsize)

**Zabbix** is a system/network monitoring solution.

The module mentions historical issues including:

- SQL injection
    
- Authentication bypass
    
- Stored XSS
    
- LDAP password disclosure
    
- Remote code execution
    

It also highlights that Zabbix has **built-in functionality that can potentially be abused for RCE**, including functionality exposed through its API.

### Important pentesting principle

```text
Monitoring software
       ↓
Can execute actions/scripts?
       ↓
Can those actions be controlled?
       ↓
Potential command execution
```

This is the same fundamental idea we saw with applications such as:

```text
Jenkins → Script Console
Splunk → Scripted Inputs
PRTG → Execute Program notifications
Zabbix → Built-in functionality/API
```

🔥 **Recognize the pattern rather than memorizing the product.**

---

# 9. Nagios

![Image](https://images.openai.com/static-rsc-4/02ZV7QFOmJ64Dm1w_4Q64enZoQIL8j_6Ailck9dnESqfE7qV_u5n_ZKW9oaq8Na8HR1plysTxyaaolmG8YPBmyrxH1tWSFFy1hMBJzgQyTc8Gt_T2xrYW1jgj5n_rbRqRj1xyP4IvIkLDv_gZbypJwvouiQQwYO2tsQwgQtGJJWps2n_kKDyyMSl-rOhBnk0?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/YEtW3jld7y7-zSGDy3vKXIPD0CN_VInybKTQ-0LOSDIW2Rf4lhKEfUP1XqAW1xwOt-q-dQotdE2s9LSMbB0nUhCgMz38yWXT6zxOsrGUWTOYtzZYnCsr__TrC-EQ667a3_tfesR4cGMCFcZTOh4dPnkhWJdEkWvy-o-HZp3rihWj_2k1ehV6G9b1NKNnNeaE?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Av-7CtNkcPnLNwRuCMS3eviaP_7JVrACYqV9Pd1ZHDfFahNzarIi0bgiY8w0WNxPF6vsBpgXU-wMI4tn0DzwPszPBTGzMF8H4EEqj06fulf6-KAoHr0YZ6PUyFH5C4yqxP8Ws0yC_84r92rPZGwcy9UkWGF95j4tUlf4d2Ko8dhtqaDihZ2Ip0KyFYOjaXTT?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/sXWY3FHROBycPMNdD7rGkIbJcWTRI8pEi10ymC5CxK1rYHsvmf8k-tn_B9UpYvQr4kirXzRF6tDdgCVbDF3_sHK8thVDOOF6ELxJuZdIwWTQwokhMBCkhw_80r8CeqrKZP-4jpuK4CIachlhuNN-ZTVqzRSmHmgDAPdDPQm7v2krz3NW85p221-wr32jYzVe?purpose=fullsize)

**Nagios** is another monitoring platform.

The module says it has historically suffered from issues including:

- RCE
    
- Root privilege escalation
    
- SQL injection
    
- Code injection
    
- Stored XSS
    

It specifically recommends checking the default credentials:

```text
nagiosadmin:PASSW0RD
```

and fingerprinting the version.

### Remember:

```text
Monitoring application
        +
Administrative functionality
        +
Weak credentials
        =
Potentially serious foothold
```

---

# 10. WebLogic

![Image](https://images.openai.com/static-rsc-4/BHdNh-ASbeImne3eHnjyvekrEGU51bPhjBA6bJZDIBEGS68UrQFNfdRcWbS4Jr-qwPv4TBiLpaa4pvJIbsxH57CedyoGnAsrdIkNJXQM993f7lFzQY8E0U5caEdmsMmRywMsQzuuS1IyJV64O9nHe2g7Y9rLUZkLnsq530Vv74kMXc9ZY6V94K65bqppbyAA?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/PEAxAP11wQCrXN6aYAu11XXFi-BB-CmW64PJXL3BGfWeGkBcpvtwg48tZoc3Eh6YP3RNCuSipBO5fewfHwiqskdDnCf1YBcN2tfPKbWpfDNQfT17Z1LA8tdDM8KBzeWuJ7_6eUmucGgtZu1UE7r9KbTLz0kDdncacTm0CsIK9ZXNYmE1sJhS7UM2dsiPIQEX?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/UfaMjcvNfKAy-2ewIx1FGJDF3_QahoEcH19R3HpBo7d06Ogl2Q3xQ0Ha-LkO7U_avZ9AvGnvkiXufpSFgQc1sA_jfx44Vq8GfkWlrq0RN8AUUTIf1Hagj8rfqDsg9sgRqa4FHDBZYpsvWsbtqQH4XKZVvv04ROKod0xw-BAhrtbSPKPE75XJ8OQrKu4RxkHx?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/I6bxZRhEZ6rB-JX1iUb9Jq3xtezMRQkHK7WMdFeH9dK_7GwgRoJOe4Qm8Pr1hQWKDO6eHF3jyLJKiI5hdCDE-WG00tDXqcEuGk4jPrsTWUTg_r2hvomOIifq8D4y0riOc1VcRTwoTHoydarf0Qa6eANZspikL_L1jw5WLYeLzAW2_hYTTJuv5foJzPggmXhE?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/vIKrRvAbsKsXi_CfcilHleutqSM29_t94Y1fcYtYPFAH4TfKhzgniuihMZPAY3UYf3Jf5fzDVoBrnKPNkp64gRU-SPQXwj9PQ6i0huv9typcZpdw4ImUuwVQ6BPpT6OkNsm41YfIkBn0KQ3YxkWrPNtwkLs0qaKyiKq23h_CZeTEH57PSMEDA3MLR0W-_dk3?purpose=fullsize)

**Oracle WebLogic Server** is a Java EE application server.

The module highlights a large historical vulnerability footprint and multiple unauthenticated RCEs, including Java deserialization vulnerabilities.

### When you discover WebLogic

Think:

```text
WebLogic
   ↓
Identify version
   ↓
Identify exposed interfaces
   ↓
Check authentication
   ↓
Research version-specific vulnerabilities
   ↓
Look for deserialization/RCE issues
```

---

# 11. Wikis / Intranets

This one is **extremely important** because it demonstrates that not every useful finding is a technical vulnerability.

Examples:

```text
MediaWiki
SharePoint
Custom intranet
Internal documentation
Document repositories
```

The module specifically notes that search functionality on intranet pages has led to discovery of **valid credentials**.

### Think beyond exploitation

Search functionality might reveal:

```text
Passwords
Usernames
Email addresses
Internal hostnames
VPN information
Configuration
Documents
API keys
```

So:

```text
"Search box"
      ↓
Information disclosure
      ↓
Credentials
      ↓
Authentication elsewhere
```

This connects directly to what we learned in **osTicket** and **GitLab**.

---

# 12. DotNetNuke (DNN)

**DotNetNuke (DNN)** is an open-source CMS written in C# using the .NET framework.

The module mentions historical vulnerabilities including:

- Authentication bypass
    
- Directory traversal
    
- Stored XSS
    
- File upload bypass
    
- Arbitrary file download
    

### Enumeration mindset

If you identify a CMS:

```text
CMS
 ↓
Version
 ↓
Plugins/modules
 ↓
Authentication
 ↓
Known vulnerabilities
 ↓
File upload
 ↓
File access
 ↓
Potential code execution
```

---

# 13. vCenter

![Image](https://images.openai.com/static-rsc-4/nLexZhr5e45DRBmpvk81IqrQX_yYsWc1TgGwKjOTmZfAVTNfKigbvV15wh_skwTlP-TeK9EoOs9ntoYqJgWjDdAExmSNnZoB0bskfAP6Qwk95J_JG4R5NjsL_JMfrUKLClnOI2pNrtM2OAQ10PazX7_FUyJ1aNRmYxcpR6b42IMcOaLKkawFPsg4a6QXcEmA?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/yF0idCrylt4Iz-tRG30qxmzPWVzRpA_cJhstqSHjEnF1aGshfn-_bD4nKi1VactQ9I8QKTy61EJbuSR_yEikaWuZeAD8ceCJsm2rN3HDChTyY5_GWyBCbuVdrd4v9Eczn7KCOPpU1uuk0KvRd7btdONrf1XPsctfmYfb8ZIIC2T30p97PBj9Ca3EQnYIqRKw?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/xaFdD-vMVAJsheP5N2nSkPQBVrW5Ta4N6TGq_SD_28WqNkXDkazf-C6BjEEXsoZArx171_YoNsvwwKyFdvXv55PUN_MqKy-qouXVMI_YRkBZ4KAyWjNMCSJlGY59qBKrmiEmicAMY3GgJV3sRRDzet7ET8XReepB8daXKpIWnnEqiwgcBQgjIsYOAXGWBxRq?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/vsBbixNFLcG-BaxHS-c1zmdGIWDZw_csajIX0ZYRQeDYok73qtd9ZGxsZAgpydbuKwa-yj4RF6UlBz7e6nawm81V0diP1VZ_n0p2VrRNv28CPa0INnwYiRLY7MlvDKKDdO_sJWXDUTn-J-4lpz00pN96HBcGN55vuH6_bPB7kzNyHIrkNRD-0wNzgJHyFCB2?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Td39uFV948xDXUSyat69MICUGVphL4Pi1eIGhaoMl8WbXxFA3FOYG6T65UJyMq_tamuE1TJR4C0FD-IKD-28PQy_JvAsj89k7dmJytKF9aQoCRkvtaRUMp7--pN5Lyc96vBR0aB4QyW_BzP1Wg004i6NL_ngZqEYhvmaYw-Og2OPRqdCo7sPH7TSrNUUon3k?purpose=fullsize)

**vCenter** is particularly interesting because of its position in enterprise infrastructure.

It's commonly used to manage multiple ESXi systems.

The module recommends checking:

```text
Weak credentials
Version
Known vulnerabilities
```

It also discusses historical vulnerabilities including unauthenticated RCE/file-upload scenarios.

### Why vCenter is high value

Conceptually:

```text
Attacker
   ↓
vCenter
   ↓
Management of ESXi
   ↓
Multiple virtual machines
   ↓
Potential enterprise-wide impact
```

Therefore, compromising a management platform can be significantly more valuable than compromising an ordinary web server.

---

# 14. Application Categories You Should Recognize

Instead of memorizing every product, categorize what you discover.

|Category|Examples|First thoughts|
|---|---|---|
|CMS|WordPress, DNN|Version, plugins, auth|
|Java server|Tomcat, WebLogic, WebSphere|Admin console, deployment|
|Monitoring|Zabbix, Nagios, PRTG|Built-in execution|
|CI/CD|Jenkins, GitLab|Scripts, runners, repositories|
|Repository|GitLab, Nexus|Credentials, source code|
|Support|osTicket|Users, emails, sensitive tickets|
|Directory|LDAP/AD|Authentication, enumeration|
|Virtualization|vCenter|Credentials, management functions|
|Search/analytics|Elasticsearch, Splunk|Auth, data exposure, scripting|
|Custom app|Anything|Source code + functionality|

---

# 15. Built-In Functionality Is a Huge Theme

Look at the modules we've studied.

We've repeatedly seen:

```text
Tomcat
→ WAR deployment

Jenkins
→ Script Console

Splunk
→ Scripted Inputs

PRTG
→ Execute Program

GitLab
→ CI/CD / uploads

Zabbix
→ API / monitoring functionality

WebSphere
→ Application deployment
```

The recurring question should be:

> **"What is this application legitimately designed to do, and can I abuse that functionality?"**

That's often more productive than immediately searching for an exploit.

---

# 16. Default Credentials

Another repeated theme across this entire module:

```text
Application
    ↓
Admin interface
    ↓
Default credentials?
```

Examples encountered in the material include:

```text
Tomcat:
tomcat:admin

Nagios:
nagiosadmin:PASSW0RD

WebSphere:
system:manager
```

The exact credentials are **version/deployment dependent**, so don't blindly assume they work. The important CPTS lesson is to recognize **default credentials as an enumeration branch**.

---

# 17. The "Scanner Doesn't Find It" Problem

This is probably the most important section conceptually.

Suppose:

```text
Nessus
   ↓
Nothing critical
```

That doesn't mean:

```text
Target = secure
```

You might still discover:

```text
Weak credentials
       ↓
Admin console
       ↓
Built-in deployment feature
       ↓
RCE
```

Or:

```text
Git repository
       ↓
Source code
       ↓
Credential
       ↓
SSH
```

The module explicitly warns against becoming discouraged when scans don't immediately reveal something exploitable.

---

# 18. The Universal Enumeration Method 🔥

For **any unknown application**, ask these questions:

### 1️⃣ What is it?

```text
Product?
Framework?
Technology?
```

### 2️⃣ What version?

```text
Version?
Build?
Release?
```

### 3️⃣ What does it do?

```text
Purpose?
Features?
```

### 4️⃣ Who can access it?

```text
Anonymous?
User?
Admin?
```

### 5️⃣ How does authentication work?

```text
Local?
LDAP?
AD?
SSO?
None?
```

### 6️⃣ Are credentials weak/default?

```text
Default?
Common?
Reused?
```

### 7️⃣ What does the application allow?

```text
Upload?
Download?
Execute?
Deploy?
Import?
Export?
Scripts?
APIs?
Plugins?
```

### 8️⃣ What information does it expose?

```text
Users
Emails
Source code
Documents
Configurations
Credentials
Keys
Tokens
```

### 9️⃣ Are there known vulnerabilities?

```text
CVE
Exploit-DB
Vendor advisories
Version-specific issues
```

### 🔟 Can the finding be chained?

```text
Finding A
   +
Finding B
   ↓
Larger impact
```

---

# 🧠 CPTS Golden Methodology

Memorize this:

```text
DISCOVER
   ↓
FINGERPRINT
   ↓
ENUMERATE
   ↓
AUTHENTICATE
   ↓
UNDERSTAND FUNCTIONALITY
   ↓
LOOK FOR DEFAULT/WEAK CREDS
   ↓
LOOK FOR INFORMATION DISCLOSURE
   ↓
RESEARCH VERSION
   ↓
TEST BUILT-IN FUNCTIONALITY
   ↓
TEST KNOWN VULNERABILITIES
   ↓
CHAIN FINDINGS
   ↓
LATERAL MOVEMENT / PRIVILEGE ESCALATION
```

---

# 🔥 Final CPTS Cheat Sheet

### When you encounter an unknown application:

```text
┌───────────────────────────┐
│ WHAT IS THIS?             │
└─────────────┬─────────────┘
              ↓
        Fingerprint it
              ↓
        Find the version
              ↓
     Map the functionality
              ↓
      Check authentication
              ↓
     Check default creds
              ↓
      Enumerate everything
              ↓
    Look for leaked secrets
              ↓
   Research known weaknesses
              ↓
    Abuse built-in features
              ↓
       Chain findings
```

### The 5 things I would **always** remember:

**1. Fingerprint everything.**

**2. Don't trust automated scanners to find the whole attack path.**

**3. Default/weak credentials can be more valuable than a CVE.**

**4. Built-in functionality can become an attack primitive.**

**5. Always ask: _"Can this finding be useful somewhere else?"_**

That last question is basically the theme connecting **osTicket → GitLab → application-connected services → other applications** throughout this module. The module explicitly frames the techniques as transferable to applications you have never encountered before.