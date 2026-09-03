![Image](https://images.openai.com/static-rsc-4/_8inGZJmJPuJJwj8-4kmsYxE7j1ZStN-wZi1SCD1SGuhpT4MvG16TE-c62oqDjY6rJLWdgtu1bb5QK78RY0K-rmgZrvoBKY_aJZwmt_PYeTlyzfQ0T-xKJsnWVMQgGCYPU_duo0xBn2uClYoi_OufMEFp2EK7ldh2Mi2TlDDz5hs7vQHuMYSVEDW569ANR6E?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/m_5oYEbrbA-PS3cjN1MNKt3wSkG4a7ngXLzvPUMev2tnLlhGzLIdEwmb0Z0szgfuXVhlTJ00gk8tP5Ezxnj8XORBZVzKvKIe-eTZapZEsTf5OB42lNhaR-hTMJnsA8dhyvNHemorHHwaoEqHLpCmo0xEZBUVGTxifr26b2V4l0YniUj_lbruPP7Tko-bV02-?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/naFiRPUsccoAse1dmZO_PnweXbKbbv6qwY3NRsSyew4njZCxal7N41S-04-rxqfTECbwtFx0ltnWbNa_PLSvpYixxASzRR57ErGgz0ZJRBgADnyjTuSfI3E3CulhzA8_QTL9pJF2F6uI7JOP-zPFk88UvFb-Ffx-KjdOOm_jXn4tbawwWkJW2z1iRo6V-4Lc?purpose=fullsize)

## 1. Introduction

**Web-based applications** are extremely common in environments encountered by penetration testers. During an assessment, testers may encounter many different types of web applications, including:

- Content Management Systems (**CMS**)
    
- Custom web applications
    
- Intranet portals
    
- Code repositories
    
- Network monitoring tools
    
- Ticketing systems
    
- Wikis
    
- Knowledge bases
    
- Issue trackers
    
- Servlet container applications
    
- And many others
    

The **same applications can appear across multiple environments**, but their security posture can differ.

An application that is secure in one environment may be:

- Misconfigured in another environment
    
- Running an outdated version
    
- Missing security patches
    
- Using insecure default settings
    
- Exposing functionality that can be abused
    

Therefore, penetration testers need a **firm grasp of enumerating and attacking common applications**.

---

# 2. What Is a Web Application?

A **web application** is an interactive application that can be accessed through a web browser.

Web applications typically use a **client-server architecture**.

### Basic architecture

![Image](https://images.openai.com/static-rsc-4/NlgHND9pRezqkTkPEHRl9h5FUFrzY5JH3okqe9m6sDt1Ie9B9E6J5ayu3H4N7B5Cef64Q_lz-9b3rgBpEdafRNF4_qqpcCvIrYcNWBisZxhveFb9ndROkqnO71f1TTVXSy-HeEp-XNiVxdDpMRLV8XB3CLgrFuIEKn9dDZ0a9sx4lwYydNERG6seKZ5dO3WQ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/CGnRUZojaGddjuOUAGFqbEVUo5kElKruhP367CxFTuM-xl3gvH38j-cpzy76DrEAAma1f2IAxTKB9qnkT8mSDvmz2eXvf4WjOuDouIRsn_MW__9eoMBQpUZ7_v2AcyR4cnt3cU9jX9l8XZkaIoE2p3krDjBABATQVaGUUYa7gOrQih2d0LI1yoAvB-SP-BtD?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/_d-h4VGT08YHVUYOTxsOo2ISQnJluislTSRG8dlz8aQhm1Wzegb7aanjz8UjnSZ-OEYTFyFq06RHu8EY1iB2GSrVk2i7Kzs5KQWPSg639ss3TvsXREuPa864p_fHiK4V_ncEppf86f6vdaw1ilC1JjqSRRHHpK_y7gi9Tw8xsmQw7btpHQCPj-y6xO2tUJkI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/A9J4PGl0T36zjpJn-gQTDA4OUA46stKuReKiyG2l07nj4965BoZ5jO5AywaB44tkkiibbTAs8JDddUDW3xtm7Y3K1xT4tsju6g5VyDFyToZg9TT30aaClehq0G6ldbwRwEM6sMh6qQYtZnu001X-paOKoHSJ-As3lFiO9I-MS1XKYOuvdNpo5hDrgoVNuCg9?purpose=fullsize)

```text
                 WEB APPLICATION
                       │
          ┌────────────┴────────────┐
          │                         │
     CLIENT-SIDE               SERVER-SIDE
       (Front End)               (Back End)
          │                         │
       Browser                  Application
          │                       Code
          │                         │
          │                    Database
          │
     What the user
        sees
```

### Front-end

The **front-end** is the portion of the application that the user interacts with.

It runs primarily on the **client side**, usually inside a web browser.

Examples:

- Website interface
    
- HTML
    
- CSS
    
- JavaScript
    
- Forms
    
- Buttons
    
- User interface elements
    

### Back-end

The **back-end** contains the server-side components.

These can include:

- Web application source code
    
- Application servers
    
- Databases
    
- Authentication mechanisms
    
- APIs
    
- Server-side processing
    

The source specifically describes the front end as **"what the user sees"**, while back-end components run on the server side/back-end server and databases.

---

# 3. Vulnerabilities in Web Applications

All types of web applications can suffer from vulnerabilities and misconfigurations.

This includes:

- **Commercial applications**
    
- **Open-source applications**
    
- **Custom applications**
    

A major reference point is the **OWASP Top 10**.

![Image](https://images.openai.com/static-rsc-4/fJSmu0-hB4lG3GxPQ7OG1zdx0KcPuDP7lAu6GxIXY5caRmdCVUd6ofdYjhJyC2LSNPt1igiQY6AGq8eWYUA5j9QRwca2utwoB-lJhQHUlYzN_hUfO2Kfu21PZfXTIVo86DAU9SE-d2ntU6lPcipaS_V8NZipLKKIEuWjOZLhH7neFN8L8GmJCKv5sQb2lsgb?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/a65WnGl82FW8mJWDPPreu4GSFkgdPuA3VuNP2goQbCPzvXH__KpC7eQdw8Vdh8YAutLZdDcu1Ta9NF7prHsXi531BdW3ubw6qvPtevFSi6YGhCdYB8mmQ51GYdu0sGfzPOYa6rIhHMN3AansMOp0mnhOSviC18OJhwq8WpEluCPzozbf-IMQbae9GdOAXQPw?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/43oZSFQ2BLaoaTN0L4rohCXFPG5hVp8DqnykQgIly_u3uSbBdCeS_P8y876qvYfBD-X4eUtE0Qy5OErlQh3dOANWU_mVz-s3LUxGcWCJrn-ApCU65PFJosngc2QmpuEu76C_uo5EoaUOGPRuV2sjbtGF337o55OK3g3ArG9rx2izUgsj10Upd9krmBgSATKx?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/omXBcaJJgUtRipIn1zwM3fCk7uMp61FxQYiG-z6J3QuHOftkW8Q_tPFA6412aPKPJMStmWpntNoEmSjk0ZtofA-fhQMG6DKLHprvoBf8URMnfi-0NSN661DOvIGpKfLuuto0d7Xw8gPjmydrBXAixnQCqBS4lHWAwQJ4XFG-QhAXBs3mYHLogxWSx_7HFA48?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/feGh25yalzUo7YUQtL9PFlV_RMudbEGppKOu4tER7lPiPbm5tBk12PrQkx2cbiXS2XMdraqx-zChw0S6ASQqyPmJ6_06VC3Dek1Atne6_T-0p0KG49OBc57ueLXc-rg0SqhNlSjaG_3t7L6atvEFmkaoyzPRH_6e-utQXzj5ctLSqth1W4Y9ukHJhqcsTSBw?purpose=fullsize)

Common vulnerabilities mentioned in the material include:

|Vulnerability|Meaning|
|---|---|
|**SQL Injection**|Manipulation of SQL queries through application input|
|**XSS**|Injecting client-side scripts into web content|
|**Remote Code Execution (RCE)**|Executing commands/code remotely on the target|
|**Local File Read**|Reading files from the target system|
|**Unrestricted File Upload**|Uploading files that the application should not permit|

However, an important lesson is that penetration testing is **not limited to finding public CVEs**.

You should also investigate the application's **built-in functionality**.

Certain application features may be abused to achieve:

> **Remote Code Execution**

---

# ⭐ 4. Why Web Applications Are Attractive Targets

Organizations have increasingly:

- Hardened their external perimeter
    
- Limited exposed services
    
- Transitioned to remote work
    
- Exposed applications to the Internet
    

As a result, **web applications have become increasingly attractive targets**.

Applications may be exposed on:

### External networks

An externally accessible vulnerable application can potentially provide an attacker with an initial **foothold**.

### Internal networks

Applications can also be used during an internal penetration test for:

- Initial foothold
    
- Lateral movement
    
- Access to sensitive information
    
- Additional vulnerabilities/issues to report
    

The important idea is:

> **Never assume that an application is harmless simply because it is "just a web application."**

---

# 5. Application Security Statistics

The source references **The State of Application Security in 2021**, a research survey commissioned by Barracuda.

The survey collected responses from:

- **750 decision-makers**
    
- Companies with **500+ employees**
    
- Organizations around the globe
    

### Key statistics

|Finding|Percentage|
|---|--:|
|Organizations suffering at least one breach due to an application vulnerability|**72%**|
|Organizations suffering two breaches|**32%**|
|Organizations suffering three breaches|**14%**|
|Bot attacks|**43%**|
|Software supply-chain attacks|**39%**|
|Vulnerability detection|**38%**|
|Securing APIs|**37%**|

### ⭐ Important takeaway

Application security is not simply about finding a single vulnerability.

A vulnerable application can become a pathway to:

```text
Web Application
      ↓
Initial Access
      ↓
Credentials / Sensitive Data
      ↓
Server Compromise
      ↓
Internal Environment
      ↓
Lateral Movement
```

---

# 6. Application Categories

During an assessment, penetration testers may encounter applications from many different categories.

![Image](https://images.openai.com/static-rsc-4/4gn5RT3LuWnK7DglRv9C2XcXPFrMBAW1R5r5FzGExKBBoO1zcGokghIcmokqO4wULv0D_ZyZUVOW1wPfKVEi_MD5z21mdjNqDqqZw_d-Z0DEuB1U47GmT0r14_bQRpOK4FK91VFZ3ysQxLR2SKW-8ajraJsz-8Lhqg7T0S_weCr87b0L26qyLmqkOoMOnQL2?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Yl95v6H5_bXoVOGK7vEKQXGKNy_wynmt0Jfx23edsWjW6ZMpWj-DPa8ZxWEnE37NyzntexNmY6P3RTMxTZhUk0ilWRGHTDJGfvqDOjVl22Sn9X-OGpgqniovlz8FIRVodIaLZM42_HqsIjXvq2fQtdlTZYTfBnvumEtD98f5_ylHUV_mHdvzBI1sbYcRrdCu?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/8v1hqy6tL5k_LlNqqXX8kX7J78KboXnH0TajGHTzq3uLffgp07ntVt_JuITEIx2NiepdSSmjNGjREN755vnWCnDf9icuDJZ1FuS-FBN7M2GZobEfb2kzscXztBrtQYdlmWoZIL6jXCtJd1dCCx4aQKjP8FGCboc5wwpTxiDq_gD86os3v31JG8y3rFvQ68A2?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/OjyE6vby9oIh7bxU6-SK9DRPJ6xsZggSSSqFwYPlfCTb2QwoL-zSl5FO85VmO9W6sxMREIWaouq2wkjDk1c2GmXQQLnafj2t1oEVJtks3jsNTYHysA_YUrHOMlAoPlC2ScfqF-VPRIzkP4JrjIMHmc6aXUbflcOnJKX4lGpbxFDalxfIcv-ObTwbw2UT3DmC?purpose=fullsize)

|Category|Examples|
|---|---|
|**Web Content Management**|Joomla, Drupal, WordPress, DotNetNuke|
|**Application Servers**|Apache Tomcat, Phusion Passenger, Oracle WebLogic, IBM WebSphere|
|**SIEM**|Splunk, Trustwave, LogRhythm|
|**Network Management**|PRTG Network Monitor, ManageEngine OpManager|
|**IT Management**|Nagios, Puppet, Zabbix, ManageEngine ServiceDesk Plus|
|**Software Frameworks**|JBoss, Axis2|
|**Customer Service Management**|osTicket, Zendesk|
|**Search Engines**|Elasticsearch, Apache Solr|
|**Software Configuration Management**|Atlassian JIRA, GitHub, GitLab, Bugzilla, Bugsnag, Bitbucket|
|**Software Development Tools**|Jenkins, Atlassian Confluence, phpMyAdmin|
|**Enterprise Application Integration**|Oracle Fusion Middleware, BizTalk Server, Apache ActiveMQ|

---

# 7. Why Application Enumeration Matters

There are **thousands of applications** that may be encountered during a penetration test.

Many of these applications can:

- Have publicly known exploits
    
- Contain misconfigurations
    
- Expose sensitive information
    
- Allow credential theft
    
- Provide RCE
    
- Provide access with valid credentials
    
- Provide access without valid credentials
    

The module focuses on applications that are repeatedly encountered during **internal and external assessments**.

---

# 8. WordPress

![Image](https://images.openai.com/static-rsc-4/M4cWn8zP92StDXq1LFmu8ANi4RS9iRvrN6sQeoXeQHF5xcuZbRYBjY9xgmPWU460SudNBZa7R6W00Ez7-K25uUhXamUKsTPKA5wdKzvor9oQnN3uFAo6cTTjZqGVMoY7673q1BEurUfk6h-phupW34b-VL4QSzUn2lMVTtiXMyUePljFktOcpmnKzWctHapt?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Q8j-Q_mNknkgZTV1umv_-g9TmuJwtesvN6r3Bn2kEvbvkXEOqJu5TB4vU5kfdxxSQSzpjUrdFvhtRmdeSa8Yj02uKRRJnNxuwJydVZWK7sDC_CyNd-uFITzrcLHTlK7t3p9JZMIx2cEfHBngce-jMxlWok7xuZwREndWOC0x24AqQwG9PKD-hMCbyLjHtHsj?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/9FZ3ji4LF8XLLQ2Ixo_z2bZXsJaGuCPMEsAL8wTkgS5AuPtuso698D5qpiL34qnva6n3S1y7qArYu5LixSVOUFuBUeoramP3FJBUZIznsgjBKZ25BO_tozF7VzqcCfu9UtQa-ho_u56qYZYEa82g4iNC0ho4bjcMthBh4TISClnTNyedt6pxJP9A-ZdCMfUb?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/8BitmEMx-58Phxtrcl3lmWiMIXzm3DpwTA9JPRLflspTQ62sChRhYuaFOPsdyMzd69mF0w0mS2Si374AD-PYG2PzZfyF3FIZCHaxBDUntKKRLqgOhwlmqT_SbiO72DgcryLAAmnZyJBMm7xik2pVUQN_TWva9UmFeEqFFrsntw5RdGn-bchSc06bHq6L2_wk?purpose=fullsize)

**WordPress** is an open-source **Content Management System (CMS)**.

### Common uses

- Blogs
    
- Forums
    
- Company websites
    
- General web content
    

### Important characteristics

- Highly customizable
    
- SEO friendly
    
- Uses themes
    
- Uses plugins
    
- Written in **PHP**
    
- Usually runs on **Apache**
    
- Commonly uses **MySQL** as the backend
    

### Security concern

Its highly customizable and extensible nature means that **third-party themes and plugins can introduce vulnerabilities**.

### Remember

```text
WordPress
   ↓
PHP
   ↓
Usually Apache
   ↓
MySQL backend
```

---

# 9. Drupal

![Image](https://images.openai.com/static-rsc-4/bYQYO7e_xfFC37lsge-54F6SfetJLaP2DK2MDK1INWdNhC21ONm-Bn62xvqpf_sYkm3-qKdigG94LqBCReqMXAHa1iI9ag_QovOOmDH4vmyiDFEgbqnjWga_ZQV_N4nnIyvxMjx4aWMvvF42l8WWAYKCct6Nll6YGPGpvMAMW1gkFhJWccH0cAuP_M8CbwU7?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/yzjQZZDJnPAwWDoYcMn8ze9SN1I2cT9oUr1us2mU-D_0QQvfef-ZuW5SKklS88WCeFzRrR3d0jNkcLaTbfjtICLpuYSXViLUZ5N6TKDAcvyuobUr41wDsKXbeW1KZBVjGjkqYnAuKNeTyDdr5T4uF93bLbd-iDaX8vpgKXnyuW7iREQRjOanaAffYe4U6pk9?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/RJbfVRdjignCOKScySha4zTjrkrrPGx7fX249hnOyb0UXXN1jWMMRKEX1d7Q7chsewgjwl_s3mb6kankpMUMnGUp5892Y2FkmJDehxqYwQgZ0J7xp8O3T2uwCB-0MTKQr1iQhrVkJ3ec57UccOtlYBzWG9ms_9O-iuxxXhn5__ycQqvTIVOTNNo-jIre36d8?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/jmfsXZt9VQxmQ8-fjc5p5fx9oQ3zt_v5_LRnU01N8CFI4OV8E_TlVglXr3WR3dGCB8CqZuk1u8jk3_mvXZMEPXYsenL6EzcWyqKtB-ohw7nxNtg8tHytpwNNVFqGF0pCeeIJrqXRtyL9L2QHvSberampcf3c0Ril8ASnu6TSDe0gkX68Pvyl04G3_zXoENki?purpose=fullsize)

**Drupal** is another popular open-source CMS.

### Technology

- Written in **PHP**
    
- Supports **MySQL**
    
- Supports **PostgreSQL**
    
- Can use **SQLite** if no DBMS is installed
    

### Customization

Drupal supports:

- Themes
    
- Modules
    

These allow functionality to be extended but can also introduce security issues.

---

# 10. Joomla

![Image](https://images.openai.com/static-rsc-4/fsFbPBrcU9Q2DXEGr0CNX4may6HHVV5wOWcCDN2xq_Ezwgg-Qh1kYb7BHFV5gAWBMAhNX1z0E7Zy_vqBJIohD-dMttmrfF1yS1ZeR9JrtSGxPJKvHfnsucc0a0lBcD0DY6i30GK6leGh75DHOpZngT7xnc6NX2R5PcnXBXFIMgHMtDUeMyVfpcSxS3QCF1Mj?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/dfRYZ4pSVAZvyz5Yj9JKWfzYvgURU59IJY2trhIWkbyOQFZi5Z-ipqg3jgg85RnzPMSzMRd8nsjxUnm4NMoKrOuY94j56uUNL-MdXyTDF6ZwspJYvwRP_tcRjcYwFqy9oa02rsj5TIdA3tr3LJaXn-kAEuzcB9P467thez7FbQ1cAPoVPtBo8Zu0w5Wv7bsE?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/puoQ57UoYl1KzNXu8ZpEuAS3z9t8TW6zUkMf1ByAHOrshIrrjt1kC3I1L_sgjGMgJbwXS3v3jW1arIDTtRsqmWEn8rcOpVPQN9pZkdUCMv-S3UYsTUi10L-B66OJFfecfgWSb_-Z_lZqdgcmp4n5vJiouRhh_Cvv2hiizvRsAeT5ObsLts4xyEpU41sAwdTJ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/yE75wQwI_1Fik2VonI1TpQsJQYh4fLcLrX8B_3AcWb_QCkaVuoI2RWh_n1Vd307Yjfcz1aF1TjvAN79cQGPo9PM33v9ElMp6xGsONo6V_G8Nsb5RVGW_6o8qsOnF8-tb8nDwL6K_NC5n0vaOUs1CsOFQ4JKKZwsubm9THUbcFBmjMoqLCV4v5ilyA6B19RAp?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/_pq9GogNAD3nhGsr5gGkYiK2CncbgPF86b4Vgc5SZBmxp_54g8UCP8BNyEk-0X8TDETbDYJY9hqqdF5MmXyNJTHF52skdENz7cs4pTvZup3EUJ94WU86LrmLdPaw0XJVghb55J-FjyYti77TZPGZGxcBYuIgP_deGCs0RECpaNeB-749ksqJUcLsnB-Fjdm-?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/lk4gE5ntkcR9sJcsVS6fE0OijqBVBD5sqz0qt5ZQJ49HlA78gcJRUOfnJcbwALFyP0YZe943C8yvly7mIKFcmu1U-X_AqwDU6527U9itzC0efL6ZXZMKfXixjQah21U2UsPEwKUxSgB6AEUsWVC7NztzRCyghcJNrOVwrqlCzBxSDtMycYmCFafYfbk28xdS?purpose=fullsize)

**Joomla** is another open-source CMS.

### Technology

- Written in **PHP**
    
- Typically uses **MySQL**
    
- Can use **PostgreSQL**
    
- Can use **SQLite**
    

### Possible uses

- Blogs
    
- Discussion forums
    
- E-commerce
    
- General websites
    

### Customization

Joomla supports:

- Themes
    
- Extensions
    

The source estimates Joomla as the **third most used CMS on the Internet after WordPress and Shopify**.

---

# 11. Apache Tomcat

![Image](https://images.openai.com/static-rsc-4/z8Gg-wS2kevYsIemCE-mWCTGNDDSedgQkyAUhXbZTpEbdBEp_JjEc5FX-nTO0FNM7bLdlz_2CAWN4mBqx0nR4-b9TFpToREWQUPY1y4KyZPwsBWGtos4-SEnpDe-oUnxOr_DsgTFgFNX59Jh4kmC5nlkWgaMoY9SAlvpnIr8x_5REJxv8Mn7rMQi6DzH7s_4?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/zGUGCfhl4SzvtImBtyz5q0LtLG4rCoSftVCbp9_vE5Zb16WNq2P8lUJn8FSNKH0lpl2BIp3fMdH8vO-dNzwSYt73J2dVyoJAsp1yvQkTdwD4OJjUMKG7dKY6etj1KgkfXF3stW_0eKyavSb-ZrIQEZsktSn_RnO8CHIZDfIfkDU9PZmppzVK8ucH9tC-dTsm?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/uBCnawvgu6u-jE-S_-q4lMwDma7rsHMsWWey1KWQ-QnPvaFIt0pqSmT7haNAVN6Ds-xnNbNd4J7_vc1AXTooBmd4B-k4BiktxNg5J2Jl619oTzSZ0vBgzvQv_Lw-QCZEHqKaidSEv9XioqEOWZPJW1aBGdWqFLiJR6xWPEJoDW-xx7aOeWISVOLCw09eOncD?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/6nBxTlmdJLFR6BbQTXb6VuOvznsH_JWoHwPxVNbgoNIJGGt8_HZ6qV6ldHiiNg4j3OcNZqHzKtZ-ChEiwcsIkW2ItA1602WZhpHy2TnDnanERl_c7aeLbHO8zdczpiusBAoe65caibbxq-CRtuZe09EQIovDVCJl9GRLZoPM1Ik__8uSuDPfhopA8_9LMX4u?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/EBqHMkuQmFP-eT-KoPX73HEQhfP1upND2fuwCJ2Un6bZpK_Fu5t0bwrnByyA8V67jqVZtNzAFgv4TcO_AugUq-C9uN34vbAzSNZyv2Ce-J-LfcGRNEQdq-bdiBD79J2HKHnIWbwOLH1paUsGkmCXyxZ8WsFGRPE-_8-mZz8CjglxGjOhvmDtJdOKHjcGDjDS?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/8YkEj6BGvWw4X-To5HWr5Bx5NnOMGkDOtaIvO9_zWir4Y-DxWqhaiREVnyBb00jORfwLSLeafS-d0xXB6OguZxf8ntjcezzop3b_9DXmC5Mu3-lPs3bgyIGwECLYu46BfNnYlofFh78mlOoT0dix9g0mAHx3g32gnhfcx1UuKivj925yPuftAwUfDYDsgqHi?purpose=fullsize)

**Apache Tomcat** is an open-source web server that hosts applications written in **Java**.

### Originally designed for

- Java Servlets
    
- Java Server Pages (**JSP**)
    

### Modern usage

Its popularity expanded with Java-based frameworks.

It is used by technologies/frameworks such as:

- **Spring**
    
- **Gradle**
    

---

# 12. Jenkins

![Image](https://images.openai.com/static-rsc-4/egbjZK7X_211anGw69KxuqDIz6X1edYDzzx_eBDZh-SrOp_AGBMPz0nP5bgKHmJKmraRU316Op7Ed-IrJfj_CQpZqHlHIR7I5hwA-10ZeGlTGwznUDhYLwLzieCyLa3t3Wei63VNB-rNrd5qaLBwwqw3Y9t5jWp6oaHmjBNCokFUz_Ge206hZvPS3mR1rByZ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/xZ_c15dijfUIh-GRmkBw5gtatqlandtMBhZWcPQCyOeseIpUfyfv0wI4Q6mp4KWJEo58uw7uQtmyG9iKWwjSpLQBoxj0rehvGWx1xekcQi0Xi2dXAj75zpydX5OcSZvG9s6tjqk8yMCW46o6sqZyOZ7W-8DE4sUpNDCg7kmaP_JRWCnPnk_vROjPj8FfzUck?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/G6br1liYJbBhrMiP2bDsq8ZssuE0f4kGZEtVbcv7A24KYzGGJlGEHHzX8DUEUMiBmHWffYu0BJan8I3m5V0Nt4nov-nflxC2NAToxEDTvxf8vTExkfjvdiXneB2CSCyHtMwBwt209Vn56XwY-Awxg7W3Z1guK6HnAqG4jVICtp_zVjQltInmiccqdbPMg4Vj?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/61ji_4SkZK_tQEM6xIfTxvzg9HQRql6NzGIEnNhY8l6SyoW8HdVtGhzXdG3YQxP1yfRVSHp0jJNpZgKN-dwufpwo5pZF9r-SUhHEGKcrRny0bY5-g007dZPHzORP8cDFIcrTDMn6cFHlppfsH-nnbYH28ezOgwhz-PGXzppSIGICy9LSZzShz3mYODroMJla?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/nijkk3f7ud11ldPkEga1KxG4UPy11GT4aIvvfh1RGjK3dXgTO4y5hYefcByYXwA1w0UShVzoh9iXHOPpxaZoJYQ-Lqr7A_lkKkTh_gBqiHWvfufhqV6MAUr9mGGq_Ga4iMLonyBlpGlkxb0jD6mDZ_VjhfDOukd65MeF7XJBRs33n6wx_mqYovIrFBZ7WD78?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/91NQOQk1ZIT0Tgywt16QjSTeyyGHY_EFZzpcFi4ttmee9gDqNS819_HdydBKygOTcW3Viz8CU35dzo4coQCpVJFbzGdfbETexP9ePNJqVyMjM0eNR0kzm1DTquZ5P4hvcGzshV0jN7VZIOS-wMzq7QSwHOQCk5KOfVxkjzvpcABQldpoa4jpUnskAtd_hQRE?purpose=fullsize)

**Jenkins** is an open-source automation server written in **Java**.

### Primary purpose

It helps developers:

- Build software
    
- Test software
    
- Continuously integrate projects
    
- Automate development processes
    

### Architecture

Jenkins is a server-based application that runs in servlet containers such as **Tomcat**.

### Security significance

Historically, Jenkins has had vulnerabilities including vulnerabilities that could allow:

> **Remote Code Execution without authentication**

The module later discusses abusing the **Jenkins Script Console**.

---

# 13. Splunk

![Image](https://images.openai.com/static-rsc-4/hHZGDkncKUCcZECNdX7lPtdgs0prwGwVdI5GZNNmnN8-BmLaC6gwdIj478kqwaH-BX6MMUcJ--Bi9K_Lyb-sngzoCoHW2fOIUYXv2g3bLSz5qtPh4KKR6s4NwBWCyyV2U_TjG6Buu51ODJfog5JzCElsYx3DmgSgq9c9wiWaQd9O38kMwjJFrj21N2RNCQgL?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/rNFRWyJ46RjJJ4vBV7DXOZ8h5aew8qnHH-dNdcpcONzJDygdvvwusMg1cx6DoueN4HqrHRCXgo3Dbe7VvrbGrayNo7zTIO2bIMqBbfhlWWksso_jAEuSv24VRSIZK8Fr9Jv9U14BU0okBpiS1s4zNgrrVqE2RqxnaRVvpZm8A7ZO1I79rlIMWjq1Yt6oyorr?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Xi1_l0XYSj9vtL7_CD5FYblfJfpWcJF3FzQHXoDTgZ6mFU8aB3RnAtkbljTgxJ5_Ebdnku0oXrT7GbsT288BerhMHqDzkSq3STraWWpZPCHGx28DVsn4ECQleL8au7U3SOxDSNnc3MsamEAlp6rA_XJSxIAgS9TRkqu8ONB4LngHsZnYKBdnzSgLNL9PtFKc?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/r4YkcV-1e4VBvsLsyyvJlhluLy765svPwt4N-y1HFPbQbmqH5n2YW_EsBVIslxrg6nguXm4VLqBMI7BN9vuwt8TasFf-iUTmwdnyINGUzkuO1nqjkd0LAn2mrEtreTPA4-TxmiiRHFMoXYz2GjRnxeX5ezIJj0qhgTLf38m1NFCn6VTreExC665xtuhR0iO2?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/OjyE6vby9oIh7bxU6-SK9DRPJ6xsZggSSSqFwYPlfCTb2QwoL-zSl5FO85VmO9W6sxMREIWaouq2wkjDk1c2GmXQQLnafj2t1oEVJtks3jsNTYHysA_YUrHOMlAoPlC2ScfqF-VPRIzkP4JrjIMHmc6aXUbflcOnJKX4lGpbxFDalxfIcv-ObTwbw2UT3DmC?purpose=fullsize)

**Splunk** is a **log analytics tool**.

It can:

- Gather data
    
- Analyze data
    
- Visualize data
    

Although it was not originally designed specifically as a SIEM, Splunk is commonly used for:

- Security monitoring
    
- Business analytics
    

### Why is Splunk interesting to attackers?

Splunk deployments can contain **sensitive information**.

If compromised, an attacker could potentially gain access to a large amount of useful information.

### Historical vulnerabilities mentioned

- **CVE-2018-11409** — information disclosure vulnerability
    
- **CVE-2011-4642** — authenticated RCE vulnerability in very old versions
    

---

# 14. PRTG Network Monitor

![Image](https://images.openai.com/static-rsc-4/5Ke_9KoXKgF3fGEDXL16dxIO0xqnAVVeHRR-0TuLYqIGATlx4-YndSMG-XaEr_IKar2D1r5EDhi0PD7sQZf9fna9yItD0ontdf23IaqoxxTbQYo38TmwxGjsW98qw-T6z_Z0h53LBLHTKmR08128Pkku3Z0rcO3J-N-h5nApGwvykoh6TnYagQPBUhWAM9BM?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/fLQCprHzoIPTxMe_Z_zISZfRRZwKpTw0eWPJLqTmZtrcZjjRsVOlqsFgtDMuHmqkIA7b52pG0GVI78-ha_aZVWlHHNqyUL7dt80Alw6_J_tWYVRF7wbfjn8ardDjSFKbMUueZRhj8G0I5-i4QeNzL1R2VwXZpXd3RJsA1wN10FxTDPzFWrsrF2FJHWEKh-Eb?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/W0_zDBJ9H45lzUCSnqMO-QjkQwqmo9IKRoeYZKDiXRxiVQyKbMW-AH8fagoht2FSaInvhd3L9ZFKCLPaZnaMkx3vnWUGXthWk32N4Jzi9fGpBA3eZiAP4dIidSZLGa2MlBsiFz8iR3ThYEpOcW9UpmG--ii-n1sR4C53yET6szqPjqHiPRwqN50306NeQqVE?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/RNOSIKSKEDdjidBykFBByL8QPfx8j8X_AztF6IaI5Xl5Fx7vOYg2DPa3RoVQ2C6NjOP42p8jM5lyI8BXh0SVRbACkGtSmmKwTJbph4WqbENWklcKt5xZX4sdculPAv76SZlVST-3UpXzY8N2Nk069kVjoVJFHzifTecFpnMVew0yrgJ7X9qnDXAN6MDeFjLp?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/knyegiP3KcrNMNw9DHWgHebSwzm5uXYQDiWgkF_z87WEdsYrsEYIVS4fVeDyPNX6lx0bnWWlF1w_VgV-geZkBA_pkiW5wwxFWh8jBu3x3hrxFmMx_LUI1RzR22LY5lXY-xj_ddz4JajUlUC5MzY4jhVsXtwb6nxfXdELY9IKOGm_VROc3WtjFi_LbnCW7JwB?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/aHJqBIWKH_tVPzFY_r18xdqc5NH3bZPeOQsJLY36RkXqtHKJu05EOpMceZjqurD8qEOVJC249XY6uWAvAqRPd4rvRy1dZ0YE-liG5wUVqDqTfapuLPK9XNZR38D1hqQ-GotXFYet_6dgK4Xv-mEUjTpOpRN1FxJbQFa2DLmLjtFaAu3dS1uZd0mdk1go2AX1?purpose=fullsize)

**PRTG Network Monitor** is an **agentless network monitoring system**.

It can monitor metrics such as:

- Uptime
    
- Bandwidth usage
    
- Network device status
    
- Server metrics
    

### Devices it can monitor

- Routers
    
- Switches
    
- Servers
    
- Other network devices
    

### Discovery

PRTG has an **auto-discovery mode** to scan networks.

### Protocols

It can use:

- **ICMP**
    
- **WMI**
    
- **SNMP**
    
- **NetFlow**
    

### Technology

PRTG is written in **Delphi**.

---

# 15. osTicket

![Image](https://images.openai.com/static-rsc-4/mxLaxg0c2pNLt-Go7j5oaHuM-X_p57lmffgvTYiBHPgv78GcBoDMpif6sT9fV6ec3jhZEWf3Dwlp7U1TVbeDipcaR4gV7u9ezW3iYWveOTnEHeTMDh17xC_4OYazwOb4QGfA-nG9WVRRLpABgtEO7OdZCKeXxonhvpLuS3S3LX_xon_whC4NTFOCbzRIKfj-?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/zMUjETjnrVDAX3wiUMCLZ_KDUJeAEqLCcXLEIT2G7sEFSNLclZlvy0_dHCfDmVIFQgK82dVc-gbHGtEzOVp1Y_Gq8GajK9hMYEj7f8KoThXH6cT2AtdVfxIelmOMcBwhHc43c2f3FngmyqtlGRyM-4UdRh_OS8YR6zpjVFrYeqk0z6cxBjDNBYjOWQG5YmFH?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/bbKrtr_9eszjRs9vpjGuVx_pClpDnmOmS7D1td8R1E7jdY98lFu8ujYZQCpljnD8Tn8A8of104i8mdjhbCwAW31TLRW1M7qkbMnXTO_4xslQQXkPWw4h6xdrssf2e_mg-EiK_LpGndOLlTz2S8EnrO9HeWMzMW4jfVftr5-vZupWDl6DHZ94MKgMwsqoIenM?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/uOrZDcblZS6b9DHvbGpXdhoYsIrW0UbzqgdXc6J2ttKqOladYrDXoaClrp8u9oNlK3Xwh3zIiY8E7upyEkMdZr3CXq6ZIqU-juHyIRpTNln_P3-Vcx4A8YeX6TPoRlalcbVXi3cvDZ6VGpMn7S0z3nYz5aTFTaNI4mhymPi815cz7lgJbYRe2_SsXPAmp9wu?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/nuoYq3XX2dtXmBtQncmoJgo8AaVHD9A4JQpg-lBot9hD6wYOOn6lE1gml6TmuEetVgstShx8fvIFOdjd_ur_8lvha1FisPXMuhUw4isDPNfaNO2Vq_FtzBaDwUKjXw_4fFx763fyF0Td3HVm98p5q7FAsmBrJ1TGfoZ9wshJ2XkYw4jxBgpAZcXh6lbnHXWL?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/bjIgkTWUjWK48wfw_jipuRLVA8m0Zg3fEY3AG_ZifP4glYtGa4bqWK-I1Snh6-r0S3Xy2SctnVVtpuWCZIJP525FEiUWz2At3ekP-eCafodC2eMhofn68tmq_DzyVcizcc7eZ-pjGLTBh-fs9dTY6Gh0rU4xo24UzO5rozywI3oniBtm21e3MZq5JgqzMgY7?purpose=fullsize)

**osTicket** is an open-source support ticketing system.

It can manage customer service tickets received through:

- Email
    
- Phone
    
- Web interface
    

### Technology

- Written in **PHP**
    
- Can run on **Apache**
    
- Can run on **IIS**
    
- Uses **MySQL** as the backend
    

---

# 16. GitLab

![Image](https://images.openai.com/static-rsc-4/fkxq2sYdALGHN2UMHRXP9W6RGGduwVYOMxehWWTmgfO3sXuuJFGlHn4-gKKyYv7FqB5z9ZVkyTDs5MNSTpP13V-U14K6UIkypv5lNCQ52fzz-iNo9DNRZJosjkwZi5gshhjpa1VaSpdFHkP8F-shDNq-JlMAIWt0mSnE43w12rzn5tVTQgzuO3fui0dvN23M?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/3FkrJw48UTCvN9glCgyhmvzeAt8CU-6eK5jpO7__Z6YDwCFwmCF1FbA9aiRZ0I_fTeZXXUbqQvMKOPB4qsyHQ0BtnQk20bKL-jJ9-jxQRwm3K15ZhAhh3CRZaUHUePS0vVpnQw7khkh3Jaxnc-AIJA6C80hp0wCPRJD9iyuSkLSlT1yS9HP6uhb_BDVuq3lr?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/VvIs9oL8qbp2VNvf0sGQvNwu68rh5kBxlWMYbi9IgXlWc22H2WiNDGRB1vB5LZLFeuJ3XeUlcWczR8aUXjnltQ0JpPpbo47xQvaHPgB7neKD877IQ8g77IXNcolHpyGhfyK2HvG1HBGanVDzF5232VqtT_6N40GG-PAKeY-0wPRjgr83ryuxNyoRJJpNY1pv?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/i7Paa0-_6n_bRA24wFTn9P5aUQsP5QVyhX6sYTDO29r_QfeD1FcOYnYk1VD7adguRskfiSKJusG8VZWBorQF7sl9B-8LUKZBRcyYGbh0pVesinN5bHzx6mY1z-a0lyld58lscBivVeNCVFb2cWxbGOp3MQKNeXsBMSBlIkDdxCTZHcWjDuxQlUEhIpCXWfIJ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/PB0OA1fwM46cX_5SQv9C9j2pkcTZpb5sqsEPbVPv4duflNmEuQIeQSYeBKjelvQrSprgj39XfntJAEmCBSE7s0xLQoXYkYNFga7qrVVrCQyfvqIKHtTDCUagtdt5P0uIfd-VHr-mDyESrD_3zyW8PhFo7uJSI_VISqdM0S0Y9K9uLkcYOm-ptT-LzzkM6Bpd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/S-kja03cMWEh2XHL6N9BXSZLnU-hrbUPFTwjVpNd5WziWqfVljcZQs7snewd0VnIbFi43sGW7upnLOrJxUQK6W-4mHE537Zqo3YZ2G0tYigO6QLlchuJRT9vvqwVqEzuQqeivCxmYTA2_cUKbJ9eubFxiufQ4Jgv9EhigkXGmIMmrL7DHHJByxINzc3nRH4L?purpose=fullsize)

**GitLab** is an open-source software development platform.

It provides:

- Git repository management
    
- Version control
    
- Issue tracking
    
- Code review
    
- Continuous Integration (**CI**)
    
- Continuous Deployment (**CD**)
    

### Technology

Originally written in **Ruby**, GitLab now utilizes:

- Ruby on Rails
    
- Go
    
- Vue.js
    

### Editions

GitLab provides:

- Community/free versions
    
- Enterprise versions
    

---

# ⭐ 17. The Most Important Lesson: Learn the Application, Not Just the Exploit

This is one of the **most important concepts in the entire introduction**.

While working through examples and exercises, you should make a deliberate effort to understand:

> **How the application works**

and, more importantly:

> **Why a particular vulnerability or misconfiguration exists.**

Do **not** simply reproduce commands from the module.

The objective is to develop transferable skills.

### Why?

During a real penetration test, you will eventually encounter an application that:

- You have never seen before
    
- Has little public documentation
    
- Uses unfamiliar functionality
    
- Doesn't have an obvious exploit
    

If you understand how applications work and how functionality can be abused, you can identify attack paths even in unfamiliar software.

---

# 🔥 18. Quick Story — Nexus Repository OSS

This example demonstrates exactly why understanding application functionality matters.

During an external penetration test, the tester encountered **Nexus Repository OSS** from Sonatype.

The application was unfamiliar to the tester.

### Step 1 — Default credentials

The tester discovered that the version still had its default administrator credentials:

```text
admin:admin123
```

The credentials had not been changed.

### Step 2 — Administrative access

After logging in, the tester explored the administrative functionality.

### Step 3 — API abuse

Using the API as an authenticated user, the tester was able to achieve:

> **Remote Code Execution**

### Step 4 — Encountering the application again

During another assessment, the tester encountered Nexus Repository OSS again.

Once again:

```text
admin:admin123
```

worked.

### Step 5 — Different attack path

This time, the tester abused the **Tasks** functionality.

The functionality had been disabled during the first assessment but was available during the second.

The tester used a **Groovy script** written using Java syntax to execute a script and achieve RCE.

This is conceptually similar to abusing the **Jenkins Script Console** later in the module.

---

# 💡 19. OpManager Example

The source also mentions **OpManager** from ManageEngine.

Some applications provide functionality that allows administrators to execute scripts.

If that script functionality executes with the privileges of the application service account, it can become extremely powerful.

The example notes that the application may run as:

```text
NT AUTHORITY\SYSTEM
```

on Windows.

Therefore:

```text
Application
     ↓
Script execution functionality
     ↓
Runs as application account
     ↓
NT AUTHORITY\SYSTEM
     ↓
Very high privileges
```

This demonstrates why **built-in administrative functionality must not be overlooked** during an assessment.

---

# ⭐ 20. General Application Assessment Mindset

When encountering an unfamiliar application, don't immediately think:

> "Is there an exploit for this?"

Instead, investigate systematically.

### Think about:

```text
1. What application is this?
        ↓
2. What version is running?
        ↓
3. What technologies does it use?
        ↓
4. What functionality does it expose?
        ↓
5. What authentication exists?
        ↓
6. Are default credentials present?
        ↓
7. What administrative functions exist?
        ↓
8. Can the application execute scripts/commands?
        ↓
9. Can files be uploaded/read?
        ↓
10. Are APIs exposed?
        ↓
11. Are there known vulnerabilities?
        ↓
12. Can functionality be chained into an attack path?
```

The exact workflow may differ depending on the application, but this **critical-eye mindset** is the key skill the module wants you to develop.

---

# 21. Common Applications — Quick Revision Table

|Application|Type|Important Technology / Function|
|---|---|---|
|**WordPress**|CMS|PHP, Apache, MySQL|
|**Drupal**|CMS|PHP, MySQL/PostgreSQL/SQLite|
|**Joomla**|CMS|PHP, MySQL/PostgreSQL/SQLite|
|**Tomcat**|Java web server / servlet container|Java, Servlets, JSP|
|**Jenkins**|Automation server|Java, CI/CD, Script Console|
|**Splunk**|Log analytics / SIEM use|Security monitoring, sensitive logs|
|**PRTG**|Network monitoring|ICMP, WMI, SNMP, NetFlow|
|**osTicket**|Ticketing system|PHP, Apache/IIS, MySQL|
|**GitLab**|Development platform|Git, Ruby on Rails, Go, Vue.js|

---

# 🧠 22. Module Targets & Virtual Hosts

The module uses hostnames such as:

```text
http://app.inlanefreight.local
```

To simulate a realistic environment with multiple web servers, the lab uses **Virtual Hosts (VHosts)**.

### What is a VHost?

A virtual host allows multiple websites/applications to be hosted and accessed through different hostnames, potentially on the same server.

For example:

```text
10.129.42.195
       │
       ├── app.inlanefreight.local
       ├── dev.inlanefreight.local
       └── blog.inlanefreight.local
```

The lab maps these different hostnames to different directories on the same host.

Therefore, the attack VM needs appropriate entries in:

```text
/etc/hosts
```

---

# 23. `/etc/hosts` Configuration

The source provides this command:

```bash
IP=10.129.42.195
printf "%s\t%s\n\n" "$IP" "app.inlanefreight.local dev.inlanefreight.local blog.inlanefreight.local" | sudo tee -a /etc/hosts
```

### What does it accomplish?

It adds the following mapping:

```text
10.129.42.195   app.inlanefreight.local
10.129.42.195   dev.inlanefreight.local
10.129.42.195   blog.inlanefreight.local
```

This allows the local machine to resolve these hostnames to the target IP.

---

# 24. Example `/etc/hosts`

The resulting file contains the normal localhost/IPv6 entries and the lab VHost entry:

```text
127.0.1.1 htb-9zftpkslke.htb-cloud.com htb-9zftpkslke
127.0.0.1 localhost

::1 ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts

10.129.42.195   app.inlanefreight.local dev.inlanefreight.local blog.inlanefreight.local
```

---

# ⚠️ 25. Common Lab Problem

If you spawn a target but **cannot access it using the FQDN**, check:

```text
/etc/hosts
```

Make sure the target's IP address and required hostname mappings are present.

The module explicitly warns:

> If a target cannot be accessed directly via its FQDN, check the hosts file and update the entries.

---

# 🔑 26. Important Things to Memorize

### Web application fundamentals

- Web applications are interactive applications accessed through web browsers.
    
- They generally use a **client-server architecture**.
    
- Front-end components run on the client/browser.
    
- Back-end components run on the server.
    
- Applications can contain both known vulnerabilities and dangerous built-in functionality.
    

### Important vulnerability types

```text
SQL Injection
XSS
Remote Code Execution
Local File Read
Unrestricted File Upload
```

### Important application names

```text
WordPress
Drupal
Joomla
Tomcat
Jenkins
Splunk
PRTG
osTicket
GitLab
```

### Important technologies

```text
WordPress → PHP + Apache + MySQL
Drupal → PHP + MySQL/PostgreSQL/SQLite
Joomla → PHP + MySQL/PostgreSQL/SQLite
Tomcat → Java + Servlets + JSP
Jenkins → Java
osTicket → PHP + Apache/IIS + MySQL
GitLab → Ruby on Rails + Go + Vue.js
PRTG → Delphi
```

### Important security concepts

```text
Default credentials
Misconfiguration
Outdated software
Public vulnerabilities
Administrative functionality
Script execution
APIs
Sensitive data
Remote Code Execution
Initial foothold
Lateral movement
```

---

# 🎯 27. Exam / CPTS-Oriented Takeaways

If you're studying this for **HTB/CPTS**, these are the points I'd make sure you can recall without looking at the notes:

### ⭐ 1. Don't only hunt CVEs

A vulnerable application doesn't necessarily require a public exploit.

Its **legitimate functionality may itself provide an attack path**.

---

### ⭐ 2. Understand why RCE occurs

For example:

```text
Admin access
     ↓
Script execution feature
     ↓
Application executes script
     ↓
Script executes with application privileges
     ↓
RCE
```

The important part isn't memorizing one exploit—it is understanding the **security boundary being violated**.

---

### ⭐ 3. Default credentials matter

The Nexus example demonstrates that something as simple as:

```text
admin:admin123
```

can completely change an assessment.

Always check for:

- Default credentials
    
- Weak credentials
    
- Documentation credentials
    
- Unchanged administrative accounts
    

---

### ⭐ 4. Application identity matters

Before attacking an application, establish:

```text
Application
Version
Technology
Authentication
Endpoints
Features
User roles
Administrative functions
Known vulnerabilities
```

---

### ⭐ 5. VHosts matter

If a lab/application uses:

```text
app.inlanefreight.local
dev.inlanefreight.local
blog.inlanefreight.local
```

you may need:

```text
/etc/hosts
```

to resolve them to the target IP.

---

# 🗺️ Complete Mental Model

![Image](https://images.openai.com/static-rsc-4/rZ2A-fpo73XPr4Llu-DwggueKaQugoe3DY-vCL8VRqD16yaxMeBNaPZeIWadG8JkZZoSvjju6UgxJuAc2U74kRC3oH7TRaj65xWa5CfbtAu_SsiMVTtFPe1kgXO_BP7vgRMCO02ag7n5i1UFoLfq1PIllcketvOPwmlb7EP8_ZmVczduRRCdzvqrTGEFgJyA?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/VIzuSiBcuFy5sWIVFwey9mqvoPvX4OcU_HGikN4JjQXrKpNW-_mbTqEntvqNzJgTvfG2fgkyGrXDEtGGfXhSmpa04JMciAGTj-OLBkqsSV2GNj9Ayio7yH9jtBjMZJ0IutlWjrSO2-ffGhl-dnapRlW7n5q3pwJTulT556v5TTY1_4M4f0bruRIAWWbLdYcd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/JLIaQg2mk1GzLYApE_6Y7YdE09S7QE6k6MR29UCXy3dY8_CsRQZQSqhIUsZRC50BSap9OOeqLdQEjWXGhLZLN8oC-EfwOnM5GiWAEcTcQRjsL08NQJorXZlgxmBppaXvtwI7--jVO1VqGjKqO1mHHVAIEy-J24-pqO5HD9T-vkNRUGhmFOAHvoOCvaDB0wvp?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/yuuVwzly9E5Q6F88gZm3KSgyC9SoiJFrPPDR5in97CWTJ3_6w9Q6wlV2kKjA_XvoXxc8lGYUpuPg3wp8a-8xSjxXqjcYvzVOfFi7yAKnRzwh85337RTR3lmOHCc2zM4hToPxU0uW3DVZy0nGYBhUJn1ylWHOTuFvmF_qvEB8as3ZFwfoVN5aiof5T2PH_gV-?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/zCbSX-oCZetwfyso7wE_UfL28HYw1fkPxVWmrf9mW4rUG3v4WjlB-3MDeXMmgOFQF9glYBYrpRmQN9GAYU2SfUPWic7CyT60Ucyy5W8eNCuyIewVKy4MWo40AKCtGxl8pYyJMA8W-6yWAIqUKaGmj28cMIk355o9a6ryYERgp20iviGYkJm1GHOlY4wtnIJs?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/3ZJLs-rXDf_96j-IqHxTaRajJ0aeM7phiNBBcItwCqoD4M0WZMcxQcGyXBr77X2UKM_4ddYtrCLPr-Zbz75ezhFEEtU2AOu2-6QMwJjjM31swoeNUwtT7koxgn25arT5jcIFUno2syzh-4l5CYC-LmR5RFoPTOIALWuKXzYJ4nfNBWq7B0LKP7ZCmfA2suKH?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/NJPJB5khcY8dhRuDvEW6yavcdjPYtZ8Xcdd7p8aGdElJC35pbI1ajwwO6UbDdMsMFMiH8fzt-Ir85ty1c-x8c91mfUhnvOHwn2zXJgQ1LHKVR-MOAYZTJZremfuV_m7mAhpKZ73bXzbeTViT3Itdg_RnvlPEbY6JeEXhwrm7ImIaPz5OE_bt9oubyJJKcwKU?purpose=fullsize)

```text
                 WEB APPLICATION
                       │
                       ▼
                 IDENTIFICATION
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
        Application            Version
             │                   │
             └─────────┬─────────┘
                       ▼
                   ENUMERATION
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
      Endpoints     Features    Technology
          │            │            │
          └────────────┼────────────┘
                       ▼
                AUTHENTICATION
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
       Valid Credentials    Default Creds
             │                   │
             └─────────┬─────────┘
                       ▼
                FUNCTIONALITY
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
       APIs       File Operations   Scripts
        │              │              │
        └──────────────┼──────────────┘
                       ▼
                 VULNERABILITY
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
        Public       Misconfig     Abuse of
       Exploit                     Functionality
          │            │            │
          └────────────┼────────────┘
                       ▼
                     RCE
                       │
                       ▼
                  FOOTHOLD
                       │
                       ▼
             INTERNAL ENVIRONMENT
                       │
                       ▼
              LATERAL MOVEMENT
```

## 🧠 Final takeaway

The **core lesson of this introduction** is not simply _"learn these nine applications."_

It is:

> **Learn how applications work, enumerate them carefully, understand their functionality, identify misconfigurations and known vulnerabilities, and think about how legitimate features could be abused to create an attack path.**

That mindset is what lets you work against **unfamiliar applications**, rather than depending entirely on memorized exploits.