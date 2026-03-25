## 🔗 What are Sessions?

- **Sessions** allow msfconsole to:
    
    - Manage **multiple modules simultaneously**
        
    - Maintain **active connections to target systems**
        

👉 In simple terms:  
**Session = Dedicated control interface for exploited target**

---

## 🧠 Key Concept

- Each successful exploit → creates a **session**
    
- Multiple sessions → can be:
    
    - Switched
        
    - Backgrounded
        
    - Reused
        

✔️ Sessions provide **flexibility in penetration testing**

---

## 🖥️ Session Communication Flow

![Image](https://www.mdpi.com/applsci/applsci-13-07161/article_deploy/html/images/applsci-13-07161-g001-550.jpg)

![Image](https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/6877c6d94cd1d4bca7c48143_bind-shell-vs-reverse-shell-01.png)

![Image](https://cdn.prod.website-files.com/5ff66329429d880392f6cba2/6707ebe9b46cc26de7bcd58a_6707e41e9a3e4a62b7053365_2%2520-%252010.10-min.jpeg)

![Image](https://www.hackthebox.com/storage/blog/YnHEQmhMyFQOFq6EfH5B4xV1NO5d7YPL.jpg)

✔️ Flow:

1. Exploit executed
    
2. Payload runs on target
    
3. Session created
    
4. Attacker gains control
    

---

## ⚙️ Using Sessions

### 🔹 Background a Session

You can background a session using:

- Keyboard:
    
    ```
    CTRL + Z
    ```
    
- Command:
    
    ```bash
    background
    ```
    

✔️ Result:

- Session continues running
    
- You return to `msf6 >` prompt
    

---

## 📋 Listing Active Sessions

```bash
msf6 > sessions
```

### Example:

```bash
Active sessions
===============

Id  Name  Type                     Information                 Connection
--  ----  ----                     -----------                 ----------
1         meterpreter x86/windows  NT AUTHORITY\SYSTEM @ MS01  10.10.10.129:443 -> 10.10.10.205:50501
```

✔️ Displays:

- Session ID
    
- Session type
    
- User/system info
    
- Connection details
    

---

## 🔌 Interacting with a Session

```bash
sessions -i 1
```

✔️ Output:

```bash
[*] Starting interaction with 1...

meterpreter >
```

✔️ Opens:

- Interactive shell (Meterpreter)
    

---

## 🔄 Switching Between Sessions

- Background current session
    
- Use:
    

```bash
sessions -i <id>
```

✔️ Enables multitasking across compromised systems

---

## 🧪 Running Modules on Sessions

- After exploitation:
    
    - Background session
        
    - Select new module
        
    - Assign session ID
        

✔️ Mostly used with:

- **Post-exploitation modules**
    

---

## 🔍 Post-Exploitation Modules

Common types:

- Credential gatherers
    
- Local exploit suggesters
    
- Internal network scanners
    

👉 Located in:

```
post/
```

---

## ⚠️ Session Stability

- Sessions may die due to:
    
    - Payload crash
        
    - Network interruption
        
    - System reboot
        

✔️ Important:  
👉 Always monitor session stability

---

# ⚙️ Jobs in Metasploit

---

## 🧠 What are Jobs?

- **Jobs** are:
    
    - Background tasks running inside Metasploit
        

👉 Example:

- Exploit handler
    
- Scanners
    

---

## 🔄 Why Jobs are Needed

- Avoid blocking terminal
    
- Run multiple tasks simultaneously
    
- Free up ports properly
    

---

## 🧰 Jobs Workflow

![Image](https://patrick.cloke.us/images/celery-architecture/celery-overview.png)

![Image](https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/6877c6d94cd1d4bca7c48143_bind-shell-vs-reverse-shell-01.png)

![Image](https://miro.medium.com/1%2A-iAskGXB1hJmS7p2Q-eDLQ.png)

![Image](https://substackcdn.com/image/fetch/f_auto%2Cq_auto%3Agood%2Cfl_progressive%3Asteep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fcb896b5d-bba1-456b-bba4-e927366e1da4_3225x1991.png)

✔️ Flow:

1. Run exploit as job
    
2. Job executes in background
    
3. User continues working
    

---

## 📋 Viewing Jobs

```bash
jobs -l
```

### Example:

```bash
Jobs
====

Id  Name                    Payload                    Payload opts
--  ----                    -------                    ------------
0   Exploit: multi/handler  generic/shell_reverse_tcp  tcp://10.10.14.34:4444
```

---

## ❌ Killing Jobs

### 🔹 Kill specific job

```bash
kill <job_id>
```

---

### 🔹 Kill all jobs

```bash
jobs -K
```

---

## 🔍 Jobs Help Menu

```bash
jobs -h
```

### Important Options:

- `-l` → List jobs
    
- `-k` → Kill job
    
- `-K` → Kill all jobs
    
- `-i` → Detailed job info
    

---

## 🚀 Running Exploit as Job

```bash
exploit -j
```

✔️ Runs exploit:

- In background
    
- As a job
    

---

### Example Output:

```bash
[*] Exploit running as background job 0
[*] Started reverse TCP handler on 10.10.14.34:4444
```

---

## ⚠️ Important Scenario (Very Important)

❌ If you press:

```
CTRL + C
```

- Session stops
    
- BUT port may still be in use
    

✔️ Correct approach:

- Use `jobs`
    
- Kill job properly
    

---

## 🔗 Sessions vs Jobs

|Feature|Sessions|Jobs|
|---|---|---|
|Purpose|Target access|Background task|
|Interaction|Yes|No|
|Example|Meterpreter|Handler|
|Control|sessions -i|jobs -l|

---

## ⚠️ Important Notes (Keep These)

✔️ Sessions:

- Maintain connection to target
    
- Can be backgrounded
    
- Used for post-exploitation
    

✔️ Jobs:

- Handle background execution
    
- Must be managed to free ports
    

✔️ Important:

- Session ≠ Job
    
- Both must be handled separately
    

---

## 🧾 Summary

|Concept|Description|
|---|---|
|Session|Active control channel|
|Background|Keep session running|
|jobs|Background processes|
|exploit -j|Run exploit as job|
|sessions -i|Interact with session|

---
