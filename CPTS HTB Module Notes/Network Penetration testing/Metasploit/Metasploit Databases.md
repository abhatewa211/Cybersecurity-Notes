## 🗄️ What are Databases in Metasploit?

- Databases in **msfconsole** are used to:
    
    - Store **scan results**
        
    - Track **hosts, services, vulnerabilities**
        
    - Save **credentials and loot**
        

👉 In simple terms:  
**Database = Memory system of Metasploit**

---

## 🧠 Why Databases are Important

- Helps manage:
    
    - Large networks
        
    - Multiple scan results
        
    - Credentials & vulnerabilities
        

✔️ Without database → Data becomes messy  
✔️ With database → Everything organized

---

## 🏗️ Architecture Overview

![Image](https://www.offsec.com/_astro/msfarch2_1bRFkI.webp)

![Image](https://www.researchgate.net/publication/338491379/figure/fig3/AS%3A863876128194561%401582975527957/Process-of-automation-of-penetration-testing.ppm)

![Image](https://cdn.prod.website-files.com/5ff66329429d880392f6cba2/6707ebe9b46cc26de7bcd58a_6707e41e9a3e4a62b7053365_2%2520-%252010.10-min.jpeg)

![Image](https://www.varonis.com/hubfs/Imported_Blog_Media/metasploit-guide-set-up.png?hsLang=en)

✔️ Metasploit uses:

- **PostgreSQL database**
    
- Integrated directly with **msfconsole**
    

---

## ⚙️ Setting up Database

### 🔹 Check PostgreSQL Status

```bash
sudo service postgresql status
```

✔️ Must be **active**

---

### 🔹 Start PostgreSQL

```bash
sudo systemctl start postgresql
```

---

### 🔹 Initialize Database

```bash
sudo msfdb init
```

✔️ This will:

- Create user → `msf`
    
- Create databases → `msf`, `msf_test`
    
- Generate config file
    

---

### ⚠️ Error Handling

If error occurs:

```bash
apt update
sudo msfdb init
```

✔️ If already configured:

```bash
sudo msfdb status
```

---

## 🚀 Start Metasploit with Database

```bash
sudo msfdb run
```

✔️ Automatically:

- Starts database
    
- Opens msfconsole
    

---

## 🔁 Reinitialize Database (If Needed)

```bash
msfdb reinit
cp /usr/share/metasploit-framework/config/database.yml ~/.msf4/
sudo service postgresql restart
msfconsole -q
```

✔️ Check connection:

```bash
db_status
```

✔️ Output:

```
Connected to msf. Connection type: PostgreSQL.
```

---

## 🧰 Database Commands

```bash
help database
```

### Important Commands:

|Command|Purpose|
|---|---|
|db_status|Check connection|
|db_connect|Connect database|
|db_disconnect|Disconnect|
|db_import|Import scan results|
|db_export|Export data|
|db_nmap|Run Nmap inside MSF|

---

## 🗂️ Workspaces

👉 Workspaces = **Folders/Projects**

### 🔹 View Workspaces

```bash
workspace
```

---

### 🔹 Create Workspace

```bash
workspace -a Target_1
```

---

### 🔹 Switch Workspace

```bash
workspace Target_1
```

---

### 🔹 Delete Workspace

```bash
workspace -d Target_1
```

---

### 🧠 Concept Visualization

![Image](https://images.squarespace-cdn.com/content/v1/5d38a6a24af5650001b6f7bb/e918265a-d468-40e1-9538-119af11164ce/firewall-every-server.PNG)

![Image](https://techzone.omnissa.com/sites/default/files/imported-images/node_5050_0116-054857/98790-0116-054851/98790-0116-054851-10.png)

![Image](https://media.licdn.com/dms/image/v2/D4D12AQHgXz6bB3cB3w/article-cover_image-shrink_720_1280/article-cover_image-shrink_720_1280/0/1732358863160?e=2147483647&t=m3P2m28evMA7Mzgtz3wsHVVRrYwghlmv1XPKd5v7e8A&v=beta)

![Image](https://media.licdn.com/dms/image/v2/D4E12AQGaWgOOBiurXA/article-cover_image-shrink_600_2000/article-cover_image-shrink_600_2000/0/1681195847847?e=2147483647&t=nq24z-pVlO2lFySEQwpSc2rGMB4tbRFKBg5xHIRT05w&v=beta)

✔️ Helps:

- Separate targets
    
- Manage multiple engagements
    

---

## 📥 Importing Scan Results

### Example Nmap Import

```bash
db_import Target.xml
```

✔️ Preferred format:

- `.xml`
    

---

### 🔍 View Imported Data

```bash
hosts
services
```

✔️ Example:

- Hosts → IP addresses
    
- Services → open ports
    

---

## 🔎 Using Nmap Inside MSF

```bash
db_nmap -sV -sS 10.10.10.8
```

✔️ Automatically:

- Runs scan
    
- Stores results in database
    

---

## 💾 Exporting Data

```bash
db_export -f xml backup.xml
```

✔️ Used for:

- Backup
    
- Sharing results
    

---

## 🖥️ Hosts Command

- Displays:
    
    - IP addresses
        
    - OS info
        
    - Comments
        

### Example Options:

```bash
hosts -h
```

✔️ Can:

- Add hosts
    
- Delete hosts
    
- Filter results
    

---

## 🌐 Services Command

- Shows:
    
    - Open ports
        
    - Service names
        
    - Protocols
        

### Example:

```bash
services -h
```

✔️ Can:

- Add/update services
    
- Filter by port
    

---

## 🔑 Credentials (creds)

- Stores:
    
    - Usernames
        
    - Passwords
        
    - Hashes
        

### Example:

```bash
creds add user:admin password:pass123
```

✔️ Supports:

- NTLM hashes
    
- SSH keys
    
- Database hashes
    

---

## 💰 Loot

- Stores:
    
    - Extracted data
        
    - Hash dumps
        
    - Sensitive files
        

### Example:

```bash
loot -h
```

✔️ Loot includes:

- `/etc/passwd`
    
- Hash dumps
    
- Config files
    

---

## 🧠 Data Flow Concept

![Image](https://cdn.prod.website-files.com/5efc3ccdb72aaa7480ec8179/673c4139f7c9e8a1b4d9468a_61ede195222006f6c54b1f20_Metasploit%2520Framework%2520Architecture.png)

![Image](https://media.licdn.com/dms/image/v2/D4D12AQFyyCxbjXnVQA/article-inline_image-shrink_1000_1488/article-inline_image-shrink_1000_1488/0/1725503825517?e=2147483647&t=U93cbv2dPRwb0hYF4Cjom-m0TwIbyplw1j-pQ51dJBE&v=beta)

![Image](https://media.licdn.com/dms/image/v2/D4E12AQH9Ypw0kC_4DQ/article-cover_image-shrink_720_1280/B4EZUQ9sKpHgAM-/0/1739746362549?e=2147483647&t=aG4XrcISMpetq40hqoefc--PKDTtleNt820YNVQbT0c&v=beta)

![Image](https://cdn.prod.website-files.com/6961173a0b3c0ce2c689dcce/6961173a0b3c0ce2c689ec38_67054eabec287819187f86bf_66437eef0af425dccde9289d_Killchain-Process_Full-Flow.jpeg)

✔️ Flow:

1. Scan → (Nmap)
    
2. Store → (Database)
    
3. Exploit → (Metasploit)
    
4. Save → (Creds/Loot)
    

---

## ⚠️ Important Points (Keep These)

✔️ Database must be:

- Running
    
- Connected
    

✔️ Always:

- Use workspaces
    
- Save results
    

✔️ Use:

- `db_import` for external scans
    
- `db_nmap` for internal scans
    

---

## 🧾 Summary

|Component|Purpose|
|---|---|
|PostgreSQL|Backend database|
|Workspaces|Organize projects|
|Hosts|Store targets|
|Services|Store ports/services|
|Creds|Store credentials|
|Loot|Store extracted data|

---