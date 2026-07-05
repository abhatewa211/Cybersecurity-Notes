## Overview

During penetration testing, we often encounter **network services** that allow users and administrators to manage systems, transfer files, authenticate users, and access resources remotely.

Common services include:

|Service|Purpose|Default Port|
|---|---|---|
|FTP|File Transfer|21|
|SMB|File Sharing|445|
|NFS|Linux File Sharing|2049|
|SSH|Secure Remote Access|22|
|WinRM|Windows Remote Management|5985/5986|
|RDP|Remote Desktop Access|3389|
|MySQL|Database Service|3306|
|MSSQL|Microsoft SQL Database|1433|
|LDAP|Directory Service|389|
|SMTP|Email Sending|25|
|IMAP|Email Retrieval|143|
|POP3|Email Retrieval|110|
|VNC|Remote Desktop|5900|

---

# Visual Overview

![Image](https://images.openai.com/static-rsc-4/rKWV9ecigjb_msz3hFlMIIsh3tmEtvH7eVvgYlMvHlX-FILE6h_kXpdWQI8Ylkh2kMCqfyPK6MNnVlJOPOdwjeFUaFEdH8J5gkp4QlMeBa6lyIKW16kK8GTD-pI54sVVw6AgY5Z9Usa9EafGk5SCHIFfZMtj9DU0w-I9Tr1nFoUPWxXGLuwFUUjOKSHMau9s?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ivS_n9HpYmzdPZzKA8_VD64z4rqHeHOPj-PSoebSrh5SeVXKKIAeXarPCUqdFJXZb8zLonpmTMgiUt5pBiBGdB93tNyIuIWTo-84_mkgGwZ0xhCPk9xWonFIAu_PYNNjn39KBi2tEtjEgFeq2X7TCNVSPoESWZG_rIXozPABppcZXEtkNmXJixyXU6B15fNy?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/HYljji7GyyCG2GDUoEKHQl_f1RBbcY0K8DBbY-ahrZPmsRgBMYz8uZ4nQYNFNqQCtAFxUPwM_0jaUT5RjQCHu-dqBv3gMuT8EQKSzqGUJEfOeii7BWbT-uA0scNlV4e47GAzdDheYr_ERCbkuFCHfYin2c40XQ8ioCYT94TjmwB05kcNPr_FXQjZAZIsAldV?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/uAcuSN6xuSTeCZbLpBJsRDKkM4uKkDxuZhox9BEa9C6LfA1NEOwDtSWLEb-Xn6U9K6S4PydJXv5x9xx-DUCXfo1rCMq7G6EtCO7EfigQhXkEExKocnXAXyV5DtGb5t-VnhAMu4evGY0IDMLiCMSU2-7-aQ6WfUHnyffpcTYN5HZV-uEDjwy7Zk2elJXtAbF6?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/aQaWSP7MwqwVaYqne8HXr1IqKWd8B1nW0wMRWrZwCB8CEnUntmLhpbCi8uqfqMh0_PdG36OEP2eujJZ-Q5c56yIKVvMEPL0tUkVe6Xbqauk7yfpJhaUuGn9ICFopw5tkJobBzcgf3M8YuXg05UPtOHxLTeDtWKpyySdVoZfiBs2XL-K9RWqcbZDMiyglC0Cu?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/nvGZtC4rLiPhzOKHTRHDsKY4Hn1Q4Kk4mNC7Mv71wC2xv0IWPQ-fmuVko7q5yUEPvH0qTx_07wSmQA7QZICs2DvDUcmFsJtCd2MkMqDTjHjgna8b1YsU7350PK3ie5ebskbyB9D3wQibj2LDQ81-zGoJuj5k77sPBQyXE1YOvL9I4c7ozi6uQieXKpFURQ8c?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/vr55Cj-lpfsAl462vv901AvyZSUsUFow05PY9KU28-B0ZOGOs_fcqa5rzlFlQ1nSxJSIM7YwyaTXVR-iJlZjm9wQxpBlFl7JMsIDXfLRasHSeigjRsS82G3XcN4Byub6FVqVWyR8qjXyOtD7O42rLI5mIJC1MePfhJU0UrXcw_izdSV0P4EMC7QSQYqR88KW?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/HF3A3_6Xkt-mi6MXwhQjCW1t0FAHUiceitUgQck2cJwybvhOCEN6J-WcCQXPKxd0w3tkNgP86dOVhetgH_kvC0P7_FwkCvBwLTtJZhpP0pbdtzQVgX6QOZ1-kRsCiqNAnklHlwrGe1tfbxZg34088ZeYq1HiucTOZ13VPY187X5c_6boHv8GJTkPlYvI0MaZ?purpose=fullsize)

---

# 1. WinRM (Windows Remote Management)

## What is WinRM?

WinRM is Microsoft's implementation of:

**WS-Management (WS-Man)**

It allows administrators to remotely manage Windows systems using:

- XML
    
- SOAP
    
- WMI
    
- PowerShell Remoting
    

### Default Ports

|Protocol|Port|
|---|---|
|HTTP|5985|
|HTTPS|5986|

---

## WinRM Architecture

```text
Administrator
      |
      |
   WinRM
      |
  SOAP/XML
      |
     WMI
      |
    Windows
```

---

## Key Exam Points

✅ Used for remote administration

✅ Uses SOAP-based communication

✅ Works with PowerShell Remoting

✅ Disabled by default on many Windows systems

✅ Ports 5985 & 5986

---

# NetExec

## What is NetExec?

NetExec (NXC) is one of the most powerful tools for:

- SMB
    
- WinRM
    
- SSH
    
- FTP
    
- LDAP
    
- MSSQL
    
- RDP
    
- WMI
    

credential attacks and enumeration.

---

## Installation

```bash
sudo apt install netexec -y
```

---

## Basic Syntax

```bash
netexec <protocol> <target> -u <user> -p <password>
```

Example:

```bash
netexec smb 10.10.10.5 -u administrator -p Password123
```

---

## Available Protocols

```text
nfs
ftp
ssh
winrm
smb
wmi
rdp
mssql
ldap
vnc
```

---

## WinRM Brute Force

```bash
netexec winrm 10.129.42.197 -u user.list -p password.list
```

Example Result:

```text
[+] None\user:password (Pwn3d!)
```

### Important

🚩 **Pwn3d!**

means:

```text
Credentials valid
Likely command execution possible
```

Memorize this for HTB exams.

---

# Evil-WinRM

## What is Evil-WinRM?

A PowerShell shell used after obtaining WinRM credentials.

Most common post-exploitation tool for WinRM.

---

## Installation

```bash
sudo gem install evil-winrm
```

---

## Usage

```bash
evil-winrm -i <IP> -u <USER> -p <PASSWORD>
```

Example:

```bash
evil-winrm -i 10.129.42.197 -u user -p password
```

---

## Successful Login

```text
*Evil-WinRM* PS C:\Users\user\Documents>
```

You now have a PowerShell session.

---

# 2. SSH (Secure Shell)

## What is SSH?

SSH provides:

- Secure remote administration
    
- Secure file transfer
    
- Command execution
    

### Default Port

```text
22/TCP
```

---

# SSH Security Components

## 1. Symmetric Encryption

Uses same key for:

```text
Encryption
Decryption
```

Examples:

- AES
    
- Blowfish
    
- 3DES
    

---

## 2. Asymmetric Encryption

Uses:

```text
Public Key
Private Key
```

Authentication process:

```text
Server sends challenge
Client decrypts using private key
Authentication succeeds
```

---

## 3. Hashing

Used to:

```text
Verify integrity
Ensure authenticity
```

Examples:

```text
SHA256
SHA512
```

---

# SSH Diagram

![Image](https://images.openai.com/static-rsc-4/i8Kgg2xBel0Vp95Vic3UXK1JGUPD18Zz-CwyjZgyIFPBalI64x_-L1JlyEBMFOx0hOWtXqAJSXDD4xCEs9UMkDq0nkmem41kL18aR4fA_9lzBHWKf7tR3JwD5hwbIxeKm5oULKPybI1g-xIMF7WVX5HdDExprEoF_MJUOEeth78JS6iH1901ja_DzmguqDkH?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/_5Ug90iSfpX9zrNTGutSuKncc7xCcJ7_gSHpTcg-St-79YZ9uDu0IEfNiqZTJXbQhbOQju-lZEkTWIpeyG5tKFhS1GwzS8gmjG_RhGg-vaAmD-lXCctb0KXtBZmYirfnzPutkZt0H6VwqQoKtk2rpIT3CCJTClUJE4th12OBekyEjrybGDgMId5PNCPW6pwO?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/oIV4UiVIIZ17FaqHQufA7q1rw-Mkrz1ETqFkZjSyCYTaNDCNYkWDn3fKmb5O8v2sqPjTxZ7bJvK8x8u1LSXyYzOHpAfR2AK92u-TRX_HarRO4qFhnZ782lo7xFJaUnFFEkOGLz63u9cIwYtJUTMeAaFpLasUaFbsEt2BPlgX13JsW_bF9xmPz9pBJEAh7qUK?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/OphbPqJGUvqbwOZRTDUpA6SqwR4zZ5pF6HgpMfBdQv7-LOPuzsuUGf2NVga95bna4BvkdHu4RjU10jWPlmibl6g91yD8z3h5hPJ7u6OZ9mhgOHRCnq3jFUumar4dPnR-WFJDot1zUTIZG3bI0iQx7KCSu6ihTvGMIBlsoGFTb6Bh4zWNPotUhGbUu77l5sWi?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/RVMxHBBA1LHxn41bfYinNVGU3ytaxITeSCduAoeP4SYyE-QH2kle96IexR_jBtbMq74jXZyOGzR4wMIbTdXQVIRC8z500joHeJPiZGL4NMqd73N4MDlW49DTXqC51TR4_jw9LISw2wSfmA9N8dF6-14cv_r2gQv1dPPZCnf1VkkFfUvCrwjrEZcqMBrRxUsL?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/AUxkJmNPK-Zib5cb09lKGgfshsABXF8rSRgTQbmuU_b4INESJSM-RlvXnIMN9AanQh7LL_3dp5Ez9rJT3c0ZCKznK2AoJErTdth4NJ7w9DXo5vQl1wMUTnarCDV1ansO7D9HgJ9hYYVq2xO0w-jsazTIZTSDumRqylEjLjNgKzMyFj0WERQ1qpwpBHqaeQUh?purpose=fullsize)

---

# Hydra – SSH Brute Force

## Syntax

```bash
hydra -L user.list -P password.list ssh://IP
```

Example:

```bash
hydra -L user.list -P password.list ssh://10.129.42.197
```

Result:

```text
login: user
password: password
```

---

## Login with SSH

```bash
ssh user@10.129.42.197
```

First time:

```text
Are you sure you want to continue connecting?
```

Answer:

```text
yes
```

---

## Successful Login

```text
user@WINSRV C:\Users\user>
```

---

# 3. RDP (Remote Desktop Protocol)

## What is RDP?

Microsoft protocol used to:

- Access Windows desktop remotely
    
- Control mouse
    
- Control keyboard
    
- Use applications remotely
    

---

## Default Port

```text
3389/TCP
```

---

## Features

✅ GUI Access

✅ Remote Desktop

✅ Printer Sharing

✅ Drive Sharing

✅ Clipboard Sharing

---

# RDP Architecture

```text
Client
   |
   |
 RDP
   |
   |
Windows Host
```

---

# Hydra – RDP

```bash
hydra -L user.list -P password.list rdp://IP
```

Example:

```bash
hydra -L user.list -P password.list rdp://10.129.42.197
```

---

## Important Note

Hydra may display:

```text
account valid but RDP disabled
```

Meaning:

```text
Password is correct
RDP access not allowed
```

---

# xFreeRDP

Linux RDP Client

## Syntax

```bash
xfreerdp /v:IP /u:USER /p:PASSWORD
```

Example:

```bash
xfreerdp /v:10.129.42.197 /u:user /p:password
```

---

## Certificate Prompt

```text
Do you trust the certificate?
```

Type:

```text
Y
```

---

# RDP Visual

![Image](https://images.openai.com/static-rsc-4/iHXpZcTNHPb2j9lUx1QN1pE48scyvNEiB0C-lweZobdfZ32pBIhsUWbVZkN0xdqCPuPUIKYXoyUrDaztoh-KNOyLNMcskYY4wTOzSV912yG5iLik3d8PcyP7WAkgDCe0jLdGGYfXDe5tbIz6QCa5_zyeQ-vzkoVI_NtUN_KJvNai0FZTx5ps4YKf71LRdvUl?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/AMie5OiNxgtaRASgcUW1clBWjh3REN8PFVlnJbfeOWI5IxE7SG0DjrPJ3Snus8Rft7Y6oiYh_V6NfkGzq-ykej57dEMuL-dxdm4JcW_1129eB5-zdTT8L902BhI_ORy6IMmERuTpfESJWcadkz4jS_96NsCN-5ja1BlxXpoit9szRvDvQ3RY9HSrGVgxOQrn?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/lGoBmp3NtjZ5-d0kxOspgJ5Pgidz049EXHrlpZOXjkGpseUTaBiVxyq427hYoynU_wp60BJsKMzQtUdJ4jtU-1KtRYR_AsPaAp7g06ERydF-7h9frCh1wxMp9glD8rhD-iGEPIfrDZMDO0agdbOGyO0HcjEitE0b-sBNWjDit7G3bOAHjwZvLl-7v-NkWpzK?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/7ZIUXhK5LkIl-EtT3N8khQzVOiJgFdhtQmHtJLt_XGBuYUv82uk2BgiO5_WeJxIWXh1th4XT0gKdJh2s9UzFnHvSgxhi6qes8QCTKSjj8PJJNIDEGobNOwuDOiLoqlUjeeouhRwQoerktSsBg0FufTiQDZcPydvL_xC3e2hZrHY5eESFWIPs4Lu9z65YKuXb?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/90vKJHZ6rvAY7cBt-iNaMjF8zPmjEHVxvJLY6oKZ2MEnXtlx0tBVqaPb2QP2xR89LXgcVtGL3rBH5ekDuqGWCdaaXVTJvizTd5W8MUhqBuIcVY3kacp7PhKOEW6yyUKSorn2Kgr5geGoffRUklgsIQFTHMM6olse8aCnTbXy6Gg7xPDhvKhnsXsQhw9W-1gc?purpose=fullsize)

---

# 4. SMB (Server Message Block)

## What is SMB?

Windows file-sharing protocol.

Used for:

- File Sharing
    
- Folder Sharing
    
- Printer Sharing
    
- Network Communication
    

---

## Default Port

```text
445/TCP
```

---

## SMB vs CIFS

```text
SMB = Protocol
CIFS = Older SMB implementation
```

---

## Samba

Open-source SMB implementation for:

- Linux
    
- macOS
    
- Unix
    

---

# Hydra – SMB

```bash
hydra -L user.list -P password.list smb://IP
```

Example:

```bash
hydra -L user.list -P password.list smb://10.129.42.197
```

---

## SMBv3 Error

Sometimes Hydra returns:

```text
invalid reply from target
```

Reason:

```text
Old Hydra version
Cannot handle SMBv3
```

Solution:

```text
Update Hydra
OR
Use Metasploit
```

---

# SMB Login Using Metasploit

## Start Metasploit

```bash
msfconsole -q
```

---

## Load SMB Module

```bash
use auxiliary/scanner/smb/smb_login
```

---

## Configure

```bash
set user_file user.list

set pass_file password.list

set rhosts 10.129.42.197
```

---

## Execute

```bash
run
```

Result:

```text
Success: '.\user:password'
```

---

# SMB Enumeration with NetExec

## Enumerate Shares

```bash
netexec smb 10.129.42.197 -u user -p password --shares
```

Example Output:

```text
ADMIN$
C$
IPC$
SHARENAME
```

---

## Common Shares

|Share|Purpose|
|---|---|
|ADMIN$|Remote Administration|
|C$|Root Drive|
|IPC$|Inter Process Communication|
|SHARENAME|Custom Share|

---

## Permissions

```text
READ
WRITE
FULL
```

---

# SMBClient

Tool used to interact with SMB shares.

---

## Connect

```bash
smbclient -U user \\\\10.129.42.197\\SHARENAME
```

---

## List Files

```bash
ls
```

Example:

```text
desktop.ini
```

---

## Useful SMBClient Commands

|Command|Purpose|
|---|---|
|ls|List files|
|cd|Change directory|
|get|Download file|
|put|Upload file|
|mkdir|Create directory|
|rm|Delete file|
|help|Show commands|

---

# HTB Exam Quick Cheatsheet

### WinRM

```bash
netexec winrm IP -u users.txt -p passwords.txt

evil-winrm -i IP -u user -p password
```

---

### SSH

```bash
hydra -L users.txt -P passwords.txt ssh://IP

ssh user@IP
```

---

### RDP

```bash
hydra -L users.txt -P passwords.txt rdp://IP

xfreerdp /v:IP /u:user /p:password
```

---

### SMB

```bash
hydra -L users.txt -P passwords.txt smb://IP

netexec smb IP -u user -p password --shares

smbclient -U user \\\\IP\\SHARE
```

---

# Things to Memorize for CPTS

⭐ WinRM Ports → **5985 / 5986**

⭐ SSH Port → **22**

⭐ RDP Port → **3389**

⭐ SMB Port → **445**

⭐ NetExec Success → **(Pwn3d!)**

⭐ Evil-WinRM = Best WinRM Shell

⭐ xFreeRDP = Linux RDP Client

⭐ SMB Enumeration:

```bash
netexec smb IP -u user -p pass --shares
```

⭐ SMB File Access:

```bash
smbclient -U user \\\\IP\\SHARE
```

⭐ Hydra supports:

```text
SSH
RDP
SMB
FTP
HTTP
Telnet
Many others
```

	These are the key notes from this HTB module that are highly relevant for CPTS, HTB Academy labs, and real-world Active Directory assessments.