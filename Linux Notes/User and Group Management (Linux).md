### 1. User and Group Management in Linux

Linux supports multiple users and groups. Each user is identified by a unique UID and associated with a default group (GID). Groups help manage user permissions in a scalable way.

**Key Files:**

- `/etc/passwd`: Stores user account info
- `/etc/shadow`: Stores encrypted user passwords
- `/etc/group`: Stores group information

**Example Scenario:**  
A system administrator wants to add a new employee, Alice, to the system and place her in the 'developers' group for accessing development files.  

```Shell
sudo groupadd developers
sudo useradd -m -s /bin/bash -G developers alice
sudo passwd alice
```

---

### 2. System Files in Linux

System files are critical for the operation and configuration of Linux.

**Important Directories:**

- `/etc`: Configuration files
- `/bin`, `/sbin`: Essential binary executables
- `/var`: Variable files like logs
- `/home`: User home directories

**Example Scenario:**  
Check system logs to diagnose a service issue.  

```Shell
cd /var/log
less syslog
```

---

### 3. Shells in Linux

A shell allows interaction with the system using commands.

**Common Shells:**

- `/bin/bash`: Bourne Again Shell
- `/bin/sh`: Bourne Shell
- `/bin/zsh`, `/bin/ksh`

**Example Scenario:**  
A user prefers zsh over bash:  

```Shell
chsh -s /bin/zsh
```

---

### 4. useradd Command in Linux

Creates a new user.

**Syntax:**

```Shell
useradd [options] username
```

**Options:**

- `m`: Create home directory
- `s`: Specify shell
- `G`: Add to groups

**Example:**

```Shell
useradd -m -s /bin/bash -G developers john
```

---

### 5. usermod Command in Linux

Modifies an existing user account.

**Syntax:**

```Shell
usermod [options] username
```

**Example Scenario:**  
Change shell and add user to a group:  

```Shell
usermod -s /bin/zsh -G sudo john
```

---

### 6. groupadd Command in Linux

Creates a new group.

**Syntax:**

```Shell
groupadd groupname
```

**Example:**

```Shell
groupadd qa_team
```

---

### 7. Linux Permissions

Linux uses a permission system to control access.

**Permission Types:**

- `r` – read
- `w` – write
- `x` – execute

**User Categories:**

- Owner
- Group
- Others

**Example:**

```Shell
ls -l
chmod 755 script.sh
```

---

### 8. chown and chmod Commands in Linux

`chown` changes ownership; `chmod` changes permissions.

**Examples:**

```Shell
chown john:developers file.txt
chmod 644 file.txt
```

**Scenario:** A file needs to be owned by a new user and readable by everyone.

---

### 9. chmod Command in Linux

Change file/directory permissions.

**Numeric Mode:**

- 7 = rwx
- 6 = rw-
- 5 = r-x

**Symbolic Mode:**

```Shell
chmod u+x file.sh
```

---

### 10. Special Permissions in Linux

- **SUID:** Run as file owner
- **SGID:** Run as group
- **Sticky Bit:** Only owner can delete files in a directory

**Example:**

```Shell
chmod u+s script.sh   # SUID
chmod g+s shared_dir  # SGID
chmod +t /public      # Sticky bit
```

---

### 11. Setgid and Sticky Bit

**SGID Directory Example:**

```Shell
mkdir shared_dir
chmod g+s shared_dir
```

New files inherit the group of the directory.

**Sticky Bit Example:**

```Shell
chmod +t /shared_dir
```

Only the file's owner can delete it.

---

### 12. Access Control List (ACL) in Linux

ACLs allow more fine-grained permissions than chmod.

**Commands:**

```Shell
setfacl -m u:alice:rwx file.txt
getfacl file.txt
```

**Scenario:**  
Give a specific user full access to a file without changing group or global permissions.  

---

### 13. su and sg Commands in Linux

- `su`: Switch user
- `sg`: Execute command with a different group

**Examples:**

```Shell
su - john
sg developers -c "make build"
```

**Scenario:** Temporarily switch to another user or execute a command under a group.