### 1. Sudo Configuration in Linux

The `sudo` command allows permitted users to run commands as the superuser or another user.

**Configuration File:** `/etc/sudoers` (Use `visudo` to edit it safely)

**Structure:**

```Plain
user host=(run-as) command
```

**Example Entry:**

```Shell
john ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart apache2
```

**Scenario:**  
You want the user  
`john` to restart the Apache server without entering a password.

**Steps:**

1. Run `sudo visudo`
2. Add the above line to allow permission.

---

### 2. Using Aliases in Sudo

Aliases are useful to group users, commands, or hosts for easier management.

**Types of Aliases:**

- `User_Alias`
- `Runas_Alias`
- `Host_Alias`
- `Cmnd_Alias`

**Example:**

```Shell
User_Alias ADMINS = alice, bob
Cmnd_Alias SERVICES = /bin/systemctl restart nginx, /bin/systemctl restart apache2
ADMINS ALL=(ALL) NOPASSWD: SERVICES
```

**Scenario:**  
Allow  
`alice` and `bob` to restart web services without password prompts.

---

### 3. Reset Root Password

Resetting the root password is essential when access is lost or compromised.

**Steps (GRUB Method):**

1. Reboot and hold `Shift` or `Esc` to access GRUB menu.
2. Select your Linux entry and press `e` to edit.
3. Find the line starting with `linux` and append:
    
    ```Shell
    init=/bin/bash
    ```
    
4. Press `Ctrl + X` to boot.
5. Mount root as read-write:
    
    ```Shell
    mount -o remount,rw /
    ```
    
6. Change root password:
    
    ```Shell
    passwd
    ```
    
7. Reboot:
    
    ```Shell
    exec /sbin/init
    ```
    

**Scenario:**  
You’ve forgotten the root password and need to regain administrative access.  

---

### 4. Protect GRUB Boot Loader by Password

Securing GRUB prevents unauthorized users from editing boot entries.

**Steps:**

1. Generate a password hash:
    

grub-mkpasswd-pbkdf2

````Plain
2. Copy the hashed output.
3. Edit `/etc/grub.d/40_custom` and add:
```bash
set superusers="admin"
password_pbkdf2 admin [hashed-password]
````

1. Update GRUB:
    
    ```Shell
    update-grub
    ```
    

**Scenario:**  
Prevent someone with physical access from resetting the root password via GRUB.  

**Note:** Always test GRUB changes and keep a backup method (e.g., live USB).