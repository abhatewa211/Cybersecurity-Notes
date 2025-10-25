## 1. SMB Client Tools

**Concept**: Utilities for accessing SMB/CIFS shares from Linux clients, enabling interaction with Windows file shares or Samba servers.

### Core Tools Package Installation (Debian/Ubuntu):

```Shell
sudo apt update
sudo apt install smbclient cifs-utils
```

### Key Client Tools:

1. **smbclient** - FTP-like interactive client:
    
    ```Shell
    # List available shares
    smbclient -L //server_ip -U username%password
    
    # Connect to specific share
    smbclient //server_ip/sharename -U username
    ```
    
2. **mount.cifs** - Mount SMB shares permanently:
    
    ```Shell
    # Create mount point
    sudo mkdir /mnt/win_share
    
    # Temporary mount
    sudo mount -t cifs //server_ip/sharename /mnt/win_share -o username=user,password=pass
    
    # Permanent mount via /etc/fstab
    //server_ip/sharename  /mnt/win_share  cifs  credentials=/etc/samba/creds,uid=1000,gid=1000,file_mode=0775,dir_mode=0775  0  0
    ```
    
3. **nmblookup** - NetBIOS name resolution:
    
    ```Shell
    nmblookup -A server_ip
    ```
    

### Example Scenario: Corporate File Access

- **Situation**: Linux workstations need access to departmental shares on Windows Server
- **Solution**:
    
    ```Shell
    # Create credentials file (secure with chmod 600)
    echo "username=domain_user" > ~/.smbcred
    echo "password=ComplexPass123" >> ~/.smbcred
    
    # Mount with credentials
    sudo mount -t cifs //fileserver/HR_Docs /mnt/hr -o credentials=~/.smbcred,domain=CORP
    ```
    

### Advanced Usage:

```Shell
# Access specific Windows share with domain authentication
smbclient //dc1/Departments -U CORP\\\\adminuser%Password123

# Backup entire share recursively
smbclient //nas/backups -U user -c "prompt; recurse; mget *"
```

## 2. Samba Server Setup

**Concept**: Configuring a Linux server to provide SMB/CIFS file services compatible with Windows clients.

### Base Installation (Debian/Ubuntu):

```Shell
sudo apt install samba
sudo systemctl enable smbd
sudo systemctl start smbd
```

### Configuration File (`/etc/samba/smb.conf`):

```Plain
[global]
   workgroup = WORKGROUP
   server string = %h server (Samba, Ubuntu)
   security = user
   map to guest = bad user
   dns proxy = no

[homes]
   comment = Home Directories
   browseable = no
   read only = no
   create mask = 0700
   directory mask = 0700
   valid users = %S

[public]
   path = /samba/public
   browseable = yes
   read only = no
   guest ok = yes
   force create mode = 0666
   force directory mode = 0777
```

### User Management:

```Shell
# Create system user
sudo adduser smbuser --shell /usr/sbin/nologin

# Set Samba password (different from system password)
sudo smbpasswd -a smbuser
```

### Share Creation Example:

1. Create directory structure:
    
    ```Shell
    sudo mkdir -p /samba/{public,secured,department}
    sudo chown -R nobody:nogroup /samba/public
    sudo chown -R finance:finance /samba/department
    ```
    
2. Configure department share:
    
    ```Plain
    [finance]
       comment = Financial Documents
       path = /samba/department
       valid users = @finance
       read only = no
       create mask = 0660
       directory mask = 0770
    ```
    

### Enterprise Scenario: Cross-Platform Office Environment

- **Requirements**:
    - Authenticate against Active Directory
    - Departmental shares with group-based access
    - Private user directories
- **Configuration**:
    
    ```Plain
    [global]
       security = ads
       realm = CORP.EXAMPLE.COM
       workgroup = CORP
       idmap config * : backend = tdb
       idmap config * : range = 3000-7999
       winbind enum users = yes
       winbind enum groups = yes
       template homedir = /home/%U
       template shell = /bin/bash
    
    [engineering]
       path = /samba/engineering
       valid users = @CORP\\eng-team
       read only = no
       nt acl support = yes
    ```
    

### Security Hardening:

1. Enable encrypted transport:
    
    ```Plain
    [global]
       smb encrypt = required
       min protocol = SMB3_11
    ```
    
2. Configure firewall:
    
    ```Shell
    sudo ufw allow proto udp ports 137,138
    sudo ufw allow proto tcp ports 139,445
    ```
    

### Troubleshooting Commands:

```Shell
# Test configuration
testparm

# Check connections
smbstatus

# Debug authentication
journalctl -u smbd -f
```

### Practical Implementation Example:

**Situation**: Small office needs shared storage for:

- Public read/write area for temporary files
- Secure department shares
- Private user directories

**Implementation**:

1. Install Samba and configure basic settings
2. Create directory structure with appropriate permissions
3. Configure shares in smb.conf with:
    - Public share with guest access
    - Departmental shares with group restrictions
    - Enabled home directories
4. Set up user accounts with smbpasswd
5. Configure Windows clients to map network drives:
    
    ```Plain
    net use Z: \\\\sambaserver\\finance /persistent:yes /user:corp\\username
    ```