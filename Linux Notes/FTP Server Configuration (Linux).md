## 1. Anonymous FTP Access Configuration on a Linux Server

**Concept**: Setting up an FTP server that allows anyone to connect without authentication, typically for public file distribution.

**Package Installation** (using vsftpd on Debian/Ubuntu):

```Shell
sudo apt update
sudo apt install vsftpd
sudo systemctl enable vsftpd
sudo systemctl start vsftpd
```

**Configuration File** (`/etc/vsftpd.conf`):

```Plain
anonymous_enable=YES
no_anon_password=YES
anon_root=/srv/ftp
anon_upload_enable=YES
anon_mkdir_write_enable=YES
anon_other_write_enable=NO
dirmessage_enable=YES
xferlog_enable=YES
connect_from_port_20=YES
chown_uploads=YES
chown_username=ftp
```

**Key Parameters**:

- `anonymous_enable`: Enables anonymous access
- `anon_root`: Sets the root directory for anonymous users
- `anon_upload_enable`: Allows file uploads (ensure directory has proper permissions)
- `anon_mkdir_write_enable`: Allows directory creation
- `chown_uploads`: Changes ownership of uploaded files to specified user

**Directory Setup**:

```Shell
sudo mkdir -p /srv/ftp/pub
sudo chown nobody:nogroup /srv/ftp/pub
sudo chmod 755 /srv/ftp
sudo chmod 777 /srv/ftp/pub
```

**Scenario**: A university department wants to share research papers publicly where:

- Anyone can download files
- Approved contributors can upload to the /pub directory
- No other write permissions are granted

**Security Considerations**:

1. Always place anonymous FTP directory outside of home directories
2. Use chroot to restrict anonymous users to the FTP directory
3. Consider read-only access unless uploads are absolutely necessary
4. Monitor uploads directory for suspicious files
5. Use firewall rules to limit access if needed

**Testing**:

```Shell
ftp localhost
# Login with "anonymous" and any password (or blank)
```

## 2. Access User Home Directory on FTP Server using vsftpd

**Concept**: Configuring authenticated FTP access where users can access their home directories.

**Configuration** (`/etc/vsftpd.conf`):

```Plain
local_enable=YES
write_enable=YES
local_umask=022
chroot_local_user=YES
allow_writeable_chroot=YES
user_sub_token=$USER
local_root=/home/$USER/ftp
userlist_enable=YES
userlist_file=/etc/vsftpd.userlist
userlist_deny=NO
```

**User Setup**:

1. Create system users:
    
    ```Shell
    sudo adduser ftpuser1
    sudo adduser ftpuser2
    ```
    
2. Create FTP directories:
    
    ```Shell
    sudo mkdir /home/ftpuser1/ftp
    sudo mkdir /home/ftpuser2/ftp
    sudo chown ftpuser1:ftpuser1 /home/ftpuser1/ftp
    sudo chown ftpuser2:ftpuser2 /home/ftpuser2/ftp
    ```
    
3. Add allowed users to vsftpd.userlist:
    
    ```Shell
    echo "ftpuser1" | sudo tee -a /etc/vsftpd.userlist
    echo "ftpuser2" | sudo tee -a /etc/vsftpd.userlist
    ```
    

**Scenario**: A small business needs to provide secure file access where:

- Each employee has personal FTP space
- Users are restricted to their own directories
- Only specific employees should have FTP access

**Security Enhancements**:

1. Enable SSL/TLS for encrypted connections:
    
    ```Plain
    ssl_enable=YES
    rsa_cert_file=/etc/ssl/certs/vsftpd.pem
    rsa_private_key_file=/etc/ssl/private/vsftpd.key
    ```
    
2. Implement connection limits:
    
    ```Plain
    max_clients=50
    max_per_ip=5
    ```
    
3. Configure passive mode for better NAT compatibility:
    
    ```Plain
    pasv_enable=YES
    pasv_min_port=40000
    pasv_max_port=50000
    ```
    

**Testing Authentication**:

```Shell
ftp localhost
# Login with user credentials
```

**Troubleshooting Tips**:

1. Check logs: `/var/log/vsftpd.log`
2. Verify permissions on home directories (should not be world-writable)
3. Test with different clients (command-line ftp, FileZilla, etc.)
4. Check SELinux/AppArmor policies if connection issues occur

**Alternative Approach**: For more security, consider using SFTP (SSH File Transfer Protocol) instead of FTP, especially for user home directory access. SFTP provides encryption by default and uses SSH authentication mechanisms.