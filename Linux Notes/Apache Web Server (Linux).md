## 1. Binding with IP Address in Apache

**Concept**: Configuring Apache to respond to requests on specific IP addresses.

**Configuration Example**:

```Plain
<VirtualHost 192.168.1.100:80>
    ServerAdmin webmaster@example.com
    DocumentRoot /var/www/html/example
    ServerName example.com
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
```

**Scenario**: A server with multiple IP addresses (192.168.1.100 and 192.168.1.101) hosting different websites on each IP.

**Implementation Steps**:

1. Assign multiple IPs to the server
2. Create separate VirtualHost blocks for each IP
3. Set up different DocumentRoot directories for each site
4. Restart Apache (`systemctl restart apache2`)

## 2. Binding with Domain Names in Apache

**Concept**: Hosting multiple websites on a single IP using virtual hosts.

**Example Configuration**:

```Plain
<VirtualHost *:80>
    ServerName site1.example.com
    DocumentRoot /var/www/site1
    # Other directives...
</VirtualHost>

<VirtualHost *:80>
    ServerName site2.example.com
    DocumentRoot /var/www/site2
    # Other directives...
</VirtualHost>
```

**Scenario**: A web hosting company serving hundreds of websites from a single server.

**Implementation**:

1. Configure DNS records for each domain to point to server IP
2. Set up name-based virtual hosts in Apache
3. Ensure `NameVirtualHost *:80` is enabled

## 3. Binding with Type (SSL-TLS)

**Concept**: Securing websites with HTTPS using SSL/TLS certificates.

**Example Configuration**:

```Plain
<VirtualHost *:443>
    ServerName secure.example.com
    DocumentRoot /var/www/secure-site

    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/example.crt
    SSLCertificateKeyFile /etc/ssl/private/example.key
    SSLCertificateChainFile /etc/ssl/certs/example.ca-bundle
</VirtualHost>
```

**Scenario**: An e-commerce site requiring secure transactions.

**Implementation Steps**:

1. Obtain SSL certificate (from Let's Encrypt or commercial CA)
2. Configure Apache SSL module (`a2enmod ssl`)
3. Set up VirtualHost for port 443
4. Redirect HTTP to HTTPS (best practice)

## 4. Directory Listing

**Concept**: Controlling how Apache displays directory contents when no index file exists.

**Example Configuration**:

```Plain
<Directory /var/www/html/public>
    Options +Indexes
    IndexOptions FancyIndexing HTMLTable NameWidth=*
    IndexIgnore .htaccess .gitignore
</Directory>
```

**Scenario**: A file repository where users need to browse available files.

**Key Options**:

- `Options +Indexes`: Enable directory listing
- `IndexOptions`: Customize listing appearance
- `IndexIgnore`: Hide specific files
- `Indexes`: Disable directory listing (more secure)

## 5. Secure Directory Hosting with User Authentication

**Concept**: Restricting access to directories with password protection.

**Example Setup**:

1. Create password file:
    
    ```Shell
    htpasswd -c /etc/apache2/.htpasswd user1
    ```
    
2. Configure Apache:
    
    ```Plain
    <Directory "/var/www/secure">
        AuthType Basic
        AuthName "Restricted Content"
        AuthUserFile /etc/apache2/.htpasswd
        Require valid-user
    </Directory>
    ```
    

**Scenario**: A company intranet with sensitive HR documents.

**Implementation Notes**:

- Use HTTPS with Basic Auth to prevent password sniffing
- Consider digest authentication for slightly better security
- For more security, implement client certificate authentication

## 6. WebDAV with Apache

**Concept**: Enabling file management over HTTP protocol.

**Example Configuration**:

```Plain
<Directory /var/www/webdav>
    DAV On
    AuthType Basic
    AuthName "WebDAV"
    AuthUserFile /etc/apache2/webdav.passwd
    Require valid-user
</Directory>
```

**Scenario**: A remote team collaborating on documents without VPN.

**Implementation Steps**:

1. Enable WebDAV modules (`dav`, `dav_fs`)
2. Configure authentication
3. Set proper file permissions
4. Test with WebDAV client (Windows Explorer, Cadaver)

## 7. CGI Scripts (Common Gateway Interface)

**Concept**: Running external programs to generate dynamic content.

**Example Configuration**:

```Plain
<Directory /var/www/cgi-bin>
    Options +ExecCGI
    AddHandler cgi-script .cgi .pl .py
</Directory>
```

**Example Perl CGI Script**:

```Perl
#!/usr/bin/perl
print "Content-type: text/html\\n\\n";
print "<html><body><h1>Hello CGI World!</h1></body></html>";
```

**Scenario**: A legacy application that still relies on CGI scripts.

**Security Considerations**:

- Place CGI scripts in separate directory from regular HTML
- Limit script permissions
- Consider more modern alternatives (PHP, Python WSGI) when possible

## 8. Debian Setup

**Initial Apache Installation on Debian**:

```Shell
sudo apt update
sudo apt install apache2
sudo systemctl enable apache2
sudo systemctl start apache2
```

**Key Files/Directories**:

- `/etc/apache2/apache2.conf`: Main config file
- `/etc/apache2/sites-available/`: Virtual host configurations
- `/etc/apache2/mods-available/`: Available modules
- `/var/www/html/`: Default web root

**Debian-Specific Commands**:

- Enable site: `a2ensite example.com`
- Disable site: `a2dissite example.com`
- Enable module: `a2enmod rewrite`
- Disable module: `a2dismod rewrite`

## 9. WordPress on Debian

**Installation Steps**:

1. Install prerequisites:
    
    ```Shell
    sudo apt install php mysql-server php-mysql
    ```
    
2. Create MySQL database and user for WordPress
3. Download and extract WordPress:
    
    ```Shell
    wget <https://wordpress.org/latest.tar.gz>
    tar -xzvf latest.tar.gz
    sudo mv wordpress /var/www/html/example.com
    ```
    
4. Configure Apache VirtualHost:
    
    ```Plain
    <VirtualHost *:80>
        ServerName example.com
        DocumentRoot /var/www/html/example.com
        <Directory /var/www/html/example.com>
            AllowOverride All
        </Directory>
    </VirtualHost>
    ```
    
5. Complete WordPress installation via web interface

**Performance Tips**:

- Enable OPcache for PHP
- Install caching plugin
- Consider Nginx as reverse proxy