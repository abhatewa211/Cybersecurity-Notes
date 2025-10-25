## 1. Introduction

Domain Name System (DNS) is used to translate human-readable domain names into IP addresses. In Linux, BIND (Berkeley Internet Name Domain) is the most commonly used DNS server.

## 2. Prerequisites

- A Linux-based system (Ubuntu, CentOS, or Debian)
- Root or sudo privileges
- A static IP address configured on the server

## 3. Installation of BIND DNS Server

### On Ubuntu/Debian:

```Bash
sudo apt update
sudo apt install bind9 bind9-utils bind9-doc -y
{SSHA}9vPH/GPH8LjXrvnlz0Lw02gCM7ObclND
```

### On CentOS/RHEL:

```Bash
sudo yum install bind bind-utils -y
```

## 4. Configuration of BIND DNS Server

### 4.1 Main Configuration File: `/etc/bind/named.conf.options` (Ubuntu/Debian) or `/etc/named.conf` (CentOS/RHEL)

Edit the configuration file:

```Bash
sudo nano /etc/bind/named.conf.options
```

Modify or add the following:

```Plain
options {
    directory "/var/cache/bind";
    recursion yes;
    allow-query { any; };
    listen-on port 53 { any; };
};
```

Save and exit.

### 4.2 Creating a Zone File

Edit the named configuration file to add a new zone:

```Bash
sudo nano /etc/bind/named.conf.local  # Ubuntu/Debian
sudo nano /etc/named.conf             # CentOS/RHEL
```

Add:

```Plain
zone "example.com" IN {
    type master;
    file "/etc/bind/db.example.com"; # Ubuntu/Debian
};
```

Add Centos9 config file changes

```Plain
sudo vim /etc/named.conf
options {
        listen-on port 53 { 127.0.0.1; 192.168.29.55; };
        listen-on-v6 port 53 { ::1; };
        directory       "/var/named";
        dump-file       "/var/named/data/cache_dump.db";
        statistics-file "/var/named/data/named_stats.txt";
        memstatistics-file "/var/named/data/named_mem_stats.txt";
        secroots-file   "/var/named/data/named.secroots";
        recursing-file  "/var/named/data/named.recursing";
        allow-query     { localhost; 192.168.29.55; };
```

Create the zone file:

```Bash
sudo nano /etc/bind/db.example.com  # Ubuntu/Debian
```

Example zone file:

```Plain
$TTL 604800
@   IN  SOA example.com. root.example.com. (
        2   ; Serial
        604800  ; Refresh
        86400   ; Retry
        2419200 ; Expire
        604800  ; Negative Cache TTL
)
;
@       IN  NS  ns1.example.com.
ns1     IN  A   192.168.1.1
www     IN  A   192.168.1.100
```

Save and exit.

## 5. Restart and Enable DNS Service

```Bash
sudo systemctl restart bind9   # Ubuntu/Debian
sudo systemctl enable bind9

sudo systemctl restart named   # CentOS/RHEL
sudo systemctl enable named
```

## 6. Allow Firewall Rules

```Bash
sudo ufw allow 53/tcp   # Ubuntu/Debian
sudo firewall-cmd --add-service=dns --permanent  # CentOS/RHEL
sudo firewall-cmd --reload
```

## 7. Testing the DNS Server

To check if the DNS server is working properly, use the following commands:

```Bash
nslookup example.com 127.0.0.1
dig example.com @127.0.0.1
```

If the correct IP addresses are returned, your DNS server is successfully installed and configured.