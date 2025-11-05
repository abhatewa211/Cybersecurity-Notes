## Introduction to DHCP

**DHCP (Dynamic Host Configuration Protocol)** is a network protocol that automatically assigns IP addresses and other network configuration parameters to clients.

### Benefits of DHCP:

- Automatic IP address management
    
- Reduced configuration errors
    
- Centralized network configuration
    
- Support for both static and dynamic addressing
    
- Efficient IP address utilization
    

## Prerequisites

### System Requirements

- Debian 12 (Bullseye) or newer
    
    
- Static IP address on the server
    
- Basic knowledge of networking concepts
    

### Network Information to Gather:

- Network subnet and mask
    
- IP address range for clients
    
- Gateway/router IP address
    
- DNS server IP addresses
    
- Domain name (optional)
    
- Lease time requirements
    

## Installation

### Step 1: Update System Packages

bash

sudo apt update
sudo apt upgrade -y

### Step 2: Install DHCP Server

bash

sudo apt install isc-dhcp-server -y

### Step 3: Verify Installation

bash

dhcpd --version

### Step 4: Check Service Status

bash

sudo systemctl status isc-dhcp-server

## Configuration

### Step 1: Configure Network Interface

Identify the network interface that will serve DHCP requests:

bash

ip addr show

Edit the DHCP server configuration to specify the interface:

bash

sudo nano /etc/default/isc-dhcp-server

Set the interface (example with eth0):

conf

INTERFACESv4="eth0"
INTERFACESv6=""

### Step 2: Configure DHCP Server

Edit the main configuration file:

bash

sudo nano /etc/dhcp/dhcpd.conf

#### Basic Configuration Example:

conf

# Global configuration parameters
option domain-name "example.com";
option domain-name-servers 8.8.8.8, 8.8.4.4;
default-lease-time 600;
max-lease-time 7200;
authoritative;

# Subnet declaration for 192.168.1.0/24
subnet 192.168.1.0 netmask 255.255.255.0 {
    range 192.168.1.100 192.168.1.200;
    option routers 192.168.1.1;
    option subnet-mask 255.255.255.0;
    option broadcast-address 192.168.1.255;
}

### Step 3: Start and Enable DHCP Service

bash

# Test configuration syntax
sudo dhcpd -t

# Start the service
sudo systemctl start isc-dhcp-server

# Enable automatic startup on boot
sudo systemctl enable isc-dhcp-server

# Check status
sudo systemctl status isc-dhcp-server

## Advanced Configuration

### Static IP Reservations

conf

# Static IP for a specific MAC address
host printer {
    hardware ethernet 08:00:27:aa:bb:cc;
    fixed-address 192.168.1.50;
}

host webserver {
    hardware ethernet 08:00:27:dd:ee:ff;
    fixed-address 192.168.1.10;
    option host-name "webserver";
}

### Multiple Subnets

conf

# Subnet for main network
subnet 192.168.1.0 netmask 255.255.255.0 {
    range 192.168.1.100 192.168.1.150;
    option routers 192.168.1.1;
    option subnet-mask 255.255.255.0;
    option domain-name-servers 192.168.1.1;
}

# Subnet for guest network
subnet 192.168.2.0 netmask 255.255.255.0 {
    range 192.168.2.100 192.168.2.200;
    option routers 192.168.2.1;
    option subnet-mask 255.255.255.0;
    option domain-name-servers 8.8.8.8;
    default-lease-time 3600;
    max-lease-time 7200;
}

### Class-Based Configuration

conf

# Define a class for specific device types
class "voip-phones" {
    match if substring (option vendor-class-identifier, 0, 4) = "Aster";
}

subnet 192.168.1.0 netmask 255.255.255.0 {
    # Regular clients
    pool {
        range 192.168.1.100 192.168.1.150;
    }
    
    # VoIP phones get specific options
    pool {
        range 192.168.1.151 192.168.1.160;
        allow members of "voip-phones";
        option voip-tftp-server code 150 = ip-address;
        option voip-tftp-server 192.168.1.10;
    }
}

### DHCP Options

conf

# Common DHCP options
option domain-name "company.local";
option domain-name-servers 192.168.1.1, 8.8.8.8;
option ntp-servers 192.168.1.1;
option time-servers 192.168.1.1;
option netbios-name-servers 192.168.1.1;
option netbios-node-type 8;

# Custom options
option space ubnt;
option ubnt.unifi-address code 1 = ip-address;

subnet 192.168.1.0 netmask 255.255.255.0 {
    range 192.168.1.100 192.168.1.200;
    option routers 192.168.1.1;
    option ubnt.unifi-address 192.168.1.5;
}

## Troubleshooting

### Common Issues and Solutions

#### 1. Check Configuration Syntax

bash

sudo dhcpd -t

#### 2. View DHCP Server Logs

bash

sudo journalctl -u isc-dhcp-server -f

#### 3. Check Lease Database

bash

sudo cat /var/lib/dhcp/dhcpd.leases

#### 4. Test DHCP Server Functionality

bash

# From a client machine
sudo dhclient -v

#### 5. Common Error: No subnet declaration

**Error:** `No subnet declaration for eth0 (x.x.x.x).`

**Solution:** Ensure your subnet declaration matches the server's network interface.

#### 6. Check Firewall Settings

bash

# Allow DHCP traffic
sudo ufw allow 67/udp
sudo ufw allow 68/udp

### Debug Mode

Run DHCP server in debug mode for detailed troubleshooting:

bash

sudo dhcpd -d -f eth0

## Security Considerations

### 1. Network Segmentation

- Place DHCP server on secure network segment
    
- Use VLANs to separate client networks
    

### 2. Firewall Configuration

bash

# Allow only necessary ports
sudo ufw allow from 192.168.1.0/24 to any port 67
sudo ufw allow from 192.168.1.0/24 to any port 68

### 3. DHCP Snooping (on switches)

- Enable DHCP snooping on network switches
    
- Configure trusted ports for legitimate DHCP servers
    

### 4. Regular Updates

bash

sudo apt update && sudo apt upgrade

### 5. Monitoring and Logging

bash

# Monitor DHCP logs
sudo tail -f /var/log/syslog | grep dhcp

# Set up log rotation
sudo nano /etc/logrotate.d/isc-dhcp-server

## Additional Configuration Files

### DHCP Server Options File

bash

sudo nano /etc/dhcp/dhcpd.conf

### Lease Database File

bash

sudo nano /var/lib/dhcp/dhcpd.leases

### Server Defaults File

bash

sudo nano /etc/default/isc-dhcp-server

## Useful Commands

### Service Management

bash

# Restart DHCP service
sudo systemctl restart isc-dhcp-server

# Reload configuration
sudo systemctl reload isc-dhcp-server

# Check status
sudo systemctl status isc-dhcp-server

# Enable on boot
sudo systemctl enable isc-dhcp-server

### Monitoring Commands

bash

# View active leases
sudo dhcp-lease-list

# Check server status
sudo netstat -tulpn | grep :67

# Monitor logs in real-time
sudo journalctl -u isc-dhcp-server -f

## Backup and Recovery

### Backup Configuration

bash

# Backup DHCP configuration
sudo tar -czf dhcp-backup-$(date +%Y%m%d).tar.gz /etc/dhcp/ /var/lib/dhcp/

### Restore Configuration

bash

# Extract backup
sudo tar -xzf dhcp-backup-YYYYMMDD.tar.gz -C /
# Restart service
sudo systemctl restart isc-dhcp-server

## Best Practices

1. **Documentation**: Keep detailed documentation of IP assignments and reservations
    
2. **Monitoring**: Implement monitoring for DHCP server availability
    
3. **Redundancy**: Consider setting up a secondary DHCP server for critical networks
    
4. **Regular Maintenance**: Periodically review and clean up old leases
    
5. **Security**: Regularly update the system and review security configurations
    
6. **Testing**: Test configurations in a lab environment before production deployment
    

This comprehensive guide should provide you with all the necessary information to successfully install, configure, and maintain a DHCP server on Debian.