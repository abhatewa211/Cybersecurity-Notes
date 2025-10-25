### **Prerequisites**

1. **Root Privileges**: Ensure you have root access or a user with root privileges.
2. **Network Information**: Collect details about the network, such as:
    - Subnet address
    - Subnet mask
    - Gateway address
    - Range of IP addresses to lease
    - DNS servers
3. **System Updates**: Update the system to ensure all packages are up to date.
    
    ```Bash
     dnf update -y
    ```
    

---

### **Step 1: Install the DHCP Server**

1. Install the `dhcp-server` package:
    
    ```Bash
    dnf install dhcp-server -y
    ```
    
2. Verify the installation:
    
    ```Bash
    rpm -qi dhcp-server
    ```
    

---

### **Step 2: Configure the DHCP Server**

1. Open the DHCP configuration file:
    
    ```Bash
    vim /etc/dhcp/dhcpd.conf
    ```
    
2. Edit the file to include the required network configuration. Below is a sample configuration:
    
    ```Plain
    authoritative;
    			\#specify network address and subnet mask
    			subnet 192.168.29.0 netmask 255.255.255.0 {
    							\#specify the range of lease IP address
    							range 192.168.29.70 192.168.29.90;
    							\#specify default gateway
    							option routers 192.168.29.1;
    							\#DNS servers for name resolution
    							option domain-name-servers 8.8.8.8, 8.8.4.4;
    							\#specify broadcast address
    							option broadcast-address 192.168.29.255;
    							\#default lease time
    							default-lease-time 600;
    							\#max lease time
    							max-lease-time 7200;
    }
    ```
    

![[image 27.png]]

  

1. Save and close the file (`:wq!` in vim).
2. Adjust the ownership and permissions of the file (if needed):
    
    ```Bash
     chown root:root /etc/dhcp/dhcpd.conf
     chmod 644 /etc/dhcp/dhcpd.conf
    ```
    

---

### **Step 3: Start and Enable the DHCP Service**

1. Start the DHCP service:
    
    ```Bash
     systemctl start dhcpd
    ```
    
2. Enable the service to start at boot:
    
    ```Bash
     systemctl enable dhcpd
    ```
    
3. Check the status of the service:
    
    ```Bash
     systemctl status dhcpd
    ```
    

---

### **Step 4: Configure Firewall Rules**

1. Allow DHCP traffic through the firewall:
    
    ```Bash
     firewall-cmd --add-service=dhcp --permanent
     firewall-cmd --reload
    ```
    
2. Verify the rules:
    
    ```Bash
     firewall-cmd --list-all
    ```
    

---

### **Step 5: Verify the DHCP Server**

1. Use `journalctl` to check the logs for errors:
    
    ```Bash
     journalctl -u dhcpd
    ```
    
2. Test the DHCP server by configuring a client machine on the same subnet to use DHCP and checking if it receives an IP address.

---

### **Additional Notes**

- **Editing Configurations**: If you make changes to `/etc/dhcp/dhcpd.conf`, restart the DHCP service:
    
    ```Bash
     systemctl restart dhcpd
    ```
    
- **Log Monitoring**: Regularly monitor logs for troubleshooting:
    
    ```Bash
     tail -f /var/log/messages
    ```
    
- **Backup Configurations**: Keep a backup of the configuration file:
    
    ```Bash
    cp /etc/dhcp/dhcpd.conf /etc/dhcp/dhcpd.conf.bak
    ```
    

---

### **Troubleshooting**

1. **Service Fails to Start**: Check configuration syntax:
    
    ```Bash
    dhcpd -t -cf /etc/dhcp/dhcpd.conf
    ```
    
2. **No IP Assigned**:
    - Verify the DHCP server is running.
    - Check if the firewall is properly configured.
    - Ensure there is no conflict with another DHCP server on the same network.
3. **Logs Indicating Issues**: Review log files:
    
    ```Bash
    journalctl -xe
    ```
    

## Allow and deny policies

Bellow is the example of allowing and denying ip’s to client.

```Plain
# Inside /etc/dhcp/dhcpd.conf

subnet 192.168.1.0 netmask 255.255.255.0 {
  range 192.168.1.100 192.168.1.200;
  option routers 192.168.1.1;
  option domain-name-servers 8.8.8.8, 8.8.4.4;

  # Deny specific clients
  host deny_client_1 {
    hardware ethernet 00:11:22:33:44:55;
    deny booting;
  }

  # Allow specific clients
  host allow_client_1 {
    hardware ethernet 66:77:88:99:AA:BB;
    fixed-address 192.168.1.102;
  }
}
```

---

### **Testing and Applying Changes**

1. **Validate the Configuration**
    
    Run the following to test your configuration:
    
    ```Shell
    sudo dhcpd -t -cf /etc/dhcp/dhcpd.conf
    ```
    
2. **Restart the DHCP Server**
    
    Apply the changes by restarting the DHCP service:
    
    ```Bash
    sudo systemctl restart dhcpd
    ```
    
3. **Check Logs**
    
    Use logs to verify the behavior of the DHCP server:
    
    ```Bash
    tail -f /var/log/syslog | grep dhcpd
    ```
    

## Reserving an IP address

Add a block to reserve an IP address for a specific device using its MAC address. Here's the syntax:

```Plain
host reserved_device {
    hardware ethernet XX:XX:XX:XX:XX:XX;  # Replace with the device's MAC address
    fixed-address 192.168.1.50;          # Replace with the desired IP address
```

### **Testing and Applying Changes**

1. **Validate the Configuration**
    
    Run the following to test your configuration:
    
    ```Shell
    sudo dhcpd -t -cf /etc/dhcp/dhcpd.conf
    ```
    
2. **Restart the DHCP Server**
    
    Apply the changes by restarting the DHCP service:
    
    ```Bash
    sudo systemctl restart dhcpd
    ```
    
3. **Check Logs**
    
    Use logs to verify the behavior of the DHCP server:
    
    ```Bash
    tail -f /var/log/syslog | grep dhcpd
    ```
    

Making pools for allow and deny lists

Allow list

pool {

range 192.168.1.201 192.168.1.250;  
allow unknown-clients;  

}

Deny list

pool {

range 192.168.1.201 192.168.1.250;  
Deny unknown-clients;  

}

### **Testing and Applying Changes**

1. **Validate the Configuration**
    
    Run the following to test your configuration:
    
    ```Shell
    sudo dhcpd -t -cf /etc/dhcp/dhcpd.conf
    ```
    
2. **Restart the DHCP Server**
    
    Apply the changes by restarting the DHCP service:
    
    ```Bash
    sudo systemctl restart dhcpd
    ```
    
3. **Check Logs**
    
    Use logs to verify the behavior of the DHCP server:
    
    ```Bash
    tail -f /var/log/syslog | grep dhcpd
    ```