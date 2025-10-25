[[Linux Firewall- An Overview (Centos) 2]]

# Steps to setup Firewall in Debian

1. **Install iptables** (if not already installed):
    
    `apt-get install iptables`
    
2. **Flush existing rules** (optional, but recommended for a clean slate):
    
    `iptables -F`
    
3. **Set default policies**:
    
    `iptables -P INPUT DROP`
    
    `iptables -P FORWARD DROP`
    
    `iptables -P OUTPUT ACCEPT`
    
4. **Allow established and related connections**:
    
    `iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`
    
5. **Allow loopback interface**:
    
    `iptables -A INPUT -i lo -j ACCEPT`
    
6. **Allow SSH (port 22)**:
    
    `iptables -A INPUT -p tcp --dport 22 -j ACCEPT`
    
7. **Allow HTTP (port 80)**:
    
    `iptables -A INPUT -p tcp --dport 80 -j ACCEPT`
    
8. **Allow HTTPS (port 443)**:
    
    `iptables -A INPUT -p tcp --dport 443 -j ACCEPT`
    
9. **Save the rules** (this may vary based on your distribution):
    
    `iptables-save > /etc/iptables/rules.v4`
    
10. **To view the current rules**:
    
    `iptables -L -v`
    
11. **If you want to allow more ports please repeat the steps same as 6 and 7 and save with step 9. So, You want to view tables please go with step 10.**

  

### **Example of table:**

![[image 26.png]]