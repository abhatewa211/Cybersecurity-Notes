# What is a Linux Firewall?

A Linux firewall is a security tool built into the Linux operating system that monitors and controls incoming and outgoing network traffic based on predetermined security rules. It acts as a barrier between trusted internal networks and untrusted external networks, such as the internet.

## Key Features of Linux Firewalls

- Network traffic filtering based on predefined rules
- Protection against unauthorized access and potential security threats
- Customizable security policies to meet specific needs
- Logging capabilities for monitoring and auditing network activities

## Common Linux Firewall Tools

- **iptables**: A command-line firewall utility for configuring the Linux kernel firewall
- **ufw (Uncomplicated Firewall)**: A user-friendly interface for managing iptables
- **firewalld**: A dynamic firewall manager for Linux systems

## Basic Firewall Configuration

To configure a Linux firewall, administrators typically use command-line tools to define rules that specify which network traffic should be allowed or blocked. These rules can be based on various criteria such as IP addresses, ports, and protocols.

## Importance in Linux Security

Firewalls play a crucial role in Linux security by:

- Preventing unauthorized access to the system
- Protecting against various network-based attacks
- Controlling which services are accessible from the network
- Providing an additional layer of security alongside other measures like regular updates and proper user management

Understanding and properly configuring your Linux firewall is essential for maintaining a secure and robust system, whether for personal use or in enterprise environments.

  

## Steps to Create a Linux Firewall

Here's a basic guide to setting up a firewall on a Linux system:

1. **Choose a firewall tool:** Decide whether to use iptables, ufw, or firewalld based on your Linux distribution and needs.
2. **Install the firewall tool:** If not already installed, use your package manager to install the chosen firewall tool.
3. **Enable the firewall:** Start the firewall service and enable it to run at boot time.
4. **Set default policies:** Configure the default policies for incoming, outgoing, and forwarded traffic.
5. **Define specific rules:** Create rules to allow or block specific types of traffic based on ports, protocols, or IP addresses.
6. **Apply the rules:** Activate the new firewall configuration.
7. **Test the configuration:** Verify that the firewall is working as expected by testing various network connections.
8. **Save the configuration:** Ensure that your firewall rules persist across system reboots.

Remember to regularly review and update your firewall rules to maintain optimal security for your Linux system.

  

## Images

Step 1

Install iptables.

![[image.png]]

Step 2

Start Iptables

![[image 1.png]]

Step 3

Check Status

![[image 2.png]]

Step 4

Check Iptables lines

![[image 3.png]]

Step 5

Reboot system

![[image 4.png]]

Step 6

Check ipv4 status

![[image 5.png]]

Step 7

Enable ipv4 and ipv4 by command systemctl enable iptables.service and ip6tables.service

![[image 6.png]]

Step 8

Install Netcat server

![[image 7.png]]

Step 9

Check iptables list

![[image 8.png]]

Step 10

Check iptables input and output, forward

![[image 9.png]]

![[image 10.png]]

step 11

Configure net cat

![[image 11.png]]

step 12

check net cat status

![[image 12.png]]

step 13

now try to connect to netcat through main pc but it should not connect and Firewall works in Transport Layer

![[image 13.png]]

Step 14

Enable TCP port in firewall

![[image 14.png]]

Step 15

Delete the port 21 input for testing

![[image 15.png]]

Step 16

change the number of line of the port which is to be allowed

![[image 16.png]]

Step 17

now try to connect to netcat through main pc but it should connect.

![[image 17.png]]

step 18

Repeat the process from step 16 and step 17 to allow port 80 and check for connection in main pc

![[image 18.png]]

Step 19

Now we will allow multiple port in bulk.

![[image 19.png]]

Step 19

Now we will allow port by name. it will allow well named ports example telnet.

![[image 20.png]]

Step 20

Configuring udp port 53.

![[image 21.png]]

Step 21

Enabling more udp ports

![[image 22.png]]

Step 22

Now we will allow multiple port in bulk in udp.

![[image 23.png]]

Step 23

Now try to make a connection b/w VM and Main PC.

![[image 24.png]]

Step 24

Check whether the port other than in firewall is working or not. (it should not work)

![[image 25.png]]

Step 25

Please save the Iptables by following the commands.

`$iptables-save > specified file name.`

  

Step 26

If you want to reuse iptables please use the command.

`$iptables-restore < specified file name.`