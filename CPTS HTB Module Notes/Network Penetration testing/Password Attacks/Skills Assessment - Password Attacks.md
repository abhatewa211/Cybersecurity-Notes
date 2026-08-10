## The Credential Theft Shuffle

[The Credential Theft Shuffle](https://adsecurity.org/?p=2362), as coined by `Sean Metcalf`, is a systematic approach attackers use to compromise Active Directory environments by exploiting `stolen credentials`. The process begins with gaining initial access, often through phishing, followed by obtaining local administrator privileges on a machine. Attackers then extract credentials from memory using tools like Mimikatz and leverage these credentials to `move laterally across the network`. Techniques such as pass-the-hash (PtH) and tools like NetExec facilitate this lateral movement and further credential harvesting. The ultimate goal is to escalate privileges and `gain control over the domain`, often by compromising Domain Admin accounts or performing DCSync attacks. Sean emphasizes the importance of implementing security measures such as the `Local Administrator Password Solution (LAPS)`, enforcing `multi-factor authentication`, and `restricting administrative privileges` to mitigate such attacks.

## Skills Assessment

`Betty Jayde` works at `Nexura LLC`. We know she uses the password `Texas123!@#` on multiple websites, and we believe she may reuse it at work. Infiltrate Nexura's network and gain command execution on the domain controller. The following hosts are in-scope for this assessment:

|Host|IP Address|
|---|---|
|`DMZ01`|`10.129.*.*` **(External)**, `172.16.119.13` **(Internal)**|
|`JUMP01`|`172.16.119.7`|
|`FILE01`|`172.16.119.10`|
|`DC01`|`172.16.119.11`|

#### Pivoting Primer

The internal hosts (`JUMP01`, `FILE01`, `DC01`) reside on a private subnet that is not directly accessible from our attack host. The only externally reachable system is `DMZ01`, which has a second interface connected to the internal network. This segmentation reflects a classic DMZ setup, where public-facing services are isolated from internal infrastructure.

To access these internal systems, we must first gain a foothold on `DMZ01`. From there, we can `pivot` — that is, route our traffic through the compromised host into the private network. This enables our tools to communicate with internal hosts as if they were directly accessible. After compromising the DMZ, refer to the module `cheatsheet` for the necessary commands to set up the pivot and continue your assessment.

###### Exercise and only Question

Steps for getting the answer

Step 1. connect openvpn through the file downloaded from htb module.
![[Pasted image 20260803231736.png]]

Step2. We will find open ports via nmap command.
![[Pasted image 20260803231906.png]]

Step3. As we know that ssh port is open so now we will connect the target machine via ssh with given credentials by name (betty jade) and password (Texas123!@#) but first we have first find the username to login into ssh so we will use hydra for username verification. I have already created a detailed username list to get the login and saved the file by the name of users.txt.
![[Pasted image 20260803233002.png]]

Step4. We have now get the login credentials for the ssh. username-jbetty password-Texas123!@#
![[Pasted image 20260803233650.png]]

Step 5. Now we will log in via ssh and create a tunnel for internal lateral movement to get access to internal network.
![[Pasted image 20260808105718.png]]

Step6. Now before connecting to ssh we will setup few things for the internal lateral movement. First we will set up proxychain server to connect to internal network. we will add a line in the last of the file for setting the proxy.
![[Screenshot From 2026-08-08 11-10-05.png]]

Step7. Now we will use nmap from main attacking machine via proxychains to know the open ports of internal networks and we will only go for AD ports. (Jump Box)

![[Pasted image 20260810163341.png]]

Step8. Now we will connect to jumpbox via rdp but before that we have to find credentials to login via rdp the credentials we have used before to login ssh will not work so we have to find new credentials in the target machine. We will use history command and also filter the commands used to get the creds to login.
![[Pasted image 20260810165802.png]]

Step9.  Now we will login into rdp via xfreerdp command to Jump01 also known jump box. We will be using the credentials which we found and also connect our main pc folder via rdp as well as shown below. We will also take the password locked file found in \\file01\HR\Archive\Employee-Passwords_OLD.psafe3 to our main attacking pc.
![[Pasted image 20260810165938.png]]
![[Pasted image 20260810170310.png]]
![[Pasted image 20260810170104.png]]

Step10. After obtaining the file from the target machine via rdp we will now crack the password file via using john the ripper to get password safe creds to get more user. as shown below. first we will convert the file into hash txt file via pwsafe2john command.
![[Pasted image 20260810174359.png]]
b. Now we will edit the file to crack the hash.
![[Pasted image 20260810174521.png]]
c. Now we will crack the hash via john the ripper.
