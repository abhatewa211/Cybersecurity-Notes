### 1. Network Configuration Basics

Linux systems require network configuration for communication.

**Key Files & Commands:**

- `/etc/network/interfaces` (Debian-based)
- `/etc/sysconfig/network-scripts/ifcfg-*` (RHEL-based)
- `ip` and `ifconfig` commands

**Static IP Configuration Example (Debian):**

```Plain
auto eth0
iface eth0 inet static
    address 192.168.1.100
    netmask 255.255.255.0
    gateway 192.168.1.1
```

**Scenario:**  
You need to configure a server with a static IP for consistent access.  

---

### 2. ifconfig (Interface Configuration)

Used to configure or display network interface settings.

**Common Usage:**

- View interfaces: `ifconfig`
- Assign IP: `ifconfig eth0 192.168.1.50 netmask 255.255.255.0`
- Enable/disable: `ifconfig eth0 up/down`

**Scenario:**  
You need to quickly assign a temporary IP address for troubleshooting.  

**Note:** `ifconfig` is deprecated; prefer `ip a` or `ip addr` in modern systems.

---

### 3. Network Monitoring – netstat and ss Commands

Used to monitor socket connections and network statistics.

**netstat:**

- View listening ports: `netstat -tuln`
- Show active connections: `netstat -an`

**ss (replacement for netstat):**

- View open ports: `ss -tuln`
- Show established connections: `ss -ant`

**Scenario:**  
You're investigating a server to see which services are listening on ports.  

---

### 4. Process Management in Linux

Managing processes (running programs) is crucial for system performance.

**Commands:**

- `ps aux` – List all running processes
- `top` / `htop` – Real-time process monitoring
- `kill PID` – Terminate a process
- `nice`, `renice` – Set/change priority
- `&`, `bg`, `fg`, `jobs` – Background/foreground control

**Scenario:**  
A process is consuming 100% CPU. Use  
`top` to find the PID and `kill` to terminate it.

---

### 5. Memory Management in Linux

Linux uses virtual memory, including RAM and swap space, to manage applications.

**Tools:**

- `free -h` – Show memory usage
- `vmstat` – System performance info
- `top` – Shows RAM and swap usage in real-time
- `/proc/meminfo` – Detailed memory info

**Example:**

```Shell
free -h
```

Displays memory in human-readable format.

**Scenario:**  
System is slow. You check memory usage with  
`free -h` and notice swap usage is high, indicating RAM exhaustion.

**Tip:**  
Consider adding swap space or upgrading RAM if usage is consistently high.