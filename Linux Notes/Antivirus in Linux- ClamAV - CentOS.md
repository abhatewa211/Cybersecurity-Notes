## ClamAV Antivirus in Linux

### What is ClamAV?

ClamAV is an open-source antivirus software designed for Linux and other UNIX-like operating systems. It provides a command-line scanner, a daemon for on-access scanning, and a tool to detect various types of malicious software such as viruses, trojans, spyware, and other malware.

ClamAV is mainly used on Linux servers to scan incoming email and files for malicious content. It supports a wide range of file formats and can be used in conjunction with email servers, file-sharing services, or as a standalone antivirus solution.

### Features of ClamAV:

1. **Open-Source**: ClamAV is free to use and can be modified according to the user's needs.
2. **Wide Format Support**: It can detect viruses in a variety of file types including executables, archives (like .tar, .zip), and more.
3. **Database Updates**: Regular updates to the virus definition database to detect the latest threats.
4. **On-demand Scanning**: ClamAV can perform manual scans of files or directories to check for infections.
5. **On-access Scanning**: ClamAV can work with a daemon to provide real-time scanning, particularly useful for mail servers.
6. **Cross-platform Support**: It is available on Linux, Windows, macOS, and other UNIX-like operating systems.
7. **Integration**: ClamAV can be integrated with email servers (e.g., Postfix, Exim) or web servers to prevent the transmission of infected files.

---

## How to Install ClamAV on CentOS

Here are the following steps to install

---

### **Step 1: Enable EPEL Repository**

The ClamAV packages are available from the **EPEL** (Extra Packages for Enterprise Linux) repository. To install ClamAV, you must first ensure that the EPEL repository is enabled on your CentOS 9 system.

### Command to enable EPEL:

```Shell
sudo dnf install epel-release
```

This will install the `epel-release` package, which enables access to the EPEL repository.

### Verify EPEL repository is enabled:

```Shell
sudo dnf repolist
```

This should show a list of repositories, including **EPEL**.

---

### **Step 2: Install ClamAV and Related Packages**

Once the EPEL repository is enabled, you can now install ClamAV and the `clamav-update` package, which is responsible for updating virus definitions.

### Command to install ClamAV:

```Shell
sudo dnf install clamav clamav-update
```

- `clamav`: This package contains the ClamAV antivirus software and the command-line scanner (`clamscan`).
- `clamav-update`: This package contains the `freshclam` tool to automatically update the virus database.

---

### **Step 3: Configure ClamAV**

Before you start using ClamAV, you may need to adjust a few configuration settings to suit your needs.

### Configuration Files:

ClamAV's main configuration files are located in the following directories:

- `/etc/clamav/`: Contains global configuration files.
- `/etc/clamd.d/`: Contains configuration files for ClamAV's daemon (clamd).

The primary files to edit are:

- `/etc/clamav/freshclam.conf`: This file is for configuring updates (via `freshclam`).
- `/etc/clamav/clamd.conf`: This file is for configuring the ClamAV daemon (`clamd`), which allows ClamAV to run as a background service.

### Edit `freshclam.conf` for virus definitions updates:

```Shell
sudo nano /etc/clamav/freshclam.conf
```

Ensure the following line is uncommented to allow automatic updates:

```Shell
# Commented out by default
DatabaseMirror db.us.clamav.net
```

You can also configure other options like how often updates should occur (e.g., hourly, daily).

### Edit `clamd.conf` to configure ClamAV daemon:

```Shell
sudo nano /etc/clamav/clamd.conf
```

A few key settings:

- **User**: By default, the daemon runs as `clamav`. Ensure this is set if you plan to run ClamAV as a daemon:
    
    ```Shell
    User clamav
    ```
    
- **LogFile**: This defines the path to the log file where ClamAV will write output. By default, it is set to `/var/log/clamav/clamd.log`.
    
    ```Shell
    LogFile /var/log/clamav/clamd.log
    ```
    
- **LocalSocket**: If you want `clamd` to use a Unix socket, you can configure it here (for communication with other software). Make sure it's commented out if you’re not using it.

---

### **Step 4: Start and Enable ClamAV Services**

ClamAV includes two main services that need to be started for the software to function properly:

1. `clamd`: The ClamAV daemon, which allows continuous scanning.
2. `freshclam`: The ClamAV virus definition updater.

### Start ClamAV Services:

Run the following commands to start the services:

1. Start the **ClamAV daemon** (`clamd`):
    
    ```Shell
    sudo systemctl start clamd@scan
    ```
    
2. Start **freshclam** (for automatic virus definition updates):
    
    ```Shell
    sudo systemctl start freshclam
    ```
    

### Enable Services to Start on Boot:

To ensure ClamAV services start automatically on boot, use the following commands:

1. Enable **clamd** to start on boot:
    
    ```Shell
    sudo systemctl enable clamd@scan
    ```
    
2. Enable **freshclam** to start on boot:
    
    ```Shell
    sudo systemctl enable freshclam
    ```
    

---

### **Step 5: Verify Installation**

After installation and configuration, verify that ClamAV is working correctly.

### Check the version of ClamAV:

```Shell
clamscan --version
```

This should print the version number of ClamAV if the installation was successful.

---

### **Step 6: Update Virus Definitions**

ClamAV requires up-to-date virus definitions to detect the latest threats. The `freshclam` service should automatically update the definitions, but you can also manually update them.

### Manually update virus definitions:

```Shell
sudo freshclam
```

### Check for the status of the `freshclam` service:

```Shell
sudo systemctl status freshclam
```

If everything is working properly, this service will automatically update ClamAV's virus database.

---

### **Step 7: Run a Scan with ClamAV**

Now that ClamAV is set up and the services are running, you can start scanning files or directories for malware.

### Scan a single file:

```Shell
clamscan /path/to/file
```

### Scan a directory recursively:

```Shell
clamscan -r /path/to/directory
```

### Scan and remove infected files automatically:

To automatically remove infected files while scanning, use the `--remove` option:

```Shell
clamscan -r --remove /path/to/directory
```

---

### **Step 8: Set Up Scheduled Scans (Optional)**

You may want to schedule ClamAV scans to run at regular intervals. The easiest way to do this is by using **cron**.

### Edit the root user's cron jobs:

```Shell
sudo crontab -e
```

### Add a cron job to run a scan every day at midnight:

```Shell
0 0 * * * /usr/bin/clamscan -r /home/user/ > /var/log/clamav/daily_scan.log
```

This will scan the `/home/user/` directory every day at midnight and log the output to `/var/log/clamav/daily_scan.log`.

---

### **Step 9: Review Logs and Reports**

ClamAV logs information about its scans and updates. These logs are usually found in the `/var/log/clamav/` directory.

### Check the scan logs:

```Shell
cat /var/log/clamav/clamd.log
```

### Check `freshclam` logs:

```Shell
cat /var/log/clamav/freshclam.log
```

Review these logs regularly to ensure that ClamAV is functioning properly and up to date.

---

### **Conclusion**

You have now successfully installed and configured **ClamAV** on CentOS 9. You should:

1. Monitor the virus definitions with `freshclam`.
2. Run periodic scans using `clamscan` or configure cron jobs for scheduled scans.
3. Review logs to ensure ClamAV is working smoothly.

By following these steps, your system will be protected against viruses and malware with ClamAV.