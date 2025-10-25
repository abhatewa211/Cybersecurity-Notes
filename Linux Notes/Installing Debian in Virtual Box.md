### Prerequisites:

1. **Download Debian ISO**:
    - Go to the official Debian website.
    - Download the appropriate ISO file for your system (e.g., Debian 12 netinst ISO).

---

### Step-by-Step Installation Guide

### Step 1: Create a New Virtual Machine

1. Open VirtualBox and click **New**.
2. Fill in the following details:
    - **Name**: Enter a name for the VM (e.g., "Debian VM").
    - **Machine Folder**: Select a location for the VM files.
    - **Type**: Choose "Linux".
    - **Version**: Select "Debian (64-bit)" or "Debian (32-bit)" based on your ISO.
3. Click **Next**.
4. Allocate memory (RAM):
    - Recommended: At least 2048 MB (2 GB) for a basic setup.
    - Adjust based on your system resources.
    - Click **Next**.
5. Create a virtual hard disk:
    - Select "Create a virtual hard disk now" and click **Create**.
    - Choose "VDI (VirtualBox Disk Image)" and click **Next**.
    - Select "Dynamically allocated" and click **Next**.
    - Specify the disk size (100 GB).
    - Click **Create**.

---

### Step 2: Configure the Virtual Machine

1. Select your VM and click **Settings**.
2. Go to the **System** tab:
    - Under "Motherboard," ensure **Enable EFI** is checked (if using UEFI).
    - Adjust boot order to have Optical at the top.
3. Go to the **Storage** tab:
    - Under "Controller: IDE," click the empty disk icon.
    - Click the disk icon on the right and choose **Choose a disk file**.
    - Select the Debian ISO you downloaded.
4. Go to the **Network** tab:
    - Ensure "Attached to" is set to "Bridged Adapter."
5. Click **OK** to save settings.

---

### Step 3: Start the Installation

1. Select your VM and click **Start**.
2. The VM will boot from the Debian ISO.
3. Follow the on-screen instructions:
    - **Language Selection**: Choose your preferred language.
    - **Location**: Select your country.
    - **Keyboard**: Choose the appropriate keyboard layout.
4. **Configure the Network**:
    - Enter the hostname (e.g., "debian").
    - Enter a domain name or leave it blank for home use.
5. **Set Up Users and Passwords**:
    - Set the root password.
    - Create a new user account and password.
6. **Partition Disks**:
    - Choose "Manual Partitioning."
    - Select the virtual disk.
    - While partitioning, Create 3 different partitions
    - the partitions are `/boot`, `/ (Root)`, `swap`.
    - The spaces given to these partitions are Boot- 1 gb, Swap- X2 of the ram and Root- remaining space.
    - Confirm partitioning.
7. **Install the Base System**:
    - The installer will copy files and install the base system.
8. **Configure the Package Manager**:
    - Select a mirror near your location for package downloads.
    - Configure a proxy if required, or leave it blank.
9. **Install Software**:
    - Select the desired desktop environment (e.g., GNOME, XFCE or Minimal).
    - Install additional utilities as needed.
10. **Install GRUB Bootloader**:
    - Select "Yes" to install GRUB.
    - Choose the disk to install GRUB.
11. Complete the installation and reboot.

---

### Step 4: Post-Installation

1. Remove the ISO:
    - Go to **Settings > Storage** and remove the ISO from the virtual drive.
2. Start the VM and log in to your new Debian installation.

---

### Optional Configurations and Commands

### Update the System

```Bash
sudo apt update && sudo apt upgrade -y
```

### Install Guest Additions

1. In VirtualBox, go to **Devices > Insert Guest Additions CD Image**.
2. Mount the CD and run the installer:

```Bash
sudo mount /dev/cdrom /mnt
cd /mnt
sudo ./VBoxLinuxAdditions.run
```

### Reboot the VM

```Bash
sudo reboot
```

---

You now have a working Debian installation on VirtualBox!