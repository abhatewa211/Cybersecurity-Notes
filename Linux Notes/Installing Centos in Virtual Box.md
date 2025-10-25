### **Step 1: Prerequisites**

1. **Download CentOS 9 Stream ISO**:
    - Navigate to the official CentOS Stream downloads page.
    - Select **CentOS Stream 9** and download the appropriate ISO image (e.g., **DVD ISO** for a full installation or **Minimal ISO** for a lightweight version).
2. **Verify System Requirements**:
    - Ensure your system meets the minimum requirements for VirtualBox and CentOS 9 Stream:
        - **Processor**: 2 GHz dual-core or better.
        - **RAM**: At least 2 GB (4 GB recommended for GUI installations).
        - **Disk Space**: Minimum 20 GB free.

---

### **Step 2: Create a Virtual Machine**

1. **Launch VirtualBox**:
    - Open VirtualBox from your applications menu.
2. **Create a New Virtual Machine**:
    - Click **New** in the VirtualBox Manager.
    - Provide the following details:
        - **Name**: e.g., `CentOS 9 Stream`.
        - **Machine Folder**: Select the desired location for storing the VM files.
        - **Type**: `Linux`.
        - **Version**: `Red Hat (64-bit)` (CentOS is derived from Red Hat).
    - Click **Next**.
3. **Allocate Memory (RAM)**:
    - Assign at least **2048 MB** (2 GB) of memory. For GUI installations, 4 GB is recommended.
    - Click **Next**.
4. **Create a Virtual Hard Disk**:
    - Select **Create a virtual hard disk now** and click **Create**.
    - Choose **VDI (VirtualBox Disk Image)** and click **Next**.
    - Select **Dynamically Allocated** (adjusts disk size as needed) and click **Next**.
    - Set the disk size (80 **GB**) and click **Create**.

---

### **Step 3: Configure the Virtual Machine**

1. **Attach the CentOS ISO**:
    - Select your new virtual machine in VirtualBox Manager and click **Settings**.
    - Go to the **Storage** tab.
    - Under **Controller: IDE**, click the empty disk icon and select **Choose a disk file**.
    - Browse to the downloaded CentOS 9 Stream ISO and select it.
    - Click **OK**.
2. **Adjust System Settings** (Optional):
    - Under **System**:
        - Ensure **Enable EFI (Special OSes only)** is unchecked unless using UEFI.
        - Increase **Processor** cores (e.g., 2 cores for better performance).
    - Under **Display**:
        - Allocate more **Video Memory** (e.g., 64 MB or higher).

---

### **Step 4: Install CentOS 9 Stream**

1. **Start the Virtual Machine**:
    - Select your virtual machine and click **Start**.
2. **Boot from ISO**:
    - In the boot menu, select **Install CentOS Stream 9** using the arrow keys and press **Enter**.
3. **Choose Language**:
    - Select your preferred language and click **Continue**.
4. **Configure Installation Destination**:
    - Under **Installation Destination**, choose the virtual disk created earlier.
    - Choose custom while partitioning and create 3 different partitions
    - the partitions are `/boot`, `/ (Root)`, `swap`.
    - The spaces given to these partitions are Boot- 1 gb, Swap- X2 of the ram and Root- remaining space.
    - Click **Done**.
5. **Network & Hostname** (Optional):
    - Go to **Network & Hostname** and enable the network adapter to configure networking Manually.
    - Just give a static ip to the network in wired Connection,
    - Disable or switch to ignore in ipv6 tab.
    - Give the static IP in ipv4 tab, change automatic to manual.
6. **Select Software**:
    - In **Software Selection**, choose:
        - **Minimal Install** for a lightweight setup.
        - **Server with GUI** or other profiles for additional features.
    - Click **Done**.
7. **Begin Installation**:
    - Click **Begin Installation**.
    - Set the **Root Password** and create a new **User Account** during the installation process.
8. **Complete Installation**:
    - Once installation finishes, click **Reboot**.

---

### **Step 5: Post-Installation Setup**

1. **Login**:
    - After rebooting, log in using the root credentials or the user account you created.
2. **Remove the ISO**:
    - Go to **Settings > Storage** in VirtualBox and remove the CentOS ISO from the virtual drive.
3. **Update the System**:
    - Open a terminal and run:
        
        ```Bash
        sudo dnf update -y
        ```
        
4. **Install VirtualBox Guest Additions** (Optional for better performance):
    - Insert the Guest Additions CD from VirtualBox's **Devices > Insert Guest Additions CD Image** menu.
    - Mount the CD and run the installer:
        
        ```Bash
        sudo mount /dev/cdrom /mnt
        sudo sh /mnt/VBoxLinuxAdditions.run
        ```
        
    - Reboot the virtual machine.

---

### **Step 6: Additional Configuration (EPEL, Remi and RPMFusion Repos)**

## **Step 1: Prerequisites**

1. **Ensure System is Updated**:  
    Run the following commands to ensure your system is updated:  
    
    ```Bash
    sudo dnf update -y
    sudo dnf upgrade -y
    ```
    
2. **Check Internet Connectivity**:  
    Verify that your system has an active internet connection, as you need to download repository files.  
    

---

## **Step 2: Installing EPEL Repository**

The **Extra Packages for Enterprise Linux (EPEL)** repository provides additional high-quality software packages.

1. **Install EPEL Repository**:  
    Run the following command to install the EPEL repository:  
    
    ```Bash
    sudo dnf install epel-release -y
    ```
    
2. **Verify EPEL Repository**:  
    Check if the repository is enabled:  
    
    ```Bash
    sudo dnf repolist
    ```
    
    You should see the **epel** repository in the list.
    
3. **Optional: Install EPEL Packages**:  
    Example of installing a package from EPEL:  
    
    ```Bash
    sudo dnf install htop -y
    ```
    

---

## **Step 3: Installing Remi Repository**

The **Remi** repository specializes in providing PHP versions and other additional packages.

1. **Install Required Dependencies**:  
    Install  
    `dnf-utils`, which provides tools for managing repositories:
    
    ```Bash
    sudo dnf install dnf-utils -y
    ```
    
2. **Add Remi Repository**:  
    Install the Remi repository package:  
    
    ```Bash
    sudo dnf install https://rpms.remirepo.net/enterprise/remi-release-9.rpm -y
    ```
    
3. **Enable the Desired PHP Stream (Optional)**:  
    If you plan to install PHP from Remi, enable the required version using  
    `dnf module`:
    
    ```Bash
    sudo dnf module reset php -y
    sudo dnf module enable php:remi-8.2 -y
    ```
    
4. **Verify Remi Repository**:  
    Check if the repository is enabled:  
    
    ```Bash
    sudo dnf repolist
    ```
    
    Look for repositories starting with `remi`.
    

---

## **Step 4: Installing RPMFusion Repositories**

The **RPMFusion** repository provides additional multimedia and open-source software packages.

### Install Free and Non-Free Repositories

1. **Install Free RPMFusion**:  
    Run the following command:  
    
    ```Bash
    sudo dnf install https://mirrors.rpmfusion.org/free/el/rpmfusion-free-release-9.noarch.rpm -y
    ```
    
2. **Install Non-Free RPMFusion**:  
    Run the following command:  
    
    ```Bash
    sudo dnf install https://mirrors.rpmfusion.org/nonfree/el/rpmfusion-nonfree-release-9.noarch.rpm -y
    ```
    
3. **Verify RPMFusion Repositories**:  
    Check if the repositories are enabled:  
    
    ```Bash
    sudo dnf repolist
    ```
    
    You should see entries like:
    
    - `rpmfusion-free-updates`
    - `rpmfusion-nonfree-updates`

---

## **Step 5: Testing and Usage**

1. **List Available Packages from EPEL, Remi, and RPMFusion**:
    
    ```Bash
    sudo dnf repository-packages epel list
    sudo dnf repository-packages remi list
    sudo dnf repository-packages rpmfusion-free list
    sudo dnf repository-packages rpmfusion-nonfree list
    ```
    
2. **Install a Package from Each Repository**:  
    Examples:  
    - From **EPEL**:
        
        ```Bash
        sudo dnf install neofetch -y
        ```
        
    - From **Remi** (PHP 8.2):
        
        ```Bash
        sudo dnf install php -y
        ```
        
    - From **RPMFusion** (VLC Media Player):
        
        ```Bash
        sudo dnf install vlc -y
        ```
        

---

## **Step 6: Disable or Enable Repositories (Optional)**

1. **Disable a Repository Temporarily**:
    
    ```Bash
    sudo dnf config-manager --set-disabled epel
    ```
    
2. **Enable a Disabled Repository**:
    
    ```Bash
    sudo dnf config-manager --set-enabled epel
    
    ```
    
3. **Use a Specific Repository**:  
    When installing packages, specify the repository using  
    `-enablerepo`:
    
    ```Bash
    sudo dnf install package_name --enablerepo=epel
    ```
    

---

## **Step 7: Troubleshooting**

1. **Clean DNF Cache**:  
    If you encounter issues, clean the cache:  
    
    ```Bash
    sudo dnf clean all
    ```
    
2. **Rebuild Repository Metadata**:
    
    ```Bash
    sudo dnf makecache
    ```
    
3. **Check Repository Configuration**:  
    Configuration files are located in  
    `/etc/yum.repos.d/`.