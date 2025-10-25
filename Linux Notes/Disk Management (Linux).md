### 1. Disk Management

Disk management in Linux involves managing storage devices, creating partitions, formatting, and mounting file systems.

**Tools:**

- `lsblk`, `fdisk`, `parted`, `mkfs`, `mount`, `umount`

**Scenario:**  
You added a new disk and need to prepare it for data storage.  

**Steps:**

1. Use `lsblk` to view available disks.
2. Use `fdisk /dev/sdb` to create partitions.
3. Format the partition with `mkfs.ext4 /dev/sdb1`.
4. Mount it using `mount /dev/sdb1 /mnt/data`.

---

### 2. fdisk, mkfs, mount

These commands are essential for preparing and using disk storage.

**fdisk:**  
Used to create/delete partitions.  

```Shell
fdisk /dev/sdb
```

- `n` to create new partition
- `w` to write changes

**mkfs:**  
Used to format partitions.  

```Shell
mkfs.ext4 /dev/sdb1
```

**mount:**  
Used to attach a filesystem to a mount point.  

```Shell
mount /dev/sdb1 /mnt/data
```

**Scenario:**  
You bought a 1TB hard drive and need to use it for backups.  

---

### 3. Permanent Mounting Partition

To mount a partition automatically at boot, edit `/etc/fstab`.

**Steps:**

1. Find UUID:

```Shell
blkid /dev/sdb1
```

1. Edit `/etc/fstab`:

```Shell
UUID=xxxx-xxxx /mnt/data ext4 defaults 0 2
```

1. Test:

```Shell
mount -a
```

**Scenario:**  
You want your backup drive to always be available after reboot.  

---

### 4. Quota Management in Linux

Quota is used to limit disk usage for users or groups.

**Steps:**

1. Enable quota in `/etc/fstab`:

```Shell
/dev/sdb1 /home ext4 defaults,usrquota,grpquota 0 2
```

1. Remount the partition:

```Shell
mount -o remount /home
```

1. Create quota files:

```Shell
quotacheck -cug /home
```

1. Assign quotas:

```Shell
edquota username
```

**Scenario:**  
You’re running a shared hosting server and want to prevent any user from filling the entire disk.  

---

### 5. Logical Volume Manager (LVM)

LVM provides flexibility in managing disk storage by creating logical volumes.

**Commands:**

- `pvcreate`, `vgcreate`, `lvcreate`, `mkfs`, `mount`

**Steps:**

```Shell
pvcreate /dev/sdb
vgcreate vg_data /dev/sdb
lvcreate -L 10G -n lv_backup vg_data
mkfs.ext4 /dev/vg_data/lv_backup
mount /dev/vg_data/lv_backup /mnt/backup
```

**Scenario:**  
You need to manage a growing amount of data with the ability to resize volumes later.  

**Advantages:**

- Resize volumes on the fly
- Snapshot support
- Better disk utilization