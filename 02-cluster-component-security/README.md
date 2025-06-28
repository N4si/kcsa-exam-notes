# Kubernetes Cluster Component Security - 22%

Understanding the security of individual Kubernetes components is crucial for maintaining a secure cluster. Each component has specific security considerations, attack vectors, and hardening requirements. This section covers the security aspects of all major Kubernetes components.

This is the highest weighted domain in the KCSA exam, so understanding these components thoroughly is essential for success.


## API Server Security

The API Server is the central component of the Kubernetes control plane and the primary attack target. It exposes the Kubernetes API and serves as the gateway for all cluster operations.

### 🏗️ API Server Security Architecture

<div align="center">

```
┌─────────────────────────────────────────────────────────────┐
│                    🔐 API SERVER                            │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ 🔑 Authn    │→ │ 🛡️ Authz    │→ │ ✅ Admission        │  │
│  │ (Who?)      │  │ (Can they?) │  │   Controllers       │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│                                                             │
│                           ↓                                 │
│                    ┌─────────────┐                         │
│                    │ 🗄️ etcd     │                         │
│                    │   Storage   │                         │
│                    └─────────────┘                         │
└─────────────────────────────────────────────────────────────┘
```

</div>

### 🔒 Security Features

<table>
<tr>
<td width="50%">

#### 🔑 **Authentication Methods**
- ✅ **X.509 Client Certificates** (Recommended)
- 🎫 **Service Account Tokens**
- 🔐 **OpenID Connect (OIDC)**
- 🌐 **Webhook Token Authentication**
- ⚠️ **Static Token Files** (Not recommended)
- 🚀 **Bootstrap Tokens** (For cluster setup)

</td>
<td width="50%">

#### 🛡️ **Authorization Modes**
- ✅ **RBAC** (Role-Based Access Control) - **Recommended**
- 📋 **ABAC** (Attribute-Based Access Control)
- 🖥️ **Node Authorization**
- 🌐 **Webhook Authorization**
- ⚠️ **AlwaysAllow** (Never use in production!)

</td>
</tr>
</table>

#### ✅ **Admission Controllers** (Security-Focused)

<table>
<tr>
<td width="50%">

##### 🔒 **Essential Controllers**
- ✅ **Pod Security Admission** (Replaces PSP)
- 🌐 **NetworkPolicy**
- 📊 **ResourceQuota**
- 📏 **LimitRanger**
- 🚫 **DenyEscalatingExec**
- 🔐 **SecurityContextDeny**

</td>
<td width="50%">

##### ⚠️ **Deprecated/Dangerous**
- ❌ **PodSecurityPolicy** (Deprecated in 1.21)
- ❌ **AlwaysAdmit** (Never use!)
- ⚠️ **DefaultStorageClass** (Use carefully)

</td>
</tr>
</table>

### 🛡️ API Server Hardening Best Practices

#### 🔐 **TLS Configuration** (Critical!)

```yaml
# 🔒 Comprehensive API Server TLS Configuration
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - name: kube-apiserver
    image: k8s.gcr.io/kube-apiserver:v1.28.0
    command:
    - kube-apiserver
    
    # 🔐 TLS Certificate Configuration
    - --tls-cert-file=/etc/kubernetes/pki/apiserver.crt
    - --tls-private-key-file=/etc/kubernetes/pki/apiserver.key
    - --client-ca-file=/etc/kubernetes/pki/ca.crt
    
    # 🔒 Strong Cipher Suites (TLS 1.2+)
    - --tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    - --tls-min-version=VersionTLS12
    
    # 🚫 Disable Insecure Features
    - --insecure-port=0
    - --insecure-bind-address=127.0.0.1
    - --profiling=false
    
    # 🔍 Enable Comprehensive Audit Logging
    - --audit-log-path=/var/log/audit.log
    - --audit-policy-file=/etc/kubernetes/audit-policy.yaml
    - --audit-log-maxage=30
    - --audit-log-maxbackup=10
    - --audit-log-maxsize=100
    
    # 🛡️ Authentication & Authorization
    - --authorization-mode=Node,RBAC
    - --enable-admission-plugins=NodeRestriction,ResourceQuota,PodSecurity
```

#### 📋 **Comprehensive Audit Policy Example**

```yaml
# /etc/kubernetes/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
# 🚨 Log security-sensitive operations at RequestResponse level
- level: RequestResponse
  resources:
  - group: ""
    resources: ["secrets", "configmaps"]
  - group: "rbac.authorization.k8s.io"
    resources: ["*"]

# 🔍 Log all authentication failures
- level: Request
  users: ["system:anonymous"]
  
# 📊 Log resource creation/deletion
- level: Metadata
  verbs: ["create", "delete", "patch"]
  
# 🔇 Don't log read-only operations on non-sensitive resources
- level: None
  verbs: ["get", "list", "watch"]
  resources:
  - group: ""
    resources: ["pods", "services", "endpoints"]
```

#### 🔒 **Security Hardening Checklist**

<table>
<tr>
<td width="50%">

##### ✅ **Must-Have Configurations**
- [ ] **Disable insecure port** (`--insecure-port=0`)
- [ ] **Enable TLS 1.2+** minimum
- [ ] **Strong cipher suites** only
- [ ] **Client certificate authentication**
- [ ] **RBAC authorization** enabled
- [ ] **Comprehensive audit logging**
- [ ] **Disable profiling** in production
- [ ] **Resource quotas** configured

</td>
<td width="50%">

##### 🚨 **Common Misconfigurations**
- ❌ **Insecure port enabled** (8080)
- ❌ **Anonymous authentication** allowed
- ❌ **Weak TLS configuration**
- ❌ **AlwaysAllow** authorization
- ❌ **No audit logging**
- ❌ **Profiling enabled** in production
- ❌ **Missing admission controllers**

</td>
</tr>
</table>

---

## 🧠 Controller Manager Security

> **🎯 Exam Focus:** Controller Manager manages cluster state - understand its security implications and service account token management!

The **Controller Manager** runs core control loops that regulate the state of the cluster. It requires elevated privileges but should be properly secured.

### Security Considerations

#### Service Account Token Management
- Automatic token rotation
- Bound service account tokens
- Token audience validation

#### Certificate Management
- Automatic certificate rotation
- Certificate signing requests (CSR) approval
- Root CA protection

### Hardening Configuration
```yaml
# Disable profiling
--profiling=false

# Secure service account key
--service-account-private-key-file=/path/to/sa.key

# Enable certificate rotation
--rotate-certificates=true

# Bind to secure address
--bind-address=127.0.0.1
```

## Scheduler Security

The Scheduler determines pod placement on nodes. While it has fewer direct security implications, proper configuration is important.

### Security Features
- **Secure communication** with API Server
- **Resource-based scheduling** to prevent resource exhaustion
- **Node affinity/anti-affinity** for security isolation

### Hardening Best Practices
```yaml
# Disable profiling
--profiling=false

# Bind to secure address
--bind-address=127.0.0.1

# Secure communication
--kubeconfig=/etc/kubernetes/scheduler.conf
```

## Kubelet Security

The Kubelet is the primary node agent and has significant security implications as it manages containers and communicates with the container runtime.

### Critical Security Settings

#### Authentication and Authorization
```yaml
# Enable authentication
--anonymous-auth=false

# Enable authorization
--authorization-mode=Webhook

# Client certificate authentication
--client-ca-file=/path/to/ca.crt
```

#### API Security
```yaml
# Disable read-only port
--read-only-port=0

# Secure port configuration
--port=10250

# Enable HTTPS
--tls-cert-file=/path/to/kubelet.crt
--tls-private-key-file=/path/to/kubelet.key
```

#### Container Security
```yaml
# Disable privileged containers (if possible)
--allow-privileged=false

# Enable container runtime security
--container-runtime-endpoint=unix:///var/run/containerd/containerd.sock

# Protect kernel defaults
--protect-kernel-defaults=true
```

### Common Vulnerabilities
- **Anonymous access** to kubelet API
- **Privilege escalation** through container runtime
- **Host filesystem access** via volume mounts
- **Network access** to sensitive services

## Container Runtime Security

The container runtime (Docker, containerd, CRI-O) is responsible for running containers and has direct access to the host system.

### Security Features

#### Namespace Isolation
- **PID namespaces**: Process isolation
- **Network namespaces**: Network isolation
- **Mount namespaces**: Filesystem isolation
- **User namespaces**: User ID isolation

#### Security Profiles
- **AppArmor**: Mandatory access control
- **SELinux**: Security-enhanced Linux
- **Seccomp**: System call filtering

#### Resource Limits
```yaml
# Example pod with security context
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
  containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
```

### Runtime Security Tools
- **Falco**: Runtime threat detection
- **Sysdig**: Container monitoring
- **Aqua**: Runtime protection
- **Twistlock**: Container security

## KubeProxy Security

KubeProxy manages network rules for service traffic routing. While it has fewer direct security implications, proper configuration is important.

### Security Considerations
- **iptables rules management**
- **Service traffic routing**
- **Network policy enforcement** (with CNI)

### Hardening Configuration
```yaml
# Bind to secure address
--bind-address=127.0.0.1

# Disable profiling
--profiling=false

# Secure metrics
--metrics-bind-address=127.0.0.1:10249
```

## Pod Security

Pods are the smallest deployable units and require comprehensive security configuration.

### Security Context
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    # Run as non-root user
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
    # Prevent privilege escalation
    allowPrivilegeEscalation: false
    # Drop all capabilities
    capabilities:
      drop:
      - ALL
    # Read-only root filesystem
    readOnlyRootFilesystem: true
    # Security profiles
    seccompProfile:
      type: RuntimeDefault
    seLinuxOptions:
      level: "s0:c123,c456"
```

### Resource Limits
```yaml
resources:
  limits:
    cpu: "500m"
    memory: "512Mi"
    ephemeral-storage: "1Gi"
  requests:
    cpu: "100m"
    memory: "128Mi"
```

### Network Policies
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

## Etcd Security

Etcd stores all cluster data and is the most critical component to secure. Compromise of etcd means complete cluster compromise.

### Security Features

#### Encryption at Rest
```yaml
# Enable encryption at rest
--encryption-provider-config=/etc/kubernetes/encryption-config.yaml
```

Example encryption configuration:
```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - secrets
  providers:
  - aescbc:
      keys:
      - name: key1
        secret: <base64-encoded-secret>
  - identity: {}
```

#### TLS Configuration
```yaml
# Client-server TLS
--cert-file=/path/to/server.crt
--key-file=/path/to/server.key
--trusted-ca-file=/path/to/ca.crt

# Peer TLS
--peer-cert-file=/path/to/peer.crt
--peer-key-file=/path/to/peer.key
--peer-trusted-ca-file=/path/to/peer-ca.crt
```

#### Access Control
```yaml
# Enable client certificate authentication
--client-cert-auth=true

# Enable peer client certificate authentication
--peer-client-cert-auth=true
```

### Backup Security
- **Encrypt backups** at rest
- **Secure backup storage** with access controls
- **Regular backup testing** and restoration procedures
- **Backup retention policies**

## Container Networking Security

Container networking involves multiple components and has various security implications.

### CNI (Container Network Interface) Security

#### Network Isolation
- **VLAN isolation**
- **Network namespaces**
- **Micro-segmentation**
- **Zero-trust networking**

#### Popular CNI Plugins
- **Calico**: Network policies and security
- **Cilium**: eBPF-based networking and security
- **Weave**: Simple networking with encryption
- **Flannel**: Basic overlay networking

### Service Mesh Security
- **Istio**: Comprehensive service mesh
- **Linkerd**: Lightweight service mesh
- **Consul Connect**: HashiCorp service mesh

#### Security Features
- **mTLS** between services
- **Traffic encryption**
- **Access policies**
- **Observability**

## Client Security

Securing access to the Kubernetes cluster involves multiple client-side considerations.

### kubectl Security

#### Kubeconfig Security
```yaml
# Secure kubeconfig permissions
chmod 600 ~/.kube/config

# Use separate contexts for different environments
kubectl config use-context production
```

#### Certificate-based Authentication
```yaml
apiVersion: v1
kind: Config
users:
- name: admin
  user:
    client-certificate: /path/to/admin.crt
    client-key: /path/to/admin.key
```

#### Token-based Authentication
```yaml
users:
- name: service-account
  user:
    token: <service-account-token>
```

### RBAC Configuration
```yaml
# ClusterRole for read-only access
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: read-only
rules:
- apiGroups: [""]
  resources: ["*"]
  verbs: ["get", "list", "watch"]

---
# ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: read-only-binding
subjects:
- kind: User
  name: readonly-user
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: read-only
  apiGroup: rbac.authorization.k8s.io
```

## Storage Security

Kubernetes storage involves multiple security considerations for data protection.

### Volume Security

#### Secret Volumes
```yaml
volumes:
- name: secret-volume
  secret:
    secretName: mysecret
    defaultMode: 0400
```

#### ConfigMap Volumes
```yaml
volumes:
- name: config-volume
  configMap:
    name: myconfig
    defaultMode: 0644
```

#### Persistent Volume Security
```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: secure-pv
spec:
  capacity:
    storage: 10Gi
  accessModes:
  - ReadWriteOnce
  persistentVolumeReclaimPolicy: Delete
  storageClassName: encrypted-storage
```

### Encryption
- **Encryption at rest** for persistent volumes
- **Encryption in transit** for network storage
- **Key management** for encryption keys
- **Access controls** for storage resources

## Practice Exercises

### Exercise 1: API Server Hardening
1. Configure API server with secure TLS settings
2. Enable audit logging with comprehensive policy
3. Disable insecure features and ports
4. Test authentication and authorization

### Exercise 2: Kubelet Security
1. Configure kubelet with webhook authorization
2. Disable anonymous access
3. Enable certificate rotation
4. Test security configurations

### Exercise 3: Etcd Security
1. Enable encryption at rest for secrets
2. Configure TLS for client-server communication
3. Set up secure backup procedures
4. Test encryption and backup restoration

### Exercise 4: Pod Security
1. Create pods with comprehensive security contexts
2. Implement resource limits and requests
3. Configure security profiles (seccomp, AppArmor)
4. Test privilege escalation prevention

## Additional Reading

### Official Documentation
- [Kubernetes Security](https://kubernetes.io/docs/concepts/security/)
- [Controlling Access to the API](https://kubernetes.io/docs/concepts/security/controlling-access/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kubelet Authentication/Authorization](https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/)

### Security Guides
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NSA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
- [NIST Container Security Guide](https://csrc.nist.gov/publications/detail/sp/800-190/final)

### Tools and Utilities
- [kube-bench](https://github.com/aquasecurity/kube-bench) - CIS benchmark testing
- [kube-hunter](https://github.com/aquasecurity/kube-hunter) - Penetration testing
- [Falco](https://falco.org/) - Runtime security monitoring
- [Polaris](https://polaris.docs.fairwinds.com/) - Configuration validation

## Navigation

- **Previous:** [← Overview of Cloud Native Security](../01-cloud-native-security/README.md)
- **Next:** [Kubernetes Security Fundamentals →](../03-security-fundamentals/README.md)
