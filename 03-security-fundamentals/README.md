# Kubernetes Security Fundamentals - 22%

This section covers the core security mechanisms and practices that form the foundation of Kubernetes security. These fundamentals are essential for implementing a secure Kubernetes environment and are heavily tested in the KCSA exam.

## Pod Security Standards

Pod Security Standards define three levels of security policies that can be applied to pods, replacing the deprecated PodSecurityPolicy.

### Security Levels

#### Privileged
The most permissive policy level with no restrictions:
- **Use Cases**: System workloads, infrastructure components, CNI plugins
- **Allowed**: All privilege escalations, host access, privileged containers
- **Risk**: High - suitable only for trusted workloads

```yaml
# Example privileged pod
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      privileged: true
      allowPrivilegeEscalation: true
```

#### Baseline
Minimally restrictive policy preventing known privilege escalations:
- **Use Cases**: General applications, non-critical workloads
- **Restrictions**: 
  - No privileged containers
  - No host network/PID/IPC access
  - Limited volume types
  - No privilege escalation
- **Risk**: Medium - good balance for most workloads

```yaml
# Example baseline-compliant pod
apiVersion: v1
kind: Pod
metadata:
  name: baseline-pod
spec:
  securityContext:
    runAsNonRoot: true
  containers:
  - name: app
    image: nginx
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
```

#### Restricted
Most restrictive policy following pod hardening best practices:
- **Use Cases**: Security-critical applications, multi-tenant environments
- **Restrictions**:
  - Must run as non-root
  - Read-only root filesystem
  - No privilege escalation
  - Drop all capabilities
  - Seccomp profile required
- **Risk**: Low - highest security posture

```yaml
# Example restricted-compliant pod
apiVersion: v1
kind: Pod
metadata:
  name: restricted-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
  containers:
  - name: app
    image: nginx
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      capabilities:
        drop:
        - ALL
      seccompProfile:
        type: RuntimeDefault
```

### Policy Violations and Exceptions
Understanding what violates each policy level:

#### Baseline Violations
- `spec.securityContext.hostNetwork: true`
- `spec.securityContext.hostPID: true`
- `spec.containers[*].securityContext.privileged: true`
- `spec.containers[*].securityContext.allowPrivilegeEscalation: true`

#### Restricted Violations (includes Baseline + additional)
- `spec.securityContext.runAsUser: 0` (root user)
- Missing `seccompProfile`
- Writable root filesystem
- Dangerous capabilities

## Pod Security Admission

Pod Security Admission is the built-in admission controller that enforces Pod Security Standards, replacing PodSecurityPolicy.

### Configuration Modes

#### Enforce
Rejects pods that violate the policy:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: secure-namespace
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
```

#### Audit
Logs policy violations but allows pods:
```yaml
metadata:
  labels:
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: v1.25
```

#### Warn
Shows warnings for policy violations:
```yaml
metadata:
  labels:
    pod-security.kubernetes.io/warn: baseline
    pod-security.kubernetes.io/warn-version: latest
```

### Multiple Modes Example
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    # Enforce restricted policy
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    
    # Audit baseline violations
    pod-security.kubernetes.io/audit: baseline
    pod-security.kubernetes.io/audit-version: latest
    
    # Warn about privileged violations
    pod-security.kubernetes.io/warn: privileged
    pod-security.kubernetes.io/warn-version: latest
```

### Exemptions
Certain resources can be exempted from Pod Security Standards:
- **Usernames**: Specific users
- **RuntimeClassNames**: Specific runtime classes
- **Namespaces**: Specific namespaces

```yaml
# API server configuration
--admission-control-config-file=/etc/kubernetes/admission-config.yaml
```

```yaml
# admission-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: PodSecurity
  configuration:
    apiVersion: pod-security.admission.config.k8s.io/v1beta1
    kind: PodSecurityConfiguration
    defaults:
      enforce: "baseline"
      enforce-version: "latest"
      audit: "restricted"
      audit-version: "latest"
      warn: "restricted"
      warn-version: "latest"
    exemptions:
      usernames: ["system:serviceaccount:kube-system:daemon-set-controller"]
      runtimeClasses: ["secure-runtime"]
      namespaces: ["kube-system"]
```

## Authentication

Authentication verifies the identity of users and services accessing the Kubernetes API.

### Authentication Methods

#### X.509 Client Certificates
Most common method for user authentication:

```bash
# Generate client certificate
openssl genrsa -out user.key 2048
openssl req -new -key user.key -out user.csr -subj "/CN=john/O=developers"

# Sign with cluster CA
openssl x509 -req -in user.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out user.crt -days 365
```

```yaml
# kubeconfig with certificate
apiVersion: v1
kind: Config
users:
- name: john
  user:
    client-certificate: /path/to/user.crt
    client-key: /path/to/user.key
```

#### Service Account Tokens
For pod-to-API server authentication:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-service-account
  namespace: default
```

```yaml
# Pod using service account
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  serviceAccountName: my-service-account
  containers:
  - name: app
    image: nginx
```

#### OpenID Connect (OIDC)
Integration with external identity providers:

```yaml
# API server OIDC configuration
--oidc-issuer-url=https://accounts.google.com
--oidc-client-id=kubernetes
--oidc-username-claim=email
--oidc-groups-claim=groups
```

#### Static Token Files
Simple but less secure method:

```csv
# token.csv
token1,user1,uid1,"group1,group2"
token2,user2,uid2,"group3"
```

```yaml
# API server configuration
--token-auth-file=/etc/kubernetes/token.csv
```

#### Bootstrap Tokens
For node bootstrapping:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: bootstrap-token-abcdef
  namespace: kube-system
type: bootstrap.kubernetes.io/token
data:
  token-id: YWJjZGVm
  token-secret: MDEyMzQ1Njc4OWFiY2RlZg==
  usage-bootstrap-authentication: dHJ1ZQ==
  usage-bootstrap-signing: dHJ1ZQ==
```

### Authentication Flow
1. **Client** sends request with credentials
2. **API Server** validates credentials using configured authenticators
3. **User information** is extracted (username, groups, UID)
4. **Request** proceeds to authorization if authentication succeeds

## Authorization

Authorization determines what authenticated users can do in the cluster.

### Authorization Modes

#### RBAC (Role-Based Access Control) - Recommended
Uses roles and role bindings to control access:

```yaml
# Role - namespace-scoped permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: development
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "watch", "list"]

---
# RoleBinding - grants role to user
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: development
subjects:
- kind: User
  name: jane
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

```yaml
# ClusterRole - cluster-wide permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secret-reader
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]

---
# ClusterRoleBinding - grants cluster role
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: read-secrets-global
subjects:
- kind: User
  name: admin
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: secret-reader
  apiGroup: rbac.authorization.k8s.io
```

#### ABAC (Attribute-Based Access Control)
Policy-based authorization using JSON policies:

```json
{
  "apiVersion": "abac.authorization.kubernetes.io/v1beta1",
  "kind": "Policy",
  "spec": {
    "user": "alice",
    "namespace": "projectCaribou",
    "resource": "pods",
    "readonly": true
  }
}
```

#### Node Authorization
Specialized authorizer for kubelet requests:
- Authorizes kubelet to read services, endpoints, nodes
- Authorizes kubelet to write node status, events
- Authorizes kubelet to read/write pods bound to the node

#### Webhook Authorization
Delegates authorization to external services:

```yaml
# API server webhook configuration
--authorization-webhook-config-file=/etc/kubernetes/webhook-config.yaml
--authorization-webhook-cache-authorized-ttl=5m
--authorization-webhook-cache-unauthorized-ttl=30s
```

### RBAC Best Practices

#### Principle of Least Privilege
Grant minimum necessary permissions:

```yaml
# Good - specific permissions
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
  resourceNames: ["my-pod"]

# Bad - overly broad permissions
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
```

#### Use Built-in Roles
Leverage predefined cluster roles:

```yaml
# Use built-in view role
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: view-binding
subjects:
- kind: User
  name: viewer
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
```

Common built-in roles:
- `cluster-admin`: Full cluster access
- `admin`: Full namespace access
- `edit`: Read/write namespace access
- `view`: Read-only namespace access

#### Service Account RBAC
```yaml
# Service account with specific permissions
apiVersion: v1
kind: ServiceAccount
metadata:
  name: monitoring-sa
  namespace: monitoring

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: monitoring-reader
rules:
- apiGroups: [""]
  resources: ["nodes", "pods", "services"]
  verbs: ["get", "list", "watch"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: monitoring-binding
subjects:
- kind: ServiceAccount
  name: monitoring-sa
  namespace: monitoring
roleRef:
  kind: ClusterRole
  name: monitoring-reader
  apiGroup: rbac.authorization.k8s.io
```

## Secrets Management

Kubernetes Secrets store sensitive information like passwords, tokens, and keys.

### Secret Types

#### Opaque Secrets
Generic secrets for arbitrary data:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mysecret
type: Opaque
data:
  username: YWRtaW4=  # base64 encoded 'admin'
  password: MWYyZDFlMmU2N2Rm  # base64 encoded password
```

#### Service Account Tokens
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: sa-token
  annotations:
    kubernetes.io/service-account.name: my-service-account
type: kubernetes.io/service-account-token
```

#### Docker Registry Secrets
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: regcred
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: eyJhdXRocyI6eyJyZWdpc3RyeS5leGFtcGxlLmNvbSI6eyJ1c2VybmFtZSI6InVzZXIiLCJwYXNzd29yZCI6InBhc3MiLCJhdXRoIjoiZFhObGNqcHdZWE56In19fQ==
```

#### TLS Secrets
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: tls-secret
type: kubernetes.io/tls
data:
  tls.crt: LS0tLS1CRUdJTi...  # base64 encoded certificate
  tls.key: LS0tLS1CRUdJTi...  # base64 encoded private key
```

### Using Secrets in Pods

#### Environment Variables
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secret-env-pod
spec:
  containers:
  - name: app
    image: nginx
    env:
    - name: SECRET_USERNAME
      valueFrom:
        secretKeyRef:
          name: mysecret
          key: username
    - name: SECRET_PASSWORD
      valueFrom:
        secretKeyRef:
          name: mysecret
          key: password
```

#### Volume Mounts
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secret-volume-pod
spec:
  containers:
  - name: app
    image: nginx
    volumeMounts:
    - name: secret-volume
      mountPath: "/etc/secrets"
      readOnly: true
  volumes:
  - name: secret-volume
    secret:
      secretName: mysecret
      defaultMode: 0400
```

### Secret Security Best Practices

#### Encryption at Rest
Enable encryption for etcd:

```yaml
# encryption-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - secrets
  providers:
  - aescbc:
      keys:
      - name: key1
        secret: <32-byte base64 encoded key>
  - identity: {}
```

#### External Secret Management
Use external secret managers:

```yaml
# Example with External Secrets Operator
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
spec:
  provider:
    vault:
      server: "https://vault.example.com"
      path: "secret"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "example-role"
```

#### Secret Rotation
Implement automatic secret rotation:

```bash
# Example script for secret rotation
kubectl create secret generic new-secret --from-literal=password=newpassword
kubectl patch deployment myapp -p '{"spec":{"template":{"spec":{"containers":[{"name":"app","env":[{"name":"SECRET_VERSION","value":"new"}]}]}}}}'
kubectl delete secret old-secret
```

## Isolation and Segmentation

Isolation prevents workloads from interfering with each other and limits blast radius of security incidents.

### Namespace Isolation

#### Resource Quotas
```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: development
spec:
  hard:
    requests.cpu: "4"
    requests.memory: "8Gi"
    limits.cpu: "8"
    limits.memory: "16Gi"
    persistentvolumeclaims: "4"
    pods: "10"
    secrets: "10"
```

#### Limit Ranges
```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: limit-range
  namespace: development
spec:
  limits:
  - default:
      cpu: "500m"
      memory: "512Mi"
    defaultRequest:
      cpu: "100m"
      memory: "128Mi"
    type: Container
```

### Process Namespace Sharing
Control process visibility between containers:

```yaml
# Disable process namespace sharing (default)
apiVersion: v1
kind: Pod
metadata:
  name: isolated-pod
spec:
  shareProcessNamespace: false
  containers:
  - name: app1
    image: nginx
  - name: app2
    image: busybox
```

```yaml
# Enable process namespace sharing (security risk)
apiVersion: v1
kind: Pod
metadata:
  name: shared-pod
spec:
  shareProcessNamespace: true  # Allows containers to see each other's processes
  containers:
  - name: app1
    image: nginx
  - name: app2
    image: busybox
```

### Container Isolation
```yaml
# Strong container isolation
apiVersion: v1
kind: Pod
metadata:
  name: isolated-container
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
  containers:
  - name: app
    image: nginx
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
      seccompProfile:
        type: RuntimeDefault
```

## Audit Logging

Audit logging records all requests to the Kubernetes API server, providing visibility into cluster activity and security events.

### Audit Policy Configuration

#### Basic Audit Policy
```yaml
# audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
# Log all requests at RequestResponse level
- level: RequestResponse
  resources:
  - group: ""
    resources: ["secrets", "configmaps"]
  
# Log metadata for all other requests
- level: Metadata
  omitStages:
  - RequestReceived
```

#### Comprehensive Audit Policy
```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
# Don't log requests to certain non-resource URLs
- level: None
  nonResourceURLs:
  - /healthz*
  - /version
  - /swagger*

# Don't log watch requests by the kubelet
- level: None
  users: ["kubelet"]
  verbs: ["watch"]

# Don't log authenticated requests to certain non-resource URLs
- level: None
  userGroups: ["system:authenticated"]
  nonResourceURLs:
  - /api*

# Log the request body of configmap changes in kube-system
- level: Request
  resources:
  - group: ""
    resources: ["configmaps"]
  namespaces: ["kube-system"]

# Log configmap and secret changes in all other namespaces at the Metadata level
- level: Metadata
  resources:
  - group: ""
    resources: ["secrets", "configmaps"]

# Log all other resources in core and extensions at the Request level
- level: Request
  resources:
  - group: ""
  - group: "extensions"

# A catch-all rule to log all other requests at the Metadata level
- level: Metadata
  omitStages:
  - RequestReceived
```

### API Server Audit Configuration
```yaml
# API server flags
--audit-log-path=/var/log/audit.log
--audit-policy-file=/etc/kubernetes/audit-policy.yaml
--audit-log-maxage=30
--audit-log-maxbackup=3
--audit-log-maxsize=100
```

### Audit Levels
- **None**: Don't log events that match this rule
- **Metadata**: Log request metadata (user, timestamp, resource, verb, etc.) but not request or response body
- **Request**: Log event metadata and request body but not response body
- **RequestResponse**: Log event metadata, request and response bodies

### Audit Stages
- **RequestReceived**: Stage for events generated as soon as the audit handler receives the request
- **ResponseStarted**: Stage for events generated when the response headers are sent
- **ResponseComplete**: Stage for events generated when the response body has been completed
- **Panic**: Stage for events generated when a panic occurred

### Log Analysis
```bash
# Search for failed authentication attempts
grep "Forbidden" /var/log/audit.log

# Search for secret access
grep "secrets" /var/log/audit.log | grep "get\|list\|watch"

# Search for privilege escalation attempts
grep "system:masters" /var/log/audit.log

# Search for pod creation in kube-system
grep "kube-system" /var/log/audit.log | grep "pods" | grep "create"
```

## Network Policies

Network Policies provide network-level security by controlling traffic flow between pods, namespaces, and external endpoints.

### Default Deny Policies

#### Deny All Ingress
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-ingress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
```

#### Deny All Egress
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Egress
```

#### Deny All Traffic
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

### Selective Allow Policies

#### Allow Specific Pod Communication
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
```

#### Allow Cross-Namespace Communication
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-cross-namespace
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: development
      podSelector:
        matchLabels:
          app: client
```

#### Allow External Traffic
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-external
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - ipBlock:
        cidr: 10.0.0.0/8
        except:
        - 10.0.1.0/24
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
    ports:
    - protocol: TCP
      port: 443
    - protocol: TCP
      port: 80
```

### DNS and System Traffic
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
```

### Network Policy Best Practices

#### Start with Default Deny
1. Implement default deny policies first
2. Add specific allow rules as needed
3. Test connectivity after each change
4. Monitor network traffic patterns

#### Use Labels Effectively
```yaml
# Good - specific label selection
podSelector:
  matchLabels:
    app: frontend
    version: v1
    environment: production

# Bad - overly broad selection
podSelector: {}
```

#### Document Network Flows
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-policy
  namespace: production
  annotations:
    description: "Allows frontend pods to communicate with backend API on port 8080"
    owner: "platform-team"
    last-reviewed: "2024-01-15"
```

## Practice Exercises

### Exercise 1: Pod Security Standards Implementation
1. Create three namespaces with different Pod Security Standards:
   - `privileged-ns`: Privileged policy
   - `baseline-ns`: Baseline policy  
   - `restricted-ns`: Restricted policy

2. Try deploying the same pod specification to each namespace:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      privileged: true
```

3. Observe which deployments succeed/fail and understand why

### Exercise 2: RBAC Configuration
1. Create a service account for a monitoring application
2. Create a ClusterRole with read-only access to pods, nodes, and services
3. Bind the role to the service account
4. Test the permissions using kubectl with the service account token

```bash
# Test commands
kubectl auth can-i get pods --as=system:serviceaccount:monitoring:monitoring-sa
kubectl auth can-i create pods --as=system:serviceaccount:monitoring:monitoring-sa
kubectl auth can-i delete nodes --as=system:serviceaccount:monitoring:monitoring-sa
```

### Exercise 3: Secrets Management
1. Create different types of secrets (generic, TLS, docker-registry)
2. Use secrets in pods via environment variables and volume mounts
3. Implement secret rotation procedure
4. Configure encryption at rest for etcd

### Exercise 4: Network Policy Implementation
1. Deploy a multi-tier application (frontend, backend, database)
2. Implement default deny network policies
3. Create specific allow policies for:
   - Frontend to backend communication
   - Backend to database communication
   - External access to frontend
   - DNS resolution for all pods

4. Test connectivity and verify policies work as expected

### Exercise 5: Audit Logging Setup
1. Configure comprehensive audit policy
2. Enable audit logging on API server
3. Generate various types of events (successful/failed operations)
4. Analyze audit logs to identify security events

## Additional Reading

### Official Kubernetes Documentation
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [Authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
- [Authorization](https://kubernetes.io/docs/reference/access-authn-authz/authorization/)
- [RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Secrets](https://kubernetes.io/docs/concepts/configuration/secret/)
- [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Audit Logging](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)

### Security Best Practices
- [Kubernetes Security Checklist](https://kubernetes.io/docs/concepts/security/security-checklist/)
- [RBAC Good Practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)
- [Secrets Good Practices](https://kubernetes.io/docs/concepts/security/secrets-good-practices/)

### Tutorials and Guides
- [Securing a Cluster](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/)
- [Enforce Pod Security Standards](https://kubernetes.io/docs/tutorials/security/ns-level-pss/)
- [Network Policy Recipes](https://github.com/ahmetb/kubernetes-network-policy-recipes)

### Tools and Utilities
- [kubectl auth can-i](https://kubernetes.io/docs/reference/access-authn-authz/authorization/#checking-api-access)
- [Polaris](https://polaris.docs.fairwinds.com/) - Configuration validation
- [Falco](https://falco.org/) - Runtime security monitoring
- [OPA Gatekeeper](https://open-policy-agent.github.io/gatekeeper/) - Policy enforcement

## Navigation

- **Previous:** [← Kubernetes Cluster Component Security](../02-cluster-component-security/README.md)
- **Next:** [Kubernetes Threat Model →](../04-threat-model/README.md)
