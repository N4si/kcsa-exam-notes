# Overview of Cloud Native Security - 14%

Cloud Native Security is the practice of securing cloud native applications and infrastructure throughout their entire lifecycle. It involves securing the complete cloud native stack, from the code running in containers to the infrastructure hosting your cluster. This is a shared responsibility model between cloud providers and customers, requiring a combination of security controls, best practices, and specialized tools.

## The 4Cs of Cloud Native Security

The 4Cs represent the layered approach to cloud native security, where each layer builds upon and depends on the security of the layers beneath it:

### 1. Code (Innermost Layer)
- **Secure coding practices**
- **Dependency management**
- **Static code analysis**
- **Secret management in code**

### 2. Container
- **Image security and scanning**
- **Runtime security**
- **Container isolation**
- **Minimal base images**

### 3. Cluster
- **Kubernetes security configurations**
- **Network policies**
- **RBAC (Role-Based Access Control)**
- **Pod security standards**

### 4. Cloud (Outermost Layer)
- **Infrastructure security**
- **Network security**
- **Identity and access management**
- **Compliance and governance**

> **Key Principle:** Security vulnerabilities at any outer layer can compromise all inner layers. You cannot fully protect the Code layer if there are vulnerabilities in the Cluster or Cloud layers.

## Cloud Provider and Infrastructure Security

### Shared Responsibility Model
Cloud providers typically handle:
- **Control plane security** (for managed Kubernetes services)
- **Infrastructure security**
- **Physical security**
- **Network infrastructure**

Customers are responsible for:
- **Workload security**
- **Application-level security**
- **Data protection**
- **Access management**
- **Configuration security**

### Key Security Areas

#### Network Security
- **Virtual Private Clouds (VPCs)**
- **Security groups and firewalls**
- **Network segmentation**
- **Private endpoints**

#### Identity and Access Management
- **Multi-factor authentication (MFA)**
- **Principle of least privilege**
- **Service account management**
- **API key rotation**

#### Encryption
- **Encryption at rest**
- **Encryption in transit**
- **Key management services**
- **Certificate management**

## Controls and Frameworks

### Compliance Frameworks

#### PCI DSS (Payment Card Industry Data Security Standard)
- Required for organizations handling credit card data
- Focuses on secure payment processing
- Network security and access controls
- Regular security testing

#### NIST (National Institute of Standards and Technology)
- Comprehensive cybersecurity framework
- Risk management approach
- Identify, Protect, Detect, Respond, Recover
- Government and enterprise adoption

#### HIPAA (Health Insurance Portability and Accountability Act)
- Healthcare data protection
- Patient privacy requirements
- Administrative, physical, and technical safeguards
- Breach notification requirements

#### MITRE ATT&CK® Framework for Kubernetes
- Tactics, techniques, and procedures (TTPs)
- Container-specific attack vectors
- Kubernetes threat modeling
- Defense mapping

### Security Benchmarks and Guidelines

#### CIS Kubernetes Benchmark
- Industry-standard security configurations
- Hardening guidelines for Kubernetes
- Automated compliance checking
- Regular updates for new versions

#### OWASP Top 10 for Kubernetes
- Most critical security risks
- Container and orchestration specific
- Practical mitigation strategies
- Community-driven insights

### Security Tools and Platforms

#### Runtime Security
- **Falco**: Runtime security monitoring
- **Aqua Security**: Container security platform
- **Sysdig**: Cloud security and monitoring
- **Twistlock/Prisma Cloud**: Comprehensive container security

#### Compliance and Assessment
- **Kubescape**: Kubernetes security assessment
- **Polaris**: Configuration validation
- **Kube-bench**: CIS benchmark testing
- **Kube-hunter**: Penetration testing

## Isolation Techniques

### Namespace-based Isolation
Namespaces provide logical separation of resources within a cluster:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    environment: prod
    security-level: high
```

**Use Cases:**
- Multi-tenancy
- Environment separation (dev/staging/prod)
- Team-based resource isolation
- Resource quota enforcement

### Network Policies
Control traffic flow between pods and external endpoints:

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

**Key Features:**
- Ingress and egress traffic control
- Label-based pod selection
- Namespace-scoped policies
- Default deny capabilities

### Pod Security Standards

Three levels of security policies:

#### Privileged
- **Use Case**: Infrastructure workloads, system components
- **Restrictions**: None - allows privilege escalation
- **Risk Level**: High

#### Baseline
- **Use Case**: General workloads, non-critical applications
- **Restrictions**: Prevents known privilege escalations
- **Risk Level**: Medium

#### Restricted
- **Use Case**: Security-critical workloads, untrusted users
- **Restrictions**: Follows pod hardening best practices
- **Risk Level**: Low

### Pod Security Admission
Replaces the deprecated PodSecurityPolicy:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: secure-namespace
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### Runtime Class
Configure container runtime properties:

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: secure-runtime
handler: runc-secure
overhead:
  podFixed:
    memory: "120Mi"
    cpu: "250m"
```

## Artifact Repository and Image Security

### Image Security Best Practices

#### Minimal Base Images
- Use distroless or minimal base images
- Reduce attack surface
- Faster deployment and scanning
- Examples: `gcr.io/distroless/java`, `alpine`

#### Image Scanning
Implement vulnerability scanning in CI/CD pipelines:

```bash
# Example with Trivy
trivy image nginx:latest

# Example with Docker Scout
docker scout cves nginx:latest
```

#### Image Signing and Verification
Use tools like Cosign and Sigstore:

```bash
# Sign an image
cosign sign --key cosign.key myregistry/myimage:latest

# Verify signature
cosign verify --key cosign.pub myregistry/myimage:latest
```

### Secure Image References
Always use immutable image references:

```yaml
# Bad - mutable tag
image: nginx:latest

# Good - immutable digest
image: nginx@sha256:abc123...
```

### Private Registry Security
- **Access controls**: RBAC for registry access
- **Network security**: Private endpoints, VPN access
- **Encryption**: TLS for image pulls/pushes
- **Audit logging**: Track image access and modifications

## Workload and Application Code Security

### Secure Coding Practices

#### Dependency Management
- Regular dependency updates
- Vulnerability scanning of dependencies
- Software Bill of Materials (SBOM)
- License compliance

#### Secret Management
- Never hardcode secrets in images
- Use Kubernetes Secrets or external secret managers
- Implement secret rotation
- Audit secret access

#### Input Validation
- Validate all external inputs
- Implement proper error handling
- Use parameterized queries
- Sanitize user data

### Runtime Security Monitoring

#### Behavioral Analysis
- Monitor for unusual process execution
- Detect privilege escalation attempts
- Track network connections
- File system monitoring

#### Security Policies
```yaml
# Example Falco rule
- rule: Unexpected outbound connection
  desc: Detect unexpected outbound network connections
  condition: >
    outbound and not fd.typechar = 4 and not fd.is_unix_socket and not proc.name in (allowed_processes)
  output: >
    Unexpected outbound connection (user=%user.name command=%proc.cmdline 
    connection=%fd.name)
  priority: WARNING
```

## Practice Exercises

### Exercise 1: Namespace Isolation
1. Create three namespaces: `development`, `staging`, `production`
2. Apply different Pod Security Standards to each
3. Create network policies to isolate traffic between namespaces

### Exercise 2: Image Security
1. Scan a container image for vulnerabilities using Trivy
2. Create a minimal Dockerfile using a distroless base image
3. Sign the image using Cosign

### Exercise 3: Security Benchmarking
1. Run kube-bench against your cluster
2. Identify and fix at least 3 security issues
3. Re-run the benchmark to verify improvements

## Additional Reading

### Official Documentation
- [Kubernetes Security Concepts](https://kubernetes.io/docs/concepts/security/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

### Security Frameworks
- [NIST Cybersecurity Framework](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [OWASP Kubernetes Top 10](https://owasp.org/www-project-kubernetes-top-ten/)
- [MITRE ATT&CK for Containers](https://medium.com/mitre-engenuity/att-ck-for-containers-now-available-4c2359654bf1)

### Tools and Platforms
- [Falco Documentation](https://falco.org/docs/)
- [Trivy Scanner](https://trivy.dev/)
- [Cosign Documentation](https://docs.sigstore.dev/cosign/overview/)
- [Kubescape](https://kubescape.io/)

### Best Practices Guides
- [Kubernetes Security Checklist](https://kubernetes.io/docs/concepts/security/security-checklist/)
- [OWASP Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)
- [Cloud Native Security Whitepaper](https://github.com/cncf/tag-security/blob/main/security-whitepaper/cloud-native-security-whitepaper.md)

---

**Next Section:** [Kubernetes Cluster Component Security →](../02-cluster-component-security/README.md)
