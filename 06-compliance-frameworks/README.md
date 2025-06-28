# Compliance and Security Frameworks - 10%

Compliance frameworks and automation tools for regulatory compliance in Kubernetes.

## Compliance Frameworks

### PCI DSS (Payment Card Industry)
- **Network segmentation** for cardholder data
- **Access controls** and authentication
- **Encryption** at rest and in transit
- **Regular security testing**
- **Audit logging** and monitoring

### HIPAA (Healthcare)
- **Data encryption** requirements
- **Access controls** and audit trails
- **Risk assessments**
- **Business associate agreements**

### NIST Cybersecurity Framework
- **Identify** - Asset management, risk assessment
- **Protect** - Access control, data security
- **Detect** - Security monitoring
- **Respond** - Incident response
- **Recover** - Recovery planning

### SOC 2 (Service Organizations)
- **Security** controls
- **Availability** controls
- **Processing integrity**
- **Confidentiality**
- **Privacy** controls
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: payment-processing
  name: pci-limited-access
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
  resourceNames: ["payment-processor"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
  resourceNames: ["payment-keys"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: pci-access-binding
  namespace: payment-processing
subjects:
- kind: User
  name: payment-admin
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: pci-limited-access
  apiGroup: rbac.authorization.k8s.io
```

##### Encryption Requirements
```yaml
# PCI DSS encryption at rest
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - secrets
  - configmaps
  providers:
  - aescbc:
      keys:
      - name: key1
        secret: <32-byte base64 encoded key>
  - identity: {}
```

### HIPAA (Health Insurance Portability and Accountability Act)

HIPAA applies to healthcare organizations and requires protection of Protected Health Information (PHI).

#### HIPAA Security Controls

##### Administrative Safeguards
```yaml
# HIPAA role-based access control
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: hipaa-healthcare-worker
rules:
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list", "watch"]
  resourceNames: ["patient-portal", "medical-records"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
  resourceNames: ["phi-encryption-keys"]
```

##### Technical Safeguards
```yaml
# HIPAA encryption and access controls
apiVersion: v1
kind: Pod
metadata:
  name: phi-database
  namespace: healthcare
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
  containers:
  - name: database
    image: postgres:13-alpine
    env:
    - name: POSTGRES_PASSWORD
      valueFrom:
        secretKeyRef:
          name: phi-db-secret
          key: password
    - name: POSTGRES_SSL_MODE
      value: "require"
    volumeMounts:
    - name: phi-data
      mountPath: /var/lib/postgresql/data
      readOnly: false
    - name: ssl-certs
      mountPath: /etc/ssl/certs
      readOnly: true
  volumes:
  - name: phi-data
    persistentVolumeClaim:
      claimName: encrypted-phi-storage
  - name: ssl-certs
    secret:
      secretName: database-ssl-certs
```

### NIST (National Institute of Standards and Technology)

NIST provides comprehensive cybersecurity frameworks widely adopted by government and enterprise organizations.

#### NIST Cybersecurity Framework Implementation

##### Identify
```yaml
# Asset inventory and classification
apiVersion: v1
kind: ConfigMap
metadata:
  name: asset-inventory
  namespace: security
  labels:
    nist.function: identify
    nist.category: asset-management
data:
  classification.yaml: |
    assets:
      - name: customer-database
        classification: confidential
        owner: data-team
        location: namespace/production
        backup-required: true
      - name: web-frontend
        classification: public
        owner: frontend-team
        location: namespace/production
        backup-required: false
```

##### Protect
```yaml
# NIST protection controls
apiVersion: v1
kind: Pod
metadata:
  name: protected-workload
  namespace: production
  labels:
    nist.function: protect
    nist.category: access-control
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: myapp:secure
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE
    resources:
      limits:
        cpu: "500m"
        memory: "512Mi"
      requests:
        cpu: "100m"
        memory: "128Mi"
```

##### Detect
```yaml
# NIST detection capabilities
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-nist-rules
  namespace: falco-system
data:
  nist_rules.yaml: |
    - rule: NIST Detect - Unauthorized Process
      desc: Detect processes not in approved baseline
      condition: >
        spawned_process and container and
        not proc.name in (approved_processes) and
        not proc.pname in (approved_parent_processes)
      output: >
        Unauthorized process detected (nist.function=detect 
        user=%user.name container=%container.name 
        process=%proc.name parent=%proc.pname)
      priority: HIGH
      tags: [nist, detect, process]
    
    - rule: NIST Detect - Data Exfiltration
      desc: Detect potential data exfiltration
      condition: >
        outbound and fd.typechar = 4 and fd.is_server = false and
        (fd.sport in (ftp_ports) or fd.dport in (ftp_ports)) and
        container
      output: >
        Potential data exfiltration detected (nist.function=detect 
        connection=%fd.name container=%container.name)
      priority: CRITICAL
      tags: [nist, detect, exfiltration]
```

### SOC 2 (Service Organization Control 2)

SOC 2 focuses on security, availability, processing integrity, confidentiality, and privacy controls.

#### SOC 2 Security Controls

##### Access Controls
```yaml
# SOC 2 access control implementation
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: soc2-auditor
  labels:
    soc2.control: access-control
    soc2.principle: security
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["list"]  # Can list but not read secret contents
```

## Threat Modeling Frameworks

Threat modeling helps identify, analyze, and mitigate security threats in Kubernetes environments.

### STRIDE Threat Model

STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) is a widely used threat modeling framework.

#### STRIDE Analysis for Kubernetes

##### Spoofing Threats
```yaml
# Anti-spoofing controls
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: anti-spoofing
  namespace: production
spec:
  mtls:
    mode: STRICT  # Prevents identity spoofing

---
# Service account authentication
apiVersion: v1
kind: ServiceAccount
metadata:
  name: verified-service
  namespace: production
  annotations:
    stride.threat: spoofing
    stride.mitigation: strong-authentication
```

##### Tampering Threats
```yaml
# Anti-tampering controls
apiVersion: v1
kind: Pod
metadata:
  name: tamper-resistant
  namespace: production
  annotations:
    stride.threat: tampering
    stride.mitigation: integrity-protection
spec:
  securityContext:
    runAsNonRoot: true
    readOnlyRootFilesystem: true
  containers:
  - name: app
    image: myapp@sha256:abc123...  # Immutable image reference
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
    volumeMounts:
    - name: config
      mountPath: /etc/config
      readOnly: true
  volumes:
  - name: config
    configMap:
      name: app-config
      defaultMode: 0444  # Read-only
```

##### Information Disclosure Threats
```yaml
# Information disclosure prevention
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: prevent-disclosure
  namespace: production
  annotations:
    stride.threat: information-disclosure
    stride.mitigation: network-segmentation
spec:
  podSelector:
    matchLabels:
      tier: database
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          tier: backend
    ports:
    - protocol: TCP
      port: 5432
  # No egress rules = deny all egress
```

### MITRE ATT&CK for Containers

MITRE ATT&CK provides a framework for understanding adversary tactics and techniques.

#### ATT&CK Technique Mapping

##### Initial Access
```yaml
# Prevent initial access techniques
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: prevent-initial-access
  namespace: production
  annotations:
    mitre.attack.technique: T1190  # Exploit Public-Facing Application
    mitre.attack.mitigation: network-segmentation
spec:
  podSelector:
    matchLabels:
      tier: frontend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - ipBlock:
        cidr: 10.0.0.0/8  # Only internal traffic
    ports:
    - protocol: TCP
      port: 80
```

##### Execution
```yaml
# Prevent malicious execution
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: prevent-execution
  annotations:
    mitre.attack.technique: T1609  # Container Administration Command
spec:
  validationFailureAction: enforce
  rules:
  - name: block-privileged-containers
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "Privileged containers blocked (MITRE T1609)"
      pattern:
        spec:
          =(securityContext):
            =(privileged): "false"
          containers:
          - name: "*"
            =(securityContext):
              =(privileged): "false"
```

## Supply Chain Compliance

Supply chain compliance ensures the security and integrity of software components throughout the development and deployment pipeline.

### SLSA (Supply-chain Levels for Software Artifacts)

SLSA provides a framework for supply chain security with four levels of increasing security guarantees.

#### SLSA Level 1 Implementation
```yaml
# SLSA Level 1 - Documentation
apiVersion: v1
kind: ConfigMap
metadata:
  name: slsa-level1-docs
  namespace: ci-cd
data:
  build-process.md: |
    # Build Process Documentation (SLSA Level 1)
    
    ## Source Code
    - Repository: https://github.com/company/app
    - Branch: main
    - Commit: ${GIT_COMMIT}
    
    ## Build Steps
    1. Source code checkout
    2. Dependency installation
    3. Unit tests execution
    4. Security scanning
    5. Container image build
    6. Image signing
    
    ## Artifacts
    - Container Image: registry.company.com/app:${VERSION}
    - SBOM: app-${VERSION}-sbom.json
    - Signature: app-${VERSION}.sig
```

#### SLSA Level 2 Implementation
```yaml
# SLSA Level 2 - Hosted build service
apiVersion: tekton.dev/v1beta1
kind: Pipeline
metadata:
  name: slsa-level2-pipeline
  namespace: ci-cd
  annotations:
    slsa.level: "2"
    slsa.build-type: "tekton"
spec:
  params:
  - name: git-url
  - name: git-revision
  workspaces:
  - name: shared-data
  tasks:
  - name: git-clone
    taskRef:
      name: git-clone
    workspaces:
    - name: output
      workspace: shared-data
    params:
    - name: url
      value: $(params.git-url)
    - name: revision
      value: $(params.git-revision)
  
  - name: build-and-sign
    taskRef:
      name: kaniko
    runAfter: ["git-clone"]
    workspaces:
    - name: source
      workspace: shared-data
    params:
    - name: IMAGE
      value: registry.company.com/app:$(params.git-revision)
    - name: DOCKERFILE
      value: ./Dockerfile
  
  - name: generate-provenance
    taskRef:
      name: slsa-provenance
    runAfter: ["build-and-sign"]
    params:
    - name: image
      value: registry.company.com/app:$(params.git-revision)
```

### Software Bill of Materials (SBOM) Compliance

#### SPDX SBOM Generation
```yaml
# SBOM generation in CI/CD
apiVersion: tekton.dev/v1beta1
kind: Task
metadata:
  name: generate-sbom
spec:
  params:
  - name: image
    description: Container image to analyze
  steps:
  - name: generate-spdx
    image: anchore/syft:latest
    script: |
      #!/bin/sh
      syft packages $(params.image) -o spdx-json > /workspace/sbom.spdx.json
      
      # Validate SBOM
      spdx-tools validate /workspace/sbom.spdx.json
      
      # Upload to artifact store
      curl -X POST https://artifacts.company.com/sbom \
        -H "Content-Type: application/json" \
        -d @/workspace/sbom.spdx.json
  workspaces:
  - name: workspace
```

## Automation and Tooling

Automation is essential for maintaining security and compliance at scale in Kubernetes environments.

### Security Automation Tools

#### Falco for Runtime Security
```yaml
# Falco deployment with custom rules
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: falco
  namespace: falco-system
spec:
  selector:
    matchLabels:
      app: falco
  template:
    metadata:
      labels:
        app: falco
    spec:
      serviceAccountName: falco
      hostNetwork: true
      hostPID: true
      containers:
      - name: falco
        image: falcosecurity/falco:latest
        securityContext:
          privileged: true
        volumeMounts:
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: boot
          mountPath: /host/boot
          readOnly: true
        - name: lib-modules
          mountPath: /host/lib/modules
          readOnly: true
        - name: usr
          mountPath: /host/usr
          readOnly: true
        - name: etc
          mountPath: /host/etc
          readOnly: true
        - name: falco-config
          mountPath: /etc/falco
      volumes:
      - name: proc
        hostPath:
          path: /proc
      - name: boot
        hostPath:
          path: /boot
      - name: lib-modules
        hostPath:
          path: /lib/modules
      - name: usr
        hostPath:
          path: /usr
      - name: etc
        hostPath:
          path: /etc
      - name: falco-config
        configMap:
          name: falco-config
```

#### Trivy for Vulnerability Scanning
```yaml
# Trivy operator for continuous scanning
apiVersion: aquasecurity.github.io/v1alpha1
kind: VulnerabilityReport
metadata:
  name: nginx-vulnerability-report
  namespace: default
spec:
  artifact:
    repository: nginx
    tag: latest
  scanner:
    name: Trivy
    vendor: Aqua Security
    version: v0.18.3
```

#### Kube-bench for CIS Compliance
```yaml
# Kube-bench job for CIS benchmark testing
apiVersion: batch/v1
kind: Job
metadata:
  name: kube-bench
  namespace: security
spec:
  template:
    spec:
      hostPID: true
      containers:
      - name: kube-bench
        image: aquasec/kube-bench:latest
        command: ["kube-bench"]
        args: ["--version", "1.20"]
        volumeMounts:
        - name: var-lib-etcd
          mountPath: /var/lib/etcd
          readOnly: true
        - name: var-lib-kubelet
          mountPath: /var/lib/kubelet
          readOnly: true
        - name: etc-systemd
          mountPath: /etc/systemd
          readOnly: true
        - name: etc-kubernetes
          mountPath: /etc/kubernetes
          readOnly: true
        - name: usr-bin
          mountPath: /usr/local/mount-from-host/bin
          readOnly: true
      restartPolicy: Never
      volumes:
      - name: var-lib-etcd
        hostPath:
          path: "/var/lib/etcd"
      - name: var-lib-kubelet
        hostPath:
          path: "/var/lib/kubelet"
      - name: etc-systemd
        hostPath:
          path: "/etc/systemd"
      - name: etc-kubernetes
        hostPath:
          path: "/etc/kubernetes"
      - name: usr-bin
        hostPath:
          path: "/usr/bin"
```

### Policy as Code

#### Open Policy Agent (OPA) Integration
```yaml
# OPA configuration for policy enforcement
apiVersion: v1
kind: ConfigMap
metadata:
  name: opa-policies
  namespace: opa-system
data:
  compliance.rego: |
    package kubernetes.compliance
    
    # PCI DSS compliance policy
    deny[msg] {
      input.kind == "Pod"
      input.metadata.namespace == "payment-processing"
      not input.spec.securityContext.runAsNonRoot
      msg := "PCI DSS: Containers must run as non-root user"
    }
    
    # HIPAA compliance policy
    deny[msg] {
      input.kind == "Pod"
      input.metadata.labels["data-classification"] == "phi"
      not input.spec.containers[_].securityContext.readOnlyRootFilesystem
      msg := "HIPAA: PHI containers must have read-only root filesystem"
    }
    
    # SOC 2 compliance policy
    deny[msg] {
      input.kind == "Secret"
      input.metadata.namespace == "production"
      not input.metadata.annotations["encryption.soc2/enabled"]
      msg := "SOC 2: Production secrets must be encrypted"
    }
```

## Practice Exercises

### Exercise 1: Multi-Framework Compliance Implementation
1. Set up compliance monitoring for PCI DSS, HIPAA, and SOC 2
2. Implement automated compliance scanning with multiple tools
3. Create compliance dashboards and reporting
4. Test compliance policies with various workload configurations

### Exercise 2: Threat Modeling Workshop
1. Conduct STRIDE analysis for a sample application
2. Map threats to MITRE ATT&CK techniques
3. Implement PASTA methodology for risk assessment
4. Document findings and mitigation strategies

### Exercise 3: Supply Chain Security Pipeline
1. Implement SLSA Level 2+ compliance
2. Set up SBOM generation and verification
3. Configure license compliance scanning
4. Create supply chain security policies

### Exercise 4: Automation and Tooling Integration
1. Deploy comprehensive security monitoring stack
2. Configure automated policy enforcement
3. Set up incident response automation
4. Implement compliance reporting automation

## Additional Reading

### Compliance Frameworks
- [PCI DSS Requirements](https://www.pcisecuritystandards.org/pci_security/)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SOC 2 Trust Services Criteria](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html)

### Threat Modeling
- [STRIDE Threat Model](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [PASTA Methodology](https://versprite.com/blog/what-is-pasta-threat-modeling/)
- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)

### Supply Chain Security
- [SLSA Framework](https://slsa.dev/)
- [NIST SSDF](https://csrc.nist.gov/Projects/ssdf)
- [CNCF Supply Chain Security Paper](https://github.com/cncf/tag-security/blob/main/supply-chain-security/supply-chain-security-paper/CNCF_SSCP_v1.pdf)
- [Software Bill of Materials (SBOM)](https://www.cisa.gov/sbom)

### Automation Tools
- [Open Policy Agent](https://www.openpolicyagent.org/)
- [Gatekeeper](https://open-policy-agent.github.io/gatekeeper/)
- [Falco](https://falco.org/)
- [Trivy](https://trivy.dev/)
- [kube-bench](https://github.com/aquasecurity/kube-bench)
- [Polaris](https://polaris.docs.fairwinds.com/)

---

**Repository Navigation:** [← Platform Security](../05-platform-security/README.md) | [Main README](../README.md)

## Summary

This section covered the essential compliance and security frameworks needed for the KCSA exam:

- **Compliance Frameworks**: PCI DSS, HIPAA, NIST, and SOC 2 requirements
- **Threat Modeling**: STRIDE, MITRE ATT&CK, and PASTA methodologies  
- **Supply Chain Compliance**: SLSA, SBOM, and license management
- **Automation and Tooling**: Security scanning, policy enforcement, and monitoring

Understanding these frameworks and their implementation in Kubernetes environments is crucial for maintaining security and regulatory compliance in production systems.

---

**Navigation:**
- **Previous:** [← Platform Security](../05-platform-security/README.md)
- **Next:** [Main README →](../README.md)
