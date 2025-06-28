# Platform Security - 16%

Platform security encompasses the broader infrastructure and tooling that supports Kubernetes clusters, including supply chain security, observability, service mesh, PKI, connectivity, and admission control mechanisms.

## Supply Chain Security

Supply chain security focuses on securing the entire software development and deployment pipeline, from source code to running containers.

### Container Image Supply Chain

#### Image Build Security
```dockerfile
# Secure Dockerfile practices
FROM gcr.io/distroless/java:11  # Use minimal base images

# Create non-root user
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

# Copy application files
COPY --chown=appuser:appgroup app.jar /app/

# Switch to non-root user
USER appuser

# Set secure defaults
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
```

#### Multi-stage Builds
```dockerfile
# Multi-stage build for security
FROM maven:3.8-openjdk-11 AS builder
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

FROM gcr.io/distroless/java:11
COPY --from=builder /app/target/app.jar /app.jar
USER 1000
ENTRYPOINT ["java", "-jar", "/app.jar"]
```

#### Image Scanning Integration
```yaml
# GitHub Actions workflow with image scanning
name: Build and Scan
on: [push]
jobs:
  build-and-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    
    - name: Build image
      run: docker build -t myapp:${{ github.sha }} .
    
    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: 'myapp:${{ github.sha }}'
        format: 'sarif'
        output: 'trivy-results.sarif'
    
    - name: Upload Trivy scan results
      uses: github/codeql-action/upload-sarif@v1
      with:
        sarif_file: 'trivy-results.sarif'
```

### Software Bill of Materials (SBOM)

#### Generating SBOMs
```bash
# Generate SBOM with Syft
syft packages docker:nginx:latest -o spdx-json > nginx-sbom.json

# Generate SBOM with Docker Scout
docker scout sbom nginx:latest --format spdx > nginx-sbom.spdx
```

#### SBOM in CI/CD
```yaml
# GitLab CI pipeline with SBOM generation
stages:
  - build
  - scan
  - sbom

generate-sbom:
  stage: sbom
  script:
    - syft packages $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA -o spdx-json > sbom.json
  artifacts:
    reports:
      sbom: sbom.json
```

### Image Signing and Verification

#### Cosign Image Signing
```bash
# Generate key pair
cosign generate-key-pair

# Sign image
cosign sign --key cosign.key myregistry/myimage:latest

# Verify signature
cosign verify --key cosign.pub myregistry/myimage:latest
```

#### Keyless Signing with OIDC
```bash
# Keyless signing using OIDC identity
cosign sign myregistry/myimage:latest

# Verify with OIDC identity
cosign verify --certificate-identity user@example.com \
  --certificate-oidc-issuer https://accounts.google.com \
  myregistry/myimage:latest
```

#### Admission Controller for Signature Verification
```yaml
# Sigstore Policy Controller
apiVersion: v1
kind: ConfigMap
metadata:
  name: policy-controller-config
  namespace: cosign-system
data:
  policy.yaml: |
    apiVersion: policy.sigstore.dev/v1beta1
    kind: ClusterImagePolicy
    metadata:
      name: image-policy
    spec:
      images:
      - glob: "myregistry/*"
      authorities:
      - keyless:
          url: https://fulcio.sigstore.dev
          identities:
          - issuer: https://accounts.google.com
            subject: user@example.com
```

## Image Repository Security

Securing container registries and image repositories is crucial for maintaining supply chain integrity.

### Private Registry Security

#### Harbor Registry Configuration
```yaml
# Harbor with security scanning
apiVersion: v1
kind: ConfigMap
metadata:
  name: harbor-config
data:
  config.yaml: |
    hostname: harbor.example.com
    http:
      port: 80
    https:
      port: 443
      certificate: /data/cert/server.crt
      private_key: /data/cert/server.key
    
    # Security settings
    harbor_admin_password: SecurePassword123!
    
    # Enable vulnerability scanning
    trivy:
      ignore_unfixed: false
      skip_update: false
      insecure: false
    
    # RBAC settings
    auth_mode: db_auth
    self_registration: false
```

#### Registry Access Control
```yaml
# Kubernetes secret for registry access
apiVersion: v1
kind: Secret
metadata:
  name: registry-secret
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: eyJhdXRocyI6eyJyZWdpc3RyeS5leGFtcGxlLmNvbSI6eyJ1c2VybmFtZSI6InVzZXIiLCJwYXNzd29yZCI6InBhc3MiLCJhdXRoIjoiZFhObGNqcHdZWE56In19fQ==
```

#### Image Pull Policies
```yaml
# Secure image pull policy
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  imagePullSecrets:
  - name: registry-secret
  containers:
  - name: app
    image: private-registry.com/myapp:v1.2.3
    imagePullPolicy: Always  # Always pull latest
```

### Content Trust and Notary
```bash
# Enable Docker Content Trust
export DOCKER_CONTENT_TRUST=1

# Sign and push image
docker trust sign myregistry/myimage:latest

# Verify signed image
docker trust inspect myregistry/myimage:latest
```

## Observability

Observability provides visibility into cluster security posture through monitoring, logging, and alerting.

### Security Monitoring

#### Falco Runtime Security
```yaml
# Falco DaemonSet deployment
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
```

#### Custom Falco Rules
```yaml
# Custom security rules
- rule: Suspicious Network Activity
  desc: Detect suspicious network connections
  condition: >
    spawned_process and container and
    (proc.name in (nc, ncat, netcat, socat) or
     (proc.name = curl and proc.args contains "-X POST"))
  output: >
    Suspicious network activity detected (user=%user.name 
    container=%container.name command=%proc.cmdline)
  priority: WARNING

- rule: Container Privilege Escalation
  desc: Detect privilege escalation attempts
  condition: >
    spawned_process and container and
    (proc.name in (sudo, su) or
     proc.args contains "chmod +s" or
     proc.args contains "setuid")
  output: >
    Privilege escalation attempt (user=%user.name 
    container=%container.name command=%proc.cmdline)
  priority: HIGH
```

### Metrics and Alerting

#### Prometheus Security Metrics
```yaml
# ServiceMonitor for security metrics
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: security-metrics
spec:
  selector:
    matchLabels:
      app: security-exporter
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics
```

#### Security Alerts
```yaml
# PrometheusRule for security alerts
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: security-alerts
spec:
  groups:
  - name: kubernetes-security
    rules:
    - alert: PodSecurityViolation
      expr: increase(falco_events_total{rule_name=~".*privilege.*"}[5m]) > 0
      for: 0m
      labels:
        severity: critical
      annotations:
        summary: "Pod security violation detected"
        description: "Privilege escalation attempt detected in {{ $labels.container }}"
    
    - alert: UnauthorizedAPIAccess
      expr: increase(apiserver_audit_total{verb="create",objectRef_resource="secrets"}[5m]) > 10
      for: 2m
      labels:
        severity: warning
      annotations:
        summary: "High rate of secret creation detected"
        description: "Unusual secret creation activity detected"
```

## Service Mesh

Service mesh provides advanced networking and security capabilities for microservices communication.

### Istio Security Features

#### Mutual TLS (mTLS)
```yaml
# Enable strict mTLS for entire mesh
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  mtls:
    mode: STRICT
```

#### Authorization Policies
```yaml
# Deny all traffic by default
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: deny-all
  namespace: production
spec:
  {}

---
# Allow specific service communication
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: frontend-to-backend
  namespace: production
spec:
  selector:
    matchLabels:
      app: backend
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/production/sa/frontend"]
  - to:
    - operation:
        methods: ["GET", "POST"]
        paths: ["/api/*"]
```

#### JWT Authentication
```yaml
# JWT authentication policy
apiVersion: security.istio.io/v1beta1
kind: RequestAuthentication
metadata:
  name: jwt-auth
  namespace: production
spec:
  selector:
    matchLabels:
      app: api-gateway
  jwtRules:
  - issuer: "https://auth.example.com"
    jwksUri: "https://auth.example.com/.well-known/jwks.json"
    audiences:
    - "api.example.com"
```

## PKI (Public Key Infrastructure)

PKI provides the foundation for certificate-based authentication and encryption in Kubernetes.

### Certificate Management

#### Cluster CA Management
```bash
# Generate cluster CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -key ca.key -sha256 -subj "/C=US/ST=CA/O=MyOrg/CN=MyCA" -days 3650 -out ca.crt

# Generate server certificate
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr -subj "/C=US/ST=CA/O=MyOrg/CN=kubernetes"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256
```

#### cert-manager Integration
```yaml
# cert-manager ClusterIssuer
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: ca-issuer
spec:
  ca:
    secretName: ca-key-pair

---
# Certificate resource
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: api-server-cert
  namespace: kube-system
spec:
  secretName: api-server-tls
  issuerRef:
    name: ca-issuer
    kind: ClusterIssuer
  commonName: kubernetes.default.svc
  dnsNames:
  - kubernetes.default.svc
  - kubernetes.default.svc.cluster.local
  - kubernetes
  - localhost
  ipAddresses:
  - 127.0.0.1
  - 10.96.0.1
```

## Connectivity

Connectivity security focuses on securing network communications and access patterns within and outside the cluster.

### Network Security

#### CNI Security Configuration
```yaml
# Calico network policy for micro-segmentation
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: database-isolation
  namespace: production
spec:
  selector: app == 'database'
  types:
  - Ingress
  - Egress
  ingress:
  - action: Allow
    source:
      selector: app == 'backend'
    destination:
      ports:
      - 5432
  egress:
  - action: Allow
    destination:
      selector: app == 'logging'
```

### Ingress Security

#### Secure Ingress Configuration
```yaml
# NGINX Ingress with security annotations
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: secure-ingress
  annotations:
    # Enable TLS
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    
    # Security headers
    nginx.ingress.kubernetes.io/configuration-snippet: |
      add_header X-Frame-Options "SAMEORIGIN" always;
      add_header X-Content-Type-Options "nosniff" always;
      add_header X-XSS-Protection "1; mode=block" always;
      add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Rate limiting
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/rate-limit-window: "1m"
spec:
  tls:
  - hosts:
    - api.example.com
    secretName: api-tls-secret
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api-service
            port:
              number: 80
```

## Admission Control

Admission controllers intercept requests to the Kubernetes API server and can validate, mutate, or reject them based on security policies.

### Built-in Admission Controllers

#### Security-Focused Admission Controllers
```yaml
# API server admission controller configuration
--enable-admission-plugins=NodeRestriction,ResourceQuota,LimitRanger,ServiceAccount,DefaultStorageClass,DefaultTolerationSeconds,MutatingAdmissionWebhook,ValidatingAdmissionWebhook,PodSecurityPolicy,Priority,StorageObjectInUseProtection,PersistentVolumeClaimResize
```

### Custom Admission Controllers

#### OPA Gatekeeper
```yaml
# Gatekeeper constraint template
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8srequiredsecuritycontext
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredSecurityContext
      validation:
        type: object
        properties:
          runAsNonRoot:
            type: boolean
          readOnlyRootFilesystem:
            type: boolean
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredsecuritycontext
        
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not container.securityContext.runAsNonRoot
          msg := "Container must run as non-root user"
        }
```

## Practice Exercises

### Exercise 1: Supply Chain Security Implementation
1. Set up a complete CI/CD pipeline with security scanning
2. Implement image signing with Cosign
3. Create admission controllers for signature verification
4. Generate and validate SBOMs

### Exercise 2: Service Mesh Security Configuration
1. Deploy Istio with strict mTLS
2. Implement authorization policies
3. Configure JWT authentication
4. Monitor security metrics

### Exercise 3: PKI and Certificate Management
1. Set up cert-manager
2. Configure automatic certificate rotation
3. Implement certificate monitoring
4. Test certificate validation

## Additional Reading

### Official Documentation
- [Kubernetes Security](https://kubernetes.io/docs/concepts/security/)
- [Admission Controllers](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
- [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

### Supply Chain Security
- [SLSA Framework](https://slsa.dev/)
- [Sigstore Documentation](https://docs.sigstore.dev/)
- [NIST SSDF](https://csrc.nist.gov/Projects/ssdf)

### Service Mesh Security
- [Istio Security](https://istio.io/latest/docs/concepts/security/)
- [Linkerd Security](https://linkerd.io/2/features/automatic-mtls/)

### Tools and Platforms
- [Trivy](https://trivy.dev/) - Vulnerability scanner
- [Cosign](https://docs.sigstore.dev/cosign/overview/) - Container signing
- [cert-manager](https://cert-manager.io/) - Certificate management
- [Harbor](https://goharbor.io/) - Container registry

---

**Next Section:** [Compliance and Security Frameworks →](../06-compliance-frameworks/README.md)
