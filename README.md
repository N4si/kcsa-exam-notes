# KCSA (Kubernetes Certified Security Associate) Study Notes

I'm **Nasiullha Chaudhari**, and I recently passed the KCSA exam. I created this comprehensive study guide to help others prepare for this challenging certification. This repository covers all six domains of the 2025 KCSA exam curriculum with practical examples, official documentation references, and real-world scenarios.

## About This Guide

This guide is based on my personal experience preparing for and passing the KCSA exam. I've structured it to be practical, technical, and focused on what you actually need to know for the exam. Each section includes hands-on examples and links to official Kubernetes documentation.

## Exam Overview

The KCSA is a pre-professional certification designed for candidates interested in advancing to the professional level through a demonstrated understanding of foundational knowledge and skills of security technologies in the cloud native ecosystem.

**Exam Details:**
- **Format:** Multiple choice (unlike hands-on Kubernetes exams)
- **Duration:** 90 minutes
- **Cost:** $250 USD (includes one free retake)
- **Passing Score:** 75%
- **Validity:** 3 years
- **Delivery:** Online, proctored

**Prerequisites:**
- Basic understanding of Kubernetes concepts
- Familiarity with containerization technologies
- Basic knowledge of security principles
- Linux command line experience

## Study Guide Structure

### [1. Overview of Cloud Native Security (14%)](./01-cloud-native-security/README.md)
- The 4Cs of Cloud Native Security
- Cloud Provider and Infrastructure Security
- Controls and Frameworks
- Isolation Techniques
- Artifact Repository and Image Security
- Workload and Application Code Security

### [2. Kubernetes Cluster Component Security (22%)](./02-cluster-component-security/README.md)
- API Server Security
- Controller Manager
- Scheduler
- Kubelet Security
- Container Runtime
- KubeProxy
- Pod Security
- Etcd Security
- Container Networking
- Client Security
- Storage Security

### [3. Kubernetes Security Fundamentals (22%)](./03-security-fundamentals/README.md)
- Pod Security Standards
- Pod Security Admissions
- Authentication
- Authorization (RBAC)
- Secrets Management
- Isolation and Segmentation
- Audit Logging
- Network Policies

### [4. Kubernetes Threat Model (16%)](./04-threat-model/README.md)
- Trust Boundaries and Data Flow
- Persistence Attacks
- Denial of Service
- Malicious Code Execution
- Network-based Attacks
- Access to Sensitive Data
- Privilege Escalation

### [5. Platform Security (16%)](./05-platform-security/README.md)
- Supply Chain Security
- Image Repository Security
- Observability
- Service Mesh
- PKI (Public Key Infrastructure)
- Connectivity
- Admission Control

### [6. Compliance and Security Frameworks (10%)](./06-compliance-frameworks/README.md)
- Compliance Frameworks (PCI DSS, NIST, HIPAA)
- Threat Modeling Frameworks
- Supply Chain Compliance
- Automation and Tooling

## Getting Started

### Prerequisites
- Basic understanding of Kubernetes concepts
- Familiarity with containerization technologies
- Basic knowledge of security principles

### Setting Up Practice Environment
For hands-on practice, set up a local Kubernetes cluster:

```bash
# Install and start Minikube
minikube start

# Enable metrics server
minikube addons enable metrics-server

# Verify cluster is running
kubectl cluster-info

# Test with sample deployment
kubectl create deployment hello-node --image=registry.k8s.io/e2e-test-images/agnhost:2.39 -- /agnhost netexec --http-port=8080
```

## Study Tips

Based on my experience taking the KCSA exam:

1. **Focus on understanding concepts** rather than memorizing commands
2. **Practice with real Kubernetes clusters** when possible
3. **Read the official Kubernetes documentation** - many questions reference it directly
4. **Understand the security implications** of each component and configuration
5. **Practice threat modeling** and thinking like an attacker

## Navigation

- **Next:** [Overview of Cloud Native Security →](./01-cloud-native-security/README.md)

## 📖 How to Use This Guide

1. **Start with the Exam Overview** to understand the structure and requirements
2. **Follow the domains in order** - each builds upon previous knowledge
3. **Complete practice exercises** in each section
4. **Use additional reading** to deepen understanding
5. **Review regularly** and test your knowledge

## 🔗 Official Resources

- [CNCF KCSA Certification Page](https://www.cncf.io/training/certification/kcsa/)
- [Official KCSA Curriculum](https://github.com/cncf/curriculum/blob/master/KCSA%20Curriculum.pdf)
- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/)

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

This study guide is provided under the MIT License. See [LICENSE](LICENSE) for details.

## ⚠️ Disclaimer

This study guide is created by the community and is not officially endorsed by the CNCF. Always refer to the official CNCF documentation and curriculum for the most current exam requirements.

---

**Good luck with your KCSA exam preparation! 🎉**

*Last updated: June 2025*
