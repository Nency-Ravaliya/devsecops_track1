# Runtime Detection & Incident Response Plan

## 1. Current State

The programme has **no runtime detection tooling anywhere** across ~100 workloads (Module 1 findings register, programme context). Module 1 identified 28 security findings including 6 Critical, none of which would generate a runtime alert today. If a pod is compromised, the earliest signal is likely a user-reported outage or a routine audit weeks later.

This module designs the runtime detection capability from scratch and defines how an actual incident is handled end to end.

## 2. Runtime Threat Detection Design

### 2.1 Tool Selection: Falco 0.38.x on EKS

**Choice:** Falco 0.38.x (CNCF Incubating project) deployed as a DaemonSet via the [falcosecurity/falco Helm chart v4.x](https://github.com/falcosecurity/charts).

**Alternatives considered:**

| Tool | Verdict |
|---|---|
| **Falco 0.38.x** | Selected. Mature Kubernetes-native runtime detection with 150+ community rules, eBPF-based kernel module (no kernel headers required on EKS 1.29+), direct integration with Kubernetes metadata enrichment, and strong Falco + K8s audit log correlation. Active CNCF community with quarterly rule updates. |
| **Tetragon (Cilium)** | Strong eBPF enforcement and detection, but requires Cilium as the CNI. Programme currently uses default AWS VPC CNI with no NetworkPolicy enforcement (K8S-015). Adopting Cilium changes the networking layer, which is a separate decision (Module 4). Tetragon can be added later if Module 4 recommends Cilium. |
| **Amazon GuardDuty EKS Runtime Monitoring** | Requires GuardDuty agent on every node, has per-cluster pricing, and lacks the custom rule flexibility needed for the RBAC-focused detections this programme requires (e.g. alerting on ClusterRoleBinding creation from a pod). Good supplementary option but insufficient alone. |
| **Sysdig Secure** | Commercial alternative with strong runtime + forensics. Adds licensing cost for 100 workloads. Falco is the open-source core of Sysdig's detection engine anyway. |

**Multi-cloud note:** Falco runs on any Kubernetes distribution (EKS, AKS, GKE). The Helm chart and rules are cloud-agnostic. When Azure and GCP onboard, the same Falco DaemonSet deploys without changes. EKS-specific Falco plugins for CloudTrail integration are AWS-only but the core detection works everywhere.

### 2.2 Deployment Architecture

```
EKS Node Group (every node)
├── Falco DaemonSet (eBPF driver, privileged=false since Falco 0.36+)
│   ├── falco-driver-loader (init container — loads eBPF probe)
│   ├── falco (main container — rule engine + output)
│   └── falcosidekick (sidecar — routes alerts)
│       ├── AWS CloudWatch Logs → SIEM
│       ├── Slack #security-alerts
│       └── webhook → PagerDuty (Critical only)
├── K8s Audit Log → CloudWatch Logs → SIEM (control-plane events)
└── Application workloads (unmodified)
```

**Key architectural decision:** Falco runs with `privileged: false` and `capabilities: drop: [ALL]` except `SYS_MODULE` (required for eBPF probe loading). This avoids creating the exact anti-pattern (K8S-006) the programme is trying to prevent.

### 2.3 Rule Categories and Priority

Rules are grouped by the Module 1 finding classes they address. Priority determines alert routing:

#### P1 — Critical: Alert + PagerDuty + Immediate Triage

| Rule | Module 1 finding | What it detects |
|---|---|---|
| `K8S RBAC ClusterRoleBinding Created` | K8S-001, K8S-002, K8S-003 | Any pod or process creating a ClusterRoleBinding or ClusterRole — this is the trigger incident detection. If a pod (not kube-system SA) creates a ClusterRoleBinding, fire immediately. |
| `Container Privileged Mode` | K8S-004, K8S-005, K8S-006 | Any container starting with `privileged: true`. In production (post-remediation), privileged pods should not exist. |
| `Container Escape Indicators` | K8S-004, K8S-005 | Processes inside containers accessing `/proc/sys/kernel` or writing to host filesystem paths (`/etc`, `/var/run/docker.sock`). |
| `Kubernetes Secrets Accessed from Unapproved Path` | K8S-009, K8S-010 | Any process reading `/var/run/secrets/kubernetes.io/serviceaccount/token` in a namespace that should not have API access, or reading Secret data via the API from a non-system pod. |
| `Unexpected Outbound Connection from Pod` | K8S-015 (NetworkPolicy absence) | Pod making outbound connection to a public IP that is not an approved destination (egress anomaly). |

#### P2 — High: Alert + Slack + 1-hour SLA Triage

| Rule | Module 1 finding | What it detects |
|---|---|---|
| `Container Drift — Binary Executed Not in Image` | K8S-013, K8S-014 | A process running in a container that was not present in the image at build time (fileless execution, injected binary, curl/wget to unknown host). |
| `Host Network Namespace Access` | K8S-006 | Any container process accessing host networking interfaces (eth0, aws-vpc-cni), indicating hostNetwork usage. |
| `Container with Sensitive File Access` | K8S-005 | Containers reading Docker socket, containerd socket, or `/etc/shadow`. |
| `Reverse Shell / Interactive Shell Detected` | General | Processes spawning `/bin/sh` or `/bin/bash` with network-connected file descriptors (reverse shell pattern). |
| `Crypto Mining Indicators` | General | Processes with high CPU + known mining pool connections (stratum+tcp). |

#### P3 — Medium: Alert + Logged to SIEM, weekly review

| Rule | Module 1 finding | What it detects |
|---|---|---|
| `Pod Running as Root in Non-System Namespace` | K8S-021 | Container processes running as UID 0 in namespaces other than kube-system. |
| `Missing Seccomp Profile` | K8S-022 | Any container not running with RuntimeDefault or Custom seccomp (logged once per pod creation). |
| `Kubernetes Service Account Token Automounting` | K8S-012 | Pods with `automountServiceAccountToken: true` (the default) in namespaces where IRSA/workload identity should be used. |

### 2.4 Telemetry Pipeline

| Signal | Source | Collection | Destination | Retention |
|---|---|---|---|---|
| **Falco alerts** | Falco DaemonSet → falcosidekick | falcosidekick output | CloudWatch Logs (SIEM sink) + Slack + PagerDuty | 90 days hot, 1 year cold (S3 Glacier) |
| **Kubernetes Audit Logs** | EKS control-plane | EKS cluster logging enabled (api, audit, authenticator, controllerManager, scheduler) | CloudWatch Logs → SIEM | 90 days hot, 1 year cold |
| **Node OS audit** | kubelet logs | CloudWatch Agent DaemonSet | CloudWatch Logs | 90 days |
| **Pod-level network flows** | VPC Flow Logs (pod ENI) | VPC Flow Logs → S3 | SIEM (queried on-demand for incident response) | 30 days hot, 1 year cold |
| **Container filesystem changes** | Falco file-integrity rules | Falco alerts | CloudWatch + SIEM | 90 days |

### 2.5 Alert Fatigue Management

At ~100 workloads, the volume of Falco alerts can be overwhelming. The programme addresses this with:

**1. Tuning via Falco Exceptions (not rule suppression):**

Falco 0.38.x supports rule exceptions (whitelisting specific known-safe patterns per workload). These are version-controlled in the platform-policies repo (Module 2):

```yaml
# Example exception: kube-bench jobs legitimately access host paths
- rule: Container with Sensitive File Access
  exception:
    - name: kube-bench-job-access
      condition: (fd.name startswith /var/lib/etcd) and (ka.target.namespace = "security-scanning")
      outcome: exclude
```

Exceptions require security team approval via MR (same CODEOWNERS gate as pipeline policy changes). Every exception has an expiry date and a justification linked to a finding ID.

**2. Deduplication in falcosidekick:**

falcosidekick 3.x has built-in deduplication windows. Identical alerts from the same pod within a 5-minute window are collapsed into one notification.

**3. Alert routing by priority:**

- **P1 Critical:** PagerDuty → on-call security engineer → immediate triage (see incident response below)
- **P2 High:** Slack `#security-alerts` → next business day triage
- **P3 Medium:** CloudWatch Logs → weekly security review meeting, bulk triaged

**4. Baseline learning period (30 days):**

On initial deployment, Falco runs in audit-only mode (output: log, no alert routing). During this period, the security team reviews and tunes exceptions for legitimate workload behaviour. After 30 days, alert routing is enabled for P1 and P2 rules. P3 rules remain in audit mode until baseline is stable.

**Expected alert volume:** For 100 workloads with tuned rules, expect 5-15 P1 alerts/week (mostly false positives in first month, dropping to <1/week after tuning), 20-50 P2 alerts/week (heavily workload-dependent), and 100+ P3 events/week (reviewed in bulk).

## 3. Incident Response: Container Escape Scenario

### 3.1 Scenario Description

A pod in the `citizen-frontend` namespace is confirmed compromised. The attacker has achieved container escape via a privileged container with host filesystem access (consistent with the patterns found in K8S-004/005/006). The Falco rule `Container Escape Indicators` has fired (P1 alert).

**Workload context:** This is a citizen-facing EKS workload running on managed node groups. It handles unauthenticated traffic via the AWS Load Balancer Controller. The cluster uses default VPC CNI with no NetworkPolicy enforcement (K8S-015).

### 3.2 Detection (T+0 to T+5 minutes)

**Signal:** PagerDuty P1 alert from Falco for `Container Escape Indicators` on node `ip-10-0-1-42.ec2.internal`, pod `frontend-deploy-7f8c9b-xk2mv` in namespace `citizen-frontend`.

**Initial triage steps (security on-call):**

```bash
# 1. Confirm the alert — check Falco event details in CloudWatch
aws logs filter-log-events \
  --log-group-name /aws/falco/citizen-cluster \
  --filter-pattern "Container Escape Indicators" \
  --start-time $(date -d '10 minutes ago' +%s000) \
  --region eu-west-2

# 2. Identify the compromised pod and its node
kubectl get pod frontend-deploy-7f8c9b-xk2mv -n citizen-frontend -o wide

# 3. Check what the pod has access to
kubectl describe pod frontend-deploy-7f8c9b-xk2mv -n citizen-frontend

# 4. Quick process listing via Falco syscall trace (avoids kubectl exec — the attacker may be watching)
# Falco's k8s.audit verbs give us the pod's process context without executing into it
```

### 3.3 Containment (T+5 to T+15 minutes)

**Goal:** Stop the attacker from doing more damage while preserving forensic evidence. Do NOT kill the pod yet — that destroys the process tree, open file handles, and memory.

**Step 1: Cordon the node (stop new pods scheduling, don't evict existing ones)**

```bash
# Cordon the node — prevents new workloads from being scheduled here
# Existing pods (including the compromised one) keep running
kubectl cordon ip-10-0-1-42.ec2.internal

# Verify
kubectl get node ip-10-0-1-42.ec2.internal
# STATUS: Ready,SchedulingDisabled
```

**Step 2: Network-isolate the pod without killing it**

```bash
# Apply an emergency NetworkPolicy that drops all traffic to/from the pod
# This works even without Cilium/Calico because we're patching the pod's
# network identity — if VPC CNI doesn't support NetworkPolicy enforcement,
# we fall back to the AWS Security Group for Pods approach:

# Option A (if Cilium/Calico is deployed — Module 4 target state):
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: incident-isolate-compromised-pod
  namespace: citizen-frontend
spec:
  podSelector:
    matchLabels:
      app: frontend-deploy
  policyTypes:
    - Ingress
    - Egress
  ingress: []  # deny all ingress
  egress: []   # deny all egress
EOF

# Option B (current state — VPC CNI, no NetworkPolicy enforcement):
# Tag the pod's node with a security group that blocks all traffic
# via AWS API:
NODE_ENI_ID=$(aws ec2 describe-instances \
  --instance-ids i-0abcdef1234567890 \
  --region eu-west-2 \
  --query 'Reservations[].Instances[].NetworkInterfaces[0].NetworkInterfaceId' \
  --output text)
aws ec2 modify-network-interface-attribute \
  --network-interface-id $NODE_ENI_ID \
  --groups sg-isolation-quarantine \  # pre-provisioned SG that allows only SIEM access
  --region eu-west-2
```

**Step 3: Capture forensic evidence BEFORE killing the pod**

```bash
# Forensic evidence must be captured without kubectl exec (attacker may detect it).
# Use the node's containerd runtime directly via SSM or node SSH:

# 3a. Process tree snapshot (via /proc on the host — no exec into container)
# SSH to node or use SSM:
NODE_ID=$(kubectl get node ip-10-0-1-42.ec2.internal -o jsonpath='{.status.addresses[?(@.type=="ExternalIP")].address}')
aws ssm send-command \
  --instance-ids i-0abcdef1234567890 \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=[
    "mkdir -p /tmp/forensics/frontend-deploy-7f8c9b-xk2mv",
    "ps auxf > /tmp/forensics/frontend-deploy-7f8c9b-xk2mv/process_tree.txt",
    "netstat -tlnp > /tmp/forensics/frontend-deploy-7f8c9b-xk2mv/network_connections.txt",
    "ss -tlnp > /tmp/forensics/frontend-deploy-7f8c9b-xk2mv/sockets.txt",
    "ls -la /proc/*/exe 2>/dev/null | grep deleted > /tmp/forensics/frontend-deploy-7f8c9b-xk2mv/deleted_exes.txt"
  ]' \
  --region eu-west-2

# 3b. Container filesystem snapshot (via crictl on the node)
aws ssm send-command \
  --instance-ids i-0abcdef1234567890 \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=[
    "CONTAINER_ID=$(crictl ps --name frontend-deploy -q)",
    "tar czf /tmp/forensics/frontend-deploy-7f8c9b-xk2mv/filesystem.tar.gz /var/lib/containerd/io.containerd.snapshot.v1.overlayfs/snapshots/$(crictl inspect $CONTAINER_ID | jq -r .info.runtimeSpec.root.path)",
    "crictl inspect $CONTAINER_ID > /tmp/forensics/frontend-deploy-7f8c9b-xk2mv/container_inspect.json"
  ]' \
  --region eu-west-2

# 3c. Memory dump (optional — requires LiME kernel module on the node)
# Skip if LiME is not pre-installed; process tree + filesystem is usually sufficient.
# If needed: insmod /tmp/lime.ko "path=/tmp/forensics/frontend-deploy-7f8c9b-xk2mv/memory.lime format=lime"

# 3d. Pod logs (capture BEFORE killing — after kill, logs may be lost if not using
# a log aggregator)
kubectl logs frontend-deploy-7f8c9b-xk2mv -n citizen-frontend --all-containers --since=1h \
  > /tmp/forensics/frontend-deploy-7f8c9b-xk2mv/pod_logs.txt

# 3e. Kubernetes audit log for the compromised pod
aws logs filter-log-events \
  --log-group-name /aws/eks/citizen-cluster/cluster \
  --filter-pattern '{ $.objectRef.name = "frontend-deploy-7f8c9b-xk2mv" }' \
  --start-time $(date -d '24 hours ago' +%s000) \
  --region eu-west-2 > /tmp/forensics/frontend-deploy-7f8c9b-xk2mv/k8s_audit.json
```

**Step 4: Snapshot evidence to S3 (immutable bucket)**

```bash
aws s3 cp /tmp/forensics/frontend-deploy-7f8c9b-xk2mv/ \
  s3://forensics-bucket-eu-west-2/incidents/$(date +%Y%m%d)-frontend-escape/ \
  --recursive \
  --region eu-west-2
# Bucket has Object Lock in Compliance mode — evidence cannot be deleted or modified
```

### 3.4 Eradication (T+15 to T+30 minutes)

```bash
# Kill the compromised pod (evidence already captured above)
kubectl delete pod frontend-deploy-7f8c9b-xk2mv -n citizen-frontend --grace-period=0

# Check if the pod is part of a ReplicaSet (it is — Deployment)
# The Deployment controller will recreate it. Prevent that by scaling down:
kubectl scale deployment frontend-deploy -n citizen-frontend --replicas=0

# Check for lateral movement — did the compromised pod create any other resources?
kubectl get all -n citizen-frontend -o wide | grep -v frontend-deploy
kubectl get clusterrolebindings -o json | jq '.items[] | select(.metadata.name | contains("frontend"))'

# If the attacker created persistence (new ClusterRoleBinding, new pod, etc.):
# Delete the persisted resources.

# Rotate the service account token used by the compromised workload
kubectl delete secret $(kubectl get sa frontend-sa -n citizen-frontend -o jsonpath='{.secrets[0].name}') -n citizen-frontend
# This forces Kubernetes to issue a new token on next API call

# Cordon remains until the node is reimaged or verified clean
```

### 3.5 Recovery (T+30 minutes to T+2 hours)

```bash
# 1. Deploy a clean replica from the last known-good image (signed — Module 4/5)
kubectl scale deployment frontend-deploy -n citizen-frontend --replicas=3
# Verify the image is the signed version:
kubectl get deployment frontend-deploy -n citizen-frontend -o jsonpath='{.spec.template.spec.containers[0].image}'

# 2. Verify the pod comes up healthy
kubectl get pods -n citizen-frontend -l app=frontend-deploy

# 3. Run Trivy scan on the new image (Module 2 pipeline already did this,
# but reconfirm as a sanity check)
trivy image $REGISTRY_URI/frontend-deploy:$LAST_GOOD_TAG --severity CRITICAL

# 4. Uncordon the node only AFTER it has been verified clean
# (ideally: cordon → drain → terminate → new node from hardened launch template)
kubectl drain ip-10-0-1-42.ec2.internal --ignore-daemonsets --delete-emptydir-data
# EKS managed node group will automatically provision a replacement node
kubectl uncordon ip-10-0-1-42.ec2.internal  # only after replacement is ready

# 5. Confirm no remaining IOCs
kubectl get events -n citizen-frontend --field-selector reason=FailedCreate --sort-by='.lastTimestamp'
```

### 3.6 Post-Incident Forensics

Evidence package in S3 is reviewed by the security team within 24 hours:

- **Process tree analysis:** Identify the exploit chain (which binary was executed, how it reached the host)
- **Network connection review:** Did the attacker exfiltrate data or connect to C2?
- **Filesystem diff:** What files were modified on the container filesystem or host?
- **Kubernetes audit log timeline:** What API calls did the attacker make via the compromised pod's service account?

## 4. Incident Communication

### 4.1 During the Incident (Unfolding)

**T+5 min — Initial notification to ITSO-equivalent / programme lead:**

> "We have a P1 security alert indicating potential container escape on the `citizen-frontend` workload in the EKS production cluster. The pod has been network-isolated. No citizen data exposure confirmed at this time. Forensic evidence capture is underway. ETA for eradication: 30 minutes. ETA for full assessment: 24 hours."

**What is said:** What happened, what is confirmed, what is being done, when the next update will come.

**What is NOT said yet:** Root cause (not yet determined), whether data was exfiltrated (forensic analysis not complete), attribution (irrelevant at this stage), whether other workloads are affected (not yet confirmed).

**Cadence:** Update every 30 minutes until eradication is complete, then every 2 hours until the 24-hour assessment is done.

**T+15 min — Broader team notification (Slack `#incidents`, not `#general`):**

> "SECURITY INCIDENT: Container escape detected on citizen-frontend workload. Pod isolated and killed. Service is degraded (3 → 0 replicas during forensic capture, recovery in progress). No public-facing impact confirmed."

### 4.2 Formal Post-Incident Report (within 5 business days)

The report follows a standard structure:

| Section | Content |
|---|---|
| **Executive Summary** | What happened, who was affected, was data compromised, what was done |
| **Timeline** | Minute-by-minute from detection to recovery |
| **Root Cause** | Technical root cause (e.g. privileged container + host filesystem mount allowed escape) |
| **Impact Assessment** | Data exposure analysis, service availability impact, blast radius |
| **Controls That Failed** | Reference Module 1 findings (e.g. "K8S-004: privileged container was not prevented by admission policy") |
| **Controls That Worked** | Falco detection, containment procedure, evidence capture |
| **Recommendations** | Remediation actions with owner and deadline (feed into Module 6) |
| **Lessons Learned** | What the team would do differently |

## 5. Ongoing Detection Maturity

| Phase | Timeframe | Capability |
|---|---|---|
| **Phase 1: Deploy & baseline** | Month 1-2 | Falco DaemonSet deployed, audit-only mode, baseline tuning |
| **Phase 2: Alert routing** | Month 2-3 | P1/P2 alert routing enabled, PagerDuty integration, weekly tuning |
| **Phase 3: Response automation** | Month 3-4 | Automated network isolation via Falco + falcosidekick webhook → Lambda (auto-cordon on P1 escape indicators) |
| **Phase 4: EKS Audit Log enrichment** | Month 4-5 | K8s audit logs correlated with Falco syscall events for full attack chain visibility |
| **Phase 5: Multi-cloud** | Month 5-6 | Falco deployed on AKS/GKE clusters with cloud-specific audit log sources |

## 6. Assumptions

- EKS managed node groups run Amazon Linux 2 or Bottlerocket with eBPF support (EKS 1.25+). Falco's eBPF driver is used rather than the kernel module.
- A dedicated forensic S3 bucket with Object Lock is provisioned by the platform team. This is a one-time infrastructure task.
- The AWS Security Group for Pods approach (Option B in §3.3 Step 2) is available as a fallback for pod network isolation on the current VPC CNI. This requires the security group to be pre-provisioned during landing-zone setup.
- LiME (Linux Memory Extractor) kernel module is NOT assumed pre-installed on nodes. If memory forensics becomes routinely needed, it should be added to the hardened AMI (Module 1, K8S-025).
