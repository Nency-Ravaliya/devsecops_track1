# Remediation Advisory

## Scope

This document provides delivery-facing remediation guidance for the **three most critical findings** from Module 1. These findings were selected because they represent the highest-severity, most immediately exploitable risks in the estate, and all three are directly referenced by the trigger incident (CI service account with cluster-admin).

The guidance is written for engineers without a security background. Each section includes:
1. Plain-language explanation of the risk
2. Step-by-step remediation instructions
3. Evidence required to confirm the fix is complete

---

## K8S-001: `superadmin` ServiceAccount Bound to `cluster-admin`

**Severity:** Critical | **Domain:** RBAC | **Effort:** 4-8 hours

### What is the risk?

The cluster currently has a Kubernetes ServiceAccount called `superadmin` in the `kube-system` namespace. This ServiceAccount is bound to the built-in `cluster-admin` role, which gives it **unrestricted access to everything in the cluster** — all namespaces, all resources, all operations. This includes reading every secret, modifying RBAC rules, and deploying privileged workloads.

**Why this is dangerous:** Any pod that uses this ServiceAccount (or anyone with the token for it) can take complete control of the cluster. This is exactly the same pattern found in the audit incident — a CI job's ServiceAccount had cluster-admin, which could reach across every workload. An attacker who compromises any workload in the cluster can steal the `superadmin` token and escalate to full cluster control.

### How to fix it

**Step 1: Identify who uses this ServiceAccount**

```bash
# Check if any pods currently use the superadmin ServiceAccount
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.serviceAccountName == "superadmin") | {name: .metadata.name, namespace: .metadata.namespace}'
```

If nothing returns, no pods currently use it. If something returns, you must replace that pod's ServiceAccount before proceeding.

**Step 2: Create a new, narrow ServiceAccount with only the permissions the workload actually needs**

Replace the content of `reference-target/scenarios/insecure-rbac/setup.yaml` — the corrected version is in `06-remediation/fixed-manifests/k8s-001-fixed-superadmin.yaml`.

**Step 3: Delete the ClusterRoleBinding**

```bash
kubectl delete clusterrolebinding superadmin
```

**Step 4: Verify no workload lost access it needs**

```bash
# Test that the application can still do what it needs to do
kubectl auth can-i get secrets -n kube-system --as=system:serviceaccount:kube-system:superadmin
# Expected: "no" — this is correct, the SA should NOT have cluster access

# If the workload needs specific access, it should now use the new namespace-scoped Role
kubectl auth can-i get pods -n citizen-frontend --as=system:serviceaccount:citizen-frontend:frontend-sa
# Expected: "yes" (if you set up the new Role correctly)
```

### Evidence of completion

1. **`kubectl get clusterrolebindings` output** showing no `superadmin` binding exists
2. **`kubectl auth can-i --list --as=system:serviceaccount:kube-system:superadmin`** showing no permissions (or "no" for all resources)
3. **Conftest policy test passing:** `conftest test fixed-manifests/k8s-001-fixed-superadmin.yaml --policy platform-policies/policy/k8s-rbac.rego` — exit code 0
4. **Git commit** deleting the binding from the manifest, reviewed and merged

---

## K8S-002/003: Helm `pwnchart` Creates Wildcard ClusterRole Bound to Default SA

**Severity:** Critical | **Domain:** RBAC | **Effort:** 1 day

### What is the risk?

The Helm chart `pwnchart` creates two resources that together give any pod in the `default` namespace full cluster control:

1. A **ClusterRole** called `all-your-base` that grants `*` (everything) on `*` (all resources) with `*` (all verbs) — this is the most powerful role possible
2. A **ClusterRoleBinding** called `belong-to-us` that binds this role to the `default` ServiceAccount in the `default` namespace

**Why this is dangerous:** Kubernetes automatically gives every pod the `default` ServiceAccount if no other ServiceAccount is specified. This means **any pod deployed in the default namespace without an explicit ServiceAccount gets full cluster-admin powers**. A developer who simply deploys a test workload with `kubectl apply -f my-app.yaml` — without specifying a ServiceAccount — gets cluster-wide control they never asked for.

### How to fix it

**Step 1: Delete the deployed resources from the cluster**

```bash
kubectl delete clusterrolebinding belong-to-us
kubectl delete clusterrole all-your-base
```

**Step 2: Remove the chart from your deployable path**

The `pwnchart` Helm chart is located at `reference-target/infrastructure/helm-tiller/pwnchart/`. This chart must NOT be deployed to any cluster. If it is referenced in any pipeline or deployment script, remove the reference.

```bash
# Check if the chart is referenced anywhere in your deployment scripts
grep -r "pwnchart" . --include="*.sh" --include="*.yml" --include="*.yaml"
```

**Step 3: Block this pattern going forward**

The pipeline Conftest policy (`platform-policies/policy/k8s-rbac.rego`) already blocks ClusterRoleBindings with wildcard ClusterRoles and blocks default ServiceAccount in binding subjects (Module 2). Verify it catches this pattern:

```bash
conftest test reference-target/infrastructure/helm-tiller/pwnchart/templates/ \
  --policy platform-policies/policy/k8s-rbac.rego
# Expected: CRITICAL policy violations reported, pipeline would block merge
```

### Evidence of completion

1. **`kubectl get clusterroles all-your-base`** returns `Error from server (NotFound)`
2. **`kubectl get clusterrolebindings belong-to-us`** returns `Error from server (NotFound)`
3. **Conftest test passing** on the chart templates (showing the pipeline would now block deployment)
4. **Git commit** removing or disabling the chart, reviewed and merged

---

## K8S-004: `system-monitor` Privileged Container with Host Root Mount

**Severity:** Critical | **Domain:** Pod Security / Node Hardening | **Effort:** 1-2 days

### What is the risk?

The `system-monitor` Deployment runs a container with three overlapping dangerous settings:
- **`privileged: true`** — the container has full access to all host devices and kernel capabilities
- **`hostPID: true`** — the container can see every process running on the node, including other containers
- **`hostPath: /` mounted read-write** — the container can read and write any file on the host filesystem

Together, these three settings mean a compromised `system-monitor` container can modify the host operating system, access other containers' data, and effectively own the node. On EKS managed nodes, this can expose kubelet credentials and affect every workload on the node.

### How to fix it

The `system-monitor` workload was designed for a security scanning/training scenario. In production, the remediation approach depends on what the workload actually needs:

**Option A: Replace with managed tooling (recommended)**

If `system-monitor` is being used for node-level metrics, replace it with:
- **Amazon CloudWatch Agent** DaemonSet for OS metrics
- **kube-state-metrics** for Kubernetes object metrics
- **Falco** (Module 3) for runtime security monitoring

These tools run with minimal privileges and do not need host root access.

**Option B: If the workload is required, tighten its security context**

The corrected manifest is in `06-remediation/fixed-manifests/k8s-004-fixed-system-monitor.yaml`. Key changes:
- Remove `hostPID`, `hostIPC`, `hostNetwork`
- Remove the host root filesystem mount
- Set `privileged: false` and `allowPrivilegeEscalation: false`
- Set `runAsNonRoot: true` with `runAsUser: 65534` (nobody)
- Add `seccompProfile: RuntimeDefault`
- Drop all capabilities

### Evidence of completion

1. **`kubectl get deployment system-monitor -n default -o jsonpath='{.spec.template.spec.containers[0].securityContext}'`** showing `privileged: false`, no hostPID/hostIPC, no hostPath
2. **Conftest policy test passing:** `conftest test 06-remediation/fixed-manifests/k8s-004-fixed-system-monitor.yaml --policy platform-policies/policy/k8s-podsec.rego` — exit code 0
3. **Trivy image scan** of the replacement image showing zero Critical findings
4. **Falco (Module 3)** deployment confirmed as the runtime detection replacement, with the `Container Privileged Mode` rule configured to alert on any future privileged pod creation
