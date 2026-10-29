# Module 08: Kubernetes Security ☸️🔐

## 📌 Overview

Kubernetes runs the containers you secured in Module 07. It decides **who may do what**, **which pods may start**, **which pods may talk to each other**, and **where secrets live**. It is powerful, and its defaults are designed for **ease of use**, not for hostile environments.

A cluster with default settings usually lets any pod talk to any other pod, lets many workloads run as root, hands every pod an API token, and stores secrets with only base64 encoding. This module teaches you to close those gaps layer by layer.

> [!NOTE]
> This module builds on the earlier ones. Module 02 taught Linux permissions and capabilities, which Kubernetes `securityContext` settings control. Module 07 taught image scanning and signing, which Kubernetes policies can **enforce**. Module 03 taught that secrets do not belong in Git, and here you learn where they **should** live in a cluster.

> [!IMPORTANT]
> **Lab environment:** You need **Docker**, **kubectl**, and **minikube** (or another disposable local cluster) with **at least 4 GB of free RAM**. All labs run on a **local throwaway cluster** that you delete at the end. Never practise these steps on a production cluster.

## 🎯 Learning Objectives

By the end of this module, you will be able to:

- Explain the Kubernetes architecture, its API request flow, and its main attack surfaces.
- Design least-privilege access with **RBAC** and audit it for dangerous permissions.
- Secure **service accounts** and understand **workload identity**.
- Enforce **Pod Security Standards** with **Pod Security Admission**.
- Control pod-to-pod traffic with **Network Policies**.
- Protect **Kubernetes Secrets** and know their limits.
- Understand where **Kyverno** (policy management) and **KubeArmor** (runtime security) fit.
- Audit and harden a cluster using benchmarks, audit logs, and scanning tools.
- Build and test a secured cluster in a hands-on lab.

## 📚 Table of Contents

1. [Kubernetes Security Fundamentals](#1-kubernetes-security-fundamentals)
2. [Kubernetes RBAC](#2-kubernetes-rbac)
3. [Service Accounts & Workload Identity](#3-service-accounts--workload-identity)
4. [Pod Security Standards & Pod Security Admission](#4-pod-security-standards--pod-security-admission)
5. [Kubernetes Network Policies](#5-kubernetes-network-policies)
6. [Kubernetes Secrets Security](#6-kubernetes-secrets-security)
7. [Kyverno – Kubernetes Policy Management](#7-kyverno--kubernetes-policy-management)
8. [Runtime Security with KubeArmor](#8-runtime-security-with-kubearmor)
9. [Kubernetes Security Auditing & Hardening](#9-kubernetes-security-auditing--hardening)
10. [Hands-on Kubernetes Security Lab](#10-hands-on-kubernetes-security-lab)

---

## 1. Kubernetes Security Fundamentals

### What Is Kubernetes?

**Kubernetes** (often written **K8s**) is a system that runs and manages containers across many machines. You tell it **what you want** (for example, "run 3 copies of this image"), and it keeps reality matching that description.

| Term | Meaning |
| :--- | :--- |
| **Cluster** | A set of machines managed together by Kubernetes. |
| **Node** | One machine (physical or virtual) in the cluster that runs pods. |
| **Pod** | The smallest unit: one or more containers sharing a network identity and storage. |
| **Namespace** | A named partition of the cluster for grouping and permissions. |
| **Deployment** | A controller that keeps a set of identical pods running. |
| **Service** | A stable network address in front of a set of pods. |
| **Manifest** | A YAML file describing resources you want. |
| **kubectl** | The command-line tool that talks to the cluster's API. |

### Architecture: The Pieces You Must Protect

```text
                     CONTROL PLANE (the "brain")                          WORKER NODES (run the pods)
 +-----------------------------------------------------------+    +----------------------------------------+
 |                                                           |    |                                        |
 |   +----------------+       +--------------------------+   |    |   +-------------+   +--------------+   |
 |   |   etcd         | <---> |   kube-apiserver         |<--+----+---|  kubelet    |   |  kube-proxy  |   |
 |   | (the database: |       |  THE front door: every   |   |    |   | (node agent)|   | (networking) |   |
 |   |  ALL cluster   |       |  request goes through it |   |    |   +------+------+   +--------------+   |
 |   |  state and     |       +------------+-------------+   |    |          |                              |
 |   |  Secrets)      |                    |                 |    |   +------v--------------------------+   |
 |   +----------------+       +------------v-------------+   |    |   |  Container runtime               |   |
 |                            | scheduler | controllers  |   |    |   |  (containerd / CRI-O)            |   |
 |                            +--------------------------+   |    |   |   [pod] [pod] [pod] ...          |   |
 +-----------------------------------------------------------+    +----------------------------------------+
        ^
        |   kubectl, CI/CD pipelines, operators, users, pods calling the API
```

| Component | What It Does | Why Attackers Want It |
| :--- | :--- | :--- |
| **kube-apiserver** | The **only** door to the cluster's state. Handles authentication, authorization, and admission. | Control of the API means control of the cluster. |
| **etcd** | Stores **all** cluster data, including Secrets. | Reading etcd reveals every secret. Writing it rewrites reality. |
| **kubelet** | The agent on each node that starts pods. Has its own API. | An open kubelet API can run commands in pods and on nodes. |
| **Container runtime** | Actually runs containers (Module 07). | A runtime flaw can allow a container escape. |
| **Scheduler and controllers** | Decide where pods run and keep desired state. | Compromise lets an attacker place workloads where they want. |
| **Nodes (Linux hosts)** | The machines (Module 02). | Root on a node exposes every pod on it. |

### Every Request Passes Four Gates

When anything talks to the API server (a person, a pipeline, a pod), the request passes through a fixed pipeline. **Each stage is a place to enforce security.**

```text
   REQUEST  (for example: "create this pod")
      |
      v
 +-----------------+
 | 1. AUTHENTICATION|  WHO are you?        certificates, OIDC tokens, service account tokens
 +--------+--------+                        (anonymous requests should be refused)
          |
          v
 +-----------------+
 | 2. AUTHORIZATION |  WHAT may you do?    RBAC (Role-Based Access Control)  <-- Section 2
 +--------+--------+
          |
          v
 +-----------------+
 | 3. ADMISSION     |  Is the REQUEST ACCEPTABLE?   mutating, then validating checks
 |    CONTROL       |  Pod Security Admission (Section 4), Kyverno (Section 7),
 +--------+--------+  ValidatingAdmissionPolicy, image checks ...
          |
          v
 +-----------------+
 | 4. PERSIST       |  Saved in etcd; controllers and kubelets act on it
 +-----------------+
```

> **Analogy:** A secure building. **Authentication** is showing your ID at the entrance. **Authorization** is the badge that opens only certain doors. **Admission control** is the inspector who checks what you are bringing in. Only then are you allowed inside.

### The 4C Model of Cloud-Native Security

Security is built in **layers**, and each outer layer protects the inner ones. An inner layer cannot make up for a broken outer layer.

```text
 +--------------------------------------------------------------+
 |  CLOUD  (account, network, IAM, VMs, data centre)            |
 |  +--------------------------------------------------------+  |
 |  |  CLUSTER  (API server, RBAC, etcd, nodes, policies)    |  |
 |  |  +--------------------------------------------------+  |  |
 |  |  |  CONTAINER  (image, runtime, securityContext)    |  |  |
 |  |  |  +--------------------------------------------+  |  |  |
 |  |  |  |  CODE  (your application and dependencies) |  |  |  |
 |  |  |  +--------------------------------------------+  |  |  |
 |  |  +--------------------------------------------------+  |  |
 |  +--------------------------------------------------------+  |
 +--------------------------------------------------------------+
```

| Layer | Examples | Where You Learned It |
| :--- | :--- | :--- |
| **Code** | Secure coding, dependencies | Modules 04 and 05 |
| **Container** | Minimal images, scanning, signing, runtime flags | Module 07 |
| **Cluster** | RBAC, admission, network policies, secrets, hardening | **This module** |
| **Cloud / infrastructure** | IAM, VPC, node OS hardening | Modules 02 and 09 |

### Shared Responsibility in Managed Kubernetes

If you use **EKS, AKS, or GKE**, the provider operates the control plane, but **you** still own most of the security that matters.

| | **Provider (managed)** | **You** |
| :--- | :--- | :--- |
| Control plane (API server, etcd) availability and patching | ✅ | |
| Control plane hardening basics | ✅ (mostly) | Choose settings such as private endpoints |
| **RBAC and who has access** | | ✅ |
| **Pod security, network policies, secrets** | | ✅ |
| **Worker node patching** (varies by service) | Partly | Often you |
| **Images, workloads, application code** | | ✅ |
| **Cloud IAM, networking, logging** | | ✅ |

### Common Misconfigurations (And the Attack They Allow)

| Misconfiguration | What an Attacker Can Do | Section |
| :--- | :--- | :---: |
| API server or dashboard exposed to the internet with weak auth | Take over the cluster | 9 |
| **Anonymous access** enabled | Query the API without credentials | 9 |
| Everyone is `cluster-admin` | One stolen token means full control | 2 |
| Pods use the **default service account** with powerful roles | Compromised pod becomes cluster admin | 3 |
| Privileged pods, `hostPath` mounts, `hostNetwork` | Escape to the node | 4 |
| No network policies | Free lateral movement between pods | 5 |
| Secrets in plain environment variables or Git | Credential theft | 6 |
| Exposed kubelet API | Run commands in containers | 9 |
| Unpatched Kubernetes version | Known exploits | 9 |
| No audit logging | You cannot investigate anything | 9 |
| Cloud metadata service reachable from pods | Steal the node's cloud credentials | 5 |

### A Typical Attack Path

Understanding how attackers chain mistakes shows why **layers** matter:

```text
 1. Vulnerable app in a pod              (Module 04/05: a code or library flaw)
        |
        v
 2. Attacker gets a shell in the pod      (running as root? has a shell and curl?)
        |
        v
 3. Reads the service account token       (/var/run/secrets/kubernetes.io/serviceaccount/token)
        |
        v
 4. Calls the API with that token         (too many permissions? can list secrets / create pods?)
        |
        v
 5. Creates a privileged pod on a node    (nothing stops it: no admission policy)
        |
        v
 6. Escapes to the node and moves sideways (no network policy, no runtime detection)
```

**Every step has a control in this module:** minimal images and non-root users (Module 07), automounting disabled and least-privilege RBAC (sections 2 and 3), admission policies (sections 4 and 7), network policies (section 5), and runtime detection (section 8).

### Security Frameworks and Guidance

| Resource | Use |
| :--- | :--- |
| **CIS Kubernetes Benchmark** | A detailed checklist for hardening clusters (section 9). |
| **NSA/CISA Kubernetes Hardening Guide** | Government guidance covering pods, network, authentication, auditing, and upgrades. |
| **OWASP Kubernetes Top Ten** | The most common Kubernetes risks, in awareness-list form. |
| **MITRE ATT&CK for Containers** | A catalog of attacker techniques, useful for threat modeling and detection. |
| **NIST SP 800-190** | Container security guidance. |

### Keep Kubernetes Updated

Kubernetes releases a new minor version roughly **every four months**, and the project supports only the **three most recent** minor versions with security fixes. Running an unsupported version means **no security patches**. Plan regular upgrades, and subscribe to the project's security announcements.

---

## 2. Kubernetes RBAC

### What Is RBAC?

**RBAC (Role-Based Access Control)** is Kubernetes' authorization system. It answers: *"Is this identity allowed to perform this action on this resource?"*

```text
        WHO                      CAN DO WHAT                  WHERE
   (subject)                (verbs on resources)           (scope)

   a user, a group,         get, list, watch,              one namespace
   or a service account     create, update, delete ...     or the whole cluster
        |                           |                          |
        +--- RoleBinding / ClusterRoleBinding links them ------+
```

### The Four RBAC Objects

| Object | Scope | Purpose |
| :--- | :--- | :--- |
| **Role** | One **namespace** | A list of permissions inside that namespace. |
| **ClusterRole** | The whole **cluster** | Permissions for cluster-wide resources (nodes, namespaces), or reusable permission sets. |
| **RoleBinding** | One namespace | Gives a Role (or ClusterRole) to subjects **within that namespace**. |
| **ClusterRoleBinding** | The whole cluster | Gives a ClusterRole to subjects **everywhere**. |

```text
 Role  +  RoleBinding         =  permissions in ONE namespace
 ClusterRole + RoleBinding    =  a reusable set of permissions, applied in ONE namespace
 ClusterRole + ClusterRoleBinding = permissions across the ENTIRE cluster  (use sparingly!)
```

### Subjects: Who Can Be Granted Access

| Subject | Meaning |
| :--- | :--- |
| **User** | A human identity. Kubernetes has **no user objects**: users come from certificates, OIDC providers, or your cloud's authentication. |
| **Group** | A set of users (for example, from your identity provider). Binding to groups is easier to manage than binding to people. |
| **ServiceAccount** | An identity for **workloads running in pods** (section 3). |

### A Role and a RoleBinding

```yaml
# Allow reading pods and their logs in the "dev" namespace, and nothing else
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: dev
rules:
  - apiGroups: [""]                 # "" means the core API group
    resources: ["pods", "pods/log"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: dev
subjects:
  - kind: ServiceAccount
    name: dev-sa
    namespace: dev
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

| Field | Meaning |
| :--- | :--- |
| `apiGroups` | Which API group the resource belongs to (`""` for pods and secrets, `apps` for deployments). |
| `resources` | What the rule applies to. Subresources look like `pods/exec` and `pods/log`. |
| `verbs` | The actions: `get`, `list`, `watch`, `create`, `update`, `patch`, `delete`, `deletecollection`. |
| `resourceNames` | (Optional) Limit the rule to specific object names. |
| `roleRef` | The role being granted. **It cannot be changed** after the binding is created. |

The same with `kubectl` shortcuts:

```bash
kubectl create role pod-reader --verb=get,list,watch --resource=pods,pods/log -n dev
kubectl create rolebinding read-pods --role=pod-reader --serviceaccount=dev:dev-sa -n dev
```

### Built-In Roles You Should Know

| ClusterRole | Permissions | Notes |
| :--- | :--- | :--- |
| `view` | Read most namespaced resources, **not Secrets** | Safe default for read access |
| `edit` | Read and write most namespaced resources, **including Secrets** | Powerful. Can read secrets and run pods. |
| `admin` | `edit`, plus manage RBAC within a namespace | A namespace owner |
| `cluster-admin` | **Everything, everywhere** | The "root" of Kubernetes. Almost nobody needs it permanently. |

> [!WARNING]
> Members of the group **`system:masters`** bypass RBAC entirely, and cannot be restricted by it. Never create credentials in that group for everyday use.

### Least Privilege in RBAC

```text
 BAD   verbs: ["*"]   resources: ["*"]   (a ClusterRoleBinding to a normal user or pipeline)
 GOOD  verbs: ["get","list"]   resources: ["pods"]   (a Role in one namespace, bound to one identity)
```

| Practice | Why |
| :--- | :--- |
| Prefer **Role + RoleBinding** over cluster-wide bindings | Limits blast radius to one namespace. |
| **Never use wildcards** (`*`) for verbs, resources, or API groups | They grant things you did not intend, including future resources. |
| Bind to **groups** from your identity provider | Joiners and leavers are managed in one place. |
| Give **each workload its own service account** | A compromise affects only what it can do. |
| Use `resourceNames` where possible | Restrict to specific objects. |
| Grant **temporary** elevated access, and remove it | Standing admin access is a liability. |
| **Review bindings regularly** | Permissions only ever grow unless you prune them. |
| Keep `cluster-admin` bindings to a tiny, audited list | Highest risk. |

### Dangerous Permissions: Quiet Paths to Cluster Admin

Some permissions look harmless but let an identity **escalate** its own access.

| Permission | Why It Is Dangerous |
| :--- | :--- |
| `get` / `list` / `watch` on **`secrets`** | `list` returns the **contents** of every secret in scope, including tokens and credentials. |
| `create` on **`pods`** | A new pod can mount any secret or service account in the namespace, or run as privileged (unless admission blocks it). |
| **`pods/exec`** | Run commands inside any pod. Access to everything the pod can reach. |
| `create` on **`serviceaccounts/token`** | Mint tokens for other service accounts. |
| **`impersonate`** | Act as any user, group, or service account. |
| **`escalate`** and **`bind`** on roles | Grant permissions you do not have yourself. |
| `create` or `update` on **`rolebindings` / `clusterrolebindings`** | Give yourself more access. |
| `*` on `*` | Everything. |
| **`nodes/proxy`** | Reach the kubelet API and, through it, run commands in pods. |
| `update` on **`deployments`**, `daemonsets`, `cronjobs` | Change what code runs, including with more privileges. |
| `patch` on **`validatingwebhookconfigurations`** or policies | Turn off admission controls. |

> **Key idea:** "can create pods" is close to "can do almost anything in that namespace" unless **admission policies** (sections 4 and 7) restrict what those pods may do.

### Checking and Auditing Permissions

```bash
# Can I create deployments in the dev namespace?
kubectl auth can-i create deployments -n dev

# Can the service account "dev-sa" list secrets in dev?
kubectl auth can-i list secrets -n dev --as=system:serviceaccount:dev:dev-sa

# Everything an identity can do in a namespace
kubectl auth can-i --list -n dev --as=system:serviceaccount:dev:dev-sa

# Who has cluster-admin?
kubectl get clusterrolebindings -o json | jq -r \
  '.items[] | select(.roleRef.name=="cluster-admin") |
   "\(.metadata.name): \([.subjects[]? | "\(.kind)/\(.name)"] | join(", "))"'

# Roles that use wildcards (candidates for tightening)
kubectl get roles,clusterroles -A -o json | jq -r \
  '.items[] | select(.rules[]? | (.verbs[]? == "*") or (.resources[]? == "*")) |
   "\(.kind)/\(.metadata.name)"' | sort -u

# Who can read secrets? (needs the "who-can" kubectl plugin, see below)
kubectl who-can get secrets -n production
```

| Tool | What It Does |
| :--- | :--- |
| `kubectl auth can-i` | Built-in permission checks. |
| `kubectl-who-can` | Shows **who** is allowed to perform an action. |
| `rakkess` | Prints an access matrix of what an identity can do. |
| `rbac-tool` | Visualizes and analyzes RBAC. |
| `KubiScan` | Finds risky permissions. |
| **Trivy**, **Kubescape**, **kube-bench** | Include RBAC-related checks (section 9). |

### RBAC Pitfalls

| Pitfall | Fix |
| :--- | :--- |
| Binding `cluster-admin` to a CI pipeline "to make it work" | Create a narrow Role for exactly what the pipeline deploys. |
| Granting permissions to `system:authenticated` or `system:unauthenticated` | Never do this broadly. It gives access to all users, or to anonymous ones. |
| Forgetting that **RBAC only adds permissions** | There is no "deny" rule. To restrict, you must **not grant**. |
| Copying example manifests with `*` | Always read and reduce them. |
| Leaving old bindings after people or projects leave | Review and prune. |
| Giving developers the `edit` role on production | They can read every secret and run pods. Use `view` for most people. |

---

## 3. Service Accounts & Workload Identity

### What Is a Service Account?

A **ServiceAccount** is an identity for **software** (a pod) rather than a person. When a pod calls the Kubernetes API (or another system), it proves who it is with a **service account token**.

```text
 Pod  --(token)-->  API server  --> "This is dev:dev-sa"  --> RBAC decides what it may do
```

Every namespace has a **`default`** service account, and **any pod that does not name a service account uses it**.

### How a Token Gets Into a Pod

By default, Kubernetes **automatically mounts a token** into every pod:

```text
 /var/run/secrets/kubernetes.io/serviceaccount/
      |-- token        <-- a JWT: the credential
      |-- ca.crt       <-- the cluster CA, to trust the API server
      '-- namespace    <-- the pod's namespace
```

**Anyone who gets a shell in the pod can read that token** and call the API with the same permissions as the pod. This is step 3 of the attack path in section 1.

### Modern Tokens vs. Legacy Tokens

| | **Bound (projected) tokens** (modern) | **Legacy secret-based tokens** (old) |
| :--- | :--- | :--- |
| **Lifetime** | **Short-lived** (about one hour by default) and refreshed automatically | **Never expire** |
| **Bound to** | The specific **pod** (invalid when the pod is deleted) and an audience | Nothing: valid until the secret is deleted |
| **Created automatically?** | Yes, for pods | **Not any more** (automatic creation was removed in Kubernetes 1.24) |
| **Risk if stolen** | Limited window | Permanent access |

> [!WARNING]
> Old clusters and some tools still create **long-lived token Secrets** (`kubernetes.io/service-account-token`). Find them and remove them. Prefer short-lived tokens obtained with the TokenRequest API (`kubectl create token <sa>`).

### Service Account Best Practices

| Practice | Why |
| :--- | :--- |
| **Do not use the `default` service account** for workloads | Give each application its own identity. |
| **One service account per workload** | Compromise of one app does not give access to another's permissions. |
| **Grant the minimum RBAC permissions** (often **none**) | Most applications never call the Kubernetes API. |
| **Disable token automounting** unless the pod calls the API | Nothing to steal. |
| Use **short-lived tokens** | Reduces the value of a stolen token. |
| Never put tokens in images, Git, or configuration | Treat them as secrets. |
| Remove unused service accounts | Fewer identities to monitor. |
| **Audit** which service accounts hold powerful roles | The most common path to cluster admin. |

### Disable Automounting

On the service account (applies to all pods that use it):

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: web-app
  namespace: production
automountServiceAccountToken: false
```

Or per pod (the pod setting wins):

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: web
  namespace: production
spec:
  serviceAccountName: web-app
  automountServiceAccountToken: false      # this pod gets NO API token
  containers:
    - name: web
      image: nginxinc/nginx-unprivileged:stable
```

If a pod **does** need the API, mount a token deliberately and limit its **audience** and **lifetime**:

```yaml
spec:
  serviceAccountName: reporter
  automountServiceAccountToken: false
  containers:
    - name: app
      image: my-org/reporter@sha256:...
      volumeMounts:
        - name: api-token
          mountPath: /var/run/secrets/tokens
          readOnly: true
  volumes:
    - name: api-token
      projected:
        sources:
          - serviceAccountToken:
              path: token
              audience: my-service       # the token is only valid for this audience
              expirationSeconds: 3600
```

### Abuse of Service Account Tokens (What You Defend Against)

From inside a compromised pod, an attacker can use the token like this:

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
     -H "Authorization: Bearer $TOKEN" \
     https://kubernetes.default.svc/api/v1/namespaces/default/pods
```

- With **no permissions** (a minimal service account): the API answers **403 Forbidden**. The token is useless.
- With **excess permissions**: the attacker lists secrets, creates pods, or worse.

You will try exactly this in the lab.

### Workload Identity: Giving Pods Access to Cloud Services Safely

Many pods must call **cloud APIs** (read from S3, use a key vault). The wrong way is a **long-lived cloud access key** stored in a Kubernetes Secret. The right way is **workload identity**: the pod proves who it is with its Kubernetes token, and the cloud provider **exchanges it for short-lived cloud credentials**.

```text
 WRONG                                              RIGHT (workload identity)

 Pod  --reads-->  Secret holding a                  Pod --(short-lived K8s token)--> Cloud IAM
                  long-lived AWS access key                  trusts the cluster's OIDC identity
       (stolen once = stolen forever)                         |
                                                              v
                                                    short-lived cloud credentials for ONE role
```

| Platform | Mechanism | Idea |
| :--- | :--- | :--- |
| **AWS EKS** | **IRSA** (IAM Roles for Service Accounts) or **EKS Pod Identity** | Annotate a service account with an IAM role. The pod receives temporary credentials for it. |
| **Google GKE** | **Workload Identity Federation for GKE** | Map a Kubernetes service account to a Google service account or principal. |
| **Azure AKS** | **Microsoft Entra Workload ID** | Federate a service account with an Entra identity. |
| **Any platform** | **SPIFFE/SPIRE** | Issues cryptographic identities to workloads for service-to-service authentication. |

Example (EKS IRSA): the service account is annotated with the role it may assume.

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: uploader
  namespace: production
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::111122223333:role/uploader-s3-write
```

On the AWS side, the role's **trust policy** names exactly this cluster, namespace, and service account. The role itself grants only the specific actions needed (for example, writing to **one** bucket).

| Workload Identity Practice | Why |
| :--- | :--- |
| One cloud role **per workload** with minimal permissions | A compromised pod gets only that role. |
| Restrict the trust policy to **one namespace and service account** | Prevents other pods assuming the role. |
| **Never** store cloud keys in Secrets or environment variables | Nothing long-lived to steal. |
| Block pod access to the **cloud metadata service** (section 5) | Stops pods stealing the **node's** credentials. |

> [!NOTE]
> This is the same principle as **OIDC for CI/CD** (Modules 03 and 10): replace stored long-lived credentials with **short-lived, identity-based** ones.

---

## 4. Pod Security Standards & Pod Security Admission

### The Problem

Without restrictions, a user who can create pods can request settings that give the pod **almost the whole node**:

```yaml
securityContext:
  privileged: true        # nearly all isolation removed
hostNetwork: true         # share the node's network
hostPID: true             # see all node processes
volumes:
  - hostPath: { path: / } # mount the entire node filesystem
```

These are the same dangerous flags you met in Module 07 (`--privileged`, `--pid=host`, `-v /:/host`). Kubernetes needs a way to **forbid them cluster-wide**.

### Pod Security Standards (PSS): Three Policy Levels

The **Pod Security Standards** define **three levels**, from permissive to strict.

| Level | Meaning | Use For |
| :--- | :--- | :--- |
| **Privileged** | **No restrictions** | Trusted system components (CNI, storage drivers, monitoring agents) |
| **Baseline** | Blocks the **known dangerous escalations**, but stays easy to adopt | A minimum for **all** workloads |
| **Restricted** | Follows **current hardening best practice** | Ordinary application workloads. **The goal.** |

**What Baseline forbids (selection):**

| Forbidden | Why |
| :--- | :--- |
| `privileged: true` | Removes isolation |
| `hostNetwork`, `hostPID`, `hostIPC` | Shares host namespaces |
| `hostPath` volumes | Exposes node files |
| `hostPort` | Binds to node ports |
| Adding dangerous capabilities (beyond a small default list) | Extra root powers |
| Unsafe `sysctl` settings and custom `procMount` | Kernel-level risk |
| Custom AppArmor or SELinux options that weaken defaults | Disables mandatory access control |

**What Restricted adds on top of Baseline:**

| Required for Restricted | Meaning |
| :--- | :--- |
| `runAsNonRoot: true` | Containers must not run as root |
| Not running as UID 0 | Same goal, enforced |
| `allowPrivilegeEscalation: false` | Block gaining privileges (for example via SUID, Module 02) |
| Drop **ALL** capabilities (only `NET_BIND_SERVICE` may be added back) | Module 02 and 07 capabilities lesson |
| `seccompProfile` set to `RuntimeDefault` (or `Localhost`) | Syscall filtering on |
| Only safe **volume types** (configMap, secret, emptyDir, projected, persistentVolumeClaim, and similar) | No host access |

### Pod Security Admission (PSA): The Enforcement Mechanism

**Pod Security Admission** is the **built-in admission controller** that applies the standards. It has been enabled by default since Kubernetes 1.25, where it replaced the removed PodSecurityPolicy. You configure it with **labels on a namespace**.

**Three modes** (you can use more than one at the same time):

| Mode | What Happens When a Pod Violates the Level |
| :--- | :--- |
| **`enforce`** | The pod is **rejected**. |
| **`audit`** | The pod is allowed, and a **violation is recorded** in the audit log. |
| **`warn`** | The pod is allowed, and the user sees a **warning** message. |

```bash
# Enforce "restricted" for everything created in the namespace "production"
kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest

# Also warn and audit at "restricted", useful while migrating
kubectl label namespace production \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted
```

The same as YAML:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
```

What a rejected pod looks like:

```text
Error from server (Forbidden): error when creating "bad-pod.yaml":
pods "bad" is forbidden: violates PodSecurity "restricted:latest":
  privileged (container "app" must not set securityContext.privileged=true),
  allowPrivilegeEscalation != false (...), unrestricted capabilities (...),
  runAsNonRoot != true (...), seccompProfile (...)
```

### A Pod That Passes `restricted`

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  namespace: production
spec:
  automountServiceAccountToken: false
  securityContext:                       # pod-level settings
    runAsNonRoot: true
    runAsUser: 101
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: web
      image: nginxinc/nginx-unprivileged:stable      # pin by digest in production
      ports:
        - containerPort: 8080
      securityContext:                   # container-level settings
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
      resources:
        requests: { cpu: "50m", memory: "64Mi" }
        limits:   { cpu: "250m", memory: "128Mi" }
```

Compare with Module 07's `docker run` flags:

| Docker Flag | Kubernetes `securityContext` |
| :--- | :--- |
| `--user 10001` | `runAsUser`, `runAsNonRoot: true` |
| `--cap-drop ALL` | `capabilities: { drop: ["ALL"] }` |
| `--security-opt no-new-privileges` | `allowPrivilegeEscalation: false` |
| default seccomp | `seccompProfile: { type: RuntimeDefault }` |
| `--read-only` | `readOnlyRootFilesystem: true` (extra hardening, not required by `restricted`) |
| `--memory`, `--cpus` | `resources.limits` |

> [!TIP]
> Adding `readOnlyRootFilesystem: true` is a strong extra control. Applications that write files need a writable `emptyDir` volume for those paths (for example `/tmp`).

### Rolling Out PSA Safely

Turning on `enforce` for a namespace that already has pods can **break deployments**. Use this order:

```text
 1. Preview     kubectl label --dry-run=server --overwrite ns <name> pod-security.kubernetes.io/enforce=restricted
                (the API lists existing pods that WOULD violate the level, without changing anything)
 2. Warn + audit  turn on warn= and audit= first. Developers see warnings; nothing is blocked.
 3. Fix           update workloads until the warnings stop
 4. Enforce       turn on enforce= once the namespace is clean
```

### Cluster-Wide Defaults and Exemptions

Cluster administrators can set **default levels** and **exemptions** (for example for system namespaces) through the API server's `AdmissionConfiguration`.

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
  - name: PodSecurity
    configuration:
      apiVersion: pod-security.admission.config.k8s.io/v1
      kind: PodSecurityConfiguration
      defaults:
        enforce: baseline
        enforce-version: latest
        audit: restricted
        warn: restricted
      exemptions:
        usernames: []
        runtimeClasses: []
        namespaces: ["kube-system"]
```

> [!WARNING]
> Keep exemptions **minimal**. Every exempted namespace or user is a place where dangerous pods are allowed.

### Limits of Pod Security Admission

| Limit | What To Use Alongside It |
| :--- | :--- |
| Only **three built-in levels**. You cannot customize rules. | A policy engine such as **Kyverno** (section 7), or the built-in **ValidatingAdmissionPolicy** (CEL-based, generally available since Kubernetes 1.30). |
| Applies **per namespace**, to **pods only** | Policies that also cover other resources. |
| Cannot check **images** (signed, from the right registry, by digest) | Kyverno image verification (Module 07 link). |
| Cannot **mutate** (add default settings automatically) | Kyverno mutation. |
| Cannot require labels, resource limits, or naming rules | Kyverno or ValidatingAdmissionPolicy. |

---

## 5. Kubernetes Network Policies

### The Default Is "Everything Can Talk to Everything"

In a default cluster, **every pod can reach every other pod** in every namespace, and can usually reach the internet and the node's metadata service.

```text
 DEFAULT (no policies)                             WITH NETWORK POLICIES

   [frontend] <----> [backend] <----> [database]     [frontend] ---> [backend] ---> [database]
        ^  \            ^   \            ^
        |   \___________|____\___________/           Only the arrows you ALLOW exist.
   [any other pod, any namespace, an attacker's pod]  An attacker's pod reaches nothing.
   ...can reach ALL of them
```

> **Analogy:** The default is an office where **every door is unlocked**. Network policies add locks, and give keys only to the people who need each room.

### What a NetworkPolicy Is

A **NetworkPolicy** is a **namespaced** object that says which traffic is **allowed** to or from a **selected group of pods**.

### Four Rules You Must Remember

| # | Rule | Consequence |
| :---: | :--- | :--- |
| 1 | **A CNI plugin that enforces policies is required** (Calico, Cilium, Antrea, and others). | On a CNI that does not enforce them, the objects are accepted and **silently do nothing**. **Always test.** |
| 2 | Pods are **open by default**. A pod becomes restricted when **at least one policy selects it**. | A pod no policy selects is wide open. |
| 3 | Policies are **additive**: allowed traffic is the **union** of all policies selecting a pod. | There is **no deny rule**. You restrict by *not allowing*. |
| 4 | Policies are **namespaced**, and select pods by **labels**. | Each namespace needs its own policies. |

### Step 1: Default Deny (Always Start Here)

Select **every pod** in the namespace, with **no allow rules**, so all traffic is blocked:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: prod
spec:
  podSelector: {}           # an empty selector means ALL pods in this namespace
  policyTypes:
    - Ingress               # block all incoming traffic
    - Egress                # block all outgoing traffic
```

### Step 2: Allow Only What Is Needed

**Allow the frontend to reach the backend on port 8080:**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: prod
spec:
  podSelector:
    matchLabels:
      app: backend              # this policy protects the backend pods
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend     # ...and allows traffic from frontend pods only
      ports:
        - protocol: TCP
          port: 8080
```

**Allow pods to look up DNS** (after a default-deny egress, nothing resolves names):

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: prod
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

**Allow the backend to reach the database:**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-to-db
  namespace: prod
spec:
  podSelector:
    matchLabels:
      app: db
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: backend
      ports:
        - protocol: TCP
          port: 5432
```

(Remember that for the backend to **send** traffic you also need an **egress** allow if you denied egress by default.)

### The Selector Trap: AND vs. OR

This is the most common mistake. Look closely at the dashes:

```yaml
# OR: allow from ANY pod in namespaces labelled team=a  OR  from pods labelled role=client (in THIS namespace)
ingress:
  - from:
      - namespaceSelector:
          matchLabels: { team: a }
      - podSelector:
          matchLabels: { role: client }

# AND: allow only from pods labelled role=client THAT ARE IN namespaces labelled team=a
ingress:
  - from:
      - namespaceSelector:
          matchLabels: { team: a }
        podSelector:
          matchLabels: { role: client }
```

> [!WARNING]
> **One missing dash changes OR into AND**, or the reverse. Read each policy carefully, and **test it**.

### Other Selectors

| Selector | Meaning |
| :--- | :--- |
| `podSelector` | Pods in the **same namespace** matching labels (or, combined with `namespaceSelector`, in other namespaces). |
| `namespaceSelector` | **All pods** in namespaces matching labels. |
| `ipBlock` | An IP range (CIDR), for traffic to or from **outside** the cluster. |

### Blocking the Cloud Metadata Service

Cloud providers expose a **metadata service** at `169.254.169.254` that can hand out the node's credentials. A compromised pod that can reach it can steal them. Allow normal outbound traffic **except** that address:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: block-metadata
  namespace: prod
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32
```

(Also protect the node itself, for example with IMDSv2 and a hop limit on AWS.)

### A Sensible Pattern for Every Namespace

```text
 1. default-deny-all                (ingress and egress)
 2. allow-dns-egress                (so names resolve)
 3. one small allow policy per real traffic path   (frontend -> backend, backend -> db ...)
 4. an egress rule for required external services only
 5. block the metadata address
```

### Testing Policies

Never assume. Prove it with a test pod:

```bash
# This should SUCCEED (allowed path)
kubectl exec -n prod deploy/frontend -- wget -qO- --timeout=3 http://backend:8080

# This should FAIL (not allowed): a different pod tries to reach the database
kubectl run probe -n prod --rm -it --restart=Never --image=busybox:1.36 -- \
  wget -qO- --timeout=3 http://db:5432
```

If the "blocked" test **succeeds**, your CNI is probably not enforcing policies.

### Beyond the Basics

| Feature | Notes |
| :--- | :--- |
| **Cluster-wide policies** | Calico (`GlobalNetworkPolicy`) and Cilium (`CiliumClusterwideNetworkPolicy`) offer policies that apply to all namespaces, with explicit **deny** rules. |
| **Layer 7 policies** | Cilium can filter by HTTP method and path, DNS names, and more. |
| **Service mesh mTLS** (Istio, Linkerd) | Encrypts and authenticates service-to-service traffic. |
| **Ingress and egress gateways** | Control and inspect traffic entering and leaving the cluster. |
| **Visualization** | The online **Network Policy Editor** (editor.networkpolicy.io) helps you draw and review policies. |

---

## 6. Kubernetes Secrets Security

### What Is a Secret?

A Kubernetes **Secret** stores small pieces of sensitive data (passwords, tokens, keys, certificates) so they do not need to be written into images or pod specs.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
  namespace: prod
type: Opaque
stringData:                       # plain text here; Kubernetes stores it base64-encoded
  username: appuser
  password: not-a-real-password
```

### The Big Misunderstanding: base64 Is Not Encryption

```bash
kubectl get secret db-credentials -n prod -o jsonpath='{.data.password}'
# bm90LWEtcmVhbC1wYXNzd29yZA==

echo 'bm90LWEtcmVhbC1wYXNzd29yZA==' | base64 -d
# not-a-real-password            <-- decoded instantly by anyone who can read the secret
```

> [!IMPORTANT]
> **base64 is an encoding, not protection.** By default, Secrets are **stored unencrypted in etcd**, and anyone who is allowed to `get` the Secret (or who can read etcd or its backups) sees the plain value. Real protection comes from **RBAC, encryption at rest, and good handling**.

### Where Secrets Can Leak

| Place | Risk |
| :--- | :--- |
| **Git** (manifests with real values) | Permanent history (Module 03). |
| **etcd** and **etcd backups** | Unencrypted by default. |
| **RBAC too broad** | `list secrets` reads them all. |
| **Environment variables** | Visible in `kubectl describe`, `/proc`, crash dumps, and logs. |
| **Pod specs with `kubectl get pod -o yaml`** | Env values from literals are visible. |
| **CI/CD logs** | A secret printed during deployment. |
| **Images** | A secret baked in during the build (Module 07). |
| **Other namespaces with `edit` permissions** | A broad role reads Secrets. |

### Ways to Give a Pod a Secret

| Method | Assessment |
| :--- | :--- |
| **Environment variable** (`env.valueFrom.secretKeyRef`) | ⚠️ Convenient but leaks easily (logs, process listing, child processes). |
| **Mounted file** (a `secret` volume) | ✅ Better. Read-only files in memory-backed storage. Updates propagate to the pod. |
| **Fetched at runtime from a secrets manager** | ✅ Best. Short-lived, audited, centrally rotated (Module 11). |

```yaml
# Mount as a read-only file instead of an environment variable
spec:
  containers:
    - name: app
      image: my-org/app@sha256:...
      volumeMounts:
        - name: db-creds
          mountPath: /etc/secrets
          readOnly: true
  volumes:
    - name: db-creds
      secret:
        secretName: db-credentials
        defaultMode: 0400             # owner read-only
```

### Securing Secrets: The Layers

**1. Limit who can read them (RBAC, section 2).**

- Grant `get` on **specific** secrets with `resourceNames`, not `list` on all.
- Avoid `edit` and `admin` roles for ordinary users and pipelines.
- Remember: anyone who can **create a pod** in a namespace can usually mount **any** secret there.
- Audit "who can read secrets?" regularly.

**2. Encrypt Secrets at rest in etcd.**

Enable **encryption at rest** on the API server with an `EncryptionConfiguration`:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources: ["secrets"]
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <BASE64-ENCODED 32-BYTE KEY>
      - identity: {}              # lets the cluster still READ old, unencrypted data
```

The API server flag `--encryption-provider-config` points to this file. The **first** provider encrypts new writes. Then re-write existing secrets so they get encrypted too:

```bash
kubectl get secrets --all-namespaces -o json | kubectl replace -f -
```

| Provider | Notes |
| :--- | :--- |
| `identity` | **No encryption** (the default). |
| `aescbc`, `aesgcm`, `secretbox` | Encrypt with a **local key** kept in the API server's config file. Better than nothing, but the key sits next to the data on the same machine. |
| **`kms`** (KMS v2) | **Envelope encryption**: data is encrypted with a key held in an external **Key Management Service** (cloud KMS or HashiCorp Vault). **Recommended.** |

> [!NOTE]
> On **managed Kubernetes** (EKS, AKS, GKE) you usually turn on **envelope encryption** with the cloud's KMS through a cluster setting, instead of editing API server files. Check your provider's documentation. Encryption at rest protects etcd **disks and backups**. It does **not** stop someone who has RBAC permission to read the Secret through the API.

**3. Keep secrets out of Git.**

| Tool | Idea |
| :--- | :--- |
| **Sealed Secrets** | Encrypt a Secret into a `SealedSecret` that is **safe to commit**. Only the cluster's controller can decrypt it. |
| **SOPS** (with age, KMS, or similar) | Encrypts values in YAML files so you can store them in Git. |
| **External Secrets Operator** | Syncs secrets **from** a secrets manager (AWS, Azure, GCP, Vault) **into** Kubernetes Secrets. |
| **Secrets Store CSI Driver** | Mounts secrets from an external manager **directly into pods** as files, without storing them as Kubernetes Secrets at all. |
| **Gitleaks** (Module 03) | Scans manifests and history for exposed secrets. |

**4. Use a dedicated secrets manager.**

For serious workloads, store secrets in **HashiCorp Vault or a cloud secrets manager** (Module 11), and give pods **short-lived, identity-based** access through workload identity (section 3).

**5. Make secrets immutable where it makes sense.**

```yaml
immutable: true      # the Secret cannot be changed. Replace it by creating a new one
```

This prevents accidental or malicious edits and reduces load on the API server.

**6. Rotate secrets.**

Plan for rotation from day one. Short-lived credentials are best. Static ones need a rotation schedule and a process that does not require downtime.

**7. Audit secret access.**

Enable **audit logging** (section 9) with a policy that records who read or changed Secrets. Record metadata only, never the secret values themselves.

### Other Kinds of Secrets

| Type | Used For |
| :--- | :--- |
| `Opaque` | General key-value data |
| `kubernetes.io/tls` | TLS certificate and private key |
| `kubernetes.io/dockerconfigjson` | **Image pull credentials** for private registries (store tokens with **read-only** scope) |
| `kubernetes.io/service-account-token` | Legacy long-lived service account tokens (avoid) |
| `kubernetes.io/basic-auth`, `ssh-auth` | Specific credential types |

### Secrets Checklist

- [ ] No real secret values in Git or in container images
- [ ] RBAC limits `get`, `list`, and `watch` on secrets to the few who need them
- [ ] Secrets are **mounted as files**, not exposed as environment variables
- [ ] **Encryption at rest** is enabled (KMS where possible)
- [ ] Workloads use **workload identity** instead of stored cloud keys
- [ ] Image pull secrets are **read-only** and scoped
- [ ] Audit logging records secret access
- [ ] A rotation plan exists
- [ ] Legacy long-lived service account tokens have been removed

---

## 7. Kyverno – Kubernetes Policy Management

**Kyverno** is a Kubernetes-native **policy engine** (a CNCF project). It runs as an **admission controller**, so it can **validate, mutate, generate, and clean up** Kubernetes resources, and **verify signed container images**, using policies written in plain YAML. It covers the custom rules that Pod Security Admission cannot, such as required labels, approved registries, resource limits, and Cosign signature checks from Module 07.

> [!NOTE]
> Kyverno has its own dedicated, in-depth guide, so this module does not repeat it.

### 📘 Learn Kyverno in Depth

➡️ **[Kyverno Zero to Hero](https://github.com/bhuvan-raj/Kyverno-Zero-to-Hero)**: installation, policy types, validation, mutation, generation, image verification, reports, testing, and hands-on labs.

### How It Fits Into This Module

| Where in the Cluster Security Story | Kyverno's Role |
| :--- | :--- |
| Admission control (section 1) | Runs in the **admission** stage and can block risky resources. |
| Pod security (section 4) | Goes beyond the three built-in levels with **custom** rules. |
| Supply chain (Module 07) | Can require that images are **signed with Cosign** and come from approved registries. |
| Auditing (section 9) | Produces **policy reports** that show violations across the cluster. |

---

## 8. Runtime Security with KubeArmor

Everything so far protects the cluster **before** a workload runs: who may deploy, what a pod may request, which pods may talk. **Runtime security** protects workloads **while they run**, by watching and restricting what processes, files, and network connections a container is **actually allowed to use**.

**KubeArmor** is a CNCF runtime security engine for Kubernetes. It uses Linux Security Modules (such as AppArmor, SELinux, or BPF-LSM) to **enforce policies** on container behavior, for example blocking a shell from starting inside a production container, or stopping access to sensitive files, and it can also report violations.

> [!NOTE]
> KubeArmor has its own dedicated, in-depth guide, so this module does not repeat it.

### 🛡️ Learn KubeArmor in Depth

➡️ **[KubeArmor Zero to Hero](https://github.com/bhuvan-raj/KubeArmour-Zero-to-Hero)**: installation, security policies, enforcement and audit modes, visibility, and hands-on labs.

### How It Fits Into This Module

| Where in the Cluster Security Story | KubeArmor's Role |
| :--- | :--- |
| Attack path steps 5 and 6 (section 1) | Limits what an attacker can **do** after getting into a container. |
| Container hardening (Module 07) | Adds **mandatory access control** around process, file, and network behavior. |
| Linux security (Module 02) | Builds on the same kernel mechanisms (AppArmor, SELinux, capabilities). |
| Monitoring (Module 12) | Provides runtime **visibility and alerts**, alongside tools such as **Falco**. |

---

## 9. Kubernetes Security Auditing & Hardening

Security is not finished when you apply the controls. You must **check that they exist, keep working, and cover everything**, and you must be able to **investigate** when something goes wrong.

### Audit Logging: The Cluster's Flight Recorder

**Kubernetes audit logs** record **every request** to the API server: who made it, what they did, to which resource, and what the result was. Without them you cannot answer *"who deleted that?"* or *"did anyone read our secrets?"*.

```text
 Each audit event shows:
   user          system:serviceaccount:dev:dev-sa
   verb          list
   resource      secrets   (namespace: prod)
   sourceIP      10.2.3.4
   result        403 Forbidden
   timestamp     2026-10-28T10:15:01Z
```

An **audit policy** decides **what** is recorded and **how much detail**:

```yaml
# audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages:
  - "RequestReceived"
rules:
  # Record who accesses Secrets and ConfigMaps, but ONLY metadata, never the values
  - level: Metadata
    resources:
      - group: ""
        resources: ["secrets", "configmaps", "serviceaccounts/token"]

  # Full detail for changes to RBAC
  - level: RequestResponse
    resources:
      - group: "rbac.authorization.k8s.io"
        resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]

  # Record exec and port-forward (common attacker actions)
  - level: Request
    resources:
      - group: ""
        resources: ["pods/exec", "pods/attach", "pods/portforward"]

  # Everything else: metadata only
  - level: Metadata
```

| Level | What Is Recorded |
| :--- | :--- |
| `None` | Nothing |
| `Metadata` | Who, what, when. **No** request or response bodies. |
| `Request` | Metadata plus the request body |
| `RequestResponse` | Metadata plus request **and** response bodies |

> [!CAUTION]
> Never log secret **values**. Use `Metadata` level for Secrets, or the audit log itself becomes a leak.

The API server needs flags such as `--audit-policy-file`, `--audit-log-path`, and retention settings. On **managed Kubernetes**, enable the provider's control-plane audit logging feature and send logs to your logging system. **Ship logs off the cluster** (Module 12: Loki and Grafana), alert on suspicious patterns, and retain them long enough to investigate.

**What to alert on:**

- Requests from `system:anonymous`
- New `ClusterRoleBinding` or `RoleBinding` creation, especially `cluster-admin`
- `exec` or `port-forward` into production pods
- Secret reads by unusual identities
- Creation of privileged pods
- Changes to admission webhooks and policies
- Many `403` errors from one identity (probing)

### Hardening the Control Plane (Self-Managed Clusters)

On managed services the provider handles most of this. On self-managed clusters (kubeadm and similar), harden these:

**kube-apiserver:**

| Setting | Recommended | Why |
| :--- | :--- | :--- |
| `--anonymous-auth` | `false` | Refuse unauthenticated requests. |
| `--authorization-mode` | `Node,RBAC` | Never `AlwaysAllow`. |
| `--enable-admission-plugins` | Include `NodeRestriction` (and keep PodSecurity enabled) | Limits what kubelets may modify. |
| `--audit-policy-file`, `--audit-log-path` | Set | Enables audit logging. |
| `--encryption-provider-config` | Set | Encryption at rest for secrets. |
| `--tls-min-version` | `VersionTLS12` or higher | Modern TLS only. |
| `--profiling` | `false` | Disable the profiling endpoint. |
| Expose the API server **privately** | Not on the public internet | Reduces attack surface. |

**etcd:**

| Setting | Why |
| :--- | :--- |
| Client and peer **TLS** with client certificate authentication | Only the API server may connect. |
| **Firewall** etcd so only control-plane nodes reach it | etcd holds everything. |
| **Encrypted backups**, stored securely | Backups contain all secrets. |

**kubelet (on each node):**

| Setting | Recommended | Why |
| :--- | :--- | :--- |
| `authentication.anonymous.enabled` | `false` | No anonymous access to the kubelet API. |
| `authorization.mode` | `Webhook` | Kubelet asks the API server whether a caller is allowed. |
| `readOnlyPort` | `0` (disabled) | Removes an unauthenticated read-only endpoint. |
| `protectKernelDefaults` | `true` | Prevents the kubelet from changing kernel settings unexpectedly. |
| `rotateCertificates` | `true` | Short-lived kubelet certificates. |

Keep file permissions on Kubernetes configuration and certificate files strict (for example `600` or `644` and owned by `root`), as you practised in Module 02.

### Harden the Nodes and the Rest of the Environment

| Area | Practice |
| :--- | :--- |
| **Node operating system** | Minimal, container-focused OS if possible. Patch regularly. Apply the Linux hardening from Module 02 (SSH, firewall, auditing, updates). |
| **Container runtime** | Keep `containerd` and `runc` patched (Module 07). |
| **Node access** | Avoid SSH to nodes. Use short-lived, audited access when needed. |
| **Cloud network** | Private subnets, restricted API server endpoint, security groups. |
| **Registries** | Private registries, image scanning, signed images (Module 07). |
| **Resource management** | Set **ResourceQuotas** and **LimitRanges** per namespace so one workload cannot starve the cluster. |
| **Namespaces** | Separate teams and environments, with separate RBAC, quotas, and network policies. Namespaces are **organization**, not a hard security boundary on their own. |
| **Upgrades** | Stay on supported versions. Upgrade regularly. |

### Add Guardrails With Admission Policies

| Tool | What It Adds |
| :--- | :--- |
| **Pod Security Admission** (section 4) | Built-in pod security levels. |
| **Kyverno** (section 7) | Flexible YAML policies, mutation, image verification, reports. |
| **ValidatingAdmissionPolicy** | Native, CEL-expression-based validation built into the API server (generally available since Kubernetes 1.30). |
| **OPA Gatekeeper** | Policy engine using the Rego language. |

### Audit Against Benchmarks and Scan Continuously

| Tool | What It Checks |
| :--- | :--- |
| **kube-bench** | Compares a cluster's configuration with the **CIS Kubernetes Benchmark**. Best on self-managed (kubeadm) clusters. Run it as a Job on the nodes. |
| **Kubescape** | Scans clusters and manifests against frameworks (NSA/CISA, CIS, MITRE) and reports risk. |
| **Trivy** | Scans manifests (`trivy config`), images, and clusters for misconfigurations and vulnerabilities. Pin and verify it as taught in Module 07. |
| **Polaris** and **kubeaudit** | Check workloads against best-practice rules. |
| **Falco** and **KubeArmor** | Runtime detection and enforcement (section 8, Module 12). |
| **Cloud-provider tools** | Native posture management for EKS, AKS, and GKE. |

```bash
# Scan Kubernetes manifests BEFORE they are applied (shift left, in CI)
trivy config ./k8s-manifests

# Scan with Kubescape against a framework
kubescape scan framework nsa

# Run kube-bench on a self-managed cluster (as a Job on a node, see its documentation)
```

(Tool options change between versions. Check each tool's `--help` and documentation.)

### Useful Audit One-Liners

```bash
# Privileged containers anywhere?
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[]?.securityContext.privileged==true) |
  "\(.metadata.namespace)/\(.metadata.name)"'

# Pods using hostPath volumes
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.volumes[]?.hostPath) |
  "\(.metadata.namespace)/\(.metadata.name)"'

# Pods sharing host namespaces
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.hostNetwork==true or .spec.hostPID==true or .spec.hostIPC==true) |
  "\(.metadata.namespace)/\(.metadata.name)"'

# Pods running with the default service account
kubectl get pods -A -o json | jq -r '.items[] | select((.spec.serviceAccountName // "default")=="default") |
  "\(.metadata.namespace)/\(.metadata.name)"'

# Pods that automount a service account token
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.automountServiceAccountToken != false) |
  "\(.metadata.namespace)/\(.metadata.name)"'

# Namespaces WITHOUT any NetworkPolicy
comm -23 \
  <(kubectl get ns -o name | sed 's|namespace/||' | sort) \
  <(kubectl get networkpolicy -A -o json | jq -r '.items[].metadata.namespace' | sort -u)

# Namespaces without a Pod Security enforce label
kubectl get ns -o json | jq -r '.items[] | select(.metadata.labels["pod-security.kubernetes.io/enforce"] == null) | .metadata.name'

# Long-lived service account token secrets
kubectl get secrets -A --field-selector type=kubernetes.io/service-account-token

# Images not pinned by digest
kubectl get pods -A -o json | jq -r '.items[] | .metadata.namespace as $ns | .metadata.name as $p |
  .spec.containers[] | select(.image | contains("@sha256:") | not) | "\($ns)/\($p): \(.image)"'
```

### Incident Response Basics for Kubernetes

If you suspect a pod is compromised:

```text
 1. ISOLATE   Apply a "quarantine" NetworkPolicy (deny all ingress and egress) to the pod's labels,
              or relabel the pod so it leaves its Service.   Do NOT delete it yet.
 2. PRESERVE  Capture evidence: logs, pod spec, process list, filesystem copy, node details
              (kubectl logs, kubectl describe, kubectl get pod -o yaml, your logging platform).
 3. CONTAIN   Revoke or rotate credentials the pod could reach: its service account, secrets it mounted,
              cloud roles. Cordon the node if the node may be affected.
 4. ERADICATE Remove the pod, fix the cause (patched image, closed permission), redeploy from a clean,
              verified image.
 5. REVIEW    Check audit logs for what the identity did. Look for similar pods and other namespaces.
 6. IMPROVE   Add the missing control: policy, network rule, detection, least privilege.
```

### The Hardening Checklist

**Identity and access**
- [ ] Anonymous access disabled; RBAC enabled
- [ ] No unnecessary `cluster-admin` bindings; no wildcards
- [ ] Each workload has its own service account; `default` is not used
- [ ] Token automounting is off unless needed
- [ ] Workload identity replaces stored cloud keys

**Workload security**
- [ ] Pod Security Admission: at least `baseline` everywhere, `restricted` for application namespaces
- [ ] Images scanned, signed, pinned by digest, and from approved registries (Module 07)
- [ ] Resource requests, limits, and quotas set

**Network**
- [ ] Default-deny network policies in every application namespace
- [ ] Metadata service blocked from pods
- [ ] API server and kubelet are not exposed publicly

**Data**
- [ ] Secrets encrypted at rest (KMS) and not in Git
- [ ] Secrets mounted as files or fetched from a secrets manager
- [ ] etcd protected and backups encrypted

**Detection and maintenance**
- [ ] Audit logging on and shipped off the cluster
- [ ] Runtime detection (KubeArmor or Falco) in place
- [ ] Benchmarks and scans run regularly (CIS, Kubescape, Trivy)
- [ ] Kubernetes and nodes are on supported, patched versions

---

## 10. Hands-on Kubernetes Security Lab

> [!WARNING]
> Use a **disposable local cluster** (this lab uses **minikube**). Do not run these steps on a shared or production cluster. All names, passwords, and images are for practice only.

### Lab Environment

**Requirements:** Docker, `kubectl`, `minikube`, `jq`, and about 4 GB of free RAM.

```bash
# 1. Start a local cluster with Calico, a CNI that ENFORCES network policies
minikube start -p k8s-sec-lab --cni=calico --cpus=2 --memory=4096

# 2. Confirm kubectl points at it
kubectl config current-context           # should show: k8s-sec-lab
kubectl get nodes

# 3. Wait for the networking pods to become Ready (this can take a minute or two)
kubectl get pods -n kube-system
```

> [!NOTE]
> Network policies only work if the cluster's CNI enforces them. This lab uses Calico for that reason. In Part 4, a **test proves** whether enforcement works on your cluster.

**Lab cleanup (at the end):**

```bash
minikube delete -p k8s-sec-lab
```

### Part 1: RBAC, Least Privilege in Practice

**Objective:** Create a limited identity and verify exactly what it can and cannot do.

```bash
# 1. A namespace and a service account
kubectl create namespace dev
kubectl create serviceaccount dev-sa -n dev

# 2. A Role that can only read pods, and a binding
kubectl create role pod-reader --verb=get,list,watch --resource=pods -n dev
kubectl create rolebinding read-pods --role=pod-reader --serviceaccount=dev:dev-sa -n dev

# 3. Create something to look at
kubectl run demo --image=nginxinc/nginx-unprivileged:stable -n dev
```

**Test the permissions with `--as` (impersonation):**

```bash
SA="system:serviceaccount:dev:dev-sa"

kubectl auth can-i list pods     -n dev --as=$SA     # yes
kubectl auth can-i delete pods   -n dev --as=$SA     # no
kubectl auth can-i list secrets  -n dev --as=$SA     # no
kubectl auth can-i list pods     -n default --as=$SA # no (wrong namespace)
kubectl auth can-i --list -n dev --as=$SA
```

**Audit the cluster:**

```bash
# Who has cluster-admin?
kubectl get clusterrolebindings -o json | jq -r \
  '.items[] | select(.roleRef.name=="cluster-admin") |
   "\(.metadata.name): \([.subjects[]? | "\(.kind)/\(.name)"] | join(", "))"'
```

**Now make a dangerous mistake on purpose, and detect it:**

```bash
# Over-privileged binding (do NOT do this in real life)
kubectl create clusterrolebinding bad-binding --clusterrole=cluster-admin --serviceaccount=dev:dev-sa

kubectl auth can-i '*' '*' --as=system:serviceaccount:dev:dev-sa       # yes: it can do everything!

# Find it again
kubectl get clusterrolebindings -o json | jq -r \
  '.items[] | select(.roleRef.name=="cluster-admin") | .metadata.name'

# Remove it
kubectl delete clusterrolebinding bad-binding
```

**Questions:**

| Question | Your Answer |
| :--- | :--- |
| Why does `dev-sa` fail to list pods in `default`? | |
| What did the `can-i --list` output show beyond pods? | |
| How would you find over-privileged service accounts in a real cluster? | |

**Expected outcome:** Reading pods in `dev` works, everything else is denied, and you can detect and remove a dangerous `cluster-admin` binding.

### Part 2: Service Account Token Abuse and Hardening

**Objective:** See how a stolen token is used, and remove it.

```bash
# 1. A pod using the DEFAULT service account, with a curl-capable image
kubectl run attacker -n dev --image=curlimages/curl:latest --restart=Never --command -- sleep 3600
kubectl wait -n dev --for=condition=Ready pod/attacker --timeout=90s

# 2. The token is mounted automatically
kubectl exec -n dev attacker -- ls /var/run/secrets/kubernetes.io/serviceaccount/

# 3. Use it like an attacker would
kubectl exec -n dev attacker -- sh -c '
  TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
  curl -s -o /dev/null -w "HTTP status: %{http_code}\n" \
    --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
    -H "Authorization: Bearer $TOKEN" \
    https://kubernetes.default.svc/api/v1/namespaces/dev/pods'
```

Expected: **403**. The default service account has no permissions. Now give the pod a service account that **can** read pods and try again:

```bash
kubectl delete pod attacker -n dev --now
kubectl run attacker -n dev --image=curlimages/curl:latest --restart=Never \
  --overrides='{"spec":{"serviceAccountName":"dev-sa"}}' --command -- sleep 3600
kubectl wait -n dev --for=condition=Ready pod/attacker --timeout=90s

kubectl exec -n dev attacker -- sh -c '
  TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
  curl -s --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
    -H "Authorization: Bearer $TOKEN" \
    https://kubernetes.default.svc/api/v1/namespaces/dev/pods | head -c 400'
```

Expected: **a JSON list of pods**. A compromised pod could do whatever `dev-sa` is allowed to do.

**Harden it: no token at all.**

```bash
kubectl delete pod attacker -n dev --now

cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: hardened
  namespace: dev
spec:
  serviceAccountName: dev-sa
  automountServiceAccountToken: false
  containers:
    - name: c
      image: curlimages/curl:latest
      command: ["sleep", "3600"]
EOF
kubectl wait -n dev --for=condition=Ready pod/hardened --timeout=90s

kubectl exec -n dev hardened -- ls /var/run/secrets/kubernetes.io/serviceaccount/ ; echo "Exit code: $?"
```

Expected: **"No such file or directory"**. There is nothing to steal.

**Questions:**

| Question | Your Answer |
| :--- | :--- |
| Why was the first request denied (403)? | |
| What decided what the second pod could do? | |
| Which setting removed the token from the third pod? | |
| Which pods in a real cluster should keep a token? | |

**Expected outcome:** You can demonstrate token abuse, show that least privilege limits it, and remove the token with `automountServiceAccountToken: false`.

### Part 3: Pod Security Admission

**Objective:** Block dangerous pods and allow compliant ones.

```bash
# 1. A namespace that ENFORCES the restricted standard
kubectl create namespace secure
kubectl label namespace secure \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted
```

**Try an insecure pod. It should be REJECTED:**

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
  namespace: secure
spec:
  hostPID: true
  containers:
    - name: bad
      image: busybox:1.36
      command: ["sleep", "3600"]
      securityContext:
        privileged: true
      volumeMounts:
        - name: host
          mountPath: /host
  volumes:
    - name: host
      hostPath:
        path: /
EOF
```

Read the error message. Which violations does it list?

**Now a compliant pod. It should be ACCEPTED:**

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
  namespace: secure
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 101
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: web
      image: nginxinc/nginx-unprivileged:stable
      ports:
        - containerPort: 8080
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
EOF

kubectl get pod good-pod -n secure
```

**Experiment with the modes:**

```bash
# warn and audit only (nothing blocked) in a second namespace
kubectl create namespace staging
kubectl label namespace staging \
  pod-security.kubernetes.io/warn=restricted pod-security.kubernetes.io/audit=restricted
kubectl run needs-fix -n staging --image=nginx:stable       # allowed, but you see warnings

# Preview what WOULD break if you enforced restricted in "dev" (nothing is changed)
kubectl label --dry-run=server --overwrite namespace dev \
  pod-security.kubernetes.io/enforce=restricted
```

**Optional hardening step:** add `readOnlyRootFilesystem: true` and an `emptyDir` volume mounted at `/tmp` to `good-pod`, redeploy it, and check that it still runs (`kubectl logs good-pod -n secure`).

**Questions:**

| Question | Your Answer |
| :--- | :--- |
| Which violations did the bad pod's error list? | |
| Which fields made the good pod compliant? | |
| How did `warn` mode differ from `enforce` mode? | |
| Why use the dry-run preview before enforcing on an existing namespace? | |

**Expected outcome:** The privileged `hostPath` pod is rejected with a clear message, the compliant pod runs, and you understand the safe rollout order (preview, warn and audit, fix, enforce).

### Part 4: Network Policies

**Objective:** Move from "everything talks to everything" to default deny with precise allows.

```bash
kubectl create namespace netlab

# Three tiers (all use the same unprivileged web image on port 8080)
for app in frontend backend db; do
  kubectl create deployment $app -n netlab --image=nginxinc/nginx-unprivileged:stable --port=8080
  kubectl expose deployment $app -n netlab --port=8080
done
kubectl wait -n netlab --for=condition=Available deployment --all --timeout=120s
```

**Step 1: Prove everything is open (the default):**

```bash
kubectl exec -n netlab deploy/frontend -- wget -qO- --timeout=3 http://db:8080 | head -3
echo "Exit code: $?"          # works: the frontend can talk straight to the database
```

**Step 2: Default deny:**

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: netlab
spec:
  podSelector: {}
  policyTypes: ["Ingress", "Egress"]
EOF

kubectl exec -n netlab deploy/frontend -- wget -qO- --timeout=3 http://backend:8080 ; echo "Exit code: $?"
```

Expected: the request **times out** (non-zero exit code). **If it still succeeds, your CNI is not enforcing policies**, so check that Calico is running.

**Step 3: Allow DNS, then the exact paths you want (frontend to backend, backend to db):**

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: netlab
spec:
  podSelector: {}
  policyTypes: ["Egress"]
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - { protocol: UDP, port: 53 }
        - { protocol: TCP, port: 53 }
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-egress-to-backend
  namespace: netlab
spec:
  podSelector:
    matchLabels: { app: frontend }
  policyTypes: ["Egress"]
  egress:
    - to:
        - podSelector:
            matchLabels: { app: backend }
      ports:
        - { protocol: TCP, port: 8080 }
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-ingress-from-frontend
  namespace: netlab
spec:
  podSelector:
    matchLabels: { app: backend }
  policyTypes: ["Ingress"]
  ingress:
    - from:
        - podSelector:
            matchLabels: { app: frontend }
      ports:
        - { protocol: TCP, port: 8080 }
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-egress-to-db
  namespace: netlab
spec:
  podSelector:
    matchLabels: { app: backend }
  policyTypes: ["Egress"]
  egress:
    - to:
        - podSelector:
            matchLabels: { app: db }
      ports:
        - { protocol: TCP, port: 8080 }
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: db-ingress-from-backend
  namespace: netlab
spec:
  podSelector:
    matchLabels: { app: db }
  policyTypes: ["Ingress"]
  ingress:
    - from:
        - podSelector:
            matchLabels: { app: backend }
      ports:
        - { protocol: TCP, port: 8080 }
EOF
```

**Step 4: Test the matrix:**

```bash
echo "frontend -> backend (should WORK):"
kubectl exec -n netlab deploy/frontend -- wget -qO- --timeout=3 http://backend:8080 > /dev/null && echo "  allowed" || echo "  BLOCKED"

echo "backend -> db (should WORK):"
kubectl exec -n netlab deploy/backend -- wget -qO- --timeout=3 http://db:8080 > /dev/null && echo "  allowed" || echo "  BLOCKED"

echo "frontend -> db (should be BLOCKED):"
kubectl exec -n netlab deploy/frontend -- wget -qO- --timeout=3 http://db:8080 > /dev/null && echo "  allowed" || echo "  BLOCKED"

echo "frontend -> internet (should be BLOCKED):"
kubectl exec -n netlab deploy/frontend -- wget -qO- --timeout=3 http://example.com > /dev/null && echo "  allowed" || echo "  BLOCKED"
```

Fill in the matrix:

| From → To | Expected | Your Result |
| :--- | :---: | :---: |
| frontend → backend | Allowed | |
| backend → db | Allowed | |
| frontend → db | **Blocked** | |
| frontend → internet | **Blocked** | |
| a **new pod in another namespace** → backend | **Blocked** | |

Test the last row yourself with `kubectl run probe --rm -it --restart=Never --image=busybox:1.36 -- wget -qO- --timeout=3 http://backend.netlab.svc:8080`.

**Questions:**

| Question | Your Answer |
| :--- | :--- |
| Why did the frontend → backend test fail right after the default deny? | |
| Why did we need a separate DNS policy? | |
| Why did backend → db need **two** policies (one egress, one ingress)? | |
| What is the difference between putting `namespaceSelector` and `podSelector` in the same list item and in separate items? | |

**Expected outcome:** Traffic follows exactly the allowed paths and nothing else, and you have **proved** enforcement with tests.

### Part 5: Secrets Handling

**Objective:** See why base64 is not protection, and handle secrets more safely.

```bash
kubectl create namespace secrets-lab

# 1. Create a secret and read it back
kubectl create secret generic db-credentials -n secrets-lab \
  --from-literal=username=appuser --from-literal=password="$(head -c 18 /dev/urandom | base64 | tr -d '/+=')"

kubectl get secret db-credentials -n secrets-lab -o jsonpath='{.data.password}' ; echo
kubectl get secret db-credentials -n secrets-lab -o jsonpath='{.data.password}' | base64 -d ; echo
```

You just decoded it in one command. Anyone with `get` permission can do the same.

**2. Compare environment variable and file delivery:**

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: secret-demo
  namespace: secrets-lab
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 101
    seccompProfile: { type: RuntimeDefault }
  containers:
    - name: app
      image: nginxinc/nginx-unprivileged:stable
      securityContext:
        allowPrivilegeEscalation: false
        capabilities: { drop: ["ALL"] }
      env:
        - name: DB_PASSWORD_ENV
          valueFrom:
            secretKeyRef: { name: db-credentials, key: password }
      volumeMounts:
        - { name: creds, mountPath: /etc/secrets, readOnly: true }
  volumes:
    - name: creds
      secret:
        secretName: db-credentials
        defaultMode: 0400
EOF
kubectl wait -n secrets-lab --for=condition=Ready pod/secret-demo --timeout=90s

kubectl exec -n secrets-lab secret-demo -- env | grep DB_PASSWORD_ENV      # exposed in the environment
kubectl exec -n secrets-lab secret-demo -- ls -l /etc/secrets               # as files, mode 0400
```

**3. Restrict who can read secrets with RBAC:**

```bash
kubectl create serviceaccount reader -n secrets-lab
kubectl create role pod-viewer --verb=get,list --resource=pods -n secrets-lab
kubectl create rolebinding reader-pods --role=pod-viewer --serviceaccount=secrets-lab:reader -n secrets-lab

kubectl auth can-i get secrets -n secrets-lab --as=system:serviceaccount:secrets-lab:reader      # no
kubectl auth can-i get pods    -n secrets-lab --as=system:serviceaccount:secrets-lab:reader      # yes
```

**4. Catch secrets in manifests before they reach Git (Module 03):**

```bash
mkdir -p ~/k8s-lab-manifests && cd ~/k8s-lab-manifests
FAKE="ghp_$(head -c 300 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 36)"
cat > bad-secret.yaml <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: oops
stringData:
  token: $FAKE
EOF
gitleaks dir . -v          # detects the fake token (Gitleaks from Module 03)
rm bad-secret.yaml
```

**5. Answer:** If a Secret can be decoded this easily, what *actually* protects it in a real cluster? List four controls from section 6.

**Expected outcome:** You can show that base64 is not protection, that file mounts are safer than environment variables, that RBAC can prevent reading secrets, and that scanners catch secrets in manifests.

### Part 6: Policy and Runtime Layers (Kyverno and KubeArmor)

**Objective:** Add the policy and runtime layers using your dedicated guides.

1. Follow the quick-start in **[Kyverno Zero to Hero](https://github.com/bhuvan-raj/Kyverno-Zero-to-Hero)** to install Kyverno on the lab cluster, and apply **one policy** that blocks something Pod Security Admission cannot (for example, a policy that requires resource limits or approved registries). Prove it works with a test deployment.
2. Follow the quick-start in **[KubeArmor Zero to Hero](https://github.com/bhuvan-raj/KubeArmor-Zero-to-Hero)** to install KubeArmor, and apply **one policy** that blocks a sensitive action inside a container (for example, running a shell). Prove it works from `kubectl exec`.

> [!NOTE]
> KubeArmor needs support from the node's Linux Security Module, and a minikube node may not support every enforcement mode. Check its guide for the requirements, and use its audit mode if enforcement is not available on your cluster.

**Expected outcome:** One admission policy and one runtime policy are active, and each has a recorded test showing it blocks the unwanted behavior.

### Part 7: Audit and Harden

**Objective:** Find what is still wrong, and fix it.

**1. Run the audit one-liners from section 9 against your lab cluster** (privileged pods, hostPath, default service account, automount, namespaces without network policies, namespaces without a Pod Security label, images not pinned by digest). Record the results:

| Check | Findings |
| :--- | :--- |
| Privileged pods | |
| Pods using the `default` service account | |
| Pods automounting tokens | |
| Namespaces without a NetworkPolicy | |
| Namespaces without a Pod Security `enforce` label | |
| Images not pinned by digest | |

**2. Scan your manifests:**

```bash
mkdir -p ~/k8s-lab-manifests && cd ~/k8s-lab-manifests
cat > insecure.yaml <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure-app
spec:
  replicas: 1
  selector:
    matchLabels: { app: insecure-app }
  template:
    metadata:
      labels: { app: insecure-app }
    spec:
      containers:
        - name: app
          image: nginx:latest
          securityContext:
            privileged: true
EOF

trivy config .            # Trivy from Module 07 (pinned and verified)
```

3. Write a **fixed** version of `insecure.yaml` (non-root, no privilege escalation, dropped capabilities, `seccompProfile`, resource limits, a pinned image, no token) and re-scan until the serious findings are gone.
4. **Optional:** run `kubescape scan framework nsa`, or review how `kube-bench` is run as a Job on a self-managed cluster, and list the top five findings you would fix first.
5. **Optional:** on a kubeadm-based practice cluster, enable an **audit policy** like the one in section 9, then trigger a few actions (a `kubectl exec`, a secret read) and find them in the audit log.

**Expected outcome:** You can produce an evidence-based list of weaknesses, fix manifest-level problems, and explain which findings need cluster-level changes.

### Part 8: Challenge: Build a Secure Namespace From Scratch

Combine everything into one reusable "secure namespace" recipe. Write the manifests for a namespace called `payments` that includes:

| Requirement | Control |
| :--- | :--- |
| Only restricted pods allowed | Pod Security labels (`enforce=restricted`) |
| A dedicated service account with **no** token | `ServiceAccount` with `automountServiceAccountToken: false` |
| Developers can **view** pods and logs but cannot read secrets | `Role` and `RoleBinding` |
| Default-deny networking, DNS allowed, and one path: `web` → `api` | `NetworkPolicy` objects |
| Resource limits for the whole namespace | `ResourceQuota` and `LimitRange` |
| A workload that passes all of the above | A compliant `Deployment` |

Deploy it, then **test each control** with the commands from the earlier parts, and keep the manifests as a template for new namespaces.

### Knowledge Check

1. Name the four stages a request passes through in the Kubernetes API server. Which controls belong to each?
2. Why is `etcd` such an attractive target, and how do you protect it?
3. In the 4C model, why can a strong container layer not compensate for a weak cluster layer?
4. In managed Kubernetes, which security tasks remain **your** responsibility?
5. What is the difference between a Role and a ClusterRole, and between a RoleBinding and a ClusterRoleBinding?
6. Why is it considered dangerous to grant `list` on `secrets`, `create` on `pods`, or `pods/exec`?
7. How can you check what a service account is allowed to do without logging in as it?
8. Why does RBAC have no "deny" rule, and what does that mean for how you design permissions?
9. What risk does the `default` service account create, and what two settings reduce it?
10. What is the difference between a legacy service account token secret and a projected token?
11. What is workload identity, and why is it better than storing a cloud access key in a Secret?
12. Explain the three Pod Security Standards levels and when you would use each.
13. What do the `enforce`, `audit`, and `warn` modes of Pod Security Admission do, and in what order would you roll them out?
14. Name six things the **restricted** level requires.
15. What can Pod Security Admission **not** do, and which tools fill the gap?
16. Why does a NetworkPolicy have no effect on some clusters? How do you test enforcement?
17. What does `podSelector: {}` mean, and why is it used in a default-deny policy?
18. Explain the difference between a `namespaceSelector` and a `podSelector` in the same list item versus separate items.
19. Why must egress to DNS be allowed explicitly after a default-deny egress policy?
20. Why is the cloud metadata address a target, and how do you block it from pods?
21. Why is base64 not encryption? What stores Secrets by default, and how can that be improved?
22. Compare delivering secrets as environment variables with delivering them as mounted files.
23. What does envelope encryption with a KMS provide that a local key does not?
24. What does a Kubernetes audit policy do, and why should Secret events be logged at `Metadata` level?
25. Name five API server, etcd, or kubelet hardening settings and the risk each reduces.
26. What is the difference between admission control (Kyverno, PSA) and runtime security (KubeArmor, Falco)?
27. Describe the steps you would take on discovering a compromised pod.
28. Describe an attack path from a vulnerable application to a cluster compromise, and name a control that breaks each step.

---

## Summary

In this module, you learned to secure Kubernetes in layers:

- **Fundamentals:** every request passes **authentication, authorization, and admission** before it is saved. Security follows the **4C** model, and in managed clusters you still own RBAC, workloads, and network and secrets security.
- **RBAC:** grant the **minimum** permissions, prefer namespaced Roles, avoid wildcards and `cluster-admin`, and watch the quiet escalation paths (secrets, `create pods`, `exec`, `impersonate`, `bind`).
- **Service accounts and workload identity:** give each workload its own identity with **no token unless it needs one**, use short-lived bound tokens, and replace stored cloud keys with **workload identity**.
- **Pod Security:** enforce **baseline** everywhere and **restricted** for applications using **Pod Security Admission**, and roll out with preview, warn and audit, fix, then enforce.
- **Network policies:** start with **default deny**, add DNS and the exact paths you need, beware the AND/OR selector trap, block the metadata service, and **always test enforcement**.
- **Secrets:** base64 is not encryption. Limit who can read secrets, encrypt etcd with a **KMS**, deliver secrets as **files**, keep them out of Git, and use a secrets manager.
- **Kyverno** adds flexible admission policies and image verification, and **KubeArmor** adds runtime enforcement. Both are covered in your dedicated guides.
- **Auditing and hardening:** keep **audit logs**, harden the API server, etcd, and kubelets, run **CIS, Kubescape, and Trivy** checks continuously, and keep the cluster **patched and supported**.

### Quick Reference

| Task | Command or Setting |
| :--- | :--- |
| Check a permission | `kubectl auth can-i <verb> <resource> -n <ns> --as=<identity>` |
| List all permissions of an identity | `kubectl auth can-i --list -n <ns> --as=<identity>` |
| Find `cluster-admin` bindings | `kubectl get clusterrolebindings -o json \| jq ...` |
| Create a role and binding | `kubectl create role ...` and `kubectl create rolebinding ...` |
| Remove the API token from a pod | `automountServiceAccountToken: false` |
| Mint a short-lived token | `kubectl create token <serviceaccount>` |
| Enforce a Pod Security level | `kubectl label ns <ns> pod-security.kubernetes.io/enforce=restricted` |
| Preview a Pod Security change | `kubectl label --dry-run=server --overwrite ns <ns> ...` |
| Default-deny a namespace | `NetworkPolicy` with `podSelector: {}` and both `policyTypes` |
| Decode a secret (shows base64 is weak) | `kubectl get secret <name> -o jsonpath='{.data.<key>}' \| base64 -d` |
| Encrypt secrets in etcd | `EncryptionConfiguration` with a `kms` provider |
| Scan manifests | `trivy config .` |
| Scan a cluster against NSA/CISA guidance | `kubescape scan framework nsa` |

### Module Completion Checklist

- [ ] I can describe the API request flow and the 4C model.
- [ ] I can write a Role and RoleBinding, and test permissions with `kubectl auth can-i --as`.
- [ ] I can list the dangerous RBAC permissions and find over-privileged identities.
- [ ] I can disable token automounting and explain workload identity.
- [ ] I can apply Pod Security Admission labels and roll them out safely.
- [ ] I can write a restricted-compliant pod spec.
- [ ] I can write default-deny and allow policies, and prove enforcement with tests.
- [ ] I can explain why base64 is not encryption and describe four controls for Secrets.
- [ ] I know where Kyverno and KubeArmor fit, and I used each repository's quick-start.
- [ ] I can enable and interpret audit logging, and scan a cluster and manifests for weaknesses.
- [ ] I completed Parts 1 to 8 of the lab.

---

## 📚 Related Repositories

| Repository | What It Covers |
| :--- | :--- |
| [Kyverno Zero to Hero](https://github.com/bhuvan-raj/Kyverno-Zero-to-Hero) | Kubernetes policy management with Kyverno |
| [KubeArmor Zero to Hero](https://github.com/bhuvan-raj/KubeArmor-Zero-to-Hero) | Kubernetes runtime security with KubeArmor |

## Official References

- Kubernetes security overview: <https://kubernetes.io/docs/concepts/security/>
- RBAC: <https://kubernetes.io/docs/reference/access-authn-authz/rbac/>
- Service accounts: <https://kubernetes.io/docs/concepts/security/service-accounts/>
- Pod Security Standards: <https://kubernetes.io/docs/concepts/security/pod-security-standards/>
- Pod Security Admission: <https://kubernetes.io/docs/concepts/security/pod-security-admission/>
- Network policies: <https://kubernetes.io/docs/concepts/services-networking/network-policies/>
- Good practices for Secrets: <https://kubernetes.io/docs/concepts/security/secrets-good-practices/>
- Encrypting data at rest: <https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/>
- Auditing: <https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/>
- ValidatingAdmissionPolicy: <https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/>
- CIS Kubernetes Benchmark: <https://www.cisecurity.org/benchmark/kubernetes>
- NSA/CISA Kubernetes Hardening Guide: <https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF>
- OWASP Kubernetes Top Ten: <https://owasp.org/www-project-kubernetes-top-ten/>
- kube-bench: <https://github.com/aquasecurity/kube-bench>
- Kubescape: <https://github.com/kubescape/kubescape>
- Calico: <https://docs.tigera.io/calico>
- Cilium: <https://cilium.io/>
- Falco: <https://falco.org/>
- Kyverno: <https://kyverno.io/>
- KubeArmor: <https://kubearmor.io/>
- Network Policy Editor: <https://editor.networkpolicy.io/>

> [!NOTE]
> Kubernetes versions, feature stages, tool options, and cloud provider features change often. When a command or setting differs from what you see, check the official documentation above for your Kubernetes version.

---

## Related Modules

- [Module 02: Linux Security](../02-linux-security/README.md) for capabilities, permissions, and node hardening.
- [Module 03: Git, GitHub and Secret Security](../03-git-github-and-secret-security/README.md) for keeping secrets out of Git.
- [Module 07: Docker and Container Security](../07-docker-and-container-security/README.md) for image scanning, signing, and runtime flags.
- [Module 11: Secrets Management and Cryptography](../11-secrets-management-and-cryptography/README.md) for Vault and secret rotation.
- [Module 12: Security Monitoring, Incident Response and Capstone Project](../12-security-monitoring-incident-response-and-capstone-project/README.md) for runtime detection, logging, and monitoring.

---

## Next Module

➡️ [Module 09: Terraform and Infrastructure as Code Security](../09-terraform-and-infrastructure-as-code-security/README.md)

[⬅️ Previous: Module 07: Docker and Container Security](../07-docker-and-container-security/README.md) | [🏠 Main README](../README.md)

---

<div align="center">

**Learn. Secure. Automate. Deploy. 🛡️**

</div>
