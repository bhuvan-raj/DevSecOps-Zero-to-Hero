# Module 07: Docker & Container Security 🐳🔐

## 📌 Overview

Containerization makes application deployment consistent and portable, but insecure container images, vulnerable packages, excessive privileges, and misconfigured runtime environments can introduce security risks.

Docker security focuses on building, distributing, and running containers securely. Container security extends these practices to the entire container lifecycle, from image creation to runtime execution.

In this module, you will learn how to secure Dockerfiles, scan container images using **Trivy**, sign and verify container images using **Cosign**, and integrate container security checks into CI/CD pipelines.

> [!NOTE]
> This module builds on the earlier ones. Module 02 taught you Linux permissions, capabilities, and firewalls, which are the exact mechanisms containers are built from. Module 03 taught you to keep secrets out of Git, and you will see how secrets also leak into **images**. Module 05 introduced vulnerabilities, CVEs, and SBOMs, which you now apply to container images.

> [!IMPORTANT]
> **Lab environment:** You need **Docker Engine** (or Docker Desktop) and a terminal. Linux, macOS, or Windows with WSL2 all work. The labs use **fake secrets**, a **deliberately insecure** sample image, and a **local registry bound to `127.0.0.1`**. Never push the insecure sample image to a public registry or run it on a public network.

## 🎯 Learning Objectives

By the end of this module, you will be able to:

- Understand container security risks and attack surfaces.
- Identify common Dockerfile security issues.
- Build secure and minimal container images.
- Understand container image layers and registries.
- Scan container images for vulnerabilities using Trivy.
- Understand vulnerability severity and remediation.
- Generate and inspect container image SBOMs.
- Sign container images using Cosign.
- Verify container image signatures before deployment.
- Integrate container security into GitHub Actions and Jenkins.
- Apply container security best practices in production environments.

## 📚 Table of Contents

1. [Introduction to Container Security](#1-introduction-to-container-security)
2. [Docker Security Architecture](#2-docker-security-architecture)
3. [Common Container Security Risks](#3-common-container-security-risks)
4. [Writing Secure Dockerfiles](#4-writing-secure-dockerfiles)
5. [Container Image Security Best Practices](#5-container-image-security-best-practices)
6. [Introduction to Trivy](#6-introduction-to-trivy)
7. [Installing Trivy](#7-installing-trivy)
8. [Scanning Container Images with Trivy](#8-scanning-container-images-with-trivy)
9. [Understanding Vulnerability Reports](#9-understanding-vulnerability-reports)
10. [Remediating Container Vulnerabilities](#10-remediating-container-vulnerabilities)
11. [Introduction to Cosign](#11-introduction-to-cosign)
12. [Signing Container Images with Cosign](#12-signing-container-images-with-cosign)
13. [Verifying Container Image Signatures](#13-verifying-container-image-signatures)
14. [Container Security in CI/CD](#14-container-security-in-cicd)
15. [Runtime Security Fundamentals](#15-runtime-security-fundamentals)
16. [Hands-On Labs](#16-hands-on-labs)
17. [Best Practices](#17-best-practices)
18. [Knowledge Check](#18-knowledge-check)
19. [Official References](#19-official-references)

---

## 1. Introduction to Container Security

### What Is a Container?

A **container** is a running program packaged together with everything it needs (libraries, runtime, configuration) so it behaves the same on any machine. A container is **not** a tiny virtual machine. It is an ordinary Linux process that the kernel **isolates** from other processes.

| Term | Meaning |
| :--- | :--- |
| **Image** | A read-only template: the files and settings needed to run an application. |
| **Container** | A **running instance** of an image. |
| **Dockerfile** | A text recipe for building an image. |
| **Registry** | A server that stores and distributes images (Docker Hub, GitHub Container Registry, and others). |
| **Tag** | A human-friendly label for an image version, such as `python:3.12-slim`. Tags can **move**. |
| **Digest** | A unique fingerprint of an image, such as `sha256:ab12...`. A digest **never changes**. |

### Containers vs. Virtual Machines

```text
        VIRTUAL MACHINES                              CONTAINERS

 +-------+ +-------+ +-------+              +-------+ +-------+ +-------+
 | App A | | App B | | App C |              | App A | | App B | | App C |
 | Libs  | | Libs  | | Libs  |              | Libs  | | Libs  | | Libs  |
 | Guest | | Guest | | Guest |              +-------+ +-------+ +-------+
 |  OS   | |  OS   | |  OS   |              +---------------------------+
 +-------+ +-------+ +-------+              |   Container runtime       |
 +---------------------------+              +---------------------------+
 |        Hypervisor         |              |   ONE shared HOST KERNEL  |
 +---------------------------+              +---------------------------+
 |        Host hardware      |              |        Host hardware      |
 +---------------------------+              +---------------------------+
```

> [!IMPORTANT]
> **All containers on a host share the host's kernel.** A virtual machine has its own kernel, so a flaw inside it is usually contained. If an attacker escapes a container, they land on the **host**, and from there they can reach **every other container**. This is why container isolation settings matter so much.

### Why Container Security Matters

| Reason | Explanation |
| :--- | :--- |
| **Images are code you did not write** | A typical image contains hundreds of OS packages and libraries from other people. |
| **Speed multiplies mistakes** | One bad base image can be copied into hundreds of deployments within hours. |
| **Defaults favor convenience** | Containers run as `root` by default, and many images ship with shells, compilers, and package managers an attacker can use. |
| **Shared kernel** | A breakout affects the whole host. |
| **Supply chain exposure** | Images are pulled from the internet, and anyone can publish one. |

### The Container Lifecycle and Where Security Fits

```text
   BUILD                  SHIP                    DEPLOY                 RUN
+---------+          +-----------+          +---------------+      +-------------+
| Write   |  build   | Push to   |  pull    | Orchestrator  | start| Container   |
| Docker- | -------> | registry  | -------> | (Docker,      |----->| running on  |
| file    |          |           |          |  Kubernetes)  |      | a host      |
+---------+          +-----------+          +---------------+      +-------------+
    |                     |                        |                     |
 Secure the           Scan, sign,              Verify signature,     Least privilege,
 Dockerfile and       SBOM, protect            enforce policy        resource limits,
 base image           the registry                                   monitoring
```

This module follows that path: **secure the build** (sections 4 and 5), **scan** (6 to 10), **sign and verify** (11 to 13), **automate** (14), and **protect at runtime** (15).

### The Container Attack Surface

| Layer | What Can Go Wrong |
| :--- | :--- |
| **Application and its dependencies** | Vulnerable libraries and insecure code (Modules 04 and 05) |
| **Image contents** | Vulnerable OS packages, unnecessary tools, embedded secrets, malware |
| **Dockerfile and build process** | Running as root, leaked secrets, unpinned or untrusted base images |
| **Registry** | Stolen credentials, overwritten tags, malicious or typosquatted images |
| **Container runtime and Docker daemon** | Exposed daemon API, runtime vulnerabilities (for example, `runc` flaws) |
| **Container configuration** | `--privileged`, mounted Docker socket, excessive capabilities, no resource limits |
| **Host operating system** | Unpatched kernel, weak host configuration (Module 02) |
| **Network** | Open ports, flat networks where every container can reach every other |
| **CI/CD pipeline and tools** | Compromised actions, stolen registry or signing credentials (Module 03) |

---

## 2. Docker Security Architecture

### How Docker Is Built

```text
 You type:  docker run nginx
      |
      v
+---------------+    REST API     +---------------------+
| Docker CLI    | --------------> | Docker daemon       |   (dockerd: runs as ROOT)
| (client)      |  (unix socket)  | images, networks,   |
+---------------+                 | volumes, build      |
                                  +----------+----------+
                                             |
                                             v
                                  +---------------------+
                                  | containerd          |   manages container lifecycle
                                  +----------+----------+
                                             |
                                             v
                                  +---------------------+
                                  | runc                |   creates the isolated process
                                  +----------+----------+
                                             |
                                             v
                                  +---------------------+
                                  | LINUX KERNEL        |   namespaces, cgroups, capabilities,
                                  +---------------------+   seccomp, AppArmor / SELinux
```

> [!WARNING]
> **The Docker daemon runs as root, and anyone who can talk to it is effectively root on the host.** Being a member of the `docker` group, or having access to `/var/run/docker.sock`, is equivalent to having `sudo` without a password. Treat both as highly privileged.

### The Linux Features Behind Containers (Module 02 Revisited)

A container is a **normal process wrapped in several kernel isolation features**:

| Feature | What It Does | Analogy |
| :--- | :--- | :--- |
| **Namespaces** | Give the process its **own view** of the system: its own process list (PID), network, filesystem mounts, hostname, and users | A separate apartment with its own front door and address |
| **cgroups** (control groups) | **Limit** how much CPU, memory, and processes a container may use | A power and water meter with a limit |
| **Capabilities** | Split root's powers into pieces. Containers start with a **reduced** set | A key ring holding only some keys |
| **seccomp** | Filters which **system calls** a process may make. Docker's default profile blocks dozens of risky calls | A bouncer checking what each request asks for |
| **AppArmor / SELinux** | Mandatory access control: restricts files and actions even for root | A building policy that overrides the tenant |
| **Union filesystem** | Stacks read-only image layers with a thin writable layer on top | Transparent sheets stacked on one another |

The main namespaces:

| Namespace | Isolates |
| :--- | :--- |
| `pid` | Process IDs (the container sees itself as PID 1) |
| `net` | Network interfaces, ports, and routing |
| `mnt` | Filesystem mount points |
| `uts` | Hostname |
| `ipc` | Shared memory and messaging |
| `user` | User and group IDs (root in the container can map to an unprivileged user on the host) |
| `cgroup` | The cgroup view |

### Docker's Default Capabilities

By default Docker gives containers a **reduced set of about 14 capabilities**, such as `CHOWN`, `SETUID`, `SETGID`, `NET_BIND_SERVICE`, `KILL`, and `NET_RAW`. Most applications need almost none of these.

```bash
# Good practice: drop everything, add back only what you need
docker run --cap-drop ALL --cap-add NET_BIND_SERVICE nginx
```

### Rootless Docker and User Namespaces

| Option | What It Does | Benefit |
| :--- | :--- | :--- |
| **Rootless mode** | Runs the Docker daemon and containers **without root** on the host | A breakout lands as an unprivileged user |
| **User namespace remapping** | Maps container root (UID 0) to a high, unprivileged host UID | "Root" in the container is **not** root on the host |
| **Non-root `USER` in the image** | The application never runs as UID 0 in the first place | Simplest and most widely effective |

### Images, Layers, and Registries

**Images are made of layers.** Each Dockerfile instruction that changes files (`RUN`, `COPY`, `ADD`) creates a **read-only layer**. Layers are stacked, and the container adds a thin writable layer on top.

```text
Dockerfile                          Image layers (read-only)

FROM python:3.12-slim      -->     [ Layer 1-4: base OS + Python ]
RUN pip install flask      -->     [ Layer 5: installed packages ]
COPY app.py /app/          -->     [ Layer 6: your code          ]
                                   [ Writable container layer    ]   <-- only exists at runtime
```

**Why layers matter for security:**

| Fact | Security Consequence |
| :--- | :--- |
| Layers are **permanent history** | A secret added in one layer and "deleted" in a later layer **remains in the earlier layer**. This is the same lesson as Git history in Module 03. |
| Anyone with the image can run `docker history` | `ENV` and `ARG` values and commands are visible. |
| Layers are shared and cached | A vulnerable base layer is reused everywhere it appears. |
| More tools in a layer means more attack surface | Compilers and shells help attackers as much as developers. |

```bash
docker history --no-trunc <image>        # every instruction that built the image
docker inspect <image>                   # environment variables, user, ports, entrypoint
```

**Registries** store images by name and tag:

```text
ghcr.io / my-org / my-app : 1.4.2          @sha256:3f1c...e9
 \_____/   \_____/ \____/   \____/          \___________/
 registry  owner   repo      tag              digest (immutable fingerprint)
```

| Registry | Notes |
| :--- | :--- |
| **Docker Hub** | Default public registry. Contains official, verified-publisher, and **community** images (not all trustworthy). Has pull rate limits. |
| **GitHub Container Registry (GHCR)** | `ghcr.io`, integrates with GitHub Actions and permissions. |
| **Cloud registries** | Amazon ECR, Azure ACR, Google Artifact Registry. |
| **Self-hosted** | Harbor (includes scanning and signing support), or the simple `registry:2` image used in the labs. |

### Tags vs. Digests: A Crucial Difference

| | **Tag** (`myapp:1.0`) | **Digest** (`myapp@sha256:3f1c...`) |
| :--- | :--- | :--- |
| **Can change?** | **Yes.** Anyone with push access can point the tag at different content. | **No.** It is a cryptographic fingerprint of the exact content. |
| **Safe for deployment pinning?** | ⚠️ No | ✅ Yes |
| **Easy to read?** | ✅ Yes | ❌ No |

> **Rule:** use tags to **find** an image, but use **digests** to **identify** it for scanning, signing, and deployment.

---

## 3. Common Container Security Risks

### Risk Overview

| # | Risk | Example | Impact | Main Control |
| :---: | :--- | :--- | :--- | :--- |
| 1 | **Vulnerable base image or packages** | `python:3.8` (end of life) with hundreds of known CVEs | Attackers exploit known flaws | Scanning, updated minimal base images |
| 2 | **Running as root** | No `USER` instruction in the Dockerfile | A compromised app has full power inside the container | Non-root `USER` |
| 3 | **Embedded secrets** | `ENV API_KEY=...` or a copied `.env` file | Anyone with the image gets the secret | Build secrets, `.dockerignore`, runtime injection |
| 4 | **Bloated images** | Shells, compilers, `curl`, package managers left in | Easier post-exploitation | Multi-stage builds, minimal or distroless bases |
| 5 | **Untrusted images** | Pulling `random-user/cool-tool` from Docker Hub | Malware, cryptominers, backdoors | Official or verified sources, scanning, signature verification |
| 6 | **Mutable tags** | Deploying `myapp:latest` | You cannot tell what is running; tag can be silently replaced | Digest pinning, immutable tags |
| 7 | **Privileged containers** | `docker run --privileged` | Almost no isolation from the host | Never use it; add only needed capabilities |
| 8 | **Mounted Docker socket** | `-v /var/run/docker.sock:/var/run/docker.sock` | The container can control the host's Docker, which means **root on the host** | Avoid; use safer build methods |
| 9 | **Host mounts and namespaces** | `-v /:/host`, `--pid=host`, `--network=host` | Container reads or changes the host | Mount only what is needed, read-only |
| 10 | **Exposed Docker API** | Daemon listening on TCP 2375 without TLS | Anyone on the network can start containers on the host (commonly abused for cryptomining) | Never expose it; use the local socket, SSH, or mutual TLS |
| 11 | **No resource limits** | One container uses all memory or processes | Denial of service for the whole host | `--memory`, `--cpus`, `--pids-limit` |
| 12 | **Flat networks** | Every container can talk to every other | Easy lateral movement | User-defined networks, network policies |
| 13 | **Outdated container runtime** | Unpatched Docker, `containerd`, or `runc` | Container breakout (for example, the 2024 `runc` flaw CVE-2024-21626) | Keep the runtime and host patched |
| 14 | **Compromised pipeline or registry credentials** | Stolen CI token pushes a malicious image | Malicious code reaches production | Short-lived credentials, signing, verification |
| 15 | **Compromised security tooling** | A poisoned scanner or CI action | Credential theft from your pipeline | Pin and verify tools (see the case study in section 7) |

### Why `--privileged` and the Docker Socket Are So Dangerous

```text
 Normal container                          Privileged container, or one with the Docker socket

 +---------------------+                   +---------------------+
 |  App (limited)      |                   |  App (almost host)  |
 +---------------------+                   +---------------------+
  isolated by namespaces,                   most protections OFF,
  capabilities, seccomp                     or can ask the host's Docker
                                            to start ANY container,
         |                                  including one that mounts "/"
         v                                          |
   Host is protected                                v
                                              Host is exposed
```

You will see a safe demonstration in Lab 1.

### Real-World Patterns

| Pattern | What Happened in Practice |
| :--- | :--- |
| **Cryptojacking** | Attackers find exposed Docker APIs or vulnerable containers and run cryptocurrency miners. |
| **Malicious public images** | Images on public registries have contained miners and credential stealers disguised as useful tools. |
| **Leaked secrets in images** | Cloud keys and tokens published inside public images are found and abused by scanners. |
| **Container breakouts** | Runtime flaws let a process escape to the host when the runtime is unpatched. |
| **Poisoned build tools** | Pipeline tools and actions were compromised, stealing the secrets of everyone who ran them. |

---

## 4. Writing Secure Dockerfiles

### A Dockerfile With Problems

Here is a typical beginner Dockerfile. Count the problems before reading the list.

```dockerfile
FROM python:3.8                          # (1)
ENV API_KEY=not-a-real-key-demo-123      # (2)
WORKDIR /app
COPY . .                                 # (3)
RUN pip install -r requirements.txt      # (4)
EXPOSE 5000
CMD ["python", "app.py"]                 # (5)
```

| # | Problem | Why It Is a Risk |
| :---: | :--- | :--- |
| 1 | **Old, large, unpinned base image** (`python:3.8` is end of life) | Hundreds of unpatched OS and Python vulnerabilities. The tag also moves. |
| 2 | **Secret in `ENV`** | Visible in `docker history`, `docker inspect`, and every container's environment. |
| 3 | **`COPY . .` copies everything** | Includes `.git`, `.env`, private keys, test data, and notes. |
| 4 | **Unpinned or cache-heavy installs, no `--no-cache-dir`** | Unpredictable versions and leftover cache. |
| 5 | **No `USER`, so it runs as root** | A compromise gives root inside the container. |
| 6 | (Not shown) **No `HEALTHCHECK`**, no `.dockerignore`, no multi-stage build | Less visibility, bigger image, more tools in the final image. |

### The Hardened Version

```dockerfile
# syntax=docker/dockerfile:1

############ Stage 1: build (tools and caches stay HERE) ############
FROM python:3.12-slim AS builder
WORKDIR /build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY requirements.txt .
RUN python -m venv /opt/venv && /opt/venv/bin/pip install -r requirements.txt

############ Stage 2: runtime (only what is needed to RUN) ############
FROM python:3.12-slim

# A dedicated, unprivileged user with a fixed numeric ID
RUN groupadd --gid 10001 app \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --chown=app:app app.py .

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')"]

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]
```

### Rule-by-Rule Explanation

| Practice | Instruction | Why |
| :--- | :--- | :--- |
| **Small, current base image** | `FROM python:3.12-slim` | Fewer packages means fewer vulnerabilities and less for attackers to use. |
| **Pin the base image** | `FROM python:3.12-slim@sha256:<digest>` | Guarantees you get exactly the image you tested. Let Dependabot or Renovate propose digest updates. |
| **Multi-stage build** | `FROM ... AS builder`, then `COPY --from=builder` | Compilers, caches, and build tools never reach the final image. |
| **Non-root user** | `USER 10001:10001` | Limits damage if the application is compromised. Use a **numeric** ID so Kubernetes can verify it is non-root (Module 08). |
| **Copy only what you need** | `COPY app.py .` plus a `.dockerignore` | Prevents accidental inclusion of secrets and junk. |
| **Set file ownership while copying** | `COPY --chown=app:app` | Avoids a separate `chown` layer. |
| **No secrets in `ENV` or `ARG`** | Use BuildKit secrets or runtime injection | Values in `ENV`, `ARG`, and `RUN` commands are recorded in image history. |
| **Pin dependencies** | `requirements.txt` with exact versions, lock files | Reproducible, reviewable builds. |
| **No cache files** | `PIP_NO_CACHE_DIR=1`, `--no-install-recommends`, delete apt lists | Smaller image and fewer files. |
| **Exec form for commands** | `CMD ["gunicorn", ...]` | The application receives signals correctly and no shell is involved. |
| **Health check** | `HEALTHCHECK` | Lets orchestrators detect a broken container. |
| **Production server** | `gunicorn`, not the Flask development server | The dev server is not designed for hostile traffic. |

### Install OS Packages Safely

```dockerfile
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
```

One `RUN` keeps the update and install in the **same layer**, `--no-install-recommends` avoids extras, and the last command removes the package index. Install only what the **running** application truly needs.

### Handling Secrets During a Build

Sometimes a build really needs a credential, for example to download a private package. Use **BuildKit secrets**, which are available to one `RUN` step and **never stored in a layer**.

```dockerfile
# syntax=docker/dockerfile:1
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN --mount=type=secret,id=pip_conf,target=/etc/pip.conf \
    pip install --no-cache-dir -r requirements.txt
```

```bash
docker build --secret id=pip_conf,src=./pip.conf -t myapp:1.0 .
```

| Method | Safe? | Why |
| :--- | :---: | :--- |
| `ENV TOKEN=...` | ❌ | Permanent in image metadata |
| `ARG TOKEN=...` with `--build-arg` | ❌ | Recorded in image history |
| `COPY .env .` then `RUN rm .env` | ❌ | The file still exists in the earlier layer |
| `RUN --mount=type=secret ...` | ✅ | Exists only during that step |
| Injecting the secret at **runtime** (mounted file or secrets manager) | ✅ | Never in the image at all |

### The `.dockerignore` File

It stops files from being sent to the build and copied by accident.

```text
# .dockerignore
.git
.gitignore
.env
.env.*
*.pem
*.key
id_rsa*
node_modules
__pycache__
*.pyc
tests/
docs/
Dockerfile
docker-compose*.yml
*.md
```

### `COPY` vs. `ADD`

| Instruction | Behavior | Guidance |
| :--- | :--- | :--- |
| `COPY` | Copies files from the build context | ✅ Use this by default |
| `ADD` | Also fetches **URLs** and auto-extracts archives | ⚠️ Avoid. Downloads without verification are risky. |

If you must download something, use `RUN curl` and **verify a checksum or signature** before using it.

### Lint Your Dockerfile

**Hadolint** is a Dockerfile linter that catches common problems:

```bash
docker run --rm -i hadolint/hadolint < Dockerfile
```

Typical messages: *DL3002* (last `USER` should not be root), *DL3006* (tag the image version), *DL3008* and *DL3013* (pin package versions), *DL3025* (use JSON form for `CMD`). **Trivy** can also scan Dockerfiles for misconfigurations (`trivy config .`, section 8).

### Language Examples: Minimal Final Images

**Go** (static binary, no OS needed):

```dockerfile
FROM golang:1.23 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/app .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
USER 65532:65532
ENTRYPOINT ["/app"]
```

**Node.js** (distroless runtime):

```dockerfile
FROM node:22-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .

FROM gcr.io/distroless/nodejs22-debian12:nonroot
WORKDIR /app
COPY --from=build /app /app
CMD ["server.js"]
```

> [!NOTE]
> Image names and version tags change. Check the project documentation (for example, the distroless repository) for the current names before using them.

---

## 5. Container Image Security Best Practices

### Choose a Good Base Image

The base image is the **largest part of your attack surface**. Pick the smallest one that works.

| Base Image Type | Examples | Size | Pros | Cons |
| :--- | :--- | :---: | :--- | :--- |
| **Full OS** | `ubuntu`, `debian`, `python:3.12` | Large | Familiar, many tools | Hundreds of packages, many CVEs |
| **Slim** | `python:3.12-slim`, `node:22-slim` | Medium | Fewer packages, still easy to use | Some tools missing |
| **Alpine** | `alpine`, `python:3.12-alpine` | Small | Tiny, minimal packages | Uses `musl` instead of `glibc`, which can break some software |
| **Distroless** | `gcr.io/distroless/*` | Very small | **No shell and no package manager**. Only your app and its runtime. | Harder to debug (no shell) |
| **Scratch** | `FROM scratch` | Tiny | Nothing but your static binary | Only for static binaries |
| **Hardened minimal images** | Commercial and community "hardened" image catalogs | Small | Built for low CVE counts and fast patching | Check licensing and update policy |

```text
Typical vulnerability counts (illustrative only):

 python:3.12        ##########################  many OS packages, many findings
 python:3.12-slim   ########                    fewer
 distroless         ##                          very few
```

### Where Your Images Come From

| Source | Trust Level | Advice |
| :--- | :--- | :--- |
| **Docker Official Images** | High (maintained, scanned) | Preferred starting point |
| **Verified Publisher** images | Good | Acceptable for well-known vendors |
| **Your organization's own base images** | High (you control them) | Best for consistency: build once, harden, scan, sign, then reuse |
| **Random community images** | Low | Avoid, or inspect and rebuild from source |
| **Typosquatted names** (`pythom`, `ngnix`) | Hostile | Double-check spellings and publishers |

### Tagging and Pinning Strategy

| Practice | Why |
| :--- | :--- |
| **Never deploy `:latest`** | You cannot tell what it is, and it changes without notice. |
| **Use specific version tags** (`1.4.2`) plus the **git commit SHA** (`1.4.2-3f9a1c2`) | Traceable and reproducible. |
| **Pin base images by digest** in the Dockerfile | Builds do not change underneath you. |
| **Deploy by digest** (`myapp@sha256:...`) | What you scanned and signed is exactly what runs. |
| **Use immutable tags** in your registry if supported | Prevents overwriting a released tag. |

Find a digest:

```bash
docker buildx imagetools inspect python:3.12-slim      # shows the digest
docker inspect --format '{{index .RepoDigests 0}}' python:3.12-slim
```

### Keep Images Fresh

New vulnerabilities are discovered **every day**, even in code that has not changed. An image that was clean last month may not be clean today.

- **Rebuild regularly** (for example, nightly or weekly) to pick up patched base images.
- Use `docker build --pull --no-cache` when you need to force fresh layers.
- Let **Dependabot** or **Renovate** propose base image updates (Module 03, section 4.8: the `docker` ecosystem).
- **Rescan** images that are already deployed and in the registry, not only at build time.

### Remove What You Do Not Need

| Remove | Why |
| :--- | :--- |
| **Shells and debug tools** (in the final image) | Attackers use them after a compromise. |
| **Compilers and build tools** | Use multi-stage builds. |
| **Package manager caches** | Smaller and cleaner. |
| **Test files, documentation, `.git`** | Not needed to run. |
| **SUID and SGID binaries** that are unnecessary | Privilege escalation paths (Module 02). |

### Registry Security

| Practice | Why |
| :--- | :--- |
| **Use private repositories** for internal images | Stops outsiders from pulling your images and studying them. |
| **Least-privilege tokens** (read-only for deployers, write only for CI) | Limits the damage of a leaked credential. |
| **Short-lived credentials** (OIDC, temporary tokens) | Nothing long-lived to steal. |
| **Never store registry passwords in code** | See Module 03. |
| **Enable scan-on-push** if your registry supports it | Findings appear as soon as an image arrives. |
| **Enforce immutable tags and retention policies** | Prevents overwriting and keeps history. |
| **Log and review pushes** | You can see who published what and when. |
| **Protect `~/.docker/config.json`** | It can contain registry credentials. Use credential helpers and `docker login --password-stdin`. |

```bash
# Safer login: the password is not placed on the command line or in shell history
echo "$REGISTRY_TOKEN" | docker login ghcr.io -u "$REGISTRY_USER" --password-stdin
```

### Image Security Checklist

- [ ] Base image is minimal, current, and from a trusted source
- [ ] Base image is pinned by digest (or by exact version at minimum)
- [ ] Multi-stage build keeps tools out of the final image
- [ ] Runs as a **non-root numeric user**
- [ ] No secrets in `ENV`, `ARG`, `COPY`, or layers
- [ ] `.dockerignore` exists and excludes secrets and junk
- [ ] Dependencies are pinned
- [ ] Image is **scanned** and meets the vulnerability policy
- [ ] An **SBOM** is generated and stored
- [ ] Image is **signed**, and the signature is **verified** before deployment
- [ ] Deployed **by digest**

---

## 6. Introduction to Trivy

### What Is Trivy?

**Trivy** is a free, open-source security scanner from Aqua Security. One tool and one command scan many kinds of targets for several kinds of problems, which is why it is so widely used in pipelines.

### What Trivy Can Scan

| Target | Command | Typical Use |
| :--- | :--- | :--- |
| **Container image** | `trivy image <image>` | Find vulnerable OS packages and libraries inside images |
| **Image saved as a tar file** | `trivy image --input image.tar` | Scan without needing a Docker daemon or socket |
| **Local folder or project** | `trivy fs .` | Scan source dependencies and lock files |
| **Git repository** | `trivy repo <url>` | Scan a remote repo |
| **Infrastructure as Code and Dockerfiles** | `trivy config .` | Find misconfigurations (Dockerfile, Terraform, Kubernetes manifests) |
| **SBOM file** | `trivy sbom <file>` | Scan an existing software bill of materials |
| **Kubernetes cluster** | `trivy k8s ...` | Cluster and workload scanning (Module 08) |

### What Trivy Can Find (Scanners)

| Scanner | Finds | Flag |
| :--- | :--- | :--- |
| **Vulnerabilities** | Known CVEs in OS packages and language libraries | `--scanners vuln` |
| **Secrets** | Passwords, API keys, tokens, private keys in files | `--scanners secret` |
| **Misconfigurations** | Insecure settings in Dockerfiles, Terraform, Kubernetes YAML | `--scanners misconfig` |
| **Licenses** | Open-source licenses of included software | `--scanners license` |

For `trivy image`, the default scanners are **vulnerabilities and secrets**.

### How Trivy Scans an Image

```text
 1. GET THE IMAGE        from a registry, the local Docker daemon, or a .tar file
         |
         v
 2. UNPACK LAYERS        read every layer's files
         |
         v
 3. IDENTIFY SOFTWARE
         |-- OS and version      (/etc/os-release)
         |-- OS packages         (dpkg, apk, rpm databases)
         '-- Language packages   (package-lock.json, requirements.txt, METADATA, go binaries ...)
         |
         v
 4. MATCH AGAINST THE VULNERABILITY DATABASE  (downloaded and cached locally)
         |      sources: Debian, Ubuntu, Alpine, Red Hat advisories, GitHub Advisory
         |      Database, NVD, language ecosystem databases ...
         v
 5. REPORT               table, JSON, SARIF, SBOM ... and an exit code for pipelines
```

> [!NOTE]
> This is the same idea as the SCA tools of Module 05: **identify components, then look them up in a database of known vulnerabilities**. Trivy simply does it for the whole image, including the operating system.

### Trivy vs. Other Tools

| Tool | Notes |
| :--- | :--- |
| **Trivy** | All-in-one: vulnerabilities, secrets, misconfigurations, SBOM, licenses. Very popular in CI. |
| **Grype** (with **Syft**) | Grype scans for vulnerabilities, Syft generates SBOMs. A fine pairing. |
| **Docker Scout** | Docker's own analysis, integrated with Docker Desktop and Docker Hub. |
| **Clair** | Registry-oriented scanner used by some registries. |
| **Snyk, Prisma, and other commercial tools** | Add dashboards, policy management, and support. |

> **No scanner is perfect.** Different tools use different data and can report different numbers. Pick one, understand its output, and use it consistently.

---

## 7. Installing Trivy

### ⚠️ Case Study: When the Scanner Becomes the Target

> [!WARNING]
> **In March 2026, Trivy itself was the victim of a supply chain attack.** This is a real-world lesson that belongs in every DevSecOps course.
>
> **What happened (summary of the public advisories):**
> - On **19 March 2026**, attackers used stolen credentials to publish a **malicious Trivy release (v0.69.4)** and to **overwrite 75 of 76 version tags of the `aquasecurity/trivy-action` GitHub Action** (plus the tags of `aquasecurity/setup-trivy`), pointing them at malicious code.
> - Later malicious Docker image tags (`0.69.5` and `0.69.6`) were also published.
> - The malicious code **stole secrets** from CI runners (cloud keys, tokens, SSH keys, registry credentials) and then ran the **real scan**, so builds looked completely normal.
> - Pipelines using a **moving tag** such as `trivy-action@0.28.0` silently ran attacker code, **even though nobody changed their workflow file**.
>
> **Lessons:**
>
> | Lesson | What To Do |
> | :--- | :--- |
> | **Tags can be moved** | Pin GitHub Actions to a **full commit SHA**, never a tag (Module 03, section 12). |
> | **"Latest" is a risk** | Pin tool **versions** (binary, Docker image tag or digest). Never auto-install `latest`. |
> | **Security tools are high-value targets** | They run with access to your secrets. Treat them like any other third-party dependency. |
> | **Verify what you download** | Check **checksums** and **signatures** (Cosign) of releases. |
> | **Limit what a CI job can steal** | Least-privilege tokens, short-lived credentials, no long-lived cloud keys in CI (OIDC). |
> | **Have a response plan** | If a compromised version might have run, **rotate every secret** that job could access. |
>
> The affected versions were **v0.69.4** (binary, with image tags `0.69.4` to `0.69.6`) and unpinned references to the actions. Aqua's advisory listed **v0.69.3** and earlier as safe at the time, and later releases were published after the incident. Always read the **current official advisory** and install a release you have **verified**.

You can read the primary sources in the references (section 19). Keep this story in mind in every pipeline you build: **the same supply chain thinking you apply to your application applies to your security tools.**

### Choose an Installation Method

| Method | Best For | Notes |
| :--- | :--- | :--- |
| **Download a release and verify it** | CI servers, careful installs | ✅ Recommended. Pin the version, verify the checksum and signature. |
| **Docker image (pinned tag)** | Quick use, isolated CI jobs | Pin an exact tag (or digest). Never `latest`. |
| **Package manager** (`apt`, `brew`) | Laptops | Convenient. Check the version you get. |
| **`curl ... \| sh` install scripts** | — | ❌ Avoid. You execute unreviewed code. |

Choose a version from the **official releases page** and set it as a variable. In this module the examples use `0.71.0` only as an **example**. Use the newest release you have verified.

### Option 1: Download, Verify, and Install (Linux)

```bash
TRIVY_VERSION=0.71.0           # example only: use a current release you have verified
BASE="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"
FILE="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"

# 1. Download the release and its checksum list
curl -sSfL -O "${BASE}/${FILE}"
curl -sSfL -O "${BASE}/trivy_${TRIVY_VERSION}_checksums.txt"

# 2. Verify the checksum (must print: "OK")
sha256sum --check --ignore-missing "trivy_${TRIVY_VERSION}_checksums.txt"

# 3. Install
sudo tar -xzf "${FILE}" -C /usr/local/bin trivy

# 4. Confirm
trivy --version
```

On ARM machines, replace `Linux-64bit` with `Linux-ARM64`. On other systems use the matching file from the releases page.

> [!TIP]
> **A checksum from the same page as the download only protects against corruption**, not against a compromised release. For stronger assurance, also verify the **signature** below.

### Verify the Signature With Cosign (Stronger)

Since Trivy v0.68.1, each release asset has a signature bundle (`.sigstore.json`). With Cosign v3:

```bash
curl -sSfL -O "${BASE}/${FILE}.sigstore.json"

cosign verify-blob "${FILE}" \
  --bundle "${FILE}.sigstore.json" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v${TRIVY_VERSION}"
```

`Verified OK` means the file was produced by the official Trivy release workflow for that tag. (With Cosign v2.4 or newer, add `--new-bundle-format`. Check Trivy's "signature verification" documentation for the current command.) You will learn how Cosign works in sections 11 to 13.

### Option 2: Docker Image

```bash
TRIVY_VERSION=0.71.0           # example only: use a verified release

docker run --rm \
  -v trivy-cache:/root/.cache/ \
  -v "$PWD:/work" \
  aquasec/trivy:${TRIVY_VERSION} image --input /work/myimage.tar
```

| Part | Why |
| :--- | :--- |
| `aquasec/trivy:${TRIVY_VERSION}` | **Pinned tag.** For stronger protection, pin the image **digest**. |
| `-v trivy-cache:/root/.cache/` | Keeps the vulnerability database between runs (otherwise it downloads every time). |
| `--input /work/myimage.tar` | Scans an image you exported with `docker save`. **No Docker socket needed.** |

> [!CAUTION]
> Many tutorials mount the Docker socket into the Trivy container (`-v /var/run/docker.sock:...`) so it can read local images. As you learned in section 3, that gives the container **control of the host's Docker**. Prefer `docker save` plus `--input`, or scan an image from a registry.

### Option 3: Package Managers (Laptops)

```bash
brew install trivy             # macOS and Linux with Homebrew
```

For Debian and Ubuntu, Trivy documents an APT repository on its website. Follow the **official installation page** for the exact, current steps, and verify the repository's signing key as instructed.

### The Vulnerability Database

Trivy downloads a **vulnerability database** the first time you scan, and refreshes it automatically. It is cached (by default under `~/.cache/trivy`).

```bash
trivy image --download-db-only                  # download or update the database now
trivy image --skip-db-update myapp:1.0          # use the cached database only (offline or faster runs)
```

If the download fails with `TOOMANYREQUESTS`, the default registry has rate-limited you. You can point Trivy at a mirror with `--db-repository` (see the official documentation for current mirror addresses) or cache the database in CI.

### Verify Your Installation

```bash
trivy --version
trivy image --help | head -20
trivy image python:3.12-slim          # first scan: downloads the database, then scans a public image
```

---

## 8. Scanning Container Images with Trivy

### Your First Scan

```bash
trivy image python:3.8
```

You will see a header (OS detected, database date) and then a table of findings:

```text
python:3.8 (debian 12.x)
========================
Total: 600 (UNKNOWN: 0, LOW: 300, MEDIUM: 200, HIGH: 80, CRITICAL: 20)    <- numbers are illustrative

┌───────────┬────────────────┬──────────┬──────────┬───────────────────┬───────────────┬─────────────────────┐
│  Library  │ Vulnerability  │ Severity │  Status  │ Installed Version │ Fixed Version │        Title        │
├───────────┼────────────────┼──────────┼──────────┼───────────────────┼───────────────┼─────────────────────┤
│ libssl3   │ CVE-XXXX-NNNN  │ CRITICAL │ fixed    │ 3.0.11-1          │ 3.0.13-1      │ openssl: ...        │
│ zlib1g    │ CVE-XXXX-NNNN  │ HIGH     │ affected │ 1:1.2.13          │               │ zlib: ...           │
└───────────┴────────────────┴──────────┴──────────┴───────────────────┴───────────────┴─────────────────────┘
```

Section 9 explains every column.

### Scan Your Own Local Image

```bash
docker build -t myapp:1.0 .

# Option A: Trivy reads the image from your local Docker daemon
trivy image myapp:1.0

# Option B: scan an exported tar file (no daemon access needed)
docker save myapp:1.0 -o myapp.tar
trivy image --input myapp.tar
```

### Filter the Output

| Goal | Option | Example |
| :--- | :--- | :--- |
| Show only important severities | `--severity` | `--severity HIGH,CRITICAL` |
| Hide vulnerabilities with **no available fix** | `--ignore-unfixed` | `--ignore-unfixed` |
| Choose what to scan for | `--scanners` | `--scanners vuln,secret,misconfig` |
| Only OS or only library packages | `--pkg-types` | `--pkg-types os` or `--pkg-types library` |
| Skip files or folders | `--skip-dirs`, `--skip-files` | `--skip-dirs /usr/share/doc` |

```bash
# A realistic day-to-day command
trivy image --severity HIGH,CRITICAL --ignore-unfixed myapp:1.0
```

### Output Formats and Reports

```bash
# JSON (best for scripts and gates)
trivy image --format json --output trivy-report.json myapp:1.0

# SARIF (for code scanning dashboards that accept it)
trivy image --format sarif --output trivy-report.sarif myapp:1.0

# Table saved to a file
trivy image --output trivy-report.txt myapp:1.0
```

| Format | `--format` value | Use |
| :--- | :--- | :--- |
| Table | `table` (default) | Reading in a terminal |
| JSON | `json` | Scripting, dashboards, gates |
| SARIF | `sarif` | GitHub code scanning and other tools |
| CycloneDX SBOM | `cyclonedx` | Software bill of materials |
| SPDX SBOM | `spdx`, `spdx-json` | Software bill of materials |
| Template | `template` | Custom reports (such as HTML) |

### Use Trivy as a Pipeline Gate

By default Trivy exits with `0` even when it finds vulnerabilities. Use `--exit-code` to make findings **fail the build**:

```bash
trivy image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed myapp:1.0
echo "Trivy exit code: $?"
```

| Exit Code | Meaning |
| :---: | :--- |
| `0` | Nothing at or above the chosen severities (or no `--exit-code`). The gate **passes**. |
| `1` | Findings at the selected severities exist. The gate **fails**. |

A common policy: **fail on CRITICAL and HIGH vulnerabilities that already have a fix**. Fixable issues are actionable, which keeps the gate fair.

### Scan for Secrets in an Image

```bash
trivy image --scanners secret myapp:1.0
```

Trivy looks for API keys, tokens, and private keys inside image files. If `COPY . .` accidentally copied a `.env` file, this finds it (Lab 3).

### Scan a Dockerfile and Other Config for Mistakes

```bash
trivy config .
```

Typical findings for a Dockerfile include **"Image user should not be 'root'"** (a missing `USER`) and **"No HEALTHCHECK defined"**. This scans the **recipe**, while `trivy image` scans the **result**. Use both.

### Scan the Project Folder (Before the Image Exists)

```bash
trivy fs --scanners vuln,secret,misconfig .
```

This checks dependency files such as `requirements.txt`, lock files, and configuration in your source folder, so problems are caught **before** you build.

### Scan Private Registries

```bash
# Trivy uses the credentials from your 'docker login', or these variables:
export TRIVY_USERNAME="$REGISTRY_USER"
export TRIVY_PASSWORD="$REGISTRY_TOKEN"
trivy image ghcr.io/my-org/myapp:1.0
```

Keep tokens in CI **secrets**, never in the command or the repository (Module 03).

### Generate an SBOM for an Image

An **SBOM** (Software Bill of Materials) lists everything inside the image, so you can answer questions like *"Which of our images contain this vulnerable library?"* in seconds. (SBOM formats, **CycloneDX** and **SPDX**, are covered in Module 05.)

**With Trivy:**

```bash
trivy image --format cyclonedx --output sbom.cdx.json myapp:1.0
trivy image --format spdx-json  --output sbom.spdx.json myapp:1.0
```

**With Syft (an alternative SBOM generator):**

```bash
syft myapp:1.0 -o cyclonedx-json=sbom.syft.cdx.json
syft myapp:1.0 -o spdx-json=sbom.syft.spdx.json
```

Install Syft the same careful way as Trivy (pinned version, verified download). See its official page.

### Inspect an SBOM

```bash
# How many components?
jq '.components | length' sbom.cdx.json

# List package names and versions
jq -r '.components[] | "\(.name)  \(.version)"' sbom.cdx.json | sort | head -30

# Is a particular package in the image?
jq -r '.components[] | select(.name=="flask") | "\(.name) \(.version)"' sbom.cdx.json
```

### Scan an SBOM for Vulnerabilities

```bash
trivy sbom sbom.cdx.json
```

This scans the **inventory** instead of the image. It is useful when you store SBOMs and want to **rescan them later against newer vulnerability data**, without the image itself.

### Handling Accepted Risks: `.trivyignore`

A `.trivyignore` file lists vulnerabilities to **skip**. Use it sparingly, with **comments** and **expiry dates**:

```text
# .trivyignore
# CVE-2024-XXXXX: not exploitable here, the vulnerable function is not called.
# Approved in SEC-231. Review before expiry.
CVE-2024-XXXXX exp:2026-12-31
```

> [!WARNING]
> A `.trivyignore` file is a **security control**. Anyone who can edit it can silence the gate. Protect it with **CODEOWNERS** and review its changes carefully, exactly like the rules file in Module 06.

### Speed Tips for CI

| Tip | Why |
| :--- | :--- |
| Cache the Trivy database between runs | Avoids a large download every time. |
| Scan **before** pushing to the registry | Bad images never leave the build. |
| Use `--ignore-unfixed` and `--severity` | Smaller, faster, more actionable reports. |
| Scan the **final** image, not intermediate stages | That is what you ship. |

---

## 9. Understanding Vulnerability Reports

### A Quick Refresher: CVE and CVSS

| Term | Meaning |
| :--- | :--- |
| **CVE** | A public ID for a specific vulnerability, such as `CVE-2024-12345`. |
| **CVSS score** | A 0 to 10 score of technical severity. |
| **CWE** | The **type** of weakness (for example, CWE-79 is XSS). |
| **EPSS** | A probability estimate that a CVE will be **exploited** soon. |
| **CISA KEV** | A list of vulnerabilities **known to be exploited** in the wild. |

(Module 05 covered CVE and CVSS in depth.)

### Reading the Trivy Table

| Column | Meaning | What To Do With It |
| :--- | :--- | :--- |
| **Library** | The affected package (`openssl`, `flask`, `zlib1g`) | Tells you what to update. |
| **Vulnerability** | The CVE ID | Search it for details and exploit status. |
| **Severity** | `UNKNOWN`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | Start prioritizing here. |
| **Status** | The fix state (see below) | Tells you whether a fix exists. |
| **Installed Version** | The version inside **your** image | Compare with the fixed version. |
| **Fixed Version** | The version that contains the fix (blank if none) | Your update target. |
| **Title** and link | Short description and reference | Read before deciding. |

### Understanding "Status"

| Status | Meaning | Typical Action |
| :--- | :--- | :--- |
| `fixed` | A patched version **exists** | **Update.** This is your easiest win. |
| `affected` | The package is vulnerable and **no fix is available yet** | Mitigate, monitor, consider another base image. |
| `will_not_fix` | The distribution has decided **not** to patch it | Accept with justification, or change base image. |
| `fix_deferred` | A fix is planned later | Track it and revisit. |
| `end_of_life` | The component or OS no longer receives updates | **Upgrade** to a supported version. |

### Severity Levels

| Severity | CVSS Range (approximate) | Typical Response |
| :--- | :--- | :--- |
| **CRITICAL** | 9.0 to 10.0 | Fix immediately, block release |
| **HIGH** | 7.0 to 8.9 | Fix urgently, block release for fixable issues |
| **MEDIUM** | 4.0 to 6.9 | Fix in normal maintenance |
| **LOW** | 0.1 to 3.9 | Fix opportunistically |
| **UNKNOWN** | Not rated | Investigate |

### Severity Is Not the Whole Story: Prioritize Wisely

A scanner may report **hundreds** of findings. You cannot, and do not need to, fix them all at once. Ask these questions:

```text
 For each finding, ask:

 1. Is a FIX AVAILABLE?            -> fixable issues come first
 2. Is it EXPLOITED in the wild?   -> on the CISA KEV list, or high EPSS? Move it up
 3. Is the component REACHABLE?    -> is the vulnerable code or package actually used?
 4. Is the container EXPOSED?      -> internet-facing, or isolated internal service?
 5. What DATA or ACCESS is at risk?-> a payment service outranks a demo page
 6. Can we REMOVE the component?   -> best fix of all: it is gone
```

> **Example:** A CRITICAL vulnerability in a `curl` binary that your running application never uses, in an image that is not internet-facing, is less urgent than a HIGH vulnerability in the web framework serving public traffic. Both need attention, but the order should follow **risk**, not just the label.

### Where Do Most Findings Come From?

In a typical image, the **OS packages from the base image** produce the **majority** of the findings, while your own libraries produce fewer, more actionable ones.

```text
 Findings by origin (typical pattern):

 Base image OS packages   ####################   most findings; fixed by changing/updating the base
 Language libraries       #####                  fixed by updating your dependencies
 Your own code            #                      found by SAST (Module 04), not by image scanning
```

That is why a better base image is often the **single biggest improvement**.

### Reading the JSON Report

```bash
trivy image --format json --output report.json myapp:1.0
```

The structure (simplified):

```json
{
  "ArtifactName": "myapp:1.0",
  "Results": [
    {
      "Target": "myapp:1.0 (debian 12.5)",
      "Class": "os-pkgs",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-XXXXX",
          "PkgName": "libssl3",
          "InstalledVersion": "3.0.11-1",
          "FixedVersion": "3.0.13-1",
          "Severity": "CRITICAL",
          "Title": "openssl: ...",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-xxxxx"
        }
      ]
    },
    { "Target": "Python", "Class": "lang-pkgs", "Vulnerabilities": [ ... ] }
  ]
}
```

Useful `jq` recipes:

```bash
# Count findings by severity
jq -r '[.Results[]?.Vulnerabilities[]?] | group_by(.Severity)
       | map("\(.[0].Severity): \(length)") | .[]' report.json

# List fixable CRITICAL and HIGH issues with the exact upgrade target
jq -r '.Results[]?.Vulnerabilities[]?
       | select((.Severity=="CRITICAL" or .Severity=="HIGH") and .FixedVersion != null)
       | "\(.Severity)  \(.VulnerabilityID)  \(.PkgName) \(.InstalledVersion) -> \(.FixedVersion)"' report.json | sort

# Which packages account for the most findings?
jq -r '.Results[]?.Vulnerabilities[]? | .PkgName' report.json | sort | uniq -c | sort -rn | head
```

### False Positives and Noise

| Situation | Explanation | Response |
| :--- | :--- | :--- |
| **Vulnerable code not used** | The package is present but the vulnerable function is never called | Document the reason (and optionally a VEX statement). Prefer removing the package. |
| **Distro backported the fix** | The version number looks old but the distribution patched it | Trivy normally uses distro data to handle this. Verify before ignoring. |
| **Vulnerability needs conditions you do not meet** | For example, a feature or configuration you do not enable | Document and re-evaluate if configuration changes. |
| **Wrong component identification** | Rare, can occur with unusual packaging | Verify manually and report to the tool's maintainers. |

For suppressions use `.trivyignore` with an **expiry and a reason**. Trivy also supports **VEX** (Vulnerability Exploitability eXchange) documents, which are structured statements such as "this product is **not affected** by CVE-X because...".

### Compare Before and After

When you change the base image or update a library, **compare reports** to prove improvement:

```bash
trivy image --format json -o before.json myapp:1.0
trivy image --format json -o after.json  myapp:1.1

for f in before after; do
  echo "== $f"
  jq -r '[.Results[]?.Vulnerabilities[]?] | group_by(.Severity) | map("\(.[0].Severity): \(length)") | .[]' $f.json
done
```

---

## 10. Remediating Container Vulnerabilities

### The Remediation Decision Path

```text
                       Finding in the report
                               |
              Which part of the image is it in?
             /                                  \
     OS package                          Language library / your dependency
  (from the base image)                  (pip, npm, Maven, Go modules ...)
             |                                       |
   +---------+------------+                 +--------+---------+
   |                      |                 |                  |
 Newer base image     No fix exists       Update to the     No fixed version
 fixes it?            for this OS yet     fixed version     available
   |                      |                 |                  |
 REBUILD on the       Switch to a         Update, test,     Replace the library,
 updated base         smaller / different  rebuild, rescan   mitigate, or accept
 (pull + rebuild)     base, remove the                       with expiry
                      package, or accept
```

### Fix 1: Rebuild on an Updated Base Image

Most OS-level fixes arrive simply by **pulling the newest version of your base image** and rebuilding.

```bash
docker pull python:3.12-slim                         # get the latest patched base
docker build --pull --no-cache -t myapp:1.1 .        # --pull checks for newer base layers
trivy image --severity HIGH,CRITICAL --ignore-unfixed myapp:1.1
```

Automate this with scheduled rebuilds and Dependabot or Renovate pull requests for base image updates.

### Fix 2: Choose a Smaller Base Image

```dockerfile
# Before: full image, hundreds of packages
FROM python:3.12

# After: slim image, far fewer packages
FROM python:3.12-slim

# Even better for suitable apps: distroless, no shell, no package manager
FROM gcr.io/distroless/python3-debian12:nonroot
```

Fewer packages means fewer findings **and** less for an attacker to use.

### Fix 3: Use a Multi-Stage Build

Vulnerabilities in **build tools** (compilers, `git`, `pip` caches) disappear when those tools never reach the final image (section 4).

### Fix 4: Update Application Dependencies

For a language library finding:

```text
CRITICAL  CVE-XXXX-NNNN  requests  2.25.0 -> 2.32.4
```

```bash
# Update the pinned version
sed -i 's/^requests==.*/requests==2.32.4/' requirements.txt     # or edit by hand

# Rebuild, rescan, and run your tests
docker build -t myapp:1.2 . && trivy image --severity HIGH,CRITICAL --ignore-unfixed myapp:1.2
```

Let **Dependabot** open these pull requests automatically (Module 03). Always run tests, because major version upgrades can break code.

### Fix 5: Remove Unneeded Packages

If a vulnerable package is not required to run the application, **uninstall it** (or never install it). A package that is not there cannot be exploited.

### Fix 6: When No Fix Exists

| Option | Details |
| :--- | :--- |
| **Mitigate** | Reduce exposure: block the vulnerable network path, disable the feature, add a WAF rule, restrict access. |
| **Change the base** | Another distribution may already have a fix or may not include the package. |
| **Accept the risk, temporarily** | Record it in `.trivyignore` (with `exp:` date, reason, and approver). |
| **Replace the component** | Use a different library or tool. |
| **Monitor** | Re-scan regularly. Fixes appear over time. |

### Verify the Fix

A fix is **not complete until you prove it**:

1. Rebuild the image.
2. **Rescan** it and confirm the finding is gone and nothing worse appeared.
3. Run your **tests**, because updates can break behavior.
4. Roll out by **digest** and keep a record.

### Example: A Step-by-Step Improvement

| Step | Change | Typical Effect on Findings |
| :---: | :--- | :--- |
| 0 | Start: `python:3.8`, old dependencies, root user | Very many findings (hundreds), including CRITICAL |
| 1 | Switch to `python:3.8-slim` | Large drop in OS findings |
| 2 | Move to `python:3.12-slim` and update dependencies | Large drop again, library findings mostly gone |
| 3 | Multi-stage build, non-root user, `.dockerignore` | Fewer files and tools, no secrets, cleaner misconfiguration scan |

You will do exactly this in Lab 4.

### Patch Timelines (Example Only)

Adapt to your organization's policy:

| Severity | Typical Target |
| :--- | :--- |
| **CRITICAL (fixable)** | Hours to a few days. Block release. |
| **HIGH (fixable)** | Within days to two weeks. Block release. |
| **MEDIUM** | Within the normal sprint or release cycle. |
| **LOW** | Routine maintenance. |

### Keep Scanning After Release

New CVEs appear **after** you ship. Schedule a **recurring scan of images in your registry and in production**, and have a process for rebuilding and redeploying when a serious new issue appears.

---

## 11. Introduction to Cosign

### The Problem: How Do You Know an Image Is Genuine?

You pull `ghcr.io/my-org/myapp:1.0`. How can you be sure that:

1. It was built by **your pipeline**, not by an attacker who stole a registry password?
2. It has **not been changed** since it was built?
3. The tag `1.0` was not **overwritten** with something malicious?

Scanning tells you what is **inside** an image. It does **not** tell you **who made it** or whether it was **tampered with**. **Signing** answers those questions.

> **Analogy:** A vulnerability scan is a **health inspection** of the food. A signature is the **tamper-evident seal** that shows the package left the real factory and nobody opened it.

### What Is Cosign?

**Cosign** is a tool from the **Sigstore** project for **signing and verifying** container images (and other software artifacts). It stores signatures **in the registry next to the image**, so no separate system is needed.

### The Sigstore Ecosystem

| Component | Role |
| :--- | :--- |
| **Cosign** | The command-line tool you use to sign and verify. |
| **Fulcio** | A certificate authority that issues **short-lived certificates** tied to an identity (for example, "this GitHub Actions workflow"). Used for **keyless** signing. |
| **Rekor** | A public, tamper-evident **transparency log** that records signatures, so they can be audited. |
| **TUF root of trust** | A secure way for Cosign to obtain Sigstore's public trust material. |

### Two Ways to Sign

| | **Key-based signing** | **Keyless signing** |
| :--- | :--- | :--- |
| **How it works** | You create a **key pair** and sign with the **private key** | You prove your **identity** (for example, through GitHub Actions' OIDC token) and get a **short-lived certificate** |
| **What you must protect** | The **private key**, forever | Nothing long-lived: the key exists for minutes |
| **Verification uses** | The **public key** | The **identity** and **issuer** ("signed by this workflow of this repo") |
| **Risk** | A stolen key lets anyone sign as you | A misconfigured identity check accepts the wrong signer |
| **Best for** | Air-gapped or private environments, learning the basics | **CI/CD pipelines**, public and open-source projects |

```text
KEY-BASED                                       KEYLESS (in GitHub Actions)

 private key (secret!)                           Workflow proves identity to GitHub (OIDC token)
        |                                                    |
        v                                                    v
 cosign sign  ---> signature in registry          Fulcio issues a short-lived certificate
                                                             |
 cosign verify --key cosign.pub                              v
                                                  cosign sign ---> signature + certificate
                                                  in registry, and a record in Rekor
                                                             |
                                                  cosign verify
                                                    --certificate-identity  (which workflow?)
                                                    --certificate-oidc-issuer (which issuer?)
```

### What a Signature Proves, and What It Does Not

| ✅ A valid signature proves | ❌ It does **not** prove |
| :--- | :--- |
| The image content **has not changed** since signing | That the image is **free of vulnerabilities** |
| The image was signed by **the holder of the key**, or by the **expected workflow identity** | That the **code** inside is safe or benign |
| (With a transparency log) when it was signed and that it was recorded | That the **signer's system was not compromised** |

> [!IMPORTANT]
> **Signing is only as trustworthy as the system doing the signing.** If an attacker controls your CI pipeline, they can sign a malicious image with your valid identity. That is why pipeline security (Modules 03 and 10) and **scanning before signing** both matter.

### Signing the Digest, Not the Tag

Cosign signatures belong to an image **digest**. A tag is only a pointer.

```text
 tag  myapp:1.0  ----points to---->  digest sha256:AAA...   (signed)

 Attacker overwrites the tag:
 tag  myapp:1.0  ----points to---->  digest sha256:BBB...   (NOT signed: verification FAILS)
```

This is exactly how signatures catch **tag tampering**. Always pass the **digest** to `cosign sign` and deploy by digest.

### Attestations: Signed Statements About an Image

Besides a signature, Cosign can attach a **signed attestation**: a verifiable statement about the image, such as:

| Attestation Type | What It States |
| :--- | :--- |
| **SBOM** (CycloneDX or SPDX) | "This image contains exactly these components." |
| **Vulnerability scan result** | "This image was scanned on this date with this result." |
| **Build provenance** (SLSA) | "This image was built from this source by this workflow." |

Policies can then require, for example, "**no image may deploy without a signed SBOM and a passing scan attestation**."

### Where Signatures Fit in the Pipeline

```text
Build --> Scan (Trivy) --> Pass? --> Push --> SIGN (Cosign) --> ... --> VERIFY (Cosign) --> Deploy
                              |                                              |
                          fail: stop                                    fail: refuse to run
```

### Installing Cosign

Install Cosign **the same careful way** as Trivy: a **pinned, verified** release. The Sigstore documentation explains how to verify the Cosign binary itself.

```bash
# Example for Linux amd64 (use a release you have verified; confirm the file name on the releases page)
COSIGN_VERSION=3.0.2           # example only
curl -sSfL -O "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64"
curl -sSfL -O "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign_checksums.txt"
sha256sum --check --ignore-missing cosign_checksums.txt
sudo install -m 0755 cosign-linux-amd64 /usr/local/bin/cosign
cosign version
```

Package managers (`brew install cosign`) also work. The examples in this module assume **Cosign v3**. Cosign v3 uses a newer signature **bundle format** by default, so some flags differ from older tutorials. When a flag does not exist in your version, check `cosign sign --help`.

---

## 12. Signing Container Images with Cosign

### Method 1: Key-Based Signing (Learning and Private Environments)

**Step 1: Generate a key pair.**

```bash
cosign generate-key-pair
```

You are asked for a **password** to encrypt the private key. This creates:

| File | What It Is | Handling |
| :--- | :--- | :--- |
| `cosign.key` | The **private** signing key (encrypted with your password) | **Secret.** Never commit it. Add it to `.gitignore`. Store it in a secret manager. |
| `cosign.pub` | The **public** verification key | Safe to share and commit. Anyone verifying needs it. |

```bash
echo "cosign.key" >> .gitignore
```

> [!CAUTION]
> Gitleaks (Module 03) will flag `cosign.key` as a private key, and rightly so. Keep it out of Git, and in CI store it as a **secret** (and its password as a separate secret).

**Step 2: Push your image and get its digest.**

```bash
docker push registry.example.com/myapp:1.0

# The digest is shown at the end of the push, or:
docker inspect --format '{{index .RepoDigests 0}}' registry.example.com/myapp:1.0
# registry.example.com/myapp@sha256:3f1c9a...e9
```

**Step 3: Sign the digest.**

```bash
export COSIGN_PASSWORD="..."        # or let Cosign prompt you; in CI use a secret
cosign sign --yes --key cosign.key registry.example.com/myapp@sha256:3f1c9a...e9
```

The signature is stored in the same registry, attached to that digest. `--yes` skips confirmation prompts, which is needed in automation.

> [!NOTE]
> **Transparency log:** by default, Cosign records signatures in the **public Rekor log**, which publishes the image **name and digest**. For **private images** you may not want that. Options are a private Sigstore deployment or `--tlog-upload=false` when signing (verification must then be told to expect no log entry, see section 13). The labs use `--tlog-upload=false` because the lab image is local and private. Your organization's policy decides the right choice.

**Step 4: Check what is attached.**

```bash
cosign tree registry.example.com/myapp@sha256:3f1c9a...e9
```

### Method 2: Keyless Signing (Recommended for CI/CD)

In GitHub Actions, the workflow can obtain a short-lived identity token and sign **without any stored key**:

```bash
# Inside a workflow that has:  permissions: id-token: write
cosign sign --yes ghcr.io/my-org/myapp@sha256:3f1c9a...e9
```

No private key to rotate, store, or steal. The certificate records **which repository and workflow** performed the signing. Section 14 shows the full workflow.

**On your own laptop**, the same command opens a browser to authenticate with an identity provider (such as GitHub or Google), then signs. This is good for demonstrations, but pipelines are the best place for keyless signing.

### Method 3: Keys in a Key Management Service

For organizations that want key-based signing with strong protection, the private key can live inside a **KMS or HSM**, and Cosign asks the service to sign without ever seeing the key:

```bash
cosign sign --key awskms:///alias/my-signing-key  registry.example.com/myapp@sha256:...
cosign sign --key gcpkms://projects/.../cryptoKeys/my-key  registry.example.com/myapp@sha256:...
cosign sign --key azurekms://myvault.vault.azure.net/mykey registry.example.com/myapp@sha256:...
cosign sign --key hashivault://my-key  registry.example.com/myapp@sha256:...
```

(HashiCorp Vault is covered in Module 11.)

### Attach an SBOM as a Signed Attestation

```bash
# 1. Generate the SBOM
trivy image --format cyclonedx --output sbom.cdx.json registry.example.com/myapp@sha256:3f1c9a...e9

# 2. Attach it as a signed attestation
cosign attest --yes --key cosign.key --type cyclonedx \
  --predicate sbom.cdx.json \
  registry.example.com/myapp@sha256:3f1c9a...e9
```

Attestation types include `cyclonedx`, `spdxjson`, `slsaprovenance`, and `vuln` (the exact list depends on your Cosign version).

### Add Annotations (Optional Metadata)

```bash
cosign sign --yes --key cosign.key \
  -a build.pipeline=github-actions -a build.commit=3f9a1c2 \
  registry.example.com/myapp@sha256:3f1c9a...e9
```

### Signing Best Practices

| Practice | Why |
| :--- | :--- |
| **Scan first, then sign** | A signature should mean "this passed our checks". |
| **Sign digests, never tags** | Tags can be moved. |
| **Prefer keyless in CI** | No long-lived key to leak. |
| **Protect private keys** | KMS or HSM, strong passphrase, strict access, rotation plan. |
| **Sign only from trusted pipelines** | Restrict who and what can sign (protected branches, protected environments). |
| **Do not sign from pull requests of forks** | Untrusted code must not obtain signing identity. |
| **Record signatures** (transparency log) where appropriate | Allows auditing. |
| **Keep the signing identity narrow** | A broad identity makes verification weaker. |

---

## 13. Verifying Container Image Signatures

Signing is useless unless something **checks** the signature before the image runs.

### Verify a Key-Based Signature

```bash
cosign verify --key cosign.pub registry.example.com/myapp@sha256:3f1c9a...e9
```

On success Cosign prints a short description of the checks and the signature payload as JSON. On failure it exits with a **non-zero code** and a message such as `no signatures found` or `no matching signatures`, which makes it perfect for scripts and pipelines.

If you signed with `--tlog-upload=false`, add `--insecure-ignore-tlog=true` to verify (as in the lab), because there is no log entry to check:

```bash
cosign verify --key cosign.pub --insecure-ignore-tlog=true registry.example.com/myapp@sha256:3f1c9a...e9
```

### Verify a Keyless Signature

You must say **who** you expect the signer to be. Without this check, "any valid Sigstore signature" would pass, including an attacker's own.

```bash
cosign verify ghcr.io/my-org/myapp@sha256:3f1c9a...e9 \
  --certificate-identity "https://github.com/my-org/my-repo/.github/workflows/container-security.yml@refs/heads/main" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

| Flag | Meaning |
| :--- | :--- |
| `--certificate-identity` | The **exact identity** that must have signed (here: this repository's workflow file on the `main` branch). |
| `--certificate-identity-regexp` | A **pattern** instead of an exact match. Use carefully: a broad pattern accepts more signers. |
| `--certificate-oidc-issuer` | Who vouches for the identity (GitHub Actions' token service here). |

> [!WARNING]
> **Never verify keyless signatures without pinning the identity and issuer.** A very loose pattern such as `.*` turns verification into a rubber stamp.

### Verify an Attestation (for Example, the SBOM)

```bash
cosign verify-attestation --key cosign.pub --type cyclonedx \
  registry.example.com/myapp@sha256:3f1c9a...e9 > attestation.json

# Extract the SBOM from the verified attestation
jq -r '.payload' attestation.json | base64 -d | jq '.predicate' > verified-sbom.json
```

(With Cosign v3 and keyless signing, the output envelope may use a slightly different field layout. Inspect the JSON if the extraction differs.)

### Test That Verification Really Catches Tampering

```text
 1. Sign:       myapp@sha256:AAA       -> verification PASSES
 2. Attacker overwrites the TAG "1.0" with a different image (digest BBB)
 3. Verify the TAG:   cosign verify --key cosign.pub registry/myapp:1.0
                      -> FAILS: no signature exists for digest BBB
```

You will reproduce this in Lab 6.

### Common Verification Failures

| Message or Symptom | Likely Cause |
| :--- | :--- |
| `no signatures found` / `no matching signatures` | The image (digest) was never signed, was re-pushed, or was signed with a different key or identity. |
| `invalid signature` | The content or signature does not match. Treat as **tampering** until proven otherwise. |
| `none of the expected identities matched` | The signer's identity differs from the one you pinned (for example, a different workflow file or branch). |
| `certificate expired` or timestamp errors | Keyless verification needs the transparency log or a signed timestamp. Do not disable checks to "fix" it. Find the cause. |
| Error about the transparency log with a **key signed using `--tlog-upload=false`** | Verify with `--insecure-ignore-tlog=true` (and understand the trade-off). |
| Registry authentication errors | `docker login` first, or provide credentials in CI. |

### A Verify-Then-Deploy Script

```bash
#!/usr/bin/env bash
# deploy.sh : refuse to run an image that is not properly signed
set -euo pipefail

IMAGE="$1"       # must be a DIGEST reference: registry/app@sha256:...
case "$IMAGE" in
  *@sha256:*) ;;
  *) echo "Refusing: deploy by digest, not by tag." >&2; exit 1 ;;
esac

if cosign verify --key cosign.pub "$IMAGE" > /dev/null 2>&1; then
  echo "Signature verified. Starting container..."
  docker run -d --name myapp "$IMAGE"
else
  echo "SIGNATURE VERIFICATION FAILED. Not deploying." >&2
  exit 1
fi
```

### Where Verification Should Happen

| Place | How |
| :--- | :--- |
| **In the deploy step of your pipeline** | `cosign verify` before `docker run` or `helm upgrade`. |
| **On the host or in scripts** | As in the script above. |
| **In Kubernetes (admission control)** | A policy engine such as **Kyverno** (Module 08) rejects unsigned or wrongly signed images **automatically** for the whole cluster. This is the strongest option because nobody can forget to check. |

> [!NOTE]
> The Docker Engine by itself does **not** verify Cosign signatures. Enforcement comes from your pipeline, scripts, or a Kubernetes admission controller.

### Verify Your Tools Too

The same technique protects your **tooling**. Verify the Trivy release signature before installing it (section 7), and verify the signatures of base images that publish them. A secure supply chain verifies **inputs**, not just **outputs**.

---

## 14. Container Security in CI/CD

### The Secure Image Pipeline

```text
  Commit
     |
     v
 1. LINT + SCAN SOURCE      Hadolint, trivy config, trivy fs, Gitleaks (M03), SAST (M04)
     |
     v
 2. BUILD IMAGE             docker build (pinned base, multi-stage, non-root)
     |
     v
 3. SCAN IMAGE              trivy image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed
     |      FAIL --------> stop. The image is never pushed.
     v
 4. GENERATE SBOM           trivy image --format cyclonedx
     |
     v
 5. PUSH TO REGISTRY        get the DIGEST
     |
     v
 6. SIGN + ATTEST           cosign sign / cosign attest (keyless in CI)
     |
     v
 7. VERIFY                  cosign verify (pinned identity)
     |
     v
 8. DEPLOY BY DIGEST        admission control re-verifies (Module 08)
```

### Pipeline Security Principles

| Principle | How |
| :--- | :--- |
| **Scan before you push** | Bad images never reach the registry. |
| **Pin everything** | Actions by **commit SHA**, tools by **exact version**, base images by **digest**. |
| **Least privilege** | Minimal `permissions:` for the workflow token. |
| **Short-lived credentials** | Keyless signing with OIDC, no stored signing keys or cloud keys. |
| **Sign only trusted builds** | Signing steps run only on protected branches. |
| **Keep reports** | Upload scan reports and SBOMs as build artifacts. |
| **Treat CI tools as part of the supply chain** | See the case study in section 7. |

### Pin GitHub Actions to a Commit SHA

Tags such as `@v4` can be re-pointed. A commit SHA cannot. Find the SHA that a tag points to:

```bash
git ls-remote --tags https://github.com/actions/checkout "refs/tags/v4*"
# Use the full 40-character commit SHA (for annotated tags, use the line ending in ^{})
```

Then use it, with a comment naming the version:

```yaml
- uses: actions/checkout@<full-40-character-commit-sha>   # v4.x.x
```

Keep the pinned SHAs current with **Dependabot** (`package-ecosystem: "github-actions"`), and consider GitHub's repository or organization setting that **requires actions to be pinned to a full commit SHA** (look under Settings → Actions). In the examples below, tags such as `@v4` appear for readability, and the comments remind you to pin.

### GitHub Actions: Full Workflow

This workflow builds, scans (and **fails on fixable HIGH and CRITICAL** findings), generates an SBOM, pushes to GHCR, **keylessly signs**, **verifies**, and attaches the SBOM as an attestation. It uses **plain Docker commands** and a **pinned, checksum-verified Trivy**, so it needs very few third-party actions.

```yaml
# .github/workflows/container-security.yml
name: Container Security

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read                  # least privilege by default

env:
  TRIVY_VERSION: "0.71.0"        # example: use a release you have verified. Never "latest".

jobs:
  build-scan-sign:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write             # push to GHCR
      id-token: write             # keyless signing (OIDC)
    steps:
      - name: Check out code
        uses: actions/checkout@v4          # PIN to a full commit SHA in production

      - name: Set image name (GHCR requires lowercase)
        run: |
          echo "IMAGE=ghcr.io/${GITHUB_REPOSITORY,,}" >> "$GITHUB_ENV"

      - name: Lint the Dockerfile (Hadolint)
        run: docker run --rm -i hadolint/hadolint < Dockerfile

      - name: Build the image
        run: docker build -t "${IMAGE}:${GITHUB_SHA}" .

      - name: Install Trivy (pinned and checksum-verified)
        run: |
          set -euo pipefail
          base="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"
          file="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
          curl -sSfL -O "${base}/${file}"
          curl -sSfL -O "${base}/trivy_${TRIVY_VERSION}_checksums.txt"
          sha256sum --check --ignore-missing "trivy_${TRIVY_VERSION}_checksums.txt"
          sudo tar -xzf "${file}" -C /usr/local/bin trivy
          trivy --version

      - name: Scan Dockerfile and config for misconfigurations
        run: trivy config --exit-code 1 --severity HIGH,CRITICAL .

      - name: Scan the image (SECURITY GATE)
        run: |
          trivy image \
            --exit-code 1 \
            --severity CRITICAL,HIGH \
            --ignore-unfixed \
            --format json --output trivy-report.json \
            "${IMAGE}:${GITHUB_SHA}"

      - name: Generate an SBOM
        if: always()
        run: trivy image --format cyclonedx --output sbom.cdx.json "${IMAGE}:${GITHUB_SHA}"

      - name: Upload reports
        if: always()
        uses: actions/upload-artifact@v4   # PIN to a full commit SHA in production
        with:
          name: container-security-reports
          path: |
            trivy-report.json
            sbom.cdx.json

      # ---- Everything below runs ONLY on main, never for pull requests ----
      - name: Log in to GHCR
        if: github.ref == 'refs/heads/main'
        run: echo "${{ secrets.GITHUB_TOKEN }}" | docker login ghcr.io -u "${{ github.actor }}" --password-stdin

      - name: Push the image and capture its digest
        if: github.ref == 'refs/heads/main'
        run: |
          docker push "${IMAGE}:${GITHUB_SHA}"
          DIGEST="$(docker inspect --format '{{index .RepoDigests 0}}' "${IMAGE}:${GITHUB_SHA}")"
          echo "IMAGE_DIGEST=${DIGEST}" >> "$GITHUB_ENV"
          echo "Pushed: ${DIGEST}"

      - name: Install Cosign
        if: github.ref == 'refs/heads/main'
        uses: sigstore/cosign-installer@v4   # PIN to a full commit SHA in production

      - name: Sign the image (keyless)
        if: github.ref == 'refs/heads/main'
        run: cosign sign --yes "${IMAGE_DIGEST}"

      - name: Attach the SBOM as a signed attestation
        if: github.ref == 'refs/heads/main'
        run: cosign attest --yes --type cyclonedx --predicate sbom.cdx.json "${IMAGE_DIGEST}"

      - name: Verify the signature (pinned identity)
        if: github.ref == 'refs/heads/main'
        run: |
          cosign verify "${IMAGE_DIGEST}" \
            --certificate-identity "https://github.com/${GITHUB_REPOSITORY}/.github/workflows/container-security.yml@${GITHUB_REF}" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

| Part | Why It Matters |
| :--- | :--- |
| `permissions` at top and job level | The default token is **read-only**. The job asks only for `packages: write` and `id-token: write`. |
| Build **then scan, then push** | A failing scan stops the job before anything reaches the registry. |
| Pinned, **checksum-verified Trivy** | Avoids the moving-tag and "latest" problems from the case study. |
| `--exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed` | The **gate**: fail on fixable serious findings. |
| Push, signing, and attestation only on `main` | Pull requests (especially from forks) never receive signing identity. |
| `cosign sign` on the **digest** | The signature binds to exact content. |
| Verification with `--certificate-identity` and issuer | Proves **this workflow** signed it, not just "someone". |
| Reports uploaded with `if: always()` | You can read what failed. |

> [!NOTE]
> Action versions change. Look up current versions, **pin them by SHA**, and update with Dependabot. Using the official `aquasecurity/trivy-action` is possible, but if you do, pin it by **full commit SHA** (never a tag) and read the current advisory first. This workflow deliberately avoids it so students can see exactly what runs.

### Make the Check Required

As in Modules 03, 04, and 06: **Settings → Rules → Rulesets** → require the **Container Security** status check on `main`, so a failing scan blocks the merge.

### Jenkins: Pipeline

This pipeline avoids mounting the Docker socket into the scanner. It exports the image to a tar file, scans it in a Trivy container, pushes, and signs with a key stored in Jenkins credentials.

```groovy
// Jenkinsfile
pipeline {
    agent any

    environment {
        REGISTRY      = 'registry.example.com'
        IMAGE         = "${REGISTRY}/myapp"
        TAG           = "${env.GIT_COMMIT?.take(8) ?: env.BUILD_NUMBER}"
        TRIVY_VERSION = '0.71.0'            // example: use a verified release, never 'latest'
    }

    stages {
        stage('Checkout') {
            steps { checkout scm }
        }

        stage('Lint Dockerfile') {
            steps {
                sh 'docker run --rm -i hadolint/hadolint < Dockerfile'
            }
        }

        stage('Build') {
            steps {
                sh 'docker build -t "$IMAGE:$TAG" .'
            }
        }

        stage('Scan (Security Gate)') {
            steps {
                sh '''
                    docker save "$IMAGE:$TAG" -o image.tar
                    mkdir -p reports && chmod a+w reports

                    docker run --rm \
                      -v trivy-cache:/root/.cache/ \
                      -v "$PWD:/work" \
                      aquasec/trivy:${TRIVY_VERSION} image \
                        --input /work/image.tar \
                        --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed \
                        --format json --output /work/reports/trivy-report.json
                '''
            }
            post {
                always {
                    sh '''
                        docker run --rm -v "$PWD:/work" aquasec/trivy:${TRIVY_VERSION} image \
                          --input /work/image.tar --format cyclonedx --output /work/reports/sbom.cdx.json || true
                    '''
                    archiveArtifacts artifacts: 'reports/*', allowEmptyArchive: true
                }
            }
        }

        stage('Push') {
            when { branch 'main' }
            steps {
                withCredentials([usernamePassword(credentialsId: 'registry-creds',
                                                  usernameVariable: 'REG_USER',
                                                  passwordVariable: 'REG_PASS')]) {
                    sh '''
                        echo "$REG_PASS" | docker login "$REGISTRY" -u "$REG_USER" --password-stdin
                        docker push "$IMAGE:$TAG"
                        docker inspect --format '{{index .RepoDigests 0}}' "$IMAGE:$TAG" > digest.txt
                    '''
                }
            }
        }

        stage('Sign and Verify') {
            when { branch 'main' }
            steps {
                withCredentials([file(credentialsId: 'cosign-key', variable: 'COSIGN_KEY'),
                                 string(credentialsId: 'cosign-password', variable: 'COSIGN_PASSWORD'),
                                 file(credentialsId: 'cosign-pub', variable: 'COSIGN_PUB')]) {
                    sh '''
                        DIGEST="$(cat digest.txt)"
                        cosign sign --yes --key "$COSIGN_KEY" "$DIGEST"
                        cosign verify --key "$COSIGN_PUB" "$DIGEST"
                    '''
                }
            }
        }
    }

    post {
        always {
            sh 'docker logout "$REGISTRY" || true'
            sh 'rm -f image.tar'
        }
    }
}
```

| Part | Why It Matters |
| :--- | :--- |
| `docker save` then `--input` | The scanner needs **no Docker socket**. |
| `aquasec/trivy:${TRIVY_VERSION}` | Pinned tag (pin the digest for more safety). |
| `exit-code 1` | A non-zero exit fails the stage and stops the pipeline. |
| `withCredentials` | Secrets are injected temporarily and masked in logs. |
| `when { branch 'main' }` | Pushing and signing only from the protected branch. |
| `docker logout` and `rm image.tar` in `post` | Clean up credentials and artifacts. |

> [!NOTE]
> The pipeline assumes `cosign` is installed on the Jenkins agent from a **verified release** (section 11). For private images signed with a key, consider the transparency log note in section 12 and add the matching flags.

### Scheduled Rescans

Add a **scheduled** pipeline (nightly or weekly) that scans the images **currently in your registry**, because new vulnerabilities are published every day:

```yaml
on:
  schedule:
    - cron: "0 3 * * *"
  workflow_dispatch:
```

---

## 15. Runtime Security Fundamentals

A secure image can still be **run insecurely**. Runtime settings decide how much damage an attacker can do if they get in.

### The Core Idea: Least Privilege at Runtime

```text
 Default docker run                          Hardened docker run

 root user (if image says so)        -->     non-root user
 ~14 capabilities                    -->     ZERO capabilities (add back only what is needed)
 writable root filesystem            -->     read-only filesystem
 can gain new privileges             -->     no-new-privileges
 unlimited memory / CPU / processes  -->     limits on all three
 can use any port and network        -->     published on localhost only, separate networks
```

### A Hardened `docker run`

```bash
docker run -d --name secure-app \
  --user 10001:10001 \
  --read-only \
  --tmpfs /tmp \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --memory 256m \
  --cpus 0.5 \
  --pids-limit 100 \
  -p 127.0.0.1:8080:8080 \
  myapp@sha256:3f1c9a...e9
```

| Flag | What It Does | Attack It Limits |
| :--- | :--- | :--- |
| `--user 10001:10001` | Runs as an unprivileged user | Root-only actions inside the container |
| `--read-only` | Makes the container's filesystem read-only | Attackers cannot drop tools or modify the app |
| `--tmpfs /tmp` | Provides a small writable in-memory `/tmp` | Lets apps that need temporary files still work |
| `--cap-drop ALL` | Removes every Linux capability | Network manipulation, ownership changes, and more |
| `--security-opt no-new-privileges:true` | Blocks privilege gain through SUID binaries | Privilege escalation inside the container (Module 02) |
| `--memory`, `--cpus`, `--pids-limit` | Resource limits | Denial of service, fork bombs |
| `-p 127.0.0.1:8080:8080` | Publishes only on localhost | Direct exposure to the network |
| deploy by `@sha256:...` | Exact verified image | Tag swapping |

### Things to Never Do (Unless You Fully Understand the Risk)

| ❌ Avoid | Why |
| :--- | :--- |
| `--privileged` | Removes most isolation. A breakout is trivial. |
| `-v /var/run/docker.sock:/var/run/docker.sock` | Gives the container control of the host's Docker (root-equivalent). |
| `-v /:/host` or mounting `/etc`, `/proc`, `/sys` | Exposes the host filesystem. |
| `--pid=host`, `--ipc=host`, `--network=host`, `--userns=host` | Shares host namespaces. |
| `--cap-add SYS_ADMIN` | A huge, root-like capability. |
| `--security-opt seccomp=unconfined` or `apparmor=unconfined` | Switches off syscall and MAC protection. |
| Exposing the Docker daemon on TCP without TLS | Remote host takeover. |
| Secrets in `-e PASSWORD=...` | Visible in `docker inspect`, process lists, and logs. |

### Secrets at Runtime

| Method | Assessment |
| :--- | :--- |
| Environment variables (`-e`, `ENV`) | ⚠️ Easy but visible through `docker inspect`, `/proc`, crash dumps, and logs |
| **Mounted secret files** (read-only, in memory) | ✅ Better. Docker secrets, Kubernetes secrets mounted as files |
| **A secrets manager** (HashiCorp Vault, cloud secret managers) | ✅ Best. Short-lived, audited, rotatable (Module 11) |
| Baked into the image | ❌ Never |

```bash
# A secret as a read-only file instead of an environment variable
docker run --rm -v "$PWD/db_password.txt:/run/secrets/db_password:ro" myapp:1.0
```

### Networking

| Practice | Why |
| :--- | :--- |
| Use **user-defined bridge networks** | Containers talk by name only to others on the same network. |
| Create **internal networks** for backends (`docker network create --internal`) | No route to the internet. |
| Publish only the ports you need, on `127.0.0.1` when possible | Smaller exposure. |
| Avoid `--network host` | Shares the host's network stack. |
| Remember Docker's firewall behavior | Published ports can **bypass `ufw`** rules (Module 02, section 9). Use localhost bindings and cloud firewalls. |

```bash
docker network create --internal backend         # no outside access
docker network create frontend
```

### Harden Docker Compose Too

```yaml
# docker-compose.yml
services:
  web:
    image: ghcr.io/my-org/myapp@sha256:3f1c9a...e9   # by digest
    user: "10001:10001"
    read_only: true
    tmpfs:
      - /tmp
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    pids_limit: 100
    mem_limit: 256m
    cpus: 0.5
    ports:
      - "127.0.0.1:8080:8080"
    networks:
      - frontend
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')"]
      interval: 30s
      timeout: 3s
      retries: 3

networks:
  frontend:
```

### Protect the Docker Daemon and Host

| Practice | Details |
| :--- | :--- |
| **Do not expose the daemon API** | Never bind it to TCP without mutual TLS. Prefer the local socket, or SSH. |
| **Limit access to the `docker` group** | Membership equals root on the host. |
| **Consider rootless Docker** | Runs the daemon and containers without host root. |
| **Keep Docker, containerd, runc, and the kernel patched** | Runtime flaws allow breakouts. |
| **Harden the host** | Everything in Module 02: SSH, firewall, auditing, updates. |
| **Use a minimal container-focused OS** where possible | Fewer host packages to attack. |
| **Run the Docker Bench for Security** | An open-source script that checks a host against the CIS Docker Benchmark. |

### Monitoring and Detection

| Tool or Source | What It Shows |
| :--- | :--- |
| `docker logs`, `docker events`, `docker stats` | Application output, lifecycle events, resource use |
| **Host audit logs** (`auditd`, Module 02) | Who ran Docker commands and changed files |
| **Falco** (Modules 08 and 12) | **Runtime threat detection**: alerts on suspicious behavior such as a shell spawned in a container or a sensitive file read |
| **Central logging** (Loki, Module 12) | Searchable logs from every container |

Signs worth alerting on: a **shell started inside a production container**, outbound connections to unusual destinations, a container running **as root** or **privileged** unexpectedly, new files written to a read-only application path, sudden CPU spikes (possible cryptomining).

### The Same Controls in Kubernetes (Preview of Module 08)

| Docker Flag | Kubernetes `securityContext` Setting |
| :--- | :--- |
| `--user 10001` | `runAsUser: 10001`, `runAsNonRoot: true` |
| `--read-only` | `readOnlyRootFilesystem: true` |
| `--cap-drop ALL` | `capabilities: { drop: ["ALL"] }` |
| `--security-opt no-new-privileges` | `allowPrivilegeEscalation: false` |
| default seccomp profile | `seccompProfile: { type: RuntimeDefault }` |
| `--memory`, `--cpus` | `resources.limits.memory`, `resources.limits.cpu` |
| `--privileged` (avoid) | `privileged: false` |

---

## 16. Hands-On Labs

> [!WARNING]
> All labs run on your own machine. The sample image is **deliberately insecure**: do not push it to a public registry, and do not run it on a public network. All "secrets" in the labs are **fake and generated locally**.

### Lab Setup: The Sample Application

Create the project files used in several labs.

```bash
mkdir -p ~/container-lab && cd ~/container-lab

cat > app.py <<'EOF'
from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/")
def index():
    return "Hello from a container!"

@app.route("/health")
def health():
    return jsonify(status="ok")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
EOF

# OLD, vulnerable dependencies (for the insecure image)
cat > requirements-old.txt <<'EOF'
flask==2.0.1
werkzeug==2.0.1
jinja2==3.0.1
itsdangerous==2.0.1
markupsafe==2.0.1
click==8.0.1
requests==2.25.0
EOF

# Newer dependencies (for the hardened image)
cat > requirements.txt <<'EOF'
flask==3.1.1
requests==2.32.4
gunicorn==23.0.0
EOF

# A fake secret file that "accidentally" ends up in the image
FAKE_TOKEN="ghp_$(head -c 300 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 36)"
printf 'GITHUB_TOKEN=%s\nDB_PASSWORD=change-me\n' "$FAKE_TOKEN" > .env

# The INSECURE Dockerfile
cat > Dockerfile.insecure <<'EOF'
FROM python:3.8
ENV API_KEY=not-a-real-key-demo-123
WORKDIR /app
COPY . .
RUN pip install -r requirements-old.txt
EXPOSE 5000
CMD ["python", "app.py"]
EOF

ls -la
```

> [!NOTE]
> Exact vulnerability counts depend on when you run the labs, because the vulnerability database changes daily. Focus on **how the numbers change**, not on matching the examples.

### Lab 1: Explore Container Risks

**Objective:** See with your own eyes why default settings and bad habits are dangerous.

**Tasks:**

```bash
cd ~/container-lab
docker build -f Dockerfile.insecure -t insecure-app:1.0 .
```

**Part A: Who am I inside the container?**

```bash
docker run --rm insecure-app:1.0 id
```

Expected: `uid=0(root)`. The application runs as **root**.

**Part B: What can anyone with the image see?**

```bash
docker history --no-trunc insecure-app:1.0 | grep -i API_KEY            # the ENV value is in the history
docker inspect insecure-app:1.0 --format '{{json .Config.Env}}'          # and in the metadata
docker run --rm insecure-app:1.0 cat /app/.env                            # the copied .env file is in the image
```

**Part C: The Docker socket is root.**

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock docker:cli docker ps
```

A container that can see **the host's other containers** can also start new ones.

**Part D: A host mount reaches the host.**

```bash
docker run --rm -v /:/host:ro alpine cat /host/etc/os-release
```

The container just read a file from your **host's** filesystem. (Read-only here, and harmless, but a writable mount would allow changes.)

Fill in the table:

| Question | Your Answer |
| :--- | :--- |
| Which user did the app run as? | |
| Where can an attacker find the `API_KEY` without running the container? | |
| Why was `.env` in the image? | |
| What does Part C prove about the Docker socket? | |
| Which four settings from section 15 would limit this? | |

**Expected outcome:** You can explain, with evidence, why root users, secrets in images, the Docker socket, and host mounts are dangerous.

### Lab 2: Write a Secure Dockerfile

**Objective:** Build a hardened image and compare it with the insecure one.

**Tasks:**

1. Create the hardened Dockerfile and `.dockerignore`:

```bash
cd ~/container-lab

cat > .dockerignore <<'EOF'
.git
.env
.env.*
*.pem
*.key
requirements-old.txt
Dockerfile*
__pycache__
*.pyc
EOF

cat > Dockerfile <<'EOF'
# syntax=docker/dockerfile:1
FROM python:3.12-slim AS builder
WORKDIR /build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY requirements.txt .
RUN python -m venv /opt/venv && /opt/venv/bin/pip install -r requirements.txt

FROM python:3.12-slim
RUN groupadd --gid 10001 app \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --chown=app:app app.py .
ENV PATH="/opt/venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')"]
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]
EOF
```

2. Lint both Dockerfiles and compare the messages:

```bash
docker run --rm -i hadolint/hadolint < Dockerfile.insecure
docker run --rm -i hadolint/hadolint < Dockerfile
```

3. Build and test:

```bash
docker build -t hardened-app:1.0 .
docker run -d --name hardened -p 127.0.0.1:8080:8080 hardened-app:1.0
sleep 3 && curl -s http://localhost:8080/health ; echo
docker rm -f hardened
```

4. Compare the two images:

```bash
docker images | grep -E "insecure-app|hardened-app"        # size
docker run --rm insecure-app:1.0 id
docker run --rm hardened-app:1.0 id
docker run --rm hardened-app:1.0 ls -la /app                # no .env, no extra files
docker history --no-trunc hardened-app:1.0 | grep -ci "api_key" || echo "No API_KEY in history"
```

| Property | insecure-app | hardened-app |
| :--- | :--- | :--- |
| Image size | | |
| Running user | | |
| `.env` file present? | | |
| Secret visible in history? | | |
| Has a `HEALTHCHECK`? | | |

**Expected outcome:** The hardened image is **much smaller**, runs as UID 10001, contains no `.env` file or secret, and still works. You can map each improvement to a rule in section 4.

### Lab 3: Scan With Trivy

**Objective:** Install Trivy safely and scan images, files, and the Dockerfile.

**Tasks:**

1. Install Trivy following section 7 (**pinned, checksum-verified**). Confirm with `trivy --version`.
2. Scan both images:

```bash
cd ~/container-lab
trivy image insecure-app:1.0 | head -60
trivy image --severity HIGH,CRITICAL --ignore-unfixed insecure-app:1.0 | tail -40
trivy image --severity HIGH,CRITICAL --ignore-unfixed hardened-app:1.0
```

3. Record counts using JSON:

```bash
for img in insecure-app hardened-app; do
  trivy image --format json -o $img.json $img:1.0 >/dev/null 2>&1
  echo "== $img"
  jq -r '[.Results[]?.Vulnerabilities[]?] | group_by(.Severity) | map("\(.[0].Severity): \(length)") | .[]' $img.json
done
```

4. Find the leaked secret and misconfigurations:

```bash
trivy image --scanners secret insecure-app:1.0         # should flag the token from .env
trivy image --scanners secret hardened-app:1.0         # should be clean
trivy config --file-patterns "dockerfile:Dockerfile.insecure" .
trivy config .                                           # scans the real Dockerfile
```

5. Test the gate:

```bash
trivy image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed insecure-app:1.0 ; echo "Exit code: $?"
trivy image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed hardened-app:1.0 ; echo "Exit code: $?"
```

Fill in:

| Question | insecure-app | hardened-app |
| :--- | :--- | :--- |
| Total CRITICAL | | |
| Total HIGH | | |
| Secret found? | | |
| Gate exit code | | |

**Expected outcome:** The insecure image has many more findings, a detected secret, and a failing gate (exit code 1). The hardened image has far fewer findings and no secret. (If the hardened image still triggers the gate, triage the remaining findings as practiced in Lab 4.)

### Lab 4: Remediate Step by Step

**Objective:** Reduce vulnerabilities in measured steps and prove it.

**Tasks:** Build three intermediate images from the insecure Dockerfile and record the counts after each step.

**Step A: Slim base only** (still old Python and old libraries):

```bash
cd ~/container-lab
sed 's/^FROM python:3.8$/FROM python:3.8-slim/' Dockerfile.insecure > Dockerfile.stepA
docker build -f Dockerfile.stepA -t stepa-app:1.0 .
```

**Step B: Modern Python and updated dependencies** (but still root and still copying everything):

```bash
cat > Dockerfile.stepB <<'EOF'
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt app.py ./
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 8080
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]
EOF
docker build -f Dockerfile.stepB -t stepb-app:1.0 .
```

**Step C:** the final hardened image from Lab 2 (`hardened-app:1.0`).

Scan all four and fill the table:

```bash
for img in insecure-app stepa-app stepb-app hardened-app; do
  trivy image --format json -o $img.json --quiet $img:1.0
  echo "== $img  $(docker images --format '{{.Size}}' $img:1.0)"
  jq -r '[.Results[]?.Vulnerabilities[]?] | group_by(.Severity) | map("\(.[0].Severity): \(length)") | .[]' $img.json
done
```

| Image | Change | Size | CRITICAL | HIGH |
| :--- | :--- | :--- | :--- | :--- |
| insecure-app | `python:3.8`, old libs, root | | | |
| stepa-app | slim base | | | |
| stepb-app | Python 3.12 slim, new libs | | | |
| hardened-app | multi-stage, non-root, `.dockerignore` | | | |

**Handle what remains:**

1. List fixable serious issues in the final image with the `jq` recipe from section 9.
2. For one finding that has **no fix**, decide whether to mitigate or accept it, and write it in `.trivyignore` with a **reason and an expiry date**:

```bash
cat > .trivyignore <<'EOF'
# <CVE-ID> : <reason>. Approved by: <name>. Review by the expiry date.
# CVE-0000-00000 exp:2026-12-31
EOF
```

3. Re-run the gate command and confirm the result.

**Expected outcome:** The counts fall at each step, with the largest drops from changing the base image and updating dependencies. You can explain why each step helped and which one matters most.

### Lab 5: Generate and Inspect an SBOM

**Objective:** Produce an image SBOM, inspect it, and rescan it.

**Tasks:**

```bash
cd ~/container-lab

# 1. Generate CycloneDX and SPDX SBOMs
trivy image --format cyclonedx --output sbom.cdx.json  hardened-app:1.0
trivy image --format spdx-json  --output sbom.spdx.json hardened-app:1.0

# 2. Inspect
jq '.components | length' sbom.cdx.json
jq -r '.components[] | "\(.name)  \(.version)"' sbom.cdx.json | sort | head -25
jq -r '.components[] | select(.name=="flask" or .name=="requests") | "\(.name) \(.version)"' sbom.cdx.json

# 3. Scan the SBOM (no image needed)
trivy sbom sbom.cdx.json --severity HIGH,CRITICAL --ignore-unfixed
```

4. **Optional:** install Syft (verified download) and compare:

```bash
syft hardened-app:1.0 -o cyclonedx-json=sbom.syft.cdx.json
jq '.components | length' sbom.syft.cdx.json
```

5. Answer: *"An organization announces a critical flaw in `requests` below version 2.32.4. How would you find every image you have that contains `requests`, using stored SBOMs?"*

**Expected outcome:** You can produce and read an SBOM, scan it, and explain how SBOM storage lets you answer "where is this component?" quickly.

### Lab 6: Sign and Verify With Cosign

**Objective:** Sign an image in a local registry, verify it, and watch verification catch tampering.

> [!NOTE]
> This lab uses **key-based** signing with a **local registry**. Keyless signing needs an internet identity provider, so you will practice it in the GitHub Actions lab. Install Cosign v3 following section 11. If a flag is not recognized by your version, check `cosign sign --help`.

**Tasks:**

```bash
cd ~/container-lab

# 1. A local registry, reachable only from your machine
docker run -d --name registry -p 127.0.0.1:5000:5000 registry:2

# 2. Tag and push the hardened image
docker tag hardened-app:1.0 localhost:5000/hardened-app:1.0
docker push localhost:5000/hardened-app:1.0

# 3. Get the digest (the immutable identity)
DIGEST_REF="$(docker inspect --format '{{index .RepoDigests 0}}' localhost:5000/hardened-app:1.0)"
echo "$DIGEST_REF"

# 4. Create a key pair (choose a password). Keep cosign.key OUT of Git!
cosign generate-key-pair
echo "cosign.key" >> .gitignore

# 5. Sign the DIGEST (no public transparency log for this private lab image)
read -rs COSIGN_PASSWORD ; export COSIGN_PASSWORD
cosign sign --yes --key cosign.key --tlog-upload=false "$DIGEST_REF"

# 6. Verify
cosign verify --key cosign.pub --insecure-ignore-tlog=true "$DIGEST_REF"
echo "Verify exit code: $?"

# 7. See what is attached
cosign tree "$DIGEST_REF"
```

**The tamper test:**

```bash
# 8. An "attacker" builds a DIFFERENT image and overwrites the same tag
cat > Dockerfile.evil <<'EOF'
FROM python:3.12-slim
CMD ["python", "-c", "print('malicious')"]
EOF
docker build -f Dockerfile.evil -t localhost:5000/hardened-app:1.0 .
docker push localhost:5000/hardened-app:1.0

# 9. Verify the TAG again
cosign verify --key cosign.pub --insecure-ignore-tlog=true localhost:5000/hardened-app:1.0
echo "Verify exit code: $?"          # NON-ZERO: the new content was never signed

# 10. Verify the ORIGINAL digest: still valid
cosign verify --key cosign.pub --insecure-ignore-tlog=true "$DIGEST_REF"
```

**Optional: attach and verify an SBOM attestation:**

```bash
cosign attest --yes --key cosign.key --tlog-upload=false --type cyclonedx \
  --predicate sbom.cdx.json "$DIGEST_REF"
cosign verify-attestation --key cosign.pub --insecure-ignore-tlog=true --type cyclonedx "$DIGEST_REF" > /dev/null && echo "Attestation OK"
```

**Cleanup:**

```bash
docker rm -f registry
```

**Expected outcome:** Verification **passes** for the signed digest and **fails** for the overwritten tag, and the original digest still verifies. You can explain why signing digests defeats tag tampering and why `cosign.key` must never be committed.

### Lab 7: Runtime Hardening

**Objective:** Run the image with least privilege and prove the restrictions work.

**Tasks:**

```bash
cd ~/container-lab

# 1. Run hardened
docker run -d --name secure-app \
  --read-only --tmpfs /tmp \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --memory 256m --cpus 0.5 --pids-limit 100 \
  -p 127.0.0.1:8080:8080 \
  hardened-app:1.0

sleep 3
curl -s http://localhost:8080/health ; echo

# 2. Prove the filesystem is read-only
docker exec secure-app sh -c 'touch /app/pwned' ; echo "Exit code: $?"      # fails: Read-only file system

# 3. Prove the user and settings
docker exec secure-app id
docker inspect --format 'ReadOnly={{.HostConfig.ReadonlyRootfs}} CapDrop={{.HostConfig.CapDrop}} SecurityOpt={{.HostConfig.SecurityOpt}} Memory={{.HostConfig.Memory}}' secure-app
docker stats --no-stream secure-app

# 4. Compare capabilities: default vs privileged vs dropped
docker run --rm alpine sh -c 'grep CapEff /proc/self/status'
docker run --rm --privileged alpine sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-drop ALL alpine sh -c 'grep CapEff /proc/self/status'

# 5. Decode the capability numbers on your host (Module 02)
#    capsh --decode=<value>

docker rm -f secure-app
```

6. Write the same settings as a `docker-compose.yml` using the example in section 15, run `docker compose up -d`, and confirm it works.
7. **Optional:** run the **Docker Bench for Security** script on a test machine and note three findings.

**Expected outcome:** The write attempt fails, the app still serves requests, and the three capability values show clearly different privilege levels (`--privileged` having the most, `--cap-drop ALL` the least).

### Lab 8: Container Security in GitHub Actions

**Objective:** Build, scan, gate, push, sign, and verify an image in a pipeline.

> [!NOTE]
> Use a **test repository**. Pushing to GHCR needs the `packages: write` permission in the workflow (already included). Make the repository private or public as you prefer, but it contains only the sample app.

**Tasks:**

1. Push the project files to a repository: `app.py`, `requirements.txt`, the **hardened** `Dockerfile` as `Dockerfile`, and `.dockerignore`. Do **not** commit `.env`, `cosign.key`, or the insecure files.
2. Add `.github/workflows/container-security.yml` from section 14. Choose a Trivy release you have verified and set `TRIVY_VERSION`.
3. Pin `actions/checkout`, `actions/upload-artifact`, and `sigstore/cosign-installer` to **full commit SHAs** and add a Dependabot entry for `github-actions`.
4. **Break it on purpose:** in a branch, change the `Dockerfile` back to the insecure version (`python:3.8`, old requirements, no `USER`), open a pull request, and watch the **scan fail** and block the job. Download the report artifact.
5. Merge the **hardened** version to `main`. Watch the image get pushed, signed, and verified.
6. On your machine, verify the signature yourself:

```bash
cosign verify ghcr.io/<owner>/<repo>@sha256:<digest> \
  --certificate-identity "https://github.com/<owner>/<repo>/.github/workflows/container-security.yml@refs/heads/main" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

7. Try a **wrong identity** (for example, a different workflow filename) and confirm verification fails.
8. Make the **Container Security** check required for `main` (Module 03, section 4.5).

**Expected outcome:** The insecure pull request is blocked by the scan, the hardened build is pushed and signed, your local verification passes with the correct identity and fails with a wrong one.

### Lab 9: Container Security in Jenkins

**Objective:** Add the same security stages to a Jenkins pipeline.

**Tasks:**

1. Use a Jenkins agent with Docker. Install a verified Cosign on the agent.
2. For a lab registry, run the local registry reachable from the agent, or use a registry you control.
3. Add Jenkins credentials: `registry-creds` (username and password), `cosign-key` (secret file), `cosign-password` (secret text), and `cosign-pub` (secret file).
4. Add the `Jenkinsfile` from section 14 and create a Pipeline job from SCM.
5. Run it with the **insecure** Dockerfile and confirm the **Scan** stage fails and **Push** and **Sign** do not run.
6. Switch to the hardened Dockerfile. Confirm Scan passes, the image is pushed, signed, and verified.
7. Download the archived `trivy-report.json` and `sbom.cdx.json`.

**Expected outcome:** A failing scan stops the pipeline before the push, and a passing build ends with a signed image whose signature the pipeline verifies. You can explain why the scan runs on a tar file instead of the Docker socket.

### Final Cleanup

```bash
docker rm -f registry secure-app hardened 2>/dev/null
docker rmi insecure-app:1.0 stepa-app:1.0 stepb-app:1.0 2>/dev/null
rm -f ~/container-lab/.env ~/container-lab/cosign.key
```

---

## 17. Best Practices

### Build

| Practice | Why |
| :--- | :--- |
| Use **minimal, current, trusted** base images | Smaller attack surface, fewer CVEs. |
| **Pin base images by digest** and update them through reviewed pull requests | Reproducible, controlled changes. |
| **Multi-stage builds** | No build tools in the final image. |
| **Non-root numeric `USER`** | Limits compromise impact and enables policy checks. |
| **`.dockerignore`**, copy only what is needed | No accidental secrets or junk. |
| **No secrets in `ENV`, `ARG`, or layers**. Use BuildKit secrets | Image history is permanent. |
| **Pin dependencies**, use lock files | Reviewable, reproducible. |
| **Lint** (Hadolint, `trivy config`) | Catches mistakes before the build. |

### Scan, Track, and Fix

| Practice | Why |
| :--- | :--- |
| **Scan every build** and fail on fixable HIGH and CRITICAL | A consistent, fair gate. |
| **Scan before pushing** | Bad images never reach the registry. |
| **Rescan registry and running images regularly** | New CVEs appear daily. |
| **Rebuild on a schedule** | Picks up patched base images. |
| **Generate and store SBOMs** | Instant "where is component X?" answers. |
| **Prioritize by risk** (fix available, exploited, exposed) | Effort goes where it matters. |
| **Document every exception** with reason and expiry | Accepted risk is deliberate and temporary. |
| **Protect `.trivyignore`** with CODEOWNERS | It is a way to bypass the gate. |

### Distribute and Trust

| Practice | Why |
| :--- | :--- |
| **Sign** images and **verify** before deploy | Integrity and origin. |
| **Prefer keyless signing** in CI with pinned verification identity | No long-lived key to steal. |
| **Sign and deploy by digest** | Tags can be moved. |
| **Attach SBOM and scan attestations** | Policies can require them. |
| **Private registries, least-privilege tokens, immutable tags** | Reduces registry abuse. |
| **Use trusted image sources**, check names for typosquatting | Avoids malicious images. |

### Run

| Practice | Why |
| :--- | :--- |
| `--cap-drop ALL`, `--read-only`, `no-new-privileges` | Strong default hardening. |
| **Resource limits** (memory, CPU, PIDs) | Prevents denial of service. |
| **Never** `--privileged`, the Docker socket, or host mounts without strong reason | Each nearly removes isolation. |
| **Secrets from a secrets manager** or mounted files | Not in env vars or images. |
| **Network segmentation**, localhost bindings, internal networks | Limits lateral movement. |
| **Patch** Docker, containerd, runc, and the host | Prevents breakouts. |
| **Rootless Docker** where feasible | Breakout lands unprivileged. |
| **Monitor runtime behavior** (Falco, audit logs) | Detect attacks in progress. |

### Protect the Supply Chain Itself

| Practice | Why |
| :--- | :--- |
| **Pin GitHub Actions to full commit SHAs** | Tags can be silently re-pointed (the 2026 Trivy incident). |
| **Pin tool versions and verify checksums or signatures** | Do not run unverified downloads. |
| **Never `curl | sh` unreviewed installers** | You run whatever the server sends. |
| **Minimal workflow `permissions:`** | Limits what a malicious step can do. |
| **Short-lived credentials (OIDC)** instead of stored cloud keys | Nothing durable to steal. |
| **Have an incident plan**: if a tool may have run compromised, rotate every reachable secret | Speed matters. |

### Maturity Roadmap

```text
Level 1  Basic       Non-root user, slim base, .dockerignore, no secrets in images
Level 2  Scanned     Trivy in CI with a gate, SBOMs stored, scheduled rescans
Level 3  Trusted     Digest pinning, signing and verification, private registry, pinned actions
Level 4  Enforced    Admission control rejects unsigned and non-compliant images (Module 08),
                     runtime detection (Falco), automated base-image rebuilds
```

### Know the Limits

- A **clean scan** means "no *known* vulnerabilities in the database at this moment", not "this image is secure".
- A **valid signature** proves origin and integrity, not safety.
- Image scanning does not replace **SAST** (your code), **DAST** (running behavior), **runtime monitoring**, or **good architecture**.

---

## 18. Knowledge Check

1. Why is a container **not** the same as a virtual machine, and why does the shared kernel matter for security?
2. Name four Linux features that provide container isolation and what each does.
3. Why is membership in the `docker` group, or access to `/var/run/docker.sock`, effectively root access?
4. Explain image layers. Why does deleting a secret in a later layer **not** remove it from the image?
5. What is the difference between a tag and a digest? Which should you deploy, and why?
6. List five problems in the insecure Dockerfile from section 4 and how to fix each.
7. What does a multi-stage build achieve for security?
8. Why should the `USER` in a Dockerfile be a **numeric** non-root ID?
9. Why are `ENV`, `ARG`, and `COPY .env` unsafe for secrets? What is the safe build-time alternative?
10. What does `.dockerignore` protect against?
11. Compare full, slim, distroless, and scratch base images.
12. What does `trivy image` look at to find vulnerabilities? Name the two main categories of packages it examines.
13. What do the **Status** values `fixed`, `affected`, and `will_not_fix` mean, and how should each change your action?
14. Why is `--ignore-unfixed` useful for a pipeline gate? What is its downside?
15. What do `--exit-code 1` and `--severity` do together?
16. Why does a base image change often cause the biggest drop in vulnerability counts?
17. How do you decide which vulnerability to fix first when a report has hundreds of findings?
18. What is an SBOM, and how does it help when a new critical vulnerability is announced?
19. What does a Cosign signature prove, and what does it **not** prove?
20. Compare **key-based** and **keyless** signing. Which is better for CI/CD, and why?
21. Why must Cosign sign a **digest** and not a tag? How does this stop tag tampering?
22. Why must keyless verification include `--certificate-identity` and `--certificate-oidc-issuer`?
23. Where can signature verification be enforced so that nobody can forget it?
24. Name six `docker run` flags that harden a container at runtime and the attack each reduces.
25. Why are `--privileged`, a mounted Docker socket, and `--network host` dangerous?
26. Why are environment variables a weak way to deliver secrets to containers? What are better options?
27. Explain what happened in the March 2026 Trivy supply chain attack and three specific defenses that would reduce the risk.
28. Why should the scan run **before** the image is pushed, and signing only on the main branch?

---

## 19. Official References

### Docker

- Docker build best practices: <https://docs.docker.com/build/building/best-practices/>
- Docker Engine security: <https://docs.docker.com/engine/security/>
- Rootless mode: <https://docs.docker.com/engine/security/rootless/>
- Build secrets: <https://docs.docker.com/build/building/secrets/>
- Docker Bench for Security: <https://github.com/docker/docker-bench-security>
- Hadolint (Dockerfile linter): <https://github.com/hadolint/hadolint>
- Distroless images: <https://github.com/GoogleContainerTools/distroless>

### Trivy

- Trivy project site and documentation: <https://trivy.dev/>
- Trivy source and releases: <https://github.com/aquasecurity/trivy>
- Trivy release signature verification: <https://trivy.dev/docs/v0.72/getting-started/signature-verification/>
- Security advisory for the March 2026 incident: <https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23>
- Aqua's incident update: <https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/>
- Incident discussion and updates: <https://github.com/aquasecurity/trivy/discussions/10425>

### Cosign, Sigstore, and SBOM Tools

- Sigstore documentation (Cosign): <https://docs.sigstore.dev/>
- Cosign source and releases: <https://github.com/sigstore/cosign>
- Syft (SBOM generator): <https://github.com/anchore/syft>
- CycloneDX: <https://cyclonedx.org/>
- SPDX: <https://spdx.dev/>
- SLSA (supply chain framework): <https://slsa.dev/>

### Standards and Guidance

- OWASP Docker Security Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html>
- NIST SP 800-190, Application Container Security Guide: <https://csrc.nist.gov/pubs/sp/800/190/final>
- CIS Docker Benchmark: <https://www.cisecurity.org/benchmark/docker>

### Related Modules in This Repository

- [Module 02: Linux Security](../02-linux-security/README.md) for capabilities, permissions, and host hardening.
- [Module 03: Git, GitHub and Secret Security](../03-git-github-and-secret-security/README.md) for pinning actions and protecting secrets.
- [Module 05: Software Composition Analysis and SBOM](../05-software-composition-analysis-sca-and-sbom/README.md) for CVE, CVSS, and SBOM concepts.
- [Module 08: Kubernetes Security](../08-kubernetes-security/README.md) for admission control, Kyverno, and Falco.

> [!NOTE]
> Tool versions, image names, action versions, flags, and registry limits change often. Security tools also publish advisories. Before relying on any command in this module, check the official documentation and advisories linked above.

---


---

## Summary

In this module, you learned to secure containers across their whole lifecycle:

- **Containers share the host kernel**, so isolation settings and a secure host matter. The Docker daemon and socket are effectively root.
- **Dockerfiles** should use a minimal, pinned base image, multi-stage builds, a non-root numeric user, a `.dockerignore`, and no secrets in layers.
- **Image layers are permanent history**. Anything that was ever copied or set in a layer can be recovered.
- **Trivy** scans images, files, Dockerfiles, and SBOMs for vulnerabilities, secrets, and misconfigurations. A gate with `--exit-code`, `--severity`, and `--ignore-unfixed` keeps risky images from shipping. Prioritize by fix availability, exploitability, exposure, and impact.
- **Remediation** is mostly a better base image, updated dependencies, and removing what is not needed. Always rescan to prove it.
- **SBOMs** answer "where is this component?" quickly and can be rescanned later.
- **Cosign** signs image **digests** to prove origin and integrity, with **keyless** signing ideal for CI. Always verify with a **pinned identity**, and enforce verification where nobody can skip it.
- **Runtime hardening** (`--cap-drop ALL`, `--read-only`, `no-new-privileges`, limits, no privileged mode or Docker socket) limits what an attacker can do.
- **Security tools are part of your supply chain.** The March 2026 Trivy compromise showed why you must **pin GitHub Actions by commit SHA, pin and verify tool versions, and limit CI credentials**.

In the next module, you will take these secured, signed images into **Kubernetes** and learn to protect clusters with RBAC, Pod Security Standards, admission control, and runtime detection.

---

## Next Module

➡️ [Module 08: Kubernetes Security](../08-kubernetes-security/README.md)

[⬅️ Previous: Module 06: Dynamic Application Security Testing](../06-dynamic-application-security-testing-dast/README.md) | [🏠 Main README](../README.md)

---

<div align="center">

**Learn. Secure. Automate. Deploy. 🛡️**

</div>
