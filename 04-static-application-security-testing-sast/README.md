# Module 04: Static Application Security Testing (SAST) 🧩

## 📌 Overview

Static Application Security Testing (SAST) analyzes application source code to identify potential security vulnerabilities **without executing the application**.

SAST helps developers detect security issues early in the Software Development Life Cycle (SDLC), before vulnerable code reaches production.

In this module, we will use **SonarQube** to perform static code analysis and integrate security checks into CI/CD pipelines.

> [!NOTE]
> This module builds on Module 03. There you learned to stop **secrets** from entering your repository. Here you learn to find **insecure code** (such as SQL injection or weak cryptography) before it is merged.

> [!IMPORTANT]
> **Lab environment:** You need a machine with **Docker and Docker Compose**, about **4 GB of free RAM** for SonarQube, and a terminal. Linux, macOS, or Windows with WSL2 all work. The lab application in this module is **intentionally vulnerable**. Scan it, but **never run it on a public network or deploy it**.

## 🎯 Learning Objectives

By the end of this module, you will be able to:

- Understand SAST and its role in DevSecOps.
- Differentiate SAST, DAST, and Software Composition Analysis (SCA).
- Identify common source-code security vulnerabilities.
- Understand SonarQube architecture and analysis workflow.
- Configure projects for static code analysis.
- Analyze security findings and remediate vulnerabilities.
- Configure Quality Gates to enforce code quality and security standards.
- Integrate SAST into GitHub Actions and Jenkins pipelines.
- Prevent vulnerable code from progressing through CI/CD.

## 📚 Table of Contents

1. [Introduction to SAST](#1-introduction-to-sast)
2. [SAST vs DAST vs SCA](#2-sast-vs-dast-vs-sca)
3. [Common Source Code Vulnerabilities](#3-common-source-code-vulnerabilities)
4. [Introduction to SonarQube](#4-introduction-to-sonarqube)
5. [SonarQube Architecture](#5-sonarqube-architecture)
6. [Setting Up SonarQube](#6-setting-up-sonarqube)
7. [Performing Your First Code Scan](#7-performing-your-first-code-scan)
8. [Understanding Security Findings](#8-understanding-security-findings)
9. [SonarQube Quality Profiles and Quality Gates](#9-sonarqube-quality-profiles-and-quality-gates)
10. [SAST with GitHub Actions](#10-sast-with-github-actions)
11. [SAST with Jenkins](#11-sast-with-jenkins)
12. [Securing Pull Requests](#12-securing-pull-requests)
13. [Hands-on Labs](#13-hands-on-labs)
14. [Best Practices](#14-best-practices)
15. [Troubleshooting](#15-troubleshooting)
16. [Interview Questions](#16-interview-questions)
17. [References](#17-references)

---

## 1. Introduction to SAST

### What Is SAST?

**Static Application Security Testing (SAST)** reads your **source code** (or compiled code) and looks for patterns that are known to be insecure. It is called **static** because the program is **never run**. The tool only reads it.

> **Analogy:** SAST is like a **proofreader checking a blueprint** before the building is built. The proofreader can spot a missing fire exit on paper, long before anyone has to evacuate a real building.

### Why Does It Matter?

Fixing a vulnerability costs **much less** the earlier you find it.

```text
Cost to fix a vulnerability

  Low  |  Writing code  ->  Pull request  ->  Testing  ->  Production  |  High
       |  (SAST here)       (SAST here)                    (breach!)    |
```

| Stage Where It Is Found | What It Typically Means |
| :--- | :--- |
| **While writing code** | The developer fixes it in minutes. |
| **In a pull request** | One reviewer comment and a quick change. |
| **In testing** | A bug ticket, a rebuild, and a re-test. |
| **In production** | An incident, emergency patching, possible data loss, and reputation damage. |

This is the **shift-left** idea from Module 01: move security checks earlier in the lifecycle.

### How SAST Works

Most SAST tools follow these steps:

```text
Source code
    |
    v
1. PARSE            Turn code into a structure the tool can reason about
    |               (an "abstract syntax tree")
    v
2. ANALYZE          Apply security rules:
    |                 - Pattern rules: "Is MD5 used for hashing?"
    |                 - Data-flow (taint) rules: "Does user input reach a database query?"
    v
3. REPORT           List findings with file, line, severity, and fix advice
```

**Taint analysis** is the most powerful technique and worth understanding:

```text
  SOURCE                    PROPAGATION                    SINK
  (untrusted input)  --->   (variables, functions)  --->   (dangerous operation)

  request.args["name"]  -->  username  -->  "SELECT ... '" + username + "'"  --> db.execute()

  If no SANITIZER (validation or escaping) sits between source and sink,
  the tool reports an injection vulnerability.
```

| Term | Meaning | Example |
| :--- | :--- | :--- |
| **Source** | Where untrusted data enters | URL parameters, form fields, HTTP headers, files |
| **Sink** | A dangerous place data must not reach unchecked | SQL query, shell command, HTML output, file path |
| **Sanitizer** | Code that makes data safe | Parameterized queries, escaping, validation |

### Strengths and Limits of SAST

| ✅ Strengths | ⚠️ Limitations |
| :--- | :--- |
| Finds problems **early**, even before the app can run | Can produce **false positives** (reports that are not real problems) |
| Points to the **exact file and line** | Can have **false negatives** (misses real problems) |
| Scans **all code paths**, including rarely used ones | Cannot see **runtime** behavior, server configuration, or deployed environments |
| Easy to **automate** in every pull request | Struggles with **business logic** flaws (for example, "any user can view any invoice") |
| Teaches developers secure patterns through fix advice | Language and framework support varies |

> [!IMPORTANT]
> **SAST is one layer, not a complete solution.** It must be combined with secret scanning (Module 03), dependency scanning (Module 05), dynamic testing (Module 06), and container and infrastructure checks (later modules).

### Where SAST Fits in the Pipeline

```text
Developer laptop        Pull request / CI                     After merge
------------------      ---------------------------------     ------------------
IDE plugin              Gitleaks (secrets)                    Build image
(SonarQube for IDE) --> SAST (SonarQube)           -->        Deploy to test
Pre-commit hook         Quality Gate: PASS or FAIL            DAST (Module 06)
                        (blocks merge if FAIL)
```

---

## 2. SAST vs DAST vs SCA

Three testing approaches look at **different things**. You need all three.

> **Analogy:** Imagine building a house.
> - **SAST** proofreads the **blueprints** (your source code).
> - **SCA** checks the **labels on purchased materials** (third-party libraries) to see if any were recalled.
> - **DAST** tries to **break into the finished house** (the running application).

| | **SAST** | **SCA** | **DAST** |
| :--- | :--- | :--- | :--- |
| **Full name** | Static Application Security Testing | Software Composition Analysis | Dynamic Application Security Testing |
| **What it examines** | **Your** source code | **Third-party** libraries and dependencies | The **running** application |
| **Needs a running app?** | No | No | **Yes** |
| **Typical findings** | SQL injection, hardcoded credentials, weak crypto, unsafe functions | Known CVEs in libraries (for example, an old vulnerable version of a framework) | Exposed endpoints, missing security headers, injection that works at runtime, authentication flaws |
| **When it runs** | Early: IDE, pull request, build | Early: build | Later: against a test or staging environment |
| **Gives exact code line?** | **Yes** | Points to the dependency | Points to the URL or request |
| **Blind spots** | Runtime and configuration issues | Flaws in your own code | Code paths that are never exercised; slower |
| **Tool in this course** | **SonarQube** (this module) | OWASP Dependency-Check, Syft (Module 05) | OWASP ZAP (Module 06) |

### One Vulnerability, Three Views

Suppose your app is vulnerable to SQL injection:

- **SAST** shows the **line of code** where user input is joined into a query.
- **DAST** proves that sending a crafted request to `/user?name=...` **actually exposes data**.
- **SCA** would not find it at all, because it is a flaw in **your** code, not in a library.

### Related Techniques You May Hear About

| Technique | What It Is |
| :--- | :--- |
| **Secret scanning** | Finds exposed credentials in code and history (Module 03, Gitleaks). |
| **IAST** (Interactive AST) | An agent inside the running app watches for vulnerabilities during testing. |
| **IaC scanning** | Checks Terraform and similar files for insecure configuration (Module 09, Checkov). |
| **Container scanning** | Checks images for known vulnerabilities (Module 07, Trivy). |

---

## 3. Common Source Code Vulnerabilities

These are the weaknesses SAST tools look for most often. For each one you will see **what it is, why it is dangerous, vulnerable code, and the fix**. The examples use Python and Flask, but the ideas apply to every language.

> [!NOTE]
> Vulnerability families are catalogued in two public lists: **OWASP Top 10** (the most critical web application risks) and **CWE** (Common Weakness Enumeration, a numbered dictionary of weakness types, such as CWE-89). SonarQube labels many rules with these identifiers. OWASP Top 10 categories change between editions, so check the current version. The mapping below uses the 2021 category names.

| Vulnerability | CWE | OWASP Top 10 (2021) Category | Can SAST Find It? |
| :--- | :---: | :--- | :--- |
| SQL injection | CWE-89 | A03 Injection | Yes (best with data-flow analysis) |
| OS command injection | CWE-78 | A03 Injection | Yes |
| Cross-site scripting (XSS) | CWE-79 | A03 Injection | Yes |
| Hardcoded credentials | CWE-798 | A07 Identification and Authentication Failures | Yes |
| Weak cryptographic hash | CWE-327 | A02 Cryptographic Failures | Yes |
| Insecure deserialization | CWE-502 | A08 Software and Data Integrity Failures | Yes |
| Path traversal | CWE-22 | A01 Broken Access Control | Yes |
| Disabled TLS certificate checks | CWE-295 | A02 Cryptographic Failures | Yes |
| Server-side request forgery (SSRF) | CWE-918 | A10 SSRF | Partly |
| Debug mode left on | CWE-489 | A05 Security Misconfiguration | Yes |
| Missing authorization checks | CWE-862 | A01 Broken Access Control | **Rarely** (needs understanding of business rules) |

### 3.1 SQL Injection

**What:** User input is joined directly into a database query, so an attacker can change the meaning of the query.

**Why it is dangerous:** Attackers can read, change, or delete data, or bypass login.

```python
# ❌ VULNERABLE: input is concatenated into the query
username = request.args.get("name")
query = "SELECT * FROM users WHERE name = '" + username + "'"
conn.execute(query)

# If name is:  ' OR '1'='1
# the query becomes:  SELECT * FROM users WHERE name = '' OR '1'='1'   (returns every user)
```

```python
# ✅ FIXED: parameterized query. The database treats input as DATA, never as code.
conn.execute("SELECT * FROM users WHERE name = ?", (username,))
```

### 3.2 OS Command Injection

**What:** User input is passed into a shell command.

**Why it is dangerous:** An attacker can run their own commands on your server.

```python
# ❌ VULNERABLE: shell=True with input
host = request.args.get("host")
subprocess.check_output("ping -c 1 " + host, shell=True)
# Input "8.8.8.8; cat /etc/passwd" would run a second command
```

```python
# ✅ FIXED: validate the input and avoid the shell (pass arguments as a list)
import ipaddress
try:
    ipaddress.ip_address(host)
except ValueError:
    return "Invalid host", 400
subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5)
```

### 3.3 Cross-Site Scripting (XSS)

**What:** User input is placed into a web page without escaping, so the browser runs attacker-supplied JavaScript.

**Why it is dangerous:** Attackers can steal sessions, act as the victim, or deface pages.

```python
# ❌ VULNERABLE
name = request.args.get("name", "")
return "<h1>Hello " + name + "</h1>"
# Input <script>...</script> would execute in the victim's browser
```

```python
# ✅ FIXED: escape output (or use a template engine with auto-escaping)
from markupsafe import escape
return "<h1>Hello " + str(escape(name)) + "</h1>"
```

### 3.4 Hardcoded Credentials

**What:** Passwords, keys, or tokens written directly in source code.

**Why it is dangerous:** Anyone with access to the code (or its history) gets the credential. See Module 03.

```python
# ❌ VULNERABLE
DB_PASSWORD = "SuperSecret123!"
```

```python
# ✅ FIXED: read from the environment (or a secret manager such as Vault, Module 11)
import os
DB_PASSWORD = os.environ["DB_PASSWORD"]
```

### 3.5 Weak Cryptography

**What:** Using broken or unsuitable algorithms such as MD5 or SHA-1 for passwords.

**Why it is dangerous:** Attackers can crack the stored hashes very quickly.

```python
# ❌ VULNERABLE: MD5 is fast and broken for passwords
hashed = hashlib.md5(password.encode()).hexdigest()
```

```python
# ✅ FIXED: use a slow, salted password hashing function
from werkzeug.security import generate_password_hash
hashed = generate_password_hash(password)
```

### 3.6 Insecure Deserialization

**What:** Loading untrusted data with a format that can run code while loading, such as Python's `pickle`.

**Why it is dangerous:** An attacker can send data that executes commands when it is loaded.

```python
# ❌ VULNERABLE
data = pickle.loads(request.data)
```

```python
# ✅ FIXED: use a data-only format and validate the structure
import json
data = json.loads(request.data)
```

### 3.7 Path Traversal

**What:** A user controls part of a file path and escapes the intended folder using `../`.

**Why it is dangerous:** Attackers can read sensitive files such as configuration or keys.

```python
# ❌ VULNERABLE
filename = request.args.get("name")
open("/var/app/files/" + filename)      # name=../../etc/passwd
```

```python
# ✅ FIXED: let a safe helper confine the path to one directory
from flask import send_from_directory
return send_from_directory("/var/app/files", filename)
```

### 3.8 Disabled TLS Certificate Verification (and SSRF)

**What:** Turning off certificate checks, or letting users choose any URL for the server to fetch.

**Why it is dangerous:** Disabling verification allows man-in-the-middle attacks. Fetching user-chosen URLs lets attackers make your server call internal services (**SSRF**).

```python
# ❌ VULNERABLE
requests.get(request.args.get("url"), verify=False)
```

```python
# ✅ FIXED: keep verification on, allow only known hosts, set a timeout
from urllib.parse import urlparse
ALLOWED_HOSTS = {"api.example.com"}
url = request.args.get("url", "")
if urlparse(url).hostname not in ALLOWED_HOSTS:
    return "Host not allowed", 400
requests.get(url, timeout=5)           # verify=True is the default
```

### 3.9 Security Misconfiguration in Code

```python
# ❌ VULNERABLE: debug mode exposes an interactive console; 0.0.0.0 exposes it to the network
app.run(host="0.0.0.0", debug=True)
```

```python
# ✅ FIXED
app.run(host="127.0.0.1", debug=False)     # use a production server (such as gunicorn) in deployment
```

### The Secure Coding Mindset

| Principle | Meaning |
| :--- | :--- |
| **Never trust input** | Treat everything from users, files, and other systems as untrusted. |
| **Validate input, encode output** | Check what comes in; escape what goes out. |
| **Use safe APIs** | Parameterized queries, argument lists instead of shell strings, auto-escaping templates. |
| **Use proven crypto** | Never invent your own. Use maintained libraries and modern algorithms. |
| **Keep secrets out of code** | Environment variables and secret managers. |
| **Fail safely** | Do not leak stack traces, and deny access by default. |

---

## 4. Introduction to SonarQube

### What Is SonarQube?

**SonarQube** is a platform that continuously inspects code for **bugs, security vulnerabilities, and maintainability problems**. You run a **scanner** against your project, send the results to the **SonarQube server**, and view them in a web dashboard. It can also **fail a pipeline** when the code does not meet your standards.

It covers three kinds of quality:

| Quality | Question It Answers | Example |
| :--- | :--- | :--- |
| 🔒 **Security** | Can an attacker abuse this code? | SQL injection, hardcoded password |
| 🐞 **Reliability** | Could this code crash or misbehave? | Null pointer, resource leak |
| 🧹 **Maintainability** | Will this code be painful to change? | Duplicated code, overly complex function ("code smell") |

### SonarQube Editions

Sonar offers several products. Names and limits change over time, so check the current pricing and documentation pages.

| Product | Where It Runs | Notes |
| :--- | :--- | :--- |
| **SonarQube Community Build** | Your own server (free, open source) | **Used in this module's labs.** Analyzes one main branch. |
| **SonarQube Server: Developer / Enterprise / Data Center editions** | Your own server (paid) | Adds branch and **pull request analysis**, deeper security analysis such as **injection (taint) detection**, and more languages and reports. |
| **SonarQube Cloud** | Hosted by Sonar | No server to maintain. Has a free tier with limits. Supports pull request analysis. |

> [!IMPORTANT]
> **What the free Community Build can and cannot do (at the time of writing):**
> - ✅ Analyze your main branch, show a dashboard, apply quality profiles, and enforce quality gates.
> - ✅ Detect many vulnerabilities and flag **Security Hotspots** for review.
> - ❌ Does **not** analyze separate branches or **pull requests**, and does **not** decorate pull requests with comments.
> - ❌ The deeper **taint (data-flow) analysis** for injection flaws is part of the paid editions, so some SQL injection, XSS, and command injection findings you saw in section 3 may not be reported by the Community Build.
>
> Section 12 explains how to protect pull requests with each option. Always check Sonar's current documentation, because editions evolve.

### Key SonarQube Concepts

| Term | Meaning |
| :--- | :--- |
| **Project** | One codebase being analyzed, identified by a unique **project key**. |
| **Rule** | A single check (for example, "Credentials should not be hard-coded"). |
| **Issue** | One place where code breaks a rule. |
| **Vulnerability** | An issue that is a **confirmed** security weakness. It should be fixed. |
| **Security Hotspot** | Security-sensitive code that **needs a human to review** and decide if it is safe. |
| **Quality Profile** | The **set of rules** used for a language. |
| **Quality Gate** | A set of **pass/fail conditions** applied to the results. This is your pipeline's gatekeeper. |
| **New Code** | The code that changed recently (since a chosen reference point). |
| **Technical debt** | Estimated time to fix all maintainability issues. |
| **Rating (A to E)** | A letter grade for Security, Reliability, or Maintainability. **A is best.** |
| **Coverage** | The percentage of code executed by automated tests (needs a coverage report). |

### The "Clean as You Code" Idea

A legacy project might have thousands of old issues. Demanding that everyone fixes them all first is unrealistic and demotivating. SonarQube's approach is **Clean as You Code**:

> **Make sure all NEW code is clean. Old code can be improved gradually.**

Quality gates therefore focus on the **New Code** period, so the rule is simple: *"Do not make things worse."* Over time the whole project improves.

### Other SAST Tools You May Meet

| Tool | Notes |
| :--- | :--- |
| **CodeQL** (GitHub code scanning) | Powerful query-based analysis; free for public repositories. |
| **Semgrep** | Fast, rule-based scanner with easy custom rules. |
| **Bandit** | Python-specific security linter. |
| **SpotBugs + Find Security Bugs** | Java-focused. |
| **ESLint security plugins** | JavaScript and TypeScript linting. |

This course uses **SonarQube** because it combines SAST, quality gates, and a dashboard in one platform and integrates with Jenkins and GitHub Actions.

---

## 5. SonarQube Architecture

### The Big Picture

```text
 DEVELOPER / CI SERVER                              SONARQUBE SERVER
+--------------------------+                +-------------------------------------------+
|                          |                |                                           |
|  Your source code        |                |  +--------------+      +----------------+ |
|        |                 |                |  | Web Server   |      | Compute Engine | |
|        v                 |   analysis     |  | (UI and API) |<---->| (processes     | |
|  +--------------+        |   report       |  | port 9000    |      |  reports)      | |
|  | SonarScanner |------- | -------------> |  +------+-------+      +--------+-------+ |
|  | (runs in CI) |        |  (HTTP + token)|         |                       |         |
|  +--------------+        |                |  +------v-------+               |         |
|                          |                |  | Search Server|<--------------+         |
+--------------------------+                |  | (Elasticsearch|                        |
                                            |  |  indexing)   |                         |
                                            |  +--------------+                         |
                                            +--------------------+----------------------+
                                                                 |
                                                      +----------v-----------+
                                                      |  Database            |
                                                      |  (PostgreSQL)        |
                                                      +----------------------+
```

### Components

| Component | Role |
| :--- | :--- |
| **SonarScanner** | A client tool that reads your code and rules, runs the analysis, and **uploads a report**. It runs on your laptop or CI agent, **not** on the server. |
| **Web Server** | Serves the **dashboard** and the **REST API** (default port **9000**). |
| **Compute Engine** | Processes uploaded reports in the **background**, computes metrics, and evaluates the **quality gate**. |
| **Search Server** | An embedded **Elasticsearch** that indexes issues so searching and filtering is fast. |
| **Database** | Stores projects, results, settings, users, and history. Use **PostgreSQL** for anything beyond a quick demo. |

### The Analysis Workflow

```text
1. Developer pushes code
        |
        v
2. CI pipeline starts the SonarScanner
        |
        v
3. Scanner asks the server for the rules (Quality Profile) for each language
        |
        v
4. Scanner analyzes the code on the CI machine
        |
        v
5. Scanner uploads the analysis report to the server (authenticated with a TOKEN)
        |
        v
6. Compute Engine processes the report (a "background task")
        |
        v
7. Results are stored and indexed. The Quality Gate is evaluated
        |
        v
8. Dashboard shows results. The pipeline can read PASSED or FAILED
```

> [!TIP]
> **Step 6 is asynchronous.** The scanner finishes before the server finishes processing. That is why CI pipelines must **wait for the quality gate result** (using `sonar.qualitygate.wait=true`, a webhook, or a dedicated action). You will do this in sections 10 and 11.

### Which Scanner Do I Use?

| Project Type | Scanner | Typical Command |
| :--- | :--- | :--- |
| **Python, JavaScript, Go, PHP, and most others** | **SonarScanner CLI** | `sonar-scanner` (reads `sonar-project.properties`) |
| **Maven (Java)** | SonarScanner for Maven | `mvn verify org.sonarsource.scanner.maven:sonar-maven-plugin:sonar` |
| **Gradle (Java/Kotlin)** | SonarScanner for Gradle | `./gradlew sonar` |
| **.NET** | SonarScanner for .NET | `dotnet sonarscanner begin ... / dotnet build / dotnet sonarscanner end` |
| **Jenkins** | SonarQube Scanner plugin | `withSonarQubeEnv(...)` and `waitForQualityGate` |

### Authentication: Tokens

The scanner proves its identity to the server with a **token** (never a password).

| Token Type | Scope | Recommendation |
| :--- | :--- | :--- |
| **Project analysis token** | Can only run analysis on **one project** | ✅ **Best for CI** (least privilege) |
| **Global analysis token** | Can run analysis on any project | Use only if necessary |
| **User token** | Acts as a user with that user's permissions | For scripts and APIs, not for CI analysis |

---

## 6. Setting Up SonarQube

### Prerequisites

| Requirement | Details |
| :--- | :--- |
| **Docker** and **Docker Compose** | Check with `docker --version` and `docker compose version`. |
| **Memory** | At least **4 GB** available to Docker (SonarQube includes Elasticsearch). |
| **Linux kernel setting** | `vm.max_map_count` must be at least `524288` (Elasticsearch requirement). |
| **Free port** | Port **9000** must not be used by another program. |

### Step 1: Set the Required Kernel Parameters (Linux and WSL2)

SonarQube will refuse to start if these are too low.

```bash
# Check the current values
sysctl vm.max_map_count fs.file-max

# Set them now (temporary, until reboot)
sudo sysctl -w vm.max_map_count=524288
sudo sysctl -w fs.file-max=131072

# Make them permanent
echo "vm.max_map_count=524288" | sudo tee /etc/sysctl.d/99-sonarqube.conf
echo "fs.file-max=131072"      | sudo tee -a /etc/sysctl.d/99-sonarqube.conf
sudo sysctl --system
```

> [!NOTE]
> On **Docker Desktop for macOS and Windows**, the Docker VM is usually already configured. On **WSL2**, run `sudo sysctl -w vm.max_map_count=524288` inside the WSL distribution (or Docker's own WSL environment) if SonarQube fails to start.

### Step 2: Create the Project Folder and a Secret File

Remember Module 03: **passwords do not belong in files you commit.** Generate a random database password and keep it in a `.env` file that Git ignores.

```bash
mkdir ~/sonarqube-lab && cd ~/sonarqube-lab

# Generate a random database password and save it in .env
echo "SONAR_DB_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=')" > .env
chmod 600 .env

# Make sure Git never tracks it
echo ".env" > .gitignore
```

### Step 3: Create `docker-compose.yml`

```yaml
# docker-compose.yml
services:
  sonarqube:
    image: sonarqube:community
    depends_on:
      - db
    environment:
      SONAR_JDBC_URL: jdbc:postgresql://db:5432/sonar
      SONAR_JDBC_USERNAME: sonar
      SONAR_JDBC_PASSWORD: ${SONAR_DB_PASSWORD:?Set SONAR_DB_PASSWORD in .env}
    ports:
      - "9000:9000"
    volumes:
      - sonarqube_data:/opt/sonarqube/data
      - sonarqube_extensions:/opt/sonarqube/extensions
      - sonarqube_logs:/opt/sonarqube/logs

  db:
    image: postgres:17
    environment:
      POSTGRES_USER: sonar
      POSTGRES_PASSWORD: ${SONAR_DB_PASSWORD:?Set SONAR_DB_PASSWORD in .env}
      POSTGRES_DB: sonar
    volumes:
      - postgresql_data:/var/lib/postgresql/data

volumes:
  sonarqube_data:
  sonarqube_extensions:
  sonarqube_logs:
  postgresql_data:
```

| Part | Why It Is There |
| :--- | :--- |
| `image: sonarqube:community` | The free Community Build. For real deployments, **pin a specific version tag** from Docker Hub instead of a moving tag, so upgrades are deliberate. |
| `db` (PostgreSQL) | A real database. SonarQube's built-in database is for evaluation only and cannot be upgraded safely. |
| `${SONAR_DB_PASSWORD:?...}` | Reads the password from `.env` and **stops with an error** if it is missing. |
| `volumes` | Keep data when containers are recreated. |
| `ports: "9000:9000"` | The web interface and API. |

### Step 4: Start SonarQube

```bash
docker compose up -d

# Watch the startup (press Ctrl+C to stop watching)
docker compose logs -f sonarqube
```

Wait until the log says that SonarQube is operational (this can take one to three minutes the first time). Then check:

```bash
curl -s http://localhost:9000/api/system/status
```

Expected output (the version will differ):

```text
{"id":"...","version":"...","status":"UP"}
```

Statuses you may see while starting: `STARTING`, `DB_MIGRATION_RUNNING`. Wait until it reads **`UP`**.

### Step 5: First Login and Hardening

1. Open **http://localhost:9000** in your browser.
2. Log in with username **`admin`** and password **`admin`**.
3. SonarQube forces you to **set a new password**. Choose a strong one and store it in your password manager.

> [!WARNING]
> **Never leave the default `admin/admin` credentials.** Scanners, bots, and attackers try them first.

### Step 6: Quick Alternative (Evaluation Only)

For a five-minute experiment without a database:

```bash
docker run -d --name sonarqube-demo -p 9000:9000 sonarqube:community
```

This uses an embedded demo database. **Do not use it for anything real**, because data cannot be migrated to a newer version.

### Hardening a Real SonarQube Server

The labs run locally, but a server used by a team needs these controls:

| Control | Details |
| :--- | :--- |
| **HTTPS** | Put SonarQube behind a reverse proxy (Nginx, Traefik) with a TLS certificate. Never send tokens over plain HTTP across a network. |
| **Authentication** | Keep **Force user authentication** enabled (**Administration → Configuration → General Settings → Security**). Use SSO/SAML/LDAP where possible. |
| **Least privilege** | Create named users and groups. Give each only the project permissions they need. Limit who is an administrator. |
| **Token hygiene** | Use **project analysis tokens** with an **expiry date** and store them as CI secrets. |
| **Network exposure** | Do not expose the server to the internet unless needed. Restrict by firewall (Module 02) or VPN. |
| **Backups** | Back up the database regularly and test restoring it. |
| **Updates** | Keep SonarQube, plugins, and the database patched. |
| **Plugins** | Install only plugins you trust. They run inside the server. |

---

## 7. Performing Your First Code Scan

You will create a small, **intentionally vulnerable** Python application, register it in SonarQube, and scan it.

> [!CAUTION]
> The code below contains **deliberate security flaws** so that SAST has something to find. It exists only to be **scanned**. Do not run it exposed to a network and do not copy its patterns into real projects.

### Step 1: Create the Sample Application

```bash
mkdir ~/vulnerable-flask-app && cd ~/vulnerable-flask-app
git init -b main
```

Create `app.py`:

```python
# app.py -- INTENTIONALLY VULNERABLE. For SAST training only. Never deploy.
import hashlib
import pickle
import sqlite3
import subprocess

import requests
from flask import Flask, request

app = Flask(__name__)

DB_PASSWORD = "SuperSecret123!"                  # 1. Hardcoded credential
API_URL = "http://internal.example.com/api"      # 2. Clear-text protocol


def get_db():
    return sqlite3.connect("users.db")


@app.route("/user")
def get_user():
    username = request.args.get("name")
    conn = get_db()
    query = "SELECT * FROM users WHERE name = '" + username + "'"   # 3. SQL injection
    return str(conn.execute(query).fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)  # 4. Command injection


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return "<h1>Hello " + name + "</h1>"                             # 5. Reflected XSS


@app.route("/register", methods=["POST"])
def register():
    password = request.form["password"]
    return hashlib.md5(password.encode()).hexdigest()                # 6. Weak hash


@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))                           # 7. Insecure deserialization


@app.route("/file")
def read_file():
    filename = request.args.get("name")
    with open("/var/app/files/" + filename) as f:                    # 8. Path traversal
        return f.read()


@app.route("/fetch")
def fetch():
    return requests.get(request.args.get("url"), verify=False).text  # 9. TLS check off + SSRF


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)                              # 10. Debug mode, all interfaces
```

Create the SonarScanner configuration file `sonar-project.properties`:

```properties
# sonar-project.properties
sonar.projectKey=vulnerable-flask-app
sonar.projectName=Vulnerable Flask App
sonar.projectVersion=1.0

# Where the source code is, and what to skip
sonar.sources=.
sonar.exclusions=**/venv/**,**/.git/**,**/node_modules/**

sonar.sourceEncoding=UTF-8
```

> [!IMPORTANT]
> **Never put the token in this file.** It is committed to Git. The token is supplied at run time through an environment variable.

### Step 2: Create the Project in SonarQube

1. Open **http://localhost:9000** and sign in.
2. Click **Create project** (or **Projects → Create Project**) and choose **Local project** (manual setup).
3. Enter:
   - **Project display name:** `Vulnerable Flask App`
   - **Project key:** `vulnerable-flask-app` (must match `sonar.projectKey`)
   - **Main branch name:** `main`
4. For the **New Code** definition, choose **Use the global setting** (or "Previous version"), then click **Create project**.
5. Choose **Locally** as the analysis method.

### Step 3: Generate a Token

1. Click your **avatar (top right) → My Account → Security**.
2. Under **Generate Tokens**, enter:
   - **Name:** `lab-analysis`
   - **Type:** **Project Analysis Token** and select your project
   - **Expires in:** 30 days
3. Click **Generate** and **copy the token now**. It is shown only once.

Store it in an environment variable without leaving it in your shell history:

```bash
read -rs SONAR_TOKEN     # paste the token, press Enter
export SONAR_TOKEN
```

### Step 4: Run the Scanner

The easiest method needs no installation: run the official scanner in Docker.

```bash
cd ~/vulnerable-flask-app

# Linux: --network host lets the scanner container reach localhost:9000
docker run --rm \
  --network host \
  -e SONAR_HOST_URL="http://localhost:9000" \
  -e SONAR_TOKEN="$SONAR_TOKEN" \
  -v "$(pwd):/usr/src" \
  sonarsource/sonar-scanner-cli
```

> [!NOTE]
> **macOS and Windows (Docker Desktop):** `--network host` does not work the same way. Remove it and use `-e SONAR_HOST_URL="http://host.docker.internal:9000"` instead.

At the end you should see something like:

```text
INFO: Analysis total time: ...
INFO: ANALYSIS SUCCESSFUL, you can find the results at: http://localhost:9000/dashboard?id=vulnerable-flask-app
```

**Alternative: install the scanner on your machine.** Download SonarScanner CLI from Sonar's website or use a package manager (for example `brew install sonar-scanner`), then run `sonar-scanner` in the project folder. It reads `sonar-project.properties` and the `SONAR_HOST_URL` and `SONAR_TOKEN` environment variables.

### Step 5: View the Results

Open **http://localhost:9000/dashboard?id=vulnerable-flask-app**. The first analysis can take a few seconds to process. Section 8 teaches you how to read what you see.

### Scanning Other Languages (Reference)

| Language | What Changes |
| :--- | :--- |
| **Java (Maven)** | `mvn -B verify org.sonarsource.scanner.maven:sonar-maven-plugin:sonar -Dsonar.projectKey=<key>` with `SONAR_TOKEN` and `SONAR_HOST_URL` set. |
| **Java (Gradle)** | Add the `org.sonarqube` Gradle plugin, then `./gradlew build sonar`. |
| **JavaScript / TypeScript** | Use the SonarScanner CLI and set `sonar.sources`. For coverage, set `sonar.javascript.lcov.reportPaths`. |
| **Python** | Use the SonarScanner CLI. For coverage, set `sonar.python.coverage.reportPaths=coverage.xml`. |
| **.NET** | `dotnet sonarscanner begin /k:"<key>" ...`, then `dotnet build`, then `dotnet sonarscanner end`. |

---

## 8. Understanding Security Findings

### Reading the Project Dashboard

The **Overview** page summarizes the latest analysis:

| Area | What It Shows |
| :--- | :--- |
| **Quality Gate status** | **Passed** or **Failed** for this project. |
| **Security** | Number of open vulnerabilities and the **security rating** (A to E). |
| **Security Hotspots** | Number to review and the **review rating**. |
| **Reliability** | Bugs and the reliability rating. |
| **Maintainability** | Code smells, technical debt, and rating. |
| **Coverage** | Test coverage (0% until you import a coverage report). |
| **Duplications** | Percentage of duplicated code. |
| **Lines of code** | Size of the analyzed code. |

Tabs across the top: **Overview, Issues, Security Hotspots, Measures, Code, Activity, Project Information**.

### Vulnerabilities vs. Security Hotspots

This distinction confuses many beginners and is **very important**.

| | **Vulnerability** | **Security Hotspot** |
| :--- | :--- | :--- |
| **Meaning** | The tool is confident this code is **insecure**. | The code is **security-sensitive**, and **safety depends on context**. |
| **Action** | **Fix it.** | **A human must review it** and decide: safe or needs a fix. |
| **Example** | Hardcoded password. | Use of a cryptographic function, `debug=True`, regular expression, or command execution. |
| **Affects** | The **Security rating**. | The **Security Review rating** (percentage of hotspots reviewed). |
| **Statuses** | Open, Confirmed, False positive, Accepted, Fixed | To review, Acknowledged, Fixed, Safe |

> [!NOTE]
> Status names change slightly between SonarQube versions (for example, "Won't fix" became "Accepted" in recent versions). The ideas stay the same.

### Reading an Issue

1. Open the **Issues** tab and filter by **Software Quality: Security** (or Type: Vulnerability) to see only security problems.
2. Click an issue. You will see the code with the problem highlighted and a detail pane with tabs. Names vary slightly by version, but typically:

| Tab | What It Tells You |
| :--- | :--- |
| **Why is this an issue?** | Explains the risk in plain language. |
| **Where is the risk?** / **Assess the risk** | Helps you decide how serious it is in your context. |
| **How can I fix it?** | Shows vulnerable and compliant code examples. |
| **More Info** | Links to OWASP, CWE, and other references. |

3. Note the **rule identifier** (for example, a rule key such as `python:S2068`), the **severity**, the **file and line**, and the CWE or OWASP tags.

### Severity Levels

SonarQube ranks issues by their impact. Newer versions use these levels (older versions used Blocker, Critical, Major, Minor, Info):

| Severity | Meaning | Typical Response |
| :--- | :--- | :--- |
| **Blocker / High** | Likely exploitable or high impact | Fix immediately, block the release |
| **Medium** | Real weakness with moderate impact | Fix soon, within the sprint |
| **Low** | Minor impact or hard to exploit | Fix when convenient |
| **Info** | Informational | Optional |

### Ratings (A to E)

| Rating | Meaning |
| :---: | :--- |
| **A** | Best. No issues of the relevant kind. |
| **B** | Minor problems only. |
| **C** | Moderate problems. |
| **D** | Serious problems. |
| **E** | Worst. At least one most-severe problem. |

The exact thresholds differ by version, so check the documentation if you need the precise numbers. For **security hotspots**, the review rating is based on the **percentage reviewed**: the more you review, the better the grade.

### What You Should Expect From the Sample App

After scanning `app.py`, you will typically see items such as:

| Finding | Type | Why It Appears |
| :--- | :--- | :--- |
| Hard-coded password (`DB_PASSWORD`) | **Vulnerability** | Credentials in source code (section 3.4). |
| Weak hash (`md5`) | **Security Hotspot** | Weak hashing algorithm (section 3.5). |
| Debug mode on (`debug=True`) | **Security Hotspot** | Debug features in production (section 3.9). |
| Disabled certificate verification | **Vulnerability** | `verify=False` (section 3.8). |
| Clear-text HTTP URL | **Security Hotspot** | `http://` instead of `https://`. |
| Command execution with `shell=True` | **Security Hotspot** | Possible command injection (section 3.2). |

> [!IMPORTANT]
> **Do not worry if the Community Build shows fewer findings than the ten flaws in the code.** The data-flow ("taint") detections for SQL injection, XSS, deserialization, path traversal, and some command injection are provided by SonarQube's paid editions. This is a **real-world lesson**: a clean report from one tool does **not** prove the code is safe. It is also why you combine SAST with code review, secure coding standards, and DAST (Module 06). The exact list depends on your SonarQube version and edition.

### Triage: Deciding What To Do With Each Finding

```text
                    Open the finding
                           |
              Is the code really vulnerable?
               /                              \
            YES                               NO / NOT SURE
             |                                   |
      Fix it now (or plan it)          Investigate: can untrusted
      and rescan                       input reach this code?
                                          /                \
                                       YES                  NO
                                        |                    |
                                  Treat as real       Mark as False Positive (issue)
                                  and fix             or Safe (hotspot) WITH A COMMENT
                                                      explaining why
```

Triage rules for teams:

- **Never mark something safe without writing a reason.** Future readers (and auditors) need it.
- Prefer **fixing** over marking. A false-positive label is a decision that someone must be able to defend.
- Limit who may change statuses (permissions: **Administer Issues** and **Administer Security Hotspots**).
- Review a sample of "safe" and "false positive" decisions regularly.

### How to Change an Issue or Hotspot Status

**For an issue:** open it, click the status button (for example **Open**), and choose **Confirm**, **False positive**, or **Accept**. Add a comment, then confirm.

**For a hotspot:** open **Security Hotspots**, select it, read **Where is the risk?**, **Assess the risk**, and **How can I fix it?**, then click **Review** and choose **Safe**, **Fixed**, or **Acknowledged** with a comment.

---

## 9. SonarQube Quality Profiles and Quality Gates

These two features control **what is checked** and **what is allowed**.

```text
QUALITY PROFILE                      QUALITY GATE
"Which RULES do we apply?"           "What RESULTS are acceptable?"

 Python rules: 300+ active            Condition 1: no new vulnerabilities
 Security rules: ON                   Condition 2: all new hotspots reviewed
 ...                                  Condition 3: coverage on new code >= 80%
        |                                           |
        v                                           v
   Analysis finds issues  ---------->  PASSED (merge/deploy)  or  FAILED (stop)
```

### Quality Profiles

A **Quality Profile** is the list of rules that are **active** for one language. Every language has a default built-in profile called **Sonar way**.

| Fact | Detail |
| :--- | :--- |
| **One profile per language** | Python projects use a Python profile, JavaScript projects use a JavaScript profile, and so on. |
| **Built-in profiles are read-only** | You cannot edit **Sonar way**. Instead, **extend** or **copy** it. |
| **Inheritance** | An **extended** profile inherits rules from its parent and receives updates when the parent is updated. A **copy** is independent. |
| **Assignment** | Set a profile as the **default** for a language, or assign it to one project. |

#### Create a Stricter Profile (Step by Step)

1. Click **Quality Profiles** in the top menu.
2. Find your language (for example **Python**) and open the **Sonar way** profile.
3. Open the profile's menu (the three dots or gear) and choose **Extend**.
4. Name it, for example `Python - Strict Security`.
5. In the new profile, click **Activate More** (or **Rules**) and filter by **Type: Vulnerability** or **Security Hotspot**, or by **Status: Inactive**.
6. Review and **activate** additional security rules.
7. Optionally change the severity of rules that matter more to your organization.
8. To make it the default: open the profile menu and choose **Set as Default**.
9. To use it for **one project only**: open the project, go to **Project Settings → Quality Profiles**, and choose the profile for that language.

> [!TIP]
> Activate more rules gradually. A sudden jump from 300 to 600 rules can bury developers in findings. Start with the security rules.

### Quality Gates

A **Quality Gate** is a set of **conditions** that the analysis results must meet. The result is **Passed** or **Failed**. This is the part your CI/CD pipeline reads to decide whether to continue.

#### The Default Gate

SonarQube includes a built-in gate called **Sonar way**. In recent versions it focuses on **new code** and, in plain terms, requires that:

- There are **no new issues** (older versions used rating A conditions instead).
- All new **security hotspots are reviewed**.
- **New code coverage** is at least **80%**.
- **New code duplication** is at most **3%**.

> [!NOTE]
> The exact conditions of the built-in gate vary by version. Open **Quality Gates → Sonar way** on your server to see what applies to you. Built-in gates cannot be edited, so create your own to customize.

#### Why Focus on New Code?

The gate evaluates **new code** (code changed since your chosen reference point), following **Clean as You Code**. An old project with 500 legacy issues can still pass the gate as long as the **new** code is clean.

Set the New Code definition in **Project Settings → New Code**:

| Option | Meaning | Best For |
| :--- | :--- | :--- |
| **Previous version** | Code since the last version number you set | Versioned releases |
| **Number of days** | Code changed in the last N days (for example 30) | Continuous delivery |
| **Reference branch** | Code that differs from a reference branch such as `main` | Feature-branch workflows (paid editions) |

#### Create a Custom Security Quality Gate (Step by Step)

1. Click **Quality Gates** in the top menu, then **Create**.
2. Name it `Strict Security`.
3. Click **Add Condition**.
4. Choose the scope **On New Code** and add conditions such as:

| Metric | Operator | Value | Meaning |
| :--- | :--- | :--- | :--- |
| **Security Rating** | is worse than | **A** | No new vulnerabilities allowed. |
| **Security Hotspots Reviewed** | is less than | **100%** | Every new hotspot must be reviewed. |
| **Reliability Rating** | is worse than | **A** | No new bugs. |
| **Coverage** | is less than | **80%** | Enough tests on new code. |
| **Duplicated Lines (%)** | is greater than | **3%** | Limit copy-and-paste. |

5. Apply it to your project: open the project, go to **Project Settings → Quality Gate**, and choose **Always use a specific Quality Gate**, then **Strict Security**. To use it for everything, open the gate in **Quality Gates** and click **Set as Default**.

#### Suggested Gates by Maturity

| Stage | Gate Strategy |
| :--- | :--- |
| **1. Visibility** (first weeks) | Do not block anything. Observe results and tune rules. |
| **2. Gate on new code** | Fail only for **new vulnerabilities** and **unreviewed new hotspots**. |
| **3. Strict** | Add reliability, coverage, and duplication conditions. |

### Reading the Gate Result in a Pipeline

Pipelines need a machine-readable result. There are three ways:

**1. Make the scanner wait** (simplest):

```bash
sonar-scanner -Dsonar.qualitygate.wait=true -Dsonar.qualitygate.timeout=300
```

The scanner polls the server and **exits with an error if the gate fails**, which fails the job.

**2. Use a dedicated action or plugin step** (GitHub Actions quality gate action, Jenkins `waitForQualityGate`).

**3. Query the REST API:**

```bash
curl -s -u "$SONAR_TOKEN:" \
  "http://localhost:9000/api/qualitygates/project_status?projectKey=vulnerable-flask-app" \
  | jq -r '.projectStatus.status'
# Prints OK or ERROR
```

Note the token is used as the **username** with an **empty password**. The status `OK` means passed and `ERROR` means failed.

### Webhooks

A **webhook** lets SonarQube **notify** another system when analysis processing finishes. Jenkins uses this to learn the gate result without polling.

Create one under **Project Settings → Webhooks → Create** (or globally under **Administration → Configuration → Webhooks**) with a name and a URL. Treat webhook secrets and URLs as sensitive.

---

## 10. SAST with GitHub Actions

### The Core Problem: Can GitHub Reach Your SonarQube?

The scan step runs on a **GitHub runner**, which then uploads the report to your SonarQube server. That means the runner must be able to **reach your server's URL**.

| Your Situation | Solution |
| :--- | :--- |
| SonarQube is **public** (HTTPS) | Use a normal GitHub-hosted runner (`ubuntu-latest`). |
| SonarQube is **internal** or on your laptop (`localhost`) | Use a **self-hosted runner** in the same network, or a VPN. GitHub-hosted runners **cannot** see `localhost`. |
| You do not want to run a server | Use **SonarQube Cloud**. |

> [!WARNING]
> **Self-hosted runners and public repositories do not mix.** A pull request from a stranger could run code on **your** machine. Use self-hosted runners only with **private** repositories and trusted contributors, and never run untrusted pull request code on them.

### Step 1: Store the Token and URL

1. In SonarQube, generate a **Project Analysis Token** for the project (section 7).
2. In GitHub, go to **Repository → Settings → Secrets and variables → Actions**.
3. Under **Secrets**, click **New repository secret**: name `SONAR_TOKEN`, value = your token.
4. Under **Variables**, click **New repository variable**: name `SONAR_HOST_URL`, value = your server URL (for example `https://sonar.example.com`).

The token is a **secret**. The URL is not secret, so a **variable** is fine.

### Step 2: Add `sonar-project.properties` to the Repository

Use the file from section 7 so the workflow and your local scans agree.

### Step 3: Create the Workflow

```yaml
# .github/workflows/sast-sonarqube.yml
name: SAST - SonarQube

on:
  push:
    branches: [main]
  pull_request:
    types: [opened, synchronize, reopened]    # PR analysis needs a paid edition or SonarQube Cloud

permissions:
  contents: read                               # least privilege

jobs:
  sonarqube:
    name: SonarQube scan and quality gate
    runs-on: ubuntu-latest                     # use "self-hosted" if SonarQube is internal
    steps:
      - name: Check out code with full history
        uses: actions/checkout@v6
        with:
          fetch-depth: 0                       # shallow clones break blame information and new-code detection

      - name: SonarQube scan
        uses: SonarSource/sonarqube-scan-action@v7
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ vars.SONAR_HOST_URL }}
        with:
          args: >
            -Dsonar.qualitygate.wait=true
            -Dsonar.qualitygate.timeout=300
```

| Line | Why It Matters |
| :--- | :--- |
| `on: push` to `main` | Analyzes the main branch after every merge (this is what the Community Build supports). |
| `on: pull_request` | Analyzes pull requests **before** merge (needs Developer Edition or higher, or SonarQube Cloud). |
| `permissions: contents: read` | The workflow's built-in token can only read code. |
| `fetch-depth: 0` | Downloads the full Git history. Without it, SonarQube may report "missing blame information" or mis-detect new code. |
| `SONAR_TOKEN` from `secrets` | The token is never written in the file or printed in logs. |
| `sonar.qualitygate.wait=true` | The job **fails** if the quality gate fails. |

> [!NOTE]
> Module 03 used `actions/checkout@v4`. Newer major versions exist and Sonar's current documentation uses `v6`. Use a current major version, and for production workflows **pin actions to a full commit SHA** (see Module 03, section 12). Check the action's release page for the latest version, and note that action versions can require a compatible SonarQube server version.

### Alternative: Use the Quality Gate Check Action

Instead of making the scanner wait, add a separate check step:

```yaml
      - name: SonarQube scan
        uses: SonarSource/sonarqube-scan-action@v7
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ vars.SONAR_HOST_URL }}

      - name: Check the quality gate
        uses: SonarSource/sonarqube-quality-gate-action@v1
        timeout-minutes: 5
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
```

The step fails when the gate fails, and exposes the result so later steps can use it.

### Step 4: Block Deployment When the Gate Fails

Make later jobs depend on the SAST job. If SonarQube fails, **deployment never starts**.

```yaml
  deploy:
    name: Deploy
    needs: sonarqube                          # only runs if the sonarqube job succeeded
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - run: echo "Deploying... (this only runs when SAST and the quality gate passed)"
```

### Step 5: Make the Check Required

As you learned in Module 03 (section 4.5), a check is only a gate if it is **required**:

1. **Settings → Rules → Rulesets** (or **Branches**) → edit the rule for `main`.
2. Enable **Require status checks to pass**.
3. Add the **SonarQube scan and quality gate** job (run the workflow once first so it appears in the list).

### Special Cases

| Situation | What To Do |
| :--- | :--- |
| **Pull requests from forks** | GitHub does **not** give secrets to workflows triggered from forks, so the scan fails with an authentication error. Skip the job for forks, for example `if: github.event.pull_request.head.repo.full_name == github.repository`. |
| **Maven project** | Replace the scan step with `mvn -B verify org.sonarsource.scanner.maven:sonar-maven-plugin:sonar` (token and URL as environment variables) and cache `~/.m2`. |
| **Monorepo** | Use a separate project key and token per project. |
| **Coverage** | Run tests first, generate a report (for example `coverage.xml`), and point `sonar.python.coverage.reportPaths` at it. |

### Combine With Module 03

A solid pipeline runs both scans:

```yaml
jobs:
  secrets:
    # Gitleaks job from Module 03
  sonarqube:
    # SonarQube job from this module
  deploy:
    needs: [secrets, sonarqube]
```

---

## 11. SAST with Jenkins

### What You Need

| Piece | Purpose |
| :--- | :--- |
| **Jenkins** | The CI server. |
| **SonarQube Scanner plugin** | Connects Jenkins to SonarQube and adds `withSonarQubeEnv` and `waitForQualityGate` pipeline steps. |
| **SonarQube token** | Stored as a Jenkins credential. |
| **SonarQube webhook** | Lets SonarQube tell Jenkins that the quality gate result is ready. |

### Step 1: Install the Plugin

1. In Jenkins, go to **Manage Jenkins → Plugins → Available plugins**.
2. Search for **SonarQube Scanner**, tick it, and click **Install**.
3. Restart Jenkins if asked.

### Step 2: Store the Token as a Jenkins Credential

1. Go to **Manage Jenkins → Credentials → System → Global credentials → Add Credentials**.
2. **Kind:** `Secret text`.
3. **Secret:** paste the SonarQube token (use a **project analysis token**).
4. **ID:** `sonar-token`.
5. **Description:** `SonarQube analysis token`.
6. Click **Create**.

### Step 3: Configure the SonarQube Server in Jenkins

1. Go to **Manage Jenkins → System**.
2. Find the **SonarQube servers** section and click **Add SonarQube**.
3. **Name:** `sonarqube-server` (you will use this exact name in the pipeline).
4. **Server URL:** the address Jenkins can reach, for example `http://sonarqube:9000` or `https://sonar.example.com`.
5. **Server authentication token:** select the `sonar-token` credential.
6. Click **Save**.

### Step 4: Configure the Scanner Tool

1. Go to **Manage Jenkins → Tools**.
2. Under **SonarQube Scanner installations**, click **Add SonarQube Scanner**.
3. **Name:** `SonarScanner`.
4. Tick **Install automatically** (it downloads the scanner for you).
5. Click **Save**.

### Step 5: Create the Webhook in SonarQube

Without this, the pipeline waits forever for the gate result.

1. In SonarQube, open **Administration → Configuration → Webhooks** (or your project's **Project Settings → Webhooks**).
2. Click **Create**.
3. **Name:** `jenkins`.
4. **URL:** `http://<jenkins-host>:8080/sonarqube-webhook/` (the **trailing slash matters**).
5. Click **Create**.

> [!TIP]
> If SonarQube and Jenkins run in Docker, use the **container name** and the Docker network (for example `http://jenkins:8080/sonarqube-webhook/`), not `localhost`. Inside a container, `localhost` means that container itself.

### Step 6: Write the Pipeline (`Jenkinsfile`)

```groovy
// Jenkinsfile
pipeline {
    agent any

    environment {
        SCANNER_HOME = tool 'SonarScanner'      // name from Manage Jenkins -> Tools
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('sonarqube-server') {     // name from Manage Jenkins -> System
                    sh '''
                        "${SCANNER_HOME}/bin/sonar-scanner" \
                          -Dsonar.projectKey=vulnerable-flask-app \
                          -Dsonar.projectName="Vulnerable Flask App" \
                          -Dsonar.sources=.
                    '''
                }
            }
        }

        stage('Quality Gate') {
            steps {
                timeout(time: 5, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true     // stops the pipeline if the gate fails
                }
            }
        }

        stage('Build') {
            steps {
                echo 'Building... (runs only if the quality gate passed)'
            }
        }

        stage('Deploy') {
            when { branch 'main' }
            steps {
                echo 'Deploying... (runs only if the quality gate passed)'
            }
        }
    }
}
```

| Part | What It Does |
| :--- | :--- |
| `tool 'SonarScanner'` | Finds the scanner installation you configured. |
| `withSonarQubeEnv('sonarqube-server')` | Injects the server URL and token as environment variables for the scanner. The token never appears in the file. |
| `waitForQualityGate abortPipeline: true` | Pauses until SonarQube reports the result (through the webhook) and **fails the build** if the gate is red. |
| `timeout(...)` | Prevents the pipeline from hanging forever if the webhook is missing. |
| Stages after the gate | Never run if the gate fails. This is how vulnerable code is **prevented from progressing**. |

### Maven Variant

```groovy
stage('SonarQube Analysis') {
    steps {
        withSonarQubeEnv('sonarqube-server') {
            sh 'mvn -B clean verify org.sonarsource.scanner.maven:sonar-maven-plugin:sonar'
        }
    }
}
```

### Jenkins Security Reminders (from Module 02 and Module 03)

- Store tokens only in **Jenkins credentials**, never in the `Jenkinsfile`.
- Use **project analysis tokens** with minimal scope and an expiry date.
- Restrict who can edit pipelines and Jenkins credentials. Someone who can change the `Jenkinsfile` can bypass the gate, so protect it with **CODEOWNERS** and branch protection.
- Keep Jenkins and its plugins updated, and run builds on isolated agents, not on the controller.

---

## 12. Securing Pull Requests

A **pull request (PR)** is the best place to stop vulnerable code, because nothing has been merged yet. The goal is:

> **No pull request can be merged if it introduces new security problems.**

### The Ideal PR Flow

```text
Developer opens PR
        |
        +--> Gitleaks scan (secrets)          --+
        +--> Tests                              +--> all REQUIRED checks must be green
        +--> SonarQube analysis of the PR     --+
                    |
                    v
        SonarQube comments on the PR and shows Quality Gate status
                    |
              Reviewer + CODEOWNERS approve
                    |
                    v
                  MERGE
```

SonarQube judges the PR by its **new code only**. A developer is not blamed for old problems, only asked not to add new ones (Clean as You Code).

### What Your Edition Allows

| Option | PR Analysis? | Notes |
| :--- | :---: | :--- |
| **SonarQube Server Developer Edition or higher** | ✅ | Branch and PR analysis, plus **PR decoration** (comments and status in GitHub). |
| **SonarQube Cloud** | ✅ | Hosted. Free tier with limits. Simple GitHub integration. |
| **SonarQube Community Build (free)** | ❌ | Analyzes the main branch only. Use the approaches below. |

### Option A: Full PR Protection (Developer Edition or SonarQube Cloud)

**1. Bind SonarQube to GitHub (one time, by an administrator).**

In SonarQube: **Administration → Configuration → General Settings → DevOps Platform Integrations → GitHub**, create a configuration, and register a **GitHub App** for it. The app lets SonarQube post comments and statuses on pull requests. Follow Sonar's official "Binding to GitHub" guide for the exact app permissions.

**2. Connect the project.**

In **Project Settings → General Settings → DevOps Platform Integration**, choose the GitHub configuration and enter the repository.

**3. Run the analysis on pull requests.**

The workflow from section 10 already triggers on `pull_request`. With a paid edition, the scan action detects the pull request automatically and sends the pull request details to the server. Do not add your own `sonar.branch.*` arguments.

**4. Make the checks required.**

In your ruleset (Module 03, section 4.5), require:

- The **SonarQube** check (or the workflow job that runs it).
- The **Gitleaks** check.
- Your test job.
- At least one approval, with **Require review from Code Owners**.

**5. Protect the gate itself.**

Developers must not be able to quietly weaken the controls. In `CODEOWNERS`:

```text
/sonar-project.properties   @my-org/security-team
/.github/workflows/         @my-org/security-team
/Jenkinsfile                @my-org/security-team
```

### Option B: Protection With the Free Community Build

Since pull requests are not analyzed, build protection in layers:

| Layer | How It Helps |
| :--- | :--- |
| **1. Analyze `main` and gate deployment** | Run SonarQube on every push to `main` and make the deploy job depend on it (section 10, step 4). Vulnerable code can reach `main` but **cannot reach production**. |
| **2. IDE feedback before commit** | Install **SonarQube for IDE** (the former SonarLint) in VS Code, IntelliJ, or others. Developers see issues **while typing**. **Connected mode** uses your server's rules. |
| **3. Strong PR checks that do work in a PR** | Gitleaks (Module 03), dependency alerts (Module 05), tests, and GitHub **CodeQL code scanning** (free for public repositories). |
| **4. Human review with a security checklist** | Reviewers use the checklist below. |
| **5. Short-lived release branches** | Merge small changes often so problems found on `main` are easy to fix. |

> [!CAUTION]
> Third-party community plugins exist that add branch and PR analysis to the Community Build. They are **not supported by Sonar**, must match your exact SonarQube version, and run **inside your server**. For a security course, treat them as a risk to evaluate carefully, not as a default recommendation.

### Using SonarQube for IDE (Connected Mode)

1. Install **SonarQube for IDE** from your editor's extension marketplace.
2. Open the extension's settings and **add a connection** to your SonarQube server using a **user token**.
3. **Bind** your project to the SonarQube project key.
4. Issues appear underlined in the editor as you work, with fix advice.

### Pull Request Security Review Checklist

| ✅ Check | Question for the Reviewer |
| :--- | :--- |
| Quality gate | Is the SonarQube gate green? Are there new vulnerabilities or unreviewed hotspots? |
| Secrets | Did Gitleaks pass? Are there new config files or tokens? |
| Input handling | Does new code accept user input? Is it validated and encoded? |
| Dangerous APIs | Does it use shell commands, `eval`, deserialization, raw SQL, or file paths from users? |
| Authentication and authorization | Does every new endpoint check who the user is **and** what they may do? (SAST often cannot see this.) |
| Dependencies | Were new libraries added? Are they needed and trusted? |
| Pipeline files | Were workflows, Jenkinsfiles, or Sonar settings changed? (Needs security-team approval.) |
| Suppressions | Did the PR add `# NOSONAR` comments or mark issues as false positive? Is there a justification? |

### Handling Suppressions Safely

Developers can silence a finding with a comment such as `# NOSONAR`. This is useful for real false positives but dangerous if abused.

- Require a **written reason** next to every suppression.
- Search for suppressions regularly: `grep -rn "NOSONAR" .`
- Review them in pull requests like any other security decision.

---

## 13. Hands-on Labs

> [!WARNING]
> All labs use the **intentionally vulnerable** sample application from section 7. Run SonarQube locally, use fake data only, and never deploy the sample app.

### Lab 1: Install SonarQube with Docker Compose

**Objective:** Run a SonarQube server with PostgreSQL and secure the first login.

**Tasks:**

```bash
# 1. Set kernel parameters (Linux / WSL2)
sudo sysctl -w vm.max_map_count=524288
sudo sysctl -w fs.file-max=131072

# 2. Create the lab folder, secret file, and compose file (section 6)
mkdir -p ~/sonarqube-lab && cd ~/sonarqube-lab
echo "SONAR_DB_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=')" > .env
chmod 600 .env && echo ".env" > .gitignore
# (create docker-compose.yml from section 6)

# 3. Start and wait until it is UP
docker compose up -d
until curl -s http://localhost:9000/api/system/status | grep -q '"status":"UP"'; do sleep 5; done
echo "SonarQube is up"
```

4. Open **http://localhost:9000**, log in as `admin` / `admin`, and **change the password**.
5. Confirm that `.env` is not tracked by Git: `git status` in a repo that contains it should not list it.

**Expected outcome:** SonarQube is reachable on port 9000, uses PostgreSQL, and the default admin password has been replaced. You can explain why the database password lives in an ignored `.env` file.

### Lab 2: Perform Your First Scan

**Objective:** Create a project, generate a token, and run a scan.

**Tasks:**

1. Create the sample application and `sonar-project.properties` from section 7.
2. In SonarQube, create the project `vulnerable-flask-app` and generate a **Project Analysis Token**.
3. Export the token safely and run the scanner:

```bash
read -rs SONAR_TOKEN ; export SONAR_TOKEN
cd ~/vulnerable-flask-app
docker run --rm --network host \
  -e SONAR_HOST_URL="http://localhost:9000" \
  -e SONAR_TOKEN="$SONAR_TOKEN" \
  -v "$(pwd):/usr/src" \
  sonarsource/sonar-scanner-cli
```

4. Open the dashboard and fill in this table:

| Question | Your Answer |
| :--- | :--- |
| Quality Gate status | |
| Number of vulnerabilities | |
| Number of security hotspots | |
| Security rating | |
| Which of the ten planted flaws were detected? | |
| Which were **not** detected? Why might that be? | |

**Expected outcome:** A successful analysis with several security findings. You can explain which flaws your edition detected and why others were not reported (the taint analysis limitation).

### Lab 3: Triage and Fix the Findings

**Objective:** Remediate vulnerabilities and verify the fix with a rescan.

**Tasks:**

1. In the **Issues** tab, open each security issue and read **Why is this an issue?** and **How can I fix it?**.
2. Replace the matching parts of `app.py` with these fixes:

```python
import json
import os
import subprocess
import ipaddress
from urllib.parse import urlparse

import requests
from flask import Flask, abort, request, send_from_directory
from markupsafe import escape
from werkzeug.security import generate_password_hash

import sqlite3

app = Flask(__name__)

DB_PASSWORD = os.environ.get("DB_PASSWORD")          # 1. no hardcoded secret
API_URL = "https://internal.example.com/api"          # 2. HTTPS
ALLOWED_HOSTS = {"api.example.com"}


def get_db():
    return sqlite3.connect("users.db")


@app.route("/user")
def get_user():
    username = request.args.get("name", "")
    conn = get_db()
    rows = conn.execute("SELECT * FROM users WHERE name = ?", (username,)).fetchall()   # 3. parameterized
    return str(rows)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    try:
        ipaddress.ip_address(host)                                                         # 4. validate, no shell
    except ValueError:
        abort(400)
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5, check=False)
    return result.stdout


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return "<h1>Hello " + str(escape(name)) + "</h1>"                                      # 5. escaped output


@app.route("/register", methods=["POST"])
def register():
    return generate_password_hash(request.form["password"])                                # 6. strong password hash


@app.route("/load", methods=["POST"])
def load():
    return str(json.loads(request.data))                                                   # 7. data-only format


@app.route("/file")
def read_file():
    return send_from_directory("/var/app/files", request.args.get("name", ""))             # 8. confined path


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if urlparse(url).hostname not in ALLOWED_HOSTS:                                        # 9. allow-list, TLS verified
        abort(400)
    return requests.get(url, timeout=5).text


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)                                                 # 10. safe defaults
```

3. Rescan with the same scanner command.
4. For any **Security Hotspot** that remains (for example, a `subprocess` call), open it, read the risk assessment, decide whether it is safe, and set the status to **Safe** or **Acknowledged** with a **written comment** explaining your reasoning.
5. Compare the dashboards before and after.

**Expected outcome:** Vulnerabilities drop to zero, the security rating improves, and every remaining hotspot has a documented review decision. You can explain why each fix works.

### Lab 4: Build and Test a Quality Gate

**Objective:** Create a gate that blocks new vulnerabilities and verify it fails when it should.

**Tasks:**

1. Create the gate `Strict Security` with these conditions **On New Code**: Security Rating worse than A, and Security Hotspots Reviewed less than 100% (section 9).
2. Assign it to `vulnerable-flask-app` (**Project Settings → Quality Gate**).
3. Rescan the fixed code. Note the gate status.
4. **Introduce a new flaw** in `app.py` (for example, re-add `DB_PASSWORD = "SuperSecret123!"`) and rescan.
5. Check the gate from the command line:

```bash
curl -s -u "$SONAR_TOKEN:" \
  "http://localhost:9000/api/qualitygates/project_status?projectKey=vulnerable-flask-app" \
  | jq -r '.projectStatus.status'
```

6. Run the scanner **with** `-Dsonar.qualitygate.wait=true` and check its exit code:

```bash
docker run --rm --network host \
  -e SONAR_HOST_URL="http://localhost:9000" -e SONAR_TOKEN="$SONAR_TOKEN" \
  -v "$(pwd):/usr/src" \
  sonarsource/sonar-scanner-cli -Dsonar.qualitygate.wait=true
echo "Exit code: $?"
```

7. Fix the flaw, rescan, and confirm the gate passes again.

**Expected outcome:** The gate **fails** (`ERROR`, non-zero exit code) when the new flaw is present and **passes** (`OK`, exit code 0) after you fix it. You can explain why a failing exit code is what stops a CI pipeline.

> [!NOTE]
> The "new code" period depends on your project's New Code setting. If the gate does not react as expected, set **Project Settings → New Code** to **Previous version** or **Number of days**, and rescan.

### Lab 5: Customize a Quality Profile

**Objective:** Extend the default profile and activate additional security rules.

**Tasks:**

1. Go to **Quality Profiles → Python → Sonar way → Extend** and name it `Python - Strict Security`.
2. Use **Activate More** and filter by **Type: Vulnerability** and **Type: Security Hotspot**. Activate any inactive security rules.
3. Assign the profile to your project (**Project Settings → Quality Profiles**).
4. Rescan and compare the number of findings.
5. Write down one rule you activated and why it matters for your organization.

**Expected outcome:** You understand the difference between a profile (what is checked) and a gate (what is allowed) and can customize both.

### Lab 6: SAST in GitHub Actions

**Objective:** Run SonarQube from a workflow and block deployment when the gate fails.

> [!WARNING]
> Use a **private** repository for this lab, because it uses a **self-hosted runner** on your own machine. Never attach a self-hosted runner to a public repository.

**Tasks:**

1. Create a **private** GitHub repository and push the sample app, `sonar-project.properties`, and a `.gitignore`.
2. Because SonarQube runs on your machine, register a **self-hosted runner**: in the repository go to **Settings → Actions → Runners → New self-hosted runner**, choose your operating system, and run the commands GitHub shows.
3. Add the secret `SONAR_TOKEN` and the variable `SONAR_HOST_URL` (for example `http://localhost:9000`, which works because the runner is on the same machine).
4. Create `.github/workflows/sast-sonarqube.yml` from section 10, and change `runs-on: ubuntu-latest` to `runs-on: self-hosted`. Add the `deploy` job with `needs: sonarqube`.
5. Push to `main` and watch the **Actions** tab. Confirm the scan passes.
6. Add a new flaw (a hardcoded password), push, and watch the job **fail** and the `deploy` job **skip**.
7. Fix it, push, and confirm that both jobs pass.
8. Make the SonarQube job a **required status check** in your ruleset (Module 03, section 4.5).

**Expected outcome:** A failing quality gate fails the workflow and prevents the deploy job from running. You can explain why `fetch-depth: 0`, `permissions: contents: read`, and storing the token as a secret are used.

### Lab 7: SAST in Jenkins

**Objective:** Add a quality-gate-enforced SonarQube stage to a Jenkins pipeline.

**Tasks:**

1. Run Jenkins on the **same Docker network** as SonarQube so they can reach each other:

```bash
docker network ls                     # find the network created by compose, e.g. sonarqube-lab_default

docker run -d --name jenkins \
  --network sonarqube-lab_default \
  -p 8080:8080 \
  -v jenkins_home:/var/jenkins_home \
  jenkins/jenkins:lts-jdk17

docker exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword
```

2. Open **http://localhost:8080**, finish the setup, and install the **SonarQube Scanner** plugin.
3. Add the token as the credential `sonar-token`, configure the server `sonarqube-server` with URL `http://sonarqube:9000`, and add the `SonarScanner` tool (section 11, steps 2 to 4).
4. In SonarQube, create the webhook with URL `http://jenkins:8080/sonarqube-webhook/` (step 5).
5. Push the sample app and the `Jenkinsfile` from section 11 to a Git repository, then create a **Pipeline** job using **Pipeline script from SCM**.
6. Run the pipeline and confirm all stages pass.
7. Add a new flaw, rebuild, and confirm the **Quality Gate** stage fails and the **Build** and **Deploy** stages do not run.

**Expected outcome:** The pipeline aborts at the Quality Gate stage when the gate fails. You can explain what the webhook is for and what happens if it is missing.

### Lab 8: Design a Pull Request Protection Policy

**Objective:** Apply section 12 to a real repository.

**Tasks:**

1. Decide which option applies to you: **A** (Developer Edition or SonarQube Cloud) or **B** (Community Build).
2. **Option A:** connect a public test repository to **SonarQube Cloud** (free tier), enable pull request analysis, open a pull request containing a deliberate vulnerability, and observe the decoration and failing status.
3. **Option B:** install **SonarQube for IDE** in connected mode and observe the issues in your editor. Then write the layered protection plan from section 12, Option B, for a fictional team.
4. Write a **one-page PR security policy** that states:
   - Which checks are required before merge.
   - Who must approve changes to pipeline and Sonar configuration.
   - How suppressions (`NOSONAR`, false positives) are justified and reviewed.
   - What happens when the quality gate fails on `main`.

**Expected outcome:** A written policy that matches the capabilities of your edition and names the exact required checks.

---

## 14. Best Practices

### Using SAST Effectively

| Practice | Why It Matters |
| :--- | :--- |
| **Scan early and often** | IDE plugin, pull request, and every merge to main. |
| **Clean as You Code** | Gate on **new code** first. Do not demand fixing all legacy issues before you start. |
| **Start in visibility mode** | Observe for a few weeks, tune noisy rules, then enforce. Sudden strict gates cause developers to resent or bypass the tool. |
| **Review every Security Hotspot** | Hotspots are where risk hides. Keep **Security Hotspots Reviewed = 100%** on new code. |
| **Assign ownership** | Every finding needs an owner and a due date based on severity. |
| **Fix, do not just suppress** | Every `NOSONAR` or "false positive" is a security decision that needs a written reason. |
| **Tune rules deliberately** | Use quality profiles to adjust rules. Do not disable categories just because they are noisy. |
| **Exclude carefully** | Exclude generated code, vendored libraries, and build output, but review changes to `sonar.exclusions` like code. Overbroad exclusions hide real flaws. |
| **Import test coverage** | Coverage reports make the coverage gate meaningful. |
| **Track metrics** | Number of open vulnerabilities, time to fix, and gate pass rate show whether the program works. |
| **Train developers** | Tools find problems, but secure coding habits prevent them. Use the rule explanations as teaching material. |

### Securing the SAST Tooling Itself

| Practice | Why It Matters |
| :--- | :--- |
| **Change default credentials** | Never leave `admin/admin`. |
| **Use HTTPS** | Tokens and source-code metadata must not travel in clear text. |
| **Use project analysis tokens with expiry** | Limits damage if a token leaks. |
| **Store tokens in secret stores** | GitHub secrets, Jenkins credentials, never in repository files. |
| **Pin versions** | Pin the SonarQube image tag, the scanner version, and GitHub Actions (preferably by commit SHA). |
| **Protect pipeline and Sonar config** | Use CODEOWNERS and branch protection on `Jenkinsfile`, workflows, and `sonar-project.properties`. |
| **Limit permissions** | Few administrators. Restrict who can change quality gates, profiles, and issue statuses. |
| **Back up and update** | Back up the database. Update SonarQube and plugins for security fixes. |
| **Be careful with self-hosted runners** | Use them only with private repositories and trusted code. |

### Adoption Roadmap

```text
Phase 1 (weeks 1-2)   Install, scan main, share results. No blocking.
Phase 2 (weeks 3-4)   Add IDE plugin. Triage the worst issues. Tune rules.
Phase 3 (weeks 5-6)   Gate on NEW vulnerabilities and unreviewed hotspots. Block deployments.
Phase 4 (ongoing)     Require PR checks (where supported), add coverage and duplication conditions,
                      review metrics monthly, retire old issues steadily.
```

### Remember the Limits

- SAST finds **code-level** patterns. It does not replace **DAST** (Module 06), **dependency scanning** (Module 05), **secret scanning** (Module 03), **code review**, or **threat modeling** (Module 01).
- A **passing gate** means "no known rule violations in new code", not "the application is secure".

---

## 15. Troubleshooting

### Quick Diagnostic Commands

```bash
docker compose ps                                      # are the containers running?
docker compose logs --tail=100 sonarqube               # SonarQube server logs
curl -s http://localhost:9000/api/system/status        # is the server UP?
sysctl vm.max_map_count                                # must be >= 524288
docker stats --no-stream                               # is a container out of memory?
```

### Server Problems

| Symptom | Likely Cause | Fix |
| :--- | :--- | :--- |
| SonarQube container **exits immediately** or logs mention Elasticsearch "bootstrap checks failed" or `max virtual memory areas vm.max_map_count [65530] is too low` | Kernel parameter too low | `sudo sysctl -w vm.max_map_count=524288` and make it permanent (section 6). Restart with `docker compose up -d`. |
| Container restarts or is killed (`Exited (137)`) | Out of memory | Give Docker at least 4 GB RAM. Close other heavy applications. |
| `Connection refused` to the database, or the server loops on database errors | Database not ready, wrong password | Check `docker compose logs db`. Make sure `.env` exists and both services read `SONAR_DB_PASSWORD`. If you changed the password after the database was first created, remove the volumes (`docker compose down -v`) in a **lab** setup. |
| `Bind for 0.0.0.0:9000 failed: port is already allocated` | Another program uses port 9000 | Stop it, or change the mapping to `"9001:9000"`. |
| Page stays on "SonarQube is starting" | First start still migrating | Wait. Check the log and `/api/system/status`. |
| Cannot log in with `admin/admin` | Password was already changed | Use your new password. For a lab with no data, recreate the volumes. |
| Server works but is **very slow** | Not enough memory or CPU | Allocate more resources. Use PostgreSQL, not the demo database. |

### Scanner Problems

| Symptom | Likely Cause | Fix |
| :--- | :--- | :--- |
| `Failed to query server version` / `Connection refused` | Scanner cannot reach the server URL. Inside Docker, `localhost` means the scanner container. | Linux: `--network host`. Docker Desktop: `http://host.docker.internal:9000`. In CI, check the runner can reach the server. |
| `Not authorized. Please check the properties sonar.token` / **401** | Wrong, expired, or revoked token. Token type does not match the project. | Generate a new **project analysis token** for that project. Confirm `SONAR_TOKEN` is set in the same shell. |
| `You're not authorized to run analysis` | Token's user lacks **Execute Analysis** permission | Grant the permission on the project, or use a project analysis token. |
| `Project not found` / project key mismatch | `sonar.projectKey` differs from the project in SonarQube | Make them identical (case-sensitive). |
| `sonar.login is deprecated` warning | Old property name | Use `sonar.token` (or the `SONAR_TOKEN` environment variable). |
| `No files nor directories matching` / **0 lines of code** analyzed | Wrong `sonar.sources`, or exclusions too broad, or you are in the wrong folder | Check `sonar.sources`, `sonar.exclusions`, and the mounted volume (`-v "$(pwd):/usr/src"`). |
| `Missing blame information` / `Could not find ref` | Shallow Git clone in CI | Use `fetch-depth: 0` in `actions/checkout`. In Jenkins, disable shallow clone. |
| Scanner runs, but **no vulnerabilities** appear | Rules not active, or the data-flow detections need a paid edition | Check the Quality Profile (rules active?) and the edition's capabilities (section 4). |
| **Coverage 0%** | No coverage report imported | Generate a report (for example `coverage.xml`) and set `sonar.python.coverage.reportPaths`. |
| Analysis fails with a Java or memory error | Scanner JVM too small | Set `SONAR_SCANNER_OPTS="-Xmx2g"` and check your Java version for non-Docker scanners. |

### Quality Gate and Pipeline Problems

| Symptom | Likely Cause | Fix |
| :--- | :--- | :--- |
| **Jenkins `waitForQualityGate` hangs** until timeout | SonarQube webhook missing or cannot reach Jenkins | Create the webhook with URL `http://<jenkins>:8080/sonarqube-webhook/` (trailing slash). In Docker, use container names on a shared network. Check **Administration → Webhooks** for delivery errors. |
| Jenkins error `No SonarQube installation named ...` | Name mismatch | Make `withSonarQubeEnv('<name>')` match **Manage Jenkins → System** exactly. |
| Jenkins `tool 'SonarScanner'` not found | Tool not configured | Add it in **Manage Jenkins → Tools** with the same name. |
| GitHub Action fails on a pull request **from a fork** | Secrets are not available to fork workflows | Skip the job for forks or run analysis after merge. |
| GitHub-hosted runner times out connecting | SonarQube is not publicly reachable | Use a self-hosted runner, a VPN, a publicly reachable HTTPS endpoint, or SonarQube Cloud. |
| Gate always **passes** even with new flaws | Findings are in **old** code, so they are not in the New Code period. Or the project uses a lenient gate. | Review **Project Settings → New Code** and **Quality Gate**. Introduce a flaw in code changed after the reference point. |
| Gate **fails** because of coverage | A coverage condition exists but no report is imported | Import coverage or remove the condition until tests are wired in. |
| Pull request analysis does not run or shows an edition error | Community Build does not support pull request analysis | Use Developer Edition or higher, SonarQube Cloud, or the Community Build alternatives in section 12. |
| Analysis uploaded but results never appear | Background task failed | Check **Administration → Projects → Background Tasks** and open the failed task's error. |

---

## 16. Interview Questions

> Click a question to reveal a model answer. Try to answer it yourself first.

### Fundamentals

<details>
<summary><b>1. What is SAST, and when does it run in the SDLC?</b></summary>

SAST analyzes source code or compiled code **without executing it** to find security weaknesses. It runs **early**: in the developer's IDE, in pull requests, and in the CI build, before the application is deployed. This is a core part of shift-left security.
</details>

<details>
<summary><b>2. What is the difference between SAST, DAST, and SCA?</b></summary>

**SAST** analyzes your own source code statically. **DAST** tests a **running** application from the outside. **SCA** examines **third-party dependencies** for known vulnerabilities. They find different problems and are used together.
</details>

<details>
<summary><b>3. What are the main advantages and limitations of SAST?</b></summary>

Advantages: finds issues early, points to exact lines, scans all code paths, and automates well. Limitations: false positives and false negatives, no visibility into runtime behavior or deployment configuration, and weakness with business logic flaws and missing authorization.
</details>

<details>
<summary><b>4. What is taint analysis?</b></summary>

A technique that tracks **untrusted data** from a **source** (such as a request parameter) through the code to a **sink** (such as a SQL query). If the data reaches the sink without a **sanitizer** (validation or escaping), the tool reports an injection vulnerability.
</details>

<details>
<summary><b>5. What is a false positive and a false negative in SAST? Which is more dangerous?</b></summary>

A **false positive** is a finding that is not a real problem. A **false negative** is a real vulnerability the tool misses. False negatives are more dangerous because they create a false sense of safety, while false positives mainly cost time and, if too many, cause developers to ignore the tool.
</details>

### SonarQube

<details>
<summary><b>6. Explain the SonarQube architecture.</b></summary>

A **scanner** analyzes code on the CI machine and uploads a report to the **SonarQube server**. The server has a **web server** (UI and API), a **compute engine** that processes reports in the background, an embedded **search server** (Elasticsearch), and a **database** (PostgreSQL for real deployments) that stores results.
</details>

<details>
<summary><b>7. What is the difference between a vulnerability and a security hotspot?</b></summary>

A **vulnerability** is code the tool is confident is insecure and should be fixed. A **security hotspot** is security-sensitive code that **needs human review** to decide if it is safe in context.
</details>

<details>
<summary><b>8. What is a Quality Profile, and how does it differ from a Quality Gate?</b></summary>

A **Quality Profile** is the set of **rules** applied for a language (what is checked). A **Quality Gate** is a set of **pass/fail conditions** on the results (what is acceptable). Profiles produce findings; gates decide whether the build may proceed.
</details>

<details>
<summary><b>9. What does "Clean as You Code" mean?</b></summary>

Make sure **new and changed code** meets the quality standard, without requiring that all legacy issues be fixed first. Quality gates focus on the New Code period, so the project improves steadily without blocking teams.
</details>

<details>
<summary><b>10. Why can the built-in "Sonar way" profile and gate not be edited, and how do you customize them?</b></summary>

Built-in items are read-only so Sonar can update them safely. To customize, **extend** or **copy** a profile, and **copy** a gate or create a new one, then assign it to projects.
</details>

<details>
<summary><b>11. Which SonarQube token type should CI use, and why?</b></summary>

A **project analysis token**, because it can only run analysis on one project. It follows least privilege, so a leak has limited impact. Add an expiry date and store it in the CI secret store.
</details>

<details>
<summary><b>12. What limits does the free Community Build have compared with paid editions?</b></summary>

At the time of writing, the Community Build analyzes a single main branch, has no pull request analysis or decoration, and does not include the deeper taint analysis for injection vulnerabilities that the paid editions provide. Always check Sonar's current documentation.
</details>

### CI/CD Integration

<details>
<summary><b>13. Why does the scanner finish before the quality gate result is available?</b></summary>

The scanner only uploads a report. The server's **compute engine** processes it **asynchronously**. Pipelines therefore must wait for the result using `sonar.qualitygate.wait=true`, a quality gate action, or (in Jenkins) a webhook with `waitForQualityGate`.
</details>

<details>
<summary><b>14. Why is a webhook needed in the Jenkins integration?</b></summary>

SonarQube uses the webhook to **notify Jenkins** when processing is complete and to deliver the quality gate status. Without it, `waitForQualityGate` never receives the result and times out.
</details>

<details>
<summary><b>15. Why must `fetch-depth: 0` be used in GitHub Actions for SonarQube?</b></summary>

By default, `actions/checkout` fetches a shallow clone. SonarQube needs the Git history for blame information and new-code detection, so a shallow clone causes warnings or wrong results.
</details>

<details>
<summary><b>16. How do you stop a deployment when SAST fails?</b></summary>

Make the deploy job depend on the SAST job (`needs:` in GitHub Actions, or stages after `waitForQualityGate abortPipeline: true` in Jenkins). Also make the SAST check a **required status check** in branch protection.
</details>

<details>
<summary><b>17. A GitHub-hosted runner cannot reach your SonarQube on localhost. What are your options?</b></summary>

Use a **self-hosted runner** in the same network (private repositories only), expose SonarQube through **HTTPS** with authentication, use a VPN, or use **SonarQube Cloud**.
</details>

<details>
<summary><b>18. How do you handle pull requests from forks in a SonarQube workflow?</b></summary>

GitHub does not give secrets to fork-triggered workflows, so the authentication fails. Skip the job for forks (compare the head repository to the base repository) or analyze the code after a maintainer merges it.
</details>

### Practical and Scenario Questions

<details>
<summary><b>19. SonarQube reports a hardcoded password. What do you do?</b></summary>

Treat it as real until proven otherwise. **Rotate the credential** (it is in Git history), move it to an environment variable or secret manager, fix the code, rescan, and check Gitleaks (Module 03) to clean and prevent recurrence.
</details>

<details>
<summary><b>20. A developer marks 30 hotspots as "Safe" in one afternoon. What is your concern, and what do you do?</b></summary>

Mass approval suggests the reviews were not genuine. Check that each has a written justification, sample several for correctness, restrict who can change hotspot statuses, and add a review step for security-sensitive decisions.
</details>

<details>
<summary><b>21. Your legacy project has 4,000 issues. How do you introduce SonarQube without blocking everyone?</b></summary>

Start with **visibility only**, then set the quality gate on **New Code** (Clean as You Code). Fix the most critical legacy vulnerabilities first, and gradually raise standards. This blocks new problems without demanding a big-bang cleanup.
</details>

<details>
<summary><b>22. The quality gate passes, but a penetration tester finds SQL injection. How is that possible?</b></summary>

SAST has limits. The edition may lack data-flow analysis, the flaw may sit in old code outside the New Code period, the code path may be unusual or framework-specific, or the issue could be in logic or configuration SAST cannot see. This is why SAST is combined with DAST, code review, and testing.
</details>

<details>
<summary><b>23. How would you secure the SonarQube server itself?</b></summary>

Change default credentials, enforce authentication and SSO, serve over HTTPS, use project analysis tokens with expiry, restrict permissions and administrators, limit network exposure, back up the database, keep it updated, and install only trusted plugins.
</details>

<details>
<summary><b>24. How can developers bypass the SAST gate, and how do you prevent it?</b></summary>

By editing the pipeline file, weakening `sonar-project.properties` (such as broad exclusions), adding `NOSONAR` comments, changing the quality gate, or merging without the required check. Prevent it with required status checks, CODEOWNERS on pipeline and Sonar files, restricted Sonar permissions, and reviews of suppressions.
</details>

<details>
<summary><b>25. Design a SAST process for a new microservice team.</b></summary>

IDE plugin in connected mode, Gitleaks pre-commit and CI (Module 03), SonarQube analysis on pull requests where supported (or on `main` with a deployment gate), a quality gate on new code requiring no new vulnerabilities and all hotspots reviewed, required status checks and CODEOWNERS, project analysis tokens in secret stores, a documented triage and suppression policy, and monthly review of metrics.
</details>

---

## 17. References

### SonarQube and Sonar

- SonarQube Community Build documentation: <https://docs.sonarsource.com/sonarqube-community-build/>
- SonarQube Server documentation: <https://docs.sonarsource.com/sonarqube-server/>
- Official SonarQube Docker image: <https://hub.docker.com/_/sonarqube>
- SonarQube Scan GitHub Action: <https://github.com/SonarSource/sonarqube-scan-action>
- SonarQube Quality Gate GitHub Action: <https://github.com/SonarSource/sonarqube-quality-gate-action>
- SonarQube Scanner for Jenkins (plugin): <https://plugins.jenkins.io/sonar/>
- SonarScanner CLI image: <https://hub.docker.com/r/sonarsource/sonar-scanner-cli>

### Security Standards and Learning Resources

- OWASP Top 10: <https://owasp.org/www-project-top-ten/>
- OWASP Source Code Analysis Tools: <https://owasp.org/www-community/Source_Code_Analysis_Tools>
- OWASP Cheat Sheet Series (secure coding guidance): <https://cheatsheetseries.owasp.org/>
- CWE (Common Weakness Enumeration): <https://cwe.mitre.org/>

### Related Modules in This Repository

- [Module 01: DevSecOps Fundamentals](../01-devsecops-fundamentals/README.md) for shift-left, security gates, and threat modeling.
- [Module 03: Git, GitHub and Secret Security](../03-git-github-and-secret-security/README.md) for branch protection, required checks, and Gitleaks.
- [Module 05: Software Composition Analysis and SBOM](../05-software-composition-analysis-sca-and-sbom/README.md) for dependency scanning.
- [Module 06: Dynamic Application Security Testing](../06-dynamic-application-security-testing-dast/README.md) for testing the running application.

> [!NOTE]
> Product names, editions, plan limits, action versions, and menu paths change frequently. When a command or screen in this module differs from what you see, consult the official documentation linked above.

---

## Summary

In this module, you learned how to find insecure code **before it ships**:

- **SAST** reads source code without running it, catching issues early, down to the exact line. It complements, but does not replace, **SCA** and **DAST**.
- Common code-level flaws include **SQL injection, command injection, XSS, hardcoded credentials, weak cryptography, insecure deserialization, path traversal, and disabled TLS checks**, each with a safe alternative.
- **SonarQube** uses scanners, a server with a compute engine and database, **quality profiles** (what is checked) and **quality gates** (what is allowed).
- **Vulnerabilities** must be fixed. **Security Hotspots** need a documented human review.
- **Clean as You Code** keeps gates focused on new code so adoption is realistic.
- Pipelines must **wait for the quality gate** and make later stages depend on it, so vulnerable code **cannot progress**, in both **GitHub Actions** and **Jenkins**.
- Pull request protection depends on your edition, and the free Community Build needs layered alternatives.
- The SAST tooling itself must be secured: HTTPS, strong authentication, scoped tokens, protected pipeline files, and pinned versions.

In the next module, you will move from **your own code** to the **third-party code** your application depends on, using Software Composition Analysis and SBOMs.

---

## Next Module

➡️ [Module 05: Software Composition Analysis (SCA) and SBOM](../05-software-composition-analysis-sca-and-sbom/README.md)

[⬅️ Previous: Module 03: Git, GitHub and Secret Security](../03-git-github-and-secret-security/README.md) | [🏠 Main README](../README.md)

---

<div align="center">

**Learn. Secure. Automate. Deploy. 🛡️**

</div>
