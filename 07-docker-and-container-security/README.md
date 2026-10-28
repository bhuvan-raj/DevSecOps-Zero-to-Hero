# Module 05: Software Composition Analysis (SCA) & SBOM 📦

## 📌 Overview

Modern applications are mostly **assembled, not written**. A typical project contains a small amount of your own code and a very large amount of **third-party open-source code**: frameworks, libraries, and their dependencies.

**Software Composition Analysis (SCA)** identifies those third-party components, checks them against databases of **known vulnerabilities**, and helps you fix or manage the risk. A **Software Bill of Materials (SBOM)** is the **ingredient list** of your software: a structured, machine-readable inventory of every component inside it.

In this module, you will learn how dependencies work, how vulnerabilities are identified and scored (CVE and CVSS), how to scan with **OWASP Dependency-Check**, how to generate SBOMs with **Syft**, how to use **Dependabot**, and how to build **security gates** that stop vulnerable dependencies from reaching production.

> [!NOTE]
> This module continues the story from Module 04. SAST (SonarQube) checks **the code you wrote**. SCA checks **the code you imported**. Module 07 will apply the same ideas to container images.

> [!IMPORTANT]
> **Lab environment:** You need **Docker** and a terminal, plus a free **NVD API key** for Dependency-Check (the steps are in section 5). The lab project contains **deliberately vulnerable library versions** so the scanner has something to find. Scan them, but **never deploy or run** that project as a real service.

## 🎯 Learning Objectives

By the end of this module, you will be able to:

- Explain what Software Composition Analysis is and why it matters.
- Distinguish direct from transitive dependencies and map a dependency tree.
- Read CVE records and understand CVSS, EPSS, and the CISA KEV catalog.
- Run OWASP Dependency-Check and interpret its reports.
- Triage findings, suppress false positives safely, and prioritize by risk.
- Explain what an SBOM is and why organizations need one.
- Compare the SPDX and CycloneDX formats.
- Generate, inspect, and scan SBOMs with Syft and other tools.
- Configure and use Dependabot alerts, security updates, and version updates.
- Integrate SCA and SBOM generation into GitHub Actions and Jenkins.
- Build security gates and remediate vulnerable dependencies.

## 📚 Table of Contents

1. [What Is SCA?](#1-what-is-sca)
2. [Direct vs. Transitive Dependencies](#2-direct-vs-transitive-dependencies)
3. [Understanding CVE and CVSS](#3-understanding-cve-and-cvss)
4. [Introduction to OWASP Dependency-Check](#4-introduction-to-owasp-dependency-check)
5. [Scanning Dependencies with Dependency-Check](#5-scanning-dependencies-with-dependency-check)
6. [Introduction to SBOM](#6-introduction-to-sbom)
7. [SBOM Formats: SPDX vs. CycloneDX](#7-sbom-formats-spdx-vs-cyclonedx)
8. [Generating an SBOM with Syft](#8-generating-an-sbom-with-syft)
9. [Understanding Dependabot](#9-understanding-dependabot)
10. [Integrating SCA into CI/CD](#10-integrating-sca-into-cicd)
11. [Security Gates and Vulnerability Remediation](#11-security-gates-and-vulnerability-remediation)
12. [Hands-On Labs](#12-hands-on-labs)
13. [Best Practices](#13-best-practices)
14. [Knowledge Check](#14-knowledge-check)
15. [Official References](#15-official-references)
16. [Module Completion Checklist](#16-module-completion-checklist)

---

## 1. What Is SCA?

### Most of Your Application Is Someone Else's Code

```text
 A typical application

 +----------------------------------------------------------+
 |  Your own code                                  ~10-20%  |
 |  ######                                                  |
 +----------------------------------------------------------+
 |  Third-party libraries and their dependencies   ~80-90%  |
 |  ######################################################  |
 +----------------------------------------------------------+
        (illustrative: the exact split varies by project,
         but open source usually dominates)
```

Every one of those libraries was written by someone else, may contain bugs and vulnerabilities, and may depend on **more** libraries. You inherit **all** of their security problems.

> **Analogy:** Think of a restaurant meal. SAST is the **chef checking their own recipe and technique**. SCA is checking the **suppliers' labels** on every ingredient for recalls, such as contaminated flour or spoiled milk. You may cook perfectly, but a recalled ingredient still makes customers sick.

### What Is SCA?

**Software Composition Analysis (SCA)** is the practice of:

1. **Identifying** every open-source and third-party component in your software.
2. **Matching** them against databases of known vulnerabilities.
3. **Reporting** which ones are affected, how severe the issue is, and which version fixes it.
4. Often also checking **licenses**, because open-source licenses carry legal obligations.

```text
 Your project  -->  1. Find components  -->  2. Look them up  -->  3. Report
 (manifests,         (name + version)          (vulnerability        (CVE, severity,
  lock files,                                    databases)           fixed version)
  JARs, images)
```

### Why SCA Matters: Log4Shell

In December 2021, a critical flaw (**CVE-2021-44228**, nicknamed **Log4Shell**) was disclosed in **Apache Log4j**, a Java logging library used in a vast number of applications and products. It scored the maximum **CVSS 10.0** and allowed **remote code execution** with a single crafted string.

| Why It Hurt So Much | Lesson |
| :--- | :--- |
| Log4j was embedded in **thousands of products** | Most teams did not know whether they used it. |
| It was often a **transitive dependency** (pulled in by another library) | You cannot fix what you cannot see. |
| Organizations scrambled for days to answer *"Are we affected?"* | An **SBOM** answers this question in minutes. |
| Attackers began scanning the internet within hours | Speed of detection and patching matters. |

> **SCA and SBOMs exist so that the next Log4Shell is a ten-minute question, not a ten-day investigation.**

### What SCA Finds, and What It Does Not

| ✅ SCA finds | ❌ SCA does not find |
| :--- | :--- |
| **Known** vulnerabilities (CVEs) in libraries you use | Flaws in **your own code** (use SAST, Module 04) |
| Outdated, unsupported, or end-of-life components | **Unknown** (not yet disclosed) vulnerabilities |
| License risks and conflicts | Runtime and configuration problems (use DAST, Module 06) |
| Which version contains the fix | Whether the vulnerable code is **actually reachable** (most tools cannot tell) |
| The full inventory of components (SBOM) | **Malicious** packages that have no CVE yet (needs extra controls, below) |

### SAST vs. SCA vs. DAST (A Quick Reminder)

| | **SAST** | **SCA** | **DAST** |
| :--- | :--- | :--- | :--- |
| Examines | Your source code | Third-party components | The running application |
| Finds | Insecure code patterns | Known vulnerable libraries | Runtime and config weaknesses |
| Needs running app | No | No | Yes |
| Tool in this course | SonarQube (M04) | **Dependency-Check, Syft (M05)** | OWASP ZAP (M06) |

### SCA Is Not Only About CVEs: The Wider Supply Chain

A vulnerability database lists **accidental** bugs. Attackers also attack the **supply chain** deliberately:

| Attack | How It Works | Example Pattern |
| :--- | :--- | :--- |
| **Typosquatting** | A malicious package with a name close to a popular one (`reqeusts`, `colourama`) | Developer mistypes the name |
| **Dependency confusion** | A public package with the **same name as your internal package** but a higher version | Build tool pulls the public one |
| **Compromised maintainer** | An attacker takes over a maintainer's account and publishes a malicious update | Stolen publishing token |
| **Malicious update / backdoor** | A trusted project receives a hidden backdoor | The 2024 `xz` compression library backdoor |
| **Protestware** | A maintainer deliberately sabotages their own package | Libraries changed to erase files or print messages |
| **Abandoned packages** | Unmaintained libraries never receive fixes | Old, unpatched dependencies |
| **Worms and credential theft in package registries** | Stolen publish tokens are used to spread malicious versions to many packages | Several npm incidents, including a 2026 campaign that compromised dozens of packages |

CVE-based scanning does **not** catch most of these on day one. You also need the controls in sections 2, 11, and 13: lock files, pinned versions, private registries, update **cooldown** periods, and review of new dependencies.

### Where SCA Fits in the Pipeline

```text
 IDE / commit      Pull request              Build               Release / runtime
 -------------   --------------------   ------------------   ----------------------------
 Dependabot      Dependency review      Dependency-Check     Rescan stored SBOMs daily
 alerts          Dependabot PRs         SBOM generation      (new CVEs appear after release)
                 Gitleaks (M03)         Syft  + sign SBOM
                 SAST (M04)
```

---

## 2. Direct vs. Transitive Dependencies

### Two Kinds of Dependencies

| Type | Meaning | Who Chose It |
| :--- | :--- | :--- |
| **Direct dependency** | A library **you** declare in your project file | You |
| **Transitive dependency** | A library that **your dependency** depends on (and so on, many levels deep) | Somebody else, indirectly |

```text
 YOUR PROJECT
   |
   +-- flask 3.1.1                      <-- DIRECT (you declared it)
   |     +-- werkzeug                   <-- transitive (level 2)
   |     +-- jinja2                     <-- transitive (level 2)
   |     |     '-- markupsafe           <-- transitive (level 3)
   |     '-- click                      <-- transitive (level 2)
   |
   '-- requests 2.32.4                  <-- DIRECT
         +-- urllib3                    <-- transitive
         +-- certifi                    <-- transitive
         '-- idna                       <-- transitive

 You wrote 2 lines in requirements.txt. You now run 10+ libraries.
```

> **Analogy:** You hire one contractor (direct). That contractor brings **their own subcontractors** (transitive). If a subcontractor does faulty electrical work, **your building** is at risk, even though you never met them.

### Why Transitive Dependencies Matter for Security

| Fact | Consequence |
| :--- | :--- |
| Most dependencies in a project are **transitive** | Most of your risk is in libraries you never chose. |
| You do not see them in your project file | Vulnerabilities are easy to miss. |
| You cannot always upgrade them directly | The fix may need the parent library to update, or you may need to **override** the version (section 11). |
| One library can appear in **several versions** at once | Conflict resolution decides which version actually ships. |
| Log4Shell was often transitive | Many teams discovered it only through scanning. |

### See Your Own Dependency Tree

Every ecosystem has a command to show the tree:

| Ecosystem | Show the Tree | Notes |
| :--- | :--- | :--- |
| **Java (Maven)** | `mvn dependency:tree` | Shows scope and conflicts |
| **Java (Gradle)** | `./gradlew dependencies` | Per configuration |
| **Python** | `pip install pipdeptree && pipdeptree` | Shows what is installed |
| **Node.js** | `npm ls --all` | Entire tree |
| **Go** | `go mod graph` or `go list -m all` | Module graph |
| **.NET** | `dotnet list package --include-transitive` | Includes transitive |
| **Rust** | `cargo tree` | |

Example from Maven (shortened):

```text
[INFO] com.example:sca-demo:jar:1.0.0
[INFO] +- org.apache.logging.log4j:log4j-core:jar:2.14.1:compile
[INFO] |  \- org.apache.logging.log4j:log4j-api:jar:2.14.1:compile     <-- transitive
[INFO] +- commons-collections:commons-collections:jar:3.2.1:compile
[INFO] \- com.fasterxml.jackson.core:jackson-databind:jar:2.9.10:compile
[INFO]    +- com.fasterxml.jackson.core:jackson-annotations:jar:2.9.0:compile   <-- transitive
[INFO]    \- com.fasterxml.jackson.core:jackson-core:jar:2.9.10:compile        <-- transitive
```

You will do this in Lab 1.

### Manifests and Lock Files

| File Type | Purpose | Examples |
| :--- | :--- | :--- |
| **Manifest** | What you **ask for** (often version ranges) | `pom.xml`, `package.json`, `requirements.txt`, `go.mod`, `Cargo.toml` |
| **Lock file** | The **exact versions** that were resolved, including transitive ones | `package-lock.json`, `yarn.lock`, `poetry.lock`, `Pipfile.lock`, `go.sum`, `Cargo.lock`, Gradle lockfiles |

```text
 package.json:        "express": "^4.18.0"       (any 4.x version at or above 4.18.0)
                                |
                                v   (resolved once, then recorded)
 package-lock.json:   express 4.18.2, body-parser 1.20.1, qs 6.11.0, ... (exact versions)
```

**Why lock files matter for security:**

| Without a Lock File | With a Lock File (and `npm ci` or equivalent) |
| :--- | :--- |
| Each build may resolve **different versions** | Every build installs **the same versions** |
| A freshly published (possibly malicious) version can enter silently | Changes happen only through a **reviewed** commit |
| Scans cannot know exactly what shipped | Scanners read the exact versions |

**Commit your lock files**, and in CI use the strict install command that respects them:

| Ecosystem | Strict, Reproducible Install |
| :--- | :--- |
| npm | `npm ci` |
| Python | `pip install -r requirements.txt` with **pinned** versions, ideally `--require-hashes` |
| Poetry | `poetry install` (uses `poetry.lock`) |
| Maven | Pin versions explicitly, use `dependencyManagement` |
| Go | `go build` verifies `go.sum` |

### Package Identifiers: PURL and CPE

To match a component to a vulnerability, tools need a **precise name**. Two identification systems are common:

| Identifier | Format | Example |
| :--- | :--- | :--- |
| **PURL** (Package URL) | `pkg:<type>/<namespace>/<name>@<version>` | `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1` |
| **CPE** (Common Platform Enumeration) | `cpe:2.3:a:<vendor>:<product>:<version>:...` | `cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*` |

```text
 pkg:pypi/flask@3.1.1                   a Python package
 pkg:npm/lodash@4.17.20                 a JavaScript package
 pkg:maven/com.google.guava/guava@32.0  a Java library
 pkg:deb/debian/openssl@3.0.11          an OS package
```

PURLs are precise and ecosystem-native, so tools that use them tend to produce **fewer false positives**. CPEs come from the NVD and can be ambiguous (the same product name can mean different things), which is a classic source of **false positives and false negatives** in tools that rely on them.

### Controlling Your Dependencies

| Practice | Why |
| :--- | :--- |
| **Fewer dependencies** | Every library is attack surface. Ask "do I really need this?" |
| **Commit lock files; install strictly** | Reproducible, reviewable. |
| **Review new dependencies** (maintainers, activity, downloads, license) | Avoid abandoned or suspicious packages. |
| **Check names carefully** | Defeats typosquatting. |
| **Use a private proxy or registry** (Artifactory, Nexus, cloud artifact registries) | One controlled entry point, allow-lists, caching. |
| **Reserve or scope your internal names** (`@my-org/pkg`) | Defeats dependency confusion. |
| **Pin versions and hashes where possible** | A changed package fails the install. |
| **Wait before adopting brand-new releases** (a "cooldown") | Malicious releases are often detected and removed within days. |
| **Remove unused dependencies** | Smaller attack surface. |

---

## 3. Understanding CVE and CVSS

### CVE: A Name for a Vulnerability

A **CVE** (Common Vulnerabilities and Exposures) identifier is a unique public name for one specific vulnerability, so everyone talks about the **same** issue.

```text
 CVE-2021-44228
  |    |     |
  |    |     +-- sequence number
  |    +-------- year the ID was assigned
  +------------- "CVE"
```

| Term | Meaning |
| :--- | :--- |
| **CVE Program** | The system that assigns CVE IDs, run through MITRE and many CNAs |
| **CNA** (CVE Numbering Authority) | An organization allowed to assign CVEs (vendors, researchers, projects) |
| **NVD** (National Vulnerability Database) | The US government database that **enriches** CVEs with severity scores and affected-product data (CPEs) |
| **GHSA** | A GitHub Security Advisory ID (`GHSA-xxxx-xxxx-xxxx`), used by the GitHub Advisory Database |
| **OSV** | An open, ecosystem-focused vulnerability database and format |
| **CWE** | A catalog of weakness **types** (CWE-502 is deserialization of untrusted data, CWE-79 is XSS) |

> [!NOTE]
> Different tools use **different databases** (NVD, GitHub Advisories, OSV, vendor feeds). That is why two scanners can give **different results** for the same project. Neither is "wrong". Understand what your tool uses.

### What a CVE Record Tells You

| Field | What It Tells You |
| :--- | :--- |
| **Description** | What the flaw is and what an attacker can do |
| **Affected versions** | Which versions are vulnerable |
| **Fixed versions** | Where to upgrade |
| **CWE** | The type of weakness |
| **CVSS score and vector** | How severe it is, and why |
| **References** | Advisories, patches, proof-of-concept articles |
| **Known exploited?** | Whether it is on the CISA KEV list |

### CVSS: Scoring Severity From 0 to 10

The **Common Vulnerability Scoring System (CVSS)** gives each vulnerability a score from **0.0 to 10.0** describing its **technical severity**.

| Score | Rating |
| :---: | :--- |
| 0.0 | None |
| 0.1 to 3.9 | **Low** |
| 4.0 to 6.9 | **Medium** |
| 7.0 to 8.9 | **High** |
| 9.0 to 10.0 | **Critical** |

CVSS has versions. **v3.1** is still very common, and **v4.0** (released in late 2023) is being adopted. A record may show one or several. Always check **which version** a score uses.

### The CVSS Vector: Why the Score Is What It Is

The score comes from a **vector string** made of metrics. Here is Log4Shell:

```text
 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H     =  10.0 (Critical)
```

| Metric | Value | Meaning in Plain Words |
| :--- | :---: | :--- |
| **AV** Attack Vector | `N` Network | Exploitable **remotely over the network** (worst case) |
| **AC** Attack Complexity | `L` Low | **Easy**: no special conditions |
| **PR** Privileges Required | `N` None | The attacker needs **no account** |
| **UI** User Interaction | `N` None | **No victim action** needed |
| **S** Scope | `C` Changed | The impact can **spill beyond** the vulnerable component |
| **C** Confidentiality | `H` High | Total loss of confidentiality |
| **I** Integrity | `H` High | Total loss of integrity |
| **A** Availability | `H` High | Total loss of availability |

**Reading it the other way:** a flaw that needs **local access** (`AV:L`), **high privileges** (`PR:H`), and **user interaction** (`UI:R`) scores much lower, even if the impact is high.

| Metric Group | What It Captures |
| :--- | :--- |
| **Base** | The vulnerability's intrinsic severity (what the NVD publishes) |
| **Temporal / Threat** | Whether exploit code exists, whether a fix exists |
| **Environmental** | How it affects **your** environment and assets |

### CVSS Is Not Risk

> [!IMPORTANT]
> **CVSS measures how severe a flaw is in theory. It does not measure how likely you are to be attacked, or how much it matters in your environment.** A CVSS 9.8 flaw in code you never call, in an internal tool, may be less urgent than a CVSS 7.5 flaw in your internet-facing login service.

Use CVSS **together with** these signals:

| Signal | What It Is | How to Use It |
| :--- | :--- | :--- |
| **EPSS** (Exploit Prediction Scoring System) | A probability (0 to 100%) that a CVE will be **exploited in the next 30 days**, published by FIRST | A high EPSS means attackers are likely to use it soon. |
| **CISA KEV** (Known Exploited Vulnerabilities catalog) | A list of CVEs **confirmed to be exploited in the wild** | If a vulnerability you have is on KEV, treat it as **urgent**, whatever its CVSS. |
| **Fix available?** | Does a patched version exist? | Fixable issues are actionable now. |
| **Exposure** | Is the component internet-facing or isolated? | Exposed components come first. |
| **Reachability** | Does your code actually call the vulnerable function? | Unreachable issues are lower priority (but still plan to fix). |
| **Data and business impact** | What would be lost? | Payment and identity systems rank higher. |

### A Simple Prioritization Flow

```text
                     A vulnerability is reported
                                |
          On the CISA KEV list (known exploited)?
              /                                \
            YES                                 NO
             |                                   |
        Fix NOW                       High EPSS or CVSS >= 9?
     (emergency)                      /                    \
                                    YES                     NO
                                     |                       |
                          Internet-facing / reachable?   CVSS 7 to 8.9, fix available?
                             /            \                  /              \
                           YES            NO               YES               NO
                            |              |                |                 |
                       Fix in days     Fix this sprint   Fix this sprint   Track, mitigate,
                                                                            re-check regularly
```

### Look Up a CVE Yourself

- **NVD:** `https://nvd.nist.gov/vuln/detail/CVE-2021-44228`
- **GitHub Advisory Database:** search the CVE ID at `github.com/advisories`
- **CISA KEV catalog:** search the CVE ID to see whether it is known exploited
- **EPSS:** look up the CVE on the FIRST EPSS site

You will do this in Lab 2.

---

## 4. Introduction to OWASP Dependency-Check

### What Is Dependency-Check?

**OWASP Dependency-Check** is a free, open-source SCA tool. It scans your project's files and libraries, identifies components, and reports the **known vulnerabilities** that affect them. It is one of the most widely used SCA tools, especially for **Java** and **.NET**, and also supports JavaScript, Python, Ruby, Go, and other ecosystems, some through **experimental** analyzers.

### How It Works

```text
 1. COLLECT EVIDENCE     Look inside each file: JAR manifests, pom.xml data, package
        |                names, file names, hashes, and metadata
        v
 2. IDENTIFY             Turn the evidence into identifiers:
        |                  - a PURL  (pkg:maven/...)   precise
        |                  - a CPE   (cpe:2.3:a:...)   matched against NVD data
        v
 3. MATCH                Compare identifiers with its local vulnerability database
        |                (built from the NVD and other sources)
        v
 4. REPORT               HTML / JSON / XML / SARIF / CSV / JUnit ... with CVEs, scores,
                         CWEs, and a confidence level for each identification
```

### Key Facts to Understand

| Fact | Explanation |
| :--- | :--- |
| **It keeps a local copy of the vulnerability data** | The first run downloads a large database from the NVD, which can take a while. Later runs only fetch updates. |
| **An NVD API key is strongly recommended** | The NVD rate-limits requests. Without a key, updates are very slow and may fail. The key is free. |
| **It is evidence-based** | It guesses what a file is from clues. Good clues give strong matches. Poor clues give uncertain ones. |
| **It reports a "confidence"** | How sure it is that the identification (and therefore the CVE match) is right. |
| **False positives can happen** | Especially for CPE-based matches. You handle them with **suppressions**. |
| **It works on files** | For Java it analyzes **JAR files**, so you usually need the **resolved dependencies**, not only the `pom.xml`. |

> [!NOTE]
> **Strengths:** free, mature, strong Java and .NET support, easy to run in CI, many report formats, built-in suppression and CVSS gating. **Limits:** CPE-based matching can be noisy, some ecosystems are experimental, and the initial database download is heavy. Many teams use **more than one** SCA tool and compare results.

### Where Dependency-Check Can Run

| Form | Command or Tool | Best For |
| :--- | :--- | :--- |
| **Command line** | `dependency-check.sh` or `dependency-check.bat` | Any language, local use |
| **Docker image** | `owasp/dependency-check` | CI pipelines, labs |
| **Maven plugin** | `org.owasp:dependency-check-maven` | Maven builds |
| **Gradle plugin** | `org.owasp.dependencycheck` | Gradle builds |
| **Jenkins plugin** | "OWASP Dependency-Check" | Jenkins jobs with trend charts |
| **GitHub Action** | `dependency-check/Dependency-Check_Action` | GitHub workflows |

### Other SCA Tools You May Meet

| Tool | Notes |
| :--- | :--- |
| **Trivy** (`trivy fs`, `trivy image`, `trivy sbom`) | All-in-one scanner (Module 07). Uses ecosystem advisory data. |
| **Grype** (pairs with Syft) | Vulnerability scanner for images, directories, and SBOMs. |
| **OSV-Scanner** | Google's scanner using the OSV database. |
| **`npm audit`**, **`pip-audit`**, `cargo audit`, `govulncheck` | Ecosystem-native auditing tools. `govulncheck` can even check **reachability**. |
| **Dependabot** | Alerts and automatic update pull requests built into GitHub (section 9). |
| **OWASP Dependency-Track** | A platform that **ingests SBOMs** and continuously monitors them for new vulnerabilities. |
| **Snyk, Mend, Sonatype, FOSSA, Black Duck** | Commercial platforms with extra features (policy, reachability, license compliance). |

> **Tip:** Because tools use different data sources and matching methods, run **two** on important projects and investigate the differences. A finding reported by both is usually solid.

---

## 5. Scanning Dependencies with Dependency-Check

### Step 1: Get a Free NVD API Key

1. Open the NVD's **"Request an API Key"** page (`https://nvd.nist.gov/developers/request-an-api-key`).
2. Enter your email and request the key. It is emailed to you (follow the activation link).
3. **Treat it as a secret.** Store it in an environment variable, a password manager, or a CI secret. Never commit it.

```bash
read -rs NVD_API_KEY       # paste the key, press Enter (nothing is displayed)
export NVD_API_KEY
```

### Step 2: Choose a Version and Install

Pin a **specific** Dependency-Check version, never a moving tag. Check the project's releases page (`github.com/dependency-check/DependencyCheck/releases`) or the Docker Hub tag list, and set it as a variable.

```bash
export ODC_VERSION="<a verified release, for example the latest shown on the releases page>"
```

> [!WARNING]
> **Supply chain reminder (Module 07):** security tools are part of your supply chain, and one was compromised earlier this year. Pin the version, prefer official sources, and **do not** pipe unreviewed install scripts into a shell.

**Option A: Docker (recommended for labs and CI)**

```bash
docker pull owasp/dependency-check:${ODC_VERSION}
```

**Option B: Command-line download**

Download the release `.zip` from the official releases page, verify its checksum or signature as the project describes, unzip it, and run `bin/dependency-check.sh`. This needs Java installed.

### Step 3: Prepare Something to Scan

Dependency-Check needs the **actual libraries**. For a Java project, copy the resolved dependencies into a folder. You will build the sample project in Lab 1, but the idea is:

```bash
# Resolve dependencies into ./libs using Maven in a container
docker run --rm -v "$PWD":/app -w /app maven:3.9-eclipse-temurin-17 \
  mvn -q dependency:copy-dependencies -DoutputDirectory=libs
ls libs
```

### Step 4: Run the Scan

```bash
mkdir -p odc-data odc-reports

docker run --rm \
  -u "$(id -u):$(id -g)" \
  --volume "$PWD:/src:z" \
  --volume "$PWD/odc-data:/usr/share/dependency-check/data:z" \
  --volume "$PWD/odc-reports:/report:z" \
  owasp/dependency-check:${ODC_VERSION} \
    --scan /src/libs \
    --project "sca-demo" \
    --format ALL \
    --out /report \
    --nvdApiKey "$NVD_API_KEY"
```

| Part | Meaning |
| :--- | :--- |
| `-u "$(id -u):$(id -g)"` | Runs as **you**, so the report and data files are owned by you. |
| `/src` mount | Your project (read by the scanner). |
| `/usr/share/dependency-check/data` mount | **The vulnerability database cache.** Keep it between runs, so you do not re-download everything each time. |
| `/report` mount | Where reports are written. |
| `--scan /src/libs` | What to scan (can be repeated). |
| `--project` | A name for the report. |
| `--format ALL` | HTML, JSON, XML, CSV, JUnit, SARIF, and more. |
| `--nvdApiKey` | Your API key (reads faster and avoids rate-limit failures). |

> [!NOTE]
> **The first run is slow.** It downloads the entire vulnerability database, which can take a long time (and longer without an API key). Be patient, and **keep the `odc-data` folder** so later runs are much faster. Passing a key on the command line makes it visible to other users on a shared machine through the process list. Use a dedicated machine or the tool's configuration options for sensitive environments.

### Important Command-Line Options

| Option | Purpose |
| :--- | :--- |
| `--scan <path>` | A file or folder to scan. Repeat for several. |
| `--project <name>` | The project name shown in reports. |
| `--format <fmt>` / `-f` | `HTML`, `JSON`, `XML`, `CSV`, `JUNIT`, `SARIF`, `JENKINS`, `GITLAB`, or `ALL`. Repeat for several. |
| `--out <dir>` / `-o` | Output folder for reports. |
| `--failOnCVSS <score>` | **Exit with an error** if any vulnerability has a CVSS score at or above this value (**the gate**). The default never fails. |
| `--suppression <file>` | An XML file listing findings to suppress. |
| `--nvdApiKey <key>` | The NVD API key. |
| `--enableExperimental` | Turn on experimental analyzers (several non-Java ecosystems). |
| `--exclude <pattern>` | Skip matching files (Ant-style patterns). |
| `--data <dir>` | Where the vulnerability database is stored. |
| `--noupdate` | Do not update the database (offline or pre-populated runs). |
| `--prettyPrint` | Make JSON and XML reports human-readable. |
| `--disableAssembly`, `--disableNodeAudit`, and similar | Switch off specific analyzers you do not need. |

### Reading the HTML Report

Open `odc-reports/dependency-check-report.html` in a browser.

**1. The summary**

| Item | Meaning |
| :--- | :--- |
| **Dependencies scanned** | How many files were examined. |
| **Vulnerable dependencies** | How many have at least one known vulnerability. |
| **Vulnerabilities found** | Total CVEs across them. |
| **Vulnerabilities suppressed** | Findings you explicitly suppressed. |

**2. The dependency table**

| Column | Meaning |
| :--- | :--- |
| **Dependency** | The file or component analyzed. |
| **Vulnerability IDs** | The CVEs found. |
| **Package** | The identified package (PURL) if one was determined. |
| **Highest Severity** | The worst severity of its CVEs. |
| **CVE Count** | How many CVEs match. |
| **Confidence** | How sure Dependency-Check is about the identification. |
| **Evidence Count** | How many clues supported it. |

**3. The detail for each dependency** shows its file path, hashes, the **evidence** used, the identified package, and a list of each CVE with its **CVSS score**, **CWE**, description, and a **suppress** button that generates the XML for a suppression.

### Understanding Confidence

| Confidence | Meaning | What To Do |
| :--- | :--- | :--- |
| **Highest / High** | Strong evidence (for example, an exact Maven coordinate match) | Findings are very likely real. |
| **Medium** | Reasonable evidence | Verify before acting. |
| **Low** | Weak clues (for example, only a file name) | **Check carefully.** This is where false positives live. |

### Reading the JSON Report

The JSON report is best for scripts and gates. Simplified:

```json
{
  "scanInfo": { "engineVersion": "..." },
  "projectInfo": { "name": "sca-demo" },
  "dependencies": [
    {
      "fileName": "log4j-core-2.14.1.jar",
      "filePath": "/src/libs/log4j-core-2.14.1.jar",
      "sha1": "...",
      "packages": [ { "id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "confidence": "HIGHEST" } ],
      "vulnerabilities": [
        {
          "name": "CVE-2021-44228",
          "severity": "CRITICAL",
          "cvssv3": { "baseScore": 10.0, "baseSeverity": "CRITICAL" },
          "cwes": [ "CWE-502" ],
          "description": "..."
        }
      ]
    }
  ]
}
```

Handy `jq` recipes:

```bash
R=odc-reports/dependency-check-report.json

# Which dependencies are vulnerable, and with which CVEs?
jq -r '.dependencies[] | select(.vulnerabilities) |
       "\(.fileName): \([.vulnerabilities[].name] | join(", "))"' $R

# Count findings by severity
jq -r '[.dependencies[].vulnerabilities[]?] | group_by(.severity)
       | map("\(.[0].severity): \(length)") | .[]' $R

# List CRITICAL and HIGH findings with their CVSS score
jq -r '.dependencies[] | .fileName as $f | .vulnerabilities[]?
       | select(.severity=="CRITICAL" or .severity=="HIGH")
       | "\(.severity)  \(.name)  \(.cvssv3.baseScore // "n/a")  \($f)"' $R | sort
```

### Use It as a Gate

```bash
docker run --rm -u "$(id -u):$(id -g)" \
  -v "$PWD:/src:z" -v "$PWD/odc-data:/usr/share/dependency-check/data:z" -v "$PWD/odc-reports:/report:z" \
  owasp/dependency-check:${ODC_VERSION} \
  --scan /src/libs --format JSON --out /report --nvdApiKey "$NVD_API_KEY" --failOnCVSS 7

echo "Dependency-Check exit code: $?"      # non-zero = at least one finding with CVSS 7.0 or higher
```

With `--failOnCVSS 7`, any finding rated **High or Critical** makes the command **fail**, which fails the pipeline. (A non-zero exit can also mean the scan itself failed, for example because the database update did not work. Read the log.)

### Handling False Positives: Suppression Files

When you have **verified** that a finding does not apply, record that decision in a **suppression file** instead of ignoring it silently.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd">

  <!-- Suppress ONE CVE for ONE package, with a reason and an expiry date -->
  <suppress until="2026-12-31Z">
    <notes><![CDATA[
      CVE-2023-XXXXX affects only the optional XML parser module, which we do not use.
      Verified by: A. Student. Ticket: SEC-231. Review before the expiry date.
    ]]></notes>
    <packageUrl regex="true">^pkg:maven/org\.example/example-lib@1\.2\..*$</packageUrl>
    <cve>CVE-2023-XXXXX</cve>
  </suppress>

</suppressions>
```

Use it:

```bash
... --suppression /src/suppressions.xml
```

| Good Suppression Practice | Why |
| :--- | :--- |
| **Narrow:** one CVE and one package | A broad suppression can hide real problems. |
| **Reason in `<notes>`** with a ticket or approver | Future readers know why. |
| **An `until` date** | Forces a re-review. |
| **Reviewed like code** (CODEOWNERS) | A suppression file is a way to bypass the gate. |
| **Verify first** | Do not suppress because a report is "noisy". |

### What Dependency-Check Does Not Do Well

- It does not know whether the vulnerable code is **reachable**.
- Non-Java ecosystems often rely on **experimental** analyzers. Compare with an ecosystem-native tool.
- CPE-based matching can **over-report** (false positives) or **under-report** when the NVD data lacks product information.
- It cannot find **malicious** packages that have no CVE.

---

## 6. Introduction to SBOM

### What Is an SBOM?

A **Software Bill of Materials (SBOM)** is a **formal, machine-readable inventory** of the components in a piece of software: their names, versions, suppliers, identifiers, licenses, and how they relate to one another.

> **Analogy:** The **nutrition and ingredients label** on food. It does not say the food is safe or healthy. It tells you **exactly what is inside**, so that when someone announces "this ingredient is recalled", you can check in seconds.

```text
 Ingredients label                         Software Bill of Materials

 Wheat flour ........ 60%                  log4j-core ............ 2.14.1   Apache-2.0
 Sugar ............... 20%                  jackson-databind ...... 2.9.10   Apache-2.0
 Palm oil ............ 10%                  commons-collections ... 3.2.1    Apache-2.0
 ...                                        ... (hundreds more, with supplier,
                                                  identifiers, and relationships)
```

### Why Organizations Need SBOMs

| Reason | Explanation |
| :--- | :--- |
| **Incident response** | "Are we affected by the new critical CVE?" becomes a **search**, not an investigation (the Log4Shell lesson). |
| **Continuous monitoring** | Re-scan stored SBOMs every day against new vulnerabilities, **without rebuilding** anything. |
| **Supply chain transparency** | Customers and partners can see what is inside what you deliver. |
| **License compliance** | Know every license obligation. |
| **Compliance and procurement** | Governments and large buyers increasingly require SBOMs (for example, US Executive Order 14028 and its follow-ups, and the EU Cyber Resilience Act). Check current rules for your sector. |
| **Quality and hygiene** | Reveals outdated, unmaintained, and duplicate components. |
| **Reproducibility and audit** | A record of what shipped in each release. |

### What an SBOM Contains

The US NTIA published **minimum elements** that an SBOM should contain. They are widely used as a baseline:

| Element | Meaning | Example |
| :--- | :--- | :--- |
| **Supplier name** | Who provides the component | `Apache Software Foundation` |
| **Component name** | The component's name | `log4j-core` |
| **Version** | The exact version | `2.14.1` |
| **Other unique identifiers** | PURL, CPE, hashes | `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1` |
| **Dependency relationship** | What depends on what | `log4j-core` depends on `log4j-api` |
| **Author of the SBOM data** | Who or what produced the SBOM | `syft 1.x` |
| **Timestamp** | When it was produced | `2026-10-28T10:00:00Z` |

Most SBOMs also include **licenses** and **hashes**.

### What an SBOM Is Not

| An SBOM is... | An SBOM is not... |
| :--- | :--- |
| An **inventory** | A **vulnerability report** (you combine it with a vulnerability database to get one) |
| A snapshot at a point in time | Automatically up to date |
| Only as accurate as the tool that generated it | A guarantee that nothing is missing |
| **Evidence of what you ship** | Proof that what you ship is **safe** |

### Types of SBOM (By When It Is Made)

| Type | Generated From | Pros and Cons |
| :--- | :--- | :--- |
| **Source SBOM** | Source and manifests (`pom.xml`, lock files) | Early and fast, but may miss what the build actually pulls in |
| **Build SBOM** | During the build (build tool knows the resolved dependencies) | Accurate for that build |
| **Analyzed SBOM** | Scanning the **final artifact** (JAR, container image) | Shows **what really ships**, including OS packages in images |
| **Deployed / runtime SBOM** | A running system | What is actually running |

> **Rule of thumb:** generate the SBOM from **the artifact you ship** (the built image or package), because that is what attackers will meet.

### The SBOM Lifecycle

```text
 GENERATE (at build)  -->  STORE (with the artifact)  -->  SIGN / ATTEST (Module 07, Cosign)
        |                                                          |
        |                                                          v
        |                                                SHARE (customers, auditors)
        v
 MONITOR continuously: re-scan stored SBOMs against new vulnerabilities
        |
        v
 ALERT and FIX (rebuild with patched components, publish a new SBOM)
```

**OWASP Dependency-Track** is a popular open-source platform for exactly this: you upload SBOMs, and it **continuously monitors** them against vulnerability sources, tracks policy violations, and notifies you.

### SBOM and VEX

An SBOM lists components. A **VEX** (Vulnerability Exploitability eXchange) document states, for a given product, whether a particular CVE **actually affects it**. Together they let a supplier say: *"Yes, our product contains Log4j (SBOM), but it is **not affected** by this CVE because the vulnerable feature is never used (VEX)."* This cuts false alarms for customers.

---

## 7. SBOM Formats: SPDX vs. CycloneDX

Two open standards dominate. Both can describe components, versions, licenses, hashes, and relationships, and most tools can read and write both.

### At a Glance

| | **SPDX** | **CycloneDX** |
| :--- | :--- | :--- |
| **Full name** | Software Package Data Exchange | CycloneDX (often "CDX") |
| **Maintained by** | The Linux Foundation | OWASP (the CycloneDX project) |
| **Origin and focus** | Started for **license compliance**, now also security | Started for **security and supply chain** use cases |
| **Standardization** | ISO/IEC 5962:2021 (SPDX 2.x) | Standardized as ECMA-424 |
| **Formats** | JSON, YAML, XML, RDF, tag-value | JSON, XML (and Protocol Buffers) |
| **Current versions** | SPDX 2.3 widely used. SPDX 3.0 is newer and more expressive. | 1.5 and 1.6 widely used, with newer revisions appearing |
| **Strengths** | Rich licensing data, mature in legal and compliance contexts, very detailed relationships | Lightweight, security-oriented, supports **VEX, services, and other BOM types** natively |
| **Typical tools** | Syft, Trivy, GitHub (export), many compliance tools | Syft, Trivy, Dependency-Track, Cosign attestation type `cyclonedx` |

> **Which should I choose?** Often **both**. Many organizations produce **CycloneDX** for security tooling (such as Dependency-Track) and **SPDX** when customers or regulators ask for it. Follow your customers' and regulators' requirements, and make sure your tools support your choice.

### The Same Component in Both Formats

**CycloneDX (JSON), simplified:**

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2026-10-28T10:00:00Z",
    "tools": { "components": [ { "type": "application", "name": "syft", "version": "1.x" } ] },
    "component": { "type": "application", "name": "sca-demo", "version": "1.0.0" }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      "group": "org.apache.logging.log4j",
      "name": "log4j-core",
      "version": "2.14.1",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      "licenses": [ { "license": { "id": "Apache-2.0" } } ]
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      "dependsOn": [ "pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1" ]
    }
  ]
}
```

**SPDX (JSON), simplified:**

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "sca-demo",
  "documentNamespace": "https://example.com/spdx/sca-demo-3e671687",
  "creationInfo": {
    "created": "2026-10-28T10:00:00Z",
    "creators": [ "Tool: syft-1.x" ]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-log4j-core",
      "name": "log4j-core",
      "versionInfo": "2.14.1",
      "supplier": "Organization: Apache Software Foundation",
      "downloadLocation": "NOASSERTION",
      "licenseConcluded": "Apache-2.0",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
        }
      ]
    }
  ],
  "relationships": [
    { "spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Package-log4j-core" }
  ]
}
```

### Reading the Key Fields

| Idea | CycloneDX Field | SPDX Field |
| :--- | :--- | :--- |
| Format and version | `bomFormat`, `specVersion` | `spdxVersion` |
| Component name and version | `components[].name`, `.version` | `packages[].name`, `.versionInfo` |
| Package identifier | `components[].purl` | `packages[].externalRefs` (type `purl`) |
| License | `components[].licenses` | `licenseConcluded`, `licenseDeclared` |
| Who created the SBOM and when | `metadata.tools`, `metadata.timestamp` | `creationInfo.creators`, `.created` |
| Dependency relationships | `dependencies[]` (`ref` and `dependsOn`) | `relationships[]` |
| Unique document ID | `serialNumber` | `documentNamespace` |

### SBOM Quality Matters

Not all SBOMs are equally useful. Check:

| Quality Check | Why |
| :--- | :--- |
| **Complete?** Are transitive dependencies and OS packages present? | Missing components mean missing vulnerabilities. |
| **Accurate versions?** | A wrong version gives wrong scan results. |
| **Has PURLs or CPEs?** | Without identifiers, matching is guesswork. |
| **Has relationships?** | Needed to understand which parent pulls in which child. |
| **Valid format?** | Use validators (CycloneDX CLI, SPDX tools) in CI. |
| **Fresh?** | Generated at build time for **that** release. |

### Converting Between Formats

Tools such as Syft (`syft convert`) and the CycloneDX CLI can convert between formats, but conversion can **lose detail** because the formats are not identical. Prefer **generating both formats directly** from the source.

### Other GitHub Features

GitHub can export an SBOM of your repository's dependency graph in **SPDX JSON**:

- **UI:** repository **Insights → Dependency graph → Export SBOM**.
- **API:** `gh api repos/OWNER/REPO/dependency-graph/sbom`.

This reflects **declared** dependencies. For the final image or package, generate an SBOM from the artifact itself.

---

## 8. Generating an SBOM with Syft

### What Is Syft?

**Syft** is a free, open-source tool from Anchore that generates SBOMs from **container images, directories, archives, and more**. It pairs with **Grype**, a vulnerability scanner, and its output works with Trivy, Dependency-Track, and others.

### Installing Syft Safely

Follow the same rules as for Trivy and Dependency-Check: **pinned, verified** versions, from the official source.

```bash
SYFT_VERSION="<a verified release from github.com/anchore/syft/releases, without the leading v>"
BASE="https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}"
FILE="syft_${SYFT_VERSION}_linux_amd64.tar.gz"

curl -sSfL -O "${BASE}/${FILE}"
curl -sSfL -O "${BASE}/syft_${SYFT_VERSION}_checksums.txt"
sha256sum --check --ignore-missing "syft_${SYFT_VERSION}_checksums.txt"      # must say OK

sudo tar -xzf "${FILE}" -C /usr/local/bin syft
syft version
```

Other options: `brew install syft`, or the Docker image `anchore/syft:<pinned-version>`. Avoid `curl ... | sh` installers. (File names can change between releases, so confirm them on the releases page.)

### What Syft Can Scan

| Source | Syntax | Example |
| :--- | :--- | :--- |
| **A directory** | `dir:<path>` | `syft dir:./libs` |
| **A container image** (local daemon) | `docker:<image>` | `syft docker:myapp:1.0` |
| **An image from a registry** | `registry:<image>` | `syft registry:ghcr.io/org/app:1.0` |
| **An image archive** | `docker-archive:<tar>` or `oci-archive:<tar>` | `syft docker-archive:image.tar` |
| **A single file** | `file:<path>` | `syft file:app.jar` |

If you give just a name (`syft myapp:1.0`), Syft tries to work out the source type.

### Generate an SBOM

```bash
# Human-readable table on screen
syft dir:./libs

# CycloneDX JSON file
syft dir:./libs -o cyclonedx-json=sbom.cdx.json

# SPDX JSON file
syft dir:./libs -o spdx-json=sbom.spdx.json

# Several formats in one run
syft dir:./libs \
  -o cyclonedx-json=sbom.cdx.json \
  -o spdx-json=sbom.spdx.json \
  -o syft-json=sbom.syft.json
```

| Output Format | Name | Use |
| :--- | :--- | :--- |
| Table | `table` | Quick look in the terminal |
| CycloneDX | `cyclonedx-json`, `cyclonedx-xml` | Security tooling, Dependency-Track |
| SPDX | `spdx-json`, `spdx-tag-value` | Compliance, customers, regulators |
| Syft native | `syft-json` | Richest detail, can be converted to other formats |
| GitHub | `github-json` | GitHub dependency submission |

### Scan the Artifact You Ship

```bash
# Maven project: scanning only the pom.xml may miss transitive libraries.
# Better: resolve the dependencies (or build the JAR/image) and scan THAT.
syft dir:./libs -o cyclonedx-json=sbom.cdx.json

# A container image: includes OS packages AND application libraries
syft docker:myapp:1.0 -o cyclonedx-json=sbom-image.cdx.json
```

> **Why this matters:** an SBOM made from a `pom.xml` lists what you **declared**. An SBOM made from the built artifact lists what you **shipped**. The second is what attackers will meet.

### Useful Options

| Option | Purpose |
| :--- | :--- |
| `-o <format>=<file>` | Choose output format and file. Repeatable. |
| `--scope all-layers` | For images, include components from **all layers** (default is the final, squashed result). |
| `--exclude "./tests/**"` | Skip paths (repeatable). |
| `--source-name`, `--source-version` | Label the main component in the SBOM (name and version of your product). |
| `-c .syft.yaml` | Use a configuration file for repeatable settings. |
| `-q` / `-v` | Quiet or verbose output. |

Giving the SBOM a meaningful **name and version** helps everyone who reads it later:

```bash
syft dir:./libs --source-name sca-demo --source-version 1.0.0 -o cyclonedx-json=sbom.cdx.json
```

### Inspect an SBOM

```bash
# Count components
jq '.components | length' sbom.cdx.json

# List names, versions, and PURLs
jq -r '.components[] | "\(.name)  \(.version)  \(.purl)"' sbom.cdx.json | sort

# Show licenses
jq -r '.components[] | "\(.name): \([.licenses[]?.license.id // .licenses[]?.license.name] | join(", "))"' sbom.cdx.json

# Search for one component
jq -r '.components[] | select(.name | test("log4j")) | "\(.name) \(.version)"' sbom.cdx.json

# Dependency relationships
jq '.dependencies' sbom.cdx.json | head -40
```

### Answer "Where Is Log4j?" Across Many SBOMs

If you store the SBOM of every build in one folder, the next Log4Shell is a one-liner:

```bash
# Which of our stored SBOMs contain log4j-core, and which version?
for f in sboms/*.cdx.json; do
  jq -r --arg f "$f" '.components[]? | select(.name=="log4j-core") | "\($f)  \(.version)"' "$f"
done
```

This is the whole point of SBOMs: **fast, evidence-based answers**. Platforms such as **Dependency-Track** do this at scale.

### Scan an SBOM for Vulnerabilities

An SBOM is an inventory. To find vulnerabilities, scan it with a tool that reads SBOMs:

```bash
# Grype (Anchore's scanner, pairs with Syft)
grype sbom:./sbom.cdx.json

# Trivy (Module 07)
trivy sbom sbom.cdx.json --severity HIGH,CRITICAL
```

Benefits: you can **rescan old SBOMs later** against new vulnerability data **without access to the original code or image**.

### Sign the SBOM (Preview of Module 07)

An SBOM should be trustworthy. Attach it to the image as a **signed attestation**:

```bash
cosign attest --yes --type cyclonedx --predicate sbom.cdx.json <image@sha256:digest>
```

Consumers can then verify that the SBOM was produced by your pipeline (Module 07, sections 12 and 13).

---

## 9. Understanding Dependabot

### What Is Dependabot?

**Dependabot** is GitHub's built-in dependency monitoring service. It watches your dependency files and does three jobs:

| Part | What It Does | Triggered By | Needs a Config File? |
| :--- | :--- | :--- | :---: |
| **Dependabot alerts** | **Warns** you when a dependency has a known vulnerability | The GitHub Advisory Database | No |
| **Dependabot security updates** | Automatically opens a **pull request** that upgrades a vulnerable dependency to a safe version | A new alert | No |
| **Dependabot version updates** | Opens regular pull requests to keep **all** dependencies current, even when not vulnerable | A schedule you set | **Yes** (`dependabot.yml`) |

```text
 Advisory published  -->  Dependabot ALERT  -->  Security UPDATE pull request  -->  You review, test, merge
 (GitHub Advisory DB)     (Security tab)         (automatic, safe version)

 Schedule (weekly)   -->  Version UPDATE pull requests  -->  You review, test, merge
 (dependabot.yml)         (keeps you current)
```

> [!NOTE]
> You enabled the basics in Module 03 (section 4.8). Here you go deeper: how to **read** alerts, **tune** the configuration, and **handle** pull requests safely.

### Turn It On (Recap)

1. Repository **Settings → Advanced Security** (older interface: **Code security and analysis**).
2. Enable **Dependency graph**, **Dependabot alerts**, and **Dependabot security updates**.
3. Add `.github/dependabot.yml` for version updates.

Dependabot supports many ecosystems, including `maven`, `gradle`, `npm`, `pip`, `docker`, `github-actions`, `terraform`, `gomod`, `cargo`, `nuget`, and `bundler`.

### A More Complete `dependabot.yml`

```yaml
version: 2
updates:

  # Java / Maven
  - package-ecosystem: "maven"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 5
    labels:
      - "dependencies"
    groups:
      minor-and-patch:                   # one combined PR for low-risk updates
        update-types: ["minor", "patch"]
    ignore:
      - dependency-name: "org.example:legacy-lib"      # documented exception
        versions: ["3.x"]
    cooldown:
      default-days: 5                    # wait a few days after a release before proposing it

  # Python
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"

  # Container base images (Module 07)
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"

  # GitHub Actions: keeps pinned action SHAs current (Modules 03 and 07)
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

| Setting | Purpose |
| :--- | :--- |
| `package-ecosystem` | The type of dependency files to watch. |
| `directory` | Where those files are. Add one entry per folder in a monorepo. |
| `schedule` | How often to check (`daily`, `weekly`, `monthly`). |
| `open-pull-requests-limit` | Prevents a flood of pull requests. |
| `groups` | Combine related updates into **one** pull request, which reduces noise. |
| `ignore` | Skip specific dependencies or versions. **Document the reason.** |
| `labels`, `reviewers` | Organize and route the pull requests. |
| `cooldown` | A newer option that **delays** proposing brand-new releases, giving the community time to spot a malicious version. Check the current documentation for exact options. |

### Reading a Dependabot Alert

Open the repository's **Security → Dependabot** tab, then an alert:

| Field | What It Tells You |
| :--- | :--- |
| **Package and ecosystem** | What is affected. |
| **Severity and CVSS** | How serious. |
| **Vulnerable version range** | Which versions are affected. |
| **Patched version** | The version to upgrade to. |
| **Manifest path** | Which file declares it. |
| **Relationship** | **Direct** or **transitive**. |
| **CVE, GHSA, CWE** | Identifiers and weakness type. |
| **EPSS** (where shown) | The likelihood of exploitation. |

### Dismissing an Alert Responsibly

If you decide not to fix an alert, **dismiss it with an honest reason** (the choices are along the lines of: *a fix has already started*, *no bandwidth to fix*, *risk is tolerable*, *vulnerable code is not actually used*, *inaccurate*). Add a comment explaining the decision. Dismissed alerts are an audit trail.

### Handling Dependabot Pull Requests Safely

A Dependabot pull request is **code you did not write** that changes your dependencies. Treat it with care:

| Step | Why |
| :--- | :--- |
| **Check that CI passes**, including tests, Gitleaks, SAST, and the SCA scan | A dependency update can break behavior or introduce new issues. |
| **Read the release notes and changelog** | Look for breaking changes. |
| **Look at the size of the change** | A tiny patch bump should not rewrite large files. |
| **Be wary of very new releases and major jumps** | These carry more risk. |
| **Do not auto-merge blindly** | Auto-merge only low-risk updates (patch updates with a strong test suite), and require passing checks. |
| **Watch for supply chain warning signs** | New maintainer, unusual install scripts, sudden large changes. |

### Dependency Review: Stop Vulnerable Dependencies Before They Merge

The **dependency review** action examines the **dependency changes in a pull request** and can **fail** the check when the pull request adds a vulnerable (or wrongly licensed) dependency.

```yaml
# .github/workflows/dependency-review.yml
name: Dependency Review
on: pull_request

permissions:
  contents: read

jobs:
  dependency-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4                      # pin to a full commit SHA in production
      - uses: actions/dependency-review-action@v4      # pin to a full commit SHA in production
        with:
          fail-on-severity: high
          # deny-licenses: GPL-3.0-only, AGPL-3.0-only   # example license policy
```

Make it a **required status check** (Module 03, section 4.5). It relies on the dependency graph, and its availability for private repositories depends on your GitHub plan.

### How Dependabot Compares With Dependency-Check

| | **Dependabot** | **Dependency-Check** |
| :--- | :--- | :--- |
| **Runs where** | On GitHub | Anywhere: laptop, CI, Jenkins |
| **Data source** | GitHub Advisory Database (ecosystem-aware) | NVD and others (CPE-based plus other analyzers) |
| **Strength** | Automatic fix pull requests, low noise for supported ecosystems | Scans **files and JARs**, works offline-ish, flexible reports and gates |
| **Weakness** | GitHub-centric, sees only declared dependencies | Can be noisier, heavy first-run database |
| **Best use** | Day-to-day updates and alerts | CI gates and scans of built artifacts |

They **complement** each other. Many teams use both.

---

## 10. Integrating SCA into CI/CD

### The Pipeline Design

```text
 Commit / Pull request
        |
        +--> Dependency review action     (fails if the PR ADDS a vulnerable dependency)
        |
        v
 Build: resolve dependencies
        |
        +--> Dependency-Check scan        (fails on CVSS >= threshold)
        |
        +--> Syft: generate SBOM          (CycloneDX + SPDX)
        |
        +--> Scan the SBOM (Grype/Trivy)  (second opinion, optional)
        |
        v
 Upload reports and SBOM as artifacts
        |
        v
 (Release) Sign / attest the SBOM, store it, and re-scan it on a schedule
```

### GitHub Actions: Dependency-Check and SBOM

This workflow uses **plain Docker commands** and a **pinned, checksum-verified Syft**, so few third-party actions are involved. Set repository **variables** `ODC_VERSION` and `SYFT_VERSION` (to verified releases), and a repository **secret** `NVD_API_KEY`.

```yaml
# .github/workflows/sca.yml
name: SCA - Dependencies and SBOM

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "0 4 * * *"          # daily: new CVEs appear even when code does not change

permissions:
  contents: read

jobs:
  sca:
    runs-on: ubuntu-latest
    steps:
      - name: Check out code
        uses: actions/checkout@v4                 # pin to a full commit SHA in production

      - name: Resolve dependencies (Maven)
        run: |
          docker run --rm -v "$PWD":/app -w /app maven:3.9-eclipse-temurin-17 \
            mvn -q -B dependency:copy-dependencies -DoutputDirectory=libs

      - name: Cache the Dependency-Check database
        uses: actions/cache@v4                    # pin to a full commit SHA in production
        with:
          path: odc-data
          key: odc-data-${{ github.run_id }}
          restore-keys: odc-data-

      - name: Run Dependency-Check (SECURITY GATE)
        env:
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
          ODC_VERSION: ${{ vars.ODC_VERSION }}
        run: |
          mkdir -p odc-data odc-reports
          docker run --rm -u "$(id -u):$(id -g)" \
            -e NVD_API_KEY \
            -v "$PWD:/src:z" \
            -v "$PWD/odc-data:/usr/share/dependency-check/data:z" \
            -v "$PWD/odc-reports:/report:z" \
            "owasp/dependency-check:${ODC_VERSION}" \
              --scan /src/libs \
              --project "${GITHUB_REPOSITORY}" \
              --format HTML --format JSON --format SARIF \
              --out /report \
              --suppression /src/.sca/suppressions.xml \
              --nvdApiKey "$NVD_API_KEY" \
              --failOnCVSS 7

      - name: Install Syft (pinned and checksum-verified)
        if: always()
        env:
          SYFT_VERSION: ${{ vars.SYFT_VERSION }}
        run: |
          set -euo pipefail
          base="https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}"
          file="syft_${SYFT_VERSION}_linux_amd64.tar.gz"
          curl -sSfL -O "${base}/${file}"
          curl -sSfL -O "${base}/syft_${SYFT_VERSION}_checksums.txt"
          sha256sum --check --ignore-missing "syft_${SYFT_VERSION}_checksums.txt"
          sudo tar -xzf "${file}" -C /usr/local/bin syft
          syft version

      - name: Generate the SBOM
        if: always()
        run: |
          syft dir:./libs \
            --source-name "${GITHUB_REPOSITORY}" --source-version "${GITHUB_SHA}" \
            -o cyclonedx-json=sbom.cdx.json \
            -o spdx-json=sbom.spdx.json

      - name: Upload reports and SBOMs
        if: always()
        uses: actions/upload-artifact@v4          # pin to a full commit SHA in production
        with:
          name: sca-reports
          path: |
            odc-reports/
            sbom.cdx.json
            sbom.spdx.json
```

| Part | Why It Matters |
| :--- | :--- |
| `schedule` (daily) | Finds **new** CVEs in unchanged code. |
| `permissions: contents: read` | Least privilege for the workflow token. |
| Resolve dependencies first | Dependency-Check scans **JAR files**. |
| Cache `odc-data` | Avoids re-downloading the database each run. |
| `NVD_API_KEY` as a **secret** | Never in the file or the logs. |
| `--failOnCVSS 7` | **The gate**: fail on High and Critical findings. |
| `--suppression` | Reviewed, documented exceptions only. |
| `if: always()` on SBOM and upload | You still get reports when the gate fails. |
| Syft pinned and verified | Avoids the "latest" and unverified-download traps from Module 07. |

### Pull Request Dependency Review

Add the **dependency review** workflow from section 9 as a **separate, fast** check. It tells reviewers **exactly which dependency changes** a pull request introduces.

### Jenkins: Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any

    environment {
        ODC_VERSION  = '<a verified release>'       // set deliberately; never 'latest'
        SYFT_VERSION = '<a verified release>'
    }

    stages {
        stage('Checkout') {
            steps { checkout scm }
        }

        stage('Resolve Dependencies') {
            steps {
                sh '''
                    docker run --rm -v "$PWD":/app -w /app maven:3.9-eclipse-temurin-17 \
                      mvn -q -B dependency:copy-dependencies -DoutputDirectory=libs
                '''
            }
        }

        stage('SCA - Dependency-Check (Security Gate)') {
            steps {
                withCredentials([string(credentialsId: 'nvd-api-key', variable: 'NVD_API_KEY')]) {
                    sh '''
                        mkdir -p odc-reports "$HOME/odc-data"
                        docker run --rm -u "$(id -u):$(id -g)" -e NVD_API_KEY \
                          -v "$PWD:/src:z" \
                          -v "$HOME/odc-data:/usr/share/dependency-check/data:z" \
                          -v "$PWD/odc-reports:/report:z" \
                          owasp/dependency-check:${ODC_VERSION} \
                            --scan /src/libs --project "$JOB_NAME" \
                            --format HTML --format JSON --format JUNIT \
                            --out /report --nvdApiKey "$NVD_API_KEY" \
                            --failOnCVSS 7
                    '''
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'odc-reports/**', allowEmptyArchive: true
                    junit allowEmptyResults: true, testResults: 'odc-reports/dependency-check-junit.xml'
                }
            }
        }

        stage('Generate SBOM') {
            steps {
                sh '''
                    docker run --rm -v "$PWD:/work" anchore/syft:${SYFT_VERSION} \
                      dir:/work/libs -o cyclonedx-json=/work/sbom.cdx.json -o spdx-json=/work/sbom.spdx.json
                '''
                archiveArtifacts artifacts: 'sbom.*.json', allowEmptyArchive: true
            }
        }
    }
}
```

| Part | Why It Matters |
| :--- | :--- |
| `withCredentials` | The NVD key is injected temporarily and masked. The shell block is **single-quoted** so Jenkins does not interpolate the secret into the script text. |
| A persistent `$HOME/odc-data` | Keeps the database between builds. |
| `--failOnCVSS 7` | A non-zero exit **fails the stage** and stops the pipeline. |
| `junit` | Shows findings as test-style results in Jenkins. |
| Pinned versions | No `latest`. |

> [!NOTE]
> A **Jenkins plugin** for Dependency-Check also exists. It offers trend charts and build-failure thresholds (`dependencyCheckPublisher`). Plugin parameters change between versions, so follow the plugin's current documentation if you prefer it. The Docker approach shown here behaves the same way on every CI system.

### Re-Scan Stored SBOMs on a Schedule

New vulnerabilities appear **after** release. Keep each release's SBOM, and re-scan them regularly:

```bash
# Nightly job: re-scan the SBOMs of everything that is deployed
for f in sboms/*.cdx.json; do
  echo "== $f"
  trivy sbom "$f" --severity HIGH,CRITICAL --ignore-unfixed --exit-code 0
done
```

Or upload SBOMs to **Dependency-Track**, which does this continuously and notifies you.

### Make It Required

As in earlier modules: **Settings → Rules → Rulesets** → require the **SCA** and **Dependency Review** checks on `main`.

---

## 11. Security Gates and Vulnerability Remediation

### What Is an SCA Security Gate?

A **gate** is a rule that decides whether the pipeline may continue after the scan. A scan without a gate is only advice.

```text
 SCA scan  -->  Meets policy?  --NO-->  FAIL: block merge or release, create a ticket
                    |
                   YES
                    v
                 Continue
```

### Gate Options

| Method | How |
| :--- | :--- |
| **CVSS threshold** | `dependency-check --failOnCVSS 7` fails on High and Critical. |
| **Severity filter in a script** | Parse the JSON report and count findings by severity (below). |
| **Dependency review** | Fails a pull request that **adds** a vulnerable dependency. |
| **SBOM scan** | `trivy sbom --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed` or `grype ... --fail-on high`. |
| **Jenkins publisher thresholds** | Fail or mark unstable by counts per severity. |
| **License policy** | Fail on disallowed licenses (dependency review `deny-licenses`, Trivy license scanning). |

A custom gate script:

```bash
#!/usr/bin/env bash
# sca-gate.sh : fail the pipeline based on the Dependency-Check JSON report
R="${1:-odc-reports/dependency-check-report.json}"

CRIT=$(jq '[.dependencies[].vulnerabilities[]? | select(.severity=="CRITICAL")] | length' "$R")
HIGH=$(jq '[.dependencies[].vulnerabilities[]? | select(.severity=="HIGH")] | length' "$R")
echo "Critical: $CRIT   High: $HIGH"

if [ "$CRIT" -gt 0 ]; then echo "GATE FAILED: Critical vulnerabilities found."; exit 1; fi
if [ "$HIGH" -gt 3 ]; then echo "GATE FAILED: more than 3 High vulnerabilities."; exit 1; fi
echo "GATE PASSED"
```

### Designing a Fair Policy

Start gently and tighten. A gate that always fails gets bypassed.

| Stage | Policy |
| :--- | :--- |
| **1. Visibility** | Report only. Learn what you have. |
| **2. Block the worst** | Fail on **Critical**, and on anything on the **CISA KEV** list. |
| **3. Block fixable High** | Fail on High findings that **have a fix**. |
| **4. Mature** | Fail on **new** findings only, track old ones with deadlines, and review suppressions on a schedule. |

| Principle | Reason |
| :--- | :--- |
| **Fixable findings first** | They are actionable now. |
| **Known-exploited always blocks** | Active exploitation outweighs a CVSS number. |
| **Gate on new findings in pull requests** | Developers are not blamed for old debt, but cannot add more. |
| **Time-bound exceptions** | An exception without an expiry becomes permanent. |
| **Scheduled rescans** | New CVEs appear daily. |

### Remediation Strategies, From Best to Last Resort

| # | Strategy | How |
| :---: | :--- | :--- |
| 1 | **Upgrade the direct dependency** to a patched version | Edit the version, run tests, rescan. |
| 2 | **Override a transitive dependency** | Force the safe version when the parent library has not updated yet. |
| 3 | **Replace the library** | Switch to a maintained alternative. |
| 4 | **Remove it** | If it is unused, delete it. The best fix of all. |
| 5 | **Use a vendor-patched build** | Some vendors backport fixes into supported versions. |
| 6 | **Mitigate** | Disable the vulnerable feature, restrict input, block the path at the network or WAF. (Mitigations for **Log4Shell** were released before the full fix, but the real solution was upgrading.) |
| 7 | **Accept the risk, temporarily** | Suppress with a documented reason, approver, and **expiry date**. |

### Upgrading a Direct Dependency

```xml
<!-- Maven: pom.xml -->
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <version>2.24.3</version>        <!-- was 2.14.1: use the latest patched release -->
</dependency>
```

```bash
mvn versions:display-dependency-updates        # Maven: what could be updated?
npm outdated && npm audit fix                  # Node
pip list --outdated                            # Python
```

### Forcing a Safe Version of a Transitive Dependency

```xml
<!-- Maven: pin the version of a transitive dependency centrally -->
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.17.2</version>
    </dependency>
  </dependencies>
</dependencyManagement>
```

```json
// npm: package.json "overrides"
{
  "overrides": {
    "vulnerable-lib": "1.2.5"
  }
}
```

```text
# Python: a constraints file (use with: pip install -r requirements.txt -c constraints.txt)
urllib3>=2.2.2
```

> [!WARNING]
> Overriding a transitive dependency can break the parent library if the new version is not compatible. **Run your tests**, and remove the override once the parent library catches up.

### Ecosystem-Native Audit Tools

| Tool | Command | Notes |
| :--- | :--- | :--- |
| **npm** | `npm audit`, `npm audit fix` | Uses the npm advisory data |
| **pip-audit** | `pip-audit -r requirements.txt` | Python Packaging Authority tool |
| **govulncheck** | `govulncheck ./...` | Go: reports vulnerabilities your code **actually calls** |
| **cargo audit** | `cargo audit` | Rust |
| **bundler-audit** | `bundle-audit check` | Ruby |
| **OSV-Scanner** | See its documentation | Multi-ecosystem, OSV data |

### Remediation Workflow

```text
 1. TRIAGE     Real? Which dependency, direct or transitive? Fix available? Exposed? Exploited?
 2. DECIDE     Upgrade / override / replace / remove / mitigate / accept (with expiry)
 3. FIX        Make the change on a branch. Open a pull request.
 4. TEST       Automated tests, plus the SCA scan itself
 5. VERIFY     Rescan: the finding is gone and nothing new and worse appeared
 6. RELEASE    New SBOM generated and stored with the release
 7. RECORD     Ticket updated, suppressions cleaned up, lessons captured
```

### Example Service-Level Targets (Adapt to Your Policy)

| Condition | Typical Target |
| :--- | :--- |
| **On the CISA KEV list** | Emergency: hours to a day |
| **Critical, internet-facing** | Days |
| **High, with a fix** | One to two weeks |
| **Medium** | Within the normal release cycle |
| **Low** | Routine maintenance |

### Measure Your Program

| Metric | What It Shows |
| :--- | :--- |
| **Open vulnerabilities by severity** | Current exposure |
| **Mean time to remediate** | How fast you fix |
| **Age of oldest open High and Critical** | Neglected risk |
| **Percentage of repos with SCA and SBOM** | Coverage |
| **Number and age of suppressions** | Accepted risk and its hygiene |
| **Dependencies per project** | Attack surface trend |

---

## 12. Hands-On Labs

> [!WARNING]
> The lab project uses **deliberately vulnerable library versions** (including the Log4Shell-affected Log4j). Use them only for scanning. **Never run it as a service, deploy it, or publish it.**

### Lab Setup: The Sample Project

```bash
mkdir -p ~/sca-lab && cd ~/sca-lab

cat > pom.xml <<'EOF'
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>sca-demo</artifactId>
  <version>1.0.0</version>
  <packaging>jar</packaging>

  <properties>
    <maven.compiler.source>17</maven.compiler.source>
    <maven.compiler.target>17</maven.compiler.target>
  </properties>

  <dependencies>
    <!-- DELIBERATELY OLD AND VULNERABLE: for scanning practice only -->
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
    <dependency>
      <groupId>commons-collections</groupId>
      <artifactId>commons-collections</artifactId>
      <version>3.2.1</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.9.10</version>
    </dependency>
  </dependencies>
</project>
EOF

# Save secrets/keys policy: never commit the NVD key
echo -e "odc-data/\nodc-reports/\nlibs/\n.env" > .gitignore
```

> [!NOTE]
> Results depend on the date you run the labs, because vulnerability data changes daily. Focus on **how the findings change** as you fix things, not on matching exact numbers.

### Lab 1: Explore Direct and Transitive Dependencies

**Objective:** See what you really depend on.

**Tasks:**

```bash
cd ~/sca-lab

# 1. Show the dependency tree
docker run --rm -v "$PWD":/app -w /app maven:3.9-eclipse-temurin-17 mvn -B dependency:tree

# 2. Copy the resolved libraries into ./libs
docker run --rm -v "$PWD":/app -w /app maven:3.9-eclipse-temurin-17 \
  mvn -q -B dependency:copy-dependencies -DoutputDirectory=libs

ls -1 libs
```

Fill in the table:

| Question | Your Answer |
| :--- | :--- |
| How many dependencies did you **declare** in `pom.xml`? | |
| How many JAR files are in `libs/`? | |
| Which libraries are **transitive**? | |
| Which direct dependency pulled in each transitive one? | |
| Why does this matter for vulnerability scanning? | |

**Optional:** do the same for a Python or Node project you have (`pipdeptree` or `npm ls --all`).

**Expected outcome:** You declared **3** dependencies but ship **more** JARs. You can point to each transitive dependency and its parent.

### Lab 2: Research a CVE and Decode CVSS

**Objective:** Learn to read vulnerability data.

**Tasks:** Using a browser, research **CVE-2021-44228** (Log4Shell):

1. Open its record on the **NVD**. Note the description, CWE, affected versions, and fixed versions.
2. Write down the **CVSS v3.1 vector** and decode each metric using section 3.
3. Search the **CISA KEV catalog**. Is it listed?
4. Look up its **EPSS** score.
5. Open the same CVE in the **GitHub Advisory Database**. Compare its data to the NVD.

| Question | Your Answer |
| :--- | :--- |
| CVSS score and vector | |
| What does `AV:N` and `PR:N` mean for an attacker? | |
| Weakness type (CWE) | |
| On the KEV list? | |
| EPSS probability | |
| Lowest fixed version you can find | |
| Why would this need an **emergency** response even without a CVSS number? | |

**Expected outcome:** You can explain, from the vector alone, why Log4Shell scored 10.0 and why KEV and EPSS add information that CVSS lacks.

### Lab 3: Scan With Dependency-Check

**Objective:** Run a full scan and read the reports.

**Tasks:**

1. Get a free **NVD API key** (section 5) and store it safely:

```bash
read -rs NVD_API_KEY ; export NVD_API_KEY
```

2. Choose a verified Dependency-Check release and pin it:

```bash
export ODC_VERSION="<verified release>"
docker pull owasp/dependency-check:${ODC_VERSION}
```

3. Run the scan (the first run downloads the database, so be patient):

```bash
cd ~/sca-lab
mkdir -p odc-data odc-reports
docker run --rm -u "$(id -u):$(id -g)" \
  -v "$PWD:/src:z" -v "$PWD/odc-data:/usr/share/dependency-check/data:z" -v "$PWD/odc-reports:/report:z" \
  owasp/dependency-check:${ODC_VERSION} \
    --scan /src/libs --project sca-demo --format ALL --out /report --nvdApiKey "$NVD_API_KEY"
```

4. Open `odc-reports/dependency-check-report.html`. Answer:

| Question | Your Answer |
| :--- | :--- |
| Dependencies scanned | |
| Vulnerable dependencies | |
| Total vulnerabilities | |
| Highest severity found, and in which library | |
| Which finding is Log4Shell, and what is its score? | |
| What is the **confidence** for that finding? | |

5. Use `jq` on the JSON report:

```bash
R=odc-reports/dependency-check-report.json
jq -r '.dependencies[] | select(.vulnerabilities) | "\(.fileName): \([.vulnerabilities[].name] | join(", "))"' $R
jq -r '[.dependencies[].vulnerabilities[]?] | group_by(.severity) | map("\(.[0].severity): \(length)") | .[]' $R
```

6. Run it again and note how much faster the second run is (the cached database).

**Expected outcome:** Several vulnerable dependencies, including **log4j-core** with a Critical finding. You can explain every column of the report.

### Lab 4: Triage, Suppress, and Gate

**Objective:** Make a pass or fail decision and document an exception.

**Tasks:**

1. Run the scan with a gate and check the exit code:

```bash
docker run --rm -u "$(id -u):$(id -g)" \
  -v "$PWD:/src:z" -v "$PWD/odc-data:/usr/share/dependency-check/data:z" -v "$PWD/odc-reports:/report:z" \
  owasp/dependency-check:${ODC_VERSION} \
    --scan /src/libs --format JSON --out /report --nvdApiKey "$NVD_API_KEY" --failOnCVSS 7
echo "Exit code: $?"
```

2. Choose **one** finding from the HTML report and **investigate** it: read the CVE, decide whether it truly applies. (For the lab, treat a finding on an unrelated module as your "verified false positive" exercise, and practice the mechanics.)
3. Click **suppress** on that finding in the HTML report to see the generated XML. Create `.sca/suppressions.xml` (section 5 format) with a **reason**, **ticket**, and an **`until`** date.
4. Re-run with `--suppression /src/.sca/suppressions.xml`. Confirm the **suppressed count** increased.
5. Run `sca-gate.sh` from section 11 against the JSON report.

**Expected outcome:** The gate **fails** (non-zero exit code) before fixes. The suppression reduces the count, and you can explain why a suppression needs a reason, a narrow scope, and an expiry date.

### Lab 5: Remediate the Vulnerabilities

**Objective:** Fix findings and prove it by rescanning.

**Tasks:**

1. Update `pom.xml`:
   - `log4j-core` to a patched release (for example `2.24.3`).
   - `commons-collections` to `3.2.2`.
   - `jackson-databind` to a current patched release (for example `2.17.2`).
2. Rebuild `libs/` and rescan:

```bash
rm -rf libs odc-reports/*
docker run --rm -v "$PWD":/app -w /app maven:3.9-eclipse-temurin-17 \
  mvn -q -B dependency:copy-dependencies -DoutputDirectory=libs

docker run --rm -u "$(id -u):$(id -g)" \
  -v "$PWD:/src:z" -v "$PWD/odc-data:/usr/share/dependency-check/data:z" -v "$PWD/odc-reports:/report:z" \
  owasp/dependency-check:${ODC_VERSION} \
    --scan /src/libs --format ALL --out /report --nvdApiKey "$NVD_API_KEY" --failOnCVSS 7
echo "Exit code: $?"
```

3. Compare before and after:

| | Before | After |
| :--- | :---: | :---: |
| Vulnerable dependencies | | |
| Critical | | |
| High | | |
| Gate exit code | | |

4. If something remains, decide: upgrade further, override a transitive dependency (section 11), or accept with an expiry.
5. **Optional:** use a `dependencyManagement` block to force a newer `jackson-databind` while leaving the declared version older, and observe the dependency tree change.

**Expected outcome:** Critical and High findings drop sharply or disappear, and the gate passes (or fails only on findings you can explain). You can describe each remediation strategy you used.

### Lab 6: Generate and Inspect SBOMs With Syft

**Objective:** Produce SBOMs in both standard formats and use them.

**Tasks:**

1. Install Syft following section 8 (**pinned and checksum-verified**).
2. Generate the SBOMs for the **fixed** project and, for comparison, the original vulnerable versions (rename `libs` first, or rebuild):

```bash
cd ~/sca-lab
mkdir -p sboms
syft dir:./libs --source-name sca-demo --source-version 1.1.0 \
  -o cyclonedx-json=sboms/sca-demo-1.1.0.cdx.json \
  -o spdx-json=sboms/sca-demo-1.1.0.spdx.json
```

3. Inspect:

```bash
jq '.components | length' sboms/sca-demo-1.1.0.cdx.json
jq -r '.components[] | "\(.name)  \(.version)  \(.purl)"' sboms/sca-demo-1.1.0.cdx.json | sort
jq '.packages | length' sboms/sca-demo-1.1.0.spdx.json
```

4. Verify the **minimum elements** from section 6 are present (supplier or author, name, version, identifiers, relationships, tool, timestamp). Which are missing in your SBOM, if any?
5. Create a second SBOM from the **old** vulnerable `pom.xml` (version `1.0.0`) and save it in `sboms/`. Then run the "Where is log4j?" search across both:

```bash
for f in sboms/*.cdx.json; do
  jq -r --arg f "$f" '.components[]? | select(.name|test("log4j")) | "\($f)  \(.name)  \(.version)"' "$f"
done
```

6. Compare CycloneDX and SPDX for the same component. Which fields correspond (section 7)?

**Expected outcome:** Two valid SBOM files per version, each listing the same libraries. The search immediately shows which version of log4j each release contains. You can explain why storing SBOMs per release answers "are we affected?" quickly.

### Lab 7: Scan the SBOM and Compare Tools

**Objective:** Use the SBOM as the input for vulnerability scanning, and compare tool results.

**Tasks:**

```bash
cd ~/sca-lab

# Trivy (Module 07)
trivy sbom sboms/sca-demo-1.0.0.cdx.json

# Grype (optional): install the same careful way as Syft
grype sbom:./sboms/sca-demo-1.0.0.cdx.json
```

Compare with the Dependency-Check results for the **vulnerable** version:

| Question | Dependency-Check | Trivy or Grype |
| :--- | :--- | :--- |
| Total findings | | |
| Critical and High count | | |
| Is Log4Shell found? | | |
| Any finding **only one tool** reports? | | |
| Likely reason for the difference (data source, matching method) | | |

**Expected outcome:** The tools agree on the **serious, well-known** issues (such as Log4Shell) and differ on the rest. You can explain that results depend on data sources and matching methods, and why running two tools on critical projects is useful.

### Lab 8: Dependabot and Dependency Review

**Objective:** Use GitHub's automatic dependency protection.

> [!NOTE]
> Use a **test repository**. Dependabot alerts and updates work for private and public repositories. Dependency review for private repositories depends on your plan.

**Tasks:**

1. Push the **vulnerable** `pom.xml` (version `1.0.0`) to a new repository on `main`.
2. Enable **Dependency graph**, **Dependabot alerts**, and **Dependabot security updates** (Settings → Advanced Security).
3. Wait a few minutes. Open **Security → Dependabot**. For the Log4j alert, record: severity, vulnerable range, patched version, and direct or transitive.
4. Look for a Dependabot **security update pull request**. Review it as described in section 9: CI, release notes, size of change.
5. Add `.github/dependabot.yml` with the Maven, `docker`, and `github-actions` ecosystems, a `groups` entry, and a `cooldown` (if available to you).
6. Add the **dependency review** workflow. Create a branch that **adds** a vulnerable dependency (for example, an old `commons-text` version), open a pull request, and watch the check fail.
7. Export the repository SBOM from **Insights → Dependency graph → Export SBOM**, and compare it to the Syft SBOM from Lab 6.

**Expected outcome:** Alerts appear, a fix pull request is proposed, the dependency review check **blocks** the pull request that adds a vulnerable dependency, and you can compare GitHub's SBOM with the Syft one.

### Lab 9: SCA in GitHub Actions and Jenkins

**Objective:** Automate the scan, the SBOM, and the gate.

**GitHub Actions tasks:**

1. In your test repository (with the **vulnerable** `pom.xml`), add `.github/workflows/sca.yml` from section 10.
2. Add the **secret** `NVD_API_KEY` and the **variables** `ODC_VERSION` and `SYFT_VERSION` (verified releases).
3. Push and watch the **Dependency-Check** step **fail** on `--failOnCVSS 7`. Download the `sca-reports` artifact and open the HTML report and SBOMs. (The first run downloads the database and may take a while.)
4. Fix the dependencies (Lab 5), push, and confirm the workflow **passes**.
5. Make the **SCA** and **Dependency Review** checks **required** for `main`.

**Jenkins tasks (optional):**

1. Use a Jenkins agent with Docker. Add credential `nvd-api-key` (secret text).
2. Add the `Jenkinsfile` from section 10 with pinned versions, create a Pipeline job from SCM, and run it with the vulnerable and fixed projects.
3. Confirm the SCA stage **fails** then **passes**, and the SBOM artifacts are archived.

**Expected outcome:** A vulnerable dependency set is **blocked** in the pipeline, and a fixed one passes, with the reports and SBOMs saved as artifacts. You can explain why the workflow runs daily as well as on every change.

### Cleanup

```bash
unset NVD_API_KEY
rm -rf ~/sca-lab/libs
# Keep (or securely delete) odc-data. It is only a vulnerability database cache.
```

---

## 13. Best Practices

### Know and Control Your Dependencies

| Practice | Why |
| :--- | :--- |
| **Keep the dependency count small** | Every library is attack surface and maintenance work. |
| **Commit lock files; install strictly** (`npm ci`, pinned versions) | Reproducible, reviewable builds. |
| **Review new dependencies** (maintainers, activity, license, alternatives) | Avoids abandoned and suspicious packages. |
| **Double-check names** | Defeats typosquatting. |
| **Use a private proxy or registry and scoped names** | One controlled entry point, defeats dependency confusion. |
| **Pin versions and hashes where possible** | Tampered packages fail to install. |
| **Delay adopting brand-new releases** (cooldowns) | Malicious releases are often caught quickly. |
| **Remove unused dependencies** | Less to patch. |
| **Do not rely on `latest` or open-ended ranges** in production builds | Unpredictable and risky. |

### Scan and Monitor

| Practice | Why |
| :--- | :--- |
| **Scan every pull request and every build** | Catch problems before merge. |
| **Rescan on a schedule** (daily) | New CVEs appear after release. |
| **Use two tools on critical projects** | Different data and methods, so you catch more. |
| **Scan the built artifact**, not only manifests | Reflects what really ships. |
| **Keep the Dependency-Check database cached; use an NVD API key** | Faster and reliable. |
| **Track findings in one place** (Dependency-Track, a ticket system) | Ownership and visibility. |

### SBOM Hygiene

| Practice | Why |
| :--- | :--- |
| **Generate an SBOM for every release** | Evidence of what shipped. |
| **Produce both CycloneDX and SPDX if needed** | Meets different consumers. |
| **Generate from the final artifact** | Accurate, includes OS packages in images. |
| **Name and version the SBOM subject** | Searchable and traceable. |
| **Store SBOMs with the release and sign them** | Integrity (Module 07). |
| **Validate SBOMs in CI** | Catch missing or malformed data. |
| **Re-scan stored SBOMs regularly** | Continuous monitoring without rebuilding. |
| **Pair with VEX when you can** | Reduces false alarms for consumers. |

### Prioritize and Fix

| Practice | Why |
| :--- | :--- |
| **Prioritize by KEV, EPSS, exposure, and fix availability, not CVSS alone** | Effort goes where the risk is. |
| **Fix fixable High and Critical first** | Actionable and valuable. |
| **Prefer upgrade over suppress** | Suppression leaves the risk in place. |
| **Test after every upgrade** | Updates can break behavior. |
| **Rescan to verify** | A fix is not done until proven. |
| **Give every exception a reason, owner, and expiry** | Accepted risk must be deliberate and temporary. |
| **Protect suppression files and gate configuration** (CODEOWNERS) | They are a way to bypass the gate. |

### Automate Safely

| Practice | Why |
| :--- | :--- |
| **Use Dependabot version updates with grouping and cooldowns** | Keeps you current with less noise and less risk. |
| **Treat Dependabot pull requests as code to review** | They change what you ship. |
| **Require the dependency review check on pull requests** | Stops vulnerable additions. |
| **Pin tool versions and GitHub Actions to commit SHAs; verify downloads** | Security tools are part of the supply chain (Module 07). |
| **Keep the NVD key and tokens in secrets** | Never in code or logs (Module 03). |
| **Least-privilege workflow permissions** | Limits the damage of a compromised step. |

### Maturity Roadmap

```text
Level 1  Aware       Dependabot alerts on, lock files committed, know your direct dependencies
Level 2  Scanning    Dependency-Check or equivalent in CI with a gate, reports archived
Level 3  Inventory   SBOM per release (CycloneDX/SPDX), stored and searchable, dependency review on PRs
Level 4  Continuous  Dependency-Track or scheduled SBOM rescans, signed SBOMs, KEV/EPSS-driven SLAs,
                     cooldowns and private registry controls
```

### Know the Limits

- A **clean SCA report** means "no *known* vulnerabilities in the databases we checked", not "no risk".
- SCA does **not** detect malicious packages that have no CVE yet, flaws in your own code, or whether vulnerable code is reachable.
- An SBOM is an **inventory**, only as good as how it was generated.

---

## 14. Knowledge Check

1. What does SCA find, and what does it **not** find? Give two examples of each.
2. Why did Log4Shell cause so much confusion, and how does an SBOM help with a similar event?
3. What is the difference between a direct and a transitive dependency? Why do transitive ones matter for security?
4. What is the difference between a manifest and a lock file? Why should lock files be committed?
5. What are a PURL and a CPE, and why can CPE-based matching produce false positives?
6. Name three supply chain attacks that a CVE scan will usually **not** catch, and one control for each.
7. What is a CVE? Who assigns CVE IDs, and what does the NVD add?
8. Decode this vector in plain words: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`.
9. Why is CVSS not the same as risk? Name four additional signals you should use.
10. What are EPSS and the CISA KEV catalog, and how do they change prioritization?
11. How does Dependency-Check identify a component and match it to a vulnerability?
12. Why should you use an NVD API key and cache the Dependency-Check database?
13. What do the confidence levels in a Dependency-Check report mean, and which findings deserve the most skepticism?
14. What does `--failOnCVSS 7` do? Why must a non-zero exit code sometimes be investigated rather than assumed to be a vulnerability?
15. What should a good suppression contain? Why is an expiry date important?
16. What is an SBOM, and what is it **not**?
17. List the NTIA minimum elements of an SBOM.
18. Compare SPDX and CycloneDX. When might you produce both?
19. Why should an SBOM be generated from the built artifact instead of only from `pom.xml`?
20. How can stored SBOMs be rescanned, and why is that valuable after a release?
21. What is VEX, and how does it complement an SBOM?
22. What are the three parts of Dependabot, and which one needs a configuration file?
23. How should you handle a Dependabot pull request? What are two supply chain risks of auto-merging?
24. What does the dependency review action do, and why is it a good pull request gate?
25. Compare Dependabot and Dependency-Check. When would you use each?
26. List four remediation strategies in order of preference, and explain how to force a safe version of a transitive dependency.
27. Design a fair SCA gate policy for a team adopting SCA for the first time.
28. Why should SCA scans run on a **schedule** as well as on every commit?

---

## 15. Official References

### SCA and Vulnerability Data

- OWASP Dependency-Check: <https://dependency-check.github.io/DependencyCheck/>
- Dependency-Check source and releases: <https://github.com/dependency-check/DependencyCheck>
- Dependency-Check CLI arguments: <https://dependency-check.github.io/DependencyCheck/dependency-check-cli/arguments.html>
- NVD (National Vulnerability Database): <https://nvd.nist.gov/>
- Request an NVD API key: <https://nvd.nist.gov/developers/request-an-api-key>
- CVE Program: <https://www.cve.org/>
- GitHub Advisory Database: <https://github.com/advisories>
- OSV (Open Source Vulnerabilities): <https://osv.dev/>
- FIRST CVSS: <https://www.first.org/cvss/>
- FIRST EPSS: <https://www.first.org/epss/>
- CISA Known Exploited Vulnerabilities catalog: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- CWE: <https://cwe.mitre.org/>

### SBOM

- Syft: <https://github.com/anchore/syft>
- Grype: <https://github.com/anchore/grype>
- CycloneDX: <https://cyclonedx.org/>
- SPDX: <https://spdx.dev/>
- Package URL (PURL) specification: <https://github.com/package-url/purl-spec>
- OWASP Dependency-Track: <https://dependencytrack.org/>
- NTIA, The Minimum Elements for an SBOM: <https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom>
- CISA SBOM resources: <https://www.cisa.gov/sbom>

### GitHub

- Dependabot documentation: <https://docs.github.com/en/code-security/dependabot>
- Dependabot configuration options (`dependabot.yml`): <https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference>
- Dependency review action: <https://github.com/actions/dependency-review-action>
- Exporting a repository SBOM: <https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/exporting-a-software-bill-of-materials-for-your-repository>

### Ecosystem Audit Tools and Guidance

- npm audit: <https://docs.npmjs.com/cli/commands/npm-audit>
- pip-audit: <https://github.com/pypa/pip-audit>
- govulncheck: <https://go.dev/doc/security/vuln/>
- OWASP Software Component Verification Standard (SCVS): <https://owasp.org/www-project-software-component-verification-standard/>
- SLSA supply chain framework: <https://slsa.dev/>

### Related Modules in This Repository

- [Module 03: Git, GitHub and Secret Security](../03-git-github-and-secret-security/README.md) for Dependabot basics and protected pipelines.
- [Module 04: Static Application Security Testing](../04-static-application-security-testing-sast/README.md) for analyzing **your** code.
- [Module 06: Dynamic Application Security Testing](../06-dynamic-application-security-testing-dast/README.md) for testing the running application.
- [Module 07: Docker and Container Security](../07-docker-and-container-security/README.md) for image SBOMs, Trivy, and signing SBOMs with Cosign.

> [!NOTE]
> Tool versions, file names, command-line options, GitHub features, and regulations change over time. Before relying on a command in this module, check the official documentation above.

---

## 16. Module Completion Checklist

Tick each box when you can do it **without looking at the notes**.

### Concepts

- [ ] I can explain SCA and how it differs from SAST and DAST.
- [ ] I can explain why most of an application is third-party code and why that is a risk.
- [ ] I can explain the Log4Shell lesson and why an SBOM would have helped.
- [ ] I can distinguish direct from transitive dependencies and show a dependency tree.
- [ ] I can explain manifests, lock files, PURL, and CPE.
- [ ] I can list supply chain attacks that CVE scanning does not catch, and the controls against them.

### Vulnerability Data

- [ ] I can read a CVE record and name its main fields.
- [ ] I can decode a CVSS vector and explain the score.
- [ ] I can explain why CVSS is not risk, and how EPSS, KEV, exposure, and fix availability change priority.

### Dependency-Check

- [ ] I can obtain an NVD API key and store it safely.
- [ ] I can run Dependency-Check with Docker, keep the database cached, and pin the version.
- [ ] I can read the HTML and JSON reports, including confidence levels.
- [ ] I can use `--failOnCVSS` as a gate and understand its exit codes.
- [ ] I can write a narrow suppression with a reason and an expiry.

### SBOM and Syft

- [ ] I can explain what an SBOM is and is not, and list its minimum elements.
- [ ] I can compare SPDX and CycloneDX and read both.
- [ ] I can generate SBOMs with Syft from a directory and an image.
- [ ] I can search a collection of SBOMs for a component.
- [ ] I can scan an SBOM with Trivy or Grype.
- [ ] I can explain SBOM signing, VEX, and continuous monitoring with Dependency-Track.

### Dependabot and CI/CD

- [ ] I can explain Dependabot alerts, security updates, and version updates.
- [ ] I can write a `dependabot.yml` with grouping, ignores, and cooldowns.
- [ ] I can review a Dependabot pull request safely.
- [ ] I can set up the dependency review check.
- [ ] I can build GitHub Actions and Jenkins pipelines that scan, generate SBOMs, and gate.
- [ ] I run scans on a schedule as well as on each change.

### Remediation

- [ ] I can upgrade a direct dependency and force a safe version of a transitive one.
- [ ] I can choose between upgrade, replace, remove, mitigate, and accept, and justify the choice.
- [ ] I can verify a fix by rescanning and record the decision.

### Labs

- [ ] Lab 1: Explored direct and transitive dependencies
- [ ] Lab 2: Researched a CVE and decoded CVSS
- [ ] Lab 3: Scanned with Dependency-Check
- [ ] Lab 4: Triaged, suppressed, and gated
- [ ] Lab 5: Remediated the vulnerabilities
- [ ] Lab 6: Generated and inspected SBOMs with Syft
- [ ] Lab 7: Scanned the SBOM and compared tools
- [ ] Lab 8: Dependabot and dependency review
- [ ] Lab 9: SCA in GitHub Actions and Jenkins

---

## Summary

In this module, you learned how to manage the risk in the code you **import**:

- **SCA** identifies third-party components and matches them against **known** vulnerabilities. It complements SAST (your code) and DAST (the running app), and it does not catch unknown or **malicious** packages by itself.
- **Transitive dependencies** make up most of what you ship. **Lock files**, pinned versions, private registries, cooldowns, and review of new dependencies reduce supply chain risk.
- **CVE** names a vulnerability, **CVSS** scores its severity, and **EPSS** and **CISA KEV** show how likely or how certain exploitation is. Prioritize by **risk**, not by CVSS alone.
- **Dependency-Check** scans files and libraries with an evidence-based method. Use an **NVD API key**, cache the database, read the **confidence**, gate with `--failOnCVSS`, and handle exceptions with **narrow, expiring suppressions**.
- An **SBOM** is the ingredient list of your software. Produce **CycloneDX and/or SPDX** from the **artifact you ship**, store it per release, sign it, and **rescan it continuously**.
- **Syft** generates SBOMs. **Trivy**, **Grype**, and **Dependency-Track** consume them.
- **Dependabot** provides alerts, security updates, and version updates. Review its pull requests like any other code, and use **dependency review** to stop vulnerable additions.
- **Gates and remediation:** fail on the worst and on known-exploited issues, fix by upgrading, overriding, replacing, or removing, and always **rescan to prove it**. Run scans **daily**, because new CVEs appear after you ship.
- **Pin and verify your security tools too.** They are part of your supply chain.

In the next module, you will move from analyzing code and components to testing the **running application** from the outside with DAST.

---

## Next Module

➡️ [Module 06: Dynamic Application Security Testing (DAST)](../06-dynamic-application-security-testing-dast/README.md)

[⬅️ Previous: Module 04: Static Application Security Testing](../04-static-application-security-testing-sast/README.md) | [🏠 Main README](../README.md)

---

<div align="center">

**Learn. Secure. Automate. Deploy. 🛡️**

</div>
