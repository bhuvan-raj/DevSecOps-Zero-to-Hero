# Module 01: DevSecOps Fundamentals 🛡️

## Overview

This module introduces the fundamental principles of DevSecOps and explains how security can be integrated into every stage of the software development lifecycle.

> [!NOTE]
> This module is designed for learners who have already completed DevOps fundamentals and understand Linux, Git, GitHub, Docker, Kubernetes, Terraform, Jenkins, and GitHub Actions.

## 🎯 Learning Objectives

By completing this module, you will be able to:

- Understand DevSecOps and its importance.
- Differentiate DevOps from DevSecOps.
- Understand the Secure Software Development Life Cycle (SSDLC).
- Apply shift-left security principles.
- Understand common application security risks.
- Identify different security testing approaches.
- Understand how security gates work in CI/CD pipelines.
- Design a basic DevSecOps workflow.

## 📚 Table of Contents

- [01. What Is DevSecOps?](#01-what-is-devsecops)
- [02. DevOps vs. DevSecOps](#02-devops-vs-devsecops)
- [03. Why Is DevSecOps Needed?](#03-why-is-devsecops-needed)
- [04. DevSecOps Lifecycle](#04-devsecops-lifecycle)
- [05. Shift-Left Security](#05-shift-left-security)
- [06. Secure Software Development Life Cycle](#06-secure-software-development-life-cycle)
- [07. Security Testing Fundamentals](#07-security-testing-fundamentals)
- [08. OWASP Top 10 Overview](#08-owasp-top-10-overview)
- [09. Security Gates in CI/CD](#09-security-gates-in-cicd)
- [10. Threat Modeling Fundamentals](#10-threat-modeling-fundamentals)
- [11. DevSecOps Best Practices](#11-devsecops-best-practices)
- [12. Hands-On Labs](#12-hands-on-labs)
- [13. Knowledge Check](#13-knowledge-check)
- [14. Summary](#14-summary)

---

## 01. What Is DevSecOps?

DevSecOps stands for **Development, Security, and Operations**.

It is an approach that integrates security practices into the software development and delivery process rather than treating security as a separate activity performed only before release.

In traditional workflows, security testing may happen near the end of development. DevSecOps encourages teams to identify and fix vulnerabilities throughout the development lifecycle.

### Example

Consider a developer building an application.

**Without DevSecOps:**

1. The developer writes the application.
2. The application is built and deployed.
3. Security testing happens near the end.
4. Vulnerabilities are discovered late.
5. The team must fix issues and potentially delay the release.

**With DevSecOps:**

1. The developer writes the application.
2. Source code is automatically scanned.
3. Dependencies are checked for vulnerabilities.
4. The container image is scanned.
5. Infrastructure configurations are checked.
6. Security policies are enforced before deployment.
7. The deployed application is monitored for suspicious activity.

The objective is to make security a continuous part of software delivery.

---

## 02. DevOps vs. DevSecOps

| DevOps | DevSecOps |
| :--- | :--- |
| Focuses on collaboration, automation, and rapid delivery. | Integrates security into automated delivery. |
| Uses CI/CD pipelines to build, test, and deploy applications. | Adds automated security checks to CI/CD pipelines. |
| Builds and deploys container images. | Scans, hardens, and verifies container images. |
| Provisions infrastructure using IaC. | Scans IaC for insecure configurations before deployment. |
| Monitors application health and availability. | Also monitors security events and suspicious activity. |
| Security may be handled in a separate process. | Security is a shared responsibility across teams. |

> [!IMPORTANT]
> DevSecOps does not replace DevOps. It extends existing DevOps workflows with security controls.

---

## 03. Why Is DevSecOps Needed?

Modern applications rely on source code, third-party libraries, container images, cloud infrastructure, CI/CD pipelines, and external services. Each component can introduce security risks.

Common risks include:

- Hardcoded credentials in Git repositories.
- Vulnerable third-party dependencies.
- Insecure application code.
- Vulnerable container images.
- Publicly exposed cloud resources.
- Excessive permissions in CI/CD pipelines.
- Insecure Kubernetes workloads.
- Compromised software build artifacts.
- Unnoticed suspicious activity in production.

DevSecOps helps organizations detect and remediate these risks earlier and enforce consistent security policies.

### Benefits

- Earlier vulnerability detection.
- Reduced remediation costs.
- More secure releases.
- Consistent security enforcement.
- Improved visibility into security risks.
- Better protection of software supply chains.
- Repeatable and auditable security processes.

---

## 04. DevSecOps Lifecycle

Security activities should be integrated into every stage of software delivery.

| Stage | Security Activity |
| :--- | :--- |
| **Plan** | Define security requirements and identify threats. |
| **Code** | Follow secure coding practices and detect leaked secrets. |
| **Build** | Perform static analysis and dependency scanning. |
| **Test** | Perform application security testing. |
| **Package** | Scan images, generate SBOMs, and sign artifacts. |
| **Release** | Verify security policies and approve releases. |
| **Deploy** | Enforce infrastructure and Kubernetes security policies. |
| **Operate** | Monitor security events and investigate incidents. |

### Example Workflow

```text
Developer
    |
    v
GitHub Repository
    |
    v
Secret Scanning
    |
    v
SAST + Dependency Scanning
    |
    v
Build Application
    |
    v
Build Container Image
    |
    v
Image Vulnerability Scanning
    |
    v
Generate SBOM and Sign Image
    |
    v
Terraform Security Checks
    |
    v
Security Approval
    |
    v
Deploy to Kubernetes
    |
    v
Runtime Security Monitoring
```

A pipeline can stop when a defined security policy fails. Not every finding must block every build; the policy should consider severity, exploitability, and risk.

---

## 05. Shift-Left Security

Shift-left security means moving security activities earlier in the software development lifecycle.

The idea is to detect vulnerabilities when they are easier and less expensive to fix.

### Example

Suppose a developer accidentally adds an API key to a source code file.

Without automated checks, the key might be committed, built into an artifact, and deployed before anyone notices.

With shift-left security, a secret scanner checks the code during development or pull request validation and prevents the change from being merged when the configured policy fails.

### Common Shift-Left Practices

- Secret scanning during code review.
- Static application security testing.
- Dependency vulnerability scanning.
- Infrastructure as Code scanning.
- Container image scanning before deployment.
- Security checks in pull requests.

> [!TIP]
> **Key takeaway:** Shift-left does not mean security should happen only at the beginning. Security must continue throughout the lifecycle, including production monitoring.

---

## 06. Secure Software Development Life Cycle

The Secure Software Development Life Cycle (SSDLC) incorporates security requirements into every development phase.

### 1. Requirements

- Identify security and privacy requirements.
- Define authentication and authorization requirements.
- Establish security acceptance criteria.

### 2. Design

- Identify trust boundaries.
- Model potential threats.
- Define secure architecture and data flows.

### 3. Development

- Follow secure coding standards.
- Avoid hardcoded credentials.
- Validate input and handle errors safely.

### 4. Testing

- Run static and dynamic security testing.
- Scan third-party dependencies.
- Verify security controls.

### 5. Deployment

- Scan container images and infrastructure configurations.
- Enforce deployment policies.
- Use least-privilege identities and secure secrets.

### 6. Maintenance

- Monitor vulnerabilities and security events.
- Apply patches.
- Investigate incidents and improve controls.

---

## 07. Security Testing Fundamentals

DevSecOps uses multiple testing approaches because each detects a different category of risk.

### SAST: Static Application Security Testing

Analyzes source code or compiled representations without running the application.

**Example:** Detecting insecure code patterns before an application is deployed.

**Tool used in this repository:** `SonarQube`

### SCA: Software Composition Analysis

Identifies vulnerable third-party libraries and dependencies.

**Example:** Detecting a known vulnerability in a dependency used by an application.

**Tool used in this repository:** `OWASP Dependency-Check`

### DAST: Dynamic Application Security Testing

Tests a running application to identify security weaknesses.

**Example:** Testing a web application for exploitable injection vulnerabilities.

**Tool used in this repository:** `OWASP ZAP`

### Secret Scanning

Detects credentials, API keys, tokens, and other sensitive values exposed in code or Git history.

**Tool used in this repository:** `Gitleaks`

### Container Security Scanning

Identifies known vulnerabilities in container images and their operating-system packages or supported dependencies.

**Tool used in this repository:** `Trivy`

### Infrastructure as Code Scanning

Checks infrastructure configurations for security misconfigurations before deployment.

**Tool used in this repository:** `Checkov`

### SBOM: Software Bill of Materials

An SBOM is an inventory of software components and dependencies included in a software artifact.

**Tool used in this repository:** `Syft`

### Image Signing

Image signing helps verify the integrity and authenticity of container artifacts.

**Tool used in this repository:** `Cosign`

### Kubernetes Policy Enforcement

Enforces security rules on Kubernetes resources before they are admitted to a cluster.

**Tool used in this repository:** `Kyverno`

### Runtime Threat Detection

Detects suspicious behavior while workloads are running.

**Tool used in this repository:** `Falco`

> [!NOTE]
> These approaches complement each other; no single scanner can detect every security issue.

---

## 08. OWASP Top 10 Overview

The OWASP Top 10 is a widely used awareness resource for major web application security risks.

Common categories include:

- Broken Access Control.
- Cryptographic Failures.
- Injection.
- Insecure Design.
- Security Misconfiguration.
- Vulnerable and Outdated Components.
- Identification and Authentication Failures.
- Software and Data Integrity Failures.
- Security Logging and Monitoring Failures.
- Server-Side Request Forgery (SSRF).

The exact categories and ordering can change between editions. Use the current official OWASP Top 10 resource when teaching the latest version.

**Reference:** [OWASP Top 10](https://owasp.org/www-project-top-ten/)

---

## 09. Security Gates in CI/CD

A security gate is a policy-based checkpoint that determines whether a pipeline can proceed.

### Example

Consider a pipeline with the following checks:

| Pipeline Stage | Security Check | Example Policy |
| :--- | :--- | :--- |
| Source | Gitleaks | Block new commits containing confirmed secrets. |
| Code analysis | SonarQube | Fail if the configured security quality gate fails. |
| Dependencies | OWASP Dependency-Check | Block release when defined vulnerability thresholds are exceeded. |
| Container image | Trivy | Reject images that violate the configured vulnerability policy. |
| SBOM | Syft | Generate and retain a software component inventory. |
| Image verification | Cosign | Verify signatures before accepting an image. |
| Infrastructure | Checkov | Reject Terraform changes that violate required policies. |
| Kubernetes | Kyverno | Reject resources that violate admission policies. |

> [!IMPORTANT]
> Security gates must be configured explicitly. Installing a tool alone does not automatically enforce a release policy.

### Important Considerations

- Define severity thresholds.
- Avoid exposing secrets in scan logs.
- Publish and retain scan reports.
- Document exceptions and their expiration dates.
- Assign responsibility for remediation.
- Re-evaluate policies as risks change.

---

## 10. Threat Modeling Fundamentals

Threat modeling is a structured process for identifying potential threats to a system before they become incidents.

### Basic Steps

1. Identify the system and its assets.
2. Map components, data flows, and trust boundaries.
3. Identify potential threats.
4. Assess impact and likelihood.
5. Select appropriate security controls.
6. Validate the controls and revisit the model when the system changes.

### STRIDE Threat Model

| Threat | Meaning | Example |
| :--- | :--- | :--- |
| **S**poofing | Pretending to be another identity. | Using stolen credentials. |
| **T**ampering | Unauthorized modification of data. | Altering a build artifact. |
| **R**epudiation | Denying an action without sufficient evidence to establish accountability. | Missing audit records for a deployment. |
| **I**nformation Disclosure | Exposing sensitive information. | Leaking an API key in logs. |
| **D**enial of Service | Making a service unavailable. | Overloading an application endpoint. |
| **E**levation of Privilege | Gaining permissions beyond those authorized. | A compromised workload obtaining cluster-admin access. |

### Practical Example: CI/CD Pipeline

Potential threats include:

- A leaked deployment credential.
- A malicious dependency entering the build.
- An untrusted pull request executing privileged pipeline code.
- A compromised image being deployed to production.

Possible controls include secret scanning, dependency checks, isolated builds, least-privilege permissions, image signing, and deployment verification.

---

## 11. DevSecOps Best Practices

- Apply least privilege to users, applications, and automation.
- Never commit credentials or private keys to Git.
- Scan source code, dependencies, images, and infrastructure.
- Pin and verify trusted build dependencies where appropriate.
- Use short-lived credentials instead of long-lived cloud access keys.
- Enforce security policies through automated gates.
- Generate SBOMs for relevant software artifacts.
- Sign and verify container images.
- Restrict Kubernetes workload privileges.
- Monitor security events and maintain audit trails.
- Patch vulnerable dependencies and infrastructure components.
- Document accepted risks and time-bound exceptions.
- Test security controls regularly.

---

## 12. Hands-On Labs

Complete these introductory labs before moving to the next module.

### Lab 1: Identify Security Risks

**Objective:** Understand common security weaknesses in a DevOps workflow.

**Tasks:**

1. Review a sample application repository.
2. Identify hardcoded credentials and insecure configuration.
3. Identify third-party dependencies.
4. Review the container build process.
5. List potential security risks and suitable controls.

**Expected outcome:** A short threat and risk assessment.

### Lab 2: Understand Security Scanning

**Objective:** Understand how security tools fit into a delivery pipeline.

**Tasks:**

1. Identify which stages should perform secret scanning, SAST, SCA, DAST, image scanning, and IaC scanning.
2. Select the appropriate tool from this repository's approved toolset.
3. Define which findings should block a build or release.
4. Document the remediation process.

**Expected outcome:** A basic security testing plan.

### Lab 3: Design a DevSecOps Pipeline

**Objective:** Design a secure pipeline using familiar DevOps tools.

**Tasks:**

1. Start with a GitHub repository.
2. Define the CI/CD stages.
3. Place security checks at appropriate stages.
4. Define security gates and failure conditions.
5. Identify how artifacts are verified before deployment.
6. Plan monitoring and incident response.

**Expected outcome:** A pipeline diagram and a written security policy.

---

## 13. Knowledge Check

1. What is DevSecOps, and how does it extend DevOps?
2. What is shift-left security?
3. What is the difference between SAST, DAST, and SCA?
4. Why should secrets be scanned before code is merged?
5. What is an SBOM, and why is it useful?
6. What is the purpose of a security gate?
7. Why is image signing different from vulnerability scanning?
8. What is the difference between a security misconfiguration and a known software vulnerability?
9. How does threat modeling help identify security risks?
10. Why must security monitoring continue after deployment?

---

## 14. Summary

In this module, you learned the foundational principles of DevSecOps, the importance of shift-left security, the SSDLC, common security testing methods, threat modeling, and automated security gates.

You are now ready to explore the tools and implementation techniques in the upcoming modules.

---

## Next Module

➡️ [Module 02: Linux Security](../02-linux-security/README.md)

[⬅️ Back to main README](../README.md)

---

<div align="center">

**Learn. Secure. Automate. Deploy. 🛡️**

</div>
