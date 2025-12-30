# **Module 2: Secure Software Development Lifecycle (SSDLC) and Secure Design**

---

## **1. SDLC vs SSDLC**

### **1.1 Software Development Lifecycle (SDLC)**

The **Software Development Lifecycle (SDLC)** is a structured process followed to design, develop, test, deploy, and maintain software applications.

**Traditional SDLC Phases**

1. Requirements Gathering
2. Design
3. Development
4. Testing
5. Deployment
6. Maintenance

> 🔴 **Limitation:** Security is often treated as a final-phase activity (usually testing), leading to late discovery of vulnerabilities, increased cost, and production risks.

---

### **1.2 Secure Software Development Lifecycle (SSDLC)**

The **Secure SDLC (SSDLC)** integrates **security activities into every phase** of the traditional SDLC.

**Key Idea:**

> *Security is not a phase — it is a continuous process.*

---

### **1.3 SDLC vs SSDLC – Comparison**

| Aspect                  | SDLC                      | SSDLC                |
| ----------------------- | ------------------------- | -------------------- |
| Security Focus          | Post-development          | Built-in from start  |
| Vulnerability Detection | Late (testing/production) | Early and continuous |
| Cost of Fixes           | High                      | Low                  |
| Risk Exposure           | High                      | Minimized            |
| Compliance Readiness    | Reactive                  | Proactive            |

---

### **1.4 Security Activities in Each SSDLC Phase**

| SSDLC Phase  | Security Integration                     |
| ------------ | ---------------------------------------- |
| Requirements | Security requirements, compliance needs  |
| Design       | Threat modeling, secure architecture     |
| Development  | Secure coding, SAST                      |
| Testing      | DAST, penetration testing                |
| Deployment   | Secure configuration, secrets management |
| Maintenance  | Monitoring, patching, incident response  |

---

## **2. Security by Design and Secure by Default**

---

### **2.1 Security by Design**

**Security by Design** means **anticipating threats during design** and building controls into the architecture itself.

**Key Principles**

* Least privilege
* Defense in depth
* Fail securely
* Separation of duties
* Zero Trust assumptions

> Example:
> Designing authentication, authorization, encryption, and logging **before writing code**.

---

### **2.2 Secure by Default**

**Secure by Default** ensures that the system is secure **out of the box**, even if users do not configure anything.

**Characteristics**

* Strong default passwords or forced password change
* Disabled unused services
* Minimal permissions by default
* Enforced encryption

> Example:
> An API denies all requests unless explicitly authorized.

---

### **2.3 Security by Design vs Secure by Default**

| Security by Design           | Secure by Default         |
| ---------------------------- | ------------------------- |
| Architectural principle      | Configuration principle   |
| Focuses on threat prevention | Focuses on safe defaults  |
| Applied during design        | Applied during deployment |

---

## **3. Threat Modeling – Deep Dive**

---

### **3.1 What is Threat Modeling?**

**Threat Modeling** is a **systematic process to identify, analyze, and mitigate potential security threats** in an application **before it is built or deployed**.

**Objectives**

* Identify attack vectors early
* Reduce security risks
* Improve design decisions
* Prioritize security controls

---

### **3.2 Threat Modeling Methodology**

A commonly used methodology consists of **four key steps**:

---

### **Step 1: Diagramming the System**

Create a **high-level architecture diagram** that includes:

* Users
* Application components
* Data stores
* APIs
* External services
* Trust boundaries

> This diagram becomes the foundation for threat identification.

---

### **Step 2: Identifying Threats**

Analyze each component and data flow to identify:

* How an attacker could exploit it
* Where trust assumptions exist
* Where sensitive data is handled

Frameworks like **STRIDE** are commonly used here.

---

### **Step 3: Mitigating Threats**

For each identified threat:

* Define security controls
* Apply preventive, detective, or corrective measures

Examples:

* Input validation
* Authentication & authorization
* Encryption
* Rate limiting
* Logging and monitoring

---

### **Step 4: Validating Threats**

Ensure mitigations are effective through:

* Security testing
* Code reviews
* Penetration testing
* Red team exercises

---

## **4. STRIDE Threat Modeling Framework**

**STRIDE** is a widely used threat classification model developed by Microsoft.

---

### **STRIDE Categories Explained**

| STRIDE | Threat Type            | Description                    | Example                  |
| ------ | ---------------------- | ------------------------------ | ------------------------ |
| **S**  | Spoofing               | Impersonating identity         | Stolen credentials       |
| **T**  | Tampering              | Unauthorized data modification | API request manipulation |
| **R**  | Repudiation            | Denying actions                | No audit logs            |
| **I**  | Information Disclosure | Data leakage                   | Exposed API keys         |
| **D**  | Denial of Service      | Service disruption             | Traffic flooding         |
| **E**  | Elevation of Privilege | Gaining higher access          | User → Admin             |

---

### **STRIDE Mapping to Controls**

| Threat                 | Mitigation                  |
| ---------------------- | --------------------------- |
| Spoofing               | Strong authentication, MFA  |
| Tampering              | Hashing, digital signatures |
| Repudiation            | Logging, audit trails       |
| Information Disclosure | Encryption, access controls |
| Denial of Service      | Rate limiting, WAF          |
| Elevation of Privilege | RBAC, least privilege       |

---

## **5. Defining Security Requirements**

Security requirements define **what must be protected and how**.

### **Types of Security Requirements**

* Authentication (Who are you?)
* Authorization (What can you do?)
* Confidentiality
* Integrity
* Availability
* Compliance (ISO, PCI-DSS, GDPR)

> Example:
> *“All sensitive data must be encrypted at rest and in transit using industry-standard algorithms.”*

---

## **6. Abuse Cases**

### **6.1 What are Abuse Cases?**

**Abuse cases** describe **how a malicious user might misuse a system**.

They are the **inverse of use cases**.

---

### **6.2 Use Case vs Abuse Case**

| Use Case            | Abuse Case           |
| ------------------- | -------------------- |
| Legitimate behavior | Malicious behavior   |
| Focuses on features | Focuses on attacks   |
| User perspective    | Attacker perspective |

---

### **6.3 Example**

**Use Case:**
User logs in and views account details.

**Abuse Case:**
Attacker attempts credential stuffing to gain unauthorized access.

---

### **6.4 Why Abuse Cases Matter**

* Improve threat modeling
* Identify missing security controls
* Strengthen authentication and validation

---

## **7. Introduction to OWASP Top 10**

---

### **7.1 What is OWASP?**

**OWASP (Open Web Application Security Project)** is a non-profit organization that provides **free resources for improving application security**.

---

### **7.2 What is OWASP Top 10?**

The **OWASP Top 10** is a **list of the most critical web application security risks**, updated periodically based on real-world data.

> It is considered the **industry standard reference for application security vulnerabilities**.

---

### **7.3 Why OWASP Top 10 is Important**

* Common language for security teams
* Guides secure coding practices
* Used in audits, compliance, and interviews
* Forms the foundation of security testing

---

### **7.4 OWASP Top 10 (High-Level Categories)**

1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity Failures
9. Security Logging and Monitoring Failures
10. Server-Side Request Forgery (SSRF)

---

### **7.5 Relationship Between SSDLC, Threat Modeling, and OWASP**

| Concept         | Role                    |
| --------------- | ----------------------- |
| SSDLC           | Process                 |
| Threat Modeling | Design-time analysis    |
| OWASP Top 10    | Vulnerability reference |

---

## **8. Key Takeaways**

* SSDLC embeds security into every development phase
* Security by Design prevents vulnerabilities at architecture level
* Threat modeling identifies risks before attackers do
* STRIDE provides a structured way to think like an attacker
* Abuse cases expose real-world attack scenarios
* OWASP Top 10 acts as a practical security checklist

---
