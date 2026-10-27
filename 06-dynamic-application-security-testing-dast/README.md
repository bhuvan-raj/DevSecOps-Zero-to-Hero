# Module 06: Dynamic Application Security Testing (DAST) 🌐

## 📌 Overview

Dynamic Application Security Testing (DAST) is a security testing technique that analyzes a **running application** to identify vulnerabilities by interacting with it **from the outside**.

Unlike Static Application Security Testing (SAST), which examines source code, DAST tests an application **while it is running**.

In this module, you will learn how to perform DAST using **OWASP ZAP**, identify common web application vulnerabilities, understand scan results, and integrate security testing into CI/CD pipelines.

> [!IMPORTANT]
> **Perform security scans only against applications you own or have explicit permission to test.** Use a local lab application for hands-on exercises. Scanning systems without permission can be **illegal**, can cause outages, and can get your accounts and networks blocked.

> [!NOTE]
> **Lab environment:** You need **Docker** and a terminal. A web browser is needed for some labs, and the optional ZAP desktop application is useful but not required. Every lab target in this module runs **on your own machine**, bound to `127.0.0.1` or to a private Docker network, so nothing vulnerable is exposed to other people.

## 🎯 Learning Objectives

By the end of this module, you will be able to:

- Understand DAST and how it differs from SAST and SCA.
- Understand the basics of HTTP, HTTPS, requests, and responses.
- Learn common web application vulnerabilities.
- Understand the OWASP Top 10.
- Install and configure OWASP ZAP.
- Perform passive and active security scans.
- Understand crawling and application discovery.
- Identify and analyze security findings.
- Generate DAST reports.
- Integrate OWASP ZAP into GitHub Actions and Jenkins.
- Configure security gates for web application testing.

## 📚 Table of Contents

1. [What Is DAST?](#1-what-is-dast)
2. [DAST vs. SAST vs. SCA](#2-dast-vs-sast-vs-sca)
3. [Understanding HTTP and HTTPS](#3-understanding-http-and-https)
4. [Common Web Application Vulnerabilities](#4-common-web-application-vulnerabilities)
5. [Introduction to OWASP ZAP](#5-introduction-to-owasp-zap)
6. [Installing OWASP ZAP](#6-installing-owasp-zap)
7. [Understanding Passive and Active Scanning](#7-understanding-passive-and-active-scanning)
8. [Spidering and Application Discovery](#8-spidering-and-application-discovery)
9. [Performing a DAST Scan](#9-performing-a-dast-scan)
10. [Understanding ZAP Reports](#10-understanding-zap-reports)
11. [DAST Integration with GitHub Actions](#11-dast-integration-with-github-actions)
12. [DAST Integration with Jenkins](#12-dast-integration-with-jenkins)
13. [Security Gates and Remediation](#13-security-gates-and-remediation)
14. [Hands-On Labs](#14-hands-on-labs)
15. [Best Practices](#15-best-practices)
16. [Knowledge Check](#16-knowledge-check)
17. [Official References](#17-official-references)
18. [Module Completion Checklist](#18-module-completion-checklist)

---

## 1. What Is DAST?

### The Idea

**Dynamic Application Security Testing (DAST)** tests an application the way an **outside attacker** would: it sends requests to the running application, studies the responses, and looks for signs of weakness. It does **not** need the source code, so it is called a **black-box** test.

> **Analogy:** Imagine a bank wants to know if its building is secure.
> - **SAST** reads the **architect's blueprints** and looks for design mistakes.
> - **DAST** hires someone to **walk around the finished building** trying every door, window, and lock to see which ones open.
>
> The tester does not need the blueprints. They only need to reach the building.

### How DAST Works

```text
1. DISCOVER      The scanner explores the application (follows links, reads pages)
        |        to build a map of every page, form, and parameter it can find
        v
2. TEST          For each input, it sends many requests:
        |          - harmless requests to observe normal behavior (passive)
        |          - crafted requests that imitate attacks (active)
        v
3. ANALYZE       It examines every response for signs of trouble:
        |          error messages, reflected input, missing protections, odd timing
        v
4. REPORT        It lists each finding with the URL, the request that triggered it,
                 the risk level, and advice on how to fix it
```

### What You Need to Run DAST

| Requirement | Why |
| :--- | :--- |
| A **running** application | DAST cannot test code that is not executing. |
| A **URL** (the target) | This is the starting point for discovery. |
| **Permission** to test | Always. See the rules of engagement below. |
| A **test environment** | Active scans change data and add load, so avoid production. |
| (Optional) **Test credentials** | Needed to test pages behind a login. |

### What DAST Finds Well and What It Misses

| ✅ Finds Well | ⚠️ Finds Poorly or Not at All |
| :--- | :--- |
| Missing security headers (CSP, HSTS, and so on) | Flaws in code that is never reached by the scanner |
| Insecure cookie settings | **Business logic** flaws ("a customer can apply the same coupon 100 times") |
| Injection that works at runtime (SQL injection, XSS) | Hardcoded secrets in source code (use Module 03 and Module 04) |
| Server and TLS misconfiguration | Vulnerable dependencies that are not visible from outside (use Module 05) |
| Exposed files, error messages, and information leaks | Complex multi-step workflows (checkout, approvals) without scripting |
| Problems that only appear in the **deployed** environment | The **exact line of code** to fix (DAST shows the URL, not the file) |

### Benefits and Limitations

| Benefits | Limitations |
| :--- | :--- |
| Finds **real, exploitable** problems in the running system | Needs a deployed, working application, so it runs **later** in the pipeline |
| Works with **any language or framework** | Slower than SAST |
| Tests the **real configuration** (servers, headers, TLS) | Cannot point to the source line |
| Few false positives for confirmed attacks | Coverage depends on what the scanner can **discover** |
| Mimics a real attacker's view | Active scanning can be intrusive |

### DAST vs. Penetration Testing

| | **DAST (automated)** | **Penetration test (manual)** |
| :--- | :--- | :--- |
| **Performed by** | A tool | A skilled human (often using tools) |
| **Strength** | Fast, repeatable, **broad** coverage on every build | **Deep**, creative, finds logic flaws and chained attacks |
| **Frequency** | Every build or nightly | Periodically (for example yearly or before major releases) |
| **Cost** | Low per run | Higher |

They complement each other. DAST catches the common problems continuously. Pen testers find what automation cannot.

### Rules of Engagement: Test Safely and Legally

> [!WARNING]
> **Before running any scan, answer "yes" to every line below.**

| ✔ | Question |
| :---: | :--- |
| ☐ | Do I **own** this application, or do I have **written permission** from the owner? |
| ☐ | Do I know exactly which **URLs and hosts are in scope**? |
| ☐ | Is this a **test or staging** environment, not production? |
| ☐ | Does the environment contain only **fake or test data**? |
| ☐ | Have I told the **team** (operations, security, anyone monitoring alerts) when the scan runs? |
| ☐ | Do I have a **backup or a way to reset** the environment? |
| ☐ | Am I scanning from a machine I am **allowed to use**? |

Active scanning can **create junk records, lock accounts, send emails, fill disks, and slow or crash** an application. Treat it like a stress test with attack traffic.

### Where DAST Fits in the Pipeline

```text
Code --> Build --> SAST + SCA + Secret scan --> Package --> DEPLOY TO TEST --> DAST --> Gate --> Promote
 (M03)    (M04, M05, M03 run here)                          environment      (this module)
```

---

## 2. DAST vs. SAST vs. SCA

You met SAST in Module 04 and SCA in Module 05. Here they are side by side.

> **Analogy (building a house):**
> - **SAST** proofreads the **blueprints** (your source code).
> - **SCA** checks the **labels on purchased materials** (third-party libraries) for recalls.
> - **DAST** tries to **break into the finished house** (the running application).

| | **SAST** | **SCA** | **DAST** |
| :--- | :--- | :--- | :--- |
| **Examines** | Your source code | Third-party libraries | The running application |
| **Needs a running app?** | No | No | **Yes** |
| **Perspective** | Inside (white-box) | Inside (dependency list) | **Outside (black-box)** |
| **Typical findings** | SQL injection pattern, hardcoded password, weak crypto | Known vulnerable library versions (CVEs) | Missing headers, runtime injection, exposed files, insecure cookies, TLS issues |
| **Points to** | File and line | Package and version | URL, parameter, and request |
| **When it runs** | Early (IDE, pull request, build) | Early (build) | Later (deployed test environment) |
| **Speed** | Fast | Fast | Slower |
| **Tools in this course** | SonarQube (Module 04) | Dependency-Check, Syft (Module 05) | **OWASP ZAP (this module)** |

### One Vulnerability, Three Views

Imagine an endpoint `/user?name=...` that is vulnerable to SQL injection:

- **SAST** highlights the **line of code** that joins user input into a query.
- **DAST** sends a crafted request and shows that the app **actually returns data it should not**. This is proof of exploitability.
- **SCA** would not notice it at all, because the flaw is in **your** code, not a library.

### Who Catches What?

| Problem | Secret Scan (M03) | SAST (M04) | SCA (M05) | DAST (M06) |
| :--- | :---: | :---: | :---: | :---: |
| Hardcoded password in code | ✅ | ✅ | ❌ | ❌ |
| SQL injection in your code | ❌ | ✅ | ❌ | ✅ |
| Vulnerable third-party library | ❌ | ❌ | ✅ | ⚠️ (only some client-side libraries) |
| Missing `Content-Security-Policy` header | ❌ | ❌ | ❌ | ✅ |
| Cookie without `HttpOnly` flag | ❌ | ⚠️ | ❌ | ✅ |
| Weak TLS configuration | ❌ | ❌ | ❌ | ✅ |
| Verbose error page in production | ❌ | ⚠️ | ❌ | ✅ |
| Business logic flaw | ❌ | ❌ | ❌ | ❌ (needs a human) |

**Lesson:** no single tool covers everything. A good pipeline uses all of them.

---

## 3. Understanding HTTP and HTTPS

DAST tools work by **crafting and changing HTTP requests**. To understand what ZAP is doing (and what it reports), you need to understand HTTP.

### The Client-Server Model

```text
 BROWSER (client)                                   WEB SERVER
+----------------+     1. REQUEST  ("give me /login")      +----------------+
|                | ---------------------------------------> |                |
|                |                                          |  Application   |
|                | <--------------------------------------- |  and database  |
+----------------+     2. RESPONSE ("here is the page")     +----------------+
```

### Anatomy of a URL

```text
https://shop.example.com:443/products/search?q=apple&sort=price#reviews
\___/   \______________/ \_/ \______________/ \________________/ \_____/
scheme       host        port      path           query string    fragment
```

| Part | Meaning | Why It Matters for Security |
| :--- | :--- | :--- |
| **Scheme** | `http` or `https` | HTTPS encrypts traffic. HTTP does not. |
| **Host / port** | Which server and service | The scope of what you are allowed to scan. |
| **Path** | Which page or resource | Scanners try to discover hidden paths. |
| **Query string** | Parameters (`q=apple`) | **User-controlled input**, a common injection point. |
| **Fragment** | Browser-only, never sent to the server | Used by some client-side attacks (DOM-based XSS). |

### Anatomy of an HTTP Request

```http
POST /login HTTP/1.1                       <-- request line: METHOD  PATH  VERSION
Host: shop.example.com                     <-- headers (name: value)
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded
Cookie: session=abc123
Content-Length: 31
                                           <-- blank line, then the BODY
username=alice&password=secret
```

### Anatomy of an HTTP Response

```http
HTTP/1.1 200 OK                            <-- status line: VERSION  CODE  REASON
Content-Type: text/html; charset=utf-8     <-- headers
Set-Cookie: session=xyz789; HttpOnly; Secure; SameSite=Lax
Content-Security-Policy: default-src 'self'
Server: nginx
                                           <-- blank line, then the BODY
<html> ... the web page ... </html>
```

> **Key insight for DAST:** Every part of a request, including the **URL path, query parameters, body fields, headers, and cookies**, is an **input** that an attacker controls. ZAP changes these inputs and watches how the responses change.

### HTTP Methods

| Method | Purpose | Security Note |
| :--- | :--- | :--- |
| `GET` | Read a resource | Parameters appear in URLs and logs, so never put secrets in them. |
| `POST` | Create or submit data | Needs protection against CSRF. |
| `PUT` / `PATCH` | Replace or update | Must check authorization. |
| `DELETE` | Remove a resource | Must check authorization. |
| `OPTIONS` | Ask what is allowed | Used by browsers for CORS checks. |
| `HEAD` | Like GET but headers only | Handy for quick checks. |

### Status Codes

| Range | Meaning | Common Examples |
| :---: | :--- | :--- |
| **1xx** | Informational | `101 Switching Protocols` |
| **2xx** | Success | `200 OK`, `201 Created`, `204 No Content` |
| **3xx** | Redirect | `301 Moved Permanently`, `302 Found` |
| **4xx** | **Client** error | `400 Bad Request`, `401 Unauthorized` (not logged in), `403 Forbidden` (not allowed), `404 Not Found` |
| **5xx** | **Server** error | `500 Internal Server Error`. A 500 after odd input can hint at a bug or injection. |

### Cookies and Sessions

HTTP has no memory. To remember that you are logged in, the server gives your browser a **session cookie**, and the browser sends it with every later request.

```text
1. You log in.
2. Server replies:   Set-Cookie: session=xyz789
3. Browser sends:    Cookie: session=xyz789   (on every following request)
4. Server thinks:    "This is the logged-in user"
```

**Anyone who steals the session cookie can act as you.** So cookies need protective flags:

| Flag | What It Does | Attack It Reduces |
| :--- | :--- | :--- |
| `HttpOnly` | JavaScript cannot read the cookie | Cookie theft through XSS |
| `Secure` | Sent only over HTTPS | Sniffing on the network |
| `SameSite=Lax` or `Strict` | Not sent on most cross-site requests | CSRF |

### Important Security Headers

| Header | Example | Purpose | Risk if Missing |
| :--- | :--- | :--- | :--- |
| `Content-Security-Policy` | `default-src 'self'` | Controls what scripts and resources may load | Easier XSS |
| `Strict-Transport-Security` (HSTS) | `max-age=31536000; includeSubDomains` | Forces browsers to use HTTPS | Downgrade and interception attacks |
| `X-Content-Type-Options` | `nosniff` | Stops browsers guessing content types | Content-type confusion |
| `X-Frame-Options` or CSP `frame-ancestors` | `DENY` | Stops other sites embedding your page | **Clickjacking** |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limits URL leakage to other sites | Information leakage |
| `Permissions-Policy` | `geolocation=(), camera=()` | Disables browser features you do not use | Feature abuse |
| `Cache-Control` | `no-store` | Prevents caching of sensitive pages | Data left in caches |

### HTTP vs. HTTPS

**HTTPS is HTTP wrapped in TLS** (Transport Layer Security). TLS provides three things:

| Property | Meaning |
| :--- | :--- |
| **Confidentiality** | Traffic is encrypted, so eavesdroppers see gibberish. |
| **Integrity** | Traffic cannot be changed in transit without detection. |
| **Authentication** | A certificate proves you are talking to the real server. |

```text
        HTTP (no TLS)                              HTTPS (TLS)

 Browser ---- "password=secret" ---> Server     Browser ---- "x9#Qz@..." ---> Server
              anyone on the path can read                     only the server can read
```

Simplified TLS connection:

```text
1. Browser connects and says which TLS versions it supports
2. Server sends its CERTIFICATE (identity, signed by a trusted authority)
3. Browser checks the certificate (valid date, right name, trusted signer)
4. Both sides agree on secret keys
5. All further traffic is encrypted with those keys
```

Related ideas DAST checks:

| Concept | Meaning |
| :--- | :--- |
| **HSTS** | A header that tells browsers "always use HTTPS for this site". |
| **Mixed content** | An HTTPS page loading some resources over HTTP, which weakens protection. |
| **Redirect HTTP to HTTPS** | Plain HTTP requests should be redirected to the secure version. |
| **Certificate problems** | Expired, self-signed, or wrongly named certificates. |

### See HTTP With Your Own Eyes

`curl` shows raw requests and responses. Try it once your lab application is running (Lab 1):

```bash
curl -i  http://localhost:3000/                  # response headers AND body
curl -I  http://localhost:3000/                  # headers only (HEAD request)
curl -v  http://localhost:3000/ 2>&1 | head -30  # also shows the request that was sent
```

You can do the same in a browser: press **F12**, open the **Network** tab, and click any request.

### How ZAP Fits In: The Intercepting Proxy

ZAP can act as a **proxy**: a "man in the middle" that you control, sitting between your browser and the application.

```text
 BROWSER  <--->  ZAP (proxy, port 8080)  <--->  TARGET APPLICATION
                      |
            sees, records, and can modify
            every request and response
```

This is how ZAP learns about your application while you click around (**manual explore**), and how it can resend modified requests as attacks. For HTTPS, ZAP generates its own certificate, which you must **explicitly trust** in your test browser (section 9).

---

## 4. Common Web Application Vulnerabilities

### The OWASP Top 10

The **OWASP Top 10** is a widely used list of the most critical web application security risks. Each category is a **family** of weaknesses. The list changes between editions, so check the current version at owasp.org. The names below are the **2021** edition.

| # | Category | In Plain Words | Can DAST Find It? |
| :---: | :--- | :--- | :---: |
| **A01** | Broken Access Control | Users can do or see things they should not (for example, open another user's data by changing an ID). | ⚠️ Partly. Needs test users and context. |
| **A02** | Cryptographic Failures | Sensitive data sent or stored without proper protection (no HTTPS, weak TLS). | ✅ Transport issues. ❌ Storage issues. |
| **A03** | Injection | Untrusted input is run as code or commands (SQL injection, XSS, command injection). | ✅ Strong area for active scans |
| **A04** | Insecure Design | Weaknesses in the design itself, not just the code. | ❌ Needs threat modeling (Module 01) |
| **A05** | Security Misconfiguration | Default settings, verbose errors, missing headers, open directories. | ✅ Strong area |
| **A06** | Vulnerable and Outdated Components | Using libraries or servers with known flaws. | ⚠️ Some (outdated client-side libraries, server banners). Use SCA. |
| **A07** | Identification and Authentication Failures | Weak login, session handling, or password rules. | ⚠️ Cookie and session checks |
| **A08** | Software and Data Integrity Failures | Unverified updates, insecure deserialization, untrusted pipelines. | ❌ Mostly no |
| **A09** | Security Logging and Monitoring Failures | Attacks go unnoticed because nothing is logged or alerted. | ❌ Not visible from outside |
| **A10** | Server-Side Request Forgery (SSRF) | The server can be tricked into calling internal or unintended URLs. | ⚠️ With out-of-band techniques |

### Injection: SQL Injection

**What:** The application builds a database query from user input without protection.

```text
Normal request:   /search?name=alice
Query built:      SELECT * FROM users WHERE name = 'alice'

Attack input:     alice' OR '1'='1
Query built:      SELECT * FROM users WHERE name = 'alice' OR '1'='1'    <-- returns EVERY user
```

**How DAST finds it:** ZAP sends special characters (such as a single quote) and variations, then looks for **database error messages**, **changed results**, or **timing differences** that show the input reached the query.

**Fix:** use **parameterized queries**, validate input, and give the database account minimal privileges. (Module 04, section 3.1.)

### Injection: Cross-Site Scripting (XSS)

**What:** The application includes user input in a page without escaping it, so the browser runs attacker-supplied script in the victim's session.

| Type | How It Works |
| :--- | :--- |
| **Reflected** | The input comes back immediately in the response (for example, a search term shown on the results page). |
| **Stored** | The input is saved (for example, in a comment) and shown to **every** visitor. |
| **DOM-based** | Client-side JavaScript writes unsafe data into the page. |

**How DAST finds it:** ZAP submits a harmless marker string in every input and checks whether it **comes back unescaped** in the response in a place where script could run.

**Fix:** encode output for its context, use auto-escaping templates, and set a strong `Content-Security-Policy`.

### Broken Access Control and IDOR

**What:** The server does not check **who is allowed** to see or change a resource. A classic form is **IDOR** (Insecure Direct Object Reference):

```text
You are user 1001 and view your invoice:   /invoices/1001
You change the number in the URL:          /invoices/1002     <-- and see someone else's invoice
```

**How DAST finds it:** Automated scanners find this **poorly**, because they do not know which data belongs to whom. Good testing uses **two test accounts** and checks whether account A can reach account B's data. This is where manual testing shines.

**Fix:** check authorization on the **server** for every request, never trust IDs from the client, and deny by default.

### Broken Authentication and Session Problems

| Problem | Example | What ZAP Reports |
| :--- | :--- | :--- |
| Weak cookie flags | Session cookie without `HttpOnly` or `Secure` | Cookie flag alerts |
| Session in the URL | `?sessionid=abc123` | Session ID in URL rewrite |
| Predictable sessions | Sequential session IDs | Session analysis findings |
| Default credentials | `admin/admin` | Found by dedicated rules or manual checks |
| No lockout or rate limiting | Unlimited login guesses | Usually manual testing |

### Security Misconfiguration

| Problem | Example | Fix |
| :--- | :--- | :--- |
| **Missing security headers** | No CSP, HSTS, or anti-clickjacking header | Add the headers (section 13) |
| **Verbose errors** | Stack traces or SQL errors shown to users | Show generic errors, log details server-side |
| **Directory listing** | `/uploads/` shows all files | Disable listing |
| **Server banners** | `Server: Apache/2.4.29 (Ubuntu)` reveals versions | Hide version details |
| **Default pages** | Sample apps or admin consoles left on | Remove them |
| **Exposed files** | `/.git/`, `/backup.zip`, `/.env` | Remove or block them |
| **Debug mode on** | Interactive debugger reachable | Disable debug in production |

### Cross-Site Request Forgery (CSRF)

**What:** A malicious site makes the victim's browser send a request to your application **using the victim's logged-in session** (for example, "change email").

**How DAST finds it:** ZAP notices **forms with no anti-CSRF token** and reports "Absence of Anti-CSRF Tokens".

**Fix:** use anti-CSRF tokens, `SameSite` cookies, and re-authentication for sensitive actions.

### Other Frequent Findings

| Finding | What It Means | Fix |
| :--- | :--- | :--- |
| **Open redirect** | `/redirect?url=` sends users to any site, making phishing links look legitimate | Allow only known destinations |
| **Path traversal** | `../` in a file parameter reaches files outside the intended folder | Confine file access to a safe directory |
| **SSRF** | The server fetches attacker-chosen URLs | Allow-list destinations, block internal ranges |
| **CORS misconfiguration** | `Access-Control-Allow-Origin: *` on sensitive APIs | Allow only trusted origins |
| **Vulnerable JavaScript library** | An old jQuery version with known flaws | Update the library (SCA, Module 05) |
| **Information disclosure** | Comments with internal URLs, version numbers, email addresses | Remove from production output |
| **Clickjacking** | Your page can be embedded invisibly in another site | `frame-ancestors` or `X-Frame-Options` |
| **Insecure transport** | HTTP used, no HSTS, weak TLS | HTTPS everywhere, HSTS, modern TLS |

### Read Alerts With This Question in Mind

> *Could an attacker use this, and what would they gain?*

A missing `Permissions-Policy` header is low risk. A confirmed SQL injection on a login page is critical. Risk depends on **what is exposed** and **how easy it is to exploit**.

---

## 5. Introduction to OWASP ZAP

### What Is ZAP?

**ZAP** (Zed Attack Proxy) is a free, open-source web application security scanner and testing tool. It began as an OWASP project and is now maintained as **"ZAP by Checkmarx"** while remaining open source, so you will see both "OWASP ZAP" and "ZAP" in documentation and tools. This module uses both names for the same project.

It is popular because it is:

- **Free and open source**, so anyone can use it.
- **Beginner friendly**, with a desktop interface, and **automation friendly**, with Docker images and an API.
- **Extensible**, with an add-on marketplace.
- Used by **both learners and professionals**, from manual testing to CI/CD pipelines.

### Core Components

| Component | What It Does |
| :--- | :--- |
| **Intercepting proxy** | Sits between your browser and the app, recording and optionally modifying traffic. |
| **Passive scanner** | Examines all traffic that flows through ZAP **without changing it**. Safe. |
| **Active scanner** | **Attacks** the application with crafted requests to find vulnerabilities. |
| **Spider** | A crawler that follows links in HTML pages to discover content. |
| **AJAX Spider** | Uses a **real browser** to crawl modern JavaScript applications. |
| **Fuzzer** | Sends many variations of an input to see how the app behaves. |
| **Forced browse** | Guesses common hidden paths (such as `/admin`). |
| **Scripts and add-ons** | Extend ZAP with custom rules and features. |
| **API** | Lets you control ZAP from scripts and pipelines. |
| **Automation Framework** | Runs ZAP from a YAML plan, ideal for CI/CD. |
| **Reports** | Generates HTML, JSON, XML, Markdown, and other reports. |

### How It Works

```text
                          +---------------------------+
   Manual: your browser ->|                           |-> TARGET WEB APPLICATION
                          |            ZAP            |
   Automatic: spiders  -->|  Proxy + Passive Scanner  |<- responses
   and active scans       |  Active Scanner + Spiders |
                          |  Alerts + Reports         |
                          +-------------+-------------+
                                        |
                                        v
                              Alerts, HTML/JSON reports
```

### ZAP Vocabulary

| Term | Meaning |
| :--- | :--- |
| **Alert** | One finding, such as "Content Security Policy (CSP) Header Not Set". |
| **Risk** | How serious the issue is: **High, Medium, Low, Informational**. |
| **Confidence** | How sure ZAP is: **False Positive, Low, Medium, High, User Confirmed**. |
| **Context** | A named group of URLs that defines your **application and scope** (and optionally its login). |
| **Scope** | The set of URLs ZAP is allowed to attack. |
| **Sites tree** | The map of everything ZAP has seen. |
| **Scan policy** | Which active rules run and how aggressively. |
| **Mode** | Safe, Protected, Standard, or ATTACK (below). |
| **Add-on** | A plug-in that adds features or scan rules. |
| **Plugin ID / rule ID** | The number that identifies a scan rule (for example `10038`). |

### ZAP Modes

| Mode | What It Allows | Use When |
| :--- | :--- | :--- |
| **Safe** | No potentially dangerous operations (no active attacks) | Only observing |
| **Protected** | Attacks only on URLs **in scope** | **Recommended default** for careful testing |
| **Standard** | Attacks on anything you choose | Experienced testers |
| **ATTACK** | Actively scans every new node as soon as it is found | Dedicated test environments only |

### The Three Packaged Scans for Automation

ZAP's Docker images include ready-made scripts. These are the easiest way to start.

| Script | What It Does | Attacks the App? | Typical Use |
| :--- | :--- | :---: | :--- |
| **`zap-baseline.py`** | Spiders the site briefly and runs **passive** rules only | **No** | Every pull request or build. Fast and safe. |
| **`zap-full-scan.py`** | Spider **plus an active scan** | **Yes** | Nightly or weekly on a test environment |
| **`zap-api-scan.py`** | Imports an **API definition** (OpenAPI, SOAP, GraphQL) and scans the API | Yes (active) | Testing REST and other APIs |

### Other DAST Tools You May Meet

| Tool | Notes |
| :--- | :--- |
| **Burp Suite** | Very popular commercial and community tool, strong for manual testing. |
| **Nikto** | Quick web server scanner. |
| **Nuclei** | Template-based scanner, fast for known issues. |
| **Wapiti**, **Arachni-style tools** | Other open-source scanners. |

---

## 6. Installing OWASP ZAP

### Choose an Installation Method

| Method | Best For | Notes |
| :--- | :--- | :--- |
| **Docker image** | **Automation, CI/CD, and these labs** | No installation to maintain. Recommended. |
| **Desktop application** | Learning, manual exploring, proxying a browser | Graphical interface. |
| **Package managers** | Quick desktop install | Version may lag behind. |

### Option 1: Docker (Recommended)

ZAP publishes official images. The `stable` tag is the latest release.

```bash
docker pull ghcr.io/zaproxy/zaproxy:stable

# Verify
docker run --rm ghcr.io/zaproxy/zaproxy:stable zap.sh -version
```

| Image Tag | Meaning |
| :--- | :--- |
| `stable` | Latest official release. **Use this for pipelines**, and pin an exact version for reproducible builds. |
| `weekly` | Weekly build with newer rules and fixes. |
| `nightly` | Newest development build. For testing only. |

> [!TIP]
> Older tutorials use `owasp/zap2docker-stable` or `softwaresecurityproject/zap-stable`. These names are outdated. Use **`ghcr.io/zaproxy/zaproxy:stable`**.

### Option 2: Desktop Application

1. Download the installer for your operating system from the official ZAP website (zaproxy.org, **Download** page).
2. Install it:
   - **Windows:** run the `.exe` installer.
   - **macOS:** open the `.dmg` and drag ZAP to Applications, or use Homebrew: `brew install --cask zap`.
   - **Linux:** use the installer script from the website, or a package such as the Flatpak or Snap, depending on your distribution.
3. Start **ZAP**. The installers normally include the Java runtime they need. A generic Linux package needs a recent Java version (recent ZAP releases require Java 17 or newer).
4. On the first start, choose whether to **persist the session** (save your work). For learning, **"No, I do not want to persist this session"** is fine.

### Your First Look at the Desktop Interface

```text
+--------------------------------------------------------------------------------+
| Mode: [Standard v]   toolbar: Spider, Active Scan, Browser, Report ...          |
+--------------------+-----------------------------------------------------------+
| SITES TREE         | WORK AREA                                                 |
| (everything ZAP    | Quick Start tab / Request / Response tabs                 |
|  has discovered)   |                                                           |
+--------------------+-----------------------------------------------------------+
| BOTTOM PANEL: History | Search | Alerts | Output | Spider | Active Scan ...      |
+--------------------------------------------------------------------------------+
```

| Area | Use |
| :--- | :--- |
| **Quick Start tab** | Automated Scan and Manual Explore buttons. |
| **Sites tree** | Browse discovered URLs. Right-click for scan options. |
| **Alerts tab** | Findings, grouped by risk with color flags. |
| **History tab** | Every request and response that passed through ZAP. |

### Security Notes About Your ZAP Installation

- ZAP listens on **localhost port 8080** as a proxy by default. **Do not expose it to the network.**
- When you run ZAP in **daemon mode** with its API, **always use an API key**, and never disable it on a shared machine.
- ZAP generates a **root CA certificate** to inspect HTTPS. Anyone with that certificate's private key can impersonate sites to a browser that trusts it, so use a **separate test browser profile** and **remove the certificate** when you are done.

---

## 7. Understanding Passive and Active Scanning

### The Difference

| | **Passive Scanning** | **Active Scanning** |
| :--- | :--- | :--- |
| **What it does** | **Observes** traffic and responses without changing anything | **Sends attack-like requests** to provoke and detect vulnerabilities |
| **Impact on the app** | None (no extra attack traffic) | Can be heavy: adds load, creates data, may break things |
| **Safe for production?** | Generally yes | **No** |
| **Speed** | Fast | Slow (can take minutes to hours) |
| **Finds** | Missing headers, cookie flags, information leaks, outdated libraries, comments | Injection (SQL, XSS, command), path traversal, SSRF, many server issues |
| **False positives** | Occasional | Fewer for confirmed attacks, but verify each |
| **ZAP script** | `zap-baseline.py` | `zap-full-scan.py`, `zap-api-scan.py` |

> **Analogy:** Passive scanning is a security guard **watching the cameras**. Active scanning is a guard **rattling every door handle** to see which ones are unlocked.

### What Passive Scanning Typically Reports

| Alert Example | What ZAP Noticed |
| :--- | :--- |
| Content Security Policy (CSP) Header Not Set | Response lacks the header |
| Missing Anti-clickjacking Header | No `X-Frame-Options` or `frame-ancestors` |
| X-Content-Type-Options Header Missing | No `nosniff` |
| Strict-Transport-Security Header Not Set | No HSTS on an HTTPS site |
| Cookie No HttpOnly Flag / Secure Flag / SameSite Attribute | Weak cookie settings |
| Server Leaks Version Information via "Server" Header | Banner shows version numbers |
| Information Disclosure: Suspicious Comments | HTML or JavaScript comments with hints |
| Absence of Anti-CSRF Tokens | Form without a token |
| Vulnerable JS Library | Known-vulnerable client-side library version |
| Cross-Domain Misconfiguration | Overly open CORS |

### What Active Scanning Typically Looks For

| Attack Class | What ZAP Tries |
| :--- | :--- |
| **SQL injection** | Special characters, boolean and time-based tests |
| **Cross-site scripting** | Marker payloads reflected back |
| **Path traversal** | `../` sequences in file parameters |
| **Command injection** | Shell separators and timing tests |
| **Server-side includes, code injection** | Template and code syntax in inputs |
| **Remote file inclusion, SSRF** | URLs in parameters, out-of-band checks |
| **Information exposure** | Probing for sensitive files and paths |

### Scan Policies: Strength and Threshold

You can tune an active scan:

| Setting | Options | Effect |
| :--- | :--- | :--- |
| **Attack Strength** | Low, Medium, High, Insane | How many variations of each attack are tried. Higher means more thorough and slower and noisier. |
| **Alert Threshold** | Off, Low, Medium, High | How **confident** ZAP must be before reporting. Lower thresholds report more (including false positives). |

In the desktop: **Analyze → Scan Policy Manager**. Start with the default policy and adjust only when you understand the impact.

### Why Active Scans Need Care

```text
Possible side effects of an active scan:
  - Hundreds or thousands of junk records (users, comments, orders)
  - Emails or notifications triggered by forms
  - Accounts locked by repeated login attempts
  - Application slowdowns or crashes
  - Alerts raised in your security monitoring
  - Log files and databases filling up
```

**Always** use a disposable test environment for active scans, and scan during agreed times.

---

## 8. Spidering and Application Discovery

### Why Discovery Matters

> **A scanner can only test what it can find.**

If ZAP never discovers `/admin/reports`, it will never test it. Coverage (how much of the app was explored) is as important as the scan rules.

### Ways ZAP Discovers Your Application

| Method | How It Works | Best For |
| :--- | :--- | :--- |
| **Traditional Spider** | Downloads a page, extracts links and forms, follows them, repeats | Classic server-rendered sites |
| **AJAX Spider** | Launches a **real browser**, clicks elements, and watches JavaScript create new links and requests | **Single-page apps** (React, Angular, Vue) |
| **Manual Explore** | You browse the app through ZAP's proxy and ZAP records everything | Complex flows, logins, multi-step forms |
| **Import an API definition** | Load an OpenAPI/Swagger, SOAP, or GraphQL definition | **APIs** with no web pages to crawl |
| **Forced browse** | Tries a list of common paths (`/admin`, `/backup`, `/test`) | Finding hidden content |
| **Import URLs or HAR files** | Load a list or a recorded browser session | Known routes, recorded test runs |

### Traditional Spider vs. AJAX Spider

```text
Traditional page:                         Single-page app (SPA):
<a href="/about">About</a>                <div id="app"></div>
Spider sees the link, follows it.         <script src="main.js"></script>
                                          Links and pages are created by JavaScript.
                                          A traditional spider sees almost nothing.
                                          The AJAX Spider runs a browser, so it sees them.
```

> [!TIP]
> If your Sites tree is nearly empty after a spider run, the application is probably JavaScript-driven. Use the **AJAX Spider**, add `-j` to the packaged scripts, or add a `spiderAjax` job to an Automation Framework plan.

### Scope and Contexts

A **context** tells ZAP what belongs to **your application**. It protects you from accidentally scanning other sites that your target links to (analytics, CDNs, partners).

```text
Context: "My Shop"
  Include:  https://staging.shop.example.com.*
  Exclude:  https://staging.shop.example.com/logout.*
            https://staging.shop.example.com/payment/live.*
```

In the desktop: right-click the site in the Sites tree and choose **Include in Context → New Context**. In **Protected** mode, ZAP only attacks URLs inside the context.

### Authenticated Scanning (Concept)

Many applications keep most features **behind a login**. A scanner that cannot log in sees only the login page.

| Approach | Idea |
| :--- | :--- |
| **Form-based login** | Tell ZAP the login URL, username and password fields, and a "logged in" indicator. |
| **Token or header** | Provide a session cookie or an `Authorization: Bearer ...` header. |
| **Script or recorded login** | Use a script or browser recording for complicated logins (SSO, MFA). |
| **Manual explore first** | Log in yourself through ZAP's proxy, then scan the recorded session. |

Rules for authenticated scanning:

- Use **dedicated test accounts** with fake data, never real users or administrators from production.
- **Exclude the logout URL** from the context, or the spider will log itself out in seconds.
- Keep credentials in **pipeline secrets**, never in plan files or the repository (Module 03).
- Use at least **two accounts** with different roles if you want to test access control.

ZAP's Automation Framework supports authentication and users. The official documentation shows complete examples, which are beyond the scope of this introduction.

### Improving Coverage: A Checklist

- Start the spider from the **right URL** (the home page or an API definition).
- Use the **AJAX Spider** for JavaScript apps.
- **Browse manually** through ZAP to record flows the spider cannot (forms, wizards).
- **Import** OpenAPI or Postman definitions for APIs.
- Add **authentication** and test accounts.
- Check the **Sites tree** afterward. Does it match the pages you know exist? Compare with the application's sitemap or route list.
- Keep spider **duration and depth** realistic. Longer is not always better.

---

## 9. Performing a DAST Scan

### Pre-Scan Checklist

- [ ] I own the application or have written permission.
- [ ] The target is a **test environment** with fake data.
- [ ] The target is reachable from where ZAP runs.
- [ ] I know the **scope** and any URLs to exclude (logout, payment, delete-everything endpoints).
- [ ] Anyone who monitors the environment has been told.

### Step 1: Start the Lab Target

You will scan **OWASP Juice Shop**, a deliberately insecure web application built for security training. It is a modern JavaScript single-page app, which makes it a good test for the AJAX Spider.

```bash
# A private Docker network shared by the target and ZAP
docker network create dast-lab

# Start Juice Shop. Publishing to 127.0.0.1 means ONLY your own machine can reach it.
docker run -d --name juice-shop --network dast-lab -p 127.0.0.1:3000:3000 bkimminich/juice-shop

# Check that it is running (wait a few seconds after starting)
curl -I http://localhost:3000
```

> [!CAUTION]
> Juice Shop is **intentionally vulnerable**. Never expose it to a network or the internet. Binding to `127.0.0.1` keeps it private. Stop and remove it when the labs are done.

### Step 2: A Baseline Scan (Passive, Safe)

```bash
mkdir -p ~/dast-lab/reports && cd ~/dast-lab
chmod a+w reports        # the ZAP container runs as a non-root user and must be able to write reports

docker run --rm --network dast-lab \
  -v "$(pwd)/reports:/zap/wrk:rw" \
  -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://juice-shop:3000 -r baseline-report.html -J baseline-report.json

echo "ZAP exit code: $?"
```

| Part | Meaning |
| :--- | :--- |
| `--network dast-lab` | Puts ZAP on the same private network as the target, so it can reach it by **container name**. |
| `-v "$(pwd)/reports:/zap/wrk:rw"` | Shares a folder so the reports land on your machine. `/zap/wrk` is where ZAP reads and writes files. |
| `-t http://juice-shop:3000` | The **target** URL. |
| `-r` / `-J` | Write an **HTML** report and a **JSON** report. |
| `-t` (after `docker run`) | Gives the container a terminal. Not the same as the scan target flag. |

While it runs you will see lines such as `PASS:` and `WARN-NEW:` for each rule, then a summary:

```text
FAIL-NEW: 0   FAIL-INPROG: 0   WARN-NEW: 8   WARN-INPROG: 0   INFO: 0   IGNORE: 0   PASS: 55
```

### ZAP Exit Codes

The packaged scans use the exit code to tell your pipeline what happened:

| Exit Code | Meaning |
| :---: | :--- |
| `0` | Success. No warnings or failures. |
| `1` | At least one rule was set to **FAIL** and raised an alert. |
| `2` | At least one **WARN**. (By default **most** rules WARN.) |
| `3` | Another failure (for example, ZAP could not start or reach the target). |

You will use these codes for security gates in section 13.

### Step 3: Useful Baseline Options

| Option | Purpose |
| :--- | :--- |
| `-m 3` | Spider for up to 3 minutes (default is 1). |
| `-j` | Also run the **AJAX Spider** (good for JavaScript apps). |
| `-a` | Include **alpha-quality** passive rules too. |
| `-c rules.tsv` | Use a **rules file** to set each rule to `IGNORE`, `WARN`, or `FAIL`. |
| `-g gen.conf` | **Generate** a starter rules file listing every rule. |
| `-I` | Do not fail on warnings (exit `0` unless a rule FAILs). |
| `-x`, `-w` | Also write XML or Markdown reports. |
| `-d` | Show debug output. |

For example, scan a JavaScript app more thoroughly:

```bash
docker run --rm --network dast-lab -v "$(pwd)/reports:/zap/wrk:rw" -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://juice-shop:3000 -j -m 3 -r baseline-ajax.html
```

### Step 4: A Full Scan (Active)

> [!WARNING]
> A full scan **attacks** the target. Only run it against your own lab application.

```bash
docker run --rm --network dast-lab \
  -v "$(pwd)/reports:/zap/wrk:rw" \
  -t ghcr.io/zaproxy/zaproxy:stable \
  zap-full-scan.py -t http://juice-shop:3000 -j -m 5 -r full-report.html -J full-report.json
```

This can take a long time (often 10 minutes to over an hour on a larger app). For predictable run times in the labs, use an Automation Framework plan (Step 6).

### Step 5: An API Scan

If you have an API definition (OpenAPI/Swagger), scan it directly:

```bash
docker run --rm --network dast-lab -v "$(pwd)/reports:/zap/wrk:rw" -t ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py -t http://my-api:8080/openapi.json -f openapi -r api-report.html
```

| Option | Meaning |
| :--- | :--- |
| `-t` | URL **or file** of the API definition. |
| `-f` | Format: `openapi`, `soap`, or `graphql`. |

### Step 6: The Automation Framework (Recommended for CI/CD)

The **Automation Framework** is ZAP's modern way of automation. You describe the whole scan in a **YAML plan**, which makes it repeatable and reviewable in Git.

Create `reports/plan.yaml`:

```yaml
env:
  contexts:
    - name: juice-shop
      urls:
        - http://juice-shop:3000
      includePaths:
        - http://juice-shop:3000.*
  parameters:
    failOnError: true
    progressToStdout: true

jobs:
  - type: passiveScan-config           # configure the passive scanner
    parameters:
      maxAlertsPerRule: 10

  - type: spider                       # classic crawl
    parameters:
      context: juice-shop
      maxDuration: 2                   # minutes

  - type: spiderAjax                   # browser-based crawl for JavaScript apps
    parameters:
      context: juice-shop
      maxDuration: 2

  - type: passiveScan-wait             # let passive scanning finish
    parameters:
      maxDuration: 5

  - type: activeScan                   # ATTACKS the target. Only with permission!
    parameters:
      context: juice-shop
      maxScanDurationInMins: 10        # keeps the lab run time predictable

  - type: report
    parameters:
      template: traditional-html
      reportDir: /zap/wrk/
      reportFile: af-report.html

  - type: exitStatus                   # sets the exit code from the alerts found
    parameters:
      errorLevel: High                 # any High alert -> exit code 1
      warnLevel: Medium                # any Medium alert -> exit code 2
```

Run the plan:

```bash
docker run --rm --network dast-lab \
  -v "$(pwd)/reports:/zap/wrk:rw" \
  -t ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -cmd -autorun /zap/wrk/plan.yaml

echo "ZAP exit code: $?"
```

| Plan Part | Purpose |
| :--- | :--- |
| `env.contexts` | Defines the application and its **scope**. |
| `jobs` | Steps that run **in order**. Order matters (for example, `passiveScan-wait` belongs after spidering). |
| `maxScanDurationInMins` | Caps the active scan so a pipeline cannot run forever. |
| `report` | Produces the report file. |
| `exitStatus` | Converts findings into a **pipeline-friendly exit code** (should be the last job). |

### Step 7: Scanning With the Desktop Application (Optional)

**Automated scan (quickest):**

1. Open ZAP and go to the **Quick Start** tab.
2. Click **Automated Scan**.
3. Enter the **URL to attack**, for example `http://localhost:3000`.
4. Tick **Use traditional spider** and **Use ajax spider**.
5. Click **Attack**. ZAP spiders the site, then actively scans it.
6. Watch the **Alerts** tab fill up.

**Manual explore (more thorough, good for logins):**

1. In **Quick Start**, click **Manual Explore**.
2. Enter the URL and choose a browser, then click **Launch Browser**. ZAP opens a browser that is **already configured** to use ZAP as its proxy.
3. Browse the application like a normal user: register, log in, search, add items.
4. Return to ZAP. The **Sites tree** now shows what you visited, and passive alerts have already appeared.
5. Right-click the site in the Sites tree → **Include in Context → New Context**.
6. Switch to **Protected** mode (toolbar), then right-click the site → **Attack → Active Scan**.

**Using your own browser through ZAP (advanced):**

1. In your browser's network settings, set the **HTTP and HTTPS proxy** to `127.0.0.1` port `8080`.
2. In ZAP, go to **Tools → Options → Network → Server Certificates** and **Save** the root CA certificate.
3. Import that certificate into your **test browser profile** as a trusted authority so HTTPS pages load without errors.
4. When finished, **remove the certificate** and reset the proxy settings.

### Step 8: Clean Up

```bash
docker rm -f juice-shop
docker network rm dast-lab
```

---

## 10. Understanding ZAP Reports

### Report Formats

| Format | Option or Template | Best For |
| :--- | :--- | :--- |
| **HTML** | `-r report.html`, template `traditional-html` | Reading and sharing with humans |
| **JSON** | `-J report.json`, template `traditional-json` | **Scripts and security gates** (parse with `jq`) |
| **XML** | `-x report.xml` | Tools that read XML |
| **Markdown** | `-w report.md` | Pasting into tickets and pull requests |
| **SARIF** | Automation Framework template `sarif-json` | Uploading to code scanning dashboards (availability depends on your GitHub plan) |

### The Structure of an HTML Report

1. **Summary of Alerts:** a table counting alerts by risk level.
2. **Alerts table:** one row per alert type, with its risk and how many instances were found.
3. **Alert details:** for each alert, a full description, every affected URL, and advice.

### Risk Levels

| Risk | Meaning | Typical Examples |
| :--- | :--- | :--- |
| 🔴 **High** | Serious, likely exploitable, major impact | SQL injection, remote code execution, stored XSS |
| 🟠 **Medium** | Real weakness with moderate impact | Missing CSP, missing anti-clickjacking, CORS issues |
| 🟡 **Low** | Minor or hard to exploit | Cookie flags, version banners, missing Permissions-Policy |
| 🔵 **Informational** | Context, not a vulnerability by itself | "Modern Web Application", session management notes |

### Confidence Levels

| Confidence | Meaning |
| :--- | :--- |
| **High** | ZAP is very sure (for example, a header is clearly absent). |
| **Medium** | Probably real, worth checking. |
| **Low** | Might be a false positive. **Verify before acting.** |
| **False Positive** | Marked as not real. |
| **User Confirmed** | A human confirmed it. |

> **Priority = Risk × Confidence × Exposure × Data sensitivity.** A Medium finding on a login page that handles customer data may deserve more attention than a High finding on an internal demo page with fake data.

### Anatomy of One Alert

Here is a typical alert, annotated:

```text
Alert name:    Content Security Policy (CSP) Header Not Set       <-- what was found
Risk:          Medium            Confidence: High                 <-- how serious, how sure
Plugin ID:     10038                                              <-- the rule number (use it in rules files)

Description:   Content Security Policy (CSP) is an added layer of security that helps to
               detect and mitigate certain types of attacks, including XSS and data injection.
               (explains WHY it matters)

Instances:     3
  URL:         http://juice-shop:3000/                            <-- WHERE
  Method:      GET
  Parameter:   (none)
  Attack:      (none, because this was a passive finding)
  Evidence:    (the part of the response that triggered it)

Solution:      Ensure that your web server, application server, load balancer, etc. is
               configured to set the Content-Security-Policy header.     <-- HOW TO FIX

Reference:     (links to documentation)
CWE Id:        693        WASC Id: 15                              <-- standard weakness IDs
```

| Field | Why It Matters |
| :--- | :--- |
| **Plugin ID** | Identifies the rule. Used in rules files and filters to set FAIL, WARN, or IGNORE. |
| **URL, Method, Parameter** | Tell you where to look and how to reproduce it. |
| **Attack** | For active findings, the **exact payload** ZAP sent. Reproduce it manually to confirm. |
| **Evidence** | The part of the response that convinced ZAP. |
| **Solution** | Practical remediation advice. |
| **CWE Id** | Standard weakness number for tracking and compliance. |

### The JSON Report Structure

```json
{
  "@programName": "ZAP",
  "site": [
    {
      "@name": "http://juice-shop:3000",
      "alerts": [
        {
          "pluginid": "10038",
          "alert": "Content Security Policy (CSP) Header Not Set",
          "riskcode": "2",
          "confidence": "3",
          "riskdesc": "Medium (High)",
          "count": "3",
          "solution": "...",
          "instances": [ { "uri": "http://juice-shop:3000/", "method": "GET" } ]
        }
      ]
    }
  ]
}
```

| Field | Values |
| :--- | :--- |
| `riskcode` | `"3"` High, `"2"` Medium, `"1"` Low, `"0"` Informational (as text) |
| `confidence` | `"3"` High, `"2"` Medium, `"1"` Low (as text) |
| `count` | Number of affected URLs |

Quick summaries with `jq`:

```bash
# Count alert TYPES by risk
jq -r '.site[].alerts[] | .riskdesc' reports/baseline-report.json | sort | uniq -c

# List high-risk alerts
jq -r '.site[].alerts[] | select(.riskcode=="3") | .name' reports/baseline-report.json

# Count HIGH alerts only
jq '[.site[].alerts[] | select(.riskcode=="3")] | length' reports/baseline-report.json
```

### How to Triage a Report

```text
 1. Sort by risk (High first), then confidence.
 2. For each alert ask: Is it REAL?
        - Reproduce it (curl, browser, or ZAP's "Resend" feature).
 3. Is it EXPLOITABLE in MY context?
        - Does it affect real data, authentication, or only a harmless page?
 4. Decide:  FIX now  /  PLAN a fix  /  ACCEPT with reason  /  FALSE POSITIVE with reason
 5. Record the decision (ticket, comment, or rules file with a justification).
 6. After fixing, RESCAN to prove it is gone.
```

### Reproducing a Finding Manually

Never trust a tool blindly. Reproduce at least the important findings:

```bash
# Is the header really missing?
curl -sI http://localhost:3000/ | grep -i "content-security-policy" || echo "CSP header is missing"

# Do cookies have the right flags?
curl -sI http://localhost:3000/ | grep -i "set-cookie"
```

For active findings, copy the **Attack** payload from the report, send it with `curl` or ZAP's **Resend** tool, and observe whether the response shows the weakness.

### Common False Positives and Informational Alerts

| Alert | Why It May Not Matter |
| :--- | :--- |
| *Timestamp Disclosure* | A number in the response looks like a date, but is harmless data. |
| *Information Disclosure: Suspicious Comments* | A comment containing a word like "TODO" or "admin", with nothing sensitive. |
| *Modern Web Application* | Informational note that the app uses JavaScript. It only affects how you scan. |
| *Cross-Domain Misconfiguration* on **public static** assets | Open CORS on public files may be intended. |

> [!WARNING]
> **Treat reports as sensitive.** They can contain real URLs, parameters, tokens, cookies, and error messages. Store them in protected artifact storage, never in public repositories or open chat channels.

---

## 11. DAST Integration with GitHub Actions

### The Pattern

DAST needs a **running application**. A pipeline therefore does this:

```text
1. Build the application (container image)
2. START it inside the pipeline (or deploy it to a test environment)
3. WAIT until it responds
4. RUN the ZAP scan against it
5. UPLOAD the report as an artifact
6. FAIL the job if the security gate is not met
7. STOP the application
```

### Option 1: The Official ZAP Baseline Action

ZAP provides GitHub Actions: `zaproxy/action-baseline`, `zaproxy/action-full-scan`, and `zaproxy/action-api-scan`.

```yaml
# .github/workflows/dast-zap.yml
name: DAST - ZAP Baseline

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read                         # least privilege

jobs:
  zap-baseline:
    name: ZAP baseline scan
    runs-on: ubuntu-latest
    steps:
      - name: Check out code
        uses: actions/checkout@v4

      - name: Build the application image
        run: docker build -t myapp:test .

      - name: Start the application
        run: |
          docker run -d --name app -p 3000:3000 myapp:test
          for i in $(seq 1 30); do
            curl -sf http://localhost:3000 > /dev/null && exit 0
            sleep 2
          done
          echo "Application did not start"; docker logs app; exit 1

      - name: ZAP baseline scan
        uses: zaproxy/action-baseline@v0.14.0       # check the releases page for the newest version
        with:
          target: "http://localhost:3000"
          rules_file_name: ".zap/rules.tsv"         # which rules FAIL, WARN, or are IGNORED
          cmd_options: "-a"                         # include alpha passive rules
          fail_action: true                         # fail the job when ZAP's exit code says so
          allow_issue_writing: false                # do not create GitHub issues (keeps permissions minimal)
          artifact_name: zap_baseline_report        # the report is uploaded automatically

      - name: Show application logs on failure
        if: failure()
        run: docker logs app

      - name: Stop the application
        if: always()
        run: docker rm -f app
```

| Line | Why It Matters |
| :--- | :--- |
| `permissions: contents: read` | The workflow token can only read code. By default the action tries to **open GitHub issues**, which needs `issues: write`. Setting `allow_issue_writing: false` avoids that need. |
| Start the app and **wait** | ZAP must not start before the app responds, or it scans an error page. |
| `target: http://localhost:3000` | The action's container shares the runner's network, so `localhost` reaches your app. |
| `rules_file_name` | **This file is your security gate** (section 13). |
| `fail_action: true` | Without it the action reports problems but does not fail the job. |
| `if: always()` cleanup | Stops the app even when the scan fails. |

> [!NOTE]
> Action version numbers change. Check each action's releases page, use a current version, and for production workflows **pin the action to a full commit SHA** (Module 03, section 12).

### Option 2: Plain Docker Commands (Full Control)

This avoids the action, creates no issues, and lets you use the exit code and reports exactly as you want:

```yaml
      - name: ZAP baseline scan (plain Docker)
        run: |
          chmod -R a+w .zap
          set +e                                    # let us inspect the exit code ourselves
          docker run --rm --network host \
            -v "$PWD/.zap:/zap/wrk:rw" \
            ghcr.io/zaproxy/zaproxy:stable \
            zap-baseline.py -t http://localhost:3000 \
              -c rules.tsv -r zap-report.html -J zap-report.json
          code=$?
          echo "ZAP exit code: $code"
          # 0 = clean, 1 = FAIL rule hit, 2 = warnings only, 3 = scan problem
          if [ "$code" -eq 1 ] || [ "$code" -eq 3 ]; then exit 1; fi

      - name: Upload ZAP reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: zap-reports
          path: |
            .zap/zap-report.html
            .zap/zap-report.json
```

Here the `.zap/` folder holds your `rules.tsv` and receives the reports. Add `.zap/zap-report.*` to `.gitignore`.

### Scheduled Full Scan

Active scans are too slow for every pull request. Run them **nightly or weekly** against a **dedicated test environment** that you control.

```yaml
# .github/workflows/dast-zap-full.yml
name: DAST - ZAP Full Scan (nightly)

on:
  schedule:
    - cron: "0 2 * * *"            # every day at 02:00 UTC
  workflow_dispatch:               # also allow manual runs

permissions:
  contents: read

jobs:
  zap-full:
    runs-on: ubuntu-latest
    steps:
      - name: ZAP full scan
        uses: zaproxy/action-full-scan@v0.12.0         # confirm the current version
        with:
          target: ${{ vars.STAGING_URL }}               # your own test environment, with permission
          rules_file_name: ".zap/rules.tsv"
          cmd_options: "-a -j"
          fail_action: true
          allow_issue_writing: false
```

> [!CAUTION]
> The target of a scheduled full scan must be a **test environment you own**, not production and not someone else's site. Store the URL in a repository **variable**, and any credentials in **secrets**.

### Choosing What Runs When

| Trigger | Scan | Why |
| :--- | :--- | :--- |
| **Pull request** | Baseline (passive, 2 to 5 minutes) | Fast feedback with no attack traffic |
| **Merge to main / deploy to staging** | Baseline, or short API scan | Verify the deployed build |
| **Nightly or weekly** | Full active scan (with a duration cap) | Deep testing without slowing developers |
| **Before a major release** | Full scan plus manual testing | Extra assurance |

### Make the Check Required

As in Modules 03 and 04, a check is a gate only when it is **required**:

1. **Settings → Rules → Rulesets** (or **Branches**) → edit the rule for `main`.
2. Turn on **Require status checks to pass**.
3. Add the **ZAP baseline scan** job (run the workflow once first so it is listed).

### Combine With Earlier Modules

```yaml
jobs:
  secrets:    # Gitleaks (Module 03)
  sast:       # SonarQube (Module 04)
  sca:        # Dependency-Check (Module 05)
  dast:
    needs: [secrets, sast, sca]       # DAST runs after the cheaper checks pass
  deploy:
    needs: [dast]
```

---

## 12. DAST Integration with Jenkins

### What You Need

| Piece | Purpose |
| :--- | :--- |
| A Jenkins agent with **Docker** | Runs the ZAP container. |
| The application under test | Started by the pipeline (for example, as a container). |
| The **HTML Publisher** plugin (optional) | Shows the HTML report inside Jenkins. |
| A **rules file** | Defines your gate (section 13). |

> [!NOTE]
> A ZAP Jenkins plugin exists, but it is rarely maintained. Running ZAP's **official Docker image** from the pipeline is simpler, version-controlled, and works the same on any CI system.

### A Complete Pipeline (`Jenkinsfile`)

```groovy
// Jenkinsfile
pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps { checkout scm }
        }

        stage('Build Application') {
            steps {
                sh 'docker build -t myapp:test .'
            }
        }

        stage('Start Application (Test Environment)') {
            steps {
                sh '''
                    docker rm -f app || true
                    docker run -d --name app -p 127.0.0.1:3000:3000 myapp:test
                    for i in $(seq 1 30); do
                        curl -sf http://localhost:3000 > /dev/null && exit 0
                        sleep 2
                    done
                    echo "Application did not start"; docker logs app; exit 1
                '''
            }
        }

        stage('DAST - ZAP Baseline') {
            steps {
                script {
                    sh 'mkdir -p zap-reports && chmod a+w zap-reports && cp .zap/rules.tsv zap-reports/rules.tsv'

                    def rc = sh(returnStatus: true, script: '''
                        docker run --rm --network host \
                          -v "$PWD/zap-reports:/zap/wrk:rw" \
                          ghcr.io/zaproxy/zaproxy:stable \
                          zap-baseline.py -t http://localhost:3000 \
                            -c rules.tsv -r zap-report.html -J zap-report.json
                    ''')

                    echo "ZAP exit code: ${rc}"
                    if (rc == 1) {
                        error('ZAP found alerts that are set to FAIL. Security gate failed.')
                    } else if (rc == 2) {
                        unstable('ZAP reported warnings. Review the report.')
                    } else if (rc != 0) {
                        error("ZAP scan did not complete correctly (exit code ${rc}).")
                    }
                }
            }
        }

        stage('Deploy') {
            when { branch 'main' }
            steps {
                echo 'Deploying... (runs only if the DAST gate did not fail)'
            }
        }
    }

    post {
        always {
            sh 'docker rm -f app || true'
            archiveArtifacts artifacts: 'zap-reports/zap-report.*', allowEmptyArchive: true
            publishHTML(target: [
                reportDir: 'zap-reports',
                reportFiles: 'zap-report.html',
                reportName: 'ZAP DAST Report',
                keepAll: true,
                alwaysLinkToLastBuild: true,
                allowMissing: true
            ])
        }
    }
}
```

| Part | What It Does |
| :--- | :--- |
| `returnStatus: true` | Lets the script **read ZAP's exit code** instead of failing immediately. |
| `rc == 1` → `error(...)` | **Fails the build** when a FAIL-level rule fires. Later stages, including **Deploy**, do not run. |
| `rc == 2` → `unstable(...)` | Marks the build **yellow** (unstable) for warnings, but lets it continue. |
| `post { always { ... } }` | Always stops the test app and saves the reports, even when the build fails. |
| `archiveArtifacts` | Stores the reports with the build. |
| `publishHTML` | Shows the HTML report in Jenkins (requires the HTML Publisher plugin). |

### Problems You May Meet

| Problem | Explanation and Fix |
| :--- | :--- |
| HTML report looks **unstyled** in Jenkins | Jenkins applies a strict Content Security Policy to hosted files. The safe approach is to **download the archived report** and open it locally. Loosening Jenkins' CSP weakens its security, so avoid doing that on a shared server. |
| `--network host` does not work | It only works on Linux agents with the Docker daemon on the same host. Otherwise, put the app and ZAP on a **shared Docker network** and use the container name as the target. |
| Jenkins itself runs in a container | Reaching the Docker daemon needs extra setup. A dedicated Linux build agent with Docker is simpler. |
| Permission denied writing reports | The ZAP container's user must be able to write to `zap-reports`. Keep `chmod a+w zap-reports`. |

### Jenkins Security Reminders

- Keep test credentials only in **Jenkins credentials**, never in the `Jenkinsfile` or rules file.
- Protect the `Jenkinsfile` and `.zap/` folder with **CODEOWNERS** and branch protection. Someone who can edit the rules file can quietly turn a FAIL into an IGNORE.
- Run DAST only against **test environments**, never production.

---

## 13. Security Gates and Remediation

### What Is a DAST Security Gate?

A **security gate** is a rule that decides whether the pipeline may continue after the scan. Without a gate, a scan is just a report that people may never read.

```text
 ZAP scan finishes
        |
        v
 Does the result meet our policy?  ----NO---->  FAIL the build, block deployment
        |
       YES
        v
 Continue to the next stage
```

### Three Ways to Build a Gate

**1. A rules file (baseline scans).** List each rule and say what to do when it fires. The file is **tab-separated**:

```text
# rules.tsv   (columns separated by TAB characters)
# <plugin ID> <TAB> <IGNORE|INFO|WARN|FAIL> <TAB> (<comment>)

10038	FAIL	(Content Security Policy (CSP) Header Not Set)
10020	FAIL	(Missing Anti-clickjacking Header)
10021	FAIL	(X-Content-Type-Options Header Missing)
10010	FAIL	(Cookie No HttpOnly Flag)
10054	WARN	(Cookie without SameSite Attribute)
10109	IGNORE	(Modern Web Application - informational, justified in ticket SEC-142)
```

Generate a starter file listing **every** rule, then edit it:

```bash
docker run --rm -v "$(pwd)/reports:/zap/wrk:rw" -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://juice-shop:3000 -g gen.conf
```

> [!TIP]
> **Plugin IDs** are shown in every ZAP report (the **Plugin ID** field). Copy IDs from **your own** report so they match the version you run. Rule numbers and names can change over time.

How the exit code follows:

| Rule Action | Effect |
| :--- | :--- |
| `FAIL` | The scan exits with **1** if this alert appears. **This is your gate.** |
| `WARN` | Reported, exit code **2**. |
| `INFO` | Reported as information. |
| `IGNORE` | Not reported. Always add a **comment with the reason**. |

**2. A threshold in an Automation Framework plan.** The `exitStatus` job (section 9, step 6):

```yaml
  - type: exitStatus
    parameters:
      errorLevel: High      # any High alert  -> exit code 1  (gate fails)
      warnLevel: Medium     # any Medium alert -> exit code 2  (warning)
```

**3. A custom script reading the JSON report.** Use this when you need your own logic, such as "no High alerts, and at most 5 Medium":

```bash
#!/usr/bin/env bash
# gate.sh : fail the pipeline based on the ZAP JSON report
REPORT="${1:-reports/zap-report.json}"

HIGH=$(jq '[.site[].alerts[] | select(.riskcode=="3")] | length' "$REPORT")
MEDIUM=$(jq '[.site[].alerts[] | select(.riskcode=="2")] | length' "$REPORT")

echo "High alerts: $HIGH   Medium alerts: $MEDIUM"

if [ "$HIGH" -gt 0 ]; then
  echo "GATE FAILED: High-risk alerts found."
  exit 1
fi
if [ "$MEDIUM" -gt 5 ]; then
  echo "GATE FAILED: more than 5 Medium-risk alerts."
  exit 1
fi
echo "GATE PASSED"
```

### Choosing a Gate Policy

Start gently, then tighten as the team improves. A gate that always fails will be bypassed.

| Stage | Gate Strategy |
| :--- | :--- |
| **1. Visibility** (first weeks) | Report only. Nothing fails. Study the findings and fix the easy ones. |
| **2. Block the worst** | `FAIL` on **High** risk alerts and on a short list of must-have controls (CSP, cookie flags, injection). |
| **3. Raise the bar** | Add Medium risk alerts. Include the full active scan nightly. |
| **4. Mature** | New alerts fail the build. Existing accepted findings are listed in the rules file with reasons and review dates. |

| Where | Policy Example |
| :--- | :--- |
| **Pull request** | Baseline scan. Fail on High and on selected rules. |
| **Staging deploy** | Baseline plus API scan. Fail on High. |
| **Nightly full scan** | Full scan. Open tickets for anything new. Fail the nightly job on High. |
| **Release** | No unresolved High. Medium needs an approved exception. |

### Handling False Positives and Accepted Risk Properly

| Practice | Why |
| :--- | :--- |
| **Reproduce first** | Confirm it is really a false positive. |
| **Use `IGNORE` with a comment** that names a ticket or approver | Future readers must know **why**. |
| **Scope it narrowly** | Ignore one rule, not a whole category. |
| **Set an expiry or review date** | Accepted risks should be rechecked. |
| **Review changes to the rules file** | Use CODEOWNERS. A quiet `FAIL` → `IGNORE` change is a way to bypass the gate. |

ZAP's Automation Framework also has an **`alertFilter`** job for changing the risk of specific alerts on specific URLs, which is more precise than a global ignore. See the official documentation for details.

### Remediation: Turning Findings Into Fixes

```text
   Finding  -->  Reproduce  -->  Find the root cause  -->  Fix  -->  Rescan  -->  Close
```

**Remediation guide for common alerts:**

| Alert | Fix |
| :--- | :--- |
| Content Security Policy (CSP) Header Not Set | Add a `Content-Security-Policy` header (start strict, such as `default-src 'self'`). |
| Missing Anti-clickjacking Header | Add `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`. |
| X-Content-Type-Options Header Missing | Add `X-Content-Type-Options: nosniff`. |
| Strict-Transport-Security Header Not Set | Add HSTS on **HTTPS** responses. |
| Cookie No HttpOnly / Secure / SameSite | Set `HttpOnly; Secure; SameSite=Lax` on session cookies. |
| Server Leaks Version Information | Hide or genericize the `Server` and `X-Powered-By` headers. |
| Absence of Anti-CSRF Tokens | Add anti-CSRF tokens to state-changing forms. |
| Cross-Domain Misconfiguration (CORS) | Replace `*` with an explicit list of trusted origins. |
| SQL Injection | Use parameterized queries. |
| Cross Site Scripting | Encode output for context, enable auto-escaping, add CSP. |
| Path Traversal | Confine file access to a fixed directory. |
| Vulnerable JS Library | Update the library (Module 05). |
| Information Disclosure in comments or errors | Remove comments and use generic error pages in production. |

### Adding Security Headers

**Nginx:**

```nginx
add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'none'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;   # HTTPS sites only
server_tokens off;                                                                    # hide the Nginx version
```

**Flask (Python):**

```python
@app.after_request
def add_security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    return resp

# Safe session cookie
resp.set_cookie("session_id", value, httponly=True, secure=True, samesite="Lax")
```

**Express (Node.js):**

```javascript
const helmet = require("helmet");
app.use(helmet());        // sets many secure headers; customize the CSP for your app
```

> [!WARNING]
> A strict **CSP** can break pages that use inline scripts or third-party resources. Test in a staging environment first, and roll out gradually (many teams start with `Content-Security-Policy-Report-Only`).

### Suggested Fix Timelines (Example Only)

Adapt these to your organization's policy:

| Risk | Typical Target |
| :--- | :--- |
| **High** | Fix immediately or within days. Block release. |
| **Medium** | Fix within a few weeks, within the current sprint if possible. |
| **Low** | Schedule into regular maintenance. |
| **Informational** | Review, document, and move on. |

### Always Retest

A fix is **not done** until a rescan proves it. Rescan the same URL, confirm the alert has gone, and check that nothing new appeared.

---

## 14. Hands-On Labs

> [!WARNING]
> All labs run **on your own machine** against targets you start yourself. **Never point these tools at a system you do not own or lack written permission to test.** Stop and remove the vulnerable containers when you finish.

### Lab 1: Build the Lab and Explore HTTP

**Objective:** Start the target and understand real HTTP requests and responses.

**Tasks:**

```bash
# 1. Private network and the vulnerable lab app (reachable only from your own machine)
docker network create dast-lab
docker run -d --name juice-shop --network dast-lab -p 127.0.0.1:3000:3000 bkimminich/juice-shop

# 2. Wait until it responds
until curl -sf http://localhost:3000 > /dev/null; do sleep 2; done && echo "Juice Shop is up"

# 3. Look at the raw response headers
curl -I http://localhost:3000/

# 4. Look at a JSON API response
curl -s "http://localhost:3000/rest/products/search?q=apple" | head -c 600; echo

# 5. See the request and response together
curl -v "http://localhost:3000/rest/products/search?q=apple" 2>&1 | head -40
```

6. Open **http://localhost:3000** in a browser, press **F12**, open the **Network** tab, and reload. Click one request and find the **request headers**, **response headers**, and **status code**.
7. Fill in this table:

| Question | Your Answer |
| :--- | :--- |
| What is the status code of the home page? | |
| Which security headers does the response contain? | |
| Which security headers from section 3 are **missing**? | |
| Does the app set any cookies? Which flags do they have? | |
| Which part of `/rest/products/search?q=apple` is **user-controlled input**? | |

**Expected outcome:** You can read a raw request and response, name the important security headers, and point to the user-controlled inputs in a URL.

### Lab 2: Your First Baseline Scan

**Objective:** Run a passive ZAP baseline scan and read the results.

**Tasks:**

```bash
mkdir -p ~/dast-lab/reports && cd ~/dast-lab
chmod a+w reports

docker run --rm --network dast-lab \
  -v "$(pwd)/reports:/zap/wrk:rw" \
  -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://juice-shop:3000 -j -m 2 -r baseline-report.html -J baseline-report.json
echo "ZAP exit code: $?"
```

1. Open `reports/baseline-report.html` in a browser.
2. Count alerts by risk with `jq`:

```bash
jq -r '.site[].alerts[] | .riskdesc' reports/baseline-report.json | sort | uniq -c
```

3. Pick **three** alerts and for each record: name, risk, confidence, plugin ID, affected URL, and the recommended solution.
4. Reproduce one alert manually (for example, check a missing header with `curl -sI`).

**Expected outcome:** A report with several Medium, Low, and Informational alerts (for example, a missing CSP or cross-domain configuration, depending on your version). Exit code **2** means warnings were found. You can explain why a baseline scan is safe: it never attacks.

### Lab 3: Proxy, Explore, and Spider With the ZAP Desktop

**Objective:** Use ZAP as an intercepting proxy and see what spidering discovers. *(Optional: needs the desktop app.)*

**Tasks:**

1. Start ZAP, choose **No, I do not want to persist this session**, and set the mode to **Standard**.
2. In **Quick Start**, click **Manual Explore**, enter `http://localhost:3000`, and click **Launch Browser**.
3. In the launched browser, browse Juice Shop: open a product, use the search box, and visit the login page.
4. Back in ZAP, look at the **Sites tree** and the **History** tab. Click one request and read its **Request** and **Response** tabs.
5. Open the **Alerts** tab and note the passive alerts that appeared **only from browsing**.
6. Right-click the site in the Sites tree → **Attack → Spider**. After it finishes, note how many URLs were found.
7. Right-click the site → **Attack → AJAX Spider**. Compare the URL counts of the two spiders.

**Expected outcome:** You see that the traditional spider finds little on a JavaScript application, and the AJAX Spider finds much more. You can explain why.

### Lab 4: A Time-Boxed Active Scan

**Objective:** Run an active scan with the Automation Framework and compare it to the baseline.

> [!CAUTION]
> This **attacks** Juice Shop. Do it only against your local lab container.

**Tasks:**

1. Create `~/dast-lab/reports/plan.yaml` using the plan from section 9, step 6.
2. Run it:

```bash
cd ~/dast-lab
docker run --rm --network dast-lab \
  -v "$(pwd)/reports:/zap/wrk:rw" \
  -t ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -cmd -autorun /zap/wrk/plan.yaml
echo "ZAP exit code: $?"
```

3. Open `reports/af-report.html`.
4. Compare with Lab 2:

| Question | Baseline (Lab 2) | Active (Lab 4) |
| :--- | :--- | :--- |
| Total alert types | | |
| High-risk alerts | | |
| Any injection alerts (SQL, XSS)? | | |
| Run time | | |
| Which alerts had an **Attack** payload? | | |

5. For one alert with an **Attack** value, reproduce the request with `curl` and observe the response.

**Expected outcome:** The active scan finds more (and sometimes more serious) issues than the baseline, including alerts that show the **exact attack payload**. You can explain why active scans must be time-boxed and run only on test systems. The exact alerts depend on your ZAP and Juice Shop versions.

### Lab 5: Triage and Build a Security Gate

**Objective:** Turn findings into a pass or fail decision.

**Tasks:**

1. From your Lab 2 report, choose **three** alerts you consider most important, and for each write a triage note:

| Alert | Reproduced? | Real risk here? | Decision (fix / accept / false positive) | Reason |
| :--- | :--- | :--- | :--- | :--- |

2. Create a rules file with **real tabs** (use your own plugin IDs from the report):

```bash
cd ~/dast-lab/reports
printf '10038\tFAIL\t(Content Security Policy (CSP) Header Not Set)\n' >  rules.tsv
printf '10109\tIGNORE\t(Modern Web Application - informational)\n'     >> rules.tsv
cat -A rules.tsv        # tabs appear as ^I
```

3. Re-run the baseline with the rules file and check the exit code:

```bash
cd ~/dast-lab
docker run --rm --network dast-lab -v "$(pwd)/reports:/zap/wrk:rw" -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://juice-shop:3000 -c rules.tsv -r gate-report.html -J gate-report.json
echo "ZAP exit code: $?"          # 1 means a FAIL rule fired: the gate FAILED
```

4. Create `gate.sh` from section 13 and run it against `reports/gate-report.json`:

```bash
chmod +x gate.sh && ./gate.sh reports/gate-report.json ; echo "Gate exit code: $?"
```

5. Change the `FAIL` line to `WARN` and run again. What happens to the exit code?

**Expected outcome:** With the `FAIL` rule, the exit code is **1** and the pipeline would stop. Changing it to `WARN` lets the pipeline pass. You can explain why changes to the rules file must be reviewed.

### Lab 6: Find, Fix, and Verify (The Full Loop)

**Objective:** Experience the complete cycle: scan, fix, rescan.

**Tasks:**

1. Create a small, insecure web app:

```bash
mkdir -p ~/dast-lab/demo && cd ~/dast-lab/demo
cat > app.py <<'EOF'
# A tiny app with missing security controls. For DAST practice only.
from flask import Flask, make_response

app = Flask(__name__)

@app.route("/")
def index():
    resp = make_response("<html><body><h1>DAST Demo</h1><a href='/about'>About</a></body></html>")
    resp.set_cookie("session_id", "abc123")          # no HttpOnly, Secure, or SameSite
    return resp

@app.route("/about")
def about():
    return "<html><body><p>About this demo app.</p><a href='/'>Home</a></body></html>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
EOF

docker run -d --name flask-demo --network dast-lab \
  -v "$(pwd):/app" -w /app python:3.12-slim \
  sh -c "pip install --quiet flask && python app.py"

sleep 15 && docker logs flask-demo | tail -3
```

2. **Scan BEFORE the fix:**

```bash
cd ~/dast-lab
docker run --rm --network dast-lab -v "$(pwd)/reports:/zap/wrk:rw" -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://flask-demo:5000 -r before.html -J before.json
```

Expected alerts (names may vary slightly by version): Content Security Policy Header Not Set, Missing Anti-clickjacking Header, X-Content-Type-Options Header Missing, Cookie No HttpOnly Flag, Cookie without SameSite Attribute, and a `Server` header that leaks version information.

3. **Fix the app.** Edit `demo/app.py` so it contains:

```python
from flask import Flask, make_response

app = Flask(__name__)

@app.after_request
def add_security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    resp.headers["Cache-Control"] = "no-store"
    return resp

@app.route("/")
def index():
    resp = make_response("<html><body><h1>DAST Demo</h1><a href='/about'>About</a></body></html>")
    resp.set_cookie("session_id", "abc123", httponly=True, secure=True, samesite="Lax")
    return resp

@app.route("/about")
def about():
    return "<html><body><p>About this demo app.</p><a href='/'>Home</a></body></html>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

4. **Restart and rescan AFTER the fix:**

```bash
docker restart flask-demo && sleep 15
cd ~/dast-lab
docker run --rm --network dast-lab -v "$(pwd)/reports:/zap/wrk:rw" -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://flask-demo:5000 -r after.html -J after.json
```

5. Compare `before.json` and `after.json`:

```bash
for f in before after; do echo "== $f"; jq -r '.site[].alerts[] | "\(.riskdesc)  \(.name)"' reports/$f.json | sort; done
```

**Expected outcome:** Most header and cookie alerts **disappear** after the fix. Some Low alerts may remain (for example, the development server's `Server` header, or HTTPS-only controls such as HSTS, which do not apply to plain HTTP). You can explain which remaining alerts are acceptable here and what you would do differently in production (a production server, HTTPS, HSTS).

### Lab 7: DAST in GitHub Actions

**Objective:** Run a ZAP baseline scan in a pipeline and make it block merges.

> [!NOTE]
> Use a **test repository** with the small Flask app from Lab 6 and a simple `Dockerfile`. For example: `FROM python:3.12-slim`, `RUN pip install flask`, `COPY app.py .`, `EXPOSE 5000`, `CMD ["python","app.py"]`. Adjust ports in the workflow to match (`5000`).

**Tasks:**

1. Push the app, its `Dockerfile`, and a `.zap/rules.tsv` containing a few `FAIL` rules (from Lab 5) to a repository.
2. Create `.github/workflows/dast-zap.yml` from section 11 (Option 2 gives full control). Change the port to `5000`.
3. Open a pull request using the **insecure** version of `app.py` and watch the job **fail** because FAIL rules fired.
4. Download the **zap-reports** artifact and read the report.
5. Push the **fixed** version, and confirm the job **passes** (or is only unstable on warnings).
6. Make the job a **required status check** in your ruleset (Module 03, section 4.5).

**Expected outcome:** An insecure pull request is blocked by DAST. A fixed pull request can merge. You can explain why the workflow starts the app, waits for it, and always cleans up.

### Lab 8: DAST in Jenkins

**Objective:** Add a ZAP stage that fails the build or marks it unstable.

**Tasks:**

1. Use a Jenkins server whose agent has **Docker** installed, and install the **HTML Publisher** plugin.
2. Add the `Jenkinsfile` from section 12 and a `.zap/rules.tsv` to your repository.
3. Create a **Pipeline** job (Pipeline script from SCM) and run it with the **insecure** app.
4. Confirm the **DAST - ZAP Baseline** stage fails and **Deploy** does not run.
5. Change one `FAIL` rule to `WARN` and rebuild. The build should become **unstable** (yellow).
6. Fix the app and rebuild. The pipeline should pass.
7. Download the archived report from the build page.

**Expected outcome:** You can explain the three outcomes (pass, unstable, fail) and how ZAP's exit codes map to them.

### Final Cleanup

```bash
docker rm -f juice-shop flask-demo 2>/dev/null
docker network rm dast-lab 2>/dev/null
```

---

## 15. Best Practices

### Scanning Safely

| Practice | Why It Matters |
| :--- | :--- |
| **Get permission and define scope** | Legal protection and clear boundaries. |
| **Use test or staging environments** | Active scans modify data and add load. |
| **Use fake data and disposable accounts** | No real user data is touched. |
| **Notify the team and monitoring owners** | Prevents false alarms and incident-response panic. |
| **Exclude dangerous URLs** | Logout, payment, "delete all", email-sending endpoints. |
| **Take backups or use resettable environments** | You can recover after an active scan. |
| **Limit scan time and rate** | Prevents denial of service by scanner. |
| **Never scan third-party sites** you do not control | Illegal and unethical, even if it is "just a quick test". |

### Getting Good Results

| Practice | Why It Matters |
| :--- | :--- |
| **Start with the baseline scan** | Fast wins with no attack risk. |
| **Use the AJAX Spider for JavaScript apps** | Otherwise coverage is poor. |
| **Scan authenticated areas** with test accounts | Most real functionality is behind login. |
| **Import API definitions** | Gives full coverage of API endpoints. |
| **Verify important findings manually** | Avoids wasting time on false positives. |
| **Test with several roles** | Finds access-control problems. |
| **Rescan after every fix** | Proves the issue is truly gone. |

### Running DAST in CI/CD

| Practice | Why It Matters |
| :--- | :--- |
| **Baseline on every PR, full scan on a schedule** | Balances speed and depth. |
| **Time-box active scans** (`maxScanDurationInMins`) | Pipelines must finish. |
| **Define a gate with a rules file or `exitStatus`** | A scan without a gate is only advice. |
| **Pin the ZAP image version** | Reproducible results. Upgrade deliberately. |
| **Pin or SHA-lock GitHub Actions** | Supply-chain safety (Module 03). |
| **Make the check required** | Otherwise it can be skipped. |
| **Fail loudly when the scan cannot reach the target** | A failed scan must not look like a clean scan. |
| **Always stop and clean up the test app** | No leftover vulnerable containers. |
| **Keep reports as artifacts** | Evidence for auditors and developers. |

### Protecting the Tooling and the Results

| Practice | Why It Matters |
| :--- | :--- |
| **Treat reports as sensitive** | They may contain tokens, cookies, internal URLs. |
| **Store credentials in secrets** | Never in plan files, rules files, or logs. |
| **Protect the rules file and pipeline files** (CODEOWNERS) | Prevents quietly weakening the gate. |
| **Do not expose ZAP's proxy or API** | Use API keys and localhost binding. |
| **Remove the ZAP root certificate** from browsers when finished | Prevents impersonation risk. |
| **Document every IGNORE** with a reason and review date | Accepted risk must be intentional. |

### Combine With the Rest of Your Pipeline

```text
Gitleaks (M03) + SonarQube (M04) + Dependency-Check (M05)   -> run on every pull request
                         |
                Build and deploy to a TEST environment
                         |
                  ZAP baseline (M06)                          -> every build
                  ZAP full scan (M06)                         -> nightly
                         |
        Container scanning (M07) + IaC scanning (M09) + runtime monitoring (M12)
```

### Know the Limits

- A **clean ZAP report** means "ZAP found nothing it knows how to find", not "the application is secure".
- DAST cannot see **business logic flaws**, most **authorization** problems, or code it never reached. Combine it with SAST, code review, threat modeling, and periodic manual penetration tests.

---

## 16. Knowledge Check

1. What is DAST, and why is it called a "black-box" test?
2. Give three differences between DAST and SAST.
3. Why can DAST not replace SCA, and why can SCA not replace DAST?
4. Name the main parts of an HTTP request and an HTTP response.
5. What is the difference between a `401` and a `403` status code?
6. Why are query parameters, headers, and cookies all considered attack surface?
7. What three protections does TLS provide, and what does HSTS do?
8. Explain the purpose of the `HttpOnly`, `Secure`, and `SameSite` cookie flags.
9. What is the difference between reflected and stored XSS?
10. What is IDOR, and why do automated scanners often miss it?
11. Name five security headers and the risk each one reduces.
12. What does ZAP's intercepting proxy do, and why must you be careful with its root certificate?
13. What is the difference between passive and active scanning? Which is safe to run against production, and why?
14. What do the three packaged scans (`zap-baseline.py`, `zap-full-scan.py`, `zap-api-scan.py`) each do?
15. Why does a traditional spider find very little in a single-page application, and what fixes that?
16. What is a ZAP context, and why is "Protected" mode useful?
17. What do ZAP exit codes `0`, `1`, `2`, and `3` mean?
18. How does a rules file (`rules.tsv`) turn a scan into a security gate? Why must changes to it be reviewed?
19. What is the Automation Framework, and what does the `exitStatus` job do?
20. Why must a pipeline start the application and wait for it before running ZAP?
21. Why should full active scans run on a schedule instead of on every pull request?
22. How do you decide whether an alert is a false positive? How should you record the decision?
23. After fixing a finding, what must you do before closing it?
24. Why should ZAP reports be treated as sensitive files?
25. Give two examples of problems DAST cannot find, and the other module or practice that covers each.

---

## 17. Official References

### ZAP Documentation

- ZAP documentation home: <https://www.zaproxy.org/docs/>
- Download ZAP: <https://www.zaproxy.org/download/>
- ZAP Docker overview: <https://www.zaproxy.org/docs/docker/>
- Baseline scan: <https://www.zaproxy.org/docs/docker/baseline-scan/>
- Full scan: <https://www.zaproxy.org/docs/docker/full-scan/>
- API scan: <https://www.zaproxy.org/docs/docker/api-scan/>
- Automation Framework: <https://www.zaproxy.org/docs/automate/automation-framework/>
- Automation Framework `exitStatus` job: <https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-exitstatus/>
- ZAP official Docker image: <https://github.com/zaproxy/zaproxy/pkgs/container/zaproxy>

### GitHub Actions

- ZAP Baseline Action: <https://github.com/zaproxy/action-baseline>
- ZAP Full Scan Action: <https://github.com/zaproxy/action-full-scan>
- ZAP API Scan Action: <https://github.com/zaproxy/action-api-scan>

### Practice Targets

- OWASP Juice Shop: <https://owasp.org/www-project-juice-shop/>
- Juice Shop source and docs: <https://github.com/juice-shop/juice-shop>

### Standards and Learning Resources

- OWASP Top 10: <https://owasp.org/www-project-top-ten/>
- OWASP Web Security Testing Guide: <https://owasp.org/www-project-web-security-testing-guide/>
- OWASP Secure Headers Project: <https://owasp.org/www-project-secure-headers/>
- OWASP Cheat Sheet Series: <https://cheatsheetseries.owasp.org/>
- MDN: HTTP overview: <https://developer.mozilla.org/en-US/docs/Web/HTTP>
- CWE (Common Weakness Enumeration): <https://cwe.mitre.org/>

### Related Modules in This Repository

- [Module 03: Git, GitHub and Secret Security](../03-git-github-and-secret-security/README.md) for required checks and protected pipelines.
- [Module 04: Static Application Security Testing](../04-static-application-security-testing-sast/README.md) for analyzing source code.
- [Module 05: Software Composition Analysis and SBOM](../05-software-composition-analysis-sca-and-sbom/README.md) for dependency risk.
- [Module 07: Docker and Container Security](../07-docker-and-container-security/README.md) for securing the images you scan.

> [!NOTE]
> Tool names, image names, action versions, rule IDs, and menu paths change over time. When something in this module differs from what you see, check the official documentation above.

---

## 18. Module Completion Checklist

Tick each box when you can do it **without looking at the notes**.

### Concepts

- [ ] I can explain DAST in my own words and why it is called black-box testing.
- [ ] I can compare DAST, SAST, and SCA, and say what each finds and misses.
- [ ] I can read a raw HTTP request and response and name their parts.
- [ ] I can explain what HTTPS, TLS, and HSTS do.
- [ ] I can explain the cookie flags `HttpOnly`, `Secure`, and `SameSite`.
- [ ] I can describe SQL injection, XSS, CSRF, IDOR, and security misconfiguration, and how each is fixed.
- [ ] I can name the OWASP Top 10 categories and say which ones DAST finds well.

### ZAP Skills

- [ ] I can run ZAP from Docker and from the desktop (if installed).
- [ ] I can explain passive vs. active scanning and when each is appropriate.
- [ ] I can explain the traditional spider, the AJAX Spider, contexts, and scope.
- [ ] I can run a baseline scan, a full scan, and an Automation Framework plan.
- [ ] I can read an HTML and JSON report and triage alerts by risk and confidence.
- [ ] I can reproduce a finding manually with `curl` or ZAP.

### CI/CD and Gates

- [ ] I can start an application inside a pipeline, wait for it, scan it, and clean up.
- [ ] I can run ZAP in GitHub Actions and in Jenkins.
- [ ] I can build a security gate using a rules file, `exitStatus`, or a `jq` script.
- [ ] I can map ZAP exit codes to pass, unstable, and fail.
- [ ] I can explain why the rules file and pipeline files must be protected.

### Remediation and Safety

- [ ] I can add security headers and safe cookie settings.
- [ ] I can fix a finding, rescan, and prove it is gone.
- [ ] I only scan systems I own or have written permission to test.
- [ ] I treat reports as sensitive and clean up lab containers and certificates.

### Labs

- [ ] Lab 1: Built the lab and explored HTTP
- [ ] Lab 2: First baseline scan
- [ ] Lab 3: Proxy, explore, and spider (optional)
- [ ] Lab 4: Time-boxed active scan
- [ ] Lab 5: Triage and security gate
- [ ] Lab 6: Find, fix, and verify
- [ ] Lab 7: DAST in GitHub Actions
- [ ] Lab 8: DAST in Jenkins

---

## Summary

In this module, you learned how to test a **running** application the way an attacker would:

- **DAST** tests from the outside without source code. It finds runtime and configuration issues that SAST and SCA cannot see, but it needs a deployed application and cannot point to a line of code.
- **HTTP knowledge** is the foundation. Every URL part, header, cookie, and body field is an input that a scanner can manipulate.
- **ZAP** works as an intercepting proxy with a passive scanner (safe, observes) and an active scanner (attacks, test environments only), plus spiders to discover the application.
- The **packaged scans** (`baseline`, `full`, `api`) and the **Automation Framework** make ZAP easy to run in pipelines.
- **Reports** list alerts by risk and confidence. You must **triage**, reproduce, fix, and **rescan**.
- **Security gates** (rules files, `exitStatus`, or custom scripts) turn a scan into a decision that can **block** risky builds.
- **Safe practice** means permission, scope, test environments, protected rules files, and treating reports as sensitive.

In the next module, you will secure the **containers** that package and run your application: building safer Docker images and scanning them for vulnerabilities.

---

## Next Module

➡️ [Module 07: Docker and Container Security](../07-docker-and-container-security/README.md)

[⬅️ Previous: Module 05: Software Composition Analysis and SBOM](../05-software-composition-analysis-sca-and-sbom/README.md) | [🏠 Main README](../README.md)

---

<div align="center">

**Learn. Secure. Automate. Deploy. 🛡️**

</div>
