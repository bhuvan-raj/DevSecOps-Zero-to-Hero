# Module 03: Git, GitHub & Secret Security 🔐

## Overview

Git and GitHub are essential components of modern DevOps workflows. However, insecure repository configurations, exposed credentials, and compromised CI/CD workflows can introduce serious security risks.

This module focuses on securing Git repositories, protecting GitHub access, detecting exposed secrets, and preventing credentials from entering source code and Git history.

**Primary tool:** `Gitleaks`

> [!NOTE]
> This module assumes that you already understand Git, GitHub repositories, branches, pull requests, and CI/CD workflows.

> [!IMPORTANT]
> **Lab safety rules for this module:**
> - Use a **test repository that contains no real data**, and **fake credentials only**. The labs generate throwaway secrets for you.
> - **Never** commit a real password, token, or key to practice, not even in a private repo.
> - Branch protection on a **private** repository needs GitHub Pro, Team, or Enterprise (students can get Pro through the GitHub Student Developer Pack). On a Free account, use a **public** test repository and keep it free of anything sensitive. The randomly generated fake tokens in these labs are harmless, but never replace them with real ones.

## 🎯 Learning Objectives

By completing this module, you will be able to:

- Understand common Git and GitHub security risks.
- Apply repository access controls and branch protection.
- Identify hardcoded credentials in source code.
- Scan Git repositories and commit history using Gitleaks.
- Prevent accidental secret commits using Git hooks.
- Integrate secret scanning into GitHub Actions.
- Understand the correct response to leaked credentials.
- Apply security controls to pull requests and CI/CD workflows.
- Create, use, and revoke personal access tokens (PATs) safely.
- Create branch protection rules and rulesets step by step.
- Enable Dependabot, secret scanning, push protection, and CODEOWNERS.
- Follow a complete runbook for securing a new repository.

## 📚 Table of Contents

- [01. Git and GitHub Security Fundamentals](#01-git-and-github-security-fundamentals)
- [02. Common Repository Security Risks](#02-common-repository-security-risks)
- [03. Understanding Secrets](#03-understanding-secrets)
- [04. GitHub Repository Security](#04-github-repository-security)
- [05. Git History and Secret Exposure](#05-git-history-and-secret-exposure)
- [06. Introduction to Gitleaks](#06-introduction-to-gitleaks)
- [07. Installing Gitleaks](#07-installing-gitleaks)
- [08. Scanning Git Repositories](#08-scanning-git-repositories)
- [09. Preventing Secret Commits](#09-preventing-secret-commits)
- [10. Integrating Gitleaks with GitHub Actions](#10-integrating-gitleaks-with-github-actions)
- [11. Handling Exposed Secrets](#11-handling-exposed-secrets)
- [12. Secure CI/CD and Repository Best Practices](#12-secure-cicd-and-repository-best-practices)
- [13. Hands-On Labs](#13-hands-on-labs)
- [14. Knowledge Check](#14-knowledge-check)
- [15. Summary](#15-summary)

---

## 01. Git and GitHub Security Fundamentals

### Git vs. GitHub: Two Different Things

Students often mix these up, and the difference matters for security.

| | **Git** | **GitHub** |
| :--- | :--- | :--- |
| **What it is** | A version control tool that runs on your computer | A website and platform that hosts Git repositories |
| **Handles** | Commits, branches, history | Accounts, access control, pull requests, Actions, security features |
| **Security role** | Stores every version of every file, **forever** | Decides **who** can read, write, and approve changes |

> **Key idea:** Git itself has **no login system**. It does not check who you are. Anyone can run `git config user.name "Anyone"` and create a commit that *claims* to be from someone else. GitHub adds authentication (proving who you are) and authorization (deciding what you may do).

### Three Facts That Shape Git Security

1. **Git remembers everything.** Every commit ever made stays in the history. Deleting a file in a new commit does **not** erase it from older commits.
2. **Git is distributed.** Every clone contains the *entire* history. If a secret reached any clone, fork, or backup, deleting it from the main repo does not make it disappear from those copies.
3. **Commit identity is not proof.** The author name and email on a commit can be typed by anyone. Only **signed commits** provide proof.

### How People and Tools Prove Who They Are

| Method | Used For | Security Notes |
| :--- | :--- | :--- |
| **Password + 2FA / passkey** | Logging in to github.com | Always turn on two-factor authentication. |
| **SSH key** | `git clone`, `git push` over SSH | Strong when the private key is protected by a passphrase. |
| **Personal access token (PAT)** | Git over HTTPS, API, scripts | Prefer **fine-grained** tokens with short expiry and minimal scope. See section 04 for how to create one. |
| **Deploy key** | A single server pulling from one repo | Read-only by default. Scope is limited to one repository. |
| **`GITHUB_TOKEN`** | GitHub Actions workflows | Created automatically per run and expires when the run ends. |
| **GitHub App** | Integrations and automation | Fine-grained permissions and short-lived tokens. |

### Where Security Fits

```text
Developer laptop        GitHub platform              CI/CD and deployment
-----------------       ------------------------     ----------------------
Secrets in files   -->  Repo access and roles   -->  Workflow permissions
Git hooks               Branch protection            Third-party actions
Signed commits          Secret scanning              Secrets in pipelines
SSH keys / tokens       Pull request reviews         Artifact integrity
```

> [!NOTE]
> **Shared responsibility:** GitHub secures its platform. **You** are responsible for how your repositories, access, workflows, and secrets are configured.

---

## 02. Common Repository Security Risks

Most repository breaches are not clever hacks. They are **simple mistakes** that were not caught in time.

| Risk | Example | Possible Impact | Main Control |
| :--- | :--- | :--- | :--- |
| **Hardcoded secrets** | A cloud key written directly in `config.py` | Attacker takes over cloud resources | Secret scanning, secret managers |
| **Committed `.env` files** | `.env` with database password pushed to Git | Database access | `.gitignore`, pre-commit hooks |
| **Public by accident** | A private project made public | Source code and secrets exposed | Visibility controls, review before changing |
| **Unprotected `main` branch** | Anyone with write access pushes straight to `main` | Unreviewed or malicious code reaches production | Branch protection |
| **Excessive access** | Every developer is an admin | One stolen account harms everything | Least privilege roles |
| **Stolen tokens** | A PAT with full access leaks | Attacker acts as the developer | Fine-grained, expiring tokens |
| **Unsigned or spoofed commits** | Someone sets another person's email on a commit | Fake attribution, hard to audit | Signed commits |
| **Compromised third-party actions** | A popular action is hijacked | Secrets stolen from your pipeline | Pin versions, allow-list actions |
| **Script injection in workflows** | Pull request title runs as a shell command | Pipeline takeover | Safe workflow patterns |
| **Over-privileged `GITHUB_TOKEN`** | Workflow can write to everything | Larger damage if the workflow is abused | `permissions:` set to least privilege |
| **Forgotten accounts** | Ex-employee still has access | Insider or stolen-credential risk | Regular access reviews |

### A Real-World Reminder

In March 2025, a widely used third-party GitHub Action (`tj-actions/changed-files`) was compromised. The malicious version printed secrets from workflow runs into build logs. Projects that referenced the action by a movable tag were exposed. This is why **pinning actions** and **limiting what secrets a workflow can see** matter, and you will learn both in this module.

### What Attackers Do With Leaked Secrets

- Automated bots scan public repositories continuously and can find exposed keys **within minutes** of a push.
- Stolen cloud keys are often used to launch expensive resources (for example, cryptocurrency mining) or to read private data.
- Leaked tokens allow attackers to push malicious code or read private repositories.

> [!WARNING]
> "Nobody will find it" is not a security control. Assume that any secret that touches a public repository is already stolen.

---

## 03. Understanding Secrets

### What Is a Secret?

A **secret** is any value that **proves identity or grants access**. If someone else obtains it, they can act as you or your application.

### Common Types of Secrets

| Type | Examples |
| :--- | :--- |
| **Passwords** | Database passwords, admin passwords |
| **API keys** | Payment, email, maps, and AI service keys |
| **Access tokens** | GitHub tokens, Slack tokens, OAuth tokens |
| **Cloud credentials** | AWS access keys, Azure service principal secrets, GCP service account keys |
| **Private keys** | SSH private keys, TLS private keys, signing keys |
| **Connection strings** | `postgres://user:password@host/db` |
| **Webhook URLs** | Slack or Discord webhook URLs (anyone with the URL can post) |
| **Config files with secrets** | `.env`, `kubeconfig`, `terraform.tfstate`, `*.tfvars` |

> [!TIP]
> Terraform **state files** (`terraform.tfstate`) often contain plaintext secrets, such as database passwords. They should never be committed to Git.

### What Secrets Look Like

Many providers give their secrets a recognizable shape, and that is how scanners find them.

| Provider | Typical Pattern (shortened for illustration) |
| :--- | :--- |
| AWS access key ID | Starts with `AKIA` followed by 16 characters |
| GitHub personal access token | Starts with `ghp_` followed by 36 characters |
| Slack bot token | Starts with `xoxb-` |
| Stripe live secret key | Starts with `sk_live_` |
| Google API key | Starts with `AIza` |
| Private key file | Begins with `-----BEGIN ... PRIVATE KEY-----` |

### How Secrets End Up in Repositories

| Mistake | Example |
| :--- | :--- |
| Hardcoding "just for testing" | `password = "Summer2024!"` in source code |
| Committing a config file | `.env`, `config.json`, or `secrets.yml` added with `git add .` |
| Copying a working command | A script containing a real token in a `curl` command |
| Docker builds | `ENV API_KEY=...` or `ARG TOKEN=...` in a Dockerfile (it stays in image layers) |
| Notebooks and documentation | A real key pasted into a README or a Jupyter notebook output |
| Debug output | Logs, screenshots, or error messages containing tokens |
| Infrastructure code | Passwords in Terraform variables or Kubernetes manifests |

### Where Secrets Should Live Instead

```text
BAD    password = "MyRealPassword"            <- in source code

BETTER password = os.environ["DB_PASSWORD"]   <- read from the environment

BEST   Secret manager (for example HashiCorp Vault, covered in Module 11)
       or GitHub Actions secrets for pipelines
```

### Keeping Secret Files Out of Git

Add them to `.gitignore` **before** your first commit:

```gitignore
# Environment and secret files
.env
.env.*
!.env.example
*.pem
*.key
id_rsa
id_ed25519

# Terraform
*.tfstate
*.tfstate.*
*.tfvars
.terraform/
```

A safe pattern is to commit a template with **fake values**, so teammates know what to configure:

```text
# .env.example  (safe to commit)
DB_HOST=localhost
DB_USER=appuser
DB_PASSWORD=change-me
```

> [!CAUTION]
> `.gitignore` only affects **untracked** files. If `.env` was already committed, adding it to `.gitignore` does nothing. Stop tracking it with `git rm --cached .env`. Remember that the old commits still contain it (see section 05).

---

## 04. GitHub Repository Security

GitHub gives you many protections, but **most of them are switched off or left at weak defaults until you configure them**. This section explains each control and shows the exact steps to set it up.

> [!NOTE]
> GitHub changes its menus and plan rules from time to time. If a button has moved or has a slightly different name, look for the same idea nearby or check GitHub's documentation. The concepts stay the same. Paths below are written like **Settings → Branches**, meaning "click Settings, then Branches".

### 4.1 What Do You Need? Plans and Availability

Before you start, check which features your account can use. This is the most common reason students say "I can't find that setting".

| Feature | Public repository | Private repository on Free plan | Private repository on Pro / Team / Enterprise |
| :--- | :---: | :---: | :---: |
| Branch protection and rulesets | ✅ | ❌ | ✅ |
| Dependabot alerts and updates | ✅ | ✅ | ✅ |
| Secret scanning and push protection | ✅ | ❌ | Paid add-on (GitHub Secret Protection) |
| Code scanning with CodeQL | ✅ | ❌ | Paid add-on (GitHub Code Security) |
| Two-factor authentication, SSH keys, tokens | ✅ | ✅ | ✅ |

> [!TIP]
> **Students:** the GitHub Student Developer Pack gives you GitHub Pro, which unlocks branch protection for private repositories. Without it, practise on a **public test repository that contains no real data**. This table reflects the plans at the time of writing, so verify it on GitHub's pricing and documentation pages.

---

### 4.2 Secure Your Account

Your account is the key to everything. If an attacker takes it over, branch protection and scanners will not help you.

#### Step 1: Turn On Two-Factor Authentication (2FA)

1. Click your **profile picture** (top right) and choose **Settings**.
2. In the left sidebar, click **Password and authentication**.
3. Under **Two-factor authentication**, click **Enable two-factor authentication**.
4. Choose a method:
   - **Passkey or security key** (strongest, resists phishing).
   - **Authenticator app** (for example, an app that shows 6-digit codes).
   - **GitHub Mobile** (approve sign-ins on your phone).
   - SMS text messages are the weakest option. Use them only as a last resort.
5. **Download your recovery codes** and store them in a password manager. Without them, losing your device can lock you out.

#### Step 2: Add an SSH Key for Git Access

SSH keys let you push and pull without typing a password or token.

1. On your computer, create a key pair (use a **passphrase** when asked):

```bash
ssh-keygen -t ed25519 -C "your-email@example.com"
```

2. Show the **public** key (the file ending in `.pub`) and copy it:

```bash
cat ~/.ssh/id_ed25519.pub
```

3. In GitHub, go to **Settings → SSH and GPG keys → New SSH key**.
4. Enter a **Title** (for example, `work-laptop`), set **Key type** to **Authentication Key**, paste the public key, and click **Add SSH key**.
5. Test the connection:

```bash
ssh -T git@github.com
```

You should see a message like `Hi <username>! You've successfully authenticated, but GitHub does not provide shell access.`

> [!CAUTION]
> Only ever share the **`.pub`** file. The private key (no extension) must never leave your computer or be committed to a repository.

---

### 4.3 Personal Access Tokens (PATs)

#### What Is a PAT?

A **personal access token (PAT)** is a long, random string that works **like a password for programs and scripts**. You use it when a tool needs to talk to GitHub on your behalf, for example `git push` over HTTPS, the GitHub API, or automation scripts.

> **Analogy:** your password is the master key to your whole house. A PAT is a **hotel key card**: you can limit which rooms it opens, and you can make it **expire** or cancel it at any time, without changing your master key.

GitHub no longer accepts your account password for Git operations over HTTPS. You must use a token (or SSH, or a credential manager that handles this for you).

#### Why PATs Are Risky

A PAT acts **as you**. Anyone who steals it can do whatever the token allows: read private code, push changes, or delete repositories. PATs are also a classic thing to leak into code, logs, and shell history, which is exactly what Gitleaks looks for.

#### Two Kinds of PATs

| | **Fine-grained token** (recommended) | **Token (classic)** |
| :--- | :--- | :--- |
| **Access to repositories** | Only the repositories you choose | **All** repositories your account can reach (with the `repo` scope) |
| **Permissions** | Detailed (for example, Contents: read only) | Broad "scopes" (for example, `repo`, `workflow`) |
| **Expiration** | **Required** (maximum is set by GitHub or your organization) | Optional, and you can pick "no expiration" (avoid this) |
| **Organization control** | Admins can require approval and restrict them | Admins can restrict or block them |
| **Token prefix** | `github_pat_...` | `ghp_...` |
| **When to use** | Almost always | Only when a tool does not support fine-grained tokens |

You will also see other GitHub token prefixes in the wild. Knowing them helps you recognize leaks:

| Prefix | Token Type |
| :--- | :--- |
| `ghp_` | Personal access token (classic) |
| `github_pat_` | Fine-grained personal access token |
| `gho_` | OAuth app access token |
| `ghu_` | GitHub App user token |
| `ghs_` | GitHub App installation token (the `GITHUB_TOKEN` in Actions looks like this) |
| `ghr_` | Refresh token |

#### How to Create a Fine-Grained PAT (Recommended)

1. Click your **profile picture → Settings**.
2. In the left sidebar, scroll to the bottom and click **Developer settings**.
3. Click **Personal access tokens → Fine-grained tokens**.
4. Click **Generate new token**.
5. Fill in the form:
   - **Token name:** something descriptive, such as `laptop-secure-repo-lab`.
   - **Expiration:** choose the **shortest time that works** (7 or 30 days is good for learning). Avoid long or custom far-future dates.
   - **Description:** write what the token is for, so you remember later.
   - **Resource owner:** you, or an organization that you belong to.
6. Under **Repository access**, choose **Only select repositories**, then pick the specific repository (for example `secure-repo-lab`). Avoid **All repositories** unless you truly need it.
7. Under **Permissions → Repository permissions**, grant only what is needed. For example, to clone and push to the repo:
   - **Contents:** *Read and write*
   - **Metadata:** *Read-only* (added automatically and required)
   - Add **Pull requests: Read and write** only if your tool must open pull requests.
   - Leave everything else on **No access**.
8. Click **Generate token**.
9. **Copy the token right now.** GitHub shows it **only once**. Store it in a password manager.

> [!NOTE]
> If the resource owner is an organization, an owner may need to **approve** your token before it works. Fine-grained tokens also do not support every API feature yet, which is the main reason classic tokens still exist.

#### How to Create a Classic PAT (Only If Required)

1. **Settings → Developer settings → Personal access tokens → Tokens (classic)**.
2. Click **Generate new token → Generate new token (classic)**.
3. Enter a **Note** describing the purpose.
4. Set an **Expiration**. Do not choose "No expiration".
5. Select the **smallest set of scopes** you need.
6. Click **Generate token** and copy it immediately (it is shown only once).

| Common Scope | What It Allows | Risk |
| :--- | :--- | :--- |
| `public_repo` | Access to public repositories | Lower |
| `repo` | **Full control of all private and public repositories you can access** | **High** |
| `workflow` | Edit GitHub Actions workflow files | High (pipeline takeover) |
| `read:packages` / `write:packages` | Download or publish packages | Medium |
| `delete_repo` | Delete repositories | **Very high** |
| `admin:org` | Manage organization settings | **Very high** |

#### How to Use a PAT

**Option 1: Git over HTTPS.** When Git asks for credentials, enter your **username** and paste the **token as the password**:

```bash
git clone https://github.com/<username>/secure-repo-lab.git
# Username: <your GitHub username>
# Password: <paste the token, NOT your account password>
```

Tell Git to remember the credential securely, so you do not paste it every time:

```bash
# Keep it in memory for one hour (Linux)
git config --global credential.helper 'cache --timeout=3600'
```

On Windows and macOS, **Git Credential Manager** or the system keychain does this safely for you.

**Option 2: GitHub CLI (easiest and safest).** The CLI signs you in through the browser and stores the token in your system's secure storage:

```bash
gh auth login
gh auth status
```

**Option 3: GitHub API from a script.** Read the token into an environment variable without typing it into your command history:

```bash
read -rs GITHUB_TOKEN        # paste the token, then press Enter (nothing is displayed)
export GITHUB_TOKEN

curl -s -H "Authorization: Bearer $GITHUB_TOKEN" \
     -H "X-GitHub-Api-Version: 2022-11-28" \
     https://api.github.com/user
```

> [!CAUTION]
> **Never** put a token inside the remote URL, such as `https://<TOKEN>@github.com/...`. It would be saved in plain text in `.git/config`, shown in process lists, and easily copied into scripts. Never hardcode a token in source code. Use an environment variable or a secret store.

#### How to Revoke or Delete a PAT

1. **Settings → Developer settings → Personal access tokens**.
2. Open **Fine-grained tokens** or **Tokens (classic)**, whichever the token belongs to.
3. Find the token and click **Revoke** (fine-grained) or **Delete** (classic).
4. Confirm.

Do this immediately if the token leaks, is no longer needed, or belongs to a laptop that was lost. The token stops working right away.

#### PAT Best Practices

- Prefer **fine-grained** tokens, limited to **specific repositories** and **minimum permissions**.
- Always set a **short expiration** and calendar a reminder to rotate it.
- Use **one token per purpose or machine**, with a clear name, so you can revoke one without breaking everything.
- Store tokens in a **password manager** or secret manager, never in code, chat messages, or notes.
- Review **Developer settings** regularly and delete tokens you do not recognize or use.
- Do not use your personal token for shared automation. Use a **GitHub App**, **deploy key**, or the built-in **`GITHUB_TOKEN`** in Actions instead.
- If a token leaks, follow the response plan in section 11: **revoke it first**.

#### Which Credential Should I Use?

| Situation | Best Choice |
| :--- | :--- |
| Developer pushing from a laptop | **SSH key**, or GitHub CLI / credential manager |
| Script on your own machine calling the API | **Fine-grained PAT** with minimum permissions |
| A server that only needs to **pull** one repository | **Read-only deploy key** |
| A GitHub Actions workflow in the same repo | Built-in **`GITHUB_TOKEN`** with a `permissions:` block |
| A pipeline deploying to a cloud provider | **OIDC short-lived credentials** (Module 10), not stored keys |
| Shared automation across many repositories | **GitHub App** |

---

### 4.4 Control Who Has Access

Give people **the lowest role that lets them do their job**.

| Role | Can Do | Typical Person |
| :--- | :--- | :--- |
| **Read** | View and clone | Reviewers, stakeholders |
| **Triage** | Manage issues and pull requests, cannot push code | Support or project managers |
| **Write** | Push branches, open pull requests | Developers |
| **Maintain** | Manage the repository without sensitive settings | Team leads |
| **Admin** | Full control, including security settings and deletion | Very few people |

> [!NOTE]
> Repositories owned by a **personal account** have only two levels: the owner, and collaborators (who get write access). Roles such as Triage and Maintain exist for repositories owned by an **organization**.

#### Add a Collaborator or Team

1. Open the repository and go to **Settings → Collaborators** (personal repo) or **Settings → Collaborators and teams** (organization repo).
2. Click **Add people** (or **Add teams**).
3. Search for the user or team, choose the **role**, and send the invitation.

To **remove** access, use the same page and click the delete (trash) icon next to the person.

#### Organization-Level Settings (for Organization Owners)

Go to your **organization → Settings**, then:

1. **Authentication security → Require two-factor authentication** for everyone in the organization.
2. **Member privileges → Base permissions:** set to **No permission** or **Read**, so people only get more access through teams.
3. **Personal access tokens:** require **approval** for fine-grained tokens, and restrict or block classic tokens if your team does not need them.
4. Review the **Audit log** regularly to see who changed access and settings.

#### Good Habits

- Use **teams** instead of granting access person by person.
- Keep **admins** to a minimum.
- Review **outside collaborators** and **deploy keys** every few months.
- **Remove access immediately** when someone leaves the project.
- Think carefully before changing a repository from **private to public**: **Settings → General → Danger Zone → Change visibility**. Scan the full history with Gitleaks first.

---

### 4.5 Branch Protection Rules and Rulesets

#### What Is Branch Protection?

**Branch protection** stops people from changing an important branch (usually `main`) carelessly or maliciously. Without it, anyone with write access can push code straight to `main`, rewrite its history, or delete it, and nobody reviews anything.

GitHub offers two ways to do this:

| | **Branch protection rules** (classic) | **Rulesets** (newer) |
| :--- | :--- | :--- |
| **Where** | Settings → Branches | Settings → Rules → Rulesets |
| **Rules per branch** | One rule per branch pattern | Several rulesets can apply and combine |
| **Bypass control** | A simple "include administrators" setting | A detailed bypass list by role or team |
| **Testing** | None | Enforcement modes (for example, Active or Evaluate on some plans) |
| **Recommendation** | Fine for simple cases | **Preferred for new projects** |

#### What Each Setting Does

| Setting | What It Prevents |
| :--- | :--- |
| **Require a pull request before merging** | Direct pushes to `main` that skip review |
| **Required approvals** (1 or more) | One person merging unreviewed code |
| **Dismiss stale approvals when new commits are pushed** | Getting approval for safe code, then adding something malicious |
| **Require review from Code Owners** | Changes to sensitive paths without the right reviewer |
| **Require conversation resolution** | Merging while review comments are unresolved |
| **Require status checks to pass** | Merging when tests or the **Gitleaks scan** fail |
| **Require branches to be up to date** | Merging code that was tested against an old base |
| **Require signed commits** | Commits with unverified author identity |
| **Require linear history** | A messy history with merge commits (optional) |
| **Restrict deletions** | Accidentally deleting `main` |
| **Block force pushes** | Rewriting or erasing history on `main` |
| **Do not allow bypassing** (classic) / empty bypass list (rulesets) | Admins skipping every rule |

#### Create a Ruleset (Recommended), Step by Step

1. Open your repository and click **Settings**.
2. In the left sidebar, click **Rules → Rulesets**.
3. Click **New ruleset → New branch ruleset**.
4. Enter a **Ruleset name**, for example `protect-main`.
5. Set **Enforcement status** to **Active**.
6. Leave the **Bypass list** empty for now. Add roles or teams only when there is a real need, and keep that list tiny.
7. Under **Target branches**, click **Add target** and choose **Include default branch** (or **Include by pattern** and enter `main`).
8. Under **Branch rules**, tick:
   - **Restrict deletions**
   - **Block force pushes**
   - **Require a pull request before merging**, then set **Required approvals** to `1`, tick **Dismiss stale pull request approvals when new commits are pushed**, tick **Require review from Code Owners**, and tick **Require conversation resolution before merging**
   - **Require status checks to pass**, then click **Add checks** and select your **Gitleaks** job (see the tip below), and tick **Require branches to be up to date before merging**
   - Optional: **Require signed commits** (only after everyone has set up signing, see 4.7)
9. Click **Create**.

> [!TIP]
> **The status check search box is empty?** GitHub only lists checks that have **run recently** (about the last 7 days). Create the Gitleaks workflow from section 10 first, let it run once on a pull request or push, then come back and add it as a required check.

#### Create a Classic Branch Protection Rule, Step by Step

1. Open the repository and click **Settings → Branches**.
2. Click **Add branch protection rule** (it may be labelled **Add classic branch protection rule**).
3. In **Branch name pattern**, enter `main`.
4. Tick **Require a pull request before merging**, set **Required number of approvals** to `1`, and tick **Dismiss stale pull request approvals when new commits are pushed** and **Require review from Code Owners**.
5. Tick **Require status checks to pass before merging**, search for **Gitleaks**, select it, and tick **Require branches to be up to date before merging**.
6. Tick **Require conversation resolution before merging**.
7. Tick **Do not allow bypassing the above settings** (this makes the rules apply to administrators too).
8. Make sure **Allow force pushes** and **Allow deletions** stay **unticked**.
9. Click **Create** (or **Save changes**).

#### Test That It Works

Try to push straight to `main`:

```bash
echo "test" >> notes.txt
git add notes.txt
git commit -m "Test direct push"
git push origin main
```

You should see an error like one of these:

```text
remote: error: GH013: Repository rule violations found for refs/heads/main.      (rulesets)
remote: error: GH006: Protected branch update failed for refs/heads/main.          (classic rules)
```

That rejection means your protection is working.

#### The Normal Workflow on a Protected Branch

```bash
git checkout -b feature/add-notes     # 1. Work on a branch, never on main
git add notes.txt
git commit -m "Add notes"
git push -u origin feature/add-notes  # 2. Push the branch
# 3. On GitHub: open a Pull Request
# 4. Wait for the required checks (tests, Gitleaks) to turn green
# 5. A reviewer approves
# 6. Click "Merge pull request"
```

> [!NOTE]
> **Working alone?** GitHub does not let you approve your own pull request. With a single account, set **Required approvals** to `0` while practising (keep "Require a pull request" and the status checks), or use a second account to review.

---

### 4.6 Define Code Owners

A **CODEOWNERS** file automatically requests a review from the right people when specific files change. Combined with the rule "Require review from Code Owners", it means that nobody can change sensitive files without the owner's approval.

1. In the repository, click **Add file → Create new file**.
2. Name it `.github/CODEOWNERS`.
3. Add rules (the **last matching rule wins**):

```text
# Default owner for everything
*                     @my-org/maintainers

# Pipeline files need security review
/.github/workflows/   @my-org/security-team

# Infrastructure code
/terraform/           @my-org/platform-team

# The scanner config itself (so nobody quietly weakens it)
/.gitleaks.toml       @my-org/security-team
```

4. Commit the file through a pull request.

For a personal repository, use usernames such as `@your-username` instead of teams. Owners must have **write access** to the repository.

---

### 4.7 Sign Your Commits

A **signed commit** shows a **Verified** badge on GitHub, proving the commit was really made by the owner of the key. You can sign with the SSH key you already use.

1. Add the same public key to GitHub as a **signing key**: **Settings → SSH and GPG keys → New SSH key**, set **Key type** to **Signing Key**, paste the public key, and save. (You can add the same key twice, once for authentication and once for signing.)
2. Tell Git to sign with it:

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
```

3. Make a commit and push it. On GitHub, open the commit and look for the green **Verified** label.
4. Once your whole team signs commits, you can turn on **Require signed commits** in your ruleset or branch protection rule.

---

### 4.8 Enable Dependabot

**Dependabot** watches your project's dependencies and warns you when one has a **known vulnerability**. It can even open pull requests to fix them. It has three parts, and you should turn on all three.

| Part | What It Does |
| :--- | :--- |
| **Dependabot alerts** | Warns you that a dependency has a known vulnerability. |
| **Dependabot security updates** | Automatically opens a pull request that upgrades a vulnerable dependency. |
| **Dependabot version updates** | Opens regular pull requests to keep **all** dependencies and GitHub Actions up to date, even if they are not vulnerable. |

#### Step 1: Turn On Alerts and Security Updates

1. Open your repository and click **Settings**.
2. In the left sidebar, open the security settings page. It is called **Advanced Security** (older interface: **Code security and analysis**).
3. Enable **Dependency graph**. Dependabot needs this to know what your project uses.
4. Enable **Dependabot alerts**.
5. Enable **Dependabot security updates**.

#### Step 2: Turn On Version Updates With a Config File

1. Create the file `.github/dependabot.yml`.
2. Add one entry for **every ecosystem** your repository uses:

```yaml
version: 2
updates:
  # Python dependencies (requirements.txt, pyproject.toml)
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5

  # Node.js dependencies (package.json)
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"

  # Docker base images (Dockerfile)
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"

  # GitHub Actions used in your workflows
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"

  # Terraform providers and modules
  - package-ecosystem: "terraform"
    directory: "/infra"
    schedule:
      interval: "weekly"
```

| Field | Meaning |
| :--- | :--- |
| `package-ecosystem` | The type of dependency (`pip`, `npm`, `docker`, `github-actions`, `terraform`, `maven`, `gomod`, and more). |
| `directory` | The folder where the dependency files live. |
| `schedule.interval` | How often to check (`daily`, `weekly`, or `monthly`). |
| `open-pull-requests-limit` | Maximum number of open Dependabot pull requests at once (stops pull request floods). |

3. Commit the file (through a pull request if `main` is protected).

#### Step 3: Review and Act on Alerts

1. Open the repository's **Security** tab and click **Dependabot** (under Vulnerability alerts).
2. Open an alert to see the vulnerable package, the **severity**, the affected versions, and the **fixed version**.
3. If Dependabot opened a pull request, check that tests pass, review it, and **merge it**.
4. If you cannot fix it right away, click **Dismiss** and choose an honest reason (for example, "Vulnerable code is not actually used"). Document why.
5. To see Dependabot's activity and any errors, open **Insights → Dependency graph → Dependabot**.

> [!TIP]
> Dependabot pull requests are **normal pull requests**. They run your CI checks and must pass your branch protection rules, including the Gitleaks scan. Do not merge them blindly. Review changes to dependencies like any other code. You will study dependency security in depth in Module 05.

---

### 4.9 Enable Secret Scanning and Push Protection

| Feature | What It Does |
| :--- | :--- |
| **Secret scanning** | Looks through your repository (code and history) for known secret formats and creates an **alert**. For many token types, GitHub also tells the provider so the token can be revoked automatically. |
| **Push protection** | Checks a push **before** it is accepted and **blocks it** if it contains a supported secret. |

#### Turn Them On

1. Open the repository and click **Settings → Advanced Security** (older interface: **Code security and analysis**).
2. Enable **Secret Protection** or **Secret scanning**, depending on how your plan names it.
3. Enable **Push protection**.
4. (Organizations) Turn these on for **all repositories** from the organization's **Settings → Advanced Security** page, and enable them for **new repositories by default**.

> [!NOTE]
> For **public** repositories these protections are available for free, and push protection is on by default for many secret types. For **private** repositories they need a paid GitHub security product (see 4.1). If you do not have it, **Gitleaks in CI and in a pre-commit hook gives you the same kind of protection for free**.

#### What a Developer Sees When a Push Is Blocked

```text
remote: error: GH013: Repository rule violations found for refs/heads/main.
remote: - GITHUB PUSH PROTECTION
remote:   Push cannot contain secrets
```

The developer should **remove the secret, rotate it if it was real**, amend the commit, and push again. If it is a false positive, GitHub offers a **bypass** with a reason, and the bypass is recorded.

> [!WARNING]
> If a blocked secret was **real**, treat it as exposed even though the push failed. It was typed into files on a developer machine and may exist in other places. Rotate it.

#### Review Secret Scanning Alerts

1. Open the **Security** tab and click **Secret scanning**.
2. For each alert, **revoke or rotate** the secret first (section 11).
3. Then close the alert as **Revoked**, **False positive**, **Used in tests**, or **Won't fix**, and add a comment.

---

### 4.10 Enable Code Scanning (Overview)

**Code scanning** finds security bugs in your own source code (SAST). GitHub's engine is called **CodeQL**. You will study SAST properly in Module 04, but you can enable it now:

1. Open **Settings → Advanced Security**.
2. Next to **Code scanning**, click **Set up → Default** and then **Enable**.
3. Results appear in the **Security** tab under **Code scanning**. Add the check as a **required status check** in your ruleset once it is running.

---

### 4.11 Add a Security Policy and Private Vulnerability Reporting

A **security policy** tells people how to report a vulnerability without posting it publicly.

1. Open the **Security** tab and click **Policy → Start setup** (this creates `SECURITY.md`).
2. Write a short policy:

```markdown
# Security Policy

## Supported Versions
Only the latest release receives security fixes.

## Reporting a Vulnerability
Please do NOT open a public issue.
Report vulnerabilities through the "Report a vulnerability" button
on the Security tab, or email security@example.com.
We will acknowledge your report within 3 working days.
```

3. Commit the file.
4. Go to **Settings → Advanced Security** and enable **Private vulnerability reporting**, so researchers can report problems privately inside GitHub.

---

### 4.12 Lock Down GitHub Actions Settings

#### Repository-Wide Defaults

1. Open **Settings → Actions → General**.
2. Under **Actions permissions**, choose **Allow OWNER, and select non-OWNER, actions and reusable workflows**. Then tick **Allow actions created by GitHub** and **Allow actions by Marketplace verified creators**, and add any other trusted actions to the list. This stops workflows from using random third-party actions.
3. Under **Fork pull request workflows from outside collaborators**, choose **Require approval for all outside collaborators** (or at least **first-time contributors**), so strangers cannot run code in your pipeline automatically.
4. Under **Workflow permissions**, choose **Read repository contents and packages permissions**. This makes the default `GITHUB_TOKEN` read-only.
5. Leave **Allow GitHub Actions to create and approve pull requests** **unticked**.
6. Click **Save**.

#### Store Pipeline Secrets Correctly

1. Open **Settings → Secrets and variables → Actions**.
2. Click **New repository secret**.
3. Enter a **Name** (for example `DEPLOY_TOKEN`) and the **Secret** value, then click **Add secret**.
4. Use it in a workflow without ever writing the value in the file:

```yaml
- name: Deploy
  env:
    DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
  run: ./deploy.sh
```

Once saved, nobody can read the value back in the UI, but they can replace it. Secrets are **not** passed to workflows triggered from forks by default.

#### Protect Production with Environments

1. Open **Settings → Environments → New environment** and name it `production`.
2. Tick **Required reviewers** and add the people who must approve a deployment.
3. Under **Deployment branches and tags**, choose **Selected branches and tags** and allow only `main`.
4. Add production secrets as **Environment secrets** here, instead of as repository secrets. Only jobs that target `production` can read them, and only after approval.

---

### 4.13 Other Useful Repository Settings

| Setting and Location | Why |
| :--- | :--- |
| **Settings → General → Pull Requests → Automatically delete head branches** | Removes merged branches so stale branches do not pile up. |
| **Settings → General → Features** (turn off Wikis, Projects, and Discussions you do not use) | Smaller attack surface and less clutter. |
| **Settings → Deploy keys** | Review every key. Keep them **read-only** unless a server must push. |
| **Settings → Webhooks** | Remove webhooks you do not recognize. Webhooks send repository events to external URLs. |
| **Settings → General → Danger Zone** | Know where visibility change, transfer, and delete live. Restrict who is an admin. |
| **Your account → Settings → Security log** (organizations: **Audit log**) | See sign-ins, token creation, and permission changes. Review regularly. |

---

### 4.14 Repository Hardening Runbook

Use this as a step-by-step order for every new repository. It takes about 15 to 20 minutes.

| Step | Action | Where | Section |
| :---: | :--- | :--- | :---: |
| **1** | Turn on 2FA and create an SSH key | Account settings | 4.2 |
| **2** | Create the repository, choose **private** unless it must be public | New repository | 4.4 |
| **3** | Add `.gitignore` (secrets, keys, state files) and `.env.example` **before** the first real commit | Repository files | 03 |
| **4** | Add collaborators through **teams** with the lowest role | Settings → Collaborators | 4.4 |
| **5** | Add `.github/CODEOWNERS` | Repository files | 4.6 |
| **6** | Add the **Gitleaks** workflow and let it run once | `.github/workflows/` | 10 |
| **7** | Create the **ruleset** for `main` with PR, approvals, and the Gitleaks check required | Settings → Rules | 4.5 |
| **8** | Enable **Dependabot** alerts, security updates, and add `dependabot.yml` | Settings → Advanced Security | 4.8 |
| **9** | Enable **secret scanning and push protection** (where available) | Settings → Advanced Security | 4.9 |
| **10** | Enable **code scanning** | Settings → Advanced Security | 4.10 |
| **11** | Lock down **Actions**: allowed actions, read-only token, fork approval | Settings → Actions → General | 4.12 |
| **12** | Add `SECURITY.md` and enable private vulnerability reporting | Security tab | 4.11 |
| **13** | Add a **pre-commit hook** on every developer machine | Local machine | 09 |
| **14** | **Test it**: try to push to `main` directly, and open a PR with a fake secret | Terminal and GitHub | 4.5, 13 |
| **15** | Schedule a review of access, tokens, deploy keys, and alerts every few months | Calendar | 4.13 |

---

## 05. Git History and Secret Exposure

This is the most important idea in the module.

### Deleting a Secret Does Not Remove It

Look at what happens when a developer notices a mistake:

```text
Commit A:  adds config.py containing a token       <- secret enters history
Commit B:  removes the token from config.py         <- "fixed"?
```

The *latest* version of the file is clean, but **Commit A still exists** and still contains the token. Anyone can read it:

```bash
git log -p                          # shows every change ever made
git show <commit-A-hash>            # shows exactly what Commit A contained
```

### Searching History Yourself

```bash
# Find commits where a text string was added or removed
git log --all -p -S "ghp_"

# Find every commit that ever touched a particular file, even deleted ones
git log --all --full-history -- .env

# Show all files that ever existed in the repo
git log --all --name-only --pretty=format: | sort -u
```

### Why Cleaning One Repository Is Not Enough

Once a secret is pushed, copies can exist in many places:

```text
Your repo ------------------------------+
Teammates' clones ----------------------+
Forks of your repo ----------------------+---> every one contains the secret
CI/CD caches and build logs ------------+
Backups and mirrors --------------------+
GitHub's cached views of old pull requests
```

### The Golden Rule

> [!CAUTION]
> **If a secret was ever committed and pushed, treat it as compromised. Rotate it first. Cleaning history is a second, optional step.**

Why "rotate first"? Because **rotation (replacing the secret and disabling the old one) is the only action that makes the leaked value useless**. Rewriting history only reduces further spread.

---

## 06. Introduction to Gitleaks

### What Is Gitleaks?

**Gitleaks** is a free, open-source command-line tool that finds hardcoded secrets in Git repositories, directories, and files. It is fast, easy to automate, and works well in pre-commit hooks and CI pipelines.

### How It Works

```text
Your repo  -->  Gitleaks reads files and Git history
                        |
                        v
           Rules look for secret patterns
           (regular expressions + keywords + entropy checks)
                        |
                        v
           Allowlists remove known false positives
                        |
                        v
        Findings are printed or saved as a report
        (exit code 1 if secrets are found, so pipelines can fail)
```

- **Rules** describe what a secret looks like (for example, the shape of an AWS key or a GitHub token).
- **Entropy** measures how random a string looks. Random-looking strings next to words like `key` or `token` are suspicious.
- **Allowlists** tell Gitleaks to ignore safe matches, such as test fixtures.

### What Gitleaks Can Scan

| Command | Scans | Typical Use |
| :--- | :--- | :--- |
| `gitleaks git` | A Git repository **including its history** | CI pipelines, full audits, pre-commit (staged changes) |
| `gitleaks dir` | A plain folder or file, ignoring Git | Checking files that are not in Git |
| `gitleaks stdin` | Text piped into Gitleaks | Scanning output from other tools |

> [!NOTE]
> The commands above are for Gitleaks **v8.19 and newer**. Older v8 versions used `detect` and `protect`. You may see those in older tutorials.
>
> | Older command (v8.18 and earlier) | Current command |
> | :--- | :--- |
> | `gitleaks detect --source .` | `gitleaks git .` |
> | `gitleaks detect --no-git --source .` | `gitleaks dir .` |
> | `gitleaks protect --staged` | `gitleaks git --pre-commit --staged` |

### Reading a Finding

```text
Finding:     GITHUB_TOKEN = "REDACTED"
Secret:      REDACTED
RuleID:      github-pat
Entropy:     5.1
File:        config.py
Line:        3
Commit:      4f8d2c1a9b7e...
Author:      Alice
Email:       alice@example.com
Date:        2025-01-10T09:30:00Z
Fingerprint: 4f8d2c1a9b7e...:config.py:github-pat:3
```

| Field | Meaning |
| :--- | :--- |
| **RuleID** | Which detection rule matched (tells you the secret type). |
| **File / Line** | Where it was found. |
| **Commit / Author / Date** | **Who added it and when.** This matters for investigating the exposure. |
| **Entropy** | How random the value looks. Higher usually means more likely to be a real secret. |
| **Fingerprint** | A unique ID for this finding. Used to ignore or baseline it later. |

### Limits to Understand

- Gitleaks finds **patterns**. It does **not** check whether a secret is still valid or active.
- It can produce **false positives** (harmless strings that look like secrets) and can **miss** secrets that do not match any rule.
- It is one layer of protection, not a replacement for good habits and a secret manager.

---

## 07. Installing Gitleaks

Pick **one** method.

### Option 1: Package Manager

```bash
# macOS or Linux with Homebrew
brew install gitleaks
```

### Option 2: Download the Binary (Linux)

Check the latest version on the [Gitleaks releases page](https://github.com/gitleaks/gitleaks/releases) and set `VERSION` to it (without the `v`).

```bash
VERSION=8.24.2
curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}/gitleaks_${VERSION}_linux_x64.tar.gz" -o gitleaks.tar.gz
tar -xzf gitleaks.tar.gz gitleaks
sudo mv gitleaks /usr/local/bin/
rm gitleaks.tar.gz
```

On ARM machines, replace `linux_x64` with `linux_arm64`.

### Option 3: Docker

```bash
docker pull zricethezav/gitleaks:latest

# Scan the current folder's repository
docker run --rm -v "$(pwd):/repo" zricethezav/gitleaks:latest git -v /repo
```

### Verify the Installation

```bash
gitleaks version
gitleaks --help
```

> [!TIP]
> Windows users can download the `.zip` from the releases page, or use a Windows package manager such as Scoop or winget, or run Gitleaks in Docker or WSL.

---

## 08. Scanning Git Repositories

### Your First Scan

Run these from the root of a repository:

```bash
# Scan the whole Git history, print details
gitleaks git . -v

# Scan only the files currently in the folder (ignores Git history)
gitleaks dir . -v
```

If nothing is found, you will see a message like `no leaks found`. If secrets are found, Gitleaks prints each finding and **exits with code 1**.

```bash
gitleaks git . ; echo "Exit code: $?"
```

| Exit Code | Meaning |
| :---: | :--- |
| `0` | No secrets found |
| `1` | Secrets found (this is what makes a CI job fail) |

### Useful Options

| Option | Purpose | Example |
| :--- | :--- | :--- |
| `-v`, `--verbose` | Show full finding details | `gitleaks git . -v` |
| `--redact` | **Hide the secret value** in output and reports | `gitleaks git . -v --redact` |
| `--report-path` | Save results to a file | `--report-path report.json` |
| `--report-format` | `json`, `csv`, `junit`, `sarif`, or `template` | `--report-format sarif` |
| `--config`, `-c` | Use a custom config file | `-c my-rules.toml` |
| `--log-opts` | Pass options to `git log` (limit which commits to scan) | `--log-opts="main..feature"` |
| `--baseline-path` | Ignore findings already in an earlier report | `--baseline-path old.json` |
| `--exit-code` | Change the exit code returned when leaks exist | `--exit-code 0` |
| `--no-banner` | Hide the logo (cleaner CI logs) | |

> [!IMPORTANT]
> **Use `--redact` in CI and shared logs.** Without it, Gitleaks prints the secret itself, which could leak it a second time into build logs.

### Scanning a Specific Range of Commits

```bash
# Only commits on a feature branch that are not on main
gitleaks git . -v --log-opts="main..feature-branch"

# Only the last 5 commits
gitleaks git . -v --log-opts="-5"
```

### Saving and Reading a Report

```bash
gitleaks git . --redact --report-format json --report-path gitleaks-report.json

# Count the findings and list rule types (requires jq)
jq length gitleaks-report.json
jq -r '.[].RuleID' gitleaks-report.json | sort | uniq -c
```

> [!WARNING]
> Reports can contain secrets if you did not use `--redact`. Treat report files as sensitive and **never commit them** to the repository.

### Handling False Positives

Not every finding is a real secret. When a finding is harmless, tell Gitleaks to ignore it **in a documented, reviewable way**. You have four options:

**1. Inline comment** for one line:

```python
example_value = "not-a-real-secret-just-a-sample"  # gitleaks:allow
```

**2. `.gitleaksignore` file** for a specific finding. Add the finding's **Fingerprint** on its own line:

```text
# .gitleaksignore
4f8d2c1a9b7e1234567890abcdef1234567890ab:tests/fixtures/sample.py:generic-api-key:12
```

**3. Allowlist in the config file** for paths or patterns (see below).

**4. Baseline** to ignore *everything already known* and only fail on **new** secrets. This is useful when adopting Gitleaks on an older repository:

```bash
# Step 1: record all current findings
gitleaks git . --report-path gitleaks-baseline.json

# Step 2: from now on, only report NEW findings
gitleaks git . --baseline-path gitleaks-baseline.json --report-path new-findings.json
```

> [!WARNING]
> A baseline does **not** make old secrets safe. Old findings must still be investigated and rotated. The baseline only helps you stop *new* leaks while you clean up.

### Custom Configuration: `.gitleaks.toml`

Gitleaks automatically uses a `.gitleaks.toml` file in the root of the scanned repository. Use it to add your own rules and allowlists while **keeping the built-in rules**.

```toml
# .gitleaks.toml
title = "My project Gitleaks config"

# Keep all the default rules
[extend]
useDefault = true

# Add a custom rule for an internal token format
[[rules]]
id = "acme-internal-token"
description = "Acme internal API token"
regex = '''acme_[a-z0-9]{32}'''
keywords = ["acme_"]

# Ignore known-safe locations
[allowlist]
description = "Known-safe paths"
paths = [
  '''(^|/)tests/fixtures/''',
]
```

| Part | What It Does |
| :--- | :--- |
| `[extend] useDefault = true` | Starts from Gitleaks' built-in rules instead of replacing them. |
| `[[rules]]` | Defines a custom detection rule. |
| `id`, `description` | Name and explanation shown in findings. |
| `regex` | The pattern that matches the secret. |
| `keywords` | Quick pre-filter words. Gitleaks only runs the regex if a keyword is present, which keeps scans fast. |
| `[allowlist]` | Paths, regexes, or commits to ignore. |

> [!CAUTION]
> Be careful with broad allowlists. Ignoring all `*.md` files or the whole `tests/` folder can hide **real** leaks. Make allowlists as narrow as possible and review changes to `.gitleaks.toml` like code (CODEOWNERS is perfect for this).

---

## 09. Preventing Secret Commits

Finding a secret after it is committed is good. **Stopping it before it is committed is much better.** Use several layers, because each one can fail.

### The Layers of Defense

```text
 1. Good habits         .gitignore, environment variables, secret managers
          |
          v
 2. Pre-commit hook     blocks the commit on the developer's machine
          |
          v
 3. Push protection     GitHub blocks the push (where available)
          |
          v
 4. CI scan on PRs      Gitleaks in GitHub Actions, as a REQUIRED check
          |
          v
 5. Scheduled full scan Regular scans of all history to catch what slipped through
```

### Layer 2: A Pre-Commit Hook

A **Git hook** is a script that Git runs automatically at certain moments. The `pre-commit` hook runs **before a commit is created**. If it exits with an error, the commit is blocked.

**Option A: a simple hook script**

```bash
# From the repository root
nano .git/hooks/pre-commit
```

```bash
#!/usr/bin/env bash
# Block commits that contain secrets
if ! command -v gitleaks >/dev/null 2>&1; then
  echo "gitleaks is not installed. Install it before committing." >&2
  exit 1
fi

gitleaks git --pre-commit --staged --redact --verbose
```

```bash
chmod +x .git/hooks/pre-commit
```

Now try to commit a file containing a secret. Gitleaks scans only the **staged changes**, prints the finding, and the commit is **blocked**.

**Sharing the hook with the whole team**

Files in `.git/hooks/` are **not** part of the repository, so teammates would not get them. Instead, keep the hook in a normal folder and tell Git to use it:

```bash
mkdir .githooks
mv .git/hooks/pre-commit .githooks/pre-commit
git config core.hooksPath .githooks
git add .githooks && git commit -m "Add shared pre-commit hook"
```

Each developer must run `git config core.hooksPath .githooks` once after cloning. Add it to your project's setup instructions.

**Option B: the `pre-commit` framework**

The [pre-commit](https://pre-commit.com/) tool manages hooks from a config file that is committed to the repository.

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.24.2          # use the latest release tag
    hooks:
      - id: gitleaks
```

```bash
pip install pre-commit
pre-commit install          # sets up the Git hook
pre-commit run --all-files  # test it on the whole repo
```

### Hooks Can Be Bypassed

```bash
git commit --no-verify -m "skip hooks"      # skips pre-commit hooks
```

Hooks also do not exist on a machine where nobody installed them. **A pre-commit hook is a helpful safety net, not a security control you can rely on alone.** That is why you also need server-side checks (push protection and CI scanning).

### Layer 3: GitHub Push Protection

When enabled, GitHub inspects pushes for supported secret formats and **rejects the push** with an explanation. Developers can remove the secret and push again. Teams can control who is allowed to bypass it, and bypasses are recorded.

---

## 10. Integrating Gitleaks with GitHub Actions

A CI scan runs on GitHub's servers, so it works **no matter what is installed on a developer's laptop**. Combined with branch protection, it can stop a leaking pull request from being merged.

### Option 1: Run the Gitleaks CLI Directly (recommended for learning)

This works for any account type and needs no license.

```yaml
# .github/workflows/secret-scan.yml
name: Secret Scan

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read            # least privilege: the job only needs to read code

jobs:
  gitleaks:
    name: Gitleaks
    runs-on: ubuntu-latest
    env:
      GITLEAKS_VERSION: "8.24.2"     # check the releases page for newer versions
    steps:
      - name: Check out code with full history
        uses: actions/checkout@v4
        with:
          fetch-depth: 0             # IMPORTANT: download all history, not just the latest commit

      - name: Install Gitleaks
        run: |
          curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" -o gitleaks.tar.gz
          tar -xzf gitleaks.tar.gz gitleaks
          sudo mv gitleaks /usr/local/bin/

      - name: Scan for secrets
        run: gitleaks git . --redact --verbose --no-banner --report-format json --report-path gitleaks-report.json

      - name: Upload report
        if: failure()                # only when secrets were found
        uses: actions/upload-artifact@v4
        with:
          name: gitleaks-report
          path: gitleaks-report.json
```

Line-by-line:

| Part | Why It Matters |
| :--- | :--- |
| `on: pull_request` | Scans every pull request **before** it can be merged. |
| `on: push` to `main` | Catches anything that reached `main` another way. |
| `permissions: contents: read` | The workflow's token can only read code. A compromised step cannot write. |
| `fetch-depth: 0` | By default, `actions/checkout` downloads only the latest commit. Gitleaks needs the **history** to find secrets in older commits. |
| `--redact` | Keeps secret values out of the public build log. |
| Non-zero exit code | When Gitleaks finds a secret it exits with `1`, so the **job fails**. |
| `upload-artifact` | Saves the (redacted) report so you can inspect it. |

### Option 2: The Official Gitleaks Action

```yaml
# .github/workflows/secret-scan.yml
name: Secret Scan
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  pull-requests: read

jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          # Organization accounts need a license key:
          # GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}
```

> [!NOTE]
> The official action is convenient, but its license terms depend on your account type (organization accounts need a license key). Check the action's documentation. The CLI approach in Option 1 avoids that dependency.

### Make the Scan Mandatory

A workflow that can be ignored is only advice. To enforce it:

1. Go to the repository **Settings → Branches** (or **Rules → Rulesets**).
2. Create or edit the rule for `main`.
3. Turn on **Require status checks to pass before merging**.
4. Add the **Gitleaks** job as a required check.

Now the "Merge" button stays blocked until the secret scan is green.

### Scheduled Full Scans

Add a schedule to periodically re-scan all history with the latest rules:

```yaml
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "0 3 * * 1"       # every Monday at 03:00 UTC
```

### What to Do When the Scan Fails

```text
Scan fails
    |
    v
Is it a REAL secret?
    |--- YES --> Do NOT just delete it. Follow section 11 (rotate first!).
    |
    '--- NO (false positive) --> Add a narrow allowlist, #gitleaks:allow comment,
                                 or .gitleaksignore entry, and have it reviewed.
```

---

## 11. Handling Exposed Secrets

When a secret leaks, **speed and order matter**. Follow these steps in this order.

### The Response Plan

| Step | Action | Why |
| :---: | :--- | :--- |
| **1** | **Revoke or rotate the secret immediately** | Makes the leaked value useless. Do this before anything else. |
| **2** | **Check for misuse** | Look at the service's audit logs (for example, cloud access logs) for activity you do not recognize since the leak. |
| **3** | **Remove the secret from the code** | Replace it with an environment variable or secret-manager reference. |
| **4** | **Decide whether to clean Git history** | Reduces ongoing exposure, but does not replace rotation. |
| **5** | **Find out how it happened and prevent a repeat** | Add the missing control: pre-commit hook, CI scan, training. |
| **6** | **Document the incident** | Who, what, when, what was done. This helps audits and future teams. |

### Step 1: Rotate

How you rotate depends on the secret:

| Secret | How to Rotate |
| :--- | :--- |
| **GitHub token** | Revoke it in GitHub settings and create a new one. |
| **Cloud access key** | Deactivate and delete the old key, create a new one, update the applications. |
| **Database password** | Change it in the database, update the application configuration. |
| **SSH or TLS private key** | Generate a new key pair, replace the public key or certificate everywhere, remove the old one. |
| **Webhook URL** | Regenerate the webhook. |

> [!CAUTION]
> **Do not skip rotation because you "deleted the commit".** Bots may have copied the secret within minutes. Assume it is compromised.

### Step 4: Cleaning Git History (When Needed)

Removing the secret from the current files is not enough, because history still has it (see section 05). The recommended tool is **`git filter-repo`**.

> [!WARNING]
> Rewriting history changes commit IDs, which affects everyone with a clone. Coordinate with your team first, and make a backup. Always **rotate the secret first**.

```bash
# Install
pip install git-filter-repo

# Work on a FRESH mirror clone, never your only copy
git clone --mirror https://github.com/my-org/my-repo.git
cd my-repo.git

# Option A: remove a file from ALL history
git filter-repo --path .env --invert-paths

# Option B: replace specific secret text everywhere in history
echo 'the-leaked-secret-value==>***REMOVED***' > replacements.txt
git filter-repo --replace-text replacements.txt
```

After rewriting:

```bash
# filter-repo removes the 'origin' remote as a safety measure, so add it back
git remote add origin https://github.com/my-org/my-repo.git

# Force-push all branches and tags (this overwrites the remote history)
git push --force --all
git push --force --tags
```

Then:

1. Tell every collaborator to **delete their old clones and clone again**, otherwise they may push the old history back.
2. Delete or clean any **forks** you control.
3. Remember that GitHub can keep hidden references (for example, to old pull requests) and cached views. For serious leaks, contact **GitHub Support** to ask for a cache purge.
4. **Re-run Gitleaks** on the cleaned repository to confirm nothing is left.

> [!NOTE]
> Another well-known tool is the BFG Repo-Cleaner. `git filter-repo` is the approach recommended by the Git project over the older `git filter-branch`.

### Do and Don't

| ✅ Do | ❌ Don't |
| :--- | :--- |
| Rotate first | Only delete the file and hope |
| Check logs for misuse | Assume nobody saw it |
| Use `--redact` when sharing scan results | Paste the real secret into a chat or ticket |
| Add a prevention control afterward | Blame the developer without fixing the process |
| Tell your security team early | Hide the incident |

---

## 12. Secure CI/CD and Repository Best Practices

### Secure GitHub Actions Workflows

Workflows run code with access to your repository and secrets, so treat workflow files like production code.

**1. Give the workflow the minimum permissions.**

```yaml
permissions:
  contents: read        # set at the top; grant more only on jobs that need it
```

**2. Do not trust input from pull requests, issues, or branch names.** Text like a PR title is controlled by whoever opens the PR. Putting it directly inside a shell command lets an attacker run their own commands (**script injection**).

```yaml
# ❌ UNSAFE: the title becomes part of the shell script
- run: echo "PR title is ${{ github.event.pull_request.title }}"

# ✅ SAFER: pass it as an environment variable, then use it as data
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "PR title is $PR_TITLE"
```

**3. Pin third-party actions to a full commit SHA**, not a movable tag. Tags such as `@v4` can be re-pointed to different code. A commit SHA cannot.

```yaml
# Tag: convenient but movable
- uses: actions/checkout@v4

# Commit SHA: immutable (add a comment so humans know the version)
- uses: actions/checkout@<full-40-character-commit-sha>   # v4.x.x
```

Let **Dependabot** keep pinned actions up to date:

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

**4. Handle secrets carefully.**

- Store pipeline secrets in **GitHub Actions secrets**, never in workflow files.
- Never `echo` a secret. GitHub masks known secret values in logs, but masking can be bypassed by transforming the value (for example, encoding it).
- Give secrets only to the **jobs or environments** that need them.
- Use **environments** with required reviewers to protect production secrets.
- Prefer **short-lived credentials via OpenID Connect (OIDC)** instead of storing long-lived cloud keys. You will study this in Module 10.

**5. Be careful with `pull_request_target` and untrusted code.** Workflows triggered by `pull_request_target` run with access to secrets and write permissions. **Never check out and run code from an untrusted fork** inside such a workflow.

### Repository Security Checklist

Use this as a review list for every new repository.

**Access and accounts**
- [ ] 2FA is required for all members.
- [ ] Access is given through teams, with the lowest role needed.
- [ ] Admins are few. Outside collaborators and deploy keys are reviewed.
- [ ] Personal access tokens are fine-grained and expire.

**Branches and reviews**
- [ ] `main` requires a pull request and at least one approval.
- [ ] Stale approvals are dismissed on new commits.
- [ ] Required status checks include the **Gitleaks** scan.
- [ ] Force pushes and branch deletion are blocked on `main`.
- [ ] `CODEOWNERS` covers workflows and infrastructure code.
- [ ] Signed commits are encouraged or required.

**Secrets**
- [ ] `.gitignore` excludes `.env`, keys, and Terraform state.
- [ ] Pre-commit hook with Gitleaks is set up.
- [ ] CI runs Gitleaks on every pull request.
- [ ] Push protection and secret scanning are on where available.
- [ ] A written secret-leak response plan exists.

**GitHub Actions**
- [ ] Default `GITHUB_TOKEN` permission is read-only.
- [ ] Workflows declare explicit `permissions:`.
- [ ] Third-party actions are pinned and from trusted sources.
- [ ] Untrusted input is never placed directly in `run:` commands.
- [ ] Production secrets are protected by environments and reviewers.

**Maintenance**
- [ ] Dependabot alerts and updates are enabled (including GitHub Actions).
- [ ] `SECURITY.md` explains how to report vulnerabilities.
- [ ] Access and audit logs are reviewed regularly, and leavers lose access promptly.

---

## 13. Hands-On Labs

> [!WARNING]
> All secrets in these labs are **randomly generated fakes** created on your own machine. Never replace them with real credentials. Do the GitHub labs in a **test repository** you own that contains no real data (see the plan note at the top of this module).

### Lab 1: Secure Your Account and a GitHub Repository

**Objective:** Follow the steps from section 04 end to end: protect your account, create and use a personal access token safely, and harden a repository.

> [!IMPORTANT]
> Use a **new test repository with no real data**. Branch protection on a **private** repository needs GitHub Pro, Team, or Enterprise (students can get Pro through the GitHub Student Developer Pack). On a Free account, make the test repository **public** and keep it free of anything sensitive.

#### Part A: Account and Token Security

**Tasks:**

1. Confirm **two-factor authentication** is enabled (**Settings → Password and authentication**).
2. Create an SSH key, add it to GitHub, and test it (section 4.2):

```bash
ssh-keygen -t ed25519 -C "your-email@example.com"
cat ~/.ssh/id_ed25519.pub          # paste into Settings → SSH and GPG keys
ssh -T git@github.com
```

3. Create a **new repository** called `secure-repo-lab` with a README.
4. Create a **fine-grained PAT** (section 4.3) with these settings:
   - Name: `secure-repo-lab-token`
   - Expiration: **7 days**
   - Repository access: **Only select repositories** → `secure-repo-lab`
   - Permissions: **Contents: Read and write** (Metadata: Read-only is automatic)
5. Test the token without writing it in your command history:

```bash
read -rs GITHUB_TOKEN ; export GITHUB_TOKEN

# This repo: should return 200
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/repos/<your-username>/secure-repo-lab

# Another repo of yours that the token was NOT granted: should return 404
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/repos/<your-username>/<another-repo>
```

6. **Revoke** the token (**Settings → Developer settings → Personal access tokens → Fine-grained tokens → Revoke**) and run the first `curl` again. It should now fail with `401`.

```bash
unset GITHUB_TOKEN
```

**Expected outcome:** The token works only for the repository you selected, and stops working immediately after you revoke it. You can explain why a fine-grained, short-lived token is safer than a classic token with the `repo` scope.

#### Part B: Harden the Repository

**Tasks:**

1. Clone the repository and add these files on a new branch (`harden-repo`):
   - `.gitignore` that excludes `.env`, `*.pem`, `*.key`, and `*.tfstate`
   - `.env.example` with fake placeholder values
   - `.github/CODEOWNERS` that makes you the owner of `/.github/`
   - `.github/dependabot.yml` for `pip` and `github-actions`
   - `SECURITY.md` with a short reporting policy
   - `requirements.txt` containing one deliberately **old** package, `requests==2.19.0`, so Dependabot has something to find

```bash
git clone git@github.com:<your-username>/secure-repo-lab.git
cd secure-repo-lab
git checkout -b harden-repo
mkdir -p .github
printf '.env\n*.pem\n*.key\n*.tfstate\n' > .gitignore
printf 'DB_PASSWORD=change-me\n' > .env.example
printf '/.github/ @<your-username>\n' > .github/CODEOWNERS
printf 'requests==2.19.0\n' > requirements.txt
cat > .github/dependabot.yml <<'EOF'
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
EOF
git add . && git commit -m "Add repository security baseline"
git push -u origin harden-repo
```

2. Open a pull request and merge it (do this **before** enabling the ruleset so that the merge is allowed).
3. Go to **Settings → Advanced Security** and turn on the **dependency graph, Dependabot alerts, Dependabot security updates**, and (where available) **secret scanning and push protection**.
4. Create a **ruleset** for `main` (section 4.5) with: restrict deletions, block force pushes, require a pull request (set approvals to `0` if you work alone), and dismiss stale approvals.
5. Try to push directly to `main`:

```bash
git checkout main && git pull
echo "test" >> notes.txt
git add notes.txt && git commit -m "Test direct push"
git push origin main
```

6. Wait a few minutes, then open **Security → Dependabot** and look for an alert about `requests`.

**Expected outcome:** The direct push to `main` is **rejected** (`GH013` or `GH006`). You must use a branch and a pull request instead. A Dependabot alert appears for the old `requests` version, and Dependabot may open a pull request to upgrade it. You can describe what each file and setting you added protects against.

> [!NOTE]
> **Going further:** Complete Lab 6 later in this module to add the Gitleaks workflow, then return to your ruleset and add **Gitleaks** as a **required status check**.

---

### Lab 2: Find Secrets with Gitleaks

**Objective:** Create a repository with leaked secrets and detect them.

**Tasks:**

```bash
# 1. Create a demo repository
mkdir ~/leaky-demo && cd ~/leaky-demo
git init -b main
git config user.name "Lab User"
git config user.email "lab@example.com"

# 2. Generate a FAKE GitHub-style token (random, not real)
FAKE_TOKEN="ghp_$(head -c 300 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 36)"

# 3. Create a file with a hardcoded secret
cat > config.py <<EOF
# Application settings
DEBUG = True
GITHUB_TOKEN = "$FAKE_TOKEN"
EOF

# 4. Generate a throwaway SSH private key and "accidentally" keep it in the repo
ssh-keygen -t ed25519 -N "" -f deploy_key -q
rm deploy_key.pub

# 5. Commit everything (the mistake!)
git add .
git commit -m "Add app config and deploy key"

# 6. Scan the history
gitleaks git . -v

# 7. Scan again with redaction and save a report
gitleaks git . --redact --report-format json --report-path ~/leaky-report.json
jq -r '.[] | "\(.RuleID)  \(.File):\(.StartLine)"' ~/leaky-report.json
```

**Expected outcome:** Gitleaks reports at least two findings (a GitHub token and a private key), shows the commit, file, and line, and exits with code 1. You can explain what each field in the finding means.

> [!NOTE]
> Placeholder keys copied from provider documentation (for example AWS's example key ending in `EXAMPLE`) are often deliberately ignored by Gitleaks. That is why this lab generates random values.

### Lab 3: Prove That History Keeps Secrets, Then Clean It

**Objective:** See why deleting a file is not enough, then remove the secret from history.

**Tasks:**

```bash
cd ~/leaky-demo

# 1. "Fix" the mistake the common (wrong) way: delete and commit
git rm config.py deploy_key
git commit -m "Remove secrets"

# 2. Scan the files only: looks clean
gitleaks dir . -v

# 3. Scan the history: the secrets are still there
gitleaks git . -v

# 4. Prove it with plain Git
git log --all --oneline --name-only
git log --all -p -S "ghp_" | head -20
```

Now clean the history using a **fresh clone** (a safe habit, and what `git filter-repo` expects):

```bash
# 5. Install filter-repo
pip install git-filter-repo

# 6. Clone the demo repo, then remove both files from all history
cd ~
git clone ~/leaky-demo leaky-clean
cd leaky-clean
git filter-repo --path config.py --path deploy_key --invert-paths

# 7. Verify
git log --all --oneline
gitleaks git . -v
```

**Expected outcome:** Step 2 reports no leaks while step 3 still reports them, proving history keeps secrets. After `git filter-repo`, the scan of `leaky-clean` is **clean**. Discuss: why must a real incident also include **rotation**?

### Lab 4: Custom Rules, Allowlists and Baselines

**Objective:** Teach Gitleaks about an internal secret format and handle false positives.

**Tasks:**

```bash
mkdir ~/rules-lab && cd ~/rules-lab
git init -b main
git config user.name "Lab User"
git config user.email "lab@example.com"

# 1. Create a custom config
cat > .gitleaks.toml <<'EOF'
title = "Lab config"

[extend]
useDefault = true

[[rules]]
id = "acme-internal-token"
description = "Acme internal API token"
regex = '''acme_[a-z0-9]{32}'''
keywords = ["acme_"]
EOF

# 2. Generate a fake internal token and commit it
ACME_TOKEN="acme_$(head -c 300 /dev/urandom | base64 | tr -dc 'a-z0-9' | head -c 32)"
echo "service_token = \"$ACME_TOKEN\"" > service.py
git add .
git commit -m "Add service config"

# 3. Detect it with the custom rule
gitleaks git . -v

# 4. Create a baseline of current findings, then rescan: nothing new is reported
gitleaks git . --report-path baseline.json
gitleaks git . --baseline-path baseline.json
echo "Exit code: $?"

# 5. Add a NEW secret and see that it is still caught
NEW_TOKEN="acme_$(head -c 300 /dev/urandom | base64 | tr -dc 'a-z0-9' | head -c 32)"
echo "other_token = \"$NEW_TOKEN\"" > other.py
git add other.py
git commit -m "Add another token"
gitleaks git . --baseline-path baseline.json -v

# 6. Practice the inline allow comment on a harmless sample line
echo "sample = \"$NEW_TOKEN\"  # gitleaks:allow" > sample.py
gitleaks dir sample.py -v
```

**Expected outcome:** The custom rule `acme-internal-token` detects the fake token. The baseline hides old findings but still catches the new one. The `#gitleaks:allow` line is ignored. You can explain the risks of overusing allowlists.

### Lab 5: Block Secrets with a Pre-Commit Hook

**Objective:** Prevent a secret from being committed, then see how a hook can be bypassed.

**Tasks:**

```bash
mkdir ~/hook-lab && cd ~/hook-lab
git init -b main
git config user.name "Lab User"
git config user.email "lab@example.com"
echo "# Hook lab" > README.md
git add README.md && git commit -m "Initial commit"

# 1. Install the hook
cat > .git/hooks/pre-commit <<'EOF'
#!/usr/bin/env bash
gitleaks git --pre-commit --staged --redact --verbose
EOF
chmod +x .git/hooks/pre-commit

# 2. Try to commit a fake secret
FAKE_TOKEN="ghp_$(head -c 300 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 36)"
echo "TOKEN = \"$FAKE_TOKEN\"" > app.py
git add app.py
git commit -m "Add app"            # should be BLOCKED

# 3. Fix it properly: read the secret from the environment instead
cat > app.py <<'EOF'
import os
TOKEN = os.environ["GITHUB_TOKEN"]
EOF
git add app.py
git commit -m "Read token from environment"     # should succeed

# 4. Show why hooks are not enough: bypass the hook
echo "TOKEN = \"$FAKE_TOKEN\"" > app.py
git add app.py
git commit --no-verify -m "Bypass the hook"      # succeeds!

# 5. Catch it afterwards by scanning history
gitleaks git . -v
```

**Expected outcome:** Step 2 is blocked, step 3 succeeds, step 4 shows the bypass, and step 5 shows that a **server-side CI scan** is still needed.

### Lab 6: Add Gitleaks to GitHub Actions

**Objective:** Make a pull request fail when it contains a secret.

**Tasks:**

1. In your `secure-repo-lab` test repository, create `.gitleaks.toml` with the custom `acme-internal-token` rule from Lab 4. (A custom pattern is used so that GitHub's own push protection does not interfere with the lab.)
2. Create `.github/workflows/secret-scan.yml` using **Option 1** from section 10.
3. Commit these files on a branch, open a pull request, and merge it once the scan passes.
4. Make **Gitleaks** a **required status check** for `main`.
5. Create a branch and add a fake token:

```bash
git checkout -b add-leak
ACME_TOKEN="acme_$(head -c 300 /dev/urandom | base64 | tr -dc 'a-z0-9' | head -c 32)"
echo "service_token = \"$ACME_TOKEN\"" > service.py
git add service.py
git commit -m "Add service token"
git push -u origin add-leak
```

6. Open a pull request and watch the **Gitleaks** check.
7. Fix it: remove the token and **rewrite the branch** so the secret is not left in the PR's history, or close the PR and open a clean one.

```bash
git reset --hard HEAD~1       # drop the bad commit from your local branch
git push --force-with-lease   # update the PR branch
```

**Expected outcome:** The pull request check **fails** and the merge button is blocked. After the leaking commit is removed, the check **passes**. Explain why `fetch-depth: 0` and `--redact` were used.

### Lab 7: Incident Response Exercise

**Objective:** Practice the correct order of response to a real-world leak.

**Scenario:** A developer pushed a commit to a **public** repository 20 minutes ago. It contains a cloud access key for a production account. The commit was then "fixed" by a second commit that deleted the key. A teammate noticed and reported it to you.

**Tasks:** Write a short incident plan (one page) that answers:

1. What is the **first** action you take, and why?
2. How do you decide whether the key was **misused**? Which logs do you check?
3. Is deleting the key from the latest commit enough? Explain.
4. How would you remove it from history, and what must you tell your team afterward?
5. Which **three controls** from this module would have prevented or caught it?
6. What would you record in the incident report?

**Expected outcome:** A plan that starts with **rotation**, includes log review, explains why history still contains the key, and lists preventive controls (pre-commit hook, push protection, required CI scan).

---

## 14. Knowledge Check

1. Why does Git history make deleting a secret in a later commit insufficient?
2. What is the difference between Git and GitHub when it comes to authentication?
3. Why can a commit's author name and email not be trusted as proof of identity? What helps?
4. Name five types of secrets and one place each might accidentally appear in a repository.
5. Why is adding a file to `.gitignore` not enough if it was already committed?
6. List four branch protection settings and the risk each one reduces.
7. Why must the Gitleaks check be a **required** status check to be effective?
8. What is the difference between `gitleaks git` and `gitleaks dir`?
9. Why do we use `--redact` when running Gitleaks in CI?
10. Why does the GitHub Actions workflow use `fetch-depth: 0`?
11. What are three ways to handle a Gitleaks false positive, and what is the danger of overusing allowlists?
12. What is a baseline in Gitleaks, and why does it not make old secrets safe?
13. Why can a pre-commit hook be bypassed, and what other controls cover that gap?
14. Put these incident response steps in order: clean Git history, rotate the secret, check logs for misuse, add a prevention control.
15. What is script injection in a GitHub Actions workflow, and how do you avoid it?
16. Why is pinning a third-party action to a commit SHA safer than using a version tag?
17. What is a personal access token, and why is it described as "a password for programs"?
18. Compare fine-grained tokens and classic tokens. Why are fine-grained tokens safer?
19. List the steps to create a fine-grained PAT that can push to only one repository. Which permissions would you grant?
20. Why should you never put a token in a Git remote URL, and what should you use instead?
21. What is the difference between a branch protection rule and a ruleset? Which would you choose for a new project, and why?
22. Why might the Gitleaks check not appear in the "required status checks" search box, and how do you fix that?
23. Name the three parts of Dependabot and what each one does.
24. How is GitHub push protection different from a Gitleaks pre-commit hook?
25. Which three Actions settings would you change first to make a repository safer by default?

---

## 15. Summary

In this module, you learned how to secure the place where your code and your pipelines begin: the Git repository.

- **Git remembers everything.** A secret that was committed once lives in history, in clones, and in forks. Treat it as compromised and **rotate first**.
- **Secrets belong in secret managers and environment variables**, never in source code. Keep secret files out of Git with `.gitignore` and templates such as `.env.example`.
- **GitHub gives you strong controls** (2FA, least-privilege roles, branch protection, CODEOWNERS, signed commits, secret scanning, push protection), but you must turn them on and configure them.
- **Gitleaks** finds secrets in files and in full history, supports custom rules, allowlists, and baselines, and fails a pipeline with exit code `1`.
- **Defense in depth works best:** good habits, then a pre-commit hook, then push protection, then a **required** CI scan, then scheduled full scans.
- **Tokens must be small, short-lived, and well stored.** Prefer fine-grained PATs limited to one repository, with an expiry date, and revoke them the moment they are no longer needed.
- **Protection must be switched on and tested.** Rulesets, CODEOWNERS, Dependabot, secret scanning, and Actions settings only help once you configure them. Use the hardening runbook (4.14) for every new repository.
- **CI/CD itself must be secured:** least-privilege tokens, pinned third-party actions, protected secrets, and safe handling of untrusted input.

In the next module, you will move from protecting secrets to analyzing the **code itself** for vulnerabilities using SonarQube.

### Quick Reference

| Task | Command or Action |
| :--- | :--- |
| Scan repo and full history | `gitleaks git . -v` |
| Scan files only (no history) | `gitleaks dir . -v` |
| Hide secret values in output | add `--redact` |
| Save a JSON report | `--report-format json --report-path report.json` |
| Scan staged changes (hook) | `gitleaks git --pre-commit --staged --redact -v` |
| Scan a commit range | `gitleaks git . --log-opts="main..feature"` |
| Ignore already-known findings | `--baseline-path baseline.json` |
| Ignore a single line | add `# gitleaks:allow` to the line |
| Use custom rules | `.gitleaks.toml` with `[extend] useDefault = true` |
| Stop tracking a committed file | `git rm --cached <file>` |
| Search history for a string | `git log --all -p -S "text"` |
| Remove a file from all history | `git filter-repo --path <file> --invert-paths` |
| Share hooks with a team | `git config core.hooksPath .githooks` |
| Skip hooks (avoid this) | `git commit --no-verify` |
| Create a fine-grained PAT | Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token |
| Create a branch ruleset | Repo Settings → Rules → Rulesets → New ruleset → New branch ruleset |
| Create classic branch protection | Repo Settings → Branches → Add branch protection rule |
| Enable Dependabot | Repo Settings → Advanced Security, plus `.github/dependabot.yml` |
| Enable secret scanning and push protection | Repo Settings → Advanced Security |
| Test an SSH key | `ssh -T git@github.com` |
| Revoke a PAT | Settings → Developer settings → Personal access tokens → Revoke / Delete |

---

## Next Module

➡️ [Module 04: Static Application Security Testing (SAST)](../04-static-application-security-testing-sast/README.md)

[⬅️ Previous: Module 02: Linux Security](../02-linux-security/README.md) | [🏠 Main README](../README.md)

---

<div align="center">

**Learn. Secure. Automate. Deploy. 🛡️**

</div>
