# Module 02: Linux Security 🐧🛡️

## Overview

Almost everything you will secure in this course runs on Linux: build servers, Docker hosts, Kubernetes nodes, and cloud virtual machines. If the Linux host underneath is weak, every security tool you add on top can be bypassed.

This module teaches you how to understand, harden, monitor, and audit a Linux system. Each section explains **what** a control is, **why** it matters, and **how** to apply it with real commands.

> [!NOTE]
> This module assumes you can already use the Linux command line (navigating directories, editing files, running commands with `sudo`). The goal is to add security knowledge on top of those skills.

> [!IMPORTANT]
> **Lab environment:** Practice only on a virtual machine or cloud instance that you own and can afford to break. Take a snapshot before starting. The commands in this module use **Ubuntu 22.04 / 24.04** (Debian family). Where Red Hat family systems (RHEL, Rocky, AlmaLinux, Fedora) differ, the difference is noted.

## 🎯 Learning Objectives

By completing this module, you will be able to:

- Explain the Linux attack surface and the principle of defense in depth.
- Manage users and groups using least privilege.
- Control access to files using permissions and ACLs.
- Find and assess risky SUID and SGID binaries.
- Configure `sudo` securely.
- Harden an SSH server.
- Understand and apply Linux capabilities.
- Secure processes and systemd services.
- Configure a host firewall with a default-deny policy.
- Read authentication logs and use `auditd` to track sensitive changes.
- Detect unauthorized file changes with AIDE.
- Keep a system patched.
- Audit a system with Lynis and act on the findings.

## 📚 Table of Contents

- [01. Linux Security Fundamentals](#01-linux-security-fundamentals)
- [02. Users, Groups and Least Privilege](#02-users-groups-and-least-privilege)
- [03. File Permissions and ACLs](#03-file-permissions-and-acls)
- [04. SUID, SGID and Sticky Bit](#04-suid-sgid-and-sticky-bit)
- [05. Sudo Security](#05-sudo-security)
- [06. SSH Hardening](#06-ssh-hardening)
- [07. Linux Capabilities](#07-linux-capabilities)
- [08. Process and Service Security](#08-process-and-service-security)
- [09. Host Firewall Security](#09-host-firewall-security)
- [10. Linux Logging and Auditing](#10-linux-logging-and-auditing)
- [11. File Integrity Monitoring](#11-file-integrity-monitoring)
- [12. Security Updates and Patch Management](#12-security-updates-and-patch-management)
- [13. Linux Security Auditing with Lynis](#13-linux-security-auditing-with-lynis)
- [14. Practical Labs](#14-practical-labs)
- [15. Knowledge Check](#15-knowledge-check)
- [16. Summary](#16-summary)

---

## 01. Linux Security Fundamentals

### What Does "Securing Linux" Mean?

Securing a system means protecting three things, often called the **CIA triad**:

| Property | Meaning | Linux Example |
| :--- | :--- | :--- |
| **C**onfidentiality | Only authorized people can read data. | Only the database user can read the database files. |
| **I**ntegrity | Data and programs cannot be changed without authorization. | An attacker cannot modify `/bin/ls` or `/etc/passwd`. |
| **A**vailability | The system works when it is needed. | A flood of connections cannot crash your SSH service. |

### What Is an Attack Surface?

The **attack surface** is the sum of all the places an attacker could try to get in. On a Linux server, that includes:

- Open network ports and the services listening on them.
- User accounts and their passwords or keys.
- Installed software and its vulnerabilities.
- Misconfigured file permissions.
- Powerful programs such as `sudo` and SUID binaries.

> **Rule of thumb:** every extra service, user, package, and open port is another door. **Fewer doors means fewer ways in.**

### Defense in Depth

No single control is perfect, so we stack several. Think of protecting a house: a fence, a locked door, an alarm, a safe inside, and a camera. If one fails, the others still help.

```text
  Network firewall / cloud security group
        |
        v
  Host firewall (ufw / nftables)
        |
        v
  SSH hardening (keys only, no root login)
        |
        v
  Least privilege (users, sudo, permissions, capabilities)
        |
        v
  Patching (fix known vulnerabilities)
        |
        v
  Monitoring and auditing (logs, auditd, AIDE)
```

### Everything Is a File

In Linux, files, directories, devices, and even running processes are exposed as files. That is why **file permissions** are one of the most important security tools in Linux.

### Hardening

**Hardening** means reducing the attack surface and tightening configuration so the system is harder to compromise. Hardening is not a one-time job. It is a repeating cycle:

```text
Baseline  ->  Harden  ->  Monitor  ->  Audit  ->  Fix  ->  (repeat)
```

### First Look at Your System

Run these commands to understand what you are protecting:

```bash
cat /etc/os-release       # Which Linux distribution and version?
uname -r                  # Which kernel version?
whoami                    # Which user am I?
id                        # My user ID, group ID, and group memberships
sudo ss -tulpn            # Which ports are listening, and which program owns each?
```

The `ss -tulpn` flags mean: **t**cp, **u**dp, **l**istening, **p**rocess, **n**umeric.

> [!TIP]
> If you see a port listening that you cannot explain, investigate it. Unknown listeners are a classic sign of a misconfiguration or a compromise.

---

## 02. Users, Groups and Least Privilege

### Principle of Least Privilege

Every user, program, and script should have **only the permissions it needs to do its job, and nothing more**. If an account is compromised, least privilege limits the damage.

### Where Linux Stores Account Information

| File | Purpose | Who Can Read It |
| :--- | :--- | :--- |
| `/etc/passwd` | List of user accounts | Everyone |
| `/etc/shadow` | Password hashes and password aging | Root (and the `shadow` group) |
| `/etc/group` | List of groups and their members | Everyone |

A line in `/etc/passwd` looks like this:

```text
alice:x:1001:1001:Alice Smith:/home/alice:/bin/bash
```

| Field | Value | Meaning |
| :--- | :--- | :--- |
| 1 | `alice` | Username |
| 2 | `x` | Password placeholder (the real hash is in `/etc/shadow`) |
| 3 | `1001` | User ID (UID) |
| 4 | `1001` | Primary group ID (GID) |
| 5 | `Alice Smith` | Comment (full name) |
| 6 | `/home/alice` | Home directory |
| 7 | `/bin/bash` | Login shell |

### UID Ranges

| UID | Type |
| :--- | :--- |
| `0` | **root**, the superuser. Full control of the system. |
| `1` to `999` | System accounts used by services (for example `www-data`, `sshd`). |
| `1000` and above | Regular human users. |

> [!WARNING]
> **Only one account should have UID 0.** Any other UID 0 account is a full backdoor.

### Managing Users

```bash
# Create a regular user with a home directory
sudo useradd -m -s /bin/bash alice
sudo passwd alice

# Create a service account (no home directory, cannot log in)
sudo useradd --system --no-create-home --shell /usr/sbin/nologin appsvc

# Add a user to a group (the -a is critical: it APPENDS)
sudo usermod -aG docker alice

# Lock and unlock an account
sudo usermod -L alice
sudo usermod -U alice

# Remove a user and their home directory
sudo userdel -r alice
```

> [!CAUTION]
> `usermod -G docker alice` (without `-a`) **replaces** all of alice's supplementary groups. Always use `-aG` to add a group.

### Password Aging

Use `chage` to force regular password changes and warn users in advance:

```bash
sudo chage -M 90 -m 1 -W 7 alice   # max 90 days, min 1 day, warn 7 days before expiry
sudo chage -l alice                # view the current settings
```

### Quick Account Security Checks

```bash
# 1. Which accounts have UID 0? (Only root should appear.)
awk -F: '$3 == 0 {print $1}' /etc/passwd

# 2. Which accounts have an EMPTY password? (Should return nothing.)
sudo awk -F: '$2 == "" {print $1}' /etc/shadow

# 3. Which accounts can log in with an interactive shell?
grep -vE '(nologin|false)$' /etc/passwd

# 4. Who is in the sudo (administrator) group?
getent group sudo        # On RHEL family: getent group wheel
```

### Best Practices

- Give every person their own named account. Never share accounts.
- Use `nologin` as the shell for service accounts.
- Lock or remove accounts for people who leave.
- Do not log in as root directly. Use a normal account and `sudo`.
- Review user and group membership regularly.

---

## 03. File Permissions and ACLs

### Reading Permissions

Run `ls -l` and you will see something like this:

```text
-rwxr-xr--  1  alice  developers  4096  Jan 10 09:30  deploy.sh
```

```text
-  rwx  r-x  r--
|   |    |    |
|   |    |    +-- Others (everyone else):  read only
|   |    +------- Group (developers):      read + execute
|   +------------ Owner (alice):           read + write + execute
+---------------- File type ( - = file, d = directory, l = link )
```

### Permission Values

| Permission | Symbol | Number | On a File | On a Directory |
| :--- | :---: | :---: | :--- | :--- |
| Read | `r` | 4 | View contents | List contents |
| Write | `w` | 2 | Modify contents | Create or delete files inside |
| Execute | `x` | 1 | Run as a program | Enter (`cd`) and access files inside |

Add the numbers to build a permission for each of the three groups (owner, group, others):

| Mode | Meaning | Typical Use |
| :---: | :--- | :--- |
| `600` | Owner read/write only | Private keys, secret files |
| `644` | Owner read/write, everyone else read | Normal files, config files |
| `640` | Owner read/write, group read | Files shared with one group |
| `700` | Owner full access only | Private directories (`~/.ssh`) |
| `755` | Owner full, everyone else read/execute | Programs, public directories |
| `777` | **Everyone can do everything** | **Almost never correct** |

### Changing Permissions and Ownership

```bash
chmod 600 secret.txt           # numeric mode
chmod u+x script.sh            # symbolic: add execute for the owner
chmod go-rwx private.txt       # remove all access for group and others
sudo chown alice:developers file.txt   # change owner and group
sudo chown -R appsvc:appsvc /var/lib/myapp   # recursive
```

### Important Files and Safe Permissions

| Path | Typical Safe Permission | Why |
| :--- | :--- | :--- |
| `/etc/passwd` | `644` (`root:root`) | Must be readable, never writable by others |
| `/etc/shadow` | `640` (`root:shadow`) on Debian/Ubuntu | Contains password hashes |
| `/etc/sudoers` | `440` (`root:root`) | Controls administrator access |
| `~/.ssh/` | `700` | SSH ignores or rejects unsafe key folders |
| `~/.ssh/id_ed25519` | `600` | Private key must stay private |
| `~/.ssh/authorized_keys` | `600` | Prevents others adding keys |

### umask: Default Permissions for New Files

The **umask** removes permissions from newly created files and directories.

| umask | New Files | New Directories | Meaning |
| :---: | :---: | :---: | :--- |
| `022` | `644` | `755` | Others can read (common default) |
| `027` | `640` | `750` | Others get **no** access (more secure) |
| `077` | `600` | `700` | Only the owner has access (most strict) |

```bash
umask          # show the current umask
umask 027      # set it for this shell session
```

### Finding Dangerous Permissions

```bash
# World-writable files (anyone can modify them)
find / -xdev -type f -perm -0002 2>/dev/null

# World-writable directories without the sticky bit
find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null

# Files with no owner (often left behind by deleted users)
find / -xdev -nouser -o -nogroup 2>/dev/null
```

### Access Control Lists (ACLs)

Standard permissions only allow **one owner, one group, and everyone else**. What if you need to give `alice` read access to a file owned by `bob`, without changing the group or opening it to everyone?

**ACLs** let you grant permissions to additional specific users or groups.

```bash
# Give user alice read+write on report.txt
setfacl -m u:alice:rw report.txt

# Give group auditors read-only access
setfacl -m g:auditors:r report.txt

# View the ACL
getfacl report.txt

# Remove alice's entry
setfacl -x u:alice report.txt

# Remove ALL ACL entries
setfacl -b report.txt
```

Sample output of `getfacl`:

```text
# file: report.txt
# owner: bob
# group: bob
user::rw-
user:alice:rw-
group::r--
group:auditors:r--
mask::rw-
other::---
```

> [!TIP]
> A `+` at the end of the permission string in `ls -l` (for example `-rw-rw-r--+`) means the file has an ACL.

**Default ACLs** on a directory are inherited by new files created inside:

```bash
setfacl -d -m g:devs:rwx /srv/project
```

---

## 04. SUID, SGID and Sticky Bit

Besides read, write, and execute, Linux has three **special permission bits**.

| Bit | Number | On a File | On a Directory |
| :--- | :---: | :--- | :--- |
| **SUID** (Set User ID) | `4` | Runs with the **file owner's** privileges | Ignored |
| **SGID** (Set Group ID) | `2` | Runs with the **file group's** privileges | New files inherit the directory's group |
| **Sticky bit** | `1` | Ignored | Only the file owner (or root) can delete files inside |

### Why Does SUID Exist?

Normal users must be able to change their own password, but passwords are stored in `/etc/shadow`, which only root can modify. The solution: the `passwd` program is owned by root and has the **SUID** bit set, so it runs *as root* while a normal user uses it.

```bash
ls -l /usr/bin/passwd
```

```text
-rwsr-xr-x 1 root root 59976 Nov 24  2022 /usr/bin/passwd
    ^
    The "s" in the owner's execute position means SUID is set
```

### Why Is SUID Dangerous?

A SUID-root program runs with **full root power**, no matter who starts it. If the program can be tricked into running other commands (for example, a text editor or file tool that allows a shell escape), a normal user can become root. This is called **privilege escalation**.

> Attackers look for SUID binaries first. A public catalog called [GTFOBins](https://gtfobins.github.io/) lists standard Linux programs and how each one can be abused when it has SUID, sudo, or capabilities set.

### Finding SUID and SGID Files

```bash
# Find all SUID files
find / -xdev -perm -4000 -type f 2>/dev/null

# Find all SGID files
find / -xdev -perm -2000 -type f 2>/dev/null

# Find both at once
find / -xdev -perm /6000 -type f 2>/dev/null
```

Expect to see legitimate entries such as `passwd`, `sudo`, `su`, `mount`, and `ping`. **Be suspicious** of anything unusual, especially tools like `find`, `vim`, `python`, `bash`, `cp`, or `nmap`, or any file in `/tmp`, `/home`, or `/var/tmp`.

### Setting and Removing the Bits

```bash
chmod u+s file      # set SUID    (or chmod 4755 file)
chmod g+s dir       # set SGID    (or chmod 2755 dir)
chmod +t dir        # set sticky  (or chmod 1777 dir)

chmod u-s file      # remove SUID
```

### Sticky Bit in Practice: `/tmp`

Everyone can write to `/tmp`, but you should not be able to delete **someone else's** files. The sticky bit enforces that.

```bash
ls -ld /tmp
```

```text
drwxrwxrwt 15 root root 4096 Jan 10 10:00 /tmp
         ^
         The "t" at the end is the sticky bit
```

### SGID on a Shared Directory

SGID on a directory is useful for team folders because every new file automatically belongs to the team's group:

```bash
sudo mkdir /srv/team
sudo chgrp developers /srv/team
sudo chmod 2775 /srv/team
```

### Reducing the Risk

- Keep a **baseline list** of SUID/SGID files and compare it regularly.
- Remove the SUID bit from programs that do not need it.
- Mount directories like `/tmp`, `/home`, and `/var` with the **`nosuid`** option so SUID is ignored there.
- Keep software patched, since vulnerabilities in SUID programs are especially serious.

---

## 05. Sudo Security

### What Is `sudo`?

`sudo` lets an authorized user run a command with another user's privileges (usually root), **without sharing the root password**. It also **logs** every use, which gives you accountability.

### The Sudoers File

Sudo rules live in `/etc/sudoers` and in files under `/etc/sudoers.d/`.

> [!CAUTION]
> **Never edit these files with a normal editor.** A syntax error can lock everyone out of `sudo`. Always use `visudo`, which checks syntax before saving.

```bash
sudo visudo                          # edit the main file
sudo visudo -f /etc/sudoers.d/deploy # create or edit a drop-in file (recommended)
```

### Reading a Sudo Rule

```text
deploy   ALL=(root)   /usr/bin/systemctl restart myapp, /usr/bin/systemctl status myapp
  |       |    |                        |
  |       |    |                        +-- WHAT commands are allowed
  |       |    +-- run AS which user
  |       +------- on which HOSTS (ALL = any)
  +--------------- WHO (a user, or %group for a group)
```

This rule lets the user `deploy` restart or check only the `myapp` service, and nothing else.

### Adding a User to the Admin Group

```bash
sudo usermod -aG sudo alice      # Debian / Ubuntu
sudo usermod -aG wheel alice     # RHEL / Rocky / Fedora
```

### Sudo Security Best Practices

**1. Grant specific commands, not everything.**

```text
# Risky: full root access without a password
%devs  ALL=(ALL) NOPASSWD: ALL

# Better: only what the team needs
%devs  ALL=(root) /usr/bin/systemctl restart myapp
```

**2. Never allow programs that can launch a shell.** Editors, pagers, and many tools can run commands from inside them. Allowing these with `sudo` is the same as giving full root.

```text
# DANGEROUS: vim, less, find, awk, python, man, and many more can spawn a root shell
alice  ALL=(root) /usr/bin/vim
```

**3. Be careful with wildcards.** A wildcard like `*` can be abused to add extra arguments.

**4. Avoid `NOPASSWD` unless necessary.** It is sometimes needed for automation, but limit it to specific, safe commands.

**5. Turn on extra logging.** Add these lines using `visudo`:

```text
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
```

### Useful Commands

```bash
sudo -l                    # what can I run with sudo?
sudo -l -U alice           # what can alice run?
sudo -k                    # forget cached sudo authentication
sudo grep sudo /var/log/auth.log | tail      # recent sudo usage (Debian/Ubuntu)
sudo journalctl _COMM=sudo --since today     # same, using the journal
```

Example log entry:

```text
Jan 10 10:15:01 server sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart myapp
```

This tells you **who** ran **what**, **as whom**, and **when**.

---

## 06. SSH Hardening

SSH (Secure Shell) is the main way administrators connect to Linux servers. Because it is exposed to the network, it is also the **most attacked service** on the internet. Servers with public IP addresses receive automated login attempts within minutes of going online.

### Step 1: Use Key-Based Authentication

SSH keys are far stronger than passwords. A key pair has two parts:

| Key | Location | Share It? |
| :--- | :--- | :--- |
| **Private key** | Your computer (`~/.ssh/id_ed25519`) | **Never** |
| **Public key** | Server (`~/.ssh/authorized_keys`) | Yes |

```bash
# On YOUR computer: create a key pair (ed25519 is modern and strong)
ssh-keygen -t ed25519 -C "alice@workstation"

# Copy the public key to the server
ssh-copy-id alice@server-ip

# Test logging in with the key
ssh alice@server-ip
```

> [!TIP]
> Protect your private key with a **passphrase** when `ssh-keygen` asks for one.

### Step 2: Harden the Server Configuration

> [!WARNING]
> **Do not lock yourself out.** Before disabling password login, confirm that key-based login works. Keep your current SSH session open while you test changes in a **second** terminal.

Create a hardening file. The `00-` prefix matters: on Ubuntu, files in `/etc/ssh/sshd_config.d/` are read in alphabetical order and **the first value found wins**, so your file must come before others (such as cloud-init files that may re-enable passwords).

```bash
sudo nano /etc/ssh/sshd_config.d/00-hardening.conf
```

```text
# Disable direct root login
PermitRootLogin no

# Keys only, no passwords
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no

# Limit guessing attempts and idle time
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

# Only these users may log in
AllowUsers alice deploy

# Turn off features you do not need
X11Forwarding no
```

| Setting | Why It Matters |
| :--- | :--- |
| `PermitRootLogin no` | Attackers always try the `root` username. Force them to also guess a real account. |
| `PasswordAuthentication no` | Removes password guessing (brute force) as an attack. |
| `MaxAuthTries 3` | Limits attempts per connection. |
| `AllowUsers` | An allow-list. Anyone not listed cannot log in, even with valid credentials. |
| `X11Forwarding no` | Reduces the attack surface if you do not need graphical forwarding. |
| `ClientAliveInterval` | Disconnects idle or dead sessions. |

### Step 3: Test and Apply

```bash
# 1. Check the syntax (no output means OK)
sudo sshd -t

# 2. Confirm the EFFECTIVE settings
sudo sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|maxauthtries|allowusers'

# 3. Apply the change
sudo systemctl reload ssh        # Debian/Ubuntu
sudo systemctl reload sshd       # RHEL family
```

Now open a **new terminal** and confirm you can still log in. Only then close your old session.

### Extra Protection

- **Fail2ban** watches logs and temporarily bans IP addresses that fail login repeatedly:

  ```bash
  sudo apt install fail2ban
  sudo systemctl enable --now fail2ban
  sudo fail2ban-client status sshd
  ```

- **Restrict SSH by source IP** using your firewall or cloud security group (see section 09).
- **Changing the SSH port** reduces log noise from bots but is **obscurity, not security**. Do not rely on it.
- Consider **multi-factor authentication** or an SSH certificate authority for larger teams.

---

## 07. Linux Capabilities

### The Problem with "Root"

Traditionally, a process was either **root** (all-powerful) or **not root** (limited). That is too coarse. A web server only needs to listen on port 80, but running it as root gives it the power to do *anything*.

### The Solution: Capabilities

Linux **capabilities** split root's power into about 40 small pieces. A program can be given **just the pieces it needs**.

| Capability | Allows | Risk Level |
| :--- | :--- | :---: |
| `CAP_NET_BIND_SERVICE` | Listen on ports below 1024 | Low |
| `CAP_CHOWN` | Change file ownership | Medium |
| `CAP_KILL` | Send signals to any process | Medium |
| `CAP_NET_ADMIN` | Change network configuration | High |
| `CAP_DAC_OVERRIDE` | Bypass file permission checks | High |
| `CAP_SETUID` | Change user IDs | High |
| `CAP_SYS_ADMIN` | A huge number of admin actions | **Very high** (often called "the new root") |

### Viewing Capabilities

```bash
# Capabilities of your current shell
capsh --print
getpcaps $$

# Find files that have capabilities assigned
getcap -r /usr/bin /usr/sbin 2>/dev/null

# Raw capability data of a process
grep Cap /proc/$$/status
```

### Example: Run a Web App on Port 80 Without Root

Without capabilities, you would need to run the app as root. With capabilities:

```bash
# Give ONLY the "bind low ports" power to this program
sudo setcap 'cap_net_bind_service=+ep' /opt/myapp/server

# Verify
getcap /opt/myapp/server

# Remove all capabilities from the file
sudo setcap -r /opt/myapp/server
```

The app now runs as a normal user but can still bind to port 80.

### Capabilities Can Be Dangerous Too

A capability such as `cap_setuid` placed on an interpreter (`python`, `perl`) or a general-purpose tool lets an attacker become root. Audit capabilities just as you audit SUID files:

```bash
getcap -r / 2>/dev/null
```

### Why This Matters for Containers

Docker and Kubernetes use the same capability system. Containers start with a limited default set, and good security practice is to **drop everything and add back only what is needed**:

```bash
docker run --cap-drop ALL --cap-add NET_BIND_SERVICE nginx
```

You will use this in the container and Kubernetes security modules.

---

## 08. Process and Service Security

### Know What Is Running

Every running program is a **process**, and every process runs as some **user**. Attackers who compromise a process inherit that user's permissions, so **never run services as root unless absolutely required**.

```bash
ps aux                              # all processes and their owners
ps -eo user,pid,ppid,cmd --sort=user | head -20
top                                 # live view (press q to quit)
sudo ss -tulpn                      # listening ports and owning processes
sudo lsof -i -P -n | grep LISTEN    # another view of listening ports
```

### Reduce the Attack Surface: Disable What You Do Not Need

```bash
# List services that start at boot
systemctl list-unit-files --state=enabled --type=service

# List services running right now
systemctl list-units --type=service --state=running

# Stop a service now AND prevent it starting at boot
sudo systemctl disable --now cups
```

Ask for every running service: **Do I need this? Does it need to be reachable from the network?** If not, disable it, or bind it to `127.0.0.1` (local only).

```bash
# Example: see whether a service listens on all interfaces or only locally
sudo ss -tulpn | grep -E '0.0.0.0|\[::\]|127.0.0.1'
```

| Listening Address | Meaning |
| :--- | :--- |
| `0.0.0.0` or `[::]` | Reachable from **any** network interface (exposed) |
| `127.0.0.1` | Reachable **only from this machine** (safer) |

### Hardening systemd Services

systemd can **sandbox** a service with a few lines in its unit file. Here is a hardened example:

```ini
# /etc/systemd/system/myapp.service
[Unit]
Description=My Web Application
After=network.target

[Service]
User=appsvc
Group=appsvc
ExecStart=/opt/myapp/server --port 8080
Restart=on-failure

# --- Security hardening ---
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/myapp
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
```

| Option | What It Does |
| :--- | :--- |
| `User=` / `Group=` | Runs the service as a **non-root** account. |
| `NoNewPrivileges=true` | The process (and its children) can never gain extra privileges, for example through SUID. |
| `PrivateTmp=true` | Gives the service its own private `/tmp`. |
| `PrivateDevices=true` | Hides most hardware devices from the service. |
| `ProtectSystem=strict` | Makes the entire filesystem **read-only** for the service. |
| `ProtectHome=true` | Hides `/home` from the service. |
| `ReadWritePaths=` | The only paths the service may write to. |
| `CapabilityBoundingSet=` | An empty list means the service has **no** capabilities. It listens on port 8080, which needs none. |

Apply and test:

```bash
sudo systemctl daemon-reload
sudo systemctl restart myapp
sudo systemctl status myapp
```

### Measure a Service's Exposure

systemd can score how exposed a service is:

```bash
systemd-analyze security                  # score for all services
systemd-analyze security myapp.service    # detailed report for one service
```

A lower score means a better-sandboxed service. Use the report to decide which hardening options to add next.

---

## 09. Host Firewall Security

### Why a Host Firewall?

A firewall controls which network traffic may reach your server. The safest approach is **default deny**:

> **Block everything incoming by default, then allow only what you specifically need.**

Even if you use a cloud firewall (security groups), a host firewall adds another layer. This is defense in depth.

### Firewall Tools at a Glance

| Tool | Common On | Notes |
| :--- | :--- | :--- |
| **ufw** | Ubuntu, Debian | Simple front-end. Best for learning. |
| **firewalld** | RHEL, Rocky, Fedora | Zone-based manager. |
| **nftables** | Modern Linux (default backend) | Powerful, current framework. |
| **iptables** | Older systems | Legacy tool, still widely seen. |

### Configure `ufw` Step by Step

> [!WARNING]
> **Allow SSH *before* enabling the firewall**, or you will cut off your own connection.

```bash
# 1. Set the defaults
sudo ufw default deny incoming
sudo ufw default allow outgoing

# 2. Allow SSH (limit also rate-limits repeated connection attempts)
sudo ufw limit 22/tcp

# 3. Allow only the services you actually run
sudo ufw allow 443/tcp

# 4. Turn the firewall on
sudo ufw enable

# 5. Check the rules
sudo ufw status verbose
sudo ufw status numbered
```

### Common Rules

```bash
# Allow SSH only from one trusted IP address
sudo ufw allow from 203.0.113.10 to any port 22 proto tcp

# Allow a subnet to reach a database port
sudo ufw allow from 10.0.0.0/24 to any port 5432 proto tcp

# Delete a rule by its number
sudo ufw delete 3

# Block one IP address
sudo ufw deny from 198.51.100.7
```

### Test Your Firewall

From another machine, scan **your own server** to see what is visible:

```bash
nmap -Pn <server-ip>
```

> [!CAUTION]
> Only scan systems that you own or have written permission to test.

### Docker and Firewalls: A Common Trap

Docker publishes container ports by editing the firewall rules directly. A port published with `-p 8080:80` may be **reachable from the internet even though `ufw` does not allow it**, because Docker's rules bypass `ufw`. For Docker hosts, bind published ports to localhost when you do not want them public:

```bash
docker run -p 127.0.0.1:8080:80 nginx
```

Also use a cloud security group as an outer layer. You will revisit this in the container security module.

---

## 10. Linux Logging and Auditing

### Why Logs Matter

Logs answer the questions that matter during and after an attack: **Who logged in? From where? What did they run? What changed?** Without logs, you cannot investigate incidents. Logs also provide the audit trail that compliance frameworks require.

### Where Logs Live

| What | Debian / Ubuntu | RHEL Family |
| :--- | :--- | :--- |
| Logins, sudo, SSH | `/var/log/auth.log` | `/var/log/secure` |
| General system log | `/var/log/syslog` | `/var/log/messages` |
| Kernel messages | `/var/log/kern.log` | `/var/log/messages` |
| Audit daemon | `/var/log/audit/audit.log` | `/var/log/audit/audit.log` |
| Successful logins | `/var/log/wtmp` (read with `last`) | same |
| Failed logins | `/var/log/btmp` (read with `lastb`) | same |

> [!NOTE]
> Some newer systems do not create `/var/log/auth.log` unless `rsyslog` is installed. If the file is missing, use `journalctl`, which always works on systemd systems.

### Reading Authentication Logs

```bash
# Who logged in recently, and from where?
last -n 10

# Failed login attempts
sudo lastb | head

# SSH events from the journal
sudo journalctl -u ssh --since "1 hour ago"        # RHEL family: -u sshd

# Failed SSH password attempts in the log file
sudo grep "Failed password" /var/log/auth.log | tail -n 20

# Which IP addresses fail the most? (a simple brute-force detector)
sudo grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head

# System errors since the last boot
sudo journalctl -p err -b
```

Example of a suspicious entry:

```text
Jan 10 03:12:44 server sshd[2231]: Failed password for invalid user admin from 198.51.100.7 port 51132 ssh2
```

Many failures from one IP address at 3 a.m. usually means an automated attack.

### The Linux Audit System: `auditd`

Normal logs record what programs choose to write. The **audit system** works at the **kernel level** and records security-relevant events such as file access, file changes, and command execution. A user or program cannot easily hide from it.

```bash
sudo apt install auditd          # Debian/Ubuntu (RHEL family: dnf install audit)
sudo systemctl enable --now auditd
```

### Writing Audit Rules

A **watch rule** monitors a file or directory:

```text
-w <path>  -p <permissions>  -k <key name>
```

| Permission | Meaning |
| :---: | :--- |
| `r` | Read |
| `w` | Write |
| `x` | Execute |
| `a` | Attribute change (ownership, permissions) |

Create a rules file that watches the most sensitive files:

```bash
sudo nano /etc/audit/rules.d/hardening.rules
```

```text
# Account and identity changes
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group  -p wa -k identity

# Administrator privilege changes
-w /etc/sudoers   -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# SSH configuration changes
-w /etc/ssh/sshd_config -p wa -k sshd_config
```

Load and verify the rules:

```bash
sudo augenrules --load      # load rules from /etc/audit/rules.d/
sudo auditctl -l            # list active rules
```

### Searching Audit Events

```bash
# Create a test event: adding a user modifies /etc/passwd
sudo useradd audittest

# Search by key
sudo ausearch -k identity -i | tail -n 20

# Summary report
sudo aureport --summary

# Cleanup
sudo userdel audittest
```

An audit record tells you which **user**, using which **program**, changed which **file**, and at what **time**.

### Logging Best Practices

- Keep logs long enough to investigate incidents (`logrotate` manages rotation).
- Protect logs from tampering. Attackers often try to delete them.
- **Ship logs to a central location** so they survive if a server is compromised. You will build this later with Loki and Grafana.
- Alert on important events: repeated login failures, new users, changes to `sudoers`, and so on.

---

## 11. File Integrity Monitoring

### What Is File Integrity Monitoring (FIM)?

After breaking in, attackers often **modify system files** (replace `ls` or `ssh` with a malicious version, add a backdoor, change configuration). FIM tools detect this.

**How it works:**

1. Take a **baseline**: record a cryptographic hash (fingerprint) of important files while the system is known to be clean.
2. Later, **recompute** the hashes and compare.
3. Any difference is reported: a file was **added**, **removed**, or **changed**.

```bash
# A hash is a fingerprint. Changing even one character changes it completely.
echo "hello" | sha256sum
echo "hellp" | sha256sum
```

### AIDE (Advanced Intrusion Detection Environment)

AIDE is a popular open-source FIM tool.

**Debian / Ubuntu**

```bash
# Install
sudo apt install aide

# Build the baseline database (this can take several minutes)
sudo aideinit

# Activate the new database as the trusted baseline
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Compare the current system against the baseline
sudo aide --check --config /etc/aide/aide.conf
```

**RHEL family**

```bash
sudo dnf install aide
sudo aide --init
sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
sudo aide --check
```

### Understanding the Result

```text
AIDE found differences between database and filesystem!!

Summary:
  Total number of entries:      xxxxx
  Added entries:                1
  Removed entries:              0
  Changed entries:              1
```

AIDE then lists exactly which files changed and **which attributes** (size, owner, permissions, hash) are different.

### Test It Yourself

```bash
# Create a new file in a monitored directory
sudo touch /etc/aide-test-file

# Run a check. It should report 1 added entry.
sudo aide --check --config /etc/aide/aide.conf

# Accept the change as legitimate and update the baseline
sudo aide --update --config /etc/aide/aide.conf
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Cleanup
sudo rm /etc/aide-test-file
```

### Using FIM Well

- Create the baseline **before** the system is exposed to risk.
- Update the baseline **only after** reviewing legitimate changes (for example, after patching).
- Store a copy of the database somewhere an attacker cannot edit it (read-only or off the server).
- Run checks automatically (cron or a systemd timer) and send the results to your monitoring system.
- Expect noise at first. Tune which paths are monitored.

> [!TIP]
> On Debian-based systems, `debsums -c` compares installed package files against their original package checksums. On RHEL, use `rpm -Va`. These are quick extra checks for modified system binaries.

---

## 12. Security Updates and Patch Management

### Why Patching Is So Important

Most successful attacks use **known vulnerabilities** that already have a fix available. Attackers scan the internet for unpatched systems immediately after a vulnerability becomes public. Patching is one of the most effective security controls you have.

### Basic Update Commands

**Debian / Ubuntu**

```bash
sudo apt update                    # refresh the list of available packages
apt list --upgradable              # see what can be upgraded
sudo apt upgrade                   # install the updates
```

**RHEL family**

```bash
sudo dnf check-update              # see what is available
sudo dnf upgrade --security        # install only security updates
```

### Does the System Need a Reboot?

Kernel and core library updates take full effect only after a reboot.

```bash
# Debian / Ubuntu: this file exists when a reboot is required
[ -f /var/run/reboot-required ] && cat /var/run/reboot-required

# Compare the running kernel with the installed one
uname -r
```

### Automatic Security Updates

For many servers, installing security updates automatically is safer than waiting for someone to do it manually.

**Debian / Ubuntu: `unattended-upgrades`**

```bash
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades

# Check that it is active
systemctl status unattended-upgrades

# Simulate a run to see what it WOULD do
sudo unattended-upgrade --dry-run --debug
```

The configuration is in `/etc/apt/apt.conf.d/50unattended-upgrades`.

**RHEL family:** use `dnf-automatic`.

### A Simple Patch Management Process

| Step | Action |
| :---: | :--- |
| 1 | **Inventory:** know what systems and software you have. |
| 2 | **Identify:** find which updates and vulnerabilities apply. |
| 3 | **Prioritize:** patch the most severe and most exposed first (use CVSS scores and internet exposure). |
| 4 | **Test:** try updates in a non-production environment first. |
| 5 | **Deploy:** apply updates, ideally during a maintenance window, with a rollback plan (snapshot or backup). |
| 6 | **Verify and document:** confirm the fix worked and record what changed. |

> [!NOTE]
> In later modules you will see the same idea applied to **dependencies** (SCA) and **container images** (Trivy). The principle is the same: find known vulnerabilities and fix them quickly.

---

## 13. Linux Security Auditing with Lynis

### What Is Lynis?

**Lynis** is a free, open-source security auditing tool. It scans your Linux system against hundreds of security checks (users, SSH, firewall, kernel settings, software, logging, and more) and gives you:

- **Warnings:** problems that need attention.
- **Suggestions:** improvements you could make.
- A **hardening index**: a score from 0 to 100.

### Install

```bash
# Quick install from the distribution (may be an older version)
sudo apt install lynis

# Or get the latest version from the official repository
git clone https://github.com/CISOfy/lynis.git
cd lynis
```

### Run an Audit

```bash
sudo lynis audit system            # if installed with apt
sudo ./lynis audit system          # if running from the cloned folder
```

The scan takes a minute or two and prints results by category, with each test marked, for example, `[ OK ]`, `[ WARNING ]`, or `[ SUGGESTION ]`.

### Read the Results

Lynis stores its findings in two files:

| File | Contents |
| :--- | :--- |
| `/var/log/lynis.log` | Detailed log of every test |
| `/var/log/lynis-report.dat` | Machine-readable results |

```bash
# Your hardening index
sudo grep hardening_index /var/log/lynis-report.dat

# All warnings
sudo grep '^warning\[\]' /var/log/lynis-report.dat

# All suggestions
sudo grep '^suggestion\[\]' /var/log/lynis-report.dat

# Explain one finding in detail (use an ID such as SSH-7440 from the report)
sudo lynis show details SSH-7440
```

### A Practical Workflow

```text
1. Run Lynis        ->  record your starting hardening index (baseline)
2. Read warnings    ->  fix the most serious ones first
3. Read suggestions ->  apply the ones that make sense for your system
4. Run Lynis again  ->  confirm the score and findings improved
5. Repeat regularly ->  and after major changes
```

> [!IMPORTANT]
> **Do not chase a perfect score.** The hardening index is a guide, not a pass or fail grade. Some suggestions may not suit your environment, and applying advice without understanding it can break services. Read each finding, understand the risk, and decide.

---

## 14. Practical Labs

> [!WARNING]
> Use a disposable **Ubuntu VM**. Take a snapshot first. Several labs change SSH and firewall settings, so keep a second terminal open and, if possible, use the VM console as a safety net.

### Lab 1: Users, Groups and Least Privilege

**Objective:** Create accounts with least privilege and check for dangerous accounts.

**Tasks:**

```bash
# 1. Create a normal user and a service account
sudo useradd -m -s /bin/bash student1
sudo passwd student1
sudo useradd --system --no-create-home --shell /usr/sbin/nologin labsvc

# 2. Create a group and add the user
sudo groupadd labteam
sudo usermod -aG labteam student1

# 3. Apply password aging
sudo chage -M 90 -m 1 -W 7 student1
sudo chage -l student1

# 4. Run the security checks
awk -F: '$3 == 0 {print $1}' /etc/passwd
sudo awk -F: '$2 == "" {print $1}' /etc/shadow
id student1

# 5. Prove the service account cannot log in
sudo su - labsvc        # should be refused
```

**Expected outcome:** `student1` and `labsvc` exist, `labsvc` cannot log in, and the checks show only `root` with UID 0 and no empty passwords.

### Lab 2: Permissions and ACLs

**Objective:** Restrict a file with permissions, then grant one extra user access with an ACL.

**Tasks:**

```bash
# 1. Create a private file
sudo mkdir -p /srv/lab && cd /srv/lab
echo "confidential" | sudo tee secret.txt
sudo chown root:root secret.txt
sudo chmod 600 secret.txt

# 2. Confirm student1 cannot read it
sudo -u student1 cat /srv/lab/secret.txt     # Permission denied

# 3. Grant student1 read-only access with an ACL
sudo setfacl -m u:student1:r secret.txt
getfacl secret.txt
ls -l secret.txt                              # note the "+" sign

# 4. Confirm access now works
sudo -u student1 cat /srv/lab/secret.txt

# 5. Remove the ACL
sudo setfacl -b secret.txt
```

**Expected outcome:** Access is denied, then allowed through the ACL, then denied again after removal. You can explain why the ACL was the right tool.

### Lab 3: Find and Understand SUID Risk

**Objective:** Build a SUID baseline and see why a misplaced SUID bit is dangerous.

**Tasks:**

```bash
# 1. Save a baseline of SUID files
find / -xdev -perm -4000 -type f 2>/dev/null | sort > ~/suid-baseline.txt
wc -l ~/suid-baseline.txt
ls -l /usr/bin/passwd /usr/bin/sudo

# 2. Simulate a MISTAKE: an administrator makes a copy of "cat" SUID-root
sudo cp /bin/cat /tmp/mycat
sudo chown root:root /tmp/mycat
sudo chmod u+s /tmp/mycat

# 3. As the normal user "student1", read a file only root should read
sudo -u student1 /tmp/mycat /etc/shadow      # works only if /tmp is not mounted nosuid

# 4. Detect the new SUID file by comparing with the baseline
find / -xdev -perm -4000 -type f 2>/dev/null | sort | diff ~/suid-baseline.txt -

# 5. Fix and clean up
sudo rm /tmp/mycat
```

**Expected outcome:** You see a normal user reading a protected file because of one misplaced bit, and you can detect it by comparing against a baseline. If step 3 is blocked, check your mount options with `findmnt /tmp`, since `nosuid` is exactly the protection that blocks this.

### Lab 4: Restricted Sudo Access

**Objective:** Give a user permission to run exactly one command with `sudo`.

**Tasks:**

```bash
# 1. Create a drop-in sudoers file (always use visudo)
sudo visudo -f /etc/sudoers.d/student1
```

Add this line, then save:

```text
student1 ALL=(root) /usr/bin/systemctl status ssh
```

```bash
# 2. Review what student1 may run
sudo -l -U student1

# 3. Test as student1
sudo -u student1 sudo systemctl status ssh      # allowed
sudo -u student1 sudo cat /etc/shadow           # denied

# 4. Find the log entries
sudo journalctl _COMM=sudo --since "10 minutes ago"
```

**Expected outcome:** `student1` can run only the one allowed command, and both the successful and denied attempts appear in the logs.

### Lab 5: Harden SSH

**Objective:** Switch SSH to key-only authentication and block root login, **safely**.

**Tasks:**

```bash
# 1. On your own computer, create a key and copy it to the VM
ssh-keygen -t ed25519 -C "lab-key"
ssh-copy-id student1@<vm-ip>
ssh student1@<vm-ip>           # confirm key login works BEFORE continuing
```

```bash
# 2. On the VM, create the hardening file
sudo nano /etc/ssh/sshd_config.d/00-hardening.conf
```

```text
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
AllowUsers student1
X11Forwarding no
```

```bash
# 3. Validate, review the effective settings, and apply
sudo sshd -t
sudo sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|maxauthtries|allowusers'
sudo systemctl reload ssh

# 4. From a NEW terminal, test
ssh student1@<vm-ip>                                              # works with key
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no student1@<vm-ip>   # refused
ssh root@<vm-ip>                                                  # refused
```

**Expected outcome:** Only key-based login for `student1` works. Password and root logins are refused.

### Lab 6: Configure a Host Firewall

**Objective:** Apply a default-deny firewall and verify it.

**Tasks:**

```bash
# 1. Set a default-deny policy, but allow SSH FIRST
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw limit 22/tcp

# 2. Install a test web server and allow only HTTP
sudo apt install -y nginx
sudo ufw allow 80/tcp

# 3. Enable and review
sudo ufw enable
sudo ufw status verbose

# 4. From another machine, scan your VM (only systems you own)
nmap -Pn <vm-ip>

# 5. Remove the HTTP rule, scan again, and compare
sudo ufw status numbered
sudo ufw delete <rule-number>
```

**Expected outcome:** Only ports 22 and 80 are visible at first. After you delete the HTTP rule, port 80 disappears from the scan.

### Lab 7: Auditing and File Integrity Monitoring

**Objective:** Record a sensitive change with `auditd` and detect a file change with AIDE.

**Tasks:**

```bash
# Part A: auditd
sudo apt install -y auditd
sudo nano /etc/audit/rules.d/hardening.rules
```

```text
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers.d/ -p wa -k sudoers
```

```bash
sudo augenrules --load
sudo auditctl -l
sudo useradd labtest
sudo ausearch -k identity -i | tail -n 15
sudo userdel labtest
```

```bash
# Part B: AIDE
sudo apt install -y aide
sudo aideinit
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
sudo touch /etc/lab-integrity-test
sudo aide --check --config /etc/aide/aide.conf
sudo rm /etc/lab-integrity-test
```

**Expected outcome:** `ausearch` shows which user changed `/etc/passwd` and when. AIDE reports the new file under "Added entries".

### Lab 8: Patch and Audit with Lynis

**Objective:** Establish a security baseline, improve it, and measure the difference.

**Tasks:**

```bash
# 1. Update the system and enable automatic security updates
sudo apt update && sudo apt upgrade -y
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades

# 2. Run Lynis and record the starting score
sudo apt install -y lynis
sudo lynis audit system
sudo grep hardening_index /var/log/lynis-report.dat

# 3. List the warnings and suggestions
sudo grep '^warning\[\]' /var/log/lynis-report.dat
sudo grep '^suggestion\[\]' /var/log/lynis-report.dat

# 4. Fix at least three findings (for example: SSH, firewall, or package updates)
# 5. Re-run Lynis and compare the score
sudo lynis audit system
sudo grep hardening_index /var/log/lynis-report.dat
```

**Expected outcome:** A before-and-after hardening index and a short written list of the findings you fixed and why.

---

## 15. Knowledge Check

1. What is the principle of least privilege, and how does it limit the damage of a compromised account?
2. What is an attack surface? Give three ways to reduce it on a Linux server.
3. What is the difference between `/etc/passwd` and `/etc/shadow`, and why are they separate?
4. What does permission mode `640` mean? Who can read, write, and execute?
5. When would you use an ACL instead of changing the owner or group of a file?
6. What does the SUID bit do, and why can a SUID-root binary lead to privilege escalation?
7. Why must you edit sudo rules with `visudo`, and why is `alice ALL=(root) /usr/bin/vim` dangerous?
8. Name four SSH hardening settings and explain the risk each one reduces.
9. Why should you keep an existing SSH session open while changing SSH configuration?
10. What problem do Linux capabilities solve, and why is `CAP_SYS_ADMIN` considered dangerous?
11. Why is a "default deny" firewall policy safer than blocking only known bad traffic?
12. What is the difference between a normal system log and an `auditd` record?
13. How does file integrity monitoring detect that a system binary has been replaced?
14. Why is patching one of the most effective security controls?
15. Why should you not chase a perfect Lynis hardening index?

---

## 16. Summary

In this module, you learned how to secure a Linux host layer by layer:

- **Foundations:** the attack surface, the CIA triad, and defense in depth.
- **Identity and access:** users, groups, least privilege, file permissions, ACLs, and `sudo`.
- **Privilege risks:** SUID/SGID binaries and Linux capabilities, the two most common privilege escalation paths.
- **Exposure reduction:** SSH hardening, service hardening with systemd, and a default-deny host firewall.
- **Detection:** authentication logs, `auditd`, and file integrity monitoring with AIDE.
- **Maintenance:** patch management and regular audits with Lynis.

These skills apply directly to the rest of the course. Containers share the host kernel and use the same capabilities and permissions you studied here. Kubernetes nodes are Linux servers that need the same hardening. CI/CD servers such as Jenkins run on Linux and need SSH, firewall, and sudo security.

### Quick Reference

| Task | Command |
| :--- | :--- |
| Show listening ports | `sudo ss -tulpn` |
| Find UID 0 accounts | `awk -F: '$3 == 0 {print $1}' /etc/passwd` |
| Find world-writable files | `find / -xdev -type f -perm -0002 2>/dev/null` |
| Find SUID files | `find / -xdev -perm -4000 -type f 2>/dev/null` |
| Find files with capabilities | `getcap -r / 2>/dev/null` |
| Edit sudo rules safely | `sudo visudo -f /etc/sudoers.d/<name>` |
| Validate SSH config | `sudo sshd -t` |
| Show effective SSH settings | `sudo sshd -T` |
| Firewall status | `sudo ufw status verbose` |
| Recent logins | `last -n 10` |
| Failed logins | `sudo lastb \| head` |
| Search audit events | `sudo ausearch -k <key> -i` |
| File integrity check | `sudo aide --check --config /etc/aide/aide.conf` |
| List available updates | `apt list --upgradable` |
| Run a security audit | `sudo lynis audit system` |
| Score a service's hardening | `systemd-analyze security <service>` |

---

## Next Module

➡️ [Module 03: Git, GitHub and Secret Security](../03-git-github-and-secret-security/README.md)

[⬅️ Previous: Module 01: DevSecOps Fundamentals](../01-devsecops-fundamentals/README.md) | [🏠 Main README](../README.md)

---

<div align="center">

**Learn. Secure. Automate. Deploy. 🛡️**

</div>
