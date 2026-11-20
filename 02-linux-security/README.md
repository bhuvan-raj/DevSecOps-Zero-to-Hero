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
- [10. Linux Logging and Auditing](#10-Linux-Logging-and-Auditing)
- [11. File Integrity Monitoring](./file-integrity-monitoring/README.md)
- [12. Security Updates and Patch Management](#12-security-updates-and-patch-management)
- [13. Linux Security Auditing with Lynis](./lynis/README.md)
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

## Linux Firewall – UFW Complete Tutorial

![Linux][badge-linux] ![Ubuntu][badge-ubuntu] ![UFW][badge-ufw] ![AWS EC2][badge-ec2] ![Level][badge-level]

---

### Table of Contents

- [Introduction to Linux Firewall](#introduction-to-linux-firewall)
- [What is UFW?](#what-is-ufw)
- [UFW vs iptables vs nftables](#ufw-vs-iptables-vs-nftables)
- [How UFW works](#how-ufw-works)
- [Installing UFW](#installing-ufw)
- [Enabling and disabling UFW](#enabling-and-disabling-ufw)
- [Default firewall policies](#default-firewall-policies)
- [Allowing and denying traffic](#allowing-and-denying-traffic)
- [Allowing and blocking specific IP addresses](#allowing-and-blocking-specific-ip-addresses)
- [Incoming and outgoing firewall rules](#incoming-and-outgoing-firewall-rules)
- [Managing firewall rules](#managing-firewall-rules)
- [UFW configuration files](#ufw-configuration-files)
- [Understanding ICMP](#understanding-icmp)
- [Blocking ICMP ping requests](#blocking-icmp-ping-requests)
- [Understanding the firewall rule inside before.rules](#understanding-the-firewall-rule-inside-beforerules)
- [Monitoring and troubleshooting UFW](#monitoring-and-troubleshooting-ufw)
- [Practical AWS EC2 Lab – Two machines communicating using ping](#practical-aws-ec2-lab--two-machines-communicating-using-ping)
- [Student practice exercises](#student-practice-exercises)
- [Interview questions and answers](#interview-questions-and-answers)
- [Final teaching recommendation](#final-teaching-recommendation)

---

## Introduction to Linux Firewall

A **firewall** is a security mechanism that monitors and controls incoming and outgoing network traffic based on predefined security rules. It acts as a barrier between trusted and untrusted networks.

Suppose you have a Linux server running multiple services:

| Service | Port |
|---------|------|
| SSH     | 22   |
| HTTP    | 80   |
| HTTPS   | 443  |
| MySQL   | 3306 |

You may want to:

- Allow SSH connections only from your administrator's IP address.
- Allow HTTP and HTTPS traffic from everyone.
- Block MySQL access from the public internet.
- Block ping requests from specific IP addresses.

A firewall helps implement these security requirements.

### Types of firewall rules

| Rule | Behaviour |
|------|-----------|
| **Allow** | Permits the specified network traffic. |
| **Deny / Drop** | Blocks the specified network traffic. |
| **Reject** | Blocks the traffic and sends a rejection response to the sender. |

### Why do we need a firewall?

- Prevent unauthorized access.
- Protect servers from unwanted network connections.
- Restrict access to specific ports and services.
- Control communication between different systems.
- Improve server security.

---

## What is UFW?

**UFW** stands for **Uncomplicated Firewall**. It is a user-friendly firewall management tool available on Linux distributions, particularly Ubuntu.

UFW provides simple commands to manage firewall rules without requiring administrators to write complex low-level firewall rules manually.

Allow SSH traffic:

```bash
sudo ufw allow 22/tcp
```

Block SSH traffic:

```bash
sudo ufw deny 22/tcp
```

Without UFW, administrators can configure firewall rules using tools such as `iptables` or `nftables`.

---

## UFW vs iptables vs nftables

These are related but different firewall technologies and utilities.

| Feature | UFW | iptables | nftables |
|---------|-----|----------|----------|
| Type | Firewall frontend | Firewall rule utility | Firewall framework |
| Complexity | Easy | Advanced | Advanced |
| Configuration | Simple commands | Detailed rules | Detailed rules |
| Beginner friendly | Yes | Less friendly | Less friendly |
| Purpose | Simplify firewall management | Manage packet filtering rules | Modern packet filtering |
| Common usage | Ubuntu administration | Traditional Linux firewall management | Modern Linux systems |

### Understand their relationship

- UFW provides a simplified interface for managing firewall rules.
- iptables provides a command-line interface for managing traditional Netfilter rules.
- nftables is the modern Linux packet-filtering framework.

> **Important:** UFW is **not** an upgraded version of iptables. They are not two independent firewall layers. UFW manages firewall rules through the underlying Linux firewall infrastructure.

---

## How UFW works

UFW acts as an interface between the administrator and the Linux firewall infrastructure.

```text
   +-------------------------------+
   |         Administrator         |
   |   sudo ufw allow 22/tcp       |
   +---------------+---------------+
                   |
                   v
   +-------------------------------+
   |              UFW              |
   |  Firewall management interface|
   +---------------+---------------+
                   |
                   v
   +-------------------------------+
   |        Linux Netfilter        |
   | Kernel packet filtering infra |
   +---------------+---------------+
                   |
                   v
   +-------------------------------+
   |   Network traffic filtering   |
   +-------------------------------+
```

When a packet reaches the Linux server, the kernel evaluates the configured firewall rules and decides whether to **accept**, **drop** or **reject** the packet.

---

## Installing UFW

UFW is commonly available in Ubuntu repositories.

Update the package repository:

```bash
sudo apt update
```

Install UFW:

```bash
sudo apt install ufw -y
```

Check the installed version:

```bash
sudo ufw version
```

Check the current firewall status:

```bash
sudo ufw status
```

Possible output:

```text
Status: inactive
```

This means UFW is installed but not currently enabled.

---

## Enabling and disabling UFW

Enable UFW:

```bash
sudo ufw enable
```

Disable UFW:

```bash
sudo ufw disable
```

Check firewall status:

```bash
sudo ufw status
```

Check detailed firewall status:

```bash
sudo ufw status verbose
```

Example output:

```text
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
```

> **Important:** Before enabling UFW on a remote server, allow SSH access first.
>
> ```bash
> sudo ufw allow 22/tcp
> sudo ufw enable
> ```
>
> Otherwise, you may lose your SSH connection.

---

## Default firewall policies

UFW supports default policies that determine what happens to traffic when no specific rule matches it.

There are three important traffic directions:

| Direction | Meaning |
|-----------|---------|
| Incoming | Traffic entering the server |
| Outgoing | Traffic leaving the server |
| Routed | Traffic forwarded through the server |

Set default incoming policy to deny (blocks incoming connections unless explicitly allowed):

```bash
sudo ufw default deny incoming
```

Set default outgoing policy to allow (allows outgoing connections unless explicitly denied):

```bash
sudo ufw default allow outgoing
```

Set default routed policy to deny (prevents forwarded traffic by default):

```bash
sudo ufw default deny routed
```

### Recommended default configuration

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw default deny routed
```

---

## Allowing and denying traffic

UFW allows administrators to control traffic based on ports and protocols.

| Goal | Command |
|------|---------|
| Allow SSH (incoming TCP 22) | `sudo ufw allow 22/tcp` |
| Deny SSH (incoming TCP 22) | `sudo ufw deny 22/tcp` |
| Allow HTTP | `sudo ufw allow 80/tcp` |
| Allow HTTPS | `sudo ufw allow 443/tcp` |
| Deny HTTP | `sudo ufw deny 80/tcp` |
| Allow DNS using UDP | `sudo ufw allow 53/udp` |
| Allow DNS using TCP | `sudo ufw allow 53/tcp` |
| Allow a port for both TCP and UDP | `sudo ufw allow 8080` |
| Allow a range of ports (TCP 8000–9000) | `sudo ufw allow 8000:9000/tcp` |

> When no protocol is specified (for example `sudo ufw allow 8080`), the rule applies to both TCP and UDP.

---

## Allowing and blocking specific IP addresses

UFW also supports rules based on source and destination IP addresses.

Allow a specific IP address:

```bash
sudo ufw allow from 192.168.1.10
```

Deny a specific IP address:

```bash
sudo ufw deny from 192.168.1.20
```

Allow a specific IP to access SSH only:

```bash
sudo ufw allow from 192.168.1.10 to any port 22 proto tcp
```

Allow a complete subnet:

```bash
sudo ufw allow from 192.168.1.0/24
```

Block a complete subnet:

```bash
sudo ufw deny from 192.168.1.0/24
```

---

## Incoming and outgoing firewall rules

UFW can control both incoming and outgoing network traffic.

### Incoming traffic

Packets **entering** the Linux server. For example, block incoming HTTP:

```bash
sudo ufw deny in 80/tcp
```

### Outgoing traffic

Packets **leaving** the Linux server. For example, block outgoing SMTP on TCP port 25:

```bash
sudo ufw deny out 25/tcp
```

Allow outgoing HTTP traffic:

```bash
sudo ufw allow out 80/tcp
```

Allow outgoing HTTPS traffic:

```bash
sudo ufw allow out 443/tcp
```

> **Remember:** `in` means incoming. `out` means outgoing.

---

## Managing firewall rules

As administrators, we need to view, delete and modify firewall rules.

List all rules:

```bash
sudo ufw status numbered
```

Example:

```text
[ 1] 22/tcp       ALLOW IN    Anywhere
[ 2] 80/tcp       ALLOW IN    Anywhere
[ 3] 443/tcp      ALLOW IN    Anywhere
```

Delete a rule by its number (deletes rule 2):

```bash
sudo ufw delete 2
```

Delete a rule using its original command:

```bash
sudo ufw delete allow 80/tcp
```

Reset UFW to its initial state (removes configured rules):

```bash
sudo ufw reset
```

Reload UFW:

```bash
sudo ufw reload
```

---

## UFW configuration files

UFW stores its configuration and firewall rules in `/etc/ufw/`.

| Configuration file | Purpose |
|--------------------|---------|
| `/etc/default/ufw` | Default firewall settings |
| `/etc/ufw/before.rules` | IPv4 rules processed **before** user-defined rules |
| `/etc/ufw/after.rules` | IPv4 rules processed **after** user-defined rules |
| `/etc/ufw/user.rules` | Persistent IPv4 rules managed by UFW |
| `/etc/ufw/before6.rules` | IPv6 rules processed before user-defined rules |
| `/etc/ufw/after6.rules` | IPv6 rules processed after user-defined rules |
| `/etc/ufw/user6.rules` | Persistent IPv6 rules managed by UFW |

### What is before.rules?

The `before.rules` file contains firewall rules that are evaluated **before** the normal user-defined UFW rules. For example, it contains rules for handling certain ICMP messages and other network traffic.

```bash
sudo nano /etc/ufw/before.rules
```

You will find rules similar to:

```text
-A ufw-before-input -p icmp --icmp-type destination-unreachable -j ACCEPT
-A ufw-before-input -p icmp --icmp-type time-exceeded -j ACCEPT
-A ufw-before-input -p icmp --icmp-type parameter-problem -j ACCEPT
-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT
```

These rules allow certain incoming ICMP messages. We can modify this file to configure additional firewall behaviour.

---

## Understanding ICMP

**ICMP** stands for **Internet Control Message Protocol**. It is a network-layer protocol used for network diagnostics and error reporting. One of its most common uses is the `ping` command.

```bash
ping 8.8.8.8
```

When we execute this command:

```text
  Source machine                      Destination machine
        |                                      |
        |---- 1. ICMP Echo Request ----------->|
        |                                      | 2. Request received
        |<--- 3. ICMP Echo Reply --------------|
        | 4. Response received                 |
```

> There are **no TCP or UDP port numbers** involved in ICMP communication.

### Common ICMP message types

| ICMP message | Purpose |
|--------------|---------|
| Echo Request | Request sent by ping |
| Echo Reply | Response received by ping |
| Destination Unreachable | Destination cannot be reached |
| Time Exceeded | TTL has expired |
| Parameter Problem | Error in IP header parameters |

---

## Blocking ICMP ping requests

UFW provides commands for managing TCP and UDP port-based rules, IP addresses and other traffic policies. However, it does **not** provide a standard direct command such as:

```bash
sudo ufw deny icmp   # NOT a standard UFW command
```

To block specific ICMP message types, we configure the underlying firewall rules.

### Block all incoming ping requests

Open the configuration file:

```bash
sudo nano /etc/ufw/before.rules
```

Find the ICMP section:

```text
# ok icmp codes for INPUT
```

Add the following rule **before** the existing ICMP Echo Request ACCEPT rule:

```text
-A ufw-before-input -p icmp --icmp-type echo-request -j DROP
```

Save the file and reload UFW:

```bash
sudo ufw reload
```

Now incoming ping requests will be dropped.

### Block ping requests from a specific IP

Suppose we have:

- Source IP: `192.168.1.20`
- Destination server: `192.168.1.10`

Add the following rule:

```text
-A ufw-before-input -s 192.168.1.20 -p icmp --icmp-type echo-request -j DROP
```

This blocks incoming ping requests originating from `192.168.1.20`. Other machines can still ping the server, provided no other firewall rule blocks them.

### Allow ping requests again

Remove or comment out the DROP rule:

```text
# -A ufw-before-input -p icmp --icmp-type echo-request -j DROP
```

Reload UFW:

```bash
sudo ufw reload
```

> **Important:** These examples are for IPv4. For equivalent IPv6 filtering, configure the corresponding rules in `/etc/ufw/before6.rules`.

---

## Understanding the firewall rule inside before.rules

Consider this rule:

```text
-A ufw-before-input -s 192.168.1.20 -p icmp --icmp-type echo-request -j DROP
```

| Parameter | Explanation |
|-----------|-------------|
| `-A` | Append a rule to a chain |
| `ufw-before-input` | Chain that processes incoming packets before user-defined rules |
| `-s` | Specifies the source IP address |
| `192.168.1.20` | IP address from which traffic originates |
| `-p icmp` | Specifies ICMP protocol |
| `--icmp-type` | Specifies the ICMP message type |
| `echo-request` | Matches ping request packets |
| `-j` | Specifies the action to perform |
| `DROP` | Silently discards matching packets |

### Understand the individual options

**`-A` – Append.** Adds a rule to the end of the specified chain. Example: `-A INPUT` adds a rule to the INPUT chain.

**`ufw-before-input` – Chain.** A chain is a collection of firewall rules that are evaluated against network packets. Common iptables chains:

| Chain | Purpose |
|-------|---------|
| `INPUT` | Incoming traffic destined for the local machine |
| `OUTPUT` | Traffic originating from the local machine |
| `FORWARD` | Traffic passing through the machine |

`ufw-before-input` is a UFW-managed chain for incoming traffic.

**`-s` – Source IP.** Specifies the IP address from which the packet originates. Example: `-s 192.168.1.20` matches packets coming from `192.168.1.20`.

**`-p` – Protocol.** Specifies the network protocol, for example `-p tcp`, `-p udp`, `-p icmp`.

**`--icmp-type` – ICMP message type.** Specifies which ICMP message should match the rule. Example: `--icmp-type echo-request` matches ping request packets.

**`-j` – Jump target.** Specifies what action should be performed when a packet matches the rule.

| Target | Meaning |
|--------|---------|
| `ACCEPT` | Allow the packet |
| `DROP` | Silently discard the packet |
| `REJECT` | Discard the packet and send an error response |

### Difference between DROP and REJECT

| DROP | REJECT |
|------|--------|
| Silently discards packets | Discards packets and sends an error |
| Sender generally experiences a timeout | Sender receives an immediate error |
| No rejection notification | Rejection notification |

### How to verify the rule

```bash
sudo iptables -L ufw-before-input -n -v
```

Or:

```bash
sudo iptables -S ufw-before-input
```

> **Note:** On systems using the nftables backend, `iptables` may be using its nft compatibility interface. You can also inspect rules with:
>
> ```bash
> sudo nft list ruleset
> ```

> **Important teaching concept:** Firewall rules are evaluated according to chain order. Place the specific `DROP` rule **before** an existing `ACCEPT` rule that would otherwise match the same packet. Do not blindly append it after an `ACCEPT` rule.

---

## Monitoring and troubleshooting UFW

Enable firewall logging:

```bash
sudo ufw logging on
```

Set logging level:

```bash
sudo ufw logging medium
```

Available levels: `off`, `low`, `medium`, `high`, `full`.

View UFW logs on Ubuntu:

```bash
sudo journalctl -k | grep UFW
```

Or:

```bash
sudo grep UFW /var/log/ufw.log
```

> The log file may need to be enabled through the system logging configuration.

Check active firewall rules and rule numbers:

```bash
sudo ufw status verbose
sudo ufw status numbered
```

Check underlying rules:

```bash
sudo iptables -L -n -v
```

---

## Practical AWS EC2 Lab – Two machines communicating using ping

![Hands-on Lab][badge-lab] ![Difficulty: Beginner][badge-beginner]

### Lab objective

Create two Ubuntu EC2 instances and establish communication between them using ICMP ping. Then:

1. Test communication between the instances.
2. Block incoming ping requests using UFW's underlying configuration.
3. Verify that ping stops working.
4. Block ping from a specific source IP.
5. Allow ping again.
6. Verify that communication works.

### Architecture

```text
+--------------------------------------------------------------+
|                    AWS VPC – 10.0.0.0/16                     |
|                                                              |
|   +---------------------------+   +-----------------------+  |
|   |          EC2-1            |   |         EC2-2         |  |
|   |      Firewall server      |   |     Client machine    |  |
|   |      Ubuntu 24.04         |   |     Ubuntu 24.04      |  |
|   |      10.0.1.10            |<--|     10.0.1.20         |  |
|   |      UFW enabled          |   |     Ping source       |  |
|   +---------------------------+   +-----------------------+  |
|                                                              |
|        ICMP communication                                    |
|        Allow / Block using UFW on EC2-1                      |
+--------------------------------------------------------------+
```

> The IP addresses are examples. Replace them with the actual private IP addresses of your instances.

### Create two EC2 instances

| Configuration | EC2-1 | EC2-2 |
|---------------|-------|-------|
| AMI | Ubuntu 24.04 | Ubuntu 24.04 |
| Instance type | t2.micro | t2.micro |
| VPC | Same VPC | Same VPC |
| Subnet | Same subnet | Same subnet |
| Security Group | Same SG | Same SG |

#### Security Group configuration

Configure these inbound rules:

| Type | Protocol | Port | Source |
|------|----------|------|--------|
| SSH | TCP | 22 | Your public IP |
| All ICMP – IPv4 | ICMP | All | VPC CIDR (for example `10.0.0.0/16`) |

Use your actual VPC CIDR instead.

> **Important:** AWS Security Groups must allow ICMP traffic for this lab. Otherwise, ping may fail before the packet reaches UFW. Also ensure the subnet routing allows the two instances to communicate.

### Connect to both instances

```bash
# EC2-1
ssh -i lab-key.pem ubuntu@<EC2-1-PUBLIC-IP>

# EC2-2
ssh -i lab-key.pem ubuntu@<EC2-2-PUBLIC-IP>
```

Find the private IP address of each instance:

```bash
hostname -I
```

Or:

```bash
ip addr show
```

For this example:

```text
EC2-1: 10.0.1.10
EC2-2: 10.0.1.20
```

### Install UFW on EC2-1

Execute the following on **EC2-1**.

```bash
# Update packages
sudo apt update

# Install UFW
sudo apt install ufw -y

# Allow SSH
sudo ufw allow 22/tcp

# Set default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Enable UFW
sudo ufw enable

# Verify
sudo ufw status verbose
```

Expected output:

```text
Status: active

Default: deny (incoming), allow (outgoing), disabled (routed)
```

### Test communication before blocking

Go to **EC2-2** and execute:

```bash
ping 10.0.1.10
```

Expected output:

```text
64 bytes from 10.0.1.10: icmp_seq=1 ttl=64 time=0.5 ms
64 bytes from 10.0.1.10: icmp_seq=2 ttl=64 time=0.4 ms
```

Result: **Ping successful** ✅

EC2-2 sends an ICMP Echo Request to EC2-1, and EC2-1 responds with an ICMP Echo Reply. The communication works because the AWS Security Group allows ICMP and UFW has not been configured to block ping requests.

Press `Ctrl + C` to stop ping.

### Block all incoming ping requests using UFW

Go to **EC2-1** and open the UFW configuration file:

```bash
sudo nano /etc/ufw/before.rules
```

Find the ICMP section:

```text
# ok icmp codes for INPUT
```

Find the existing Echo Request ACCEPT rule:

```text
-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT
```

Add the following DROP rule **immediately before** that ACCEPT rule:

```text
-A ufw-before-input -p icmp --icmp-type echo-request -j DROP
```

Save the file and reload UFW:

```bash
sudo ufw reload
```

Now go to **EC2-2**:

```bash
ping 10.0.1.10
```

Expected result:

```text
Request timeout
Request timeout
Request timeout
```

Result: **Ping blocked** ❌

What happened:

1. EC2-2 sends an ICMP Echo Request.
2. EC2-1 receives the packet.
3. The UFW-managed firewall chain checks the incoming packet.
4. The DROP rule matches the ICMP Echo Request.
5. The firewall silently discards the packet.
6. EC2-2 does not receive an Echo Reply.

### Block ping requests from a specific IP

Suppose you want to block ping only from EC2-2, while allowing other machines to ping EC2-1.

On **EC2-1**, edit:

```bash
sudo nano /etc/ufw/before.rules
```

Use this rule:

```text
-A ufw-before-input -s 10.0.1.20 -p icmp --icmp-type echo-request -j DROP
```

Make sure this rule is placed **before** the general ICMP Echo Request ACCEPT rule. If you previously added the rule that blocks all incoming ping requests, comment it out or remove it for this test.

Reload:

```bash
sudo ufw reload
```

Expected result:

| Source machine | Destination | Result |
|----------------|-------------|--------|
| EC2-2 – 10.0.1.20 | EC2-1 – 10.0.1.10 | Blocked |
| EC2-3 – 10.0.1.30 | EC2-1 – 10.0.1.10 | Allowed |

> EC2-3 is an optional third machine for testing. Its ping will work provided the security group, routing and other firewall rules allow it.

### Allow ping requests again

Go back to **EC2-1** and open:

```bash
sudo nano /etc/ufw/before.rules
```

Comment out or remove the DROP rule:

```text
# -A ufw-before-input -s 10.0.1.20 -p icmp --icmp-type echo-request -j DROP
```

Reload UFW:

```bash
sudo ufw reload
```

Now go to **EC2-2**:

```bash
ping 10.0.1.10
```

Result: **Ping successful again** ✅ — the incoming Echo Request is now allowed by the existing ICMP rules.

### Verify firewall rules

On **EC2-1**:

```bash
sudo ufw status verbose
```

View the underlying firewall chain:

```bash
sudo iptables -L ufw-before-input -n -v
```

This demonstrates that UFW manages rules in the underlying Linux firewall infrastructure.

### Lab result

| Experiment | Expected result |
|------------|-----------------|
| Initial ping | Successful |
| Block all ICMP Echo Requests | Failed |
| Block only EC2-2 IP | EC2-2 blocked |
| Ping from another permitted machine | Successful |
| Remove DROP rule | Successful again |

**Lab conclusion:** Students will understand how to configure a Linux firewall, control incoming traffic, filter network communication based on source IP addresses, and use UFW configuration files to manage ICMP traffic.

---

## Student practice exercises
·

**Practical exercise tracker: 0 / 15**

- [ ] Install UFW on an Ubuntu machine.
- [ ] Enable UFW and configure default incoming and outgoing policies.
- [ ] Allow SSH traffic on port 22.
- [ ] Allow HTTP and HTTPS traffic.
- [ ] Block incoming traffic on port 8080.
- [ ] Allow UDP traffic on port 53.
- [ ] Allow incoming connections only from a specific IP address.
- [ ] Block a specific IP address.
- [ ] Configure an outgoing rule to block TCP port 25.
- [ ] Delete an existing firewall rule.
- [ ] Enable firewall logging and inspect the logs.
- [ ] Create two EC2 instances and test ping communication.
- [ ] Block all incoming ICMP Echo Requests.
- [ ] Block ping requests from only one source IP.
- [ ] Remove the DROP rule and restore ping communication.

---

## Interview questions and answers

**Q1. What is UFW?**
UFW stands for Uncomplicated Firewall. It is a user-friendly frontend for managing Linux firewall rules.

**Q2. Is UFW an upgraded version of iptables?**
No. UFW is a simplified firewall management interface, whereas iptables is a utility for managing traditional Linux firewall rules.

**Q3. What is the difference between DROP and REJECT?**
DROP silently discards packets, whereas REJECT discards packets and sends an error response.

**Q4. What is the default incoming policy of UFW?**
The common default policy is to deny incoming connections.

**Q5. How do you allow SSH using UFW?**

```bash
sudo ufw allow 22/tcp
```

**Q6. How do you block a specific IP address?**

```bash
sudo ufw deny from 192.168.1.20
```

**Q7. Can we block ICMP using a normal UFW command?**
There is no standard direct `ufw deny icmp` command. We can configure specific ICMP filtering rules in UFW's underlying firewall configuration.

**Q8. What is the purpose of before.rules?**
It contains firewall rules processed before UFW's normal user-defined rules.

**Q9. What does `-p icmp` mean?**
It specifies that the firewall rule matches ICMP traffic.

**Q10. What does `-s` mean in iptables?**
It specifies the source IP address.

**Q11. What does `-j DROP` mean?**
It tells the firewall to silently discard matching packets.

**Q12. What happens if the AWS Security Group blocks ICMP but UFW allows it?**
Ping will fail because the packet is blocked at the AWS Security Group level before it reaches the instance's firewall.

**Q13. How do you check UFW status?**

```bash
sudo ufw status verbose
```

**Q14. How do you delete a UFW rule?**

```bash
sudo ufw delete allow 80/tcp
```

**Q15. What is the difference between incoming and outgoing traffic?**
Incoming traffic enters the server, whereas outgoing traffic leaves the server.

---

> **Lab safety:** Keep SSH allowed from your administrator IP before enabling UFW. Do not experiment with SSH-blocking rules on your only remote connection. Restore the ICMP configuration after the lab, and terminate the EC2 instances when finished to avoid unnecessary AWS charges.

---

<!-- Reference-style badge definitions -->
[badge-linux]: https://img.shields.io/badge/Linux-Administration-FCC624?logo=linux&logoColor=black
[badge-ubuntu]: https://img.shields.io/badge/Ubuntu-24.04-E95420?logo=ubuntu&logoColor=white
[badge-ufw]: https://img.shields.io/badge/Firewall-UFW-blue
[badge-ec2]: https://img.shields.io/badge/AWS-EC2-FF9900?logo=amazonaws&logoColor=white
[badge-level]: https://img.shields.io/badge/Level-Beginner-brightgreen
[badge-lab]: https://img.shields.io/badge/Hands--on-Lab-purple

---

# 10. Linux Logging and Auditing

![Linux][badge-linux] ![Ubuntu][badge-ubuntu] ![journald][badge-journald] ![auditd][badge-auditd] ![DevSecOps][badge-devsecops]

> Visibility into system activity: where Linux logs live, how to read them, how to detect suspicious SSH activity, and how to use `auditd` to record security-sensitive events.

---

## Table of Contents

- [Why Do Logs Matter?](#why-do-logs-matter)
- [Understanding Linux Logging Architecture](#understanding-linux-logging-architecture)
- [Where Are Linux Logs Stored?](#where-are-linux-logs-stored)
- [Understanding Authentication Logs](#understanding-authentication-logs)
- [Understanding Login History Commands](#understanding-login-history-commands)
- [Understanding systemd Journal Logs](#understanding-systemd-journal-logs)
- [Understanding Log Priorities](#understanding-log-priorities)
- [Detecting Suspicious SSH Activity](#detecting-suspicious-ssh-activity)
- [Introduction to the Linux Audit System: auditd](#introduction-to-the-linux-audit-system-auditd)
- [Installing and Starting auditd](#installing-and-starting-auditd)
- [Understanding Audit Rules](#understanding-audit-rules)
- [Creating Persistent Audit Rules](#creating-persistent-audit-rules)
- [Understanding the always,exit Rule](#understanding-the-alwaysexit-rule)
- [Searching Audit Events](#searching-audit-events)
- [Understanding Audit Records](#understanding-audit-records)
- [Generating Test Audit Events](#generating-test-audit-events)
- [Generating Audit Reports Using aureport](#generating-audit-reports-using-aureport)
- [Understanding Log Rotation with logrotate](#understanding-log-rotation-with-logrotate)
- [Logging and Auditing Best Practices](#logging-and-auditing-best-practices)
- [Lynis vs auditd vs journalctl](#lynis-vs-auditd-vs-journalctl)
- [Practical Lab: Linux Logging and Auditing](#practical-lab-linux-logging-and-auditing)
- [Conclusion](#conclusion)

---

## Why Do Logs Matter?

Logging is one of the most important components of Linux system administration and security.

A Linux system continuously generates information about activities performed by users, applications, services, the kernel and the operating system. This information is stored in log files or collected by a logging service.

Logs help administrators understand what happened on a system, when it happened, which user or process was involved, and whether the activity was expected or suspicious.

During a security incident, logs help answer questions such as:

- Who logged into the server?
- From which IP address did the login originate?
- Was the login successful or unsuccessful?
- Which commands were executed?
- When was a sensitive configuration file modified?
- Who created or deleted a user account?
- Was someone attempting to gain unauthorized privileges?
- Which service failed, and when did it fail?

### Example scenario

Imagine you are managing an Ubuntu EC2 instance hosting a production website. One morning, you discover that someone has modified the SSH configuration and created an unauthorized Linux user.

Without logging and auditing, it may be difficult to determine:

- When the modification happened.
- Which account performed the operation.
- Whether the account accessed the server through SSH.
- Whether other sensitive files were modified.

With proper logging and auditing, you can investigate these activities and reconstruct important parts of the incident.

> **Remember:** Logs help with detection, investigation, troubleshooting and accountability. They are not a replacement for preventive security controls.

---

## Understanding Linux Logging Architecture

Linux uses multiple components to collect, process, store and analyze system logs.

### systemd-journald

`systemd-journald` is the logging service provided by systemd. It collects messages from:

- The Linux kernel.
- System services.
- Applications using the systemd journal interface.
- Standard output and standard error of services managed by systemd.

It stores these messages in the systemd journal, which can be queried using `journalctl`.

### rsyslog

`rsyslog` is a system logging service that collects and processes log messages. It can:

- Collect logs from applications and services.
- Store logs in different files.
- Forward logs to remote logging servers.
- Filter messages based on facility and severity.
- Process logs according to configurable rules.

For example, Ubuntu commonly uses rsyslog to maintain files such as `/var/log/syslog` and `/var/log/auth.log`.

### auditd

`auditd` is the Linux Audit daemon. Unlike ordinary application logging, the Linux Audit System can record security-relevant events generated through the kernel audit subsystem. It can monitor:

- Changes to sensitive files.
- File access.
- File ownership and permission changes.
- Selected system calls.
- Command execution events when appropriate rules are configured.

It is particularly useful for security investigations and compliance auditing.

### Logging architecture

```text
        Linux Applications
        System Services
        Kernel Messages
                |
                v
        systemd-journald
                |
                v
             journalctl
                |
                v
        Persistent Journal

        Applications / Services
                |
                v
              rsyslog
                |
          +-----+------+
          |            |
          v            v
       Local Logs   Remote Server


        Kernel Audit Subsystem
                |
                v
              auditd
                |
                v
        /var/log/audit/
                |
                v
          ausearch / aureport
```

> **Note:** This is a conceptual view. Journald and rsyslog can operate independently or together. Audit events follow a separate audit subsystem and are not simply ordinary application log messages.

---

## Where Are Linux Logs Stored?

Most Linux distributions store log files under `/var/log/`. You can explore the directory using:

```bash
ls -lh /var/log/
```

Different distributions may use different logging configurations.

| What | Debian / Ubuntu | RHEL Family |
|------|-----------------|-------------|
| Authentication logs | `/var/log/auth.log` | `/var/log/secure` |
| General system logs | `/var/log/syslog` | `/var/log/messages` |
| Kernel messages | `/var/log/kern.log` | `/var/log/messages` |
| Audit logs | `/var/log/audit/audit.log` | `/var/log/audit/audit.log` |
| Successful login records | `/var/log/wtmp` | `/var/log/wtmp` |
| Failed login records | `/var/log/btmp` | `/var/log/btmp` |

Some systems may not have all these files. For example, a minimal Ubuntu installation may use journald without installing rsyslog. In that situation, `/var/log/auth.log` and `/var/log/syslog` may not exist. You can use `journalctl` to inspect the journal.

---

## Understanding Authentication Logs

Authentication logs contain information about user authentication and authorization activities. They are especially important when investigating:

- SSH login attempts.
- Failed password attempts.
- Successful authentication.
- Sudo operations.
- Invalid usernames.
- Authentication failures.

On Ubuntu, authentication messages are commonly stored in `/var/log/auth.log`. On RHEL-based systems, they are in `/var/log/secure`.

### View authentication logs

```bash
sudo less /var/log/auth.log
```

### Display the last 20 authentication events

```bash
sudo tail -n 20 /var/log/auth.log
```

### Monitor authentication logs continuously

```bash
sudo tail -f /var/log/auth.log
```

The `-f` option follows the log file and displays new entries as they are written. This is useful when testing SSH connections or sudo operations.

### Search for successful SSH logins

```bash
sudo grep "Accepted" /var/log/auth.log
```

### Search for failed SSH password attempts

```bash
sudo grep "Failed password" /var/log/auth.log
```

### Search for invalid user attempts

```bash
sudo grep "Invalid user" /var/log/auth.log
```

### Search for sudo activity

```bash
sudo grep "sudo" /var/log/auth.log
```

These searches help administrators identify authentication-related activities.

---

## Understanding Login History Commands

Linux provides several commands for examining login history.

### last

Reads login records from `/var/log/wtmp` and displays previous login sessions.

```bash
last
```

Display only the latest 10 records:

```bash
last -n 10
```

You may see: username, terminal or session, remote IP address or hostname, login time, logout time and session duration.

### lastb

Reads failed login records from `/var/log/btmp`.

```bash
sudo lastb
```

Display only the latest failed login records:

```bash
sudo lastb | head
```

This can help identify repeated unsuccessful login attempts.

### who

Displays users currently logged into the system.

```bash
who
```

### w

Displays currently logged-in users along with their activities.

```bash
w
```

It can display logged-in users, login time, source terminal or remote host, idle time, and the current process or command.

### users

Displays usernames of users currently logged into the system.

```bash
users
```

---

## Understanding systemd Journal Logs

Modern Linux distributions commonly use systemd-journald for collecting system logs. The `journalctl` command allows administrators to query these logs.

Unlike traditional log files, the systemd journal stores structured log records containing information such as timestamps, service names, process IDs and priorities.

| Goal | Command |
|------|---------|
| View all journal entries | `sudo journalctl` |
| Logs from the current boot | `sudo journalctl -b` |
| Logs from the previous boot | `sudo journalctl -b -1` |
| Latest 50 entries | `sudo journalctl -n 50` |
| Monitor logs continuously | `sudo journalctl -f` |
| Error-level messages | `sudo journalctl -p err` |
| Error messages from the current boot | `sudo journalctl -p err -b` |
| Logs from the last hour | `sudo journalctl --since "1 hour ago"` |

> `journalctl -f` is similar to `tail -f`: it continuously displays newly generated journal entries.

Specify a time range:

```bash
sudo journalctl --since "2026-11-20 08:00:00" \
                --until "2026-11-20 09:00:00"
```

### View logs for a particular service

Inspect NGINX logs:

```bash
sudo journalctl -u nginx
```

Inspect SSH service logs.

Ubuntu:

```bash
sudo journalctl -u ssh
```

RHEL:

```bash
sudo journalctl -u sshd
```

Display only recent NGINX service logs:

```bash
sudo journalctl -u nginx --since "1 hour ago"
```

---

## Understanding Log Priorities

Linux logging systems classify messages according to their severity. The traditional syslog severity levels are:

| Priority | Name | Description |
|----------|------|-------------|
| 0 | Emergency | System is unusable. |
| 1 | Alert | Immediate action is required. |
| 2 | Critical | Critical system condition. |
| 3 | Error | Error condition occurred. |
| 4 | Warning | Warning condition. |
| 5 | Notice | Normal but significant event. |
| 6 | Informational | General information. |
| 7 | Debug | Detailed debugging information. |

For example, display warning-level messages and more severe messages:

```bash
sudo journalctl -p warning
```

Display error-level messages and more severe messages:

```bash
sudo journalctl -p err
```

---

## Detecting Suspicious SSH Activity

Authentication logs can help identify potential brute-force attacks. A brute-force attack occurs when an attacker repeatedly attempts to authenticate using different passwords or usernames until a valid combination is discovered.

Consider the following log entry:

```text
Nov 20 03:12:44 server sshd[2231]: Failed password for invalid user admin from 198.51.100.7 port 51132 ssh2
```

| Field | Meaning |
|-------|---------|
| `Nov 20 03:12:44` | Date and time of the event |
| `server` | Hostname |
| `sshd[2231]` | SSH daemon and process ID |
| `Failed password` | Authentication failed |
| `invalid user admin` | Attempted username does not exist |
| `198.51.100.7` | Source IP address |
| `port 51132` | Client-side source port |
| `ssh2` | SSH protocol version |

This entry indicates that someone attempted to authenticate using a nonexistent username.

### Count failed password attempts (Ubuntu)

```bash
sudo grep "Failed password" /var/log/auth.log | wc -l
```

### Identify IP addresses generating failed password attempts

```bash
sudo grep "Failed password" /var/log/auth.log \
| awk '{print $(NF-3)}' \
| sort \
| uniq -c \
| sort -nr
```

How it works:

- `grep` filters failed password messages.
- `awk` extracts the source IP address.
- `sort` groups identical IP addresses together.
- `uniq -c` counts occurrences.
- `sort -nr` sorts the counts in descending order.

### Identify repeated invalid usernames

```bash
sudo grep "Invalid user" /var/log/auth.log \
| awk '{print $(NF-5)}' \
| sort \
| uniq -c \
| sort -nr
```

> The exact log format can vary, so always verify extracted fields against your distribution's actual log entries.

> **Important:** Repeated failed logins can indicate brute-force activity, but they can also result from misconfigured automation, expired credentials or legitimate users entering incorrect passwords. Investigate before blocking an IP address.

---

## Introduction to the Linux Audit System: auditd

Normal application and system logs record information that programs and services choose to generate. However, sometimes we need more detailed information about security-sensitive activities, such as:

- Who modified `/etc/passwd`?
- Who changed the permissions of `/etc/shadow`?
- Who modified the SSH configuration?
- Which process accessed a sensitive file?
- Which user executed a monitored system call?

This is where the **Linux Audit System** becomes useful. It is a kernel-supported auditing framework that records security-related events according to configured audit rules. `auditd` is the userspace daemon responsible for collecting and writing audit events to audit log files.

It is commonly used for:

- Monitoring sensitive file changes.
- Tracking changes to user accounts.
- Monitoring modifications to sudo policies.
- Recording selected system calls.
- Investigating security incidents.
- Meeting audit and compliance requirements.

### How auditd works

```text
       User / Application
               |
               v
        System Call
               |
               v
        Linux Kernel
               |
               v
       Audit Subsystem
               |
        Matching Rules?
               |
               v
        Audit Events
               |
               v
            auditd
               |
               v
 /var/log/audit/audit.log
               |
          +----+----+
          |         |
          v         v
       ausearch  aureport
```

The audit subsystem evaluates configured rules and generates matching audit events. The daemon collects and writes these events.

> **Important:** auditd does not automatically record every command or every file access. You must configure appropriate rules for the activities you want to monitor.

---

## Installing and Starting auditd

Ubuntu / Debian:

```bash
sudo apt update
sudo apt install auditd audispd-plugins -y
```

RHEL-based distributions:

```bash
sudo dnf install audit -y
```

Start the service:

```bash
sudo systemctl enable --now auditd
```

Check its status:

```bash
sudo systemctl status auditd
```

Check the audit daemon version:

```bash
sudo auditctl -v
```

The default audit log location is `/var/log/audit/audit.log`. View it with:

```bash
sudo less /var/log/audit/audit.log
```

---

## Understanding Audit Rules

Audit rules define which activities the Linux Audit System should monitor. For example, you may want to monitor modifications to `/etc/passwd`. Instead of continuously checking the file manually, you can create an audit rule that generates an event whenever a matching modification occurs.

There are two commonly discussed approaches: **watch rules** and **syscall-based rules**.

### Watch rules

A watch rule monitors a specified file or directory.

```bash
-w <path> -p <permissions> -k <key>
```

| Parameter | Meaning |
|-----------|---------|
| `-w` | Specifies the file or directory to monitor. |
| `-p` | Specifies the permissions or types of activity to monitor. |
| `-k` | Assigns a searchable key to the rule. |

Permission flags:

| Permission | Meaning |
|------------|---------|
| `r` | Read access |
| `w` | Write access |
| `x` | Execute access |
| `a` | Attribute changes such as ownership or permission changes |

Example:

```bash
sudo auditctl -w /etc/passwd -p wa -k passwd_monitor
```

Breakdown:

- `auditctl`: Command-line utility used to manage audit rules.
- `-w`: Create a watch on the specified path.
- `/etc/passwd`: File being monitored.
- `-p wa`: Monitor write and attribute changes.
- `-k passwd_monitor`: Assign the rule the key `passwd_monitor`.

This rule monitors changes to the `/etc/passwd` file. For example, when a user is created or deleted, the file may be modified and a corresponding audit event can be generated.

> **Note:** Legacy `-w` watch rules are supported but deprecated for new rule design on many modern audit installations because they can be less efficient. For newer environments, syscall-based rules are generally preferred.

### Syscall-based rules

System calls are requests made by programs to the Linux kernel to perform operations such as opening files, changing permissions, creating processes and modifying files. The Linux Audit System can monitor selected system calls.

```bash
-a <action>,<filter> -S <syscall> -F <field=value> -k <key>
```

| Parameter | Meaning |
|-----------|---------|
| `-a` | Adds an audit rule. |
| `always,exit` | Generates an event when a matching system call exits. |
| `-S` | Specifies the system call to monitor. |
| `-F` | Applies a filter to the event. |
| `-k` | Assigns a searchable key. |

Example:

```bash
sudo auditctl -a always,exit -F arch=b64 \
-S chmod -S fchmod -S fchmodat \
-k permission_changes
```

Breakdown:

- `-a always,exit`: Generate an audit event when a matching system call exits.
- `-F arch=b64`: Apply the rule to 64-bit system calls.
- `-S chmod`, `-S fchmod`, `-S fchmodat`: Monitor these system calls.
- `-k permission_changes`: Assign the key `permission_changes`.

This rule monitors selected system calls responsible for changing file permissions. For systems that support multiple architectures, consider whether equivalent 32-bit rules are needed.

---

## Creating Persistent Audit Rules

Rules created using `auditctl` directly are generally runtime rules. They may not survive a reboot. To make rules persistent, store them under `/etc/audit/rules.d/`.

Create a rules file:

```bash
sudo nano /etc/audit/rules.d/hardening.rules
```

Add the following rules:

```text
# Account and identity changes
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity

# Administrator privilege changes
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# SSH configuration changes
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config
```

> These are legacy watch-rule examples for teaching purposes. On modern systems, you can convert them to syscall-based rules using `path` and `dir` filters where supported.

Load the rules:

```bash
sudo augenrules --load
```

Verify active rules:

```bash
sudo auditctl -l
```

Check the audit daemon:

```bash
sudo systemctl status auditd
```

> **Important:** If the audit system is configured with immutable rules using `-e 2`, rules cannot be changed until the next reboot. Do not enable immutable mode until you have validated your complete rule set and understand the recovery implications.

---

## Understanding the always,exit Rule

One important concept in auditd is `always,exit`. It is an action/filter combination used in syscall-based audit rules.

- **always:** The rule requests that a matching event be generated rather than applying a conditional action such as never recording it.
- **exit:** The event is evaluated when the monitored system call exits.

For example:

```bash
sudo auditctl -a always,exit -F arch=b64 \
-S chmod -k chmod_monitor
```

When a matching `chmod` system call exits, the audit subsystem generates an event. This allows the audit system to capture details associated with the system call, including its result.

The audit event may contain:

- Process ID.
- User ID.
- Effective user ID.
- Executed command.
- System call information.
- Success or failure status.
- Relevant file path.

---

## Searching Audit Events

Once audit rules are configured, you can search the events generated by those rules using `ausearch`.

| Goal | Command |
|------|---------|
| Search using an audit key | `sudo ausearch -k identity` |
| Human-readable output | `sudo ausearch -k identity -i` |
| SSH configuration modifications | `sudo ausearch -k sshd_config -i` |
| Sudo policy changes | `sudo ausearch -k sudoers -i` |
| Permission changes | `sudo ausearch -k permission_changes -i` |
| Events from today | `sudo ausearch --start today -i` |
| Events for a specific user ID | `sudo ausearch -ua 1001 -i` |

> The `-i` option interprets certain numeric values and displays them in a more readable format. Replace the user ID with the actual UID you want to investigate.

---

## Understanding Audit Records

Audit events can contain multiple records associated with the same event ID. Consider a simplified example:

```text
type=SYSCALL msg=audit(1795160000.123:450):
arch=c000003e syscall=90 success=yes
pid=2231 uid=1001 auid=1001
comm="chmod" exe="/usr/bin/chmod"

type=PATH msg=audit(1795160000.123:450):
name="/var/www/index.html"
```

| Field | Meaning |
|-------|---------|
| `type=SYSCALL` | Indicates a system-call audit record. |
| `msg=audit(...)` | Contains the event timestamp and event serial number. |
| `syscall=90` | System-call number, architecture-dependent. |
| `success=yes` | Indicates that the system call succeeded. |
| `pid=2231` | Process ID. |
| `uid=1001` | User ID associated with the process. |
| `auid=1001` | Login audit UID, which can help identify the original authenticated user. |
| `comm="chmod"` | Command name. |
| `exe="/usr/bin/chmod"` | Executable path. |
| `name="/var/www/index.html"` | File path associated with the event. |

The event ID in the timestamp field allows related audit records to be correlated. The `auid` field is particularly useful because it can preserve the original login identity even when a user executes a command through `sudo`.

> **Note:** Numeric syscall values depend on architecture. Use `ausearch -i` for more readable interpretations.

---

## Generating Test Audit Events

A simple practical exercise.

First, make sure you have the identity watch rule loaded:

```bash
sudo auditctl -l
```

Create a test user:

```bash
sudo useradd audittest
```

This operation normally modifies account databases such as `/etc/passwd` and `/etc/shadow`. Search for the generated event:

```bash
sudo ausearch -k identity -i
```

You should find events associated with the monitored account files.

You can also test a permission modification:

```bash
sudo chmod 600 /tmp/audit-test.txt
```

If you configured a suitable syscall rule for permission changes, search using:

```bash
sudo ausearch -k permission_changes -i
```

Cleanup:

```bash
sudo userdel audittest
sudo rm -f /tmp/audit-test.txt
```

> The cleanup operation can generate additional audit events.

---

## Generating Audit Reports Using aureport

The `aureport` command generates summary reports from audit logs. Instead of manually searching individual events, administrators can use it to understand audit activity.

| Goal | Command |
|------|---------|
| General summary | `sudo aureport --summary` |
| Authentication reports | `sudo aureport -au` |
| Failed authentication attempts | `sudo aureport -au --failed` |
| Executable reports | `sudo aureport -x` |
| File access reports | `sudo aureport -f` |
| User activity reports | `sudo aureport -u` |

These reports help administrators identify suspicious activity and understand the security events recorded by the audit subsystem.

---

## Understanding Log Rotation with logrotate

Linux systems continuously generate logs. Over time, log files can become very large and consume significant disk space. For example:

```text
/var/log/syslog
/var/log/auth.log
/var/log/audit/audit.log
```

Linux commonly uses `logrotate` to manage log files. It can:

- Rotate old log files.
- Compress archived logs.
- Remove logs older than a configured retention period.
- Create new log files.
- Manage rotation based on size or time.

Install (or check) logrotate:

```bash
sudo apt install logrotate -y
```

Check the main configuration:

```bash
sudo cat /etc/logrotate.conf
```

Application-specific configurations are commonly stored under `/etc/logrotate.d/`:

```bash
ls -l /etc/logrotate.d/
```

Check the NGINX log rotation configuration:

```bash
sudo cat /etc/logrotate.d/nginx
```

Test logrotate configuration without performing actual rotation:

```bash
sudo logrotate -d /etc/logrotate.conf
```

Force a rotation for testing:

```bash
sudo logrotate -f /etc/logrotate.conf
```

> Use force rotation carefully, particularly on production systems.

> **Important:** auditd has its own log rotation and retention configuration. Its logs should be managed using auditd's supported settings rather than assuming that ordinary logrotate rules are appropriate.

---

## Logging and Auditing Best Practices

Logging is useful only when logs are properly collected, protected, retained and monitored.

### Enable persistent logging

Ensure that important logs survive system reboots. For journald, check:

```bash
sudo journalctl --disk-usage
```

Persistent journal storage is commonly configured through `/etc/systemd/journald.conf`. The `Storage=persistent` setting enables persistent journal storage when configured and supported.

### Protect log files

Logs may contain sensitive information about users, IP addresses and system activity. Restrict access to sensitive log files and directories:

```bash
sudo ls -ld /var/log
sudo ls -l /var/log/auth.log
```

Avoid granting unnecessary users permission to modify security logs.

### Configure appropriate retention

Keep logs long enough to support investigations and applicable compliance requirements. Use log rotation and retention policies to manage storage.

### Monitor failed authentication attempts

Regularly investigate repeated failed SSH login attempts:

```bash
sudo grep "Failed password" /var/log/auth.log | tail
```

### Monitor sensitive configuration files

Use auditd to monitor important files such as:

- `/etc/passwd`
- `/etc/shadow`
- `/etc/sudoers`
- `/etc/ssh/sshd_config`
- Critical application configuration files.

### Forward logs to a centralized logging server

Do not depend entirely on local logs. If an attacker compromises a server, they may attempt to delete or modify locally stored logs. Forwarding logs to a separate, protected logging platform makes investigations more reliable.

Examples include:

- Grafana Loki.
- Elasticsearch and Logstash.
- Splunk.
- Graylog.

In later modules, you can explore centralized logging using Grafana Loki and Grafana.

### Configure alerts

Generate alerts for important security events, such as:

- Repeated SSH authentication failures.
- Creation of unexpected user accounts.
- Changes to sudoers policies.
- Modifications to SSH configuration.
- Unexpected service failures.
- Suspicious privilege escalation activity.

### Protect audit configuration

Restrict who can modify audit rules and access audit logs. Consider forwarding audit events to a remote logging platform and using appropriate integrity and retention controls.

### Synchronize system time

Accurate timestamps are essential when correlating events across multiple servers. Use a reliable time synchronization service such as chrony or systemd-timesyncd.

### Test your logging configuration

Do not assume that logs are being collected correctly. Generate test events, verify that they appear in the appropriate log source, and confirm that your alerting and retention mechanisms work.

---

## Lynis vs auditd vs journalctl

These tools serve different purposes and complement each other.

| Feature | Lynis | auditd | journalctl |
|---------|-------|--------|------------|
| Primary purpose | Security posture assessment | Security event auditing | System journal inspection |
| Identifies misconfigurations | Yes | Not its primary purpose | Not its primary purpose |
| Monitors configured file changes | Through security checks | Yes | Only when relevant messages are generated |
| Records configured syscall activity | No | Yes | Not its primary purpose |
| Displays service logs | No | No | Yes |
| Provides hardening recommendations | Yes | No | No |
| Typical usage | Periodic security audits | Continuous event monitoring | Troubleshooting and log analysis |

### Example

Imagine an administrator changes the SSH configuration:

```bash
sudo nano /etc/ssh/sshd_config
```

- **journalctl** can display SSH service messages, including errors or reload activity.
- **auditd** can record the file modification if a matching rule is configured.
- **Lynis** can examine the resulting SSH configuration during a security audit and identify insecure settings.

---

## Practical Lab: Linux Logging and Auditing

**Scenario:** You are managing an Ubuntu EC2 instance hosting a website using NGINX. Your responsibility is to configure logging and auditing so that important security-related activities can be investigated.

### Task 1: Explore Linux logs

- Navigate to `/var/log`.
- Identify authentication, system and kernel logs.
- Check whether rsyslog is installed.
- Identify the role of journald.

### Task 2: Investigate authentication activity

```bash
last -n 10
sudo lastb | head
sudo journalctl -u ssh --since "1 hour ago"
```

Identify successful and unsuccessful login attempts.

### Task 3: Monitor SSH activity

Open two terminal sessions. In the first terminal:

```bash
sudo journalctl -u ssh -f
```

In the second terminal, perform an SSH login attempt. Observe the events generated by the SSH service.

### Task 4: Install and configure auditd

Install auditd and enable the service. Create persistent audit rules to monitor:

- `/etc/passwd`
- `/etc/shadow`
- `/etc/group`
- `/etc/sudoers`
- `/etc/ssh/sshd_config`

Load and verify the rules.

### Task 5: Monitor file modifications

Create an audit rule for a test file. Modify its contents and permissions. Search the audit logs and identify the event.

### Task 6: Investigate audit events

```bash
sudo ausearch
sudo aureport --summary
```

Identify the user, process, file path and event timestamp.

### Task 7: Configure log rotation

Explore the logrotate configuration. Identify how NGINX logs are rotated and how old logs are compressed.

### Task 8: Document your findings

Prepare a report containing:

- Authentication log analysis.
- Successful and failed login information.
- Configured audit rules.
- Generated audit events.
- Log rotation configuration.
- Security improvements recommended for the server.

---

## Conclusion

Linux logging and auditing are essential for maintaining visibility into system activities and investigating security incidents.

Authentication logs help administrators investigate login activity, journald helps troubleshoot services, rsyslog collects and forwards system messages, and auditd records configured security-sensitive events.

By combining these tools with proper log retention, access restrictions, centralized logging and alerting, administrators can build a more reliable security monitoring environment.

> **Remember:** Logging tells you what the system reported, while auditing helps you establish a detailed record of specifically monitored security activities. Both are essential for effective Linux security monitoring.

---

<!-- Reference-style badge definitions -->
[badge-linux]: https://img.shields.io/badge/Linux-Logging-FCC624?logo=linux&logoColor=black
[badge-ubuntu]: https://img.shields.io/badge/Ubuntu-RHEL-E95420?logo=ubuntu&logoColor=white
[badge-journald]: https://img.shields.io/badge/systemd-journald-blue
[badge-auditd]: https://img.shields.io/badge/Audit-auditd-red
[badge-devsecops]: https://img.shields.io/badge/Focus-DevSecOps-purple
---
# File Integrity Monitoring (FIM)

![Linux][badge-linux] ![AIDE][badge-aide] ![Ubuntu][badge-ubuntu] ![RHEL][badge-rhel] ![DevSecOps][badge-devsecops]

> Detecting unauthorized or unexpected changes to files and directories on Linux: how FIM works, how to set up and operate AIDE, and how FIM fits alongside auditd in a DevSecOps workflow.

---

## Table of Contents

- [What Is File Integrity Monitoring?](#what-is-file-integrity-monitoring)
- [Why Is File Integrity Monitoring Important?](#why-is-file-integrity-monitoring-important)
- [How Does File Integrity Monitoring Work?](#how-does-file-integrity-monitoring-work)
- [Understanding File Attributes Monitored by FIM](#understanding-file-attributes-monitored-by-fim)
- [Types of File Integrity Monitoring](#types-of-file-integrity-monitoring)
- [Introduction to AIDE](#introduction-to-aide)
- [Understanding AIDE Architecture](#understanding-aide-architecture)
- [Installing AIDE](#installing-aide)
- [Understanding AIDE Configuration](#understanding-aide-configuration)
- [Creating the Initial AIDE Baseline](#creating-the-initial-aide-baseline)
- [Performing an AIDE Integrity Check](#performing-an-aide-integrity-check)
- [Understanding AIDE Results](#understanding-aide-results)
- [Practical Exercise: Detecting Unauthorized File Changes](#practical-exercise-detecting-unauthorized-file-changes)
- [Updating the AIDE Baseline](#updating-the-aide-baseline)
- [Automating AIDE Checks](#automating-aide-checks)
- [Protecting the AIDE Database](#protecting-the-aide-database)
- [AIDE vs auditd](#aide-vs-auditd)
- [Additional Integrity Verification Tools](#additional-integrity-verification-tools)
- [File Integrity Monitoring in DevSecOps](#file-integrity-monitoring-in-devsecops)
- [Best Practices for File Integrity Monitoring](#best-practices-for-file-integrity-monitoring)
- [Conclusion](#conclusion)

---

## 11.What Is File Integrity Monitoring?

**File Integrity Monitoring (FIM)** is a security mechanism used to detect unauthorized or unexpected changes to files and directories in an operating system.

In Linux, important system files contain information about users, authentication, services, permissions and security configurations. Attackers who compromise a Linux server may attempt to modify these files to maintain access, hide their activities or weaken existing security controls.

For example, an attacker who gains administrative access might:

- Replace legitimate system binaries with malicious versions.
- Modify SSH configuration to enable unauthorized remote access.
- Add a backdoor user account.
- Modify sudoers to grant unauthorized administrative privileges.
- Change firewall configurations.
- Modify application configuration files.
- Add malicious scripts to startup directories.
- Modify web application files to inject malicious code.

Traditional logging and monitoring can help detect some of these activities. However, it is also important to have a mechanism that can independently verify whether important files have changed. This is where FIM becomes useful.

FIM establishes a **trusted baseline** of important files and periodically compares the current filesystem state against that baseline. If a file is added, deleted or modified, the FIM tool reports the difference.

---

## Why Is File Integrity Monitoring Important?

Consider a scenario where you manage an Ubuntu EC2 instance hosting a production application. An attacker compromises the server and replaces a legitimate executable, for example `/usr/bin/ls`, with a malicious version. The new executable may perform malicious activities while appearing to be the normal `ls` command.

Without file integrity monitoring, identifying such a modification can be difficult. With FIM:

1. A trusted baseline of the original executable is created.
2. The file is modified by an attacker.
3. The FIM tool calculates the current file fingerprint.
4. It compares the fingerprint with the original baseline.
5. A difference is reported.

This helps administrators identify unexpected modifications.

> **Important:** FIM detects changes. It does not automatically prevent attackers from modifying files or repair compromised files.

---

## How Does File Integrity Monitoring Work?

Most traditional FIM tools use **cryptographic hashing** to identify changes in files.

A cryptographic hash function generates a fixed-length fingerprint from the contents of a file. For example, SHA-256 generates a 256-bit hash, commonly represented as a 64-character hexadecimal string. Even a small change in the original content produces a completely different hash with extremely high probability.

Example:

```bash
echo "hello" | sha256sum
echo "hellp" | sha256sum
```

The two commands generate different hash values because the input content is different.

You can also calculate the hash of an actual file:

```bash
sha256sum /etc/passwd
```

If the file changes, its hash will generally change as well.

### FIM workflow

```text
        Trusted Linux System
                |
                v
       Select Important Files
                |
                v
       Calculate File Hashes
                |
                v
         Create Baseline
                |
                v
        Store Trusted Database
                |
                v
       Periodic FIM Scan
                |
                v
      Calculate Current Hashes
                |
                v
       Compare With Baseline
                |
          +-----+-----+
          |           |
          v           v
       No Change    Difference
          |           |
          v           v
        Passed      Alert / Report
                      |
                      v
               Investigate Changes
```

---

## Understanding File Attributes Monitored by FIM

FIM tools can monitor more than just file contents. Depending on the configuration, they can track several filesystem attributes.

| Attribute | What It Monitors |
|-----------|------------------|
| File checksum | Whether the file contents have changed. |
| File size | Whether the size of the file has changed. |
| File permissions | Whether permissions such as 644 or 755 have changed. |
| File ownership | Whether the owner has changed. |
| Group ownership | Whether the assigned group has changed. |
| Modification time | Whether the file's modification timestamp has changed. |
| Inode information | Changes in filesystem object identity. |
| File type | Whether the object is a regular file, directory, symbolic link, etc. |

For example, consider:

```text
-rw-r--r-- 1 root root 1200 Nov 20 09:00 config.conf
```

An attacker changes its permissions:

```bash
sudo chmod 777 config.conf
```

Even if the file contents remain unchanged, a properly configured FIM tool can detect the permission modification.

> **Important:** Modification timestamps alone are not sufficient for integrity verification because they can be manipulated. Cryptographic checksums provide stronger evidence of content changes.

---

## Types of File Integrity Monitoring

FIM solutions generally use different approaches.

### Hash-based monitoring

The tool calculates cryptographic hashes of files and compares them with previously recorded values.

```bash
sha256sum /etc/ssh/sshd_config
```

If the hash differs from the trusted baseline, the file contents may have changed.

### Attribute-based monitoring

The tool monitors metadata such as ownership, permissions, file size, modification time and inode information. This helps detect configuration and permission changes even when file contents remain the same.

### Real-time file monitoring

Some FIM solutions use Linux filesystem notification mechanisms such as **inotify** or kernel facilities such as **fanotify** to detect filesystem events as they happen. For example, a monitoring solution can detect when a file is created, modified, renamed or deleted.

> Traditional AIDE scanning is generally periodic rather than real-time.

---

## Introduction to AIDE

**AIDE (Advanced Intrusion Detection Environment)** is a free, open-source file integrity monitoring tool for Linux and Unix-like systems. It helps administrators detect unexpected changes to important files and directories.

AIDE works by creating a database containing the attributes and checksums of selected filesystem objects. During subsequent scans, it compares the current filesystem against the previously generated database. If differences are identified, AIDE reports them.

AIDE can monitor:

- System binaries.
- Configuration files.
- User account databases.
- SSH configuration.
- Application files.
- Web server directories.
- File ownership and permissions.
- File checksums.

---

## Understanding AIDE Architecture

AIDE primarily works using two important components.

### AIDE configuration file

The configuration file defines:

- Which directories and files should be monitored.
- Which attributes should be checked.
- Which directories should be excluded.
- Which cryptographic algorithms should be used.
- Where the AIDE database should be stored.

Default configuration location:

```text
/etc/aide/aide.conf
```

### AIDE database

The AIDE database stores the trusted baseline information generated during initialization. It contains the recorded attributes and checksums of monitored filesystem objects.

Common database locations:

```text
/var/lib/aide/aide.db
/var/lib/aide/aide.db.new
```

> Exact filenames and compression formats can vary by distribution and configuration.

### Architecture

```text
            /etc/aide/aide.conf
                     |
                     v
             AIDE Configuration
                     |
                     v
              Select Files
                     |
                     v
             Calculate Hashes
                     |
                     v
             AIDE Database
                     |
                     v
             Future AIDE Scan
                     |
              +------+------+
              |             |
              v             v
        Current State    Baseline
              |             |
              +------+------+
                     |
                     v
               Comparison
                     |
                     v
              Change Report
```

---

## Installing AIDE

AIDE is available in the package repositories of many Linux distributions.

### Debian / Ubuntu

```bash
sudo apt update
sudo apt install aide -y
aide --version
```

### RHEL family

```bash
sudo dnf install aide -y
aide --version
```

---

## Understanding AIDE Configuration

AIDE uses a configuration file to determine what should be monitored. On Ubuntu and Debian:

```bash
sudo nano /etc/aide/aide.conf
```

The configuration file contains rules that specify which paths should be monitored and which attributes should be checked.

AIDE supports predefined attribute groups. Some commonly used ones:

| Group | Meaning |
|-------|---------|
| `p` | File permissions |
| `i` | Inode information |
| `n` | Number of hard links |
| `u` | User ownership |
| `g` | Group ownership |
| `s` | File size |
| `b` | Block count |
| `m` | Modification time |
| `c` | Change time |
| `S` | Check for growing or shrinking file size |
| `md5` | MD5 checksum |
| `sha256` | SHA-256 checksum |
| `sha512` | SHA-512 checksum |

AIDE combines these attributes into predefined groups:

- `R`: Commonly used for monitoring regular files.
- `L`: Commonly used for monitoring symbolic links.
- `E`: An empty rule that checks no attributes.
- `>`: A special rule for checking growing log files.

The exact attribute combinations depend on the configuration.

Example:

```text
/etc/passwd R
/etc/shadow R
/etc/ssh R
/etc/sudoers R
```

These rules instruct AIDE to monitor the specified paths using the `R` attribute group.

> AIDE configuration supports directory and file-specific rules, exclusions and other expressions. Review the existing distribution configuration before adding custom rules.

---

## Creating the Initial AIDE Baseline

The initial baseline is one of the most important parts of FIM. It represents the trusted state of the system against which future changes are compared.

For example, assume you have a newly configured Ubuntu server. You have already installed the operating system, updated system packages, configured SSH, installed NGINX, applied file permission restrictions and configured firewall rules. At this point, you can create an initial AIDE baseline.

### Ubuntu / Debian

Initialize the database:

```bash
sudo aideinit
```

Depending on the distribution, this generates a new database file, commonly `/var/lib/aide/aide.db.new`. Activate it as the trusted baseline:

```bash
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

> Some distributions use compressed database filenames or provide helper commands for activating the database. Always verify the actual output and paths.

### RHEL family

Initialize AIDE:

```bash
sudo aide --init
```

A new database is commonly generated as `/var/lib/aide/aide.db.new.gz`. Activate it:

```bash
sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
```

> Check the actual database paths in the configuration before executing these commands.

> **Important:** Create the initial baseline only after verifying that the system is in a trusted state. Otherwise, existing malicious modifications may become part of your trusted baseline.

---

## Performing an AIDE Integrity Check

After creating the baseline, you can periodically check whether monitored files have changed (same command on Ubuntu / Debian and RHEL):

```bash
sudo aide --check
```

AIDE compares the current filesystem state with the stored database. If no changes are detected, it reports that the database and filesystem match for the monitored attributes. If changes are detected, AIDE generates a report describing the differences.

You can also specify the configuration file explicitly:

```bash
sudo aide --check --config /etc/aide/aide.conf
```

---

## Understanding AIDE Results

Consider the following example:

```text
AIDE found differences between database and filesystem!!

Summary:
  Total number of entries:      12500
  Added entries:                1
  Removed entries:              0
  Changed entries:              1
```

| Result | Meaning |
|--------|---------|
| Total entries | Number of filesystem objects represented in the comparison. |
| Added entries | New monitored files or directories were detected. |
| Removed entries | Previously monitored files or directories are missing. |
| Changed entries | Existing monitored files or their attributes have changed. |

AIDE may also display which attributes changed:

```text
File: /etc/ssh/sshd_config

Permissions: Changed
Size: Changed
SHA256: Changed
```

This indicates that the monitored SSH configuration file differs from its baseline. An administrator should investigate:

- Who modified the file?
- Was it an authorized configuration change?
- Did a package update modify it?
- Was the modification associated with suspicious activity?

> AIDE detects differences, but it does not determine whether a change was malicious or legitimate.

---

## Practical Exercise: Detecting Unauthorized File Changes

**Scenario:** You are managing an Ubuntu Linux server and want to monitor changes to a sensitive configuration file. For this exercise, use a dedicated test file rather than modifying important production configurations.

### Step 1: Create a test directory

```bash
sudo mkdir -p /opt/fim-lab
echo "Original configuration" | sudo tee /opt/fim-lab/config.txt
```

### Step 2: Configure AIDE to monitor the test directory

```bash
sudo nano /etc/aide/aide.conf
```

Add:

```text
/opt/fim-lab R
```

This tells AIDE to monitor the directory and its contents using the `R` attribute group.

### Step 3: Initialize the baseline

On Ubuntu / Debian:

```bash
sudo aideinit
```

Activate the newly generated database using the actual database path configured on your system. For example:

```bash
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

### Step 4: Perform an initial integrity check

```bash
sudo aide --check
```

The test directory should match its baseline.

### Step 5: Modify the file

```bash
echo "Modified configuration" | sudo tee /opt/fim-lab/config.txt
```

### Step 6: Run AIDE again

```bash
sudo aide --check
```

AIDE should identify the modification. Depending on the configured attributes, it may report changes to file size, modification time and checksum.

### Step 7: Create a new file

```bash
sudo touch /opt/fim-lab/newfile.txt
sudo aide --check
```

AIDE should report the newly created file as an addition.

### Step 8: Delete the new file

```bash
sudo rm /opt/fim-lab/newfile.txt
sudo aide --check
```

AIDE should report the file removal relative to the original baseline.

### Step 9: Cleanup

After completing the exercise, remove the test directory and its configuration rule.

> Do not blindly accept every detected change as legitimate.

---

## Updating the AIDE Baseline

Sometimes files change for legitimate reasons, for example:

- Linux security updates modify system binaries.
- Administrators modify SSH configurations.
- NGINX configuration is updated.
- Application deployments replace application files.
- Package installations create new files.

When legitimate changes occur, you may need to update the AIDE baseline. The process involves reviewing the changes and accepting only those that are expected.

```bash
sudo aide --update
```

This creates a new database based on the current filesystem state, commonly named `/var/lib/aide/aide.db.new`. Activate the new baseline:

```bash
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

> Verify the database paths and compression settings on your distribution.

> **Important:** Never update the baseline immediately after detecting an unexpected modification without investigating it. If an attacker modifies a system binary and you accept the modification into the new database, the malicious version may become part of your trusted baseline.

---

## Automating AIDE Checks

Manually executing AIDE checks is not practical when managing multiple production servers. You can automate integrity checks using cron or systemd timers.

For example, create a daily cron job:

```bash
sudo crontab -e
```

Add:

```text
0 2 * * * /usr/bin/aide --check
```

This schedules an AIDE integrity check every day at 2:00 AM. Verify the actual AIDE binary location with:

```bash
command -v aide
```

AIDE's output should be captured and forwarded to a monitoring or alerting system. Some Linux distributions also provide AIDE-related systemd services or timers, so check the available units before creating your own schedule.

> For production environments, ensure that the check results are not silently discarded.

---

## Protecting the AIDE Database

One of the most important security considerations is protecting the integrity of the AIDE database itself.

Imagine an attacker gains root privileges on a Linux server. The attacker modifies a sensitive system file and then modifies the AIDE database to match the malicious file. During the next integrity check, AIDE may not detect the modification because the trusted baseline has also been changed.

Therefore, storing the only copy of the AIDE database on the same server creates a security weakness.

Recommended practices:

- Store a trusted copy of the database on a separate secure system.
- Use read-only storage where practical.
- Restrict access to the AIDE configuration and database.
- Protect the baseline using appropriate access controls and integrity mechanisms.
- Forward audit and integrity reports to a centralized monitoring platform.
- Update the baseline only after reviewing legitimate changes.
- Maintain backup copies of trusted baselines.

AIDE can also be configured to use database locations that are not writable by ordinary users. For stronger protection, consider storing baseline copies on a separate administrative system.

---

## AIDE vs auditd

AIDE and auditd are both useful Linux security tools, but they serve different purposes.

| Feature | AIDE | auditd |
|---------|------|--------|
| Primary purpose | File integrity monitoring | Security event auditing |
| Detects file modifications | Yes, during scans | Records matching modification events |
| Detects file additions | Yes | Can record matching creation events |
| Detects file deletions | Yes | Can record matching deletion events |
| Records who modified a file | Not reliably by itself | Can record user and process information when suitable rules are configured |
| Monitors file permissions | Yes, if configured | Can record permission-changing operations |
| Operation | Usually periodic scanning | Event-driven auditing |
| Main use case | Detecting unexpected filesystem changes | Investigating who performed monitored activities |

### Example

Imagine someone modifies `/etc/ssh/sshd_config`.

- **AIDE** can identify that the file differs from its trusted baseline.
- **auditd** can record the modification event if an appropriate rule is configured.

Together, these tools provide better visibility. AIDE identifies the difference, while auditd can help investigate the activity that caused it.

---

## Additional Integrity Verification Tools

Apart from AIDE, Linux provides other tools that can help verify file integrity.

### SHA-256

Calculate a file checksum manually:

```bash
sha256sum /etc/passwd
```

Compare the current checksum with a previously stored trusted checksum. This is useful for understanding the basic concept behind hash-based FIM.

> A manually maintained checksum file stored on the same compromised system is not a strong security boundary.

### debsums

On Debian-based distributions, `debsums` checks installed package files against checksum information supplied by the package database.

```bash
sudo apt install debsums -y
sudo debsums -c
```

This reports files whose checksums differ from the package-provided checksums or cannot be verified.

> Not every package file necessarily has checksum information available.

### rpm verification

On RHEL-based distributions, RPM provides a package verification mechanism:

```bash
sudo rpm -Va
```

This verifies installed package files against metadata stored in the RPM database. The output can identify differences involving file size, permissions, ownership, checksums, modification time and other package attributes.

> RPM verification output is not automatically evidence of compromise. Configuration changes, package updates and legitimate modifications can also produce differences.

---

## File Integrity Monitoring in DevSecOps

FIM is useful in DevSecOps because infrastructure and application security do not stop after deployment. Even after deploying a secured application, system files and application configurations may change unexpectedly.

Consider a production Kubernetes worker node or an EC2 instance running NGINX. You can use FIM to monitor:

- SSH configuration files.
- System binaries.
- Sudoers policies.
- User account databases.
- NGINX configuration.
- Application configuration.
- Important deployment files.

A practical security monitoring workflow:

```text
  Deploy server (Terraform / IaC)
               |
               v
  Apply security configuration (Ansible)
               |
               v
  Install and configure AIDE
               |
               v
  Generate trusted baseline after validation
               |
               v
  Schedule regular integrity checks
               |
               v
  Forward reports to centralized logging
               |
               v
  Investigate unexpected changes
               |
               v
  Update baseline after approved changes
```

This helps maintain security visibility throughout the infrastructure lifecycle.

---

## Best Practices for File Integrity Monitoring

- Create the initial baseline when the system is known to be clean.
- Monitor critical operating system and application files.
- Avoid monitoring every temporary or frequently changing file without a reason.
- Use strong cryptographic hash algorithms such as SHA-256 or SHA-512.
- Protect the AIDE database from unauthorized modifications.
- Store a trusted baseline copy outside the monitored server.
- Schedule integrity checks regularly.
- Investigate all unexpected changes.
- Update the baseline only after validating legitimate modifications.
- Forward FIM reports to centralized logging and monitoring platforms.
- Integrate integrity verification into server hardening and deployment workflows.
- Review monitoring coverage periodically as the server configuration changes.

---

## Conclusion

File Integrity Monitoring is an important component of Linux security because it helps identify unauthorized modifications to critical system and application files.

AIDE provides a practical way to establish trusted file baselines and detect changes through periodic integrity checks. When combined with auditd, FIM becomes more useful for security investigations:

- AIDE identifies what changed.
- auditd can help identify who performed a monitored operation and when it happened.
- Centralized logging helps preserve and correlate the evidence.

> **Remember:** File Integrity Monitoring detects unexpected changes; it does not prevent them. The goal is to identify suspicious modifications as early as possible and investigate them before they affect the system.

---

<!-- Reference-style badge definitions -->
[badge-linux]: https://img.shields.io/badge/Linux-Security-FCC624?logo=linux&logoColor=black
[badge-aide]: https://img.shields.io/badge/Tool-AIDE-blue
[badge-ubuntu]: https://img.shields.io/badge/Ubuntu-Debian-E95420?logo=ubuntu&logoColor=white
[badge-rhel]: https://img.shields.io/badge/RHEL-Family-EE0000?logo=redhat&logoColor=white
[badge-devsecops]: https://img.shields.io/badge/Focus-DevSecOps-purple

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

# Linux Security Auditing with Lynis

![Linux][badge-linux] ![Ubuntu][badge-ubuntu] ![Lynis][badge-lynis] ![DevSecOps][badge-devsecops] ![License][badge-license]

> Security auditing and system hardening for Linux servers: what Lynis is, how it works, how to read its output, and a practical audit-and-remediate workflow.

---

## Table of Contents

- [What Is Lynis?](#what-is-lynis)
- [How Does Lynis Work?](#how-does-lynis-work)
- [Installing Lynis](#installing-lynis)
- [Performing a Linux Security Audit](#performing-a-linux-security-audit)
- [Understanding Lynis Warnings and Suggestions](#understanding-lynis-warnings-and-suggestions)
- [Understanding the Lynis Hardening Index](#understanding-the-lynis-hardening-index)
- [Understanding Lynis Log and Report Files](#understanding-lynis-log-and-report-files)
- [Investigating Individual Security Findings](#investigating-individual-security-findings)
- [Running a Quick Audit](#running-a-quick-audit)
- [Practical Example: Improving Linux Server Security Using Lynis](#practical-example-improving-linux-server-security-using-lynis)
- [Practical Workflow for Linux Security Auditing](#practical-workflow-for-linux-security-auditing)
- [Lynis Best Practices](#lynis-best-practices)
- [Lynis vs auditd](#lynis-vs-auditd)
- [Conclusion](#conclusion)

---

## What Is Lynis?

**Lynis** is a free, open-source security auditing and system hardening tool for Linux and Unix-based operating systems. It is used by Linux administrators, DevSecOps engineers and security professionals to evaluate the security posture of a server.

Lynis performs hundreds of automated security checks to identify misconfigurations, weak security controls, unnecessary services and potential security vulnerabilities.

It examines different components of a Linux system, including:

| Area | What Lynis checks |
|------|-------------------|
| **User and Authentication Security** | User accounts, password policies, authentication mechanisms and account configurations |
| **SSH Security** | Insecure SSH configurations, such as root login permissions and weak authentication settings |
| **File Permissions** | Permissions and ownership of sensitive system files and directories |
| **Firewall Configuration** | Whether a firewall is installed, enabled and configured |
| **Kernel Security** | Kernel parameters and security-related configurations |
| **Running Services** | Unnecessary services and potentially insecure processes |
| **Logging and Auditing** | System logging configurations and auditing mechanisms |
| **Software Security** | Installed packages, outdated software and security-related configurations |
| **Network Security** | Network-related configurations and security controls |
| **System Hardening** | Missing security mechanisms, with recommendations to improve the overall security posture |

---

## How Does Lynis Work?

Lynis performs a series of security tests against the operating system and its installed components.

```text
  +------------------------------------------------------+
  | 1. Collect info: distro, kernel, packages, services  |
  +--------------------------+---------------------------+
                             |
                             v
  +------------------------------------------------------+
  | 2. Execute security tests against system components  |
  +--------------------------+---------------------------+
                             |
                             v
  +------------------------------------------------------+
  | 3. Evaluate configurations against security checks   |
  +--------------------------+---------------------------+
                             |
                             v
  +------------------------------------------------------+
  | 4. Identify weaknesses and missing controls          |
  +--------------------------+---------------------------+
                             |
                             v
  +------------------------------------------------------+
  | 5. Generate warnings and suggestions                 |
  +--------------------------+---------------------------+
                             |
                             v
  +------------------------------------------------------+
  | 6. Calculate the hardening index                     |
  +------------------------------------------------------+
```

### Example

Consider an Ubuntu server running an NGINX website. During the audit, Lynis may identify:

- SSH root login is permitted.
- Firewall is not enabled.
- Some unnecessary services are running.
- Sensitive files have inappropriate permissions.
- Audit logging is not configured.
- Additional kernel hardening parameters could be enabled.

Lynis reports these findings so that the administrator can investigate and remediate them.

---

## Installing Lynis

There are multiple ways to install Lynis on a Linux system.

### Method 1: Install using APT

For Ubuntu and Debian-based distributions:

```bash
sudo apt update
sudo apt install lynis -y
```

Verify the installation:

```bash
lynis show version
```

> **Note:** Distribution repositories may provide an older Lynis release.

### Method 2: Install from the official GitHub repository

You can also obtain Lynis directly from its [official source repository][lynis-repo].

Install Git:

```bash
sudo apt install git -y
```

Clone the repository:

```bash
git clone https://github.com/CISOfy/lynis.git
```

Navigate to the directory:

```bash
cd lynis
```

Verify the version:

```bash
sudo ./lynis show version
```

This method allows you to run Lynis directly from the cloned source directory without using the package manager.

> For production systems, use a controlled update process and verify the source before executing security tools with elevated privileges.

---

## Performing a Linux Security Audit

Once Lynis is installed, you can perform a complete security audit.

If installed through APT:

```bash
sudo lynis audit system
```

If running from the cloned repository:

```bash
sudo ./lynis audit system
```

The `audit system` command initiates a comprehensive security assessment of the Linux server. Lynis executes multiple tests and displays the results directly in the terminal.

You may encounter the following result indicators:

| Indicator | Meaning |
|-----------|---------|
| `[ OK ]` | The security test passed. |
| `[ WARNING ]` | A potential security issue requires investigation. |
| `[ SUGGESTION ]` | An additional security improvement is recommended. |
| `[ FOUND ]` | A particular component or configuration was detected. |
| `[ NOT FOUND ]` | The tested component or configuration was not detected. |

> The exact output depends on the Lynis version and the tests executed.

---

## Understanding Lynis Warnings and Suggestions

Lynis generates two important categories of findings.

### Warnings

Warnings indicate configurations or conditions that may introduce security risks.

Examples:

- SSH permits direct root login.
- Firewall protection is missing or inactive.
- Sensitive configuration files have weak permissions.
- Unnecessary services are enabled.

Warnings should be investigated and prioritised based on their actual security impact.

### Suggestions

Suggestions are recommendations that can improve the security posture of the system.

Examples:

- Enable additional kernel hardening parameters.
- Configure a stronger password policy.
- Improve system logging.
- Enable additional security mechanisms.
- Remove unnecessary software packages.

Not every suggestion is mandatory. Evaluate each recommendation based on your server's role and operational requirements.

---

## Understanding the Lynis Hardening Index

One of the important outputs generated by Lynis is the **Hardening Index**. It is a numerical indicator intended to help administrators evaluate and compare the system's security hardening status, commonly presented on a scale of 0–100.

```text
Hardening index : 72 [##########]
```

The index can help administrators understand whether their hardening efforts are improving the system's security posture. However, it is important to understand that:

- A higher score does not guarantee that the server is secure.
- A lower score does not necessarily mean the server is vulnerable.
- The score depends on the tests executed and the system configuration.
- Different server roles may produce different results.
- Some recommendations may not apply to a particular environment.

> **Important:** Do not blindly chase a perfect score. The actual objective is to identify and reduce security risks, not simply increase a numerical value.

---

## Understanding Lynis Log and Report Files

After performing an audit, Lynis stores information about the tests and their results. The default locations are:

| File | Purpose |
|------|---------|
| `/var/log/lynis.log` | Detailed information about the security tests performed during the audit |
| `/var/log/lynis-report.dat` | Structured audit findings, warnings, suggestions and report information |

### View the detailed audit log

```bash
sudo less /var/log/lynis.log
```

This file helps you investigate what Lynis checked and what results were generated.

### View the structured report

```bash
sudo less /var/log/lynis-report.dat
```

This report contains information that can be filtered using commands such as `grep`.

### Extract the Hardening Index

```bash
sudo grep hardening_index /var/log/lynis-report.dat
```

### Display all warnings

```bash
sudo grep '^warning\[\]' /var/log/lynis-report.dat
```

### Display all suggestions

```bash
sudo grep '^suggestion\[\]' /var/log/lynis-report.dat
```

These commands help administrators quickly identify the findings without manually reading the entire report.

---

## Investigating Individual Security Findings

Sometimes Lynis generates a warning or suggestion with a test identifier, for example:

```text
SSH-7440
```

This identifier helps you identify the security test associated with the finding. You can investigate the test using:

```bash
sudo lynis show details SSH-7440
```

This displays additional information about the test and helps you understand what it checks. Investigate the finding before making configuration changes.

A good security remediation process involves:

1. Identify the finding.
2. Understand the security risk.
3. Locate the affected configuration.
4. Apply an appropriate security fix.
5. Validate that the fix does not break existing services.
6. Run Lynis again to verify the result.

---

## Running a Quick Audit

If you want to perform a quicker assessment, Lynis provides the `--quick` option.

```bash
sudo lynis audit system --quick
```

This option reduces interactive pauses during the audit. It is useful when performing repeated assessments or incorporating Lynis into administrative workflows.

---

## Practical Example: Improving Linux Server Security Using Lynis

**Scenario:** You have an Ubuntu EC2 instance hosting a website using NGINX. You want to evaluate its security posture and identify possible weaknesses.

### Step 1: Install Lynis

```bash
sudo apt update
sudo apt install lynis -y
```

### Step 2: Perform the initial audit

```bash
sudo lynis audit system
```

Record the initial hardening index and identify all warnings and suggestions.

### Step 3: Investigate the findings

Check the warnings:

```bash
sudo grep '^warning\[\]' /var/log/lynis-report.dat
```

Check the suggestions:

```bash
sudo grep '^suggestion\[\]' /var/log/lynis-report.dat
```

### Step 4: Apply security improvements

Depending on the findings, you may perform the following:

- Disable direct SSH root login.
- Disable SSH password authentication after verifying key-based access.
- Configure UFW with a default-deny inbound policy.
- Remove unnecessary services.
- Correct permissions on sensitive files.
- Enable auditd for security event monitoring.
- Apply appropriate kernel security parameters.
- Update outdated packages.

### Step 5: Run the audit again

```bash
sudo lynis audit system
```

Compare the new findings with the initial audit. Check whether the warnings have been resolved and whether the hardening index has improved.

### Step 6: Document the results

Maintain a record of the initial and final audit results.

| Security Check | Initial Status | Final Status |
|----------------|----------------|--------------|
| SSH root login | Enabled | Disabled |
| UFW firewall | Inactive | Active |
| Auditd | Not configured | Configured |
| Sensitive file permissions | Needs investigation | Verified |
| System packages | Updates available | Updated |

> The actual results will depend on your system and the changes you implement.

---

## Practical Workflow for Linux Security Auditing

A recommended workflow for using Lynis in Linux security auditing:

```text
        Start Linux Security Audit
                   |
                   v
           Install Lynis
                   |
                   v
          Perform Initial Audit
                   |
                   v
        Record Hardening Index
                   |
                   v
        Investigate Warnings
                   |
                   v
       Review Security Suggestions
                   |
                   v
         Apply Security Fixes
                   |
                   v
        Perform Audit Again
                   |
                   v
       Compare Audit Results
                   |
                   v
        Document Improvements
```

---

## Lynis Best Practices

- Run Lynis periodically to evaluate the security posture of Linux servers.
- Perform an audit after major system configuration changes.
- Use elevated privileges when performing a complete system audit so that Lynis can access the necessary system information.
- Investigate warnings before implementing changes.
- Do not blindly apply every suggestion.
- Maintain audit reports to compare security improvements over time.
- Use Lynis alongside other security tools such as auditd, UFW and file integrity monitoring solutions.
- Include Lynis audits in regular server security assessment procedures.

---

## Lynis vs auditd

Lynis and auditd are both useful Linux security tools, but they serve different purposes.

| Feature | Lynis | auditd |
|---------|-------|--------|
| Primary purpose | Security auditing and hardening assessment | Security event auditing |
| Operation | Runs security tests when invoked | Runs continuously as an auditing service |
| Identifies misconfigurations | Yes | Not its primary purpose |
| Provides hardening recommendations | Yes | No |
| Monitors file changes | Checks file security configurations | Records configured file changes |
| Records security events | Maintains audit logs and reports | Records matching security events |
| Typical usage | Periodic security assessments | Continuous security monitoring |

### Example

Imagine someone modifies the SSH configuration file:

```bash
sudo nano /etc/ssh/sshd_config
```

- **Lynis:** Can identify potentially insecure SSH configuration settings during its next security audit.
- **auditd:** Can record the modification event if an appropriate audit rule is configured.

Therefore, both tools complement each other.

---

## Conclusion

Lynis is an important tool for Linux security auditing and system hardening. It helps administrators identify security weaknesses, understand missing security controls and improve the overall security posture of Linux servers.

In a DevSecOps environment, Lynis can be incorporated into regular server security assessments to validate hardening configurations and identify areas requiring improvement.

> **Remember:** Lynis identifies security weaknesses and recommends improvements; the administrator is responsible for evaluating and implementing the appropriate fixes.

---

<!-- Reference-style link definitions -->
[lynis-repo]: https://github.com/CISOfy/lynis
[badge-linux]: https://img.shields.io/badge/Linux-Security-FCC624?logo=linux&logoColor=black
[badge-ubuntu]: https://img.shields.io/badge/Ubuntu-Debian--based-E95420?logo=ubuntu&logoColor=white
[badge-lynis]: https://img.shields.io/badge/Tool-Lynis-blue
[badge-devsecops]: https://img.shields.io/badge/Focus-DevSecOps-purple
[badge-license]: https://img.shields.io/badge/Lynis-Open--Source-brightgreen
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
