README-secure-baseline.md
```

---

# Secure Baseline Deployment

## Overview

`secure-baseline.sh` is a system hardening and service-preparation script for Ubuntu-based systems.

It configures:

* OpenSSH server (secured)
* Stateful iptables firewall (default deny)
* Fail2Ban intrusion prevention
* Port 8888 reserved for future services
* Persistent firewall rules
* Execution logging

This script is designed to be:

* Idempotent (safe to re-run)
* Structured
* Logged
* Expandable

---

# What the Script Actually Does

## 1. Enables Strict Bash Mode

```bash
set -euo pipefail
```

This ensures:

* Script exits on any error
* Undefined variables cause failure
* Pipeline errors are not ignored

Prevents silent misconfiguration.

---

## 2. Logs All Output

All output is written to:

```
/var/log/secure-baseline.log
```

This allows:

* Auditing
* Debugging
* Change tracking

---

## 3. Installs Required Packages

Installs:

* `openssh-server`
* `fail2ban`
* `iptables-persistent`

Ensures required services exist before configuration.

---

## 4. Configures SSH

Changes `/etc/ssh/sshd_config`:

* `PermitRootLogin no`
* `PasswordAuthentication yes`
* `X11Forwarding no`
* `MaxAuthTries 3`

Effects:

* Root login disabled
* Password auth allowed (can later switch to key-only)
* Limits brute-force attempts
* Reduces attack surface

Restarts SSH after modification.

---

## 5. Configures Firewall (iptables)

### Default Policy

```
INPUT DROP
FORWARD DROP
OUTPUT ACCEPT
```

Meaning:

* All inbound traffic denied unless explicitly allowed
* Outbound allowed

### Allows:

* Loopback interface
* Established/related connections
* TCP port 22 (SSH)
* TCP port 8888 (future service)

Then saves rules so they persist across reboot.

This creates a “default deny” posture.

---

## 6. Configures Fail2Ban

Creates `/etc/fail2ban/jail.local` with:

### Global Defaults

* 1 hour ban
* 10 minute detection window
* 5 failed attempts trigger ban
* Uses systemd log backend
* Uses nftables for enforcement

### SSH Jail

Monitors SSH logs.
Bans IPs that brute-force login.

### python-8888 Jail

Prepares monitoring for:

* Port 8888
* Custom log pattern:

  ```
  Failed login from <IP>
  ```

This allows future custom services to integrate with Fail2Ban simply by logging correctly.

---

## 7. Creates Custom Filter

File:

```
/etc/fail2ban/filter.d/python-8888.conf
```

Defines the pattern Fail2Ban will match.

This makes port 8888 enforcement ready before the service even exists.

---

## 8. Restarts Fail2Ban

Applies configuration changes.

---

## 9. Prints Status Summary

Displays:

* SSH status
* Fail2Ban status
* Active jails
* Firewall rules

This confirms deployment state immediately.

---

# Security Model After Execution

System behavior becomes:

* All inbound traffic blocked by default
* SSH exposed and protected
* Brute force attempts automatically banned
* Port 8888 open but monitored
* Rules persistent across reboot
* Logged execution trail

---

# Why Port 8888 Is Open

Port 8888 is reserved for:

* API services
* Local model inference
* FastAPI applications
* Internal development servers

Opening it now:

* Avoids future firewall drift
* Ensures Fail2Ban integration works immediately
* Prepares for service hosting

If not needed, remove this rule from the script.

---

# How to Run

1. Save script:

```
secure-baseline.sh
```

2. Make executable:

```
chmod +x secure-baseline.sh
```

3. Run:

```
sudo ./secure-baseline.sh
```

---

# How to Extend It

Future enhancements may include:

* Switching SSH to key-only authentication
* Changing SSH port
* Adding nginx reverse proxy
* Enabling TLS
* Docker-based service isolation
* Rate limiting
* Log rotation policy
* LAN-only mode

---

# Intended Use Case

This script is designed for:

* Personal hardened workstation
* Lab environment
* Development machine
* Lightweight service host
* Pre-production experimentation

It is not a full enterprise compliance framework.

---

# Recovery Notes

If something breaks:

* Check `/var/log/secure-baseline.log`
* Check:

  ```
  systemctl status ssh
  systemctl status fail2ban
  ```
* Inspect firewall:

  ```
  iptables -L -n --line-numbers
  ```

---

# Versioning Recommendation

At top of script:

```
# Version: 1.0
```

Increment version when modifying.

Keep script + README together in same directory or repository.

---

If you want, next we can:

* Convert this into a Git-tracked infrastructure repo
* Create a “hardened + inference ready” edition
* Or build a second script specifically for model hosting

Now you’re not typing commands.

You’re maintaining a baseline.

