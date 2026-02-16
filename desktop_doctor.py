#!/usr/bin/env python3

import subprocess
import os
import shutil
from pathlib import Path

def run(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout.strip()
    except:
        return "ERROR"

def section(title):
    print("\n" + "="*60)
    print(title)
    print("="*60)


# ------------------------------------------------
section("SYSTEM INFO")

print(run("uname -a"))
print("User:", os.getenv("USER"))
print("Home:", Path.home())


# ------------------------------------------------
section("CPU / MEMORY")

print(run("lscpu | head -n 20"))
print(run("free -h"))


# ------------------------------------------------
section("DISK STATUS")

print(run("lsblk"))
print(run("df -h"))
print(run("mount | grep '^/dev'"))


# ------------------------------------------------
section("ENCRYPTION CHECK")

print(run("lsblk -f | grep crypt"))
print(run("sudo cryptsetup status $(lsblk -o NAME,TYPE | grep crypt | awk '{print $1}' | head -n1) 2>/dev/null"))


# ------------------------------------------------
section("NETWORK")

print(run("ip a"))
print(run("ip route"))
print(run("resolvectl status | grep DNS"))


# ------------------------------------------------
section("VPN STATUS")

ip = run("curl -s ifconfig.me")
org = run("curl -s https://ipinfo.io/org")

print("Public IP:", ip)
print("Org:", org)

if "Proton" in org:
    print("VPN: ACTIVE")
else:
    print("VPN: NOT DETECTED")

print(run("ip a | grep proton"))


# ------------------------------------------------
section("FIREWALL")

print(run("sudo ufw status"))
print(run("sudo iptables -L | head -n 20"))


# ------------------------------------------------
section("SECURITY SERVICES")

services = ["ufw", "fail2ban", "auditd"]

for s in services:
    status = run(f"systemctl is-active {s}")
    print(f"{s}: {status}")


# ------------------------------------------------
section("FAILED SERVICES")

print(run("systemctl --failed"))


# ------------------------------------------------
section("PYTHON")

print(run("python3 --version"))
print(run("pip3 --version"))
print(run("which python3"))
print(run("pipx --version"))


# ------------------------------------------------
section("VS CODE")

print("Code binary:", shutil.which("code"))
print(run("code --version"))
print(run("code --list-extensions"))


# ------------------------------------------------
section("HARDWARE")

print(run("lspci | head -n 20"))
print(run("lsusb"))


# ------------------------------------------------
section("TEMPERATURE / POWER")

print(run("sensors 2>/dev/null"))
print(run("upower -e 2>/dev/null"))


# ------------------------------------------------
section("PROCESS LOAD")

print(run("top -b -n1 | head -n 20"))


# ------------------------------------------------
section("SUMMARY")

print("""
If everything shows:

VPN ACTIVE
No failed services
Disk healthy
Memory normal

System state = GOOD
""")

print("\nDR-PC COMPLETE")
