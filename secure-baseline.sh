#!/usr/bin/env bash
#
# Secure Baseline Deployment Script
# Version: 1.0
# Purpose: Harden workstation + prepare service host
#

set -euo pipefail

LOGFILE="/var/log/secure-baseline.log"
exec > >(tee -a "$LOGFILE") 2>&1

echo "======================================"
echo " Secure Baseline Deployment Starting "
echo "======================================"
echo "Timestamp: $(date)"
echo

### -----------------------------
### 1. Install Required Packages
### -----------------------------
echo "[1] Installing required packages..."
apt update -y
apt install -y openssh-server fail2ban iptables-persistent

### -----------------------------
### 2. Enable & Harden SSH
### -----------------------------
echo "[2] Configuring SSH..."

systemctl enable ssh
systemctl start ssh

SSHD_CONFIG="/etc/ssh/sshd_config"

sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' $SSHD_CONFIG
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' $SSHD_CONFIG
sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' $SSHD_CONFIG
sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' $SSHD_CONFIG

systemctl restart ssh

### -----------------------------
### 3. Configure Firewall
### -----------------------------
echo "[3] Configuring iptables firewall..."

iptables -F
iptables -X

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 8888 -j ACCEPT

netfilter-persistent save

### -----------------------------
### 4. Configure Fail2Ban
### -----------------------------
echo "[4] Configuring Fail2Ban..."

cat > /etc/fail2ban/jail.local <<'F2B'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd
banaction = nftables-multiport

[sshd]
enabled = true
port = 22
logpath = %(sshd_log)s

[python-8888]
enabled = true
port = 8888
filter = python-8888
logpath = /var/log/syslog
maxretry = 5
F2B

mkdir -p /etc/fail2ban/filter.d

cat > /etc/fail2ban/filter.d/python-8888.conf <<'FILTER'
[Definition]
failregex = .*Failed login from <HOST>.*
ignoreregex =
FILTER

systemctl restart fail2ban

### -----------------------------
### 5. Status Summary
### -----------------------------
echo
echo "========= STATUS SUMMARY ========="
echo
systemctl is-active ssh
systemctl is-active fail2ban
fail2ban-client status || true
iptables -L -n --line-numbers
echo
echo "Log file saved to: $LOGFILE"
echo "=================================="

