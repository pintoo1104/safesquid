#!/bin/bash

# ============================
# Linux Security Audit and Hardening Script
# Author: Akshay
# ============================

# Output report file
REPORT_FILE="security_audit_report.txt"
> "$REPORT_FILE"

log() {
    echo -e "$1" | tee -a "$REPORT_FILE"
}

section() {
    log "\n==================== $1 ===================="
}

# ==========================
# User and Group Audit
# ==========================
user_group_audit() {
    section "User and Group Audit"
    log "All Users:" && cut -d: -f1 /etc/passwd
    log "\nUsers with UID 0 (non-root):" && awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd
    log "\nUsers without passwords:" && awk -F: '($2 == "*" || $2 == "!") {print $1}' /etc/shadow
}

# ==========================
# File and Directory Permissions Audit
# ==========================
permission_audit() {
    section "File and Directory Permissions"
    log "World-writable files:" && find / -xdev -type f -perm -0002 2>/dev/null
    log "\nWorld-writable directories:" && find / -xdev -type d -perm -0002 2>/dev/null
    log "\nSUID/SGID Files:" && find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null
}

# ==========================
# Service Audit
# ==========================
service_audit() {
    section "Service Audit"
    log "Active Services:" && systemctl list-units --type=service --state=active
    log "\nListening Ports:" && ss -tulnp
}

# ==========================
# Firewall and Network Audit
# ==========================
firewall_network_audit() {
    section "Firewall and Network Audit"
    if command -v ufw >/dev/null; then
        ufw status verbose | tee -a "$REPORT_FILE"
    elif command -v iptables >/dev/null; then
        iptables -L -n -v | tee -a "$REPORT_FILE"
    else
        log "No firewall found."
    fi

    log "\nIP Forwarding:"
    sysctl net.ipv4.ip_forward | tee -a "$REPORT_FILE"
    sysctl net.ipv6.conf.all.forwarding | tee -a "$REPORT_FILE"
}

# ==========================
# IP and Network Configuration
# ==========================
ip_checks() {
    section "IP Configuration"
    ip -o addr show | awk '{print $2, $4}' | tee -a "$REPORT_FILE"
    log "\nPublic IPs:" && curl -s ifconfig.me | tee -a "$REPORT_FILE"
}

# ==========================
# Security Updates
# ==========================
check_updates() {
    section "Security Updates"
    apt update -qq && apt list --upgradable 2>/dev/null | grep security | tee -a "$REPORT_FILE"
}

# ==========================
# Log Monitoring
# ==========================
log_monitoring() {
    section "Suspicious SSH Logins"
    journalctl -u ssh | grep -i "failed\|invalid" | tail -n 20 | tee -a "$REPORT_FILE"
}

# ==========================
# SSH Hardening
# ==========================
ssh_hardening() {
    section "SSH Hardening"
    sed -i 's/^#?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
    log "SSH hardened: root login disabled and password auth disabled."
}

# ==========================
# Disable IPv6
# ==========================
disable_ipv6() {
    section "Disabling IPv6"
    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1
    echo -e "net.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p
    log "IPv6 disabled."
}

# ==========================
# GRUB Hardening
# ==========================
secure_bootloader() {
    section "GRUB Bootloader Hardening"
    if ! command -v grub-mkpasswd-pbkdf2 >/dev/null; then
        log "Installing grub-common..."
        apt install -y grub-common
    fi

    read -s -p "Enter GRUB password: " GRUB_PASSWORD
    echo
    read -s -p "Confirm GRUB password: " GRUB_PASSWORD_CONFIRM
    echo

    if [ "$GRUB_PASSWORD" != "$GRUB_PASSWORD_CONFIRM" ]; then
        log "Password mismatch. Skipping GRUB hardening."
        return
    fi

    HASHED=$(echo -e "$GRUB_PASSWORD\n$GRUB_PASSWORD" | grub-mkpasswd-pbkdf2 | grep grub.pbkdf2 | awk '{print $NF}')
    echo "set superusers=\"admin\"" > /etc/grub.d/40_custom
    echo "password_pbkdf2 admin $HASHED" >> /etc/grub.d/40_custom
    update-grub
    log "GRUB password set."
}

# ==========================
# Automatic Updates
# ==========================
setup_auto_updates() {
    section "Automatic Updates"
    apt install -y unattended-upgrades
    dpkg-reconfigure -f noninteractive unattended-upgrades
    log "Unattended upgrades configured."
}

# ==========================
# Run all audits and hardening
# ==========================
main() {
    user_group_audit
    permission_audit
    service_audit
    firewall_network_audit
    ip_checks
    check_updates
    log_monitoring
    ssh_hardening
    disable_ipv6
    secure_bootloader
    setup_auto_updates

    section "Summary"
    log "Audit and hardening complete. Review $REPORT_FILE for full details."
}

main
