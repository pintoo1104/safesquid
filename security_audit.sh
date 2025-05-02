#!/bin/bash

# ========================
# Linux Security Audit and Hardening Script
# Author: Akshay
# Description: Modular and reusable script to audit and harden Linux servers.
# ========================

REPORT_FILE="security_audit_report.txt"
> "$REPORT_FILE"  # Clear previous report if any

# Function to log messages to both the console and the report file
log() {
    echo -e "$1" | tee -a "$REPORT_FILE"
}

# Function for section headers in the report
section() {
    log "\n==================== $1 ===================="
}

# ========================
# 1. User and Group Audit
# ========================

user_group_audit() {
    section "User and Group Audit"
    log "All Users:" && cut -d: -f1 /etc/passwd
    log "\nUsers with UID 0 (non-root):"
    awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd
    log "\nUsers without passwords:"
    awk -F: '($2 == "*" || $2 == "!") {print $1}' /etc/shadow
}

# ========================
# 2. File Permission Audit
# ========================

permission_audit() {
    section "File and Directory Permissions"
    log "World-writable files:" && find / -xdev -type f -perm -0002 2>/dev/null
    log "\nWorld-writable directories:" && find / -xdev -type d -perm -0002 2>/dev/null
    log "\nSUID/SGID Files:" && find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null
}

# ========================
# 3. Service Audit
# ========================

service_audit() {
    section "Service Audit"
    log "Active Services:" && systemctl list-units --type=service --state=active
    log "\nListening Ports:" && ss -tulnp
}

# ========================
# 4. Firewall & Network Security
# ========================

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

# ========================
# 5. IP and Network Configuration
# ========================

ip_checks() {
    section "IP Configuration"
    ip -o addr show | awk '{print $2, $4}' | tee -a "$REPORT_FILE"
    log "\nPublic IPs:" && curl -s ifconfig.me | tee -a "$REPORT_FILE"
}

# ========================
# 6. Security Updates
# ========================

check_updates() {
    section "Security Updates"
    apt update -qq && apt list --upgradable 2>/dev/null | grep security | tee -a "$REPORT_FILE"
}

# ========================
# 7. Log Monitoring
# ========================

log_monitoring() {
    section "Suspicious SSH Logins"
    journalctl -u ssh | grep -i "failed\|invalid" | tail -n 20 | tee -a "$REPORT_FILE"
}

# ========================
# Main Function to Run All Audits
# ========================

main() {
    user_group_audit
    permission_audit
    service_audit
    firewall_network_audit
    ip_checks
    check_updates
    log_monitoring

    section "Summary"
    log "Audit and hardening complete. Review $REPORT_FILE for full details."
}

main
