#!/bin/bash

# ==============================
# Linux Security Audit Script
# ==============================

REPORT="security_audit_report.txt"
> "$REPORT"

log() {
    echo -e "\n$1" | tee -a "$REPORT"
}

# 1. User and Group Audits
user_audit() {
    log "----- USER & GROUP AUDITS -----"
    getent passwd | awk -F: '$3 == 0 {print "UID 0 user: "$1}' | tee -a "$REPORT"
    getent passwd | cut -d: -f1 | xargs -n1 -I{} sudo passwd -S {} | grep -E "NP|!!" | tee -a "$REPORT"
    cut -d: -f1 /etc/group | tee -a "$REPORT"
}

# 2. File and Directory Permissions
file_permission_audit() {
    log "----- FILE & DIRECTORY PERMISSIONS -----"
    find / -type d -perm -0002 -exec ls -ld {} \; 2>/dev/null | tee -a "$REPORT"
    find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -ld {} \; 2>/dev/null | tee -a "$REPORT"
    find /home -name ".ssh" -exec ls -ld {} \; 2>/dev/null | tee -a "$REPORT"
}

# 3. Service Audits
service_audit() {
    log "----- SERVICE AUDITS -----"
    systemctl list-units --type=service --state=running | tee -a "$REPORT"
    netstat -tulnp | grep -v "127.0.0.1" | tee -a "$REPORT"
}

# 4. Firewall and Network Security
firewall_audit() {
    log "----- FIREWALL & NETWORK SECURITY -----"
    if command -v ufw &> /dev/null; then
        ufw status verbose | tee -a "$REPORT"
    elif command -v iptables &> /dev/null; then
        iptables -L -n -v | tee -a "$REPORT"
    else
        log "No firewall tool found."
    fi

    ss -tuln | tee -a "$REPORT"
}

# 5. IP and Network Configuration
ip_check() {
    log "----- IP CONFIGURATION -----"
    ip -4 addr show | grep inet | awk '{print $2}' | while read ip; do
        if [[ "$ip" =~ ^10\.|^172\.1[6-9]|^192\.168 ]]; then
            echo "Private IP: $ip" | tee -a "$REPORT"
        else
            echo "Public IP: $ip" | tee -a "$REPORT"
        fi
    done
}

# 6. Security Updates and Patching
update_check() {
    log "----- SECURITY UPDATES -----"
    if command -v apt &> /dev/null; then
        apt update -y && apt list --upgradable | tee -a "$REPORT"
    elif command -v yum &> /dev/null; then
        yum check-update | tee -a "$REPORT"
    fi
}

# 7. Log Monitoring
log_monitor() {
    log "----- LOG MONITORING -----"
    grep "Failed password" /var/log/auth.log | tail -n 10 | tee -a "$REPORT"
}

# 8. Server Hardening
server_hardening() {
    log "----- SERVER HARDENING -----"

    # SSH Configuration
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl reload sshd

    # Disable IPv6
    echo "Disabling IPv6..." | tee -a "$REPORT"
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p

    # Secure GRUB Bootloader
    log "Bootloader hardening (manual check recommended)." | tee -a "$REPORT"
}

# 9. Custom Security Checks Placeholder
custom_checks() {
    log "----- CUSTOM CHECKS -----"
    echo "Add your custom checks here." | tee -a "$REPORT"
}

# 10. Reporting
report() {
    log "----- AUDIT COMPLETED -----"
    echo "Audit report saved to: $REPORT"
}

# Run All Checks
main() {
    user_audit
    file_permission_audit
    service_audit
    firewall_audit
    ip_check
    update_check
    log_monitor
    server_hardening
    custom_checks
    report
}

main
