#!/bin/bash

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT="security_audit_report_$TIMESTAMP.txt"

# Create empty report in current directory
touch "$REPORT"

log() {
    echo "[+] $1" | tee -a "$REPORT"
}

warn() {
    echo "[!] $1" | tee -a "$REPORT"
}

error() {
    echo "[X] $1" | tee -a "$REPORT"
}

section() {
    echo -e "\n==================== $1 ====================\n" | tee -a "$REPORT"
}

# 1. User & Group Audits
user_group_audit() {
    section "User & Group Audit"
    log "All system users:"
    getent passwd | tee -a "$REPORT"

    log "All system groups:"
    getent group | tee -a "$REPORT"

    log "Users with UID 0 (expect only root):"
    awk -F: '($3 == 0) {print $1}' /etc/passwd | grep -v '^root$' | while read -r user; do
        warn "Non-root user with UID 0: $user"
    done

    log "Users without passwords or locked accounts:"
    awk -F: '($2 == "" || $2 ~ /^[*!]$/) {print $1}' /etc/shadow | tee -a "$REPORT"
}

# 2. File & Directory Permissions
permissions_audit() {
    section "File and Directory Permissions"
    log "World-writable files:"
    find / -xdev -type f -perm -0002 -print 2>/dev/null | tee -a "$REPORT"

    log "World-writable directories:"
    find / -xdev -type d -perm -0002 -print 2>/dev/null | tee -a "$REPORT"

    log ".ssh directory permissions:"
    find /home -name ".ssh" -exec ls -ld {} + 2>/dev/null | tee -a "$REPORT"

    log "Files with SUID/SGID bits:"
    find / -xdev \( -perm -4000 -o -perm -2000 \) -exec ls -ld {} + 2>/dev/null | tee -a "$REPORT"
}

# 3. Services Audit
service_audit() {
    section "Service Audit"
    log "Running services:"
    systemctl list-units --type=service --state=running | tee -a "$REPORT"

    for svc in ssh ufw iptables; do
        if systemctl is-enabled "$svc" >/dev/null 2>&1; then
            log "$svc is enabled"
        else
            warn "$svc is NOT enabled"
        fi
    done

    log "Listening ports:"
    ss -tuln | tee -a "$REPORT"
}

# 4. Firewall & Network Security
firewall_check() {
    section "Firewall and Network Security"
    if ufw status | grep -q "Status: active"; then
        log "UFW is active"
    else
        warn "UFW is not active"
    fi

    log "Open ports:"
    ss -tuln | tee -a "$REPORT"

    log "IP forwarding:"
    sysctl net.ipv4.ip_forward | tee -a "$REPORT"
    sysctl net.ipv6.conf.all.disable_ipv6 | tee -a "$REPORT"
}

# 5. IP Check
ip_check() {
    section "IP Configuration and Public/Private IP Check"
    ip -br a | tee -a "$REPORT"
    ip a | grep inet | while read -r line; do
        ip=$(echo $line | awk '{print $2}' | cut -d/ -f1)
        if [[ $ip == 10.* || $ip == 172.* || $ip == 192.168.* ]]; then
            log "Private IP: $ip"
        else
            warn "Public IP: $ip"
        fi
    done
}

# 6. Security Updates
check_updates() {
    section "Security Updates"
    apt update -y >/dev/null 2>&1
    apt list --upgradable 2>/dev/null | tee -a "$REPORT"

    log "Installing unattended-upgrades..."
    apt install -y unattended-upgrades >/dev/null 2>&1
    dpkg-reconfigure -f noninteractive unattended-upgrades
    log "Unattended-upgrades configured"
}

# 7. Log Monitoring
monitor_logs() {
    section "Log Monitoring (SSH login attempts)"
    grep -i "failed\|invalid" /var/log/auth.log | tail -n 10 | tee -a "$REPORT"
}

# 8. SSH Hardening
secure_ssh() {
    section "SSH Hardening"
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
    log "SSH configuration updated: root login and password auth disabled"
}

# 9. Disable IPv6
disable_ipv6() {
    section "Disabling IPv6"
    echo -e "\n# Disable IPv6" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p
    log "IPv6 disabled"
}

# 10. Secure GRUB
secure_bootloader() {
    section "GRUB Bootloader Hardening"
    GRUB_PASSWORD='SafeSquidSecure#123'
    HASHED=$(echo -e "$GRUB_PASSWORD\n$GRUB_PASSWORD" | grub-mkpasswd-pbkdf2 | grep grub.pbkdf2 | awk '{print $NF}')
    echo "set superusers=\"admin\"" > /etc/grub.d/40_custom
    echo "password_pbkdf2 admin $HASHED" >> /etc/grub.d/40_custom
    update-grub
    log "Bootloader password set"
}

# 11. Configure Firewall
configure_firewall() {
    section "Firewall Rules (UFW)"
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw enable
    log "UFW firewall configured and enabled"
}

# 12. Custom Security Checks (placeholder)
custom_checks() {
    section "Custom Security Checks"
    log "No custom checks defined yet. You can add checks here."
}

# 13. Optional: Email Alerts (disabled)
send_alerts() {
    # Placeholder function
    log "Email alerting not configured. You may integrate sendmail/mailx here."
}

# Main Function
main() {
    section "Linux Security Audit and Hardening Report"
    user_group_audit
    permissions_audit
    service_audit
    firewall_check
    ip_check
    check_updates
    monitor_logs
    secure_ssh
    disable_ipv6
    secure_bootloader
    configure_firewall
    custom_checks
    log "Audit complete. Report saved to: $REPORT"
}

main
