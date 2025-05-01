#!/bin/bash

# ===========================
# Linux Security Audit & Hardening Script
# Compatible with VirtualBox and Ubuntu 20.04+
# ===========================

REPORT_FILE="/var/log/security_hardening_report_$(date +%F_%T).log"
mkdir -p /var/log

echo "===== Security Audit and Hardening Report =====" | tee -a "$REPORT_FILE"

log() {
    echo "[$(date)] [INFO] $1" | tee -a "$REPORT_FILE"
}

error() {
    echo "[$(date)] [ERROR] $1" | tee -a "$REPORT_FILE"
}

# ========== User and Group Audits ==========
user_group_audit() {
    log "User and Group Audit"
    getent passwd | tee -a "$REPORT_FILE"
    getent group | tee -a "$REPORT_FILE"
    awk -F: '($3 == 0) {print $1}' /etc/passwd | grep -v '^root$' | while read -r user; do
        error "Non-root user with UID 0: $user"
    done
    log "Users without passwords:"
    awk -F: '($2 == "" || $2 == "*" || $2 == "!" ) {print $1}' /etc/shadow | tee -a "$REPORT_FILE"
}

# ========== File Permissions Audit ==========
permissions_audit() {
    log "File and Directory Permissions Audit"
    find / -xdev -type f -perm -0002 -print | tee -a "$REPORT_FILE"
    find / -xdev -type d -perm -0002 -print | tee -a "$REPORT_FILE"
    find /home -name ".ssh" -exec ls -ld {} + | tee -a "$REPORT_FILE"
    find / -xdev \( -perm -4000 -o -perm -2000 \) -exec ls -ld {} + | tee -a "$REPORT_FILE"
}

# ========== Service Audit ==========
service_audit() {
    log "Service Audit"
    systemctl list-units --type=service --state=running | tee -a "$REPORT_FILE"
    log "Checking for critical services..."
    for svc in ssh ufw iptables; do
        systemctl is-enabled "$svc" >/dev/null 2>&1 && log "$svc is enabled" || error "$svc not enabled"
    done
    netstat -tulnp | tee -a "$REPORT_FILE"
}

# ========== Firewall and Network Security ==========
firewall_network_audit() {
    log "Firewall and Network Configuration"
    ufw status | tee -a "$REPORT_FILE"
    netstat -tuln | tee -a "$REPORT_FILE"
    sysctl net.ipv4.ip_forward | tee -a "$REPORT_FILE"
    sysctl net.ipv6.conf.all.disable_ipv6 | tee -a "$REPORT_FILE"
}

# ========== IP Configuration Checks ==========
ip_check() {
    log "IP Address and Exposure Check"
    ip -br a | tee -a "$REPORT_FILE"
    ip a | grep inet | while read -r line; do
        ip=$(echo $line | awk '{print $2}' | cut -d/ -f1)
        if [[ $ip == 10.* || $ip == 172.* || $ip == 192.168.* ]]; then
            log "Private IP: $ip"
        else
            error "Public IP detected: $ip"
        fi
    done
}

# ========== Security Updates ==========
check_updates() {
    log "Checking for Security Updates"
    apt update -y && apt list --upgradable 2>/dev/null | tee -a "$REPORT_FILE"
    apt install -y unattended-upgrades
    dpkg-reconfigure -f noninteractive unattended-upgrades
}

# ========== Log Monitoring ==========
monitor_logs() {
    log "Log Monitoring"
    grep -i "failed\|invalid" /var/log/auth.log | tail -n 10 | tee -a "$REPORT_FILE"
}

# ========== SSH Hardening ==========
secure_ssh() {
    log "Securing SSH"
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
}

# ========== Disable IPv6 ==========
disable_ipv6() {
    log "Disabling IPv6"
    echo -e "\n# Disable IPv6" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p
}

# ========== Bootloader Hardening ==========
secure_bootloader() {
    log "Securing Bootloader"
    GRUB_PASSWORD=${GRUB_PASSWORD:-'SecurePass123'}
    HASHED_PASSWORD=$(echo -e "$GRUB_PASSWORD\n$GRUB_PASSWORD" | grub-mkpasswd-pbkdf2 | grep grub.pbkdf2 | awk '{print $NF}')
    {
        echo "set superusers=\"admin\""
        echo "password_pbkdf2 admin $HASHED_PASSWORD"
    } > /etc/grub.d/40_custom
    update-grub
    log "GRUB password set and bootloader secured"
}

# ========== Configure Firewall ==========
configure_firewall() {
    log "Configuring Firewall"
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw enable
}

# ========== Run All ==========
main() {
    user_group_audit
    permissions_audit
    service_audit
    firewall_network_audit
    ip_check
    check_updates
    monitor_logs
    secure_ssh
    disable_ipv6
    secure_bootloader
    configure_firewall
    log "Security audit and hardening complete. Report saved to $REPORT_FILE"
}

main
