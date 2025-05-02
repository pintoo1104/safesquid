#!/bin/bash

# ==============================
# Linux Security Audit Dashboard
# ==============================

REPORT="security_audit_report.txt"
> "$REPORT"

print_title() {
    echo -e "\n========== $1 ==========" | tee -a "$REPORT"
}

section() {
    echo -e "\n+------------------------------------------------------------+" | tee -a "$REPORT"
    echo -e "| $1" | tee -a "$REPORT"
    echo -e "+------------------------------------------------------------+" | tee -a "$REPORT"
}

log_and_print() {
    echo -e "$1" | tee -a "$REPORT"
}

# 1. User and Group Audit
user_audit() {
    print_title "1. USER AND GROUP AUDIT"

    section "Users with UID 0 (root access)"
    root_users=$(getent passwd | awk -F: '$3 == 0 {print $1}')
    log_and_print "$root_users"

    section "Users without passwords"
    no_pass=$(getent shadow | awk -F: '($2=="*" || $2=="!" || $2=="") {print $1}')
    log_and_print "$no_pass"

    section "All Groups"
    groups=$(cut -d: -f1 /etc/group)
    log_and_print "$groups"
}

# 2. File and Directory Permissions
permission_audit() {
    print_title "2. FILE & DIRECTORY PERMISSIONS"

    section "World-writable files"
    find / -type f -perm -0002 -exec ls -l {} \; 2>/dev/null | tee -a "$REPORT"

    section ".ssh Directories"
    find /home -type d -name ".ssh" -exec ls -ld {} \; 2>/dev/null | tee -a "$REPORT"

    section "Files with SUID/SGID"
    find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null | tee -a "$REPORT"
}

# 3. Service Audits
service_audit() {
    print_title "3. SERVICE AUDITS"

    section "Running Services"
    systemctl list-units --type=service --state=running | tee -a "$REPORT"

    section "Critical Services (ssh, iptables)"
    systemctl is-active ssh && echo "SSH is active" || echo "SSH is inactive"
    systemctl is-active netfilter-persistent && echo "iptables is active" || echo "iptables is inactive"
}

# 4. Firewall & Network Security
network_security() {
    print_title "4. FIREWALL & NETWORK SECURITY"

    section "Firewall Status"
    ufw status verbose 2>/dev/null | tee -a "$REPORT"

    section "Open Ports"
    ss -tuln | tee -a "$REPORT"

    section "IP Forwarding Check"
    grep -E 'net.ipv4.ip_forward|net.ipv6.conf.all.forwarding' /etc/sysctl.conf | tee -a "$REPORT"
}

# 5. IP Configuration Check
ip_config_audit() {
    print_title "5. IP CONFIGURATION AUDIT"

    section "IP Addresses and Type"
    ip -o -f inet addr show | awk '{print $2, $4}' | while read line; do
        ip_addr=$(echo $line | awk '{print $2}' | cut -d/ -f1)
        if [[ $ip_addr =~ ^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
            type="Private"
        else
            type="Public"
        fi
        echo "$line - $type" | tee -a "$REPORT"
    done
}

# 6. Security Updates
security_updates() {
    print_title "6. SECURITY UPDATES AND PATCHING"

    section "Checking for updates (non-interactive)"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    updates=$(apt-get -s upgrade | grep -P '^\d+ upgraded' | cut -d' ' -f1)
    echo "Pending Updates: $updates" | tee -a "$REPORT"

    if [ "$updates" -gt 0 ]; then
        section "Applying updates automatically..."
        apt-get upgrade -y >> "$REPORT"
        apt-get autoremove -y >> "$REPORT"
    fi

    section "Unattended Upgrades Status"
    systemctl is-enabled unattended-upgrades && echo "Unattended-upgrades is enabled" || echo "Disabled"
}

# 7. Log Monitoring
log_monitoring() {
    print_title "7. LOG MONITORING"

    section "Failed SSH Logins (Last 7 Days)"
    journalctl -u ssh --since "7 days ago" | grep "Failed password" | tee -a "$REPORT"

    section "Suspicious Auth Logs (Too many login attempts)"
    grep "Failed password" /var/log/auth.log | awk '{print $1,$2,$3,$11}' | sort | uniq -c | sort -nr | head -10 | tee -a "$REPORT"
}

# 8. Server Hardening Steps (SSH + GRUB + Auto-updates)
server_hardening() {
    print_title "8. SERVER HARDENING STEPS"

    section "SSH Hardening Check"
    grep -E "PermitRootLogin|PasswordAuthentication" /etc/ssh/sshd_config | tee -a "$REPORT"

    section "GRUB Bootloader Security (Manual Password Required)"
    echo "NOTE: GRUB password is not set automatically for security. Run the following to configure:" | tee -a "$REPORT"
    echo "grub-mkpasswd-pbkdf2  # Generate encrypted password" | tee -a "$REPORT"
    echo "Then edit /etc/grub.d/40_custom and update /boot/grub/grub.cfg" | tee -a "$REPORT"

    section "Auto Security Updates Config"
    if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
        cat /etc/apt/apt.conf.d/20auto-upgrades | tee -a "$REPORT"
    fi
}

main() {
    clear
    echo -e "\n=== Starting Linux Security Audit ==="
    user_audit
    permission_audit
    service_audit
    network_security
    ip_config_audit
    security_updates
    log_monitoring
    server_hardening
    echo -e "\n=== Security Audit Completed ==="
}

main
