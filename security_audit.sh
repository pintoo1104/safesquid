#!/bin/bash

# ==============================
# Linux Security Audit Dashboard
# ==============================

REPORT="security_audit_report.txt"
> "$REPORT"

print_title() {
    local title="$1"
    echo -e "\n\033[1;34m========== $title ==========\033[0m"
    echo -e "\n========== $title ==========" >> "$REPORT"
}

print_subtitle() {
    echo -e "\n\033[1;32m-- $1 --\033[0m"
    echo -e "\n-- $1 --" >> "$REPORT"
}

# 1. User and Group Audits
user_audit() {
    print_title "1. USER AND GROUP AUDIT"

    print_subtitle "Users with UID 0 (root access)"
    getent passwd | awk -F: '$3 == 0 {print "UID 0 user: "$1}' | tee -a "$REPORT"

    print_subtitle "Users with no password set (potential risk)"
    getent passwd | cut -d: -f1 | xargs -n1 -I{} sudo passwd -S {} | grep -E "NP|!!" | tee -a "$REPORT"

    print_subtitle "All Local Groups"
    cut -d: -f1 /etc/group | tee -a "$REPORT"
}

# 2. File and Directory Permissions
file_permission_audit() {
    print_title "2. FILE AND DIRECTORY PERMISSIONS"

    print_subtitle "World-writable directories"
    find / -type d -perm -0002 -exec ls -ld {} \; 2>/dev/null | tee -a "$REPORT"

    print_subtitle "SUID/SGID Files"
    find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -ld {} \; 2>/dev/null | tee -a "$REPORT"

    print_subtitle "SSH Directory Permissions"
    find /home -name ".ssh" -exec ls -ld {} \; 2>/dev/null | tee -a "$REPORT"
}

# 3. Service Audits
service_audit() {
    print_title "3. SERVICE AUDIT"

    print_subtitle "Running Services"
    systemctl list-units --type=service --state=running | tee -a "$REPORT"

    print_subtitle "Listening Network Ports (excluding localhost)"
    netstat -tulnp | grep -v "127.0.0.1" | tee -a "$REPORT"
}

# 4. Firewall and Network Security
firewall_audit() {
    print_title "4. FIREWALL & NETWORK SECURITY"

    print_subtitle "Firewall Rules"
    if command -v ufw &> /dev/null; then
        ufw status verbose | tee -a "$REPORT"
    elif command -v iptables &> /dev/null; then
        iptables -L -n -v | tee -a "$REPORT"
    else
        echo "No firewall tool (ufw/iptables) found." | tee -a "$REPORT"
    fi

    print_subtitle "Active Listening Ports"
    ss -tuln | tee -a "$REPORT"
}

# 5. IP and Network Configuration
ip_check() {
    print_title "5. IP CONFIGURATION CHECK"

    print_subtitle "Assigned IP Addresses"
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
    print_title "6. SECURITY UPDATES & PATCHING"

    print_subtitle "Available Updates"
    if command -v apt &> /dev/null; then
        apt update -y > /dev/null
        apt list --upgradable 2>/dev/null | tee -a "$REPORT"
    elif command -v yum &> /dev/null; then
        yum check-update | tee -a "$REPORT"
    fi
}

# 7. Log Monitoring
log_monitor() {
    print_title "7. LOGIN ATTEMPTS & AUTH LOGS"

    print_subtitle "Recent Failed Login Attempts"
    grep "Failed password" /var/log/auth.log | tail -n 10 | tee -a "$REPORT"
}

# 8. Server Hardening
server_hardening() {
    print_title "8. SERVER HARDENING"

    print_subtitle "SSH Configuration (Root login disabled)"
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl reload sshd
    echo "Updated /etc/ssh/sshd_config to disable root login and password auth" | tee -a "$REPORT"

    print_subtitle "Disabling IPv6"
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p | tee -a "$REPORT"

    print_subtitle "Bootloader Security Check"
    echo "Manual verification recommended for /boot/grub/grub.cfg permissions." | tee -a "$REPORT"
}

# 9. Custom Checks Placeholder
custom_checks() {
    print_title "9. CUSTOM CHECKS"
    echo "You can extend this section for application-specific security checks." | tee -a "$REPORT"
}

# 10. Summary
summary() {
    print_title "10. AUDIT COMPLETED"
    echo "Complete report saved to: $REPORT" | tee -a "$REPORT"
}

# Main
main() {
    clear
    echo -e "\n\033[1;35m=== Starting Linux Security Audit ===\033[0m"
    user_audit
    file_permission_audit
    service_audit
    firewall_audit
    ip_check
    update_check
    log_monitor
    server_hardening
    custom_checks
    summary
}

main
