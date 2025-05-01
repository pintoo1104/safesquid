#!/bin/bash

# ==============================
# Linux Security Audit Dashboard
# ==============================

REPORT="security_audit_report.txt"
> "$REPORT"

print_title() {
    local title="$1"
    echo -e "\n\033[1;44m========= $title =========\033[0m"
    echo -e "\n========= $title =========" >> "$REPORT"
}

print_subtitle() {
    local subtitle="$1"
    echo -e "\n\033[1;42m-- $subtitle --\033[0m"
    echo -e "\n-- $subtitle --" >> "$REPORT"
}

# 1. User and Group Audits
user_audit() {
    print_title "1. USER AND GROUP AUDIT"

    print_subtitle "Users with UID 0 (root access)"
    root_users=$(getent passwd | awk -F: '$3 == 0 {print $1}')
    echo "$root_users" | tee -a "$REPORT"
    echo -e "\033[1;33mTotal: $(echo "$root_users" | wc -l)\033[0m"

    print_subtitle "Users with no password set (potential risk)"
    no_pass_users=$(getent passwd | cut -d: -f1 | xargs -n1 -I{} sudo passwd -S {} 2>/dev/null | grep -E "NP|!!")
    echo "$no_pass_users" | tee -a "$REPORT"
    echo -e "\033[1;33mTotal: $(echo "$no_pass_users" | wc -l)\033[0m"

    print_subtitle "All Local Groups"
    groups=$(cut -d: -f1 /etc/group)
    echo "$groups" | tee -a "$REPORT"
    echo -e "\033[1;33mTotal Groups: $(echo "$groups" | wc -l)\033[0m"
}

# 2. File and Directory Permissions
file_permission_audit() {
    print_title "2. FILE AND DIRECTORY PERMISSIONS"

    print_subtitle "World-writable directories"
    dirs=$(find / -type d -perm -0002 -exec ls -ld {} \; 2>/dev/null)
    echo "$dirs" | tee -a "$REPORT"
    echo -e "\033[1;33mCount: $(echo "$dirs" | wc -l)\033[0m"

    print_subtitle "SUID/SGID Files"
    suid_sgid=$(find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -ld {} \; 2>/dev/null)
    echo "$suid_sgid" | tee -a "$REPORT"
    echo -e "\033[1;33mCount: $(echo "$suid_sgid" | wc -l)\033[0m"

    print_subtitle "SSH Directory Permissions"
    ssh_dirs=$(find /home -name ".ssh" -exec ls -ld {} \; 2>/dev/null)
    echo "$ssh_dirs" | tee -a "$REPORT"
    echo -e "\033[1;33mFound: $(echo "$ssh_dirs" | wc -l) .ssh directories\033[0m"
}

# 3. Service Audits
service_audit() {
    print_title "3. SERVICE AUDIT"

    print_subtitle "Running Services"
    services=$(systemctl list-units --type=service --state=running)
    echo "$services" | tee -a "$REPORT"
    echo -e "\033[1;33mTotal Running: $(echo "$services" | grep '.service' | wc -l)\033[0m"

    print_subtitle "Listening Network Ports (excluding localhost)"
    ports=$(netstat -tulnp | grep -v "127.0.0.1")
    echo "$ports" | tee -a "$REPORT"
    echo -e "\033[1;33mListening Ports: $(echo "$ports" | wc -l)\033[0m"
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
    ports=$(ss -tuln)
    echo "$ports" | tee -a "$REPORT"
    echo -e "\033[1;33mActive: $(echo "$ports" | grep -c LISTEN)\033[0m"
}

# 5. IP and Network Configuration
ip_check() {
    print_title "5. IP CONFIGURATION CHECK"

    print_subtitle "Assigned IP Addresses"
    count=0
    ip -4 addr show | grep inet | awk '{print $2}' | while read ip; do
        if [[ "$ip" =~ ^10\.|^172\.1[6-9]|^192\.168 ]]; then
            echo "Private IP: $ip" | tee -a "$REPORT"
        else
            echo "Public IP: $ip" | tee -a "$REPORT"
        fi
        ((count++))
    done
    echo -e "\033[1;33mTotal IPs Found: $count\033[0m"
}

# 6. Security Updates and Patching
update_check() {
    print_title "6. SECURITY UPDATES & PATCHING"

    print_subtitle "Available Updates"
    if command -v apt &> /dev/null; then
        apt update -y > /dev/null
        updates=$(apt list --upgradable 2>/dev/null)
    elif command -v yum &> /dev/null; then
        updates=$(yum check-update)
    fi
    echo "$updates" | tee -a "$REPORT"
    echo -e "\033[1;33mUpdate Count: $(echo "$updates" | grep -cE '^[a-zA-Z0-9]')\033[0m"
}

# 7. Log Monitoring
log_monitor() {
    print_title "7. LOGIN ATTEMPTS & AUTH LOGS"

    print_subtitle "Recent Failed Login Attempts"
    fails=$(grep "Failed password" /var/log/auth.log | tail -n 10)
    echo "$fails" | tee -a "$REPORT"
    echo -e "\033[1;33mEntries Shown: $(echo "$fails" | wc -l)\033[0m"
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
    echo "Manual check: run 'ls -l /boot/grub/grub.cfg'" | tee -a "$REPORT"
}

# 9. Custom Checks Placeholder
custom_checks() {
    print_title "9. CUSTOM CHECKS"
    echo "You can extend this section for application-specific security checks." | tee -a "$REPORT"
}

# 10. Summary
summary() {
    print_title "10. AUDIT COMPLETED"
    echo -e "\033[1;35mAudit report saved to: $REPORT\033[0m"
    echo "Complete report saved to: $REPORT" >> "$REPORT"
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
