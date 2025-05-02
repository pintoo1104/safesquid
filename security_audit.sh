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

log_and_print() {
    echo -e "$1"
    echo -e "$1" >> "$REPORT"
}

section() {
    echo -e "\n+------------------------------------------------------------+"
    echo -e "| $1"
    echo -e "+------------------------------------------------------------+"
    echo -e "\n+------------------------------------------------------------+" >> "$REPORT"
    echo -e "| $1" >> "$REPORT"
    echo -e "+------------------------------------------------------------+" >> "$REPORT"
}

# 1. User and Group Audits
user_audit() {
    print_title "1. USER AND GROUP AUDIT"

    section "Users with UID 0 (root access)"
    root_users=$(getent passwd | awk -F: '$3 == 0 {print $1}')
    log_and_print "$root_users"
    log_and_print "\n→ Total users with UID 0: $(echo "$root_users" | wc -l)"

    section "Users with no password set (potential risk)"
    no_pass=$(getent passwd | cut -d: -f1 | xargs -n1 -I{} sudo passwd -S {} 2>/dev/null | grep -E "NP|!!")
    log_and_print "$no_pass"
    log_and_print "\n→ Total users without password: $(echo "$no_pass" | wc -l)"

    section "All Local Groups"
    groups=$(cut -d: -f1 /etc/group)
    log_and_print "$groups"
    log_and_print "\n→ Total groups: $(echo "$groups" | wc -l)"
}

# 2. File and Directory Permissions
file_permissions_audit() {
    print_title "2. FILE AND DIRECTORY PERMISSIONS"

    section "World-writable files and directories"
    world_writable=$(find / -type f -perm -0002 2>/dev/null)
    log_and_print "$world_writable"
    log_and_print "\n→ Total world-writable files: $(echo "$world_writable" | wc -l)"

    section "Check for .ssh directories with secure permissions"
    ssh_dirs=$(find / -type d -name ".ssh" -exec ls -ld {} \; 2>/dev/null)
    log_and_print "$ssh_dirs"
    log_and_print "\n→ Total .ssh directories with secure permissions: $(echo "$ssh_dirs" | wc -l)"

    section "SUID and SGID Executables"
    suid_sgid=$(find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)
    log_and_print "$suid_sgid"
    log_and_print "\n→ Total SUID/SGID files: $(echo "$suid_sgid" | wc -l)"
}

# 3. Service Audits
service_audit() {
    print_title "3. SERVICE AUDIT"

    section "List of running services"
    running_services=$(ps aux --no-headers)
    log_and_print "$running_services"
    log_and_print "\n→ Total running services: $(echo "$running_services" | wc -l)"

    section "Critical Services Status (e.g., sshd, iptables)"
    critical_services=$(systemctl status sshd iptables 2>/dev/null)
    log_and_print "$critical_services"

    section "Check for unauthorized services"
    unauthorized_services=$(ps aux --no-headers | grep -v 'sshd' | grep -v 'iptables' | awk '{print $11}' | sort | uniq)
    log_and_print "$unauthorized_services"
    log_and_print "\n→ Unauthorized services: $(echo "$unauthorized_services" | wc -l)"
}

# 4. Firewall and Network Security
firewall_network_audit() {
    print_title "4. FIREWALL AND NETWORK SECURITY"

    section "Firewall Status"
    firewall_status=$(ufw status verbose 2>/dev/null)
    log_and_print "$firewall_status"

    section "Open Ports"
    open_ports=$(netstat -tuln 2>/dev/null)
    log_and_print "$open_ports"

    section "IP Forwarding and Network Configurations"
    ip_forwarding=$(sysctl net.ipv4.ip_forward)
    log_and_print "$ip_forwarding"
}

# 5. IP and Network Configuration Checks
network_config_audit() {
    print_title "5. IP AND NETWORK CONFIGURATION CHECKS"

    section "Public vs. Private IP Addresses"
    ip_addresses=$(hostname -I)
    public_ips=$(echo "$ip_addresses" | grep -E '^(?:8[0-9]|10|172|192)\.')
    private_ips=$(echo "$ip_addresses" | grep -E '^10\.')

    log_and_print "Public IPs: $public_ips"
    log_and_print "Private IPs: $private_ips"
    log_and_print "\n→ Total IP addresses: $(echo "$ip_addresses" | wc -w)"
}

# 6. Security Updates and Patching
security_updates_audit() {
    print_title "6. SECURITY UPDATES AND PATCHING"

    section "Checking for available updates"
    available_updates=$(sudo apt list --upgradable 2>/dev/null | grep -i security)
    log_and_print "$available_updates"
    log_and_print "\n→ Total security updates available: $(echo "$available_updates" | wc -l)"

    section "Ensure automatic updates are enabled"
    auto_updates_status=$(systemctl is-active unattended-upgrades)
    log_and_print "Automatic updates status: $auto_updates_status"

    if [[ "$auto_updates_status" == "active" ]]; then
        log_and_print "\n→ Automatic updates are active."
    else
        log_and_print "\n→ Automatic updates are NOT active. Enabling automatic updates..."
        sudo systemctl start unattended-upgrades
        sudo systemctl enable unattended-upgrades
    fi
}

# 7. Log Monitoring
log_monitoring() {
    print_title "7. LOG MONITORING"

    section "Checking for failed SSH login attempts"
    failed_logins=$(grep "Failed password" /var/log/auth.log 2>/dev/null)
    log_and_print "$failed_logins"
    log_and_print "\n→ Total failed SSH login attempts: $(echo "$failed_logins" | wc -l)"

    section "Checking for suspicious login attempts (multiple attempts from the same IP)"
    suspicious_logins=$(grep "Failed password" /var/log/auth.log | awk '{print $0}' | sort | uniq -c | sort -n)
    log_and_print "$suspicious_logins"
    log_and_print "\n→ Total suspicious login attempts: $(echo "$suspicious_logins" | wc -l)"
}

# Main function to start the audit
main() {
    clear
    echo -e "\n\033[1;35m=== Starting Linux Security Audit ===\033[0m"
    
    # Run all sections
    user_audit
    file_permissions_audit
    service_audit
    firewall_network_audit
    network_config_audit
    security_updates_audit
    log_monitoring
    
    echo -e "\n\033[1;32m=== Security Audit Completed ===\033[0m"
}

main
