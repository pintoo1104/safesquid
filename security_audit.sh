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
file_permissions() {
    print_title "2. FILE AND DIRECTORY PERMISSIONS"

    section "Files and Directories with World Writable Permissions"
    world_writable=$(find / -type f -perm -0002 2>/dev/null)
    log_and_print "$world_writable"
    log_and_print "\n→ Total files with world writable permissions: $(echo "$world_writable" | wc -l)"

    section "Presence and Permissions of .ssh Directories"
    ssh_dirs=$(find / -type d -name ".ssh" -exec ls -ld {} \; 2>/dev/null)
    log_and_print "$ssh_dirs"

    section "Files with SUID or SGID Bits Set"
    suid_sgid=$(find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)
    log_and_print "$suid_sgid"
    log_and_print "\n→ Total files with SUID/SGID bits set: $(echo "$suid_sgid" | wc -l)"
}

# 3. Service Audits
service_audit() {
    print_title "3. SERVICE AUDITS"

    section "Running Services"
    services=$(ps -e)
    log_and_print "$services"

    section "Checking for Critical Services"
    critical_services=("sshd" "iptables")
    for service in "${critical_services[@]}"; do
        status=$(systemctl is-active "$service")
        log_and_print "$service: $status"
    done

    section "Services Listening on Non-Standard Ports"
    non_standard_ports=$(netstat -tuln | grep -Ev '127.0.0.1|::1')
    log_and_print "$non_standard_ports"
}

# 4. Firewall and Network Security
firewall_and_network_security() {
    print_title "4. FIREWALL AND NETWORK SECURITY"

    section "Firewall Status"
    firewall_status=$(ufw status verbose 2>/dev/null)
    log_and_print "$firewall_status"

    section "Open Ports and Associated Services"
    open_ports=$(netstat -tuln)
    log_and_print "$open_ports"

    section "IP Forwarding and Network Configurations"
    ip_forwarding=$(sysctl net.ipv4.ip_forward)
    log_and_print "$ip_forwarding"
}

# 5. IP and Network Configuration Checks
ip_network_checks() {
    print_title "5. IP AND NETWORK CONFIGURATION CHECKS"

    section "Public vs Private IPs"
    ips=$(hostname -I)
    for ip in $ips; do
        if [[ "$ip" =~ ^10\. || "$ip" =~ ^172\.16\. || "$ip" =~ ^192\.168\. ]]; then
            echo "$ip is a private IP"
        else
            echo "$ip is a public IP"
        fi
    done
}

# 6. Security Updates and Patching
security_updates() {
    print_title "6. SECURITY UPDATES AND PATCHING"

    section "Checking for Available Security Updates"
    available_updates=$(apt list --upgradable 2>/dev/null)
    log_and_print "$available_updates"
    log_and_print "\n→ Total available updates: $(echo "$available_updates" | wc -l)"

    section "Applying Security Updates"
    sudo unattended-upgrade -d
    log_and_print "\n→ Security updates applied successfully."

    section "Automatic Updates"
    automatic_updates_status=$(systemctl is-enabled apt-daily.timer)
    log_and_print "$automatic_updates_status"
}

# 7. Log Monitoring
log_monitoring() {
    print_title "7. LOG MONITORING"

    section "Checking for failed SSH login attempts"
    failed_logins=$(grep "Failed password" /var/log/auth.log 2>/dev/null)
    log_and_print "$failed_logins"
    log_and_print "\n→ Total failed SSH login attempts: $(echo "$failed_logins" | wc -l)"

    section "Detailed Failed SSH login attempts"
    detailed_failed_logins=$(grep "Failed password" /var/log/auth.log | awk '{print $1, $2, $3, $9, $11}' | sort | uniq)
    log_and_print "$detailed_failed_logins"
    log_and_print "\n→ Total unique failed login attempts: $(echo "$detailed_failed_logins" | wc -l)"

    section "Checking for suspicious login attempts (multiple attempts from the same IP)"
    suspicious_logins=$(grep "Failed password" /var/log/auth.log | awk '{print $0}' | sort | uniq -c | sort -n)
    log_and_print "$suspicious_logins"
    log_and_print "\n→ Total suspicious login attempts: $(echo "$suspicious_logins" | wc -l)"
}

# Main function to start the audit
main() {
    clear
    echo -e "\n\033[1;35m=== Starting Linux Security Audit ===\033[0m"
    
    # Run the User and Group Audits
    user_audit
    
    # Run the File and Directory Permissions
    file_permissions

    # Run the Service Audits
    service_audit
    
    # Run the Firewall and Network Security
    firewall_and_network_security
    
    # Run the IP and Network Configuration Checks
    ip_network_checks
    
    # Run the Security Updates and Patching
    security_updates
    
    # Run the Log Monitoring
    log_monitoring
    
    echo -e "\n\033[1;32m=== Security Audit Completed ===\033[0m"
}

main
