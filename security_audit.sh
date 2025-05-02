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

    section "World-writable files and directories"
    world_writable_files=$(find / -xdev -type f -perm -0002 2>/dev/null)
    log_and_print "$world_writable_files"
    log_and_print "\n→ Total world-writable files: $(echo "$world_writable_files" | wc -l)"

    section "Files with SUID or SGID bits set"
    suid_sgid_files=$(find / -xdev \( -type f -perm -4000 -o -type f -perm -2000 \) 2>/dev/null)
    log_and_print "$suid_sgid_files"
    log_and_print "\n→ Total files with SUID/SGID bits set: $(echo "$suid_sgid_files" | wc -l)"

    section ".ssh directory permissions"
    ssh_dirs=$(find / -type d -name ".ssh" 2>/dev/null)
    log_and_print "$ssh_dirs"
    log_and_print "\n→ Total .ssh directories: $(echo "$ssh_dirs" | wc -l)"
}

# 3. Service Audits
service_audit() {
    print_title "3. SERVICE AUDITS"

    section "List of running services"
    running_services=$(systemctl list-units --type=service --state=running)
    log_and_print "$running_services"

    section "Critical services status"
    critical_services=$(systemctl status sshd iptables)
    log_and_print "$critical_services"
}

# 4. Firewall and Network Security
firewall_network_security() {
    print_title "4. FIREWALL AND NETWORK SECURITY"

    section "Firewall status"
    firewall_status=$(sudo ufw status)
    log_and_print "$firewall_status"

    section "Open ports and associated services"
    open_ports=$(ss -tuln)
    log_and_print "$open_ports"

    section "IP forwarding status"
    ip_forwarding=$(sysctl net.ipv4.ip_forward)
    log_and_print "$ip_forwarding"
}

# 5. IP and Network Configuration Checks
ip_network_config() {
    print_title "5. IP AND NETWORK CONFIGURATION CHECKS"

    section "Public vs Private IPs"
    ips=$(ip addr show | grep inet)
    log_and_print "$ips"

    section "Sensitive services exposed on public IPs"
    exposed_services=$(ss -tuln | grep -E '0.0.0.0|::')
    log_and_print "$exposed_services"
}

# 6. Security Updates and Patching
security_updates() {
    print_title "6. SECURITY UPDATES AND PATCHING"

    section "Check for available security updates"
    updates=$(apt list --upgradable 2>/dev/null | grep security)
    log_and_print "$updates"

    section "Automatic Updates Status"
    automatic_updates=$(systemctl is-enabled unattended-upgrades)
    log_and_print "$automatic_updates"

    section "Applying security updates (if available)"
    if [ -n "$updates" ]; then
        log_and_print "Applying security updates..."
        sudo apt update && sudo apt upgrade -y
    else
        log_and_print "No security updates available."
    fi
}

# 7. Log Monitoring
log_monitoring() {
    print_title "7. LOG MONITORING"

    section "Checking for Suspicious Login Attempts"

    # Using 'auth.log' to get login attempts (can be other logs depending on system setup)
    suspicious_logins=$(grep -E "Failed password|authentication failure|sshd.*Failed" /var/log/auth.log)
    log_and_print "$suspicious_logins"
    log_and_print "\n→ Total failed login attempts: $(echo "$suspicious_logins" | wc -l)"

    section "Recent Successful Logins"
    successful_logins=$(grep "Accepted password" /var/log/auth.log)
    log_and_print "$successful_logins"
    log_and_print "\n→ Total successful logins: $(echo "$successful_logins" | wc -l)"
    
    section "Login Attempt Details"
    log_and_print "Last 10 login attempts (successful and failed):"
    last_10_logins=$(tail -n 10 /var/log/auth.log | grep -E "sshd|Accepted|Failed")
    log_and_print "$last_10_logins"

    log_and_print "\nDetails of the last 10 login attempts (timestamp, user, IP address, outcome):"
    last_10_logins_details=$(tail -n 10 /var/log/auth.log | grep -E "sshd|Accepted|Failed" | awk '{print $1, $2, $3, $9, $11}')
    log_and_print "$last_10_logins_details"
}

# Main function to start the audit
main() {
    clear
    echo -e "\n\033[1;35m=== Starting Linux Security Audit ===\033[0m"
    
    # Run all audit sections
    user_audit
    file_permissions
    service_audit
    firewall_network_security
    ip_network_config
    security_updates
    log_monitoring
    
    echo -e "\n\033[1;32m=== Security Audit Completed ===\033[0m"
}

main
