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
file_permission_audit() {
    print_title "2. FILE AND DIRECTORY PERMISSIONS"

    section "Files and Directories with World-Writable Permissions"
    world_writable_files=$(find / -xdev -type f -perm -0002 2>/dev/null)
    log_and_print "$world_writable_files"
    log_and_print "\n→ Total world-writable files: $(echo "$world_writable_files" | wc -l)"

    section "Checking for .ssh Directories with Secure Permissions"
    ssh_dirs=$(find / -type d -name ".ssh" -exec ls -ld {} \; 2>/dev/null)
    log_and_print "$ssh_dirs"
    log_and_print "\n→ Total .ssh directories: $(echo "$ssh_dirs" | wc -l)"

    section "Files with SUID or SGID Bits Set"
    suid_sgid_files=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null)
    log_and_print "$suid_sgid_files"
    log_and_print "\n→ Total SUID/SGID files: $(echo "$suid_sgid_files" | wc -l)"
}

# 3. Service Audits
service_audit() {
    print_title "3. SERVICE AUDITS"

    section "Running Services"
    running_services=$(systemctl list-units --type=service --state=running)
    log_and_print "$running_services"

    section "Critical Services"
    critical_services=$(systemctl list-units --type=service --state=running | grep -E 'sshd|iptables')
    log_and_print "$critical_services"

    section "Checking for Services Listening on Non-Standard Ports"
    non_standard_ports=$(ss -tuln | grep -vE '22|80|443')
    log_and_print "$non_standard_ports"
    log_and_print "\n→ Total services on non-standard ports: $(echo "$non_standard_ports" | wc -l)"
}

# 6. Security Updates and Patching
security_updates() {
    print_title "6. SECURITY UPDATES AND PATCHING"

    section "Available Security Updates"
    available_updates=$(apt-get --just-print upgrade | grep -i "security")
    log_and_print "$available_updates"
    log_and_print "\n→ Total security updates available: $(echo "$available_updates" | wc -l)"

    section "Ensure Automatic Updates are Enabled"
    auto_update_status=$(systemctl is-active unattended-upgrades)
    log_and_print "Automatic updates status: $auto_update_status"
    if [[ "$auto_update_status" != "active" ]]; then
        log_and_print "→ Warning: Automatic updates are not enabled."
    else
        log_and_print "→ Automatic updates are enabled."
    fi

    # Check if automatic updates are working by examining logs
    section "Unattended-upgrades Logs"
    update_logs=$(cat /var/log/unattended-upgrades/unattended-upgrades.log 2>/dev/null)
    log_and_print "$update_logs"
}

# Main function to start the audit
main() {
    clear
    echo -e "\n\033[1;35m=== Starting Linux Security Audit ===\033[0m"
    
    # Run the User and Group Audits
    user_audit

    # Run the File and Directory Permissions Audit
    file_permission_audit

    # Run the Service Audits
    service_audit

    # Run the Security Updates Check
    security_updates
    
    echo -e "\n\033[1;32m=== Security Audit Completed ===\033[0m"
}

main
