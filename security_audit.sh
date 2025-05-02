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
file_permissions_check() {
    print_title "2. FILE AND DIRECTORY PERMISSIONS"

    section "World-Writable Files and Directories"
    world_writable_files=$(find / -type f -perm -0002 2>/dev/null)
    log_and_print "$world_writable_files"
    log_and_print "\n→ Total world-writable files: $(echo "$world_writable_files" | wc -l)"

    section "Checking .ssh Directories"
    ssh_dirs=$(find /home -type d -name ".ssh" 2>/dev/null)
    log_and_print "$ssh_dirs"
    log_and_print "\n→ Total .ssh directories: $(echo "$ssh_dirs" | wc -l)"

    section "Files with SUID or SGID Bits Set"
    suid_sgid_files=$(find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)
    log_and_print "$suid_sgid_files"
    log_and_print "\n→ Total files with SUID/SGID: $(echo "$suid_sgid_files" | wc -l)"
}

# 3. Security Updates Check and Automatic Update
security_updates_check() {
    print_title "3. SECURITY UPDATES AND PATCHING"

    section "Checking for Available Security Updates"
    available_updates=$(apt list --upgradable 2>/dev/null | grep -i security)
    
    if [ -n "$available_updates" ]; then
        log_and_print "Security updates available:\n$available_updates"
        
        # Apply security updates automatically using unattended-upgrades
        log_and_print "\n→ Attempting to apply security updates using unattended-upgrades..."
        sudo unattended-upgrade -d
        
    else
        log_and_print "No security updates available."
    fi

    section "Checking Automatic Updates Configuration"
    log_and_print "Checking if unattended-upgrades is active..."
    auto_update_status=$(systemctl is-active unattended-upgrades)
    
    if [ "$auto_update_status" == "active" ]; then
        log_and_print "Unattended-upgrades service is active."
    else
        log_and_print "Unattended-upgrades service is NOT active."
        log_and_print "Attempting to start unattended-upgrades..."
        sudo systemctl start unattended-upgrades
    fi
    
    log_and_print "Checking for automatic updates status..."
    sudo unattended-upgrades --dry-run
}

# Main function to start the audit
main() {
    clear
    echo -e "\n\033[1;35m=== Starting Linux Security Audit ===\033[0m"
    
    # Run the User and Group Audits
    user_audit
    
    # Run the File and Directory Permissions Check
    file_permissions_check
    
    # Run the Security Updates Check and Automatic Update
    security_updates_check
    
    echo -e "\n\033[1;32m=== Security Audit Completed ===\033[0m"
}

main
