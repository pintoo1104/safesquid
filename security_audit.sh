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
    no_pass=$(getent shadow | awk -F: '($2 == "" || $2 ~ /^[*!]$/) {print $1}')
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

    section "World-Writable Files and Directories"
    world_writable=$(find / -xdev \( -type f -o -type d \) -perm -0002 2>/dev/null)
    if [[ -z "$world_writable" ]]; then
        log_and_print "✔ No world-writable files or directories found."
    else
        log_and_print "$world_writable"
        log_and_print "\n→ Total world-writable entries: $(echo "$world_writable" | wc -l)"
    fi

    section ".ssh Directory Permission Checks"
    ssh_dirs=$(find /home /root -type d -name ".ssh" 2>/dev/null)
    for dir in $ssh_dirs; do
        perms=$(stat -c "%a" "$dir")
        owner=$(stat -c "%U:%G" "$dir")
        log_and_print "Directory: $dir | Permissions: $perms | Owner: $owner"
        if [[ "$perms" -gt 700 ]]; then
            log_and_print "⚠ Warning: Permissions too open for $dir"
        fi
    done
    [[ -z "$ssh_dirs" ]] && log_and_print "✔ No .ssh directories found."

    section "SUID and SGID Files (Executables)"
    suid_sgid_files=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null)
    if [[ -z "$suid_sgid_files" ]]; then
        log_and_print "✔ No SUID or SGID files found."
    else
        log_and_print "$suid_sgid_files"
        log_and_print "\n→ Total SUID/SGID files: $(echo "$suid_sgid_files" | wc -l)"
    fi
}

# Main function
main() {
    clear
    echo -e "\n\033[1;35m=== Starting Linux Security Audit ===\033[0m"

    user_audit
    file_permission_audit

    echo -e "\n\033[1;32m=== Security Audit Completed ===\033[0m"
    echo -e "\nReport saved to: $REPORT"
}

main
