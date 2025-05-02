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
    root_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)
    log_and_print "$root_users"
    log_and_print "\n→ Total users with UID 0: $(echo "$root_users" | wc -l)"

    section "Users with No or Locked Passwords"
    no_pass_users=$(awk -F: '($2 == "" || $2 ~ /^[*!]/) {print $1}' /etc/shadow)
    log_and_print "$no_pass_users"
    log_and_print "\n→ Users with no/locked passwords: $(echo "$no_pass_users" | wc -l)"

    section "System Groups (GID < 1000)"
    system_groups=$(getent group | awk -F: '$3 < 1000 {print $1}' | sort)
    log_and_print "$system_groups"
    log_and_print "\n→ Total system groups: $(echo "$system_groups" | wc -l)"

    section "User-Created Groups (GID >= 1000)"
    user_groups=$(getent group | awk -F: '$3 >= 1000 {print $1}' | sort)
    log_and_print "$user_groups"
    log_and_print "\n→ Total user-created groups: $(echo "$user_groups" | wc -l)"
}

# Main function to start the audit
main() {
    clear
    echo -e "\n\033[1;35m=== Starting Linux Security Audit ===\033[0m"
    
    user_audit
    
    echo -e "\n\033[1;32m=== Security Audit Completed ===\033[0m"
}

main
