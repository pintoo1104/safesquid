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

    section "Files with world-writable permissions"
    world_writable_files=$(find / -type f -perm -002 2>/dev/null)
    log_and_print "$world_writable_files"
    log_and_print "\n→ Total world-writable files: $(echo "$world_writable_files" | wc -l)"

    section "Directories with world-writable permissions"
    world_writable_dirs=$(find / -type d -perm -002 2>/dev/null)
    log_and_print "$world_writable_dirs"
    log_and_print "\n→ Total world-writable directories: $(echo "$world_writable_dirs" | wc -l)"

    section "Presence of .ssh directories with secure permissions"
    ssh_dirs=$(find / -type d -name ".ssh" -exec ls -ld {} \; 2>/dev/null)
    log_and_print "$ssh_dirs"

    section "Files with SUID or SGID bits set"
    suid_sgid_files=$(find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)
    log_and_print "$suid_sgid_files"
    log_and_print "\n→ Total files with SUID/SGID bits set: $(echo "$suid_sgid_files" | wc -l)"
}

# 3. Service Audits
service_audit() {
    print_title "3. SERVICE AUDIT"

    section "Running Services"
    running_services=$(systemctl list-units --type=service --state=running)
    log_and_print "$running_services"

    section "Critical Services Check"
    critical_services=("sshd" "iptables")
    for service in "${critical_services[@]}"; do
        status=$(systemctl is-active "$service")
        log_and_print "$service: $status"
    done

    section "Services Listening on Non-Standard Ports"
    non_standard_ports=$(ss -tuln | grep -vE ':(22|80|443|8080)' 2>/dev/null)
    log_and_print "$non_standard_ports"
}

# 5. IP and Network Configuration Checks
network_configuration() {
    print_title "5. IP AND NETWORK CONFIGURATION CHECKS"

    section "Assigned IP Addresses"
    ip_addresses=$(hostname -I)
    log_and_print "IP Addresses assigned to the server: $ip_addresses"

    section "Public vs Private IP Check"
    public_ips=""
    private_ips=""
    for ip in $ip_addresses; do
        if echo "$ip" | grep -E "^(10\.|172\.16\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+)" >/dev/null; then
            private_ips="$private_ips\n$ip (Private)"
        else
            public_ips="$public_ips\n$ip (Public)"
        fi
    done
    log_and_print "Private IPs: $private_ips"
    log_and_print "Public IPs: $public_ips"

    section "Sensitive Services on Public IP"
    if [[ -n "$public_ips" ]]; then
        services=$(ss -tuln | grep -E 'ssh' 2>/dev/null)
        if [[ -n "$services" ]]; then
            log_and_print "Sensitive services (SSH) exposed on public IPs:\n$services"
        else
            log_and_print "No sensitive services exposed on public IPs."
        fi
    fi
}

# Main function to start the audit
main() {
    clear
    echo -e "\n\033[1;35m=== Starting Linux Security Audit ===\033[0m"
    
    # Run the User and Group Audits
    user_audit

    # Run the File and Directory Permissions audit
    file_permissions

    # Run the Service Audits
    service_audit

    # Run the IP and Network Configuration Checks
    network_configuration

    # Future calls for other sections will go here

    echo -e "\n\033[1;32m=== Security Audit Completed ===\033[0m"
}

main
