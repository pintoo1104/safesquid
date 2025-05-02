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
permissions_audit() {
    print_title "2. FILE AND DIRECTORY PERMISSIONS"

    section "World-writable files and directories"
    world_writable=$(find / -xdev -type f -perm -0002 2>/dev/null)
    log_and_print "$world_writable"
    log_and_print "\n→ Total world-writable files: $(echo "$world_writable" | wc -l)"

    section ".ssh directories with insecure permissions"
    insecure_ssh=$(find /home -type d -name ".ssh" -perm /022 2>/dev/null)
    log_and_print "$insecure_ssh"
    log_and_print "\n→ Total insecure .ssh dirs: $(echo "$insecure_ssh" | wc -l)"

    section "Files with SUID or SGID permissions"
    suid_sgid=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null)
    log_and_print "$suid_sgid"
    log_and_print "\n→ Total SUID/SGID files: $(echo "$suid_sgid" | wc -l)"
}

# 3. Service Audits
service_audit() {
    print_title "3. SERVICE AUDITS"

    section "Running services"
    services=$(systemctl list-units --type=service --state=running | grep ".service" | awk '{print $1}')
    log_and_print "$services"
    log_and_print "\n→ Total running services: $(echo "$services" | wc -l)"

    section "Check critical services (e.g., sshd, iptables)"
    for svc in sshd iptables ufw; do
        if systemctl is-active --quiet "$svc"; then
            log_and_print "$svc: Active"
        else
            log_and_print "$svc: Inactive or Not Installed"
        fi
    done

    section "Services listening on non-standard or insecure ports"
    listening=$(ss -tuln | awk 'NR>1 {print $5}' | cut -d: -f2 | sort -n | uniq)
    log_and_print "$listening"
}

# 4. Firewall and Network Security
firewall_network_audit() {
    print_title "4. FIREWALL AND NETWORK SECURITY"

    section "Firewall status"
    if command -v ufw >/dev/null; then
        ufw_status=$(sudo ufw status verbose)
        log_and_print "$ufw_status"
    elif command -v iptables >/dev/null; then
        iptables_status=$(sudo iptables -L -n -v)
        log_and_print "$iptables_status"
    else
        log_and_print "No firewall found (neither ufw nor iptables is installed)"
    fi

    section "Open ports and associated services"
    open_ports=$(ss -tuln)
    log_and_print "$open_ports"

    section "IP forwarding and insecure network settings"
    ip_fwd_ipv4=$(sysctl net.ipv4.ip_forward)
    ip_fwd_ipv6=$(sysctl net.ipv6.conf.all.forwarding)
    log_and_print "$ip_fwd_ipv4"
    log_and_print "$ip_fwd_ipv6"
}

# Main function to start the audit
main() {
    clear
    echo -e "\n\033[1;35m=== Starting Linux Security Audit ===\033[0m"

    user_audit
    permissions_audit
    service_audit
    firewall_network_audit

    echo -e "\n\033[1;32m=== Security Audit Completed ===\033[0m"
    echo -e "\n📄 Report saved to: $REPORT"
}

main
