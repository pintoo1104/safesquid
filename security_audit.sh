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

    section "World-writable directories"
    dirs=$(find / -type d -perm -0002 -exec ls -ld {} \; 2>/dev/null)
    log_and_print "$dirs"
    log_and_print "\n→ Total world-writable directories: $(echo "$dirs" | grep -c '^')"

    section "SUID/SGID Files"
    suid_sgid=$(find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -ld {} \; 2>/dev/null)
    log_and_print "$suid_sgid"
    log_and_print "\n→ Total SUID/SGID files: $(echo "$suid_sgid" | grep -c '^')"

    section "SSH Directory Permissions"
    ssh_dirs=$(find /home -name ".ssh" -exec ls -ld {} \; 2>/dev/null)
    log_and_print "$ssh_dirs"
    log_and_print "\n→ Total .ssh directories: $(echo "$ssh_dirs" | wc -l)"
}

# 3. Service Audits
service_audit() {
    print_title "3. SERVICE AUDIT"

    section "Running Services"
    running=$(systemctl list-units --type=service --state=running)
    log_and_print "$running"
    log_and_print "\n→ Total running services: $(echo "$running" | grep -c 'loaded')"

    section "Listening Network Ports (excluding localhost)"
    ports=$(netstat -tulnp | grep -v "127.0.0.1")
    log_and_print "$ports"
    log_and_print "\n→ Total open ports (non-localhost): $(echo "$ports" | grep -c '^')"
}

# 4. Firewall and Network Security
firewall_audit() {
    print_title "4. FIREWALL & NETWORK SECURITY"

    section "Firewall Rules"
    if command -v ufw &> /dev/null; then
        rules=$(ufw status verbose)
        log_and_print "$rules"
    elif command -v iptables &> /dev/null; then
        rules=$(iptables -L -n -v)
        log_and_print "$rules"
    else
        log_and_print "No firewall tool (ufw/iptables) found."
    fi

    section "Active Listening Ports"
    ss_output=$(ss -tuln)
    log_and_print "$ss_output"
    log_and_print "\n→ Total listening ports: $(echo "$ss_output" | grep -c '^tcp\|^udp')"
}

# 5. IP and Network Configuration
ip_check() {
    print_title "5. IP CONFIGURATION CHECK"

    section "Assigned IP Addresses"
    ip_list=$(ip -4 addr show | grep inet | awk '{print $2}')
    private=0
    public=0
    while read ip; do
        if [[ "$ip" =~ ^10\. || "$ip" =~ ^172\.1[6-9] || "$ip" =~ ^192\.168 ]]; then
            log_and_print "Private IP: $ip"
            ((private++))
        else
            log_and_print "Public IP: $ip"
            ((public++))
        fi
    done <<< "$ip_list"
    log_and_print "\n→ Private IPs: $private, Public IPs: $public"
}

# 6. Security Updates and Patching
update_check() {
    print_title "6. SECURITY UPDATES & PATCHING"

    section "Available Updates"
    if command -v apt &> /dev/null; then
        apt update -y > /dev/null
        updates=$(apt list --upgradable 2>/dev/null)
        log_and_print "$updates"
        log_and_print "\n→ Total upgradable packages: $(echo "$updates" | grep -c '/')"
    elif command -v yum &> /dev/null; then
        updates=$(yum check-update)
        log_and_print "$updates"
        log_and_print "\n→ Total upgradable packages (if listed): $(echo "$updates" | grep -c '^')"
    fi
}

# 7. Log Monitoring
log_monitor() {
    print_title "7. LOGIN ATTEMPTS & AUTH LOGS"

    section "Recent Failed Login Attempts"
    failed=$(grep "Failed password" /var/log/auth.log | tail -n 10)
    log_and_print "$failed"
    log_and_print "\n→ Total recent failed logins shown: $(echo "$failed" | grep -c 'Failed')"
}

# 8. Server Hardening
server_hardening() {
    print_title "8. SERVER HARDENING"

    section "SSH Configuration (Root login/password auth disabled)"
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl reload sshd
    log_and_print "→ Updated sshd_config to disable root login and password authentication."

    section "Disabling IPv6"
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    reload=$(sysctl -p)
    log_and_print "$reload"

    section "Bootloader Security Check"
    log_and_print "Manual verification recommended for /boot/grub/grub.cfg permissions."
}

# 9. Custom Checks Placeholder
custom_checks() {
    print_title "9. CUSTOM CHECKS"
    log_and_print "You can extend this section for application-specific security checks."
}

# 10. Summary
summary() {
    print_title "10. AUDIT COMPLETED"
    log_and_print "Complete report saved to: $REPORT"
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
