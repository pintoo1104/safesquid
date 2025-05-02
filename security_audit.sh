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
    world_writable_files=$(find / -type f -perm -0002 2>/dev/null)
    log_and_print "$world_writable_files"
    log_and_print "\n→ Total world-writable files: $(echo "$world_writable_files" | wc -l)"

    section ".ssh Directories Permissions"
    ssh_dirs=$(find / -type d -name '.ssh' -exec ls -ld {} \; 2>/dev/null)
    log_and_print "$ssh_dirs"
    log_and_print "\n→ Total .ssh directories found: $(echo "$ssh_dirs" | wc -l)"

    section "Files with SUID or SGID Bits Set"
    suid_sgid_files=$(find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)
    log_and_print "$suid_sgid_files"
    log_and_print "\n→ Total files with SUID/SGID bits: $(echo "$suid_sgid_files" | wc -l)"
}

# 3. Service Audits
service_audit() {
    print_title "3. SERVICE AUDIT"

    section "Running Services"
    running_services=$(ps aux --no-headers)
    log_and_print "$running_services"
    log_and_print "\n→ Total running services: $(echo "$running_services" | wc -l)"

    section "Checking for Critical Services"
    critical_services="sshd iptables"
    for service in $critical_services; do
        service_status=$(systemctl is-active $service)
        log_and_print "$service: $service_status"
    done
}

# 4. Firewall and Network Security
firewall_network_security() {
    print_title "4. FIREWALL AND NETWORK SECURITY"

    section "Firewall Status"
    firewall_status=$(ufw status verbose)
    log_and_print "$firewall_status"
    
    section "Open Ports"
    open_ports=$(ss -tuln)
    log_and_print "$open_ports"

    section "IP Forwarding"
    ip_forwarding=$(sysctl net.ipv4.ip_forward)
    log_and_print "$ip_forwarding"
}

# 5. IP and Network Configuration Checks
ip_network_config() {
    print_title "5. IP AND NETWORK CONFIGURATION"

    section "Public vs Private IP"
    public_private_ip=$(ip a | grep inet)
    log_and_print "$public_private_ip"
}

# 6. Security Updates and Patching
security_updates() {
    print_title "6. SECURITY UPDATES AND PATCHING"

    section "Check for Available Security Updates"
    updates_available=$(apt list --upgradable 2>/dev/null)
    log_and_print "$updates_available"
    
    section "Applying Security Updates Automatically"
    if [ -n "$updates_available" ]; then
        log_and_print "Security updates available, applying updates..."
        sudo apt-get update && sudo apt-get upgrade -y
    else
        log_and_print "No security updates available."
    fi
}

# 7. Log Monitoring
log_monitoring() {
    print_title "7. LOG MONITORING"

    section "Recent SSH Login Attempts"
    recent_logins=$(grep "sshd" /var/log/auth.log | tail -n 20)
    log_and_print "$recent_logins"
}

# 8. Server Hardening Steps
server_hardening() {
    print_title "8. SERVER HARDENING STEPS"

    section "Set GRUB Password"
    generate_grub_password_hash

    section "Disable IPv6 if not required"
    disable_ipv6_if_needed

    section "Secure Bootloader"
    set_grub_password

    section "Configure Firewall Rules"
    configure_firewall

    section "Enable Automatic Updates"
    enable_automatic_updates
}

# Function to generate GRUB password hash
generate_grub_password_hash() {
    read -sp "Enter GRUB password: " grub_password
    echo
    grub_hash=$(echo -n "$grub_password" | grub-mkpasswd-pbkdf2 | grep -o 'grub.pbkdf2.*')
    echo "set superusers=\"root\"" >> /etc/grub.d/40_custom
    echo "password_pbkdf2 root $grub_hash" >> /etc/grub.d/40_custom
    update-grub
    log_and_print "GRUB password has been set."
}

# Function to disable IPv6 if needed
disable_ipv6_if_needed() {
    if [ "$DISABLE_IPV6" == "yes" ]; then
        sysctl -w net.ipv6.conf.all.disable_ipv6=1
        sysctl -w net.ipv6.conf.default.disable_ipv6=1
        sysctl -w net.ipv6.conf.lo.disable_ipv6=1
        log_and_print "IPv6 has been disabled."
    else
        log_and_print "IPv6 is enabled, no action taken."
    fi
}

# Function to configure firewall rules
configure_firewall() {
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw enable
    log_and_print "Firewall rules have been configured."
}

# Function to enable automatic updates
enable_automatic_updates() {
    apt-get install unattended-upgrades
    dpkg-reconfigure --priority=low unattended-upgrades
    log_and_print "Automatic updates have been enabled."
}

# Main function to start the audit
main() {
    clear
    echo -e "\n\033[1;35m=== Starting Linux Security Audit ===\033[0m"

    # Run all audit functions
    user_audit
    file_permissions_audit
    service_audit
    firewall_network_security
    ip_network_config
    security_updates
    log_monitoring
    server_hardening
    
    echo -e "\n\033[1;32m=== Security Audit Completed ===\033[0m"
}

main
