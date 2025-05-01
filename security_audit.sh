#!/bin/bash

# ===========================
# Linux Security Audit & Hardening Script
# ===========================

# Define the output file to be created in the current directory
REPORT_FILE="./security_hardening_report_$(date +%F_%H-%M-%S).txt"

# Initialize the report file
echo "===== Security Audit and Hardening Report =====" > "$REPORT_FILE"
echo "Security Audit and Hardening Report - $(date)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Function to display output and also save it to the report file
output_and_report() {
    echo "$1"        # Display the output in terminal
    echo "$1" >> "$REPORT_FILE"  # Save the output to the file
}

# ========== User and Group Audits ==========
user_group_audit() {
    output_and_report "User and Group Audit"
    output_and_report "List of all users and groups:"
    getent passwd >> "$REPORT_FILE"
    getent group >> "$REPORT_FILE"
    output_and_report "Non-root users with UID 0:"
    awk -F: '($3 == 0) {print $1}' /etc/passwd | grep -v '^root$' >> "$REPORT_FILE"
    output_and_report "Users without passwords:"
    awk -F: '($2 == "" || $2 == "*" || $2 == "!" ) {print $1}' /etc/shadow >> "$REPORT_FILE"
}

# ========== File Permissions Audit ==========
permissions_audit() {
    output_and_report "File and Directory Permissions Audit"
    output_and_report "Files and directories with world-writable permissions:"
    find / -xdev -type f -perm -0002 -print >> "$REPORT_FILE"
    find / -xdev -type d -perm -0002 -print >> "$REPORT_FILE"
    output_and_report ".ssh directories:"
    find /home -name ".ssh" -exec ls -ld {} + >> "$REPORT_FILE"
    output_and_report "Files with SUID/SGID bits set:"
    find / -xdev \( -perm -4000 -o -perm -2000 \) -exec ls -ld {} + >> "$REPORT_FILE"
}

# ========== Service Audit ==========
service_audit() {
    output_and_report "Service Audit"
    output_and_report "List of running services:"
    systemctl list-units --type=service --state=running >> "$REPORT_FILE"
    output_and_report "Critical services status:"
    for svc in ssh ufw iptables; do
        systemctl is-enabled "$svc" >/dev/null 2>&1 && echo "$svc is enabled" || echo "$svc not enabled"
    done >> "$REPORT_FILE"
    output_and_report "Active network ports and services:"
    netstat -tulnp >> "$REPORT_FILE"
}

# ========== Firewall and Network Security ==========
firewall_network_audit() {
    output_and_report "Firewall and Network Configuration"
    output_and_report "Firewall status (ufw):"
    ufw status >> "$REPORT_FILE"
    output_and_report "Active network ports:"
    netstat -tuln >> "$REPORT_FILE"
    output_and_report "IP forwarding status:"
    sysctl net.ipv4.ip_forward >> "$REPORT_FILE"
    sysctl net.ipv6.conf.all.disable_ipv6 >> "$REPORT_FILE"
}

# ========== IP Configuration Checks ==========
ip_check() {
    output_and_report "IP Address and Exposure Check"
    output_and_report "IP address details:"
    ip -br a >> "$REPORT_FILE"
    ip a | grep inet | while read -r line; do
        ip=$(echo $line | awk '{print $2}' | cut -d/ -f1)
        if [[ $ip == 10.* || $ip == 172.* || $ip == 192.168.* ]]; then
            output_and_report "Private IP: $ip"
        else
            output_and_report "Public IP detected: $ip"
        fi
    done >> "$REPORT_FILE"
}

# ========== Security Updates ==========
check_updates() {
    output_and_report "Checking for Security Updates"
    apt update -y && apt list --upgradable 2>/dev/null >> "$REPORT_FILE"
    apt install -y unattended-upgrades
    dpkg-reconfigure -f noninteractive unattended-upgrades
}

# ========== Log Monitoring ==========
monitor_logs() {
    output_and_report "Log Monitoring"
    output_and_report "Recent failed login attempts:"
    grep -i "failed\|invalid" /var/log/auth.log | tail -n 10 >> "$REPORT_FILE"
}

# ========== SSH Hardening ==========
secure_ssh() {
    output_and_report "Securing SSH"
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
}

# ========== Disable IPv6 ==========
disable_ipv6() {
    output_and_report "Disabling IPv6"
    echo -e "\n# Disable IPv6" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p
}

# ========== Bootloader Hardening ==========
secure_bootloader() {
    output_and_report "Securing Bootloader"
    GRUB_PASSWORD=${GRUB_PASSWORD:-'SecurePass123'}
    HASHED_PASSWORD=$(echo -e "$GRUB_PASSWORD\n$GRUB_PASSWORD" | grub-mkpasswd-pbkdf2 | grep grub.pbkdf2 | awk '{print $NF}')
    {
        echo "set superusers=\"admin\""
        echo "password_pbkdf2 admin $HASHED_PASSWORD"
    } > /etc/grub.d/40_custom
    update-grub
    output_and_report "GRUB password set and bootloader secured"
}

# ========== Configure Firewall ==========
configure_firewall() {
    output_and_report "Configuring Firewall"
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw enable
}

# ========== Run All ==========
main() {
    user_group_audit
    permissions_audit
    service_audit
    firewall_network_audit
    ip_check
    check_updates
    monitor_logs
    secure_ssh
    disable_ipv6
    secure_bootloader
    configure_firewall
    output_and_report "Security audit and hardening complete. Report saved to $REPORT_FILE"
}

main
