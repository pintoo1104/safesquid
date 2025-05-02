#!/bin/bash

# =========================================
# Linux Security Audit and Hardening Script
# =========================================

REPORT="security_audit_report.txt"
> "$REPORT"

export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none

# ----------- Utility Functions ------------

apt_update() {
    apt-get update -q -y >> "$REPORT" 2>&1
    apt-get upgrade -q -y >> "$REPORT" 2>&1
}

install_package() {
    local package="$1"
    apt-get install -y -q "$package" >> "$REPORT" 2>&1
}

print_title() {
    local title="$1"
    echo -e "\n========== $title ==========\n" | tee -a "$REPORT"
}

print_section() {
    local title="$1"
    echo -e "\n-- $title --\n" | tee -a "$REPORT"
}

log_command() {
    echo -e "\n\$ $1" >> "$REPORT"
    eval "$1" >> "$REPORT" 2>&1
}

# ----------- 1. User and Group Audit ------------

user_audit() {
    print_title "1. USER AND GROUP AUDIT"

    print_section "Users with UID 0 (root access)"
    log_command "getent passwd | awk -F: '\$3 == 0 {print \$1}'"

    print_section "Users without passwords or disabled accounts"
    log_command "awk -F: '(\$2 == \"\" || \$2 == \"!\" || \$2 == \"*\") {print \$1}' /etc/shadow"

    print_section "All Local Users"
    log_command "cut -d: -f1 /etc/passwd"

    print_section "All Local Groups"
    log_command "cut -d: -f1 /etc/group"
}

# ----------- 2. File and Directory Permissions ------------

file_perm_audit() {
    print_title "2. FILE AND DIRECTORY PERMISSIONS"

    print_section "World-writable files and directories"
    log_command "find / -xdev -type f -perm -0002 -ls 2>/dev/null"

    print_section ".ssh directories and permissions"
    log_command "find /home -name '.ssh' -exec ls -ld {} \; 2>/dev/null"

    print_section "Files with SUID/SGID"
    log_command "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f -ls 2>/dev/null"
}

# ----------- 3. Service Audits ------------

service_audit() {
    print_title "3. SERVICE AUDIT"

    print_section "Running services"
    log_command "systemctl list-units --type=service --state=running"

    print_section "Critical services (sshd, ufw, iptables)"
    for svc in sshd ufw iptables; do
        echo -e "\nService: $svc" >> "$REPORT"
        systemctl is-active "$svc" >> "$REPORT" 2>&1
    done

    print_section "Services listening on non-standard ports"
    log_command "ss -tulpn | grep -vE '(:22|:80|:443)'"
}

# ----------- 4. Firewall & Network Security ------------

network_audit() {
    print_title "4. FIREWALL & NETWORK SECURITY"

    print_section "Firewall (ufw) status"
    log_command "ufw status verbose"

    print_section "Open ports"
    log_command "ss -tuln"

    print_section "IP Forwarding Status"
    log_command "sysctl net.ipv4.ip_forward"
}

# ----------- 5. IP Configuration & Type ------------

ip_audit() {
    print_title "5. PUBLIC vs PRIVATE IP AUDIT"

    print_section "IP Address (Local)"
    log_command "ip -4 a"

    print_section "Public IP (external)"
    log_command "curl -s ifconfig.me"
}

# ----------- 6. Security Updates & Patch Check ------------

security_updates() {
    print_title "6. SECURITY UPDATES AND PATCHING"

    print_section "System package updates"
    apt_update

    print_section "Unattended-upgrades dry run"
    install_package unattended-upgrades
    log_command "unattended-upgrade -d --dry-run"
}

# ----------- 7. Log Monitoring ------------

log_monitoring() {
    print_title "7. LOG MONITORING"

    print_section "SSH login attempts (last 50 lines from auth.log)"
    log_command "grep -E 'Failed|Accepted' /var/log/auth.log | tail -n 50"
}

# ----------- 8. Server Hardening ------------

hardening_steps() {
    print_title "8. SERVER HARDENING MEASURES"

    print_section "Disabling root SSH and password authentication"
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    log_command "systemctl restart sshd"

    print_section "Disabling IPv6"
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    log_command "sysctl -p"

    print_section "Securing GRUB with Password"
    read -s -p "Enter GRUB password: " grub_pass1
    echo
    read -s -p "Confirm GRUB password: " grub_pass2
    echo

    if [[ "$grub_pass1" != "$grub_pass2" ]]; then
        echo "❌ GRUB password mismatch. Skipping setup." | tee -a "$REPORT"
    else
        grub_hash=$(echo -e "$grub_pass1\n$grub_pass1" | grub-mkpasswd-pbkdf2 | grep 'grub.pbkdf2' | awk '{print $7}')
        sed -i '/set superusers=/d' /etc/grub.d/40_custom
        sed -i '/password_pbkdf2 root/d' /etc/grub.d/40_custom

        cat <<EOF >> /etc/grub.d/40_custom

set superusers="root"
password_pbkdf2 root $grub_hash
EOF

        chmod 600 /etc/grub.d/40_custom
        log_command "update-grub"
    fi

    print_section "Configure firewall (UFW)"
    install_package ufw
    ufw default deny incoming >> "$REPORT" 2>&1
    ufw default allow outgoing >> "$REPORT" 2>&1
    ufw allow 22 >> "$REPORT" 2>&1
    ufw --force enable >> "$REPORT" 2>&1

    print_section "Enable Unattended Upgrades"
    install_package unattended-upgrades
    cat <<EOF > /etc/apt/apt.conf.d/10periodic
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

    cat <<EOF > /etc/apt/apt.conf.d/20auto-upgrades
Unattended-Upgrade::Automatic-Reboot "true";
EOF

    log_command "unattended-upgrade -d"
}

# ----------- MAIN ------------

main() {
    clear
    echo "=== Starting Linux Security Audit ==="
    user_audit
    file_perm_audit
    service_audit
    network_audit
    ip_audit
    security_updates
    log_monitoring
    hardening_steps
    echo -e "\n✅ Audit completed. Full report saved to: $REPORT"
}

main
