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
    apt-get update -q -y > /dev/null
    apt-get upgrade -q -y > /dev/null
}

install_package() {
    local package="$1"
    apt-get install -y -q "$package" > /dev/null
}

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

# ----------- 1. User and Group Audit ------------

user_audit() {
    print_title "1. USER AND GROUP AUDIT"

    section "Users with UID 0 (root access)"
    getent passwd | awk -F: '$3 == 0 {print $1}' | log_and_print

    section "Users without password"
    awk -F: '($2 == "" || $2 == "!" || $2 == "*") {print $1}' /etc/shadow | log_and_print

    section "All Local Users"
    cut -d: -f1 /etc/passwd | log_and_print

    section "All Local Groups"
    cut -d: -f1 /etc/group | log_and_print
}

# ----------- 2. File and Directory Permissions ------------

file_perm_audit() {
    print_title "2. FILE AND DIRECTORY PERMISSIONS"

    section "World-writable files and directories"
    find / -xdev -type f -perm -0002 -ls 2>/dev/null | tee -a "$REPORT"

    section "Check .ssh directories for permissions"
    find /home -name ".ssh" -exec ls -ld {} \; 2>/dev/null | tee -a "$REPORT"

    section "Files with SUID/SGID"
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -ls 2>/dev/null | tee -a "$REPORT"
}

# ----------- 3. Service Audits ------------

service_audit() {
    print_title "3. SERVICE AUDIT"

    section "Running services"
    systemctl list-units --type=service --state=running | tee -a "$REPORT"

    section "Critical services check"
    for svc in sshd ufw iptables; do
        if systemctl is-active --quiet "$svc"; then
            log_and_print "$svc is running"
        else
            log_and_print "$svc is NOT running"
        fi
    done

    section "Check for services on non-standard ports"
    ss -tulpn | grep -vE '(:22|:80|:443)' | tee -a "$REPORT"
}

# ----------- 4. Firewall & Network Security ------------

network_audit() {
    print_title "4. FIREWALL & NETWORK SECURITY"

    section "Firewall status"
    ufw status verbose | tee -a "$REPORT"

    section "Open ports"
    ss -tuln | tee -a "$REPORT"

    section "IP forwarding status"
    sysctl net.ipv4.ip_forward | tee -a "$REPORT"
}

# ----------- 5. IP Configuration & Type ------------

ip_audit() {
    print_title "5. PUBLIC vs PRIVATE IP CHECK"

    section "IP address summary"
    ip -4 a | tee -a "$REPORT"

    section "Public IP check"
    curl -s ifconfig.me | tee -a "$REPORT"
}

# ----------- 6. Security Updates & Patch Check ------------

security_updates() {
    print_title "6. SECURITY UPDATES AND PATCHING"

    section "System updates"
    apt_update

    section "Running unattended upgrade"
    install_package unattended-upgrades
    unattended-upgrade -d --dry-run | tee -a "$REPORT"
}

# ----------- 7. Log Monitoring ------------

log_monitoring() {
    print_title "7. LOG MONITORING"

    section "SSH login attempts from auth.log"
    grep -E "Failed|Accepted" /var/log/auth.log | tail -n 50 | tee -a "$REPORT"
}

# ----------- 8. Hardening Steps ------------

hardening_steps() {
    print_title "8. SERVER HARDENING"

    section "SSH Hardening"
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
    log_and_print "✅ SSH hardened: root login & password auth disabled"

    section "Disable IPv6"
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p | tee -a "$REPORT"

    section "Secure GRUB Bootloader with Password"
    read -s -p "Enter GRUB password: " grub_plain
    echo
    read -s -p "Confirm GRUB password: " grub_confirm
    echo

    if [[ "$grub_plain" != "$grub_confirm" ]]; then
        log_and_print "❌ GRUB password mismatch. Skipping GRUB protection."
    else
        grub_hash=$(echo -e "$grub_plain\n$grub_plain" | grub-mkpasswd-pbkdf2 | grep 'grub.pbkdf2' | awk '{print $7}')

        sed -i '/set superusers=/d' /etc/grub.d/40_custom 2>/dev/null
        sed -i '/password_pbkdf2 root/d' /etc/grub.d/40_custom 2>/dev/null

        cat <<EOF >> /etc/grub.d/40_custom

set superusers="root"
password_pbkdf2 root $grub_hash
EOF

        chmod 600 /etc/grub.d/40_custom
        update-grub
        log_and_print "✅ GRUB bootloader secured with password."
    fi

    section "Firewall rules setup"
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22
    ufw --force enable
    log_and_print "✅ Firewall (ufw) configured and enabled"

    section "Enable Automatic Updates"
    install_package unattended-upgrades
    cat <<EOF > /etc/apt/apt.conf.d/10periodic
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

    cat <<EOF > /etc/apt/apt.conf.d/20auto-upgrades
Unattended-Upgrade::Automatic-Reboot "true";
EOF

    unattended-upgrade -d > /dev/null
    log_and_print "✅ Automatic security updates enabled"
}

# ----------- Main ------------
main() {
    clear
    echo -e "\n\033[1;35m=== Starting Linux Security Audit ===\033[0m"
    user_audit
    file_perm_audit
    service_audit
    network_audit
    ip_audit
    security_updates
    log_monitoring
    hardening_steps
    echo -e "\n\033[1;32m=== Audit Completed. Report saved to $REPORT ===\033[0m"
}

main
