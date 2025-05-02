#!/bin/bash

# ===============================
# Linux Security Audit & Hardening
# ===============================

REPORT="security_audit_report.txt"
CUSTOM_CONF="custom_checks.conf"
EMAIL="akshay.bendke12@gmail.com"
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
> "$REPORT"

export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none

apt_update() {
    apt-get update -qq -y > /dev/null
    apt-get upgrade -qq -y > /dev/null
}

install_package() {
    local package="$1"
    dpkg -s "$package" &> /dev/null || apt-get install -qq -y "$package" > /dev/null
}

print_title() {
    echo -e "\n========== $1 ==========" | tee -a "$REPORT"
}

log_and_print() {
    echo -e "$1" | tee -a "$REPORT"
}

section() {
    echo -e "\n+------------------------------------------------------------+" | tee -a "$REPORT"
    echo -e "| $1" | tee -a "$REPORT"
    echo -e "+------------------------------------------------------------+" | tee -a "$REPORT"
}

# 1. User and Group Audits
user_audit() {
    print_title "1. USER AND GROUP AUDIT"
    section "Users with UID 0"
    getent passwd | awk -F: '$3 == 0 {print $1}' | tee -a "$REPORT"
    section "Users without password"
    awk -F: '($2 == "" || $2 == "!" || $2 == "*") {print $1}' /etc/shadow | tee -a "$REPORT"
    section "All Users"
    cut -d: -f1 /etc/passwd | tee -a "$REPORT"
    section "All Groups"
    cut -d: -f1 /etc/group | tee -a "$REPORT"
    section "Users with sudo"
    getent group sudo | cut -d: -f4 | tr ',' '\n' | tee -a "$REPORT"
}

# 2. File Permissions
file_perm_audit() {
    print_title "2. FILE AND DIRECTORY PERMISSIONS"
    section "World-writable Files"
    find / -xdev -type f -perm -0002 -ls 2>/dev/null | tee -a "$REPORT"
    section ".ssh Directory Permissions"
    find /home -name ".ssh" -exec ls -ld {} \; 2>/dev/null | tee -a "$REPORT"
    section "Files with SUID/SGID"
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -ls 2>/dev/null | tee -a "$REPORT"
}

# 3. Service Audit
service_audit() {
    print_title "3. SERVICE AUDIT"
    section "Running Services"
    systemctl list-units --type=service --state=running | tee -a "$REPORT"
    section "Critical Services"
    for svc in ssh ufw iptables; do
        systemctl is-active --quiet "$svc" && log_and_print "$svc is running" || log_and_print "$svc is NOT running"
    done
    section "Non-Standard Ports"
    ss -tulpn | grep -vE '(:22|:80|:443)' | tee -a "$REPORT"
}

# 4. Firewall and Network
network_audit() {
    print_title "4. FIREWALL & NETWORK SECURITY"
    section "Firewall Status"
    ufw status verbose | tee -a "$REPORT"
    section "Open Ports"
    ss -tuln | tee -a "$REPORT"
    section "IP Forwarding"
    sysctl net.ipv4.ip_forward | tee -a "$REPORT"
}

# 5. Public vs Private IP
ip_audit() {
    print_title "5. PUBLIC vs PRIVATE IP CHECK"
    section "Local IPs"
    ip -4 a | tee -a "$REPORT"
    section "Public IP"
    curl -s ifconfig.me | tee -a "$REPORT"
    section "SSH Exposure"
    ss -tulpn | grep ':22' | tee -a "$REPORT"
}

# 6. Security Updates
security_updates() {
    print_title "6. SECURITY UPDATES"
    apt_update
    section "Running unattended-upgrade"
    install_package unattended-upgrades
    unattended-upgrade -d --dry-run | tee -a "$REPORT"
}

# 7. Log Monitoring
log_monitoring() {
    print_title "7. LOG MONITORING"
    section "Last SSH login attempts"
    grep -E "Failed|Accepted" /var/log/auth.log | tail -n 50 | tee -a "$REPORT"
}

# 8. Server Hardening
hardening_steps() {
    print_title "8. SERVER HARDENING"
    section "SSH Hardening"
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
    log_and_print "→ SSH hardened"

    section "Disable IPv6"
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p | tee -a "$REPORT"

    section "GRUB Password"
    GRUB_USER="root"
    GRUB_PASS="Strong@$(date +%s)"
    hash=$(echo -e "$GRUB_PASS\n$GRUB_PASS" | grub-mkpasswd-pbkdf2 | awk '/grub.pbkdf2/ {print $NF}')
    echo "password_pbkdf2 $GRUB_USER $hash" > /etc/grub.d/01_password
    chmod 600 /etc/grub.d/01_password
    update-grub
    log_and_print "→ GRUB password set. Password: $GRUB_PASS"

    section "Firewall Rules"
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22
    ufw --force enable

    section "Automatic Security Updates"
    echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/10periodic
    echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/10periodic
    echo 'APT::Periodic::AutocleanInterval "7";' >> /etc/apt/apt.conf.d/10periodic
}

# 9. Custom Checks
custom_checks() {
    print_title "9. CUSTOM SECURITY CHECKS"
    if [[ ! -f "$CUSTOM_CONF" ]]; then
        log_and_print "No custom_checks.conf found."
        return
    fi

    while IFS=: read -r desc cmd; do
        [[ -z "$desc" || -z "$cmd" ]] && continue
        section "$desc"
        bash -c "$cmd" 2>/dev/null | tee -a "$REPORT"
    done < "$CUSTOM_CONF"
}

send_email() {
    install_package mailutils
    echo "Security Audit Report attached." | mail -s "Linux Security Audit Report" -a "$REPORT" "$EMAIL"
}

main() {
    clear
    echo -e "\n=== Starting Security Audit ==="
    install_package curl
    install_package ufw
    user_audit
    file_perm_audit
    service_audit
    network_audit
    ip_audit
    security_updates
    log_monitoring
    hardening_steps
    custom_checks
    send_email
    echo -e "\n=== Audit Complete. Report: $REPORT ==="
}

main
