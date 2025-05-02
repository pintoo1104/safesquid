#!/bin/bash

# ======================================
# Linux Security Audit and Hardening
# ======================================

REPORT="security_audit_report.txt"
> "$REPORT"

# Set APT to non-interactive to avoid CLI warnings
export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none

# Function to suppress any warnings or prompts from apt
apt_update() {
    apt-get update -q -y > /dev/null
    apt-get upgrade -q -y > /dev/null
}

# Function to install packages without interactive prompts
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

# 1. User and Group Audits
user_audit() {
    print_title "1. USER AND GROUP AUDIT"

    section "Users with UID 0 (root access)"
    root_users=$(getent passwd | awk -F: '$3 == 0 {print $1}')
    log_and_print "$root_users"

    section "Users without password"
    no_pass=$(sudo awk -F: '($2 == "" || $2 == "!" || $2 == "*") {print $1}' /etc/shadow)
    log_and_print "$no_pass"

    section "All Local Users"
    cut -d: -f1 /etc/passwd | log_and_print

    section "All Local Groups"
    cut -d: -f1 /etc/group | log_and_print

    # Check for users with sudo access
    section "Users with sudo privileges"
    sudo_users=$(getent passwd | grep -E '^(.*:.*:.*:.*:.*:.*:(.*sudo.*))' | cut -d: -f1)
    log_and_print "$sudo_users"
}

# 2. File and Directory Permissions
file_perm_audit() {
    print_title "2. FILE AND DIRECTORY PERMISSIONS"

    section "World-writable files and directories"
    find / -xdev -type f -perm -0002 -ls 2>/dev/null | tee -a "$REPORT"

    section "Check .ssh directories for permissions"
    find /home -name ".ssh" -exec ls -ld {} \; 2>/dev/null | tee -a "$REPORT"

    section "Files with SUID/SGID"
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -ls 2>/dev/null | tee -a "$REPORT"
}

# 3. Service Audits
service_audit() {
    print_title "3. SERVICE AUDIT"

    section "Running services"
    systemctl list-units --type=service --state=running | tee -a "$REPORT"

    section "Critical services check"
    for svc in sshd ufw iptables; do
        if systemctl is-active --quiet $svc; then
            log_and_print "$svc is running"
        else
            log_and_print "$svc is NOT running"
        fi
    done

    section "Check for services on non-standard ports"
    ss -tulpn | grep -vE '(:22|:80|:443)' | tee -a "$REPORT"
}

# 4. Firewall and Network Security
network_audit() {
    print_title "4. FIREWALL & NETWORK SECURITY"

    section "Firewall status"
    ufw status verbose | tee -a "$REPORT"

    section "Open ports"
    ss -tuln | tee -a "$REPORT"

    section "IP forwarding status"
    sysctl net.ipv4.ip_forward | tee -a "$REPORT"
}

# 5. IP and Network Configuration Checks
ip_audit() {
    print_title "5. PUBLIC vs PRIVATE IP CHECK"

    section "IP address summary"
    ip -4 a | tee -a "$REPORT"

    section "Public IP check"
    curl -s ifconfig.me | tee -a "$REPORT"

    # Check if any sensitive service is exposed on public IP
    section "Sensitive service exposure"
    ss -tulpn | grep ':22' | tee -a "$REPORT"
}

# 6. Security Updates and Patching
security_updates() {
    print_title "6. SECURITY UPDATES AND PATCHING"

    section "Available updates"
    apt_update

    section "Security updates"
    apt-get upgrade -q -y --only-upgrade | tee -a "$REPORT"

    section "Running unattended upgrade"
    apt-get install -y unattended-upgrades > /dev/null
    unattended-upgrade -d --dry-run | tee -a "$REPORT"
}

# 7. Log Monitoring
log_monitoring() {
    print_title "7. LOG MONITORING"

    section "SSH login attempts from auth.log"
    grep -E "Failed|Accepted" /var/log/auth.log | tail -n 50 | tee -a "$REPORT"
}

# 8. Server Hardening Steps
hardening_steps() {
    print_title "8. SERVER HARDENING"

    section "SSH hardening"
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
    log_and_print "→ SSH hardened: root login & password auth disabled"

    section "Disable IPv6"
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p | tee -a "$REPORT"

    section "Configure GRUB password"
    GRUB_PASS="Strong@$(date +%s)"
    hash=$(echo -e "$GRUB_PASS\n$GRUB_PASS" | grub-mkpasswd-pbkdf2 | awk '/grub.pbkdf2/ {print $NF}')
    echo "password_pbkdf2 $GRUB_USER $hash" > /etc/grub.d/01_password
    chmod 600 /etc/grub.d/01_password
    update-grub
    log_and_print "→ GRUB password set. Password: $GRUB_PASS"

    section "Firewall rules"
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22
    ufw enable

    section "Enable automatic updates"
    apt install -y unattended-upgrades > /dev/null

    # Directly modify the configuration file for automatic updates
    echo "APT::Periodic::Update-Package-Lists \"1\";" > /etc/apt/apt.conf.d/10periodic
    echo "APT::Periodic::Unattended-Upgrade \"1\";" >> /etc/apt/apt.conf.d/10periodic
    echo "APT::Periodic::AutocleanInterval \"7\";" >> /etc/apt/apt.conf.d/10periodic

    # Set automatic updates for security upgrades
    echo "Unattended-Upgrade::Automatic-Reboot 'true';" > /etc/apt/apt.conf.d/20auto-upgrades
    echo "Unattended-Upgrade::Allowed-Origins::${distro_id} ${distro_codename}-security;" >> /etc/apt/apt.conf.d/20auto-upgrades

    # Manually trigger unattended-upgrades without reconfigure (bypassing the warning)
    unattended-upgrade -d > /dev/null

    log_and_print "→ Automatic security updates enabled"
}

# Main function to execute all sections
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
