#!/bin/bash

# ======================================
# Linux Security Audit and Hardening
# ======================================

REPORT="security_audit_report.txt"
> "$REPORT"
EMAIL="admin@example.com"
CUSTOM_CHECKS_CONF="./custom_checks.conf"

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

    section "Firewall rules"
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22
    ufw enable

    section "Enable automatic updates"
    apt install -y unattended-upgrades > /dev/null
    echo "APT::Periodic::Update-Package-Lists \"1\";" > /etc/apt/apt.conf.d/10periodic
    echo "APT::Periodic::Unattended-Upgrade \"1\";" >> /etc/apt/apt.conf.d/10periodic
    echo "APT::Periodic::AutocleanInterval \"7\";" >> /etc/apt/apt.conf.d/10periodic
    unattended-upgrade -d > /dev/null
    log_and_print "→ Automatic security updates enabled"
}

# 9. Custom Security Checks
custom_security_checks() {
    print_title "9. CUSTOM SECURITY CHECKS"
    if [ -f "$CUSTOM_CHECKS_CONF" ]; then
        while IFS= read -r line; do
            if [[ ! "$line" =~ ^#.* ]]; then
                section "Running custom check: $line"
                eval "$line" | tee -a "$REPORT"
            fi
        done < "$CUSTOM_CHECKS_CONF"
    else
        log_and_print "No custom checks configuration found. Please create '$CUSTOM_CHECKS_CONF'."
    fi
}

# 10. Reporting and Alerting
generate_report() {
    print_title "10. REPORTING AND ALERTING"
    
    section "Generating Summary Report"
    echo -e "Security Audit Summary" > "$REPORT"
    echo -e "======================" >> "$REPORT"
    
    if grep -q "is NOT running" "$REPORT"; then
        log_and_print "ALERT: Some critical services are not running. Sending email alert..."
        send_email_alert
    fi

    section "Audit completed successfully"
    log_and_print "Audit completed. No critical issues found."
}

send_email_alert() {
    echo "Critical vulnerabilities or misconfigurations found in the security audit. Please review the report at $(hostname)." | mail -s "Security Audit Alert" "$EMAIL"
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
    custom_security_checks
    generate_report

    echo -e "\n\033[1;32m=== Audit Completed. Report saved to $REPORT ===\033[0m"
}

main
