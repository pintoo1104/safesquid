#!/bin/bash

# ===============================
# Linux Security Audit & Hardening Script (Set 2)
# ===============================

# Output Report File
REPORT_FILE="$(pwd)/linux_audit_report_$(date +%F_%T).txt"

# Colors for output
RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; NC="\e[0m"

# ===============================
# Section 1: User and Group Audits
# ===============================
user_group_audit() {
    echo "[SECTION 1: User and Group Audits]" >> "$REPORT_FILE"
    echo "\n>> All Users:" >> "$REPORT_FILE"
    cut -d: -f1 /etc/passwd >> "$REPORT_FILE"

    echo "\n>> All Groups:" >> "$REPORT_FILE"
    cut -d: -f1 /etc/group >> "$REPORT_FILE"

    echo "\n>> Users with UID 0 (should be only root):" >> "$REPORT_FILE"
    awk -F: '($3 == 0) { print $1 }' /etc/passwd >> "$REPORT_FILE"

    echo "\n>> Users with no password or weak password (chkpasswd):" >> "$REPORT_FILE"
    if ! command -v john &>/dev/null; then
        echo "[*] Installing John the Ripper for weak password checks..." >> "$REPORT_FILE"
        sudo apt update && sudo apt install -y john
    fi
    unshadow /etc/passwd /etc/shadow > /tmp/passwords.txt
    john /tmp/passwords.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=crypt >> "$REPORT_FILE"
}

# ===============================
# Section 2: File and Directory Permissions
# ===============================
file_permission_audit() {
    echo "\n[SECTION 2: File and Directory Permissions]" >> "$REPORT_FILE"
    echo "\n>> World-writable files and directories:" >> "$REPORT_FILE"
    find / -xdev \( -type d -o -type f \) -perm -0002 -ls 2>/dev/null >> "$REPORT_FILE"

    echo "\n>> .ssh directories and their permissions:" >> "$REPORT_FILE"
    find /home /root -type d -name ".ssh" -exec ls -ld {} + 2>/dev/null >> "$REPORT_FILE"

    echo "\n>> Files with SUID/SGID bits set:" >> "$REPORT_FILE"
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec ls -l {} + 2>/dev/null >> "$REPORT_FILE"
}

# ===============================
# Section 3: Service Audits
# ===============================
service_audit() {
    echo "\n[SECTION 3: Service Audits]" >> "$REPORT_FILE"
    echo "\n>> All running services:" >> "$REPORT_FILE"
    systemctl list-units --type=service --state=running >> "$REPORT_FILE"

    echo "\n>> Enabled services on boot:" >> "$REPORT_FILE"
    systemctl list-unit-files | grep enabled >> "$REPORT_FILE"

    echo "\n>> SSH and iptables status:" >> "$REPORT_FILE"
    systemctl is-active sshd >> "$REPORT_FILE"
    systemctl is-active iptables >> "$REPORT_FILE"

    echo "\n>> Services listening on non-standard ports:" >> "$REPORT_FILE"
    ss -tuln | grep -vE ':22|:80|:443' >> "$REPORT_FILE"
}

# ===============================
# Section 4: Firewall and Network Security
# ===============================
firewall_network_audit() {
    echo "\n[SECTION 4: Firewall and Network Security]" >> "$REPORT_FILE"
    echo "\n>> Firewall status (ufw or iptables):" >> "$REPORT_FILE"
    if command -v ufw &>/dev/null; then
        ufw status verbose >> "$REPORT_FILE"
    elif command -v iptables &>/dev/null; then
        iptables -L -n -v >> "$REPORT_FILE"
    else
        echo "No firewall tool found (ufw/iptables)" >> "$REPORT_FILE"
    fi

    echo "\n>> Open ports and services:" >> "$REPORT_FILE"
    ss -tuln >> "$REPORT_FILE"

    echo "\n>> IP forwarding status:" >> "$REPORT_FILE"
    sysctl net.ipv4.ip_forward >> "$REPORT_FILE"
    sysctl net.ipv6.conf.all.forwarding >> "$REPORT_FILE"
}

# ===============================
# Section 5: Public vs Private IP
# ===============================
ip_check() {
    echo "\n[SECTION 5: Public vs Private IPs]" >> "$REPORT_FILE"
    echo "\n>> IP addresses and classification:" >> "$REPORT_FILE"
    for ip in $(hostname -I); do
        if [[ "$ip" =~ ^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])|^192\.168 ]]; then
            echo "$ip - Private" >> "$REPORT_FILE"
        else
            echo "$ip - Public" >> "$REPORT_FILE"
        fi
    done

    echo "\n>> Services exposed on public IPs (if any):" >> "$REPORT_FILE"
    ss -tunlp | grep $(curl -s ifconfig.me) >> "$REPORT_FILE" 2>/dev/null
}

# ===============================
# Section 6: Security Updates and Patching
# ===============================
security_updates() {
    echo "\n[SECTION 6: Security Updates and Patching]" >> "$REPORT_FILE"
    echo "\n>> Available updates:" >> "$REPORT_FILE"
    apt update -qq && apt list --upgradable 2>/dev/null >> "$REPORT_FILE"

    echo "\n>> Unattended Upgrades status:" >> "$REPORT_FILE"
    systemctl is-enabled unattended-upgrades >> "$REPORT_FILE"
}

# ===============================
# Section 7: Log Monitoring
# ===============================
log_monitoring() {
    echo "\n[SECTION 7: Log Monitoring]" >> "$REPORT_FILE"
    echo "\n>> SSH login attempts in last 24 hours:" >> "$REPORT_FILE"
    grep "sshd" /var/log/auth.log | grep "Failed" | tail -n 20 >> "$REPORT_FILE"
}

# ===============================
# Section 8: SSH, GRUB, IPv6 Hardening
# ===============================
hardening_steps() {
    echo "\n[SECTION 8: SSH, GRUB, IPv6 Hardening]" >> "$REPORT_FILE"

    echo "\n>> SSH Configuration:" >> "$REPORT_FILE"
    grep -Ei 'PermitRootLogin|PasswordAuthentication' /etc/ssh/sshd_config >> "$REPORT_FILE"

    echo "\n>> IPv6 status:" >> "$REPORT_FILE"
    sysctl net.ipv6.conf.all.disable_ipv6 >> "$REPORT_FILE"

    echo "\n>> GRUB Password Protection Check:" >> "$REPORT_FILE"
    grep GRUB2_PASSWORD /etc/grub.d/40_custom >> "$REPORT_FILE" 2>/dev/null
}

# ===============================
# Section 9: Automatic Updates
# ===============================
auto_update_config() {
    echo "\n[SECTION 9: Automatic Updates]" >> "$REPORT_FILE"
    grep -E '^Unattended-Upgrade::Automatic-Reboot|Install-On-Shutdown' /etc/apt/apt.conf.d/* >> "$REPORT_FILE" 2>/dev/null
}

# ===============================
# Section 10: Reporting and Email Alerts
# ===============================
send_report_via_email() {
    read -rp "Enter the email address to send the audit report: " RECIPIENT_EMAIL

    if ! command -v mailx &>/dev/null; then
        echo "[*] Installing 'mailx'..."
        if [ -f /etc/debian_version ]; then
            sudo apt update && sudo apt install -y mailutils
        elif [ -f /etc/redhat-release ]; then
            sudo yum install -y mailx
        else
            echo "[!] Unsupported OS for mailx install."
            return 1
        fi
    fi

    echo "Security audit report for $(hostname) on $(date)" | \
        mailx -s "🛡️ Linux Audit Report - $(hostname)" -a "$REPORT_FILE" "$RECIPIENT_EMAIL"

    if [ $? -eq 0 ]; then
        echo "[+] Email sent successfully to $RECIPIENT_EMAIL."
    else
        echo "[!] Failed to send email to $RECIPIENT_EMAIL."
    fi
}

# ===============================
# MAIN
# ===============================
echo "[+] Starting Security Audit and Hardening..."
user_group_audit
file_permission_audit
service_audit
firewall_network_audit
ip_check
security_updates
log_monitoring
hardening_steps
auto_update_config
send_report_via_email

echo "[+] Audit Completed. Report saved to: $REPORT_FILE"
