#!/bin/bash

# Define the report file
REPORT_FILE="security_audit_report.txt"
> "$REPORT_FILE" # Clear the previous report

# Function to write headers to the report
write_header() {
    echo "Security Audit and Hardening Report - $(date)" | tee -a "$REPORT_FILE"
    echo "===================================" | tee -a "$REPORT_FILE"
}

# Section 1: User and Group Audits
user_group_audits() {
    echo "===== User and Group Audits =====" | tee -a "$REPORT_FILE"

    # List all users and groups
    echo "[+] Users and Groups:" | tee -a "$REPORT_FILE"
    getent passwd | tee -a "$REPORT_FILE"
    getent group | tee -a "$REPORT_FILE"

    # Check for users with UID 0 (root privileges) and non-standard users
    echo "[+] Checking for non-standard users with UID 0:" | tee -a "$REPORT_FILE"
    awk -F: '($3 == "0") { print $1 }' /etc/passwd | tee -a "$REPORT_FILE"

    # Identify and report users with weak passwords
    echo "[+] Identifying users with weak passwords:" | tee -a "$REPORT_FILE"
    if ! command -v cracklib-check &>/dev/null; then
        echo "[!] cracklib-check not found, please install it first." | tee -a "$REPORT_FILE"
    fi
    awk -F: '{ print $1 }' /etc/shadow | while read user; do
        password=$(grep "^$user:" /etc/shadow | cut -d: -f2)
        echo "$password" | cracklib-check | tee -a "$REPORT_FILE"
    done
    echo "" | tee -a "$REPORT_FILE"
}

# Section 2: File and Directory Permissions
file_permissions() {
    echo "===== File and Directory Permissions =====" | tee -a "$REPORT_FILE"

    # Scan for world-writable files
    echo "[+] World-writable files:" | tee -a "$REPORT_FILE"
    find / -type f -perm -002 -exec ls -l {} \; 2>/dev/null | tee -a "$REPORT_FILE"

    # Check for .ssh directories and secure permissions
    echo "[+] Checking .ssh directories:" | tee -a "$REPORT_FILE"
    find / -type d -name '.ssh' -exec ls -ld {} \; 2>/dev/null | tee -a "$REPORT_FILE"

    # Report SUID/SGID bits set
    echo "[+] SUID/SGID files:" | tee -a "$REPORT_FILE"
    find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"
}

# Section 3: Service Audits
service_audits() {
    echo "===== Service Audits =====" | tee -a "$REPORT_FILE"

    # List running services
    echo "[+] Running Services:" | tee -a "$REPORT_FILE"
    systemctl list-units --type=service --state=running | tee -a "$REPORT_FILE"

    # Check for unauthorized services
    echo "[+] Checking for unauthorized services:" | tee -a "$REPORT_FILE"
    systemctl list-units --type=service --state=inactive | tee -a "$REPORT_FILE"

    # Ensure critical services are running
    echo "[+] Checking critical services:" | tee -a "$REPORT_FILE"
    for service in sshd iptables; do
        systemctl is-active --quiet $service && echo "$service is running." | tee -a "$REPORT_FILE" || echo "$service is not running." | tee -a "$REPORT_FILE"
    done
    echo "" | tee -a "$REPORT_FILE"
}

# Section 4: Firewall and Network Security
firewall_network_security() {
    echo "===== Firewall and Network Security =====" | tee -a "$REPORT_FILE"

    # Verify if firewall is active
    echo "[+] Checking firewall status:" | tee -a "$REPORT_FILE"
    if systemctl is-active --quiet ufw; then
        echo "ufw is active" | tee -a "$REPORT_FILE"
    else
        echo "ufw is inactive" | tee -a "$REPORT_FILE"
    fi

    # Report open ports and services
    echo "[+] Checking open ports and services:" | tee -a "$REPORT_FILE"
    netstat -tuln | tee -a "$REPORT_FILE"

    # Check for IP forwarding
    echo "[+] Checking IP forwarding:" | tee -a "$REPORT_FILE"
    sysctl net.ipv4.ip_forward | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"
}

# Section 5: IP and Network Configuration Checks
ip_network_config_checks() {
    echo "===== IP and Network Configuration Checks =====" | tee -a "$REPORT_FILE"

    # Public vs Private IP Checks
    echo "[+] Identifying public and private IPs:" | tee -a "$REPORT_FILE"
    ip addr show | tee -a "$REPORT_FILE"

    # Ensure no sensitive services are exposed on public IP
    echo "[+] Checking for exposed services on public IPs:" | tee -a "$REPORT_FILE"
    if [ "$(hostname -I)" != "" ]; then
        for ip in $(hostname -I); do
            if [[ "$ip" == 10.* || "$ip" == 172.* || "$ip" == 192.* ]]; then
                echo "$ip is a private IP" | tee -a "$REPORT_FILE"
            else
                echo "$ip is a public IP" | tee -a "$REPORT_FILE"
                # Check if SSH is exposed
                nc -zv -w3 "$ip" 22 2>&1 | tee -a "$REPORT_FILE"
            fi
        done
    fi
    echo "" | tee -a "$REPORT_FILE"
}

# Section 6: Security Updates and Patching
security_updates() {
    echo "===== Security Updates and Patching =====" | tee -a "$REPORT_FILE"

    # Check for available updates
    echo "[+] Checking for available updates:" | tee -a "$REPORT_FILE"
    apt update && apt list --upgradable | tee -a "$REPORT_FILE"

    # Ensure automatic updates are configured
    echo "[+] Checking automatic updates configuration:" | tee -a "$REPORT_FILE"
    if systemctl is-active --quiet unattended-upgrades; then
        echo "Unattended upgrades is active." | tee -a "$REPORT_FILE"
    else
        echo "Unattended upgrades is inactive." | tee -a "$REPORT_FILE"
    fi
    echo "" | tee -a "$REPORT_FILE"
}

# Section 7: Log Monitoring
log_monitoring() {
    echo "===== Log Monitoring =====" | tee -a "$REPORT_FILE"

    # Check for suspicious log entries
    echo "[+] Checking SSH login attempts:" | tee -a "$REPORT_FILE"
    grep "Failed password" /var/log/auth.log | tee -a "$REPORT_FILE"

    # Report any suspicious entries
    echo "[+] Checking for unusual log entries:" | tee -a "$REPORT_FILE"
    grep "error" /var/log/syslog | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"
}

# Section 8: Server Hardening Steps
server_hardening() {
    echo "===== Server Hardening Steps =====" | tee -a "$REPORT_FILE"

    # SSH Configuration: Disable password-based login
    echo "[+] SSH Configuration - Disabling Password Authentication" | tee -a "$REPORT_FILE"
    sed -i '/^PasswordAuthentication/ s/yes/no/' /etc/ssh/sshd_config
    sed -i '/^PermitRootLogin/ s/yes/no/' /etc/ssh/sshd_config
    systemctl restart sshd

    # GRUB Password Setup
    set_grub_password

    # Disable IPv6 (if not required)
    echo "[+] Disabling IPv6 (if not required):" | tee -a "$REPORT_FILE"
    sysctl net.ipv6.conf.all.disable_ipv6=1
    sysctl net.ipv6.conf.default.disable_ipv6=1
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf

    # Configure firewall
    echo "[+] Configuring Firewall Rules (iptables/ufw)" | tee -a "$REPORT_FILE"
    ufw default deny incoming
    ufw default allow outgoing
    ufw enable

    # Configure automatic updates
    echo "[+] Enabling Automatic Security Updates" | tee -a "$REPORT_FILE"
    apt install unattended-upgrades
    dpkg-reconfigure --priority=low unattended-upgrades

    echo "" | tee -a "$REPORT_FILE"
}

# Section 9: Custom Security Checks
custom_security_checks() {
    echo "===== Custom Security Checks =====" | tee -a "$REPORT_FILE"
    # Custom checks based on your organization's requirements can be added here
    echo "[+] Custom checks can be added here." | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"
}

# Section 10: Reporting and Email Alerts
send_email_report() {
    echo "===== Sending Email Report =====" | tee -a "$REPORT_FILE"

    # Ask for email address
    echo "Enter the email address to send the report to:"
    read -r email_address

    # Use mail command to send the report
    mail -s "Security Audit Report" "$email_address" < "$REPORT_FILE"

    echo "[+] Report sent to $email_address" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"
}

# Main script execution
write_header
user_group_audits
file_permissions
service_audits
firewall_network_security
ip_network_config_checks
security_updates
log_monitoring
server_hardening
custom_security_checks
send_email_report

echo "Security audit and hardening completed. Report is saved to $REPORT_FILE."
