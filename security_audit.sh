#!/bin/bash

# Define the report file path
REPORT_FILE="./security_audit_report.txt"

# Function to log messages to both console and report file
log_message() {
    echo "$1" | tee -a "$REPORT_FILE"
}

# Function for User and Group Audits
user_group_audit() {
    log_message "[+] User and Group Audit started..."
    # List all users and groups on the server
    log_message "[*] List of users and groups:"
    cut -d: -f1 /etc/passwd >> "$REPORT_FILE"
    log_message "[*] Checking for root users with UID 0..."
    grep 'x:0' /etc/passwd >> "$REPORT_FILE"
    log_message "[*] Checking for weak passwords..."
    # Install John the Ripper for weak password detection
    if ! command -v john &>/dev/null; then
        log_message "[*] Installing John the Ripper for password check..."
        apt-get install -y john
    fi
    # Password strength check (you can customize this part)
    john --list=passwords /etc/shadow >> "$REPORT_FILE"
    log_message "[+] User and Group Audit completed."
}

# Function for File and Directory Permissions
file_permissions() {
    log_message "[+] File and Directory Permissions Audit started..."
    # Scan for world-writable files
    log_message "[*] Checking for world-writable files and directories..."
    find / -xdev -type f -perm -002 >> "$REPORT_FILE"
    find / -xdev -type d -perm -002 >> "$REPORT_FILE"
    log_message "[*] Checking for SUID and SGID files..."
    find / -xdev \( -perm -4000 -o -perm -2000 \) >> "$REPORT_FILE"
    log_message "[*] Checking .ssh directory permissions..."
    find / -type d -name .ssh -exec ls -ld {} \; >> "$REPORT_FILE"
    log_message "[+] File and Directory Permissions Audit completed."
}

# Function for Service Audits
service_audit() {
    log_message "[+] Service Audit started..."
    # List running services
    log_message "[*] Running services:"
    service --status-all >> "$REPORT_FILE"
    log_message "[*] Checking for critical services like sshd and iptables..."
    systemctl status sshd >> "$REPORT_FILE"
    systemctl status iptables >> "$REPORT_FILE"
    log_message "[*] Checking for unauthorized services..."
    # Replace this with your list of essential services
    critical_services=("sshd" "iptables")
    for service in "${critical_services[@]}"; do
        if ! systemctl is-active --quiet "$service"; then
            log_message "[!] WARNING: $service is not running!" >> "$REPORT_FILE"
        fi
    done
    log_message "[+] Service Audit completed."
}

# Function for Firewall and Network Security
firewall_network_security() {
    log_message "[+] Firewall and Network Security Audit started..."
    # Check for active firewall
    ufw_status=$(ufw status verbose)
    log_message "[*] Checking firewall status: $ufw_status"
    echo "$ufw_status" >> "$REPORT_FILE"
    log_message "[*] Checking for open ports and associated services..."
    netstat -tuln >> "$REPORT_FILE"
    log_message "[+] Firewall and Network Security Audit completed."
}

# Function for Security Updates and Patching
security_updates() {
    log_message "[+] Checking for security updates..."
    # Check for available security updates
    apt list --upgradable >> "$REPORT_FILE"
    log_message "[+] Checking for automatic updates..."

    # Ensure automatic updates are enabled without interaction
    apt-get install -y unattended-upgrades

    # Configure automatic updates to avoid interactive prompts
    dpkg-reconfigure --priority=low unattended-upgrades > /dev/null 2>&1

    # Ensure automatic updates are enabled in the configuration
    log_message "[+] Enabling automatic updates..."
    echo 'Unattended-Upgrade::Automatic-Reboot "true";' >> /etc/apt/apt.conf.d/50unattended-upgrades
    echo 'APT::Periodic::Update-Package-Lists "1";' >> /etc/apt/apt.conf.d/10periodic
    echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/10periodic
    echo 'APT::Periodic::AutocleanInterval "7";' >> /etc/apt/apt.conf.d/10periodic

    log_message "[+] Automatic updates configured successfully."
}

# Function for IP and Network Configuration Checks
network_config_check() {
    log_message "[+] IP and Network Configuration Check started..."
    # Identify public and private IP addresses
    ip_addresses=$(hostname -I)
    log_message "[*] IP addresses on this system: $ip_addresses"
    for ip in $ip_addresses; do
        if [[ "$ip" =~ ^10\. || "$ip" =~ ^172\.16\. || "$ip" =~ ^192\.168\. ]]; then
            log_message "[*] Private IP: $ip"
        else
            log_message "[*] Public IP: $ip"
        fi
    done
    log_message "[+] IP and Network Configuration Check completed."
}

# Function for SSH Configuration (Key-based Authentication)
ssh_configuration() {
    log_message "[+] SSH Configuration started..."
    # Disable root login and password authentication
    sed -i '/^PermitRootLogin/s/yes/no/' /etc/ssh/sshd_config
    sed -i '/^PasswordAuthentication/s/yes/no/' /etc/ssh/sshd_config
    systemctl restart sshd
    log_message "[+] SSH configuration updated."
}

# Function to Set GRUB Password (Manual Configuration)
set_grub_password() {
    log_message "[+] WARNING: GRUB password must be set manually."
    log_message "[*] Please configure a GRUB password manually to secure bootloader."
    log_message "[*] You can follow these steps: https://www.digitalocean.com/community/tutorials/how-to-set-up-grub-passwords-on-ubuntu-18-04"
}

# Main Execution Flow
main() {
    log_message "[+] Security Audit Script Started..."

    # Call functions in the required order
    user_group_audit
    file_permissions
    service_audit
    firewall_network_security
    security_updates
    network_config_check
    ssh_configuration
    set_grub_password

    log_message "[+] Security Audit Script Completed."

    # Send the report via email
    send_report_email
}

# Function to send report via email (if required)
send_report_email() {
    read -p "Enter the email address to send the report to: " email
    mail -s "Security Audit Report" "$email" < "$REPORT_FILE"
    log_message "[+] Report sent to $email."
}

# Start the script
main
