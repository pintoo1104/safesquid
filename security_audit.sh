#!/bin/bash

# Set the report file
REPORT_FILE="./security_audit_report.txt"

# Create or clear the report file
echo "Security Audit and Hardening Report" > "$REPORT_FILE"
echo "===============================" >> "$REPORT_FILE"
echo "Date: $(date)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Function for User and Group Audits
user_and_group_audit() {
    echo "[+] Performing user and group audit..." | tee -a "$REPORT_FILE"

    # List all users and groups
    echo "List of users and groups on the system:" >> "$REPORT_FILE"
    cat /etc/passwd >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    # Check for users with UID 0 (root privileges)
    echo "Users with UID 0 (root privileges):" >> "$REPORT_FILE"
    awk -F: '($3 == 0) {print $1}' /etc/passwd >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    # Check for users without passwords or with weak passwords
    echo "Users without passwords or with weak passwords:" >> "$REPORT_FILE"
    awk -F: '($2 == "") {print $1}' /etc/passwd >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
}

# Function for File and Directory Permissions
file_and_directory_permissions() {
    echo "[+] Checking file and directory permissions..." | tee -a "$REPORT_FILE"

    # Scan for files and directories with world-writable permissions
    echo "Files and directories with world-writable permissions:" >> "$REPORT_FILE"
    find / -xdev -type f -perm -0002 -exec ls -l {} \; >> "$REPORT_FILE"
    find / -xdev -type d -perm -0002 -exec ls -ld {} \; >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    # Check for the presence of .ssh directories with secure permissions
    echo "Checking .ssh directories for proper permissions:" >> "$REPORT_FILE"
    find / -name ".ssh" -exec ls -ld {} \; >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    # Report any files with SUID or SGID bits set
    echo "Files with SUID or SGID bits set:" >> "$REPORT_FILE"
    find / -xdev \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
}

# Function for Service Audits
service_audit() {
    echo "[+] Performing service audit..." | tee -a "$REPORT_FILE"

    # List all running services
    echo "List of running services:" >> "$REPORT_FILE"
    service --status-all >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    # Check for critical services (e.g., sshd, iptables)
    echo "Ensuring critical services are running (e.g., sshd, iptables)..." >> "$REPORT_FILE"
    systemctl is-active sshd >> "$REPORT_FILE"
    systemctl is-active iptables >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    # Check for services listening on non-standard ports
    echo "Services listening on non-standard ports:" >> "$REPORT_FILE"
    netstat -tulnp | grep -v ":22" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
}

# Function for Firewall and Network Security
firewall_and_network_security() {
    echo "[+] Checking firewall and network security..." | tee -a "$REPORT_FILE"

    # Check if a firewall is active
    echo "Checking firewall status..." >> "$REPORT_FILE"
    ufw status verbose >> "$REPORT_FILE"
    iptables -L >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    # Report any open ports and their associated services
    echo "Open ports and their associated services:" >> "$REPORT_FILE"
    netstat -tuln >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    # Check for IP forwarding
    echo "Checking for IP forwarding configuration..." >> "$REPORT_FILE"
    sysctl net.ipv4.ip_forward >> "$REPORT_FILE"
    sysctl net.ipv6.conf.all.forwarding >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
}

# Function for IP and Network Configuration Checks
ip_and_network_config_check() {
    echo "[+] Performing IP and Network Configuration Checks..." | tee -a "$REPORT_FILE"

    # Public vs Private IP Checks
    echo "Identifying public vs private IP addresses..." >> "$REPORT_FILE"
    ip addr show >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    # Check sensitive services exposure on public IPs (SSH)
    echo "Checking SSH exposure on public IPs..." >> "$REPORT_FILE"
    netstat -tuln | grep :22 >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
}

# Function for Security Updates and Patching
security_updates() {
    echo "[+] Checking for security updates..." | tee -a "$REPORT_FILE"

    # Check for available security updates
    echo "Checking for available security updates..." >> "$REPORT_FILE"
    apt list --upgradable >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    # Ensure automatic updates are enabled
    echo "Ensuring automatic updates are enabled..." >> "$REPORT_FILE"
    dpkg-reconfigure --priority=low unattended-upgrades
    echo "" >> "$REPORT_FILE"
}

# Function for Log Monitoring
log_monitoring() {
    echo "[+] Performing log monitoring..." | tee -a "$REPORT_FILE"

    # Check for suspicious login attempts
    echo "Checking for suspicious login attempts..." >> "$REPORT_FILE"
    grep "Failed password" /var/log/auth.log >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
}

# Function for SSH Configuration (Hardening)
ssh_configuration() {
    echo "[+] Hardening SSH configuration..." | tee -a "$REPORT_FILE"

    # Disable password-based login for root
    echo "Disabling root password login for SSH..." >> "$REPORT_FILE"
    sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

    # Ensure key-based authentication is enabled
    echo "Ensuring key-based authentication for SSH..." >> "$REPORT_FILE"
    sed -i 's/^#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config

    # Restart SSH service to apply changes
    systemctl restart sshd
    echo "[+] SSH configuration hardened successfully." | tee -a "$REPORT_FILE"
}

# Function for GRUB Password Setup
set_grub_password() {
    echo "[+] Setting up GRUB password..." | tee -a "$REPORT_FILE"

    # Prompt user for a password for GRUB
    echo "Enter the password for GRUB (this will be hashed and set):"
    read -s grub_password

    # Generate the hashed password for GRUB
    grub_password_hash=$(grub-mkpasswd-pbkdf2 <<< "$grub_password" | grep -oP "(?<=password_pbkdf2 ).*" | tee -a "$REPORT_FILE")

    # Check if the GRUB password hash is generated successfully
    if [ -z "$grub_password_hash" ]; then
        echo "[!] Failed to generate the GRUB password hash." | tee -a "$REPORT_FILE"
        exit 1
    fi

    # Edit GRUB configuration to add password
    echo "[+] Configuring GRUB to use the password" | tee -a "$REPORT_FILE"
    echo "set superusers="root"" >> /etc/grub.d/40_custom
    echo "password_pbkdf2 root $grub_password_hash" >> /etc/grub.d/40_custom

    # Update GRUB to apply changes
    update-grub

    echo "[+] GRUB password set successfully." | tee -a "$REPORT_FILE"
}

# Call the functions
user_and_group_audit
file_and_directory_permissions
service_audit
firewall_and_network_security
ip_and_network_config_check
security_updates
log_monitoring
ssh_configuration
set_grub_password

# Notify user
echo "[+] Security audit and hardening completed. Report saved to $REPORT_FILE"
