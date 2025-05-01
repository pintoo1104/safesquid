#!/bin/bash

# Function to print headers in the log
log() {
    local level="$1"
    local message="$2"
    echo "[$(date)] [$level] $message"
}

# Function to print section headers in the log
section() {
    local section_name="$1"
    log "INFO" "========== $section_name =========="
}

# User and Group Audits
user_group_audit() {
    section "User and Group Audits"
    
    # List all users and groups
    log "INFO" "Listing all users and groups..."
    cat /etc/passwd

    # Check for users with UID 0 (root privileges) and report any non-standard users
    log "INFO" "Checking for users with UID 0 (root privileges)..."
    awk -F: '$3 == 0 {print $1}' /etc/passwd

    # Identify and report any users without passwords or with weak passwords
    log "INFO" "Checking for users without passwords..."
    awk -F: '($2 == "" || $2 == "x") {print $1}' /etc/passwd
}

# File and Directory Permissions
file_permissions() {
    section "File and Directory Permissions"
    
    # Scan for files and directories with world-writable permissions
    log "INFO" "Scanning for world-writable files..."
    find / -type f -perm -0002 -exec ls -l {} \;

    # Check for the presence of .ssh directories and ensure they have secure permissions
    log "INFO" "Checking .ssh directories for secure permissions..."
    find / -type d -name ".ssh" -exec ls -ld {} \;

    # Report any files with SUID or SGID bits set
    log "INFO" "Checking for SUID/SGID files..."
    find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \;
}

# Service Audits
service_audit() {
    section "Service Audits"
    
    # List all running services and check for any unauthorized services
    log "INFO" "Listing all running services..."
    systemctl list-units --type=service --state=running

    # Ensure critical services are running (e.g., sshd, iptables)
    log "INFO" "Checking critical services (sshd, iptables)..."
    systemctl is-active sshd
    systemctl is-active iptables
}

# Firewall and Network Security
firewall_network_security() {
    section "Firewall and Network Security"
    
    # Verify that a firewall (e.g., iptables, ufw) is active and configured
    log "INFO" "Checking if firewall is active..."
    systemctl is-active ufw || systemctl is-active iptables

    # Report any open ports and their associated services
    log "INFO" "Listing open ports..."
    ss -tuln

    # Check for any IP forwarding or insecure network configurations
    log "INFO" "Checking for IP forwarding..."
    sysctl net.ipv4.ip_forward
}

# Public vs. Private IP Checks
public_private_ip_check() {
    section "IP and Network Configuration Checks"
    
    # Identify whether the server’s IP addresses are public or private
    log "INFO" "Identifying public and private IPs..."
    ip -o -4 addr show | awk '{print $2, $4}' | while read iface ip; do
        if [[ "$ip" =~ ^10\.|^172\.16\..*|^192\.168\..* ]]; then
            log "INFO" "$iface: Private IP - $ip"
        else
            log "INFO" "$iface: Public IP - $ip"
        fi
    done
}

# Security Updates and Patching
security_updates() {
    section "Security Updates and Patching"
    
    # Check for available security updates
    log "INFO" "Checking for available security updates..."
    apt update && apt list --upgradable

    # Ensure unattended-upgrades is configured for security updates
    log "INFO" "Checking if unattended-upgrades is enabled..."
    dpkg-query -l | grep unattended-upgrades
}

# Log Monitoring
log_monitoring() {
    section "Log Monitoring"
    
    # Check for suspicious log entries
    log "INFO" "Checking for suspicious log entries..."
    grep "Failed password" /var/log/auth.log
}

# SSH Configuration
ssh_configuration() {
    section "SSH Configuration"
    
    # Implement SSH key-based authentication and disable password-based login for root
    log "INFO" "Configuring SSH for key-based authentication and disabling password login for root..."
    sed -i 's/^PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
}

# Bootloader Hardening
secure_grub() {
    section "Bootloader Hardening"
    
    # Ensure a strong password is used (prompting for one if needed)
    read -sp "Enter password for GRUB bootloader: " grub_password
    echo

    # Generate PBKDF2 password hash for GRUB
    PASSWORD_HASH=$(grub-mkpasswd-pbkdf2 <<< "$grub_password" | grep 'PBKDF2' | awk '{print $7}')

    # Add password to GRUB configuration
    GRUB_FILE="/etc/grub.d/40_custom"
    
    # Add password hash to the grub configuration to secure bootloader
    echo "set superuser=\"admin\"" >> "$GRUB_FILE"
    echo "password_pbkdf2 admin $PASSWORD_HASH" >> "$GRUB_FILE"

    # Update GRUB to apply changes
    export DEBIAN_FRONTEND=noninteractive
    update-grub || log "ERROR" "Failed to update GRUB configuration"

    log "SUCCESS" "GRUB password set and bootloader secured"
}

# Automatic Updates Configuration
automatic_updates() {
    section "Automatic Updates"
    
    # Configure unattended-upgrades to automatically apply security updates
    log "INFO" "Configuring unattended-upgrades for automatic security updates..."
    apt install unattended-upgrades -y
    dpkg-reconfigure --priority=low unattended-upgrades
}

# Main function to execute the checks and harden the server
main() {
    # Run all the functions
    user_group_audit
    file_permissions
    service_audit
    firewall_network_security
    public_private_ip_check
    security_updates
    log_monitoring
    ssh_configuration
    secure_grub
    automatic_updates
}

# Run the main function
main
