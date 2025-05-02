#!/bin/bash

# Global Variables
REPORT_DIR="$(pwd)/security_audit_report"
REPORT_FILE="$REPORT_DIR/security_audit_$(date +'%Y-%m-%d_%H-%M-%S').txt"
EMAIL=""
SMTP_SERVER="smtp.gmail.com"
SMTP_PORT="587"
FROM_EMAIL="<your-email>@gmail.com"
FROM_PASSWORD="<your-password>"

# Function to print and log messages
log_msg() {
  echo "[INFO] $1"
  echo "[INFO] $1" >> "$REPORT_FILE"
}

# Create report directory if not exists
mkdir -p "$REPORT_DIR"

# Section 1: User and Group Audits
audit_users_and_groups() {
  log_msg "Starting User and Group Audits..."

  # List all users and groups
  log_msg "Listing all users and groups:"
  cut -d: -f1 /etc/passwd >> "$REPORT_FILE"

  # Check for users with UID 0 (root privileges)
  log_msg "Checking for users with UID 0 (root privileges):"
  awk -F: '$3 == 0 {print $1}' /etc/passwd >> "$REPORT_FILE"

  # Check for users with weak or no passwords
  log_msg "Checking for users with weak or no passwords..."
  while IFS=: read -r username _ _ _ _ _; do
    passwd -S "$username" | grep -E 'NP|L' && echo "Weak or no password: $username" >> "$REPORT_FILE"
  done < /etc/passwd
}

# Section 2: File and Directory Permissions
audit_file_permissions() {
  log_msg "Starting File and Directory Permissions Audit..."

  # Scan for world-writable files and directories
  log_msg "Scanning for world-writable files and directories:"
  find / -type f -perm -0002 -exec ls -l {} \; >> "$REPORT_FILE"

  # Check for .ssh directories and their permissions
  log_msg "Checking for .ssh directories and permissions:"
  find / -type d -name '.ssh' -exec ls -ld {} \; >> "$REPORT_FILE"

  # Check for SUID/SGID bits on executables
  log_msg "Checking for files with SUID/SGID bits set:"
  find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; >> "$REPORT_FILE"
}

# Section 3: Service Audits
audit_services() {
  log_msg "Starting Service Audits..."

  # List running services
  log_msg "Listing running services:"
  systemctl list-units --type=service --state=running >> "$REPORT_FILE"

  # Check for critical services and unauthorized services
  log_msg "Checking for unauthorized services and critical service status..."
  for service in sshd iptables; do
    systemctl status "$service" >> "$REPORT_FILE" || echo "$service is not running!" >> "$REPORT_FILE"
  done
}

# Section 4: Firewall and Network Security
audit_firewall_network() {
  log_msg "Starting Firewall and Network Security Audit..."

  # Check if firewall is active
  log_msg "Checking if firewall is active:"
  systemctl is-active --quiet ufw && echo "Firewall is active" >> "$REPORT_FILE" || echo "Firewall is inactive" >> "$REPORT_FILE"

  # Report open ports and services
  log_msg "Reporting open ports and associated services:"
  netstat -tuln >> "$REPORT_FILE"

  # Check for IP forwarding
  log_msg "Checking for IP forwarding:"
  sysctl net.ipv4.ip_forward >> "$REPORT_FILE"
}

# Section 5: IP and Network Configuration Checks
audit_ip_configuration() {
  log_msg "Starting IP and Network Configuration Audit..."

  # Check for public vs private IP addresses
  log_msg "Checking for public vs private IP addresses:"
  ip a | grep inet >> "$REPORT_FILE"

  # Check if SSH is exposed on public IPs
  log_msg "Checking if SSH is exposed on public IPs:"
  ip a | grep inet | grep -E 'inet (.*)' >> "$REPORT_FILE"
}

# Section 6: Security Updates and Patching
audit_security_updates() {
  log_msg "Starting Security Updates Audit..."

  # Check for available updates
  log_msg "Checking for available security updates:"
  apt-get update && apt-get upgrade -s | grep ^Inst >> "$REPORT_FILE"

  # Ensure unattended-upgrades is enabled
  log_msg "Checking if unattended-upgrades is enabled:"
  systemctl is-enabled unattended-upgrades >> "$REPORT_FILE"
}

# Section 7: Log Monitoring
audit_logs() {
  log_msg "Starting Log Monitoring..."

  # Check for suspicious log entries (e.g., failed SSH logins)
  log_msg "Checking for suspicious log entries:"
  grep "Failed password" /var/log/auth.log >> "$REPORT_FILE"
}

# Section 8: SSH Configuration Hardening
audit_ssh_hardening() {
  log_msg "Starting SSH Configuration Hardening..."

  # Disable root login and password authentication
  log_msg "Disabling root login and password authentication for SSH:"
  sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
  sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
  systemctl restart sshd
}

# Section 9: GRUB Password
# Manual intervention: Setting GRUB password
set_grub_password() {
  log_msg "WARNING: You must manually set the GRUB password for bootloader protection."
  echo "To set the GRUB password, follow these steps:" >> "$REPORT_FILE"
  echo "1. Edit /etc/grub.d/40_custom and add the password." >> "$REPORT_FILE"
  echo "2. Run 'sudo grub-mkconfig -o /boot/grub/grub.cfg'." >> "$REPORT_FILE"
}

# Section 10: Sending Report via Email
send_email_report() {
  log_msg "Sending email report..."

  # Prompt for email
  if [ -z "$EMAIL" ]; then
    read -p "Enter the email address to send the report to: " EMAIL
  fi

  # Send the report via email
  cat "$REPORT_FILE" | mail -s "Security Audit Report" "$EMAIL"
}

# Run All Functions
audit_users_and_groups
audit_file_permissions
audit_services
audit_firewall_network
audit_ip_configuration
audit_security_updates
audit_logs
audit_ssh_hardening
set_grub_password
send_email_report

log_msg "Security audit and hardening completed successfully. Report saved in: $REPORT_FILE"
