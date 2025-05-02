#!/bin/bash

# ===== CONFIGURATION =====
REPORT_FILE="$(pwd)/security_audit_report_$(date +%F_%T).txt"
CUSTOM_CHECKS_FILE="custom_checks.sh"
CONFIG_FILE="config.cfg"

# ===== COLORS =====
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
NC="\033[0m"

function header() {
    echo -e "\n${BLUE}========== $1 ==========${NC}" | tee -a "$REPORT_FILE"
}

function status() {
    echo -e "${GREEN}[OK]${NC} $1" | tee -a "$REPORT_FILE"
}

function warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$REPORT_FILE"
}

function error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$REPORT_FILE"
}

# ===== SECTION 1: USER AND GROUP AUDITS =====
header "Section 1: User and Group Audits"
echo "Users:" | tee -a "$REPORT_FILE"
cut -d: -f1 /etc/passwd | tee -a "$REPORT_FILE"
echo -e "\nGroups:" | tee -a "$REPORT_FILE"
cut -d: -f1 /etc/group | tee -a "$REPORT_FILE"

uid0_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)
echo -e "\nUsers with UID 0: $uid0_users" | tee -a "$REPORT_FILE"

weak_pass_tool="john"
if ! command -v $weak_pass_tool &>/dev/null; then
    echo "Installing $weak_pass_tool..." | tee -a "$REPORT_FILE"
    apt-get update && apt-get install -y john
else
    status "$weak_pass_tool already installed."
fi

unshadow /etc/passwd /etc/shadow > /tmp/john_shadow_combined
john /tmp/john_shadow_combined --show | tee -a "$REPORT_FILE"

# ===== SECTION 2: FILE AND DIRECTORY PERMISSIONS =====
header "Section 2: File and Directory Permissions"
echo "World-writable files:" | tee -a "$REPORT_FILE"
find / -xdev -type f -perm -0002 2>/dev/null | tee -a "$REPORT_FILE"
echo -e "\nSSH directory permissions:" | tee -a "$REPORT_FILE"
find /home -name .ssh -exec ls -ld {} + 2>/dev/null | tee -a "$REPORT_FILE"
echo -e "\nFiles with SUID/SGID:" | tee -a "$REPORT_FILE"
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | tee -a "$REPORT_FILE"

# ===== SECTION 3: SERVICE AUDITS =====
header "Section 3: Service Audits"
echo "Running services:" | tee -a "$REPORT_FILE"
systemctl list-units --type=service --state=running | tee -a "$REPORT_FILE"
echo -e "\nEnabled services:" | tee -a "$REPORT_FILE"
systemctl list-unit-files --type=service | grep enabled | tee -a "$REPORT_FILE"
echo -e "\nListening ports:" | tee -a "$REPORT_FILE"
ss -tuln | tee -a "$REPORT_FILE"

# ===== SECTION 4: FIREWALL AND NETWORK SECURITY =====
header "Section 4: Firewall and Network Security"
echo "Firewall status (ufw):" | tee -a "$REPORT_FILE"
ufw status verbose 2>/dev/null | tee -a "$REPORT_FILE"
echo -e "\nOpen ports:" | tee -a "$REPORT_FILE"
lsof -i -P -n | grep LISTEN | tee -a "$REPORT_FILE"
echo -e "\nIP forwarding status:" | tee -a "$REPORT_FILE"
cat /proc/sys/net/ipv4/ip_forward | tee -a "$REPORT_FILE"

# ===== SECTION 5: IP AND NETWORK CONFIGURATION CHECKS =====
header "Section 5: IP and Network Configuration"
ip -4 addr show | grep inet | tee -a "$REPORT_FILE"
ip -6 addr show | grep inet6 | tee -a "$REPORT_FILE"
echo -e "\nHostname IPs:" | tee -a "$REPORT_FILE"
hostname -I | tee -a "$REPORT_FILE"
echo -e "\nChecking for public IP exposure..." | tee -a "$REPORT_FILE"
if curl -s ifconfig.me | grep -qE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b'; then
    warning "Public IP detected: $(curl -s ifconfig.me)"
fi

# ===== SECTION 6: SECURITY UPDATES AND PATCHING =====
header "Section 6: Security Updates"
apt update -qq && apt list --upgradable 2>/dev/null | tee -a "$REPORT_FILE"
if ! dpkg -l | grep -q unattended-upgrades; then
    echo "Installing unattended-upgrades..." | tee -a "$REPORT_FILE"
    apt-get install -y unattended-upgrades
fi

# ===== SECTION 7: LOG MONITORING =====
header "Section 7: Log Monitoring"
echo "Recent suspicious SSH logins (last 50):" | tee -a "$REPORT_FILE"
tail -n 50 /var/log/auth.log | grep sshd | tee -a "$REPORT_FILE"

# ===== SECTION 8: SSH, BOOTLOADER, IPV6, FIREWALL HARDENING =====
header "Section 8: Server Hardening"
echo -e "\nSSH Config Changes:" | tee -a "$REPORT_FILE"
sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd
status "SSH hardening complete."

echo -e "\nDisabling IPv6:" | tee -a "$REPORT_FILE"
echo 'net.ipv6.conf.all.disable_ipv6 = 1' >> /etc/sysctl.conf
echo 'net.ipv6.conf.default.disable_ipv6 = 1' >> /etc/sysctl.conf
sysctl -p | tee -a "$REPORT_FILE"

echo -e "\nSetting GRUB password (manual step recommended)." | tee -a "$REPORT_FILE"
warning "You must manually configure /etc/grub.d/40_custom with a GRUB password."

# ===== SECTION 9: CUSTOM SECURITY CHECKS =====
header "Section 9: Custom Security Checks"
if [[ -f "$CUSTOM_CHECKS_FILE" ]]; then
    bash "$CUSTOM_CHECKS_FILE" | tee -a "$REPORT_FILE"
else
    warning "Custom checks file not found. Skipping."
fi

# ===== SECTION 10: REPORTING AND EMAIL =====
header "Section 10: Reporting and Email"
read -p "Enter email address to send report: " EMAIL_ADDR
if ! command -v mail &>/dev/null; then
    echo "Installing mailutils..." | tee -a "$REPORT_FILE"
    apt-get install -y mailutils
fi

mail -s "Security Audit Report" "$EMAIL_ADDR" < "$REPORT_FILE"
status "Email sent to $EMAIL_ADDR"

header "Audit Completed. Report saved to: $
