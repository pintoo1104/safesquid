#!/bin/bash

# ===== CONFIGURATION =====
TIMESTAMP=$(date +%F_%H-%M-%S)
REPORT_FILE="$(pwd)/security_audit_report_$TIMESTAMP.txt"
CUSTOM_CHECKS_FILE="custom_checks.sh"

# ===== COLORS =====
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
NC="\033[0m"

# ===== FUNCTIONS =====
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

function install_if_missing() {
    local pkg=$1
    if ! command -v "$pkg" &>/dev/null; then
        echo "Installing $pkg..." | tee -a "$REPORT_FILE"
        apt-get update -qq && apt-get install -y "$pkg"
    else
        status "$pkg is already installed."
    fi
}

# ===== SECTION 1: USER AND GROUP AUDITS =====
header "Section 1: User and Group Audits"
cut -d: -f1 /etc/passwd | tee -a "$REPORT_FILE"
cut -d: -f1 /etc/group | tee -a "$REPORT_FILE"

uid0_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)
echo -e "\nUsers with UID 0: $uid0_users" | tee -a "$REPORT_FILE"

install_if_missing "john"
install_if_missing "unshadow"
unshadow /etc/passwd /etc/shadow > /tmp/john_shadow_combined 2>/dev/null
john /tmp/john_shadow_combined --show | tee -a "$REPORT_FILE"

# ===== SECTION 2: FILE AND DIRECTORY PERMISSIONS =====
header "Section 2: File and Directory Permissions"
find / -xdev -type f -perm -0002 2>/dev/null | tee -a "$REPORT_FILE"
find /home -name .ssh -exec ls -ld {} + 2>/dev/null | tee -a "$REPORT_FILE"
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | tee -a "$REPORT_FILE"

# ===== SECTION 3: SERVICE AUDITS =====
header "Section 3: Service Audits"
systemctl list-units --type=service --state=running | tee -a "$REPORT_FILE"
systemctl list-unit-files --type=service | grep enabled | tee -a "$REPORT_FILE"
ss -tuln | tee -a "$REPORT_FILE"

# ===== SECTION 4: FIREWALL AND NETWORK SECURITY =====
header "Section 4: Firewall and Network Security"
install_if_missing "ufw"
ufw status verbose 2>/dev/null | tee -a "$REPORT_FILE"
lsof -i -P -n | grep LISTEN | tee -a "$REPORT_FILE"
cat /proc/sys/net/ipv4/ip_forward | tee -a "$REPORT_FILE"

# ===== SECTION 5: IP AND NETWORK CONFIGURATION =====
header "Section 5: IP and Network Configuration"
ip -4 addr show | grep inet | tee -a "$REPORT_FILE"
ip -6 addr show | grep inet6 | tee -a "$REPORT_FILE"
hostname -I | tee -a "$REPORT_FILE"

pub_ip=$(curl -s ifconfig.me)
if [[ "$pub_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    warning "Public IP detected: $pub_ip"
fi

# ===== SECTION 6: SECURITY UPDATES AND PATCHING =====
header "Section 6: Security Updates"
apt update -qq && apt list --upgradable 2>/dev/null | tee -a "$REPORT_FILE"
install_if_missing "unattended-upgrades"

# ===== SECTION 7: LOG MONITORING =====
header "Section 7: Log Monitoring"
tail -n 50 /var/log/auth.log | grep sshd | tee -a "$REPORT_FILE"

# ===== SECTION 8: HARDENING: SSH, IPV6, GRUB =====
header "Section 8: Hardening Measures"

echo -e "\nSSH Hardening..." | tee -a "$REPORT_FILE"
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd
status "SSH config hardened."

echo -e "\nIPv6 Disabling..." | tee -a "$REPORT_FILE"
sysctl_file="/etc/sysctl.d/99-ipv6-disable.conf"
echo -e "net.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1" > "$sysctl_file"
sysctl -p "$sysctl_file" | tee -a "$REPORT_FILE"

# GRUB PASSWORD SETUP (with expect)
header "GRUB Password Setup"

install_if_missing "expect"
read -sp "Enter GRUB password: " grub_pw
echo
read -sp "Re-enter GRUB password: " grub_pw2
echo

if [[ "$grub_pw" == "$grub_pw2" ]]; then
    GRUB_HASH=$(expect -c "
    spawn grub-mkpasswd-pbkdf2
    expect \"Enter password:\"
    send \"$grub_pw\r\"
    expect \"Reenter password:\"
    send \"$grub_pw\r\"
    expect eof
    " | grep -oP '(?<=password_pbkdf2 ).*')

    if ! grep -q "password_pbkdf2 root" /etc/grub.d/40_custom; then
        echo -e "set superusers=\"root\"\npassword_pbkdf2 root $GRUB_HASH" >> /etc/grub.d/40_custom
        update-grub
        status "GRUB password set successfully."
    else
        warning "GRUB password already configured. Skipping."
    fi
else
    error "Passwords did not match. GRUB password not set."
fi

# ===== SECTION 9: CUSTOM SECURITY CHECKS =====
header "Section 9: Custom Security Checks"
if [[ -f "$CUSTOM_CHECKS_FILE" ]]; then
    bash "$CUSTOM_CHECKS_FILE" | tee -a "$REPORT_FILE"
else
    warning "Custom checks file not found: $CUSTOM_CHECKS_FILE"
fi

# ===== SECTION 10: REPORTING & EMAIL =====
header "Section 10: Reporting & Email"
read -p "Enter email address to send report: " EMAIL_ADDR
install_if_missing "mailutils"

mail -s "Security Audit Report - $HOSTNAME" "$EMAIL_ADDR" < "$REPORT_FILE"
status "Report sent to $EMAIL_ADDR"

header "Audit Completed - Report saved to $REPORT_FILE"
