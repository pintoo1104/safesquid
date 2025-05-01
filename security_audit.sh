#!/bin/bash

# Secure error handling
#set -euo pipefail
IFS=$'\n\t'

# Configuration
REPORT="security_audit_report.txt"
IMPORTANT_SERVICES=("sshd" "iptables" "ufw" "nginx" "apache2")

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging
log() {
    local level="$1"
    local message="$2"
    local color="$NC"
    case "$level" in
        INFO) color="$BLUE" ;;
        WARNING) color="$YELLOW" ;;
        ERROR) color="$RED" ;;
        SUCCESS) color="$GREEN" ;;
    esac
    echo -e "${color}[$level] $message${NC}"
    echo "[$level] $message" >> "$REPORT"
}

# Section header
section() {
    local title="$1"
    echo -e "\n${BLUE}========== $title ==========${NC}\n" | tee -a "$REPORT"
}

# Root user check
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "This script must be run as root!"
        exit 1
    fi
}

# User and Group Audit
audit_users() {
    section "User and Group Audit"
    
    log "INFO" "Users with UID 0:"
    awk -F: '$3 == 0 {print $1}' /etc/passwd | tee -a "$REPORT"

    log "INFO" "Users with no/locked passwords:"
    awk -F: '($2 == "" || $2 ~ /^[*!]/) {print $1}' /etc/shadow | tee -a "$REPORT"

    log "INFO" "Users in sudo group:"
    getent group sudo | awk -F: '{print $4}' | tr ',' '\n' | tee -a "$REPORT"
}

# Filesystem permissions
audit_filesystem() {
    section "Filesystem Security"

    log "INFO" "World-writable files:"
    find / -type f -perm -0002 -not -path "/proc/*" 2>/dev/null | tee -a "$REPORT"

    log "INFO" "SUID/SGID files:"
    find / -type f \( -perm -4000 -o -perm -2000 \) -not -path "/proc/*" 2>/dev/null | tee -a "$REPORT"

    log "INFO" "Checking .ssh directory permissions:"
    find /home -type d -name ".ssh" 2>/dev/null | while read dir; do
        perms=$(stat -c %a "$dir")
        if [[ "$perms" != "700" ]]; then
            log "WARNING" "$dir has insecure permissions: $perms"
        fi
    done
}

# Services
audit_services() {
    section "Service Audit"
    for svc in "${IMPORTANT_SERVICES[@]}"; do
        if systemctl is-active --quiet "$svc"; then
            log "SUCCESS" "$svc is running"
        else
            log "WARNING" "$svc is NOT running"
        fi
    done
}

# Network Security
audit_network() {
    section "Firewall & Network Security"

    log "INFO" "Open ports:"
    if command -v ss &>/dev/null; then
        ss -tuln | grep LISTEN | tee -a "$REPORT"
    elif command -v netstat &>/dev/null; then
        netstat -tuln | grep LISTEN | tee -a "$REPORT"
    else
        log "ERROR" "Neither ss nor netstat found"
    fi

    log "INFO" "Firewall rules:"
    if command -v ufw &>/dev/null; then
        ufw status verbose | tee -a "$REPORT"
    elif command -v iptables &>/dev/null; then
        iptables -L -n -v | tee -a "$REPORT"
    else
        log "ERROR" "No firewall tool found"
    fi

    log "INFO" "Checking IP forwarding:"
    if [[ "$(sysctl -n net.ipv4.ip_forward)" == "1" ]]; then
        log "WARNING" "IPv4 forwarding is ENABLED"
    else
        log "SUCCESS" "IPv4 forwarding is DISABLED"
    fi
}

# IP Configuration
check_ip_config() {
    section "IP Configuration"

    ip -o -4 addr show | awk '{print $2, $4}' | while read iface ip; do
        ip_addr="${ip%%/*}"
        if [[ "$ip_addr" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])) ]]; then
            log "INFO" "Private IP on $iface: $ip_addr"
        else
            log "WARNING" "Public IP on $iface: $ip_addr"
        fi
    done
}

# Updates
check_updates() {
    section "Security Updates"

    if command -v apt &>/dev/null; then
        apt update -qq
        apt list --upgradable 2>/dev/null | grep -v "Listing..." | tee -a "$REPORT"
    elif command -v yum &>/dev/null; then
        yum check-update | tee -a "$REPORT"
    else
        log "ERROR" "Package manager not supported"
    fi
}

# SSH Hardening
harden_ssh() {
    section "SSH Hardening"

    SSH_CONF="/etc/ssh/sshd_config"
    if [[ -f "$SSH_CONF" ]]; then
        sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$SSH_CONF"
        sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' "$SSH_CONF"
        systemctl restart sshd
        log "SUCCESS" "SSH root login and password auth disabled"
    else
        log "ERROR" "SSH config file not found"
    fi
}

# Disable IPv6 (optional)
disable_ipv6() {
    section "IPv6 Disable Check"
    if [[ "$(sysctl -n net.ipv6.conf.all.disable_ipv6)" == "1" ]]; then
        log "SUCCESS" "IPv6 already disabled"
    else
        echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
        echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
        sysctl -p
        log "SUCCESS" "IPv6 disabled"
    fi
}

# GRUB Hardening (bootloader)
secure_grub() {
    section "Bootloader Hardening"

    # Check if grub-mkpasswd-pbkdf2 is available
    if ! command -v grub-mkpasswd-pbkdf2 &>/dev/null; then
        log "ERROR" "grub-mkpasswd-pbkdf2 command not found. Please install it to proceed."
        exit 1
    fi

    # Generate password hash
    PASSWORD_HASH=$(grub-mkpasswd-pbkdf2 | grep 'PBKDF2' | awk '{print $7}')
    
    if [[ -z "$PASSWORD_HASH" ]]; then
        log "ERROR" "Failed to generate GRUB password hash."
        exit 1
    fi

    GRUB_FILE="/etc/grub.d/40_custom"
    
    # Backup the current GRUB file
    cp "$GRUB_FILE" "$GRUB_FILE.bak"
    
    # Append password protection settings to the GRUB file
    echo "set superuser=\"admin\"" >> "$GRUB_FILE"
    echo "password_pbkdf2 admin $PASSWORD_HASH" >> "$GRUB_FILE"

    # Update GRUB configuration
    update-grub
    
    log "SUCCESS" "GRUB password set and configuration updated."
}

# Main
main() {
    check_root
    echo "" > "$REPORT"
    log "INFO" "Starting audit on $(hostname) at $(date)"

    audit_users
    audit_filesystem
    audit_services
    audit_network
    check_ip_config
    check_updates
    harden_ssh
    disable_ipv6
    secure_grub   # Uncomment if GRUB password hardening is required

    log "SUCCESS" "Security audit and hardening complete. Report saved to $REPORT"
}

main
