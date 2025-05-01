#!/bin/bash

# Secure error handling
set -euo pipefail
IFS=$'\n\t'

# Configuration
REPORT="security_audit_report.txt"
LOG_DIR="/var/log"
IMPORTANT_SERVICES=("sshd" "nginx" "apache2" "iptables" "ufw")
CRITICAL_PORTS=(22 80 443)

# Initialize report
: > "$REPORT"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Helper functions
log() {
    local level="$1"
    local message="$2"
    local color=""
    
    case "$level" in
        "INFO") color="$BLUE" ;;
        "WARNING") color="$YELLOW" ;;
        "ERROR") color="$RED" ;;
        "SUCCESS") color="$GREEN" ;;
    esac
    
    echo -e "${color}[$level] $message${NC}"
    echo "[$level] $message" >> "$REPORT"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log "ERROR" "This script must be run as root"
        exit 1
    fi
}

section_header() {
    local title="$1"
    local line="================================================================"
    echo -e "\n${BLUE}$line\n$title\n$line${NC}"
    echo -e "\n$line\n$title\n$line" >> "$REPORT"
}

# User and Group Audit
audit_users() {
    section_header "USER AND GROUP AUDIT"
    
    # Check root users
    log "INFO" "Checking for users with root privileges..."
    local root_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)
    if [[ $(echo "$root_users" | wc -l) -gt 1 ]]; then
        log "WARNING" "Multiple users found with UID 0:"
        echo "$root_users" | while read -r user; do
            log "WARNING" "Root user: $user"
        done
    fi
    
    # Check password policies
    log "INFO" "Checking password policies..."
    local weak_pass=$(awk -F: '($2 == "" || $2 == "*" || $2 == "!") {print $1}' /etc/shadow)
    if [[ -n "$weak_pass" ]]; then
        log "WARNING" "Users with weak/no password:"
        echo "$weak_pass"
    fi
    
    # Check sudo access
    log "INFO" "Checking sudo access..."
    local sudo_users=$(getent group sudo | cut -d: -f4)
    log "INFO" "Users with sudo access: $sudo_users"
}

# File System Security
audit_filesystem() {
    section_header "FILE SYSTEM SECURITY"
    
    # World-writable files
    log "INFO" "Checking for world-writable files..."
    find / -type f -perm -0002 -exec ls -l {} \; 2>/dev/null | while read -r file; do
        log "WARNING" "World-writable file found: $file"
    done
    
    # SUID/SGID files
    log "INFO" "Checking for SUID/SGID files..."
    find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null | while read -r file; do
        log "WARNING" "SUID/SGID file found: $file"
    done
    
    # SSH directory permissions
    log "INFO" "Checking SSH directory permissions..."
    find /home -name ".ssh" -type d -exec ls -ld {} \; 2>/dev/null | while read -r dir; do
        if [[ $(stat -c %a "$dir") != "700" ]]; then
            log "ERROR" "Insecure SSH directory permissions: $dir"
        fi
    done
}

# Network Security
audit_network() {
    section_header "NETWORK SECURITY"
    
    # Check listening ports
    log "INFO" "Checking listening ports..."
    netstat -tuln | grep LISTEN | while read -r line; do
        log "INFO" "Open port: $line"
    done
    
    # Check firewall status
    log "INFO" "Checking firewall status..."
    if command -v ufw >/dev/null 2>&1; then
        if ufw status | grep -q "Status: active"; then
            log "SUCCESS" "UFW is active"
        else
            log "ERROR" "UFW is not active"
        fi
    elif command -v iptables >/dev/null 2>&1; then
        if iptables -L | grep -q "Chain"; then
            log "SUCCESS" "IPTables rules exist"
        else
            log "ERROR" "No IPTables rules found"
        fi
    else
        log "ERROR" "No firewall found"
    fi
}

# Service Security
audit_services() {
    section_header "SERVICE SECURITY"
    
    for service in "${IMPORTANT_SERVICES[@]}"; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            log "SUCCESS" "Service $service is running"
        else
            log "WARNING" "Service $service is not running"
        fi
    done
}

# System Updates
check_updates() {
    section_header "SYSTEM UPDATES"
    
    if command -v apt-get >/dev/null 2>&1; then
        log "INFO" "Checking for updates (Debian/Ubuntu)..."
        apt-get update >/dev/null 2>&1
        local updates=$(apt-get -s upgrade | grep -P "^Inst" | wc -l)
        log "INFO" "$updates updates available"
    elif command -v yum >/dev/null 2>&1; then
        log "INFO" "Checking for updates (RHEL/CentOS)..."
        local updates=$(yum check-update --quiet | grep -v "^$" | wc -l)
        log "INFO" "$updates updates available"
    fi
}

# IP Configuration
check_ip_config() {
    section_header "IP CONFIGURATION"
    
    log "INFO" "Checking IP addresses..."
    ip addr show | grep "inet " | while read -r line; do
        local ip=$(echo "$line" | awk '{print $2}')
        if [[ $ip =~ ^(192\.168|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.) ]]; then
            log "INFO" "Private IP found: $ip"
        else
            log "WARNING" "Public IP found: $ip"
        fi
    done
}

# Main execution
main() {
    check_root
    
    log "INFO" "Starting security audit..."
    date "+%Y-%m-%d %H:%M:%S" >> "$REPORT"
    
    audit_users
    audit_filesystem
    audit_network
    audit_services
    check_updates
    check_ip_config
    
    log "SUCCESS" "Security audit completed. Report saved to $REPORT"
}

main "$@"
