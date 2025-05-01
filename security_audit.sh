#!/bin/bash

# Secure error handling
set -euo pipefail
IFS=$'\n\t'

# Configuration
REPORT="security_audit_report.txt"
LOG_DIR="/var/log"
IMPORTANT_SERVICES=("sshd" "nginx" "apache2" "iptables" "ufw")

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Initialize report
: > "$REPORT"

# Logging function
log() {
    local level="$1"
    local message="$2"
    local color=""
    case "$level" in
        INFO) color="$BLUE" ;;
        WARNING) color="$YELLOW" ;;
        ERROR) color="$RED" ;;
        SUCCESS) color="$GREEN" ;;
        *) color="$NC" ;;
    esac
    echo -e "${color}[$level] $message${NC}"
    echo "[$level] $message" >> "$REPORT"
}

# Root check
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        log "ERROR" "This script must be run as root."
        exit 1
    fi
}

# Section header
section_header() {
    local title="$1"
    local line="==================== $title ===================="
    echo -e "\n${BLUE}$line${NC}"
    echo -e "\n$line" >> "$REPORT"
}

# 1. Audit Users and Groups
audit_users() {
    section_header "USER AND GROUP AUDIT"

    # Root users
    log "INFO" "Checking users with UID 0..."
    awk -F: '$3 == 0 {print $1}' /etc/passwd | while read -r user; do
        log "WARNING" "Root-level user: $user"
    done

    # Weak passwords
    log "INFO" "Checking for users with empty/locked passwords..."
    awk -F: '($2 == "" || $2 == "!" || $2 == "*") {print $1}' /etc/shadow | while read -r user; do
        log "WARNING" "Weak/locked password: $user"
    done

    # Sudo users
    log "INFO" "Checking sudo access..."
    getent group sudo | cut -d: -f4 | tr ',' '\n' | while read -r user; do
        log "INFO" "Sudo user: $user"
    done
}

# 2. File System Security
audit_filesystem() {
    section_header "FILE SYSTEM SECURITY"

    # World-writable files
    log "INFO" "Scanning for world-writable files..."
    find / -type f -perm -0002 -not -path "/proc/*" 2>/dev/null | while read -r file; do
        log "WARNING" "World-writable file: $file"
    done

    # SUID/SGID files
    log "INFO" "Checking for SUID/SGID files..."
    find / -type f \( -perm -4000 -o -perm -2000 \) -not -path "/proc/*" 2>/dev/null | while read -r file; do
        log "WARNING" "SUID/SGID file: $file"
    done

    # SSH directory permissions
    log "INFO" "Checking SSH directory permissions..."
    find /home -type d -name ".ssh" 2>/dev/null | while read -r dir; do
        perms=$(stat -c %a "$dir")
        if [[ "$perms" != "700" ]]; then
            log "ERROR" "Insecure SSH directory ($dir) - Permissions: $perms"
        fi
    done
}

# 3. Network Security
audit_network() {
    section_header "NETWORK SECURITY"

    # Open ports
    log "INFO" "Listing open ports..."
    if command -v ss &>/dev/null; then
        ss -tuln | grep LISTEN | while read -r line; do
            log "INFO" "Open port: $line"
        done
    elif command -v netstat &>/dev/null; then
        netstat -tuln | grep LISTEN | while read -r line; do
            log "INFO" "Open port: $line"
        done
    else
        log "ERROR" "Neither ss nor netstat found"
    fi

    # Firewall rules
    log "INFO" "Checking firewall status..."
    if command -v ufw &>/dev/null; then
        ufw status verbose | while read -r line; do
            log "INFO" "UFW: $line"
        done
    elif command -v iptables &>/dev/null; then
        iptables -L -n -v 2>/dev/null | while read -r rule; do
            log "INFO" "IPTables: $rule"
        done
    else
        log "ERROR" "No firewall tools found"
    fi
}

# 4. Service Security
audit_services() {
    section_header "SERVICE SECURITY"

    for service in "${IMPORTANT_SERVICES[@]}"; do
        if systemctl is-active --quiet "$service"; then
            log "SUCCESS" "Service '$service' is running"
        else
            log "WARNING" "Service '$service' is NOT running"
        fi
    done
}

# 5. System Updates
check_updates() {
    section_header "SYSTEM UPDATES"

    if command -v apt &>/dev/null; then
        apt update -qq &>/dev/null
        updates=$(apt list --upgradable 2>/dev/null | grep -v "Listing..." | wc -l)
        log "INFO" "Updates available: $updates"
        apt list --upgradable 2>/dev/null | grep -v "Listing..." | while read -r pkg; do
            log "INFO" "Update: $pkg"
        done
    elif command -v yum &>/dev/null; then
        yum check-update -q &>/dev/null
        updates=$(yum check-update | wc -l)
        log "INFO" "Updates available: $updates"
    else
        log "ERROR" "No supported package manager found"
    fi
}

# 6. IP Configuration
check_ip_config() {
    section_header "IP CONFIGURATION"

    if command -v ip &>/dev/null; then
        ip -4 addr | grep inet | awk '{print $2}' | while read -r ip; do
            if [[ "$ip" =~ ^(10\.|192\.168|172\.(1[6-9]|2[0-9]|3[0-1])) ]]; then
                log "INFO" "Private IP: $ip"
            else
                log "WARNING" "Public IP: $ip"
            fi
        done
    else
        log "ERROR" "No IP tool found"
    fi
}

# Main function
main() {
    check_root
    log "INFO" "Starting Linux security audit..."
    date >> "$REPORT"

    audit_users
    audit_filesystem
    audit_network
    audit_services
    check_updates
    check_ip_config

    log "SUCCESS" "Security audit completed. Report: $REPORT"
}

main "$@"
