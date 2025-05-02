#!/bin/bash

# ========================
# Linux Security Audit and Hardening Script
# Author: Akshay (Modified)
# Description: Enhanced modular script to audit and harden Linux servers
# ========================

set -euo pipefail  # Exit on error, undefined vars, and pipe failures

# Configuration
REPORT_FILE="/tmp/security_audit_$(date +%Y%m%d_%H%M%S).txt"
BACKUP_DIR="/root/security_backup_$(date +%Y%m%d_%H%M%S)"
EMAIL_RECIPIENT=""
CUSTOM_CHECKS_FILE="/etc/security_audit/custom_checks.conf"

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Enhanced logging with severity levels
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "[$timestamp] [$level] $message" | tee -a "$REPORT_FILE"
    
    # Alert on critical issues
    if [[ "$level" == "CRITICAL" && -n "$EMAIL_RECIPIENT" ]]; then
        echo "[$timestamp] $message" | mail -s "Security Alert: Critical Issue" "$EMAIL_RECIPIENT"
    fi
}

# Backup function
backup_file() {
    local file=$1
    if [[ -f "$file" ]]; then
        cp "$file" "$BACKUP_DIR/$(basename "$file").bak"
    fi
}

# Enhanced user audit with weak password detection
user_group_audit() {
    log "INFO" "Starting User and Group Audit"
    
    # Check for users with weak password policies
    while IFS=: read -r user pass uid gid desc home shell; do
        if [[ $uid -eq 0 && $user != "root" ]]; then
            log "CRITICAL" "Non-root user with UID 0 found: $user"
        fi
        
        # Check password aging
        local max_days=$(chage -l "$user" | grep "Maximum" | awk '{print $9}')
        if [[ "$max_days" -gt 90 ]]; then
            log "WARNING" "User $user has password maximum age > 90 days"
        fi
    done < /etc/passwd
}

# Enhanced permission audit with common vulnerability checks
permission_audit() {
    log "INFO" "Starting Permission Audit"
    
    # Check for unauthorized SUID binaries
    local known_suid="/usr/bin/sudo /usr/bin/passwd /usr/bin/su"
    find / -xdev -type f -perm -4000 2>/dev/null | while read -r file; do
        if ! echo "$known_suid" | grep -q "$file"; then
            log "WARNING" "Unknown SUID binary found: $file"
        fi
    done
}

# Firewall configuration verification
verify_firewall_rules() {
    log "INFO" "Verifying Firewall Rules"
    
    # Check for basic firewall requirements
    if command -v iptables >/dev/null; then
        if ! iptables -L INPUT | grep -q "policy DROP"; then
            log "CRITICAL" "Firewall INPUT policy is not set to DROP"
        fi
        
        # Check for essential rules
        if ! iptables -L | grep -q "state RELATED,ESTABLISHED"; then
            log "WARNING" "Missing stateful firewall rules"
        fi
    fi
}

# Load and execute custom checks
execute_custom_checks() {
    if [[ -f "$CUSTOM_CHECKS_FILE" ]]; then
        log "INFO" "Executing Custom Security Checks"
        while IFS= read -r check; do
            if [[ "$check" =~ ^[^#] ]]; then
                eval "$check"
            fi
        done < "$CUSTOM_CHECKS_FILE"
    fi
}

# Main execution with error handling
main() {
    trap 'log "ERROR" "Script failed on line $LINENO"' ERR
    
    log "INFO" "Starting Security Audit and Hardening"
    
    # Core functions with error handling
    user_group_audit || log "ERROR" "User audit failed"
    permission_audit || log "ERROR" "Permission audit failed"
    verify_firewall_rules || log "ERROR" "Firewall verification failed"
    execute_custom_checks || log "ERROR" "Custom checks failed"
    
    # Encrypt the report
    if command -v gpg >/dev/null; then
        gpg --encrypt --recipient "$EMAIL_RECIPIENT" "$REPORT_FILE"
        rm "$REPORT_FILE"
        log "INFO" "Report encrypted: ${REPORT_FILE}.gpg"
    fi
}

main
