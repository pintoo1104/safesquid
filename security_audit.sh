#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

REPORT="security_audit_report_$(hostname)_$(date +%F).txt"
touch "$REPORT"

# Colors for terminal
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log() {
    local level="$1"; local msg="$2"; local color="$3"
    echo -e "${color}[$level] $msg${NC}"
    echo "[$level] $msg" >> "$REPORT"
}

header() {
    local title="$1"
    echo -e "\n${BLUE}========== $title ==========${NC}"
    echo -e "\n========== $title ==========" >> "$REPORT"
}

check_root() {
    [[ "$EUID" -ne 0 ]] && { log "ERROR" "Script must be run as root." "$RED"; exit 1; }
}

audit_users_groups() {
    header "USER AND GROUP AUDIT"
    awk -F: '$3 == 0' /etc/passwd | while read -r u; do log "INFO" "UID 0 User: $u" "$YELLOW"; done
    awk -F: '$2 == "" || $2 == "!" || $2 == "*"' /etc/shadow | while read -r u; do log "WARNING" "Weak/empty password: $u" "$RED"; done
    getent group sudo | cut -d: -f4 | tr ',' '\n' | while read -r u; do log "INFO" "Sudo User: $u" "$GREEN"; done
}

audit_files() {
    header "FILE & DIRECTORY PERMISSIONS"
    find / -xdev -type f -perm -0002 -not -path "/proc/*" 2>/dev/null | while read -r f; do log "WARNING" "World-writable: $f" "$RED"; done
    find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | while read -r f; do log "WARNING" "SUID/SGID: $f" "$YELLOW"; done
    find /home -type d -name ".ssh" 2>/dev/null | while read -r d; do
        perms=$(stat -c %a "$d")
        [[ "$perms" != "700" ]] && log "ERROR" "$d has insecure permissions: $perms" "$RED"
    done
}

audit_services() {
    header "SERVICE AUDIT"
    local services=("sshd" "iptables" "ufw")
    for svc in "${services[@]}"; do
        if systemctl is-active --quiet "$svc"; then
            log "SUCCESS" "$svc is running" "$GREEN"
        else
            log "WARNING" "$svc not running" "$YELLOW"
        fi
    done
}

check_network_config() {
    header "FIREWALL & NETWORK CONFIG"
    command -v iptables &>/dev/null && iptables -L -n -v | while read -r l; do log "INFO" "IPTABLES: $l" "$BLUE"; done
    netstat -tuln 2>/dev/null | grep LISTEN | while read -r l; do log "INFO" "Open port: $l" "$YELLOW"; done
    ip a | grep inet | awk '{print $2}' | while read -r ip; do
        if [[ "$ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168) ]]; then
            log "INFO" "Private IP: $ip" "$GREEN"
        else
            log "WARNING" "Public IP: $ip" "$RED"
        fi
    done
}

check_updates() {
    header "SECURITY UPDATES"
    if command -v apt &>/dev/null; then
        apt update -qq
        apt list --upgradable 2>/dev/null | grep -v "Listing" | while read -r line; do
            log "INFO" "Update available: $line" "$YELLOW"
        done
    elif command -v yum &>/dev/null; then
        yum check-update || true
    fi
}

harden_ssh() {
    header "SSH HARDENING"
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
    log "SUCCESS" "Disabled SSH root and password login" "$GREEN"
}

disable_ipv6() {
    header "DISABLING IPV6"
    if grep -q "disable_ipv6 = 1" /etc/sysctl.conf; then
        log "INFO" "IPv6 already disabled" "$YELLOW"
    else
        echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
        echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
        sysctl -p
        log "SUCCESS" "Disabled IPv6" "$GREEN"
    fi
}

secure_grub() {
    header "SECURING GRUB BOOTLOADER"
    grub_pass_file="/etc/grub.d/40_custom"
    if grep -q "set superusers" "$grub_pass_file"; then
        log "INFO" "GRUB already secured" "$YELLOW"
    else
        read -rp "Enter GRUB admin username: " user
        read -srp "Enter GRUB password: " pass
        echo
        grub_password=$(echo -e "$pass\n$pass" | grub-mkpasswd-pbkdf2 | awk '/grub.pbkdf2/ {print $7}')
        echo -e "set superusers=\"$user\"\npassword_pbkdf2 $user $grub_password" >> "$grub_pass_file"
        update-grub
        log "SUCCESS" "GRUB password set" "$GREEN"
    fi
}

enable_auto_updates() {
    header "AUTOMATIC SECURITY UPDATES"
    if command -v apt &>/dev/null; then
        apt install -y unattended-upgrades
        dpkg-reconfigure -f noninteractive unattended-upgrades
        log "SUCCESS" "Unattended upgrades enabled" "$GREEN"
    fi
}

run_custom_checks() {
    header "CUSTOM SECURITY CHECKS"
    config_file="./custom_checks.sh"
    if [[ -f "$config_file" ]]; then
        bash "$config_file" >> "$REPORT"
        log "INFO" "Executed custom checks from $config_file" "$BLUE"
    else
        log "INFO" "No custom check file found" "$YELLOW"
    fi
}

main() {
    check_root
    log "INFO" "Starting full Linux security audit and hardening..." "$BLUE"

    audit_users_groups
    audit_files
    audit_services
    check_network_config
    check_updates
    harden_ssh
    disable_ipv6
    secure_grub
    enable_auto_updates
    run_custom_checks

    log "SUCCESS" "Audit complete. Report: $REPORT" "$GREEN"
}

main "$@"
