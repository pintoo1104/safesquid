#!/bin/bash

# ==============================
# Linux Security Audit Dashboard
# ==============================

HTML_REPORT="security_audit_report.html"
> "$HTML_REPORT"

# Initialize HTML structure
cat <<EOF >> "$HTML_REPORT"
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Linux Security Audit Dashboard</title>
  <style>
    body { font-family: monospace; background-color: #f4f4f4; padding: 20px; }
    h1 { background-color: #3333cc; color: white; padding: 10px; }
    h2 { background-color: #44aa44; color: white; padding: 8px; }
    pre { background: #fff; border: 1px solid #ccc; padding: 10px; overflow-x: auto; }
    .summary { color: #aa00aa; font-weight: bold; }
  </style>
</head>
<body>
<h1>Linux Security Audit Dashboard</h1>
EOF

print_title() {
    local title="$1"
    echo -e "\n\033[1;44m========= $title =========\033[0m"
    echo "<h1>$title</h1>" >> "$HTML_REPORT"
}

print_subtitle() {
    local subtitle="$1"
    echo -e "\n\033[1;42m-- $subtitle --\033[0m"
    echo "<h2>$subtitle</h2>" >> "$HTML_REPORT"
}

write_html_block() {
    echo "<pre>$1</pre>" >> "$HTML_REPORT"
}

write_html_summary() {
    echo "<p class='summary'>$1</p>" >> "$HTML_REPORT"
}

user_audit() {
    print_title "1. USER AND GROUP AUDIT"

    print_subtitle "Users with UID 0 (root access)"
    root_users=$(getent passwd | awk -F: '$3 == 0 {print $1}')
    echo "$root_users"
    write_html_block "$root_users"
    write_html_summary "Total: $(echo "$root_users" | wc -l)"

    print_subtitle "Users with no password set (potential risk)"
    no_pass_users=$(getent passwd | cut -d: -f1 | xargs -n1 -I{} sudo passwd -S {} 2>/dev/null | grep -E "NP|!!")
    echo "$no_pass_users"
    write_html_block "$no_pass_users"
    write_html_summary "Total: $(echo "$no_pass_users" | wc -l)"

    print_subtitle "All Local Groups"
    groups=$(cut -d: -f1 /etc/group)
    echo "$groups"
    write_html_block "$groups"
    write_html_summary "Total Groups: $(echo "$groups" | wc -l)"
}

file_permission_audit() {
    print_title "2. FILE AND DIRECTORY PERMISSIONS"

    print_subtitle "World-writable directories"
    dirs=$(find / -type d -perm -0002 -exec ls -ld {} \; 2>/dev/null)
    echo "$dirs"
    write_html_block "$dirs"
    write_html_summary "Count: $(echo "$dirs" | wc -l)"

    print_subtitle "SUID/SGID Files"
    suid_sgid=$(find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -ld {} \; 2>/dev/null)
    echo "$suid_sgid"
    write_html_block "$suid_sgid"
    write_html_summary "Count: $(echo "$suid_sgid" | wc -l)"

    print_subtitle "SSH Directory Permissions"
    ssh_dirs=$(find /home -name ".ssh" -exec ls -ld {} \; 2>/dev/null)
    echo "$ssh_dirs"
    write_html_block "$ssh_dirs"
    write_html_summary "Found: $(echo "$ssh_dirs" | wc -l)"
}

service_audit() {
    print_title "3. SERVICE AUDIT"

    print_subtitle "Running Services"
    services=$(systemctl list-units --type=service --state=running)
    echo "$services"
    write_html_block "$services"
    write_html_summary "Total Running: $(echo "$services" | grep '.service' | wc -l)"

    print_subtitle "Listening Network Ports (excluding localhost)"
    ports=$(netstat -tulnp | grep -v "127.0.0.1")
    echo "$ports"
    write_html_block "$ports"
    write_html_summary "Listening Ports: $(echo "$ports" | wc -l)"
}

firewall_audit() {
    print_title "4. FIREWALL & NETWORK SECURITY"

    print_subtitle "Firewall Rules"
    if command -v ufw &> /dev/null; then
        fw=$(ufw status verbose)
    elif command -v iptables &> /dev/null; then
        fw=$(iptables -L -n -v)
    else
        fw="No firewall tool (ufw/iptables) found."
    fi
    echo "$fw"
    write_html_block "$fw"

    print_subtitle "Active Listening Ports"
    ports=$(ss -tuln)
    echo "$ports"
    write_html_block "$ports"
    write_html_summary "Active: $(echo "$ports" | grep -c LISTEN)"
}

ip_check() {
    print_title "5. IP CONFIGURATION CHECK"

    print_subtitle "Assigned IP Addresses"
    count=0
    ips=""
    while IFS= read -r ip; do
        if [[ "$ip" =~ ^10\.|^172\.1[6-9]|^192\.168 ]]; then
            ips+="Private IP: $ip"$'\n'
        else
            ips+="Public IP: $ip"$'\n'
        fi
        ((count++))
    done < <(ip -4 addr show | grep inet | awk '{print $2}')
    echo "$ips"
    write_html_block "$ips"
    write_html_summary "Total IPs Found: $count"
}

update_check() {
    print_title "6. SECURITY UPDATES & PATCHING"

    print_subtitle "Available Updates"
    if command -v apt &> /dev/null; then
        apt update -y > /dev/null
        updates=$(apt list --upgradable 2>/dev/null)
    elif command -v yum &> /dev/null; then
        updates=$(yum check-update)
    fi
    echo "$updates"
    write_html_block "$updates"
    write_html_summary "Update Count: $(echo "$updates" | grep -cE '^[a-zA-Z0-9]')"
}

log_monitor() {
    print_title "7. LOGIN ATTEMPTS & AUTH LOGS"

    print_subtitle "Recent Failed Login Attempts"
    fails=$(grep "Failed password" /var/log/auth.log | tail -n 10)
    echo "$fails"
    write_html_block "$fails"
    write_html_summary "Entries Shown: $(echo "$fails" | wc -l)"
}

server_hardening() {
    print_title "8. SERVER HARDENING"

    print_subtitle "SSH Configuration (Root login disabled)"
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl reload sshd
    msg="Updated sshd_config to disable root login and password auth"
    echo "$msg"
    write_html_block "$msg"

    print_subtitle "Disabling IPv6"
    sysctl_conf="net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1"
    echo "$sysctl_conf" >> /etc/sysctl.conf
    output=$(sysctl -p)
    echo "$output"
    write_html_block "$output"

    print_subtitle "Bootloader Security Check"
    write_html_block "Manual check: run 'ls -l /boot/grub/grub.cfg'"
}

custom_checks() {
    print_title "9. CUSTOM CHECKS"
    write_html_block "You can extend this section for application-specific security checks."
}

summary() {
    print_title "10. AUDIT COMPLETED"
    echo -e "\033[1;35mAudit report saved to: $HTML_REPORT\033[0m"
    write_html_summary "Audit report saved to: $HTML_REPORT"
    echo "</body></html>" >> "$HTML_REPORT"
}

main() {
    clear
    echo -e "\n\033[1;35m=== Starting Linux Security Audit ===\033[0m"
    user_audit
    file_permission_audit
    service_audit
    firewall_audit
    ip_check
    update_check
    log_monitor
    server_hardening
    custom_checks
    summary
}

main
