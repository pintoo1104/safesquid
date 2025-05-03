🖥️ Linux Security Audit and Hardening Script
security_audit.sh is a comprehensive Bash script designed to automate the security auditing and hardening of Linux servers. It performs a range of security checks, from user audits to network configurations, and helps secure the server by implementing best practices and critical security measures.

🔧 Features
Security Audits
User and Group Audits: Lists all users and groups, checks for users with root privileges, and identifies users with weak or missing passwords.

File and Directory Permissions: Scans for files and directories with world-writable permissions, and checks for SUID/SGID bits on executables.

Service Audits: Lists all running services, checks for unauthorized or unnecessary services, and ensures critical services are properly configured.

Firewall and Network Security: Verifies firewall status, open ports, and checks for insecure network configurations.

Hardening Measures
SSH Hardening: Disables root login and password authentication for SSH.

IPv6 Disabling: Disables IPv6 across the system.

GRUB Password Setup: Configures a GRUB password for bootloader security.

Custom Security Checks
Allows the inclusion of a custom security checks script to run additional checks as required.

Email Reporting
Sends the generated security audit report via email for further analysis.

🧱 Dependencies
Ensure the following utilities are available on your Linux system:

bash

john (for password cracking)

unshadow (for combining passwd and shadow files)

ufw (for firewall management)

expect (for automating GRUB password setup)

mailutils (for sending email reports)

lsof (for listing open files)

systemctl (for managing system services)

Tested on:

Ubuntu 20.04 / 22.04

Debian-based systems

🚀 Usage
Make the script executable:

bash
Copy
Edit
chmod +x security_audit.sh
Run the script:

bash
Copy
Edit
./security_audit.sh
The script will perform various security checks and implement hardening measures.

Exit the script: Simply press Ctrl+C to exit.

Customization
Custom Checks: Create a custom_checks.sh file and place it in the same directory as the script for additional security checks.

Email Notification: The script will prompt for an email address to send the generated report. Ensure mailutils is installed for this functionality.

🖥️ Linux System Monitor Dashboard
monitor_dashboard.sh is an interactive, real-time system monitoring dashboard built in Bash. It provides a comprehensive view of system health, including CPU, memory, disk usage, network statistics, top processes, and critical service status — all in a terminal-friendly format.

🔧 Features
CPU Monitoring

Real-time usage with a visual usage bar

Load averages displayed

Memory Monitoring

Displays used, total, and percentage of memory

Swap usage shown with progress bar

Disk Usage Monitoring

Root (/) and optional /var disk usage

Auto-warns when /var exceeds 80% usage

Top Processes

Displays top 10 processes by CPU usage

Memory usage approximated in MB

Network Monitoring

Active connections

Packet drops

Total incoming and outgoing data (in GB)

Service Status

Live status check of key services: sshd, nginx, and iptables

Visual Dashboard

Color-coded sections

Clean terminal output with refresh loop

Graceful exit on Ctrl+C or pressing Q

🧱 Dependencies
Make sure the following commands/utilities are available on your Linux system:

bash

top

awk

free

df

ps

ss or netstat

tput

systemctl

Tested on:

Ubuntu 20.04 / 22.04

Debian-based systems

🚀 Usage
Make the script executable:

bash
Copy
Edit
chmod +x monitor_dashboard.sh
Run the script:

bash
Copy
Edit
./monitor_dashboard.sh
Exit the dashboard:
Press Q or Ctrl+C to exit gracefully.

Customization
Refresh Interval: The current refresh interval is set to 2 seconds by default (via read -t 2). You can modify the timeout in the script to a different value.

Add More Services: Update the for svc in ... loop to include more services you want to monitor.

Interface Adaptation: The script currently detects interfaces like eth0, enp, wlp. You can modify it to dynamically detect active network interfaces.

📸 Preview


This README.md combines both your security audit and monitoring dashboard scripts into one file, each with its own section. You can now include both scripts in your repository and explain them in a unified manner! Let me know if you'd like any changes.
