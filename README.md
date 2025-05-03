# 🖥️ Linux System Monitor Dashboard

`monitor_dashboard.sh` is an interactive, real-time system monitoring dashboard built in Bash. It provides a comprehensive view of system health including CPU, memory, disk usage, network statistics, top processes, and critical service status — all in a terminal-friendly format.

---

## 🔧 Features

- **CPU Monitoring**
  - Real-time usage with a visual usage bar
  - Load averages displayed

- **Memory Monitoring**
  - Displays used, total, and percentage of memory
  - Swap usage shown with progress bar

- **Disk Usage Monitoring**
  - Root (`/`) and optional `/var` disk usage
  - Auto-warns when `/var` exceeds 80% usage

- **Top Processes**
  - Displays top 10 processes by CPU usage
  - Memory usage approximated in MB

- **Network Monitoring**
  - Active connections
  - Packet drops
  - Total incoming and outgoing data (in GB)

- **Service Status**
  - Live status check of key services: `sshd`, `nginx`, and `iptables`

- **Visual Dashboard**
  - Color-coded sections
  - Clean terminal output with refresh loop
  - Graceful exit on Ctrl+C or pressing `Q`

---

## 🧱 Dependencies

Make sure the following commands/utilities are available on your Linux system:

- `bash`
- `top`
- `awk`
- `free`
- `df`
- `ps`
- `ss` or `netstat`
- `tput`
- `systemctl`

Tested on:
- Ubuntu 20.04 / 22.04
- Debian-based systems

---

## 🚀 Usage

1. **Make the script executable**:
   ```bash
   chmod +x monitor_dashboard.sh
Exit the dashboard:

Press Q or Ctrl+C to exit gracefully.

Customization
Refresh Interval:

Currently set to 2 seconds by default (via read -t 2).

You can modify the timeout in the script to a different value.

Add More Services:

Update the for svc in ... loop to include more services you want to monitor.

Interface Adaptation:

Currently matches interfaces like eth0, enp, wlp.

You can enhance this to dynamically detect active network interfaces.

📸 Preview

![image](https://github.com/user-attachments/assets/be9e2536-8e40-4477-abed-ea2a7af0d635)
