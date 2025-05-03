#!/bin/bash

# Trap for Ctrl+C to exit cleanly
trap "tput cnorm; clear; exit" SIGINT

# Color Codes
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
CYAN=$(tput setaf 6)
RESET=$(tput sgr0)

draw_box() {
  echo "+$(printf -- '-%.0s' $(seq 1 $1))+"
}

draw_section() {
  draw_box 60
  printf "| %-58s |\n" "$1"
  draw_box 60
}

while true; do
  clear
  tput civis  # Hide cursor

  # HEADER
  draw_section "${CYAN}SYSTEM MONITOR DASHBOARD${RESET}"

  # CPU Usage
  cpu_idle=$(top -bn1 | awk -F'id,' '/Cpu\(s\):/ { split($1, a, ","); print a[length(a)] }' | awk '{print $NF}')
  cpu_usage=$(awk "BEGIN {printf \"%.1f\", 100 - $cpu_idle}")
  load_avg=$(uptime | awk -F'load average:' '{ print $2 }')
  printf "| CPU Usage: [%-10s] %4.1f%%   Load Avg:%s |\n" "$(printf '#%.0s' $(seq 1 $((${cpu_usage%.*} / 10))))" "$cpu_usage" "$load_avg"

  # Memory Usage
  read -r mem_total mem_used <<< $(free -m | awk '/Mem:/ {print $2, $3}')
  mem_percent=$((mem_used * 100 / mem_total))
  swap_info=$(free -h | awk '/Swap:/ {print $3 " / " $2}')
  printf "| Memory:    [%-10s] %2d%%   Swap: %s |\n" "$(printf '#%.0s' $(seq 1 $((mem_percent / 10))))" "$mem_percent" "$swap_info"

  # Disk Usage
  disk_usage=$(df / | awk 'END {print $5}' | tr -d '%')
  disk_bar=$(printf '#%.0s' $(seq 1 $((disk_usage / 10))))
  var_usage=$(df /var 2>/dev/null | awk 'END {print $5}' | tr -d '%')
  disk_warn=""
  [[ -n "$var_usage" && $var_usage -gt 80 ]] && disk_warn="${RED}Warning: /var $var_usage%% used${RESET}"
  printf "| Disk:      [%-10s] %2d%%   %-30s |\n" "$disk_bar" "$disk_usage" "$disk_warn"

  draw_box 60

  # Top Processes
  draw_section "${YELLOW}Top Processes (CPU & Mem)${RESET}"
  printf "| %-3s | %-15s | %-8s | %-10s |\n" "#" "Process Name" "CPU (%)" "Memory (MB)"
  ps -eo pid,comm,%cpu,%mem --sort=-%cpu | head -n 6 | tail -n 5 | awk '{printf "| %-3d | %-15s | %-8s | %-10s |\n", NR, $2, $3, int($4 * 16)}'
  draw_box 60

  # Network Monitoring
  draw_section "${YELLOW}Network Monitoring${RESET}"
  connections=$(ss -s | awk '/estab/ {print $4}')
  drops=$(netstat -s 2>/dev/null | grep -i "dropped" | head -n 1 | awk '{print $1}')
  rx_bytes=$(awk '/:/ {gsub(/:/,"",$1); if($1 ~ "eth0|enp|wlp") sum+=$2} END {print sum}' /proc/net/dev)
  tx_bytes=$(awk '/:/ {gsub(/:/,"",$1); if($1 ~ "eth0|enp|wlp") sum+=$10} END {print sum}' /proc/net/dev)
  in_data=$(awk "BEGIN {printf \"%.2f GB\", $rx_bytes/1024/1024}")
  out_data=$(awk "BEGIN {printf \"%.2f GB\", $tx_bytes/1024/1024}")
  printf "| Active Connections: %-4s | Packet Drops: %-4s |\n" "$connections" "${drops:-0}"
  printf "| Data In: %-10s | Data Out: %-10s |\n" "$in_data" "$out_data"
  draw_box 60

  # Services Status
  draw_section "${YELLOW}Services Status${RESET}"
  for svc in sshd nginx iptables; do
    if systemctl is-active --quiet $svc; then
      state="${GREEN}[RUNNING]${RESET}"
    else
      state="${RED}[STOPPED]${RESET}"
    fi
    printf "| %-10s: %-15s |\n" "$svc" "$state"
  done
  draw_box 60

  # Footer
  echo -e "| Press [Q] to exit | Refreshing every 2s...         |"
  draw_box 60

  # Read keypress with timeout
  read -t 2 -n 1 key
  if [[ "$key" == "q" || "$key" == "Q" ]]; then
    tput cnorm
    clear
    exit
  fi
done
