#!/bin/bash

# Trap for Ctrl+C to exit cleanly
trap "tput cnorm; clear; exit" SIGINT

# Colors
RESET='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'

# Function to draw box
draw_box() {
  echo "+$(printf -- '-%.0s' $(seq 1 $1))+" 
}

# Function to draw section header
draw_section() {
  draw_box 60
  printf "| %-58s |\n" "$1"
  draw_box 60
}

# Function to get memory and swap usage
get_memory_usage() {
  # Fetch memory details, ensuring they are integers
  read -r mem_total mem_used <<< $(free -m | awk '/Mem:/ {print $2, $3}')
  
  # Check if the values are numeric
  if [[ ! "$mem_total" =~ ^[0-9]+$ ]] || [[ ! "$mem_used" =~ ^[0-9]+$ ]]; then
    echo -e "${RED}Error: Invalid memory values${RESET}"
    return 1
  fi

  # Calculate memory usage percentage
  mem_percent=$((mem_used * 100 / mem_total))

  # Get swap information
  swap_info=$(free -h | awk '/Swap:/ {print $3 " / " $2}')
  
  # Display memory and swap usage
  printf "| Memory:    [%-10s] %2d%%   Swap: %s |\n" "$(printf '#%.0s' $(seq 1 $((mem_percent / 10))))" "$mem_percent" "$swap_info"
}

# Function to get CPU and load usage
get_cpu_usage() {
  cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print 100 - $8}')
  load_avg=$(uptime | awk -F'load average:' '{ print $2 }')
  printf "| CPU Usage: [%-10s] %2.0f%%   Load Avg:%s |\n" "$(printf '#%.0s' $(seq 1 $((cpu_usage / 10))))" "$cpu_usage" "$load_avg"
}

# Function to get disk usage
get_disk_usage() {
  disk_usage=$(df / | awk 'END {print $5}' | tr -d '%')
  disk_bar=$(printf '#%.0s' $(seq 1 $((disk_usage / 10))))
  disk_warn=""
  var_usage=$(df /var | awk 'END {print $5}' | tr -d '%')
  [[ $var_usage -gt 80 ]] && disk_warn="${RED}Warning: /var $var_usage% used${RESET}"
  printf "| Disk:      [%-10s] %2d%%   %-20s |\n" "$disk_bar" "$disk_usage" "$disk_warn"
}

# Function to get top processes
get_top_processes() {
  draw_section "Top Processes (CPU & Mem)"
  printf "| %-3s | %-15s | %-8s | %-10s |\n" "#" "Process Name" "CPU (%)" "Memory (MB)"
  ps -eo pid,comm,%cpu,%mem --sort=-%cpu | head -n 6 | tail -n 5 | awk '{printf "| %-3d | %-15s | %-8s | %-10s |\n", NR, $2, $3, int($4 * 16)}'
  draw_box 60
}

# Function to get network stats
get_network_usage() {
  draw_section "Network Monitoring"
  connections=$(ss -s | awk '/estab/ {print $4}')
  drops=$(netstat -s | grep -i "dropped" | head -n 1 | awk '{print $1}')
  in_data=$(ifconfig | grep "RX bytes" | awk '{print $2}' | awk -F: '{sum+=$2} END {printf "%.2f GB", sum/1024/1024}')
  out_data=$(ifconfig | grep "TX bytes" | awk '{print $6}' | awk -F: '{sum+=$2} END {printf "%.2f GB", sum/1024/1024}')
  printf "| Active Connections: %-4s | Packet Drops: %-4s |\n" "$connections" "$drops"
  printf "| Data In: %-10s | Data Out: %-10s |\n" "$in_data" "$out_data"
  draw_box 60
}

# Function to get service statuses
get_service_status() {
  draw_section "Services Status"
  for svc in sshd nginx iptables; do
    systemctl is-active --quiet $svc && state="${GREEN}[RUNNING]${RESET}" || state="${RED}[STOPPED]${RESET}"
    printf "| %-10s: %-10s |\n" "$svc" "$state"
  done
  draw_box 60
}

while true; do
  clear
  tput civis  # Hide cursor

  # HEADER
  draw_section "${CYAN}SYSTEM MONITOR DASHBOARD${RESET}"

  # Get CPU Usage
  get_cpu_usage

  # Get Memory Usage
  get_memory_usage

  # Get Disk Usage
  get_disk_usage

  draw_box 60

  # Get Top Processes
  get_top_processes

  # Get Network Usage
  get_network_usage

  # Get Service Statuses
  get_service_status

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
