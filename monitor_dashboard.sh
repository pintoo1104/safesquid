#!/bin/bash

# Trap for Ctrl+C to exit cleanly
trap "tput cnorm; clear; exit" SIGINT

# Default flags for sections
show_all=true
show_cpu=false
show_memory=false
show_disk=false
show_network=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -cpu)
            show_all=false
            show_cpu=true
            shift
            ;;
        -memory)
            show_all=false
            show_memory=true
            shift
            ;;
        -disk)
            show_all=false
            show_disk=true
            shift
            ;;
        -network)
            show_all=false
            show_network=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [-cpu] [-memory] [-disk] [-network]"
            echo "  -cpu     : Show only CPU statistics"
            echo "  -memory  : Show only memory statistics"
            echo "  -disk    : Show only disk statistics"
            echo "  -network : Show only network statistics"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

draw_box() {
    echo "+$(printf -- '-%.0s' $(seq 1 $1))+"
}

draw_section() {
    draw_box 60
    printf "| %-58s |\n" "$1"
    draw_box 60
}

show_cpu_stats() {
    # CPU Usage with more detailed breakdown
    cpu_stats=$(top -bn1 | grep "Cpu(s)" | sed 's/%//g')
    user=$(echo "$cpu_stats" | awk '{print $2}')
    system=$(echo "$cpu_stats" | awk '{print $4}')
    idle=$(echo "$cpu_stats" | awk '{print $8}')
    cpu_usage=$(echo "100 - $idle" | bc)
    load_avg=$(uptime | awk -F'load average:' '{ print $2 }')
    printf "| CPU Usage: [%-10s] %2.1f%%                        |\n" "$(printf '#%.0s' $(seq 1 $((cpu_usage / 10))))" "$cpu_usage"
    printf "| User: %2.1f%% | System: %2.1f%% | Idle: %2.1f%%              |\n" "$user" "$system" "$idle"
    printf "| Load Average:%s |\n" "$load_avg"
}

show_memory_stats() {
    # Enhanced Memory Usage
    eval $(free -m | awk '/Mem:/ {printf "mem_total=%d;mem_used=%d;mem_free=%d;mem_cache=%d", $2, $3, $4, $6}')
    mem_percent=$((mem_used * 100 / mem_total))
    swap_info=$(free -h | awk '/Swap:/ {print $3 " / " $2}')
    printf "| Memory:    [%-10s] %2d%%   Total: %d MB        |\n" "$(printf '#%.0s' $(seq 1 $((mem_percent / 10))))" "$mem_percent" "$mem_total"
    printf "| Used: %d MB | Free: %d MB | Cached: %d MB           |\n" "$mem_used" "$mem_free" "$mem_cache"
    printf "| Swap Usage: %s                              |\n" "$swap_info"
}

show_disk_stats() {
    # Enhanced Disk Usage
    printf "| %-15s %-10s %-10s %-10s %-8s |\n" "Filesystem" "Size" "Used" "Avail" "Use%"
    df -h | grep '^/dev/' | while read -r line; do
        dev=$(echo "$line" | awk '{print $1}')
        size=$(echo "$line" | awk '{print $2}')
        used=$(echo "$line" | awk '{print $3}')
        avail=$(echo "$line" | awk '{print $4}')
        use_percent=$(echo "$line" | awk '{print $5}')
        use_num=$(echo "$use_percent" | tr -d '%')
        if [ "$use_num" -gt 80 ]; then
            printf "| \033[1;31m%-15s %-10s %-10s %-10s %-8s\033[0m |\n" "$dev" "$size" "$used" "$avail" "$use_percent"
        else
            printf "| %-15s %-10s %-10s %-10s %-8s |\n" "$dev" "$size" "$used" "$avail" "$use_percent"
        fi
    done
}

show_network_stats() {
    # Enhanced Network Monitoring
    draw_section "Network Monitoring"
    connections=$(ss -s | awk '/TCP:/ {print $2}')
    drops=$(cat /proc/net/dev | grep -v "lo:" | awk '{sum += $5} END {print sum}')
    
    # Calculate network throughput
    rx_bytes=$(cat /proc/net/dev | grep -v "lo:" | awk '{sum += $2} END {print sum}')
    tx_bytes=$(cat /proc/net/dev | grep -v "lo:" | awk '{sum += $10} END {print sum}')
    rx_mb=$(echo "scale=2; $rx_bytes/1024/1024" | bc)
    tx_mb=$(echo "scale=2; $tx_bytes/1024/1024" | bc)
    
    printf "| Active TCP Connections: %-6s                      |\n" "$connections"
    printf "| Total Packet Drops: %-6s                         |\n" "$drops"
    printf "| Data Received: %-8.2f MB                           |\n" "$rx_mb"
    printf "| Data Transmitted: %-8.2f MB                        |\n" "$tx_mb"
}

while true; do
    clear
    tput civis  # Hide cursor

    # HEADER
    draw_section "SYSTEM MONITOR DASHBOARD"

    # Display sections based on flags
    if [ "$show_all" = true ] || [ "$show_cpu" = true ]; then
        show_cpu_stats
        draw_box 60
    fi

    if [ "$show_all" = true ] || [ "$show_memory" = true ]; then
        show_memory_stats
        draw_box 60
    fi

    if [ "$show_all" = true ] || [ "$show_disk" = true ]; then
        show_disk_stats
        draw_box 60
    fi

    if [ "$show_all" = true ] || [ "$show_network" = true ]; then
        show_network_stats
        draw_box 60
    fi

    if [ "$show_all" = true ]; then
        # Top Processes
        draw_section "Top Processes (CPU & Memory)"
        printf "| %-20s | %-8s | %-8s | %-8s |\n" "COMMAND" "PID" "CPU%" "MEM%"
        ps aux --sort=-%cpu | head -11 | tail -10 | awk '{printf "| %-20s | %-8s | %-8.1f | %-8.1f |\n", substr($11,1,20), $2, $3, $4}'
        draw_box 60

        # Services Status
        draw_section "Services Status"
        for svc in sshd nginx apache2 iptables; do
            if command -v systemctl >/dev/null 2>&1; then
                systemctl is-active --quiet $svc && state="[RUNNING]" || state="[STOPPED]"
            else
                pgrep -x $svc >/dev/null && state="[RUNNING]" || state="[STOPPED]"
            fi
            printf "| %-20s: %-33s |\n" "$svc" "$state"
        done
        draw_box 60
    fi

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
