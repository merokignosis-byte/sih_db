#!/bin/bash


MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/network"
ROLLBACK_SCRIPT="$SCRIPT_DIR/../rollback_network.bash"
MODULE_NAME="Network"

mkdir -p "$BACKUP_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0
MANUAL_CHECKS=0

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fixed() { echo -e "${BLUE}[FIXED]${NC} $1"; }

# ============================================================================
# Database Functions
# ============================================================================
init_database() {
    python3 -c "
import sqlite3
conn = sqlite3.connect('$DB_PATH')
cursor = conn.cursor()

# Create scan_results table
cursor.execute('''
CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    module_name TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_name TEXT NOT NULL,
    expected_value TEXT NOT NULL,
    current_value TEXT NOT NULL,
    status TEXT NOT NULL,
    scan_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(module_name, policy_id)
);
''')

# Create fix_history table
cursor.execute('''
CREATE TABLE IF NOT EXISTS fix_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    module_name TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_name TEXT NOT NULL,
    expected_value TEXT NOT NULL,
    original_value TEXT NOT NULL,
    current_value TEXT NOT NULL,
    status TEXT NOT NULL,
    fix_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    rollback_executed TEXT DEFAULT 'NO',
    UNIQUE(module_name, policy_id)
);
''')

conn.commit()
conn.close()
"
}

save_scan_result() {
    local policy_id="$1"
    local policy_name="$2"
    local expected_value="$3"
    local current_value="$4"
    local status="$5"

    python3 - <<EOF
import sqlite3
DB_PATH = "$DB_PATH"
MODULE_NAME = "$MODULE_NAME"

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()
cursor.execute("""
    INSERT OR REPLACE INTO scan_results
    (module_name, policy_id, policy_name, expected_value, current_value, status, scan_timestamp)
    VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
""", (MODULE_NAME, "$policy_id", "$policy_name", "$expected_value", "$current_value", "$status"))
conn.commit()
conn.close()
EOF
}

save_fix_result() {
    local policy_id="$1"
    local policy_name="$2"
    local expected_value="$3"
    local original_value="$4"
    local current_value="$5"
    local status="$6"

    python3 - <<EOF
import sqlite3
DB_PATH = "$DB_PATH"
MODULE_NAME = "$MODULE_NAME"
try:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS fix_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            module_name TEXT NOT NULL,
            policy_id TEXT NOT NULL,
            policy_name TEXT NOT NULL,
            expected_value TEXT NOT NULL,
            original_value TEXT NOT NULL,
            current_value TEXT NOT NULL,
            status TEXT NOT NULL,
            fix_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            rollback_executed TEXT DEFAULT 'NO',
            UNIQUE(module_name, policy_id)
        );
    ''')
    cursor.execute("""
        INSERT OR REPLACE INTO fix_history
        (module_name, policy_id, policy_name, expected_value, original_value, current_value, status, rollback_executed)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'NO')
    """, (MODULE_NAME, "$policy_id", "$policy_name", "$expected_value", "$original_value", "$current_value", "$status"))
    conn.commit()
    conn.close()
except Exception as e:
    print(f'Error updating fix_history: {e}')
EOF
}

# ============================================================================
# Print Results Like network.sh
# ============================================================================
print_check_result() {
    local policy_id="$1"
    local policy_name="$2"
    local expected="$3"
    local current="$4"
    local status="$5"

    echo "=============================================="
    echo "Module Name    : $MODULE_NAME"
    echo "Policy ID      : $policy_id"
    echo "Policy Name    : $policy_name"
    echo "Expected Value : $expected"
    echo "Current Value  : $current"
    if [[ "$status" == "PASS" ]]; then
        echo -e "Status         : ${GREEN}$status${NC}"
    elif [[ "$status" == "FAIL" ]]; then
        echo -e "Status         : ${RED}$status${NC}"
    else
        echo -e "Status         : ${YELLOW}$status${NC}"
    fi
    echo "=============================================="
}

# ============================================================================
# Network Device Checks
# ============================================================================
check_ipv6_status() {
    local policy_id="NET-1-a.i"
    local policy_name="Ensure IPv6 status is identified"
    local expected="IPv6 disabled"
    ((TOTAL_CHECKS++))

    local state
    state=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "unknown")

    local current
    local status

    if [ "$state" = "1" ]; then
        current="IPv6 disabled"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="IPv6 enabled (disable_ipv6=$state)"
        status="FAIL"
        ((FAILED_CHECKS++))
        if [ "$MODE" = "fix" ]; then
            sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null
            current="IPv6 disabled"
            status="PASS"
            ((FIXED_CHECKS++))
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    if [ "$MODE" = "scan" ]; then
    save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    fi
    if [ "$MODE" = "fix" ]; then
        save_fix_result "$policy_id" "$policy_name" "$expected" "IPv6=$state" "$current" "$status"
    fi
}

check_disable_wireless() {
    local policy_id="NET-1-a.ii"
    local policy_name="Ensure wireless interfaces are disabled"
    local expected="Wireless disabled"
    ((TOTAL_CHECKS++))

    local wifi_iface
    wifi_iface=$(iw dev 2>/dev/null | awk '/Interface/ {print $2}')

    local current
    local status

    if [ -z "$wifi_iface" ]; then
        current="No wireless interfaces detected"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        if ip link show "$wifi_iface" | grep -q "state DOWN"; then
            current="Wireless $wifi_iface is disabled"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="Wireless $wifi_iface is ENABLED"
            status="FAIL"
            ((FAILED_CHECKS++))
            if [ "$MODE" = "fix" ]; then
                ip link set "$wifi_iface" down
                current="Wireless $wifi_iface disabled"
                status="PASS"
                ((FIXED_CHECKS++))
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    if [ "$MODE" = "scan" ]; then
    save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    fi
    if [ "$MODE" = "fix" ]; then
        save_fix_result "$policy_id" "$policy_name" "$expected" "$current" "$current" "$status"
    fi
}

check_bluetooth() {
    local policy_id="NET-1-a.iii"
    local policy_name="Ensure Bluetooth service is not in use"
    local expected="Bluetooth disabled"
    ((TOTAL_CHECKS++))

    local enabled
    enabled=$(systemctl is-enabled bluetooth 2>/dev/null | head -n1)
    [ -z "$enabled" ] && enabled="none"

    local active
    active=$(systemctl is-active bluetooth 2>/dev/null | head -n1)
    [ -z "$active" ] && active="inactive"

    local loaded
    if lsmod | grep -q "^bluetooth"; then loaded="Yes"; else loaded="No"; fi

    local current status

    if [[ "$enabled" =~ ^(disabled|masked|static|indirect|none)$ ]] && [ "$active" = "inactive" ] && [ "$loaded" = "No" ]; then
        current="Bluetooth service disabled"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="Bluetooth service enabled or module loaded"
        status="FAIL"
        ((FAILED_CHECKS++))
        if [ "$MODE" = "fix" ]; then
            systemctl stop bluetooth >/dev/null 2>&1
            systemctl mask bluetooth >/dev/null 2>&1
            modprobe -r bluetooth >/dev/null 2>&1
            systemctl daemon-reload
            current="Bluetooth service disabled and module removed"
            status="PASS"
            ((FIXED_CHECKS++))
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    if [ "$MODE" = "scan" ]; then
    save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    fi
    if [ "$MODE" = "fix" ]; then
        save_fix_result "$policy_id" "$policy_name" "$expected" "${enabled}/${active}/${loaded}" "$current" "$status"
    fi
}

# ============================================================================
# Network Kernel Module Checks
# ============================================================================
disable_module_rule() {
    local module="$1"
    local policy_id="$2"
    local policy_name="$3"
    local expected="Module disabled"
    ((TOTAL_CHECKS++))

    local loaded
    if lsmod | grep -q "^$module"; then
        loaded="Yes"
    else
        loaded="No"
    fi

    local current="$loaded"
    local status

    if [ "$loaded" = "No" ]; then
        status="PASS"
        ((PASSED_CHECKS++))
    else
        status="FAIL"
        ((FAILED_CHECKS++))
        if [ "$MODE" = "fix" ]; then
            echo "install $module /bin/true" > /etc/modprobe.d/"$module".conf
            modprobe -r "$module" 2>/dev/null
            current="No"
            status="PASS"
            ((FIXED_CHECKS++))
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    if [ "$MODE" = "scan" ]; then
    save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    fi
    if [ "$MODE" = "fix" ]; then
        save_fix_result "$policy_id" "$policy_name" "$expected" "$loaded" "$current" "$status"
    fi
}

check_dccp() { disable_module_rule "dccp" "NET-1-b.i" "Ensure dccp kernel module is not available"; }
check_tipc() { disable_module_rule "tipc" "NET-1-b.ii" "Ensure tipc kernel module is not available"; }
check_rds()  { disable_module_rule "rds"  "NET-1-b.iii"  "Ensure rds kernel module is not available"; }
check_sctp() { disable_module_rule "sctp" "NET-1-b.iv" "Ensure sctp kernel module is not available"; }

# ============================================================================
# Sysctl Kernel Parameter Checks
# ============================================================================
sysctl_rule() {
    local policy_id="$1"
    local policy_name="$2"
    local key="$3"
    local expected_val="$4"
    ((TOTAL_CHECKS++))
    local current_val
    current_val=$(sysctl -n "$key" 2>/dev/null || echo "unknown")
    local status
    if [ "$current_val" = "$expected_val" ]; then
        status="PASS"
        ((PASSED_CHECKS++))
    else
        status="FAIL"
        ((FAILED_CHECKS++))
        if [ "$MODE" = "fix" ]; then
            sysctl -w "$key=$expected_val" >/dev/null
            if grep -q "^$key" /etc/sysctl.conf; then
                sed -i "s|^$key.*|$key = $expected_val|" /etc/sysctl.conf
            else
                echo "$key = $expected_val" >> /etc/sysctl.conf
            fi
            current_val="$expected_val"
            status="PASS"
            ((FIXED_CHECKS++))
        fi
    fi
    print_check_result "$policy_id" "$policy_name" "$expected_val" "$current_val" "$status"
    if [ "$MODE" = "scan" ]; then
        save_scan_result "$policy_id" "$policy_name" "$expected_val" "$current_val" "$status"
    fi

    if [ "$MODE" = "fix" ]; then
        save_fix_result "$policy_id" "$policy_name" "$expected_val" "$current_val" "$current_val" "$status"
    fi
}

check_ip_forwarding()            { sysctl_rule "NET-1-c.i"      "Ensure IP forwarding is disabled"             "net.ipv4.ip_forward" "0"; }
check_redirect_sending()         { sysctl_rule "NET-1-c.ii"    "Ensure packet redirect sending is disabled"   "net.ipv4.conf.all.send_redirects" "0"; }
check_bogus_icmp()               { sysctl_rule "NET-1-c.iii"    "Ensure bogus ICMP responses are ignored"      "net.ipv4.icmp_ignore_bogus_error_responses" "1"; }
check_broadcast_icmp()           { sysctl_rule "NET-1-c.iv"    "Ensure broadcast ICMP requests are ignored"   "net.ipv4.icmp_echo_ignore_broadcasts" "1"; }
check_icmp_redirects()           { sysctl_rule "NET-1-c.v"  "Ensure ICMP redirects are not accepted"       "net.ipv4.conf.all.accept_redirects" "0"; }
check_secure_redirects()         { sysctl_rule "NET-1-c.vi"   "Ensure secure ICMP redirects are not accepted" "net.ipv4.conf.all.secure_redirects" "0"; }
check_reverse_path_filter()      { sysctl_rule "NET-1-c.vii"      "Ensure reverse path filtering is enabled"      "net.ipv4.conf.all.rp_filter" "1"; }
check_source_routing()           { sysctl_rule "NET-1-c.viii"   "Ensure source routed packets are not accepted" "net.ipv4.conf.all.accept_source_route" "0"; }
check_log_martians()             { sysctl_rule "NET-1-c.ix"     "Ensure suspicious packets are logged"         "net.ipv4.conf.all.log_martians" "1"; }
check_syn_cookies()              { sysctl_rule "NET-1-c.x"     "Ensure TCP SYN cookies are enabled"           "net.ipv4.tcp_syncookies" "1"; }
check_ipv6_ra()                  { sysctl_rule "NET-1-c.xi"       "Ensure IPv6 router advertisements are not accepted" "net.ipv6.conf.all.accept_ra" "0"; }

# ============================================================================
# Main Execution
# ============================================================================
main() {
    echo "========================================================================"
    echo "Network Hardening Script"
    echo "Module: $MODULE_NAME"
    echo "Mode: $MODE"
    echo "========================================================================"

    init_database

    if [ "$MODE" = "fix" ] && [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root for fix mode"
        exit 1
    fi

    # a. Network Devices
    check_ipv6_status
    check_disable_wireless
    check_bluetooth

    # b. Network Kernel Modules
    check_dccp
    check_tipc
    check_rds
    check_sctp

    # c. Network Kernel Parameters
    check_ip_forwarding
    check_redirect_sending
    check_bogus_icmp
    check_broadcast_icmp
    check_icmp_redirects
    check_secure_redirects
    check_reverse_path_filter
    check_source_routing
    check_log_martians
    check_syn_cookies
    check_ipv6_ra

    # Summary
    echo ""
    echo "========================================================================"
    echo "Network Hardening Summary"
    echo "========================================================================"
    echo "Total Checks: $TOTAL_CHECKS"
    echo "Passed: $PASSED_CHECKS"
    echo "Failed: $FAILED_CHECKS"
    echo "Fixed:  $FIXED_CHECKS"
    echo "Manual Actions Required: $MANUAL_CHECKS"
    echo "========================================================================"
}

main

