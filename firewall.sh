#!/bin/bash
# ============================================================================
# Firewall Hardening Script
# Module: Firewall
# Modes: scan | fix | rollback
# ============================================================================
MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/firewall"
MODULE_NAME="Firewall"

mkdir -p "$BACKUP_DIR"

# ============================================================================
# Colors for output
# ============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ============================================================================
# Counters
# ============================================================================
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0
MANUAL_CHECKS=0

# ============================================================================
# Logging Functions
# ============================================================================
log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fixed() { echo -e "${BLUE}[FIXED]${NC} $1"; }

# ============================================================================
# Database Functions
# ============================================================================
init_database() {
    python3 - <<EOF
import sqlite3
conn = sqlite3.connect('$DB_PATH')
cursor = conn.cursor()
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
)
''')
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
)
''')
conn.commit()
conn.close()
EOF
}

save_scan_result() {
    local policy_id="$1"
    local policy_name="$2"
    local expected="$3"
    local current="$4"
    local status="$5"

    python3 - <<EOF
import sqlite3
conn = sqlite3.connect('$DB_PATH')
cursor = conn.cursor()
cursor.execute("""
    INSERT OR REPLACE INTO scan_results
    (module_name, policy_id, policy_name, expected_value, current_value, status, scan_timestamp)
    VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
""", ('$MODULE_NAME', '$policy_id', '$policy_name', '$expected', '$current', '$status'))
conn.commit()
conn.close()
EOF
}

save_fix_result() {
    local policy_id="$1"
    local policy_name="$2"
    local expected="$3"
    local original="$4"
    local current="$5"
    local status="$6"

    python3 - <<EOF
import sqlite3, sys
conn = sqlite3.connect('$DB_PATH')
cursor = conn.cursor()
original_esc = repr("""$original""")
current_esc = repr("""$current""")
cursor.execute("""
    INSERT OR REPLACE INTO fix_history
    (module_name, policy_id, policy_name, expected_value, original_value, current_value, status, rollback_executed)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'NO')
""", ('$MODULE_NAME', '$policy_id', '$policy_name', '$expected', eval(original_esc), eval(current_esc), '$status'))
conn.commit()
conn.close()
EOF
}

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
# Firewall Checks
# ============================================================================
check_ufw_installed() {
    local policy_id="FW-1-a.i"
    local policy_name="Ensure ufw is installed"
    local expected="ufw installed"
    ((TOTAL_CHECKS++))

    local current status
    if command -v ufw >/dev/null 2>&1; then
        current="ufw installed"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="ufw not installed"
        status="FAIL"
        ((FAILED_CHECKS++))
        if [[ "$MODE" == "fix" ]]; then
            apt-get update -y >/dev/null
            apt-get install -y ufw >/dev/null
            current="ufw installed"
            status="PASS"
            ((FIXED_CHECKS++))
        fi
    fi
    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "not installed" "$current" "$status"
}

check_no_iptables_persistent() {
    local policy_id="FW-1-a.ii"
    local policy_name="Ensure iptables-persistent is not installed with ufw"
    local expected="Not installed"
    ((TOTAL_CHECKS++))

    local installed="no"
    dpkg -l | grep -q "^ii  iptables-persistent" && installed="yes"

    local current status
    if [[ "$installed" == "no" ]]; then
        current="Not installed"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="Installed"
        status="FAIL"
        ((FAILED_CHECKS++))
        if [[ "$MODE" == "fix" ]]; then
            apt-get purge -y iptables-persistent >/dev/null
            current="Removed"
            status="PASS"
            ((FIXED_CHECKS++))
        fi
    fi
    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Installed" "$current" "$status"
}

check_ufw_enabled() {
    local policy_id="FW-1-a.iii"
    local policy_name="Ensure ufw service is enabled"
    local expected="ufw enabled"
    ((TOTAL_CHECKS++))

    local current status
    if systemctl is-active ufw >/dev/null 2>&1; then
        current="Active"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="Inactive"
        status="FAIL"
        ((FAILED_CHECKS++))
        if [[ "$MODE" == "fix" ]]; then
            systemctl enable ufw >/dev/null
            systemctl start ufw >/dev/null
            ufw --force enable >/dev/null
            current="Active"
            status="PASS"
            ((FIXED_CHECKS++))
        fi
    fi
    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Disabled" "$current" "$status"
}

check_ufw_loopback() {
    local policy_id="FW-1-a.iv"
    local policy_name="Ensure ufw loopback traffic is configured"
    local expected="Loopback allowed"
    ((TOTAL_CHECKS++))

    local snapshot
    snapshot=$(ufw status verbose 2>/dev/null)
    local current status

    if echo "$snapshot" | grep -qE "ALLOW IN.*(lo|127\.0\.0\.1)" && \
       echo "$snapshot" | grep -qE "ALLOW OUT.*(lo|127\.0\.0\.1)"; then
        current="Configured"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="Not configured"
        status="FAIL"
        ((FAILED_CHECKS++))
        if [[ "$MODE" == "fix" ]]; then
            ufw allow in on lo >/dev/null
            ufw allow out on lo >/dev/null
            ufw allow in from 127.0.0.1 >/dev/null
            ufw allow out to 127.0.0.1 >/dev/null
            ufw reload >/dev/null
            current="Configured"
            status="PASS"
            ((FIXED_CHECKS++))
        fi
    fi
    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not Configured" "$current" "$status"
}

check_ufw_outbound() {
    local policy_id="FW-1-a.v"
    local policy_name="Ensure ufw outbound connections are allowed"
    local expected="Default allow outgoing"
    ((TOTAL_CHECKS++))

    local snapshot current status
    snapshot=$(ufw status verbose 2>/dev/null)

    if echo "$snapshot" | grep -q "Default: deny (incoming), allow (outgoing)"; then
        current="allow"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "Default outbound policy is allow"
    else
        current="not allow"
        status="FAIL"
        ((FAILED_CHECKS++))
        if [[ "$MODE" == "fix" ]]; then
            ufw default allow outgoing >/dev/null
            ufw reload >/dev/null
            current="allow"
            status="PASS"
            ((FIXED_CHECKS++))
            log_fixed "Set default outbound policy to allow"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not Configured" "$current" "$status"
}

check_ufw_rules_for_open_ports() {
    local policy_id="FW-1-a.vi"
    local policy_name="Ensure UFW firewall rules exist for all open ports"
    local expected="UFW rules applied for all open ports"
    ((TOTAL_CHECKS++))

    echo -e "\nChecking: $policy_name\nRule ID: $policy_id"

    local snapshot ports missing=0
    snapshot=$(ufw status verbose 2>/dev/null)
    ports=$(ss -tunl | awk 'NR>1 {gsub(/.*:/,"",$5); print $5}' | sort -u)

    for p in $ports; do
        if ! echo "$snapshot" | grep -q "$p/tcp"; then
            log_warn "Adding missing UFW TCP rule for port: $p"
            ufw allow "$p"/tcp >/dev/null 2>&1 && log_info "Added TCP rule for port: $p"
            missing=1
        fi
        if ! echo "$snapshot" | grep -q "$p/udp"; then
            log_warn "Adding missing UFW UDP rule for port: $p"
            ufw allow "$p"/udp >/dev/null 2>&1 && log_info "Added UDP rule for port: $p"
            missing=1
        fi
    done

    if [[ $missing -eq 1 ]]; then
        ufw reload >/dev/null
        log_info "UFW reloaded after adding missing rules."
    fi

    local current status
    if [[ $missing -eq 1 ]]; then
        current="Missing rules were added automatically"
        status="PASS"
        ((FIXED_CHECKS++))
        log_fixed "$current"
    else
        current="All open ports have UFW rules"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "$current"
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"

    # SAVE ONLY THE SHORT SUMMARY, NEVER $snapshot
    if [[ "$MODE" == "scan" ]]; then
        save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    elif [[ "$MODE" == "fix" ]]; then
        save_fix_result "$policy_id" "$policy_name" "$expected" "Not configured / missing" "$current" "$status"
    fi
}

check_ufw_default_deny() {
    local policy_id="FW-1-a.vii"
    local policy_name="Ensure ufw default deny firewall policy"
    local expected="Default deny incoming, allow outgoing"
    ((TOTAL_CHECKS++))

    local default_in
    default_in=$(ufw status verbose 2>/dev/null | awk '/Default:/ {print $2}')
    local current status
    if [[ "$default_in" == "deny" ]]; then
        current="Configured"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="Not configured"
        status="FAIL"
        ((FAILED_CHECKS++))
        if [[ "$MODE" == "fix" ]]; then
            ufw default deny incoming >/dev/null
            ufw default allow outgoing >/dev/null
            ufw reload >/dev/null
            current="Configured"
            status="PASS"
            ((FIXED_CHECKS++))
        fi
    fi
    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not configured" "$current" "$status"
}

check_ufw_no_iptables_conflict() {
    local policy_id="FW-1-a.viii"
    local policy_name="Ensure ufw is not in use with iptables"
    local expected="No conflict"
    ((TOTAL_CHECKS++))

    local current status
    if iptables -L | grep -q "ACCEPT" && ! ufw status | grep -q "active"; then
        current="Conflict detected"
        status="FAIL"
        ((FAILED_CHECKS++))
    else
        current="No conflict"
        status="PASS"
        ((PASSED_CHECKS++))
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "$current" "$current" "$status"
}

# ============================================================================
# Main Execution
# ============================================================================
main() {
    echo "========================================================================"
    echo "Firewall Hardening Script"
    echo "Module: $MODULE_NAME"
    echo "Mode: $MODE"
    echo "========================================================================"

    init_database

    if [[ "$MODE" == "fix" ]] && [[ "$EUID" -ne 0 ]]; then
        log_error "This script must be run as root for fix mode"
        exit 1
    fi

    # Execute all 8 rules
    check_ufw_installed
    check_no_iptables_persistent
    check_ufw_enabled
    check_ufw_loopback
    check_ufw_outbound
    check_ufw_rules_for_open_ports
    check_ufw_default_deny
    check_ufw_no_iptables_conflict

    # Summary
    echo ""
    echo "========================================================================"
    echo "Firewall Hardening Summary"
    echo "========================================================================"
    echo "Total Checks: $TOTAL_CHECKS"
    echo "Passed: $PASSED_CHECKS"
    echo "Failed: $FAILED_CHECKS"
    echo "Fixed:  $FIXED_CHECKS"
    echo "Manual Actions Required: $MANUAL_CHECKS"
    echo "========================================================================"
}

main

