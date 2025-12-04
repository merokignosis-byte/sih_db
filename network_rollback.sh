#!/bin/bash
# Network Hardening Rollback Script
# Uniform with Filesystem rollback

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/network"
MODULE_NAME="Network"

mkdir -p "$BACKUP_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
TOTAL_ROLLBACKS=0
SUCCESS_ROLLBACKS=0
FAILED_ROLLBACKS=0

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Run as root"
        exit 1
    fi
}

check_database() {
    if [ ! -f "$DB_PATH" ]; then
        log_error "Database not found at $DB_PATH"
        exit 1
    fi
}

# Fetch fixes for Network module
get_fixes() {
    python3 - <<PY
import sqlite3, json
conn = sqlite3.connect("$DB_PATH")
cur = conn.cursor()
cur.execute("SELECT policy_id, policy_name, original_value, current_value FROM fix_history WHERE module_name='Network' AND rollback_executed='NO'")
rows = cur.fetchall()
for r in rows:
    print(json.dumps({"policy_id": r[0], "policy_name": r[1], "original_value": r[2], "current_value": r[3]}))
conn.close()
PY
}

mark_rollback_executed() {
    local policy_id="$1"
    python3 - <<PY
import sqlite3
conn = sqlite3.connect("$DB_PATH")
cur = conn.cursor()
cur.execute("UPDATE fix_history SET rollback_executed='YES' WHERE module_name='Network' AND policy_id=?", ("$policy_id",))
conn.commit()
conn.close()
PY
}

rollback_sysctl() {
    local policy_id="$1"
    local key="$2"
    local original="$3"

    ((TOTAL_ROLLBACKS++))
    log_info "Rolling back sysctl $key"

    if sysctl -n "$key" &>/dev/null; then
        sysctl -w "$key=$original" &>/dev/null
        sed -i "s|^$key.*|$key = $original|" /etc/sysctl.conf 2>/dev/null || echo "$key = $original" >> /etc/sysctl.conf
        log_success "Restored $key to $original"
        ((SUCCESS_ROLLBACKS++))
        mark_rollback_executed "$policy_id"
    else
        log_warn "Sysctl key $key not found"
        ((FAILED_ROLLBACKS++))
    fi
}

rollback_module() {
    local policy_id="$1"
    local module="$2"

    ((TOTAL_ROLLBACKS++))
    log_info "Rolling back kernel module $module"

    local conf_file="/etc/modprobe.d/${module}.conf"
    if [ -f "$conf_file" ]; then
        rm -f "$conf_file"
        modprobe -r "$module" &>/dev/null
        log_success "Removed module disable config for $module"
        ((SUCCESS_ROLLBACKS++))
        mark_rollback_executed "$policy_id"
    else
        log_warn "$module config not found, skipping"
        ((FAILED_ROLLBACKS++))
    fi
}

rollback_ipv6() {
    local policy_id="$1"
    log_info "Rolling back IPv6"

    sysctl -w net.ipv6.conf.all.disable_ipv6=0 &>/dev/null
    sed -i "s|^net.ipv6.conf.all.disable_ipv6.*|net.ipv6.conf.all.disable_ipv6 = 0|" /etc/sysctl.conf 2>/dev/null || echo "net.ipv6.conf.all.disable_ipv6 = 0" >> /etc/sysctl.conf
    log_success "IPv6 restored"
    ((SUCCESS_ROLLBACKS++))
    mark_rollback_executed "$policy_id"
}

rollback_wireless() {
    local policy_id="$1"
    log_info "Rolling back wireless interfaces"

    local iface
    iface=$(iw dev 2>/dev/null | awk '/Interface/ {print $2}')
    if [ -n "$iface" ]; then
        ip link set "$iface" up
        log_success "Wireless interface $iface enabled"
    else
        log_warn "No wireless interface found"
    fi
    ((SUCCESS_ROLLBACKS++))
    mark_rollback_executed "$policy_id"
}

rollback_bluetooth() {
    local policy_id="$1"
    log_info "Rolling back Bluetooth service"

    systemctl enable bluetooth >/dev/null 2>&1
    systemctl start bluetooth >/dev/null 2>&1
    log_success "Bluetooth restored"
    ((SUCCESS_ROLLBACKS++))
    mark_rollback_executed "$policy_id"
}

# Preview fixes
list_rollback_items() {
    echo "=========================================="
    echo "Items to be rolled back:"
    echo "=========================================="
    get_fixes
    echo "=========================================="
}

display_summary() {
    echo "=========================================="
    echo "Rollback Summary"
    echo "Total Rollbacks: $TOTAL_ROLLBACKS"
    echo "Successful: $SUCCESS_ROLLBACKS"
    echo "Failed: $FAILED_ROLLBACKS"
    echo "=========================================="
}

main() {
    echo "========================================================================"
    echo "Network Hardening Rollback Script"
    echo "========================================================================"

    check_root
    check_database

    list_rollback_items

    read -p "Do you want to proceed with rollback? (yes/no): " confirm
    [[ "$confirm" != "yes" && "$confirm" != "y" ]] && { log_info "Cancelled"; exit 0; }

    # Iterate fixes
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        policy_id=$(echo "$line" | python3 -c "import sys, json; print(json.load(sys.stdin)['policy_id'])")
        policy_name=$(echo "$line" | python3 -c "import sys, json; print(json.load(sys.stdin)['policy_name'])")
        original=$(echo "$line" | python3 -c "import sys, json; print(json.load(sys.stdin)['original_value'])")
        current=$(echo "$line" | python3 -c "import sys, json; print(json.load(sys.stdin)['current_value'])")

        case "$policy_name" in
            *IPv6*) rollback_ipv6 "$policy_id" ;;
            *wireless*) rollback_wireless "$policy_id" ;;
            *Bluetooth*) rollback_bluetooth "$policy_id" ;;
            *kernel\ module*|*dccp*|*tipc*|*rds*|*sctp*) rollback_module "$policy_id" "$(echo $policy_name | awk '{print $NF}')" ;;
            *net.ipv4*|*net.ipv6*) rollback_sysctl "$policy_id" "$(echo $policy_name | awk '{print $NF}')" "$original" ;;
            *) log_warn "Unknown fix: $policy_name"; ((FAILED_ROLLBACKS++)) ;;
        esac
    done <<< "$(get_fixes)"

    display_summary

    log_info "Rollback completed. Some changes may require reboot."
}

main

