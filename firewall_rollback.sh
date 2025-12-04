#!/bin/bash
# Rollback Script for Firewall Module
# Only reverts fixes recorded in fix_history

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/firewall"

mkdir -p "$BACKUP_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Counters
TOTAL_ROLLBACKS=0
SUCCESS_ROLLBACKS=0
FAILED_ROLLBACKS=0

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_database() {
    if [ ! -f "$DB_PATH" ]; then
        log_error "Database not found: $DB_PATH"
        exit 1
    fi
}

# Get firewall fixes pending rollback
get_firewall_fixes() {
    python3 << PYTHON_SCRIPT
import sqlite3, json, sys
try:
    conn = sqlite3.connect("$DB_PATH")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT policy_id, policy_name, original_value, current_value
        FROM fix_history
        WHERE module_name='Firewall' AND rollback_executed='NO'
        ORDER BY policy_id
    """)
    fixes = cursor.fetchall()
    conn.close()
    for fix in fixes:
        print(json.dumps({
            "policy_id": fix[0],
            "policy_name": fix[1],
            "original_value": fix[2],
            "current_value": fix[3]
        }))
except sqlite3.Error as e:
    print(f"Database error: {e}", file=sys.stderr)
    sys.exit(1)
PYTHON_SCRIPT
}

# Mark rollback executed
mark_rollback_executed() {
    local policy_id="$1"
    python3 - <<PYTHON_SCRIPT
import sqlite3
conn = sqlite3.connect("$DB_PATH")
cursor = conn.cursor()
cursor.execute("UPDATE fix_history SET rollback_executed='YES' WHERE module_name='Firewall' AND policy_id=?", ("$policy_id",))
conn.commit()
conn.close()
PYTHON_SCRIPT
}

# Rollback individual firewall fix
rollback_firewall_fix() {
    local policy_id="$1"
    local policy_name="$2"
    local original_value="$3"
    local current_value="$4"

    ((TOTAL_ROLLBACKS++))
    log_info "Rolling back: $policy_name"

    case "$policy_id" in
        "FW-1-a.vi"|"FW-1-b.vi"|"FW-1-c.vi"|"FW-1-d.vi"|"FW-1-e.vi"|"FW-1-f.vi"|"FW-1-g.vi"|"FW-1-h.vi")
            # We assume original_value contains either "allow" or "deny" for UFW rules
            # Remove current rule first
            if [[ -n "$current_value" ]]; then
                ufw delete "$current_value" >/dev/null 2>&1
            fi

            # Restore original rule if exists
            if [[ -n "$original_value" ]]; then
                ufw allow "$original_value" >/dev/null 2>&1 || ufw deny "$original_value" >/dev/null 2>&1
            fi

            log_success "Rollback applied for $policy_id"
            ((SUCCESS_ROLLBACKS++))
            mark_rollback_executed "$policy_id"
            ;;
        *)
            log_warn "Unknown firewall policy ID: $policy_id"
            ((FAILED_ROLLBACKS++))
            ;;
    esac
}

# Main rollback
main() {
    check_root
    check_database

    local fixes
    fixes=$(get_firewall_fixes)

    if [ -z "$fixes" ]; then
        log_info "No Firewall fixes pending rollback."
        exit 0
    fi

    echo ""
    read -p "Proceed with Firewall rollback? (yes/no): " confirm
    if [[ "$confirm" != "yes" && "$confirm" != "y" ]]; then
        log_info "Rollback cancelled."
        exit 0
    fi
    echo ""

    while IFS= read -r fix_json; do
        local policy_id=$(echo "$fix_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['policy_id'])")
        local policy_name=$(echo "$fix_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['policy_name'])")
        local original_value=$(echo "$fix_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['original_value'])")
        local current_value=$(echo "$fix_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['current_value'])")

        rollback_firewall_fix "$policy_id" "$policy_name" "$original_value" "$current_value"
    done <<< "$fixes"

    echo ""
    log_info "Firewall rollback complete."
    echo "Total rollbacks: $TOTAL_ROLLBACKS, Successful: $SUCCESS_ROLLBACKS, Failed: $FAILED_ROLLBACKS"

    # Reload UFW to apply changes
    ufw reload >/dev/null 2>&1
    log_info "UFW reloaded"
}

main

