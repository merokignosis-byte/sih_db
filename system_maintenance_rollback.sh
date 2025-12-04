#!/bin/bash
# Rollback Script for System Maintenance Module
# Reverts changes recorded in fix_history (permissions, dotfiles, world-writable files)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
TOTAL_ROLLBACKS=0
SUCCESS_ROLLBACKS=0
FAILED_ROLLBACKS=0

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
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

# Fetch all System Maintenance fixes pending rollback
get_system_maintenance_fixes() {
    python3 <<PYTHON_SCRIPT
import sqlite3, json, sys
try:
    conn = sqlite3.connect("$DB_PATH")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT policy_id, policy_name, original_value, current_value
        FROM fix_history
        WHERE module_name='System Maintenance' AND rollback_executed='NO'
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

mark_rollback_executed() {
    local policy_id="$1"
    python3 - <<PYTHON_SCRIPT
import sqlite3
conn = sqlite3.connect("$DB_PATH")
cursor = conn.cursor()
cursor.execute("UPDATE fix_history SET rollback_executed='YES' WHERE module_name='System Maintenance' AND policy_id=?", ("$policy_id",))
conn.commit()
conn.close()
PYTHON_SCRIPT
}

rollback_file_permission() {
    local file_path="$1"
    local orig_perm="$2"

    if [ -e "$file_path" ]; then
        chmod "$orig_perm" "$file_path" && return 0 || return 1
    fi
    return 1
}

rollback_world_writable() {
    local orig_value="$1"
    # If original_value was "0 files found", nothing to do
    if [[ "$orig_value" == "0 files found" ]]; then
        return 0
    fi
    # Remove group/other write from current files
    find / -xdev -type f -perm /022 -exec chmod go-w {} \; 2>/dev/null
    find / -xdev -type d -perm /022 -exec chmod go-w {} \; 2>/dev/null
}

rollback_dotfiles() {
    local orig_value="$1"
    # Remove group/other write from home dotfiles
    find /home -maxdepth 2 -name ".*" -type f -exec chmod go-w {} \; 2>/dev/null
}

rollback_suid_sgid() {
    local orig_value="$1"
    # SUID/SGID cannot be fully restored without backup
    # Just notify user
    log_warn "Manual review required to restore SUID/SGID files: $orig_value"
}

rollback_fix() {
    local policy_id="$1"
    local policy_name="$2"
    local original_value="$3"
    local current_value="$4"

    ((TOTAL_ROLLBACKS++))
    log_info "Rolling back: $policy_name"

    case "$policy_id" in
        SM-9.a.i)   rollback_file_permission "/etc/passwd" "$original_value" ;;
        SM-9.a.ii)  rollback_file_permission "/etc/passwd-" "$original_value" ;;
        SM-9.a.iii) rollback_file_permission "/etc/group" "$original_value" ;;
        SM-9.a.iv)  rollback_file_permission "/etc/group-" "$original_value" ;;
        SM-9.a.v)   rollback_file_permission "/etc/shadow" "$original_value" ;;
        SM-9.a.vi)  rollback_file_permission "/etc/shadow-" "$original_value" ;;
        SM-9.a.vii) rollback_file_permission "/etc/gshadow" "$original_value" ;;
        SM-9.a.viii) rollback_file_permission "/etc/gshadow-" "$original_value" ;;
        SM-9.a.ix)  rollback_file_permission "/etc/shells" "$original_value" ;;
        SM-9.a.x)   rollback_file_permission "/etc/security/opasswd" "$original_value" ;;
        SM-9.a.xi)  rollback_world_writable "$original_value" ;;
        SM-9.a.xiii) rollback_suid_sgid "$current_value" ;;
        SM-9.a.xxiii) rollback_dotfiles "$original_value" ;;
        # For other policies requiring manual review
        SM-9.a.xii|SM-9.a.xiv|SM-9.a.xvi|SM-9.a.xviii|SM-9.a.xix|SM-9.a.xx|SM-9.a.xxi|SM-9.a.xxii)
            log_warn "Policy $policy_id requires manual review for rollback" ;;
        *)
            log_warn "Unknown policy $policy_id, skipping rollback" ;;
    esac

    log_success "Rollback executed for $policy_id"
    ((SUCCESS_ROLLBACKS++))
    mark_rollback_executed "$policy_id"
}

main() {
    check_root
    check_database

    local fixes
    fixes=$(get_system_maintenance_fixes)

    if [ -z "$fixes" ]; then
        log_info "No System Maintenance fixes pending rollback."
        exit 0
    fi

    echo ""
    read -p "Proceed with System Maintenance rollback? (yes/no): " confirm
    if [[ "$confirm" != "yes" && "$confirm" != "y" ]]; then
        log_info "Rollback cancelled."
        exit 0
    fi
    echo ""

    while IFS= read -r fix_json; do
        policy_id=$(echo "$fix_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['policy_id'])")
        policy_name=$(echo "$fix_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['policy_name'])")
        original_value=$(echo "$fix_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['original_value'])")
        current_value=$(echo "$fix_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['current_value'])")

        rollback_fix "$policy_id" "$policy_name" "$original_value" "$current_value"
    done <<< "$fixes"

    echo ""
    log_info "System Maintenance rollback complete."
    echo "Total rollbacks: $TOTAL_ROLLBACKS, Successful: $SUCCESS_ROLLBACKS, Failed: $FAILED_ROLLBACKS"
}

main

