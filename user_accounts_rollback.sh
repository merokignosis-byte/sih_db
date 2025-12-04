#!/bin/bash
# ============================================================================
# Rollback Script for User Accounts Module
# Compares fix_history with scan_results and reverts to original values
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/user_accounts"

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
SKIPPED_MANUAL=0

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

# Get fixes that need rollback (compare scan_results FAIL with fix_history FIXED)
get_rollback_items() {
    python3 << PYTHON_SCRIPT
import sqlite3, json, sys
try:
    conn = sqlite3.connect("$DB_PATH")
    cursor = conn.cursor()
    
    # Get all FIXED items from fix_history that haven't been rolled back
    cursor.execute("""
        SELECT fh.policy_id, fh.policy_name, fh.original_value, fh.current_value, fh.status,
               sr.status as scan_status
        FROM fix_history fh
        LEFT JOIN scan_results sr ON fh.policy_id = sr.policy_id 
            AND fh.module_name = sr.module_name
        WHERE fh.module_name='User Accounts and Environment' 
            AND fh.rollback_executed='NO'
            AND (fh.status='FIXED' OR fh.status='MANUAL')
        ORDER BY fh.policy_id
    """)
    
    fixes = cursor.fetchall()
    conn.close()
    
    for fix in fixes:
        print(json.dumps({
            "policy_id": fix[0],
            "policy_name": fix[1],
            "original_value": fix[2],
            "current_value": fix[3],
            "fix_status": fix[4],
            "scan_status": fix[5] if fix[5] else "UNKNOWN"
        }))
except sqlite3.Error as e:
    print(f"Database error: {e}", file=sys.stderr)
    sys.exit(1)
PYTHON_SCRIPT
}

# Mark rollback as executed
mark_rollback_executed() {
    local policy_id="$1"
    python3 - <<PYTHON_SCRIPT
import sqlite3
conn = sqlite3.connect("$DB_PATH")
cursor = conn.cursor()
cursor.execute("UPDATE fix_history SET rollback_executed='YES' WHERE module_name='User Accounts and Environment' AND policy_id=?", ("$policy_id",))
conn.commit()
conn.close()
PYTHON_SCRIPT
}

# Rollback individual policy
rollback_policy() {
    local policy_id="$1"
    local policy_name="$2"
    local original_value="$3"
    local current_value="$4"
    local fix_status="$5"
    local scan_status="$6"

    ((TOTAL_ROLLBACKS++))
    log_info "Rolling back: $policy_name ($policy_id)"
    log_info "Scan Status: $scan_status | Fix Status: $fix_status"
    
    # Skip manual fixes
    if [[ "$fix_status" == "MANUAL" ]]; then
        log_warn "MANUAL fix detected - skipping automatic rollback"
        log_warn "ACTION REQUIRED: Manually revert changes for $policy_name"
        ((SKIPPED_MANUAL++))
        mark_rollback_executed "$policy_id"
        return
    fi

    case "$policy_id" in
        "UA-7.a.i")
            # Password expiration
            if [ -f /etc/login.defs ]; then
                cp /etc/login.defs "$BACKUP_DIR/login.defs.rollback.$(date +%Y%m%d_%H%M%S)"
                if [ -n "$original_value" ] && [ "$original_value" != "not set" ]; then
                    sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t$original_value/" /etc/login.defs
                    log_success "Restored PASS_MAX_DAYS to $original_value"
                else
                    sed -i '/^PASS_MAX_DAYS/d' /etc/login.defs
                    log_success "Removed PASS_MAX_DAYS"
                fi
                ((SUCCESS_ROLLBACKS++))
                mark_rollback_executed "$policy_id"
            fi
            ;;
            
        "UA-7.a.ii")
            # Minimum password days
            if [ -f /etc/login.defs ]; then
                cp /etc/login.defs "$BACKUP_DIR/login.defs.rollback.$(date +%Y%m%d_%H%M%S)"
                if [ -n "$original_value" ] && [ "$original_value" != "not set" ]; then
                    sed -i "s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t$original_value/" /etc/login.defs
                    log_success "Restored PASS_MIN_DAYS to $original_value"
                else
                    sed -i '/^PASS_MIN_DAYS/d' /etc/login.defs
                    log_success "Removed PASS_MIN_DAYS"
                fi
                ((SUCCESS_ROLLBACKS++))
                mark_rollback_executed "$policy_id"
            fi
            ;;
            
        "UA-7.a.iii")
            # Password warning days
            if [ -f /etc/login.defs ]; then
                cp /etc/login.defs "$BACKUP_DIR/login.defs.rollback.$(date +%Y%m%d_%H%M%S)"
                if [ -n "$original_value" ] && [ "$original_value" != "not set" ]; then
                    sed -i "s/^PASS_WARN_AGE.*/PASS_WARN_AGE\t$original_value/" /etc/login.defs
                    log_success "Restored PASS_WARN_AGE to $original_value"
                else
                    sed -i '/^PASS_WARN_AGE/d' /etc/login.defs
                    log_success "Removed PASS_WARN_AGE"
                fi
                ((SUCCESS_ROLLBACKS++))
                mark_rollback_executed "$policy_id"
            fi
            ;;
            
        "UA-7.a.iv")
            # Password hashing algorithm
            if [ -f /etc/login.defs ]; then
                cp /etc/login.defs "$BACKUP_DIR/login.defs.rollback.$(date +%Y%m%d_%H%M%S)"
                if [ -n "$original_value" ] && [ "$original_value" != "not set" ]; then
                    sed -i "s/^ENCRYPT_METHOD.*/ENCRYPT_METHOD $original_value/" /etc/login.defs
                    log_success "Restored ENCRYPT_METHOD to $original_value"
                else
                    sed -i '/^ENCRYPT_METHOD/d' /etc/login.defs
                    log_success "Removed ENCRYPT_METHOD"
                fi
                ((SUCCESS_ROLLBACKS++))
                mark_rollback_executed "$policy_id"
            fi
            ;;
            
        "UA-7.a.v")
            # Inactive password lock
            if [ -n "$original_value" ] && [ "$original_value" != "not set" ]; then
                useradd -D -f "$original_value" >/dev/null 2>&1
                log_success "Restored inactive password lock to $original_value days"
            else
                useradd -D -f -1 >/dev/null 2>&1
                log_success "Disabled inactive password lock"
            fi
            ((SUCCESS_ROLLBACKS++))
            mark_rollback_executed "$policy_id"
            ;;
            
        "UA-7.a.vi")
            # Password change dates
            log_warn "Password change dates were reset - cannot automatically rollback"
            log_warn "Users affected: $original_value"
            ((SKIPPED_MANUAL++))
            mark_rollback_executed "$policy_id"
            ;;
            
        "UA-7.a.vii"|"UA-7.a.viii"|"UA-7.a.ix"|"UA-7.a.xi")
            # Manual policies - UID/GID checks and PATH integrity
            log_warn "MANUAL policy - no automatic rollback"
            ((SKIPPED_MANUAL++))
            mark_rollback_executed "$policy_id"
            ;;
            
        "UA-7.a.x")
            # Root SSH access
            if [ -f /etc/ssh/sshd_config ]; then
                cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.rollback.$(date +%Y%m%d_%H%M%S)"
                if [ -n "$original_value" ] && [ "$original_value" != "default" ]; then
                    if grep -q "^PermitRootLogin" /etc/ssh/sshd_config; then
                        sed -i "s/^PermitRootLogin.*/PermitRootLogin $original_value/" /etc/ssh/sshd_config
                    else
                        echo "PermitRootLogin $original_value" >> /etc/ssh/sshd_config
                    fi
                else
                    sed -i '/^PermitRootLogin/d' /etc/ssh/sshd_config
                fi
                systemctl reload sshd 2>/dev/null || service ssh reload 2>/dev/null
                log_success "Restored PermitRootLogin to $original_value"
                ((SUCCESS_ROLLBACKS++))
                mark_rollback_executed "$policy_id"
            fi
            ;;
            
        "UA-7.a.xii")
            # Root umask
            for file in /root/.bashrc /root/.bash_profile; do
                if [ -f "$file" ]; then
                    cp "$file" "$BACKUP_DIR/$(basename $file).rollback.$(date +%Y%m%d_%H%M%S)"
                    if [ -n "$original_value" ] && [ "$original_value" != "not set" ]; then
                        if grep -q "^umask" "$file"; then
                            sed -i "s/^umask.*/umask $original_value/" "$file"
                        else
                            echo "umask $original_value" >> "$file"
                        fi
                    else
                        sed -i '/^umask/d' "$file"
                    fi
                fi
            done
            log_success "Restored root umask configuration"
            ((SUCCESS_ROLLBACKS++))
            mark_rollback_executed "$policy_id"
            ;;
            
        "UA-7.a.xiii")
            # System accounts shell
            if [[ "$current_value" =~ ^fixed: ]]; then
                local accounts_to_restore=$(echo "$current_value" | sed 's/fixed: //')
                cp /etc/passwd "$BACKUP_DIR/passwd.rollback.$(date +%Y%m%d_%H%M%S)"
                
                log_warn "Restoring shell for system accounts: $accounts_to_restore"
                log_warn "Original shells were not recorded - setting to /bin/bash"
                
                for account in $accounts_to_restore; do
                    usermod -s /bin/bash "$account" 2>/dev/null
                done
                log_success "Restored shells for system accounts"
                ((SUCCESS_ROLLBACKS++))
                mark_rollback_executed "$policy_id"
            fi
            ;;
            
        "UA-7.a.xiv")
            # Unlock accounts without valid shell
            if [[ "$current_value" =~ ^locked: ]]; then
                local accounts_to_unlock=$(echo "$current_value" | sed 's/locked: //')
                cp /etc/shadow "$BACKUP_DIR/shadow.rollback.$(date +%Y%m%d_%H%M%S)"
                
                for account in $accounts_to_unlock; do
                    passwd -u "$account" >/dev/null 2>&1
                done
                log_success "Unlocked accounts: $accounts_to_unlock"
                ((SUCCESS_ROLLBACKS++))
                mark_rollback_executed "$policy_id"
            fi
            ;;
            
        "UA-7.b.i")
            # nologin in /etc/shells
            if [[ "$original_value" == "present" ]]; then
                cp /etc/shells "$BACKUP_DIR/shells.rollback.$(date +%Y%m%d_%H%M%S)"
                echo "/usr/sbin/nologin" >> /etc/shells
                echo "/sbin/nologin" >> /etc/shells
                log_success "Restored nologin to /etc/shells"
                ((SUCCESS_ROLLBACKS++))
                mark_rollback_executed "$policy_id"
            fi
            ;;
            
        "UA-7.b.ii")
            # Shell timeout
            if [ -f /etc/profile.d/tmout.sh ]; then
                rm -f /etc/profile.d/tmout.sh
                log_success "Removed shell timeout configuration"
                ((SUCCESS_ROLLBACKS++))
                mark_rollback_executed "$policy_id"
            fi
            ;;
            
        "UA-7.b.iii")
            # Default user umask
            if [ -f /etc/profile.d/umask.sh ]; then
                rm -f /etc/profile.d/umask.sh
                log_success "Removed default user umask configuration"
                ((SUCCESS_ROLLBACKS++))
                mark_rollback_executed "$policy_id"
            fi
            ;;
            
        *)
            log_warn "Unknown policy ID: $policy_id"
            ((FAILED_ROLLBACKS++))
            ;;
    esac
}

# Main rollback execution
main() {
    check_root
    check_database

    echo "========================================================================"
    echo "User Accounts Rollback Script"
    echo "========================================================================"
    echo ""

    local rollback_items
    rollback_items=$(get_rollback_items)

    if [ -z "$rollback_items" ]; then
        log_info "No User Accounts fixes pending rollback."
        exit 0
    fi

    echo "The following policies will be rolled back:"
    echo "$rollback_items" | python3 -c "import sys,json; [print(f\"  - {json.loads(line)['policy_id']}: {json.loads(line)['policy_name']}\") for line in sys.stdin]"
    echo ""
    read -p "Proceed with User Accounts rollback? (yes/no): " confirm
    if [[ "$confirm" != "yes" && "$confirm" != "y" ]]; then
        log_info "Rollback cancelled."
        exit 0
    fi
    echo ""

    while IFS= read -r item_json; do
        local policy_id=$(echo "$item_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['policy_id'])")
        local policy_name=$(echo "$item_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['policy_name'])")
        local original_value=$(echo "$item_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['original_value'])")
        local current_value=$(echo "$item_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['current_value'])")
        local fix_status=$(echo "$item_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['fix_status'])")
        local scan_status=$(echo "$item_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['scan_status'])")

        rollback_policy "$policy_id" "$policy_name" "$original_value" "$current_value" "$fix_status" "$scan_status"
        echo ""
    done <<< "$rollback_items"

    echo "========================================================================"
    echo "User Accounts Rollback Summary"
    echo "========================================================================"
    echo "Total Rollback Items: $TOTAL_ROLLBACKS"
    echo "Successfully Rolled Back: $SUCCESS_ROLLBACKS"
    echo "Manual Actions Required: $SKIPPED_MANUAL"
    echo "Failed: $FAILED_ROLLBACKS"
    echo "========================================================================"
    
    if [ $SKIPPED_MANUAL -gt 0 ]; then
        echo ""
        log_warn "Some policies require manual rollback. Review the output above."
    fi
}

main
