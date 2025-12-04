#!/bin/bash
# ============================================================================
# Rollback Script for Access Control Module
# Only reverts fixes recorded in fix_history table
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/access_control"
MODULE_NAME="Access Control"

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
TOTAL_ROLLBACKS=0
SUCCESS_ROLLBACKS=0
FAILED_ROLLBACKS=0

# ============================================================================
# Logging Functions
# ============================================================================
log_info()    { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

# ============================================================================
# Privilege Check
# ============================================================================
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# ============================================================================
# Database Check
# ============================================================================
check_database() {
    if [ ! -f "$DB_PATH" ]; then
        log_error "Database not found: $DB_PATH"
        exit 1
    fi
}

# ============================================================================
# Get Pending Rollbacks
# ============================================================================
get_pending_rollbacks() {
    python3 <<PYTHON_SCRIPT
import sqlite3, json, sys
try:
    conn = sqlite3.connect("$DB_PATH")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT policy_id, policy_name, original_value, current_value
        FROM fix_history
        WHERE module_name='$MODULE_NAME' AND rollback_executed='NO'
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

# ============================================================================
# Mark Rollback Executed
# ============================================================================
mark_rollback_executed() {
    local policy_id="$1"
    python3 - <<PYTHON_SCRIPT
import sqlite3
conn = sqlite3.connect("$DB_PATH")
cursor = conn.cursor()
cursor.execute("UPDATE fix_history SET rollback_executed='YES' WHERE module_name='$MODULE_NAME' AND policy_id=?", ("$policy_id",))
conn.commit()
conn.close()
PYTHON_SCRIPT
}

# ============================================================================
# Rollback SSH Configuration
# ============================================================================
rollback_ssh_config() {
    local policy_id="$1"
    local policy_name="$2"
    local original_value="$3"
    local current_value="$4"

    ((TOTAL_ROLLBACKS++))
    log_info "Rolling back: $policy_name"

    case "$policy_id" in
        AC-6.a.i)
            # Restore SSH config permissions
            if [ -f /etc/ssh/sshd_config ]; then
                local orig_perms=$(echo "$original_value" | awk '{print $1}')
                local orig_owner=$(echo "$original_value" | awk '{print $2}' | cut -d: -f1)
                local orig_group=$(echo "$original_value" | awk '{print $2}' | cut -d: -f2)
                
                if [ -n "$orig_perms" ] && [ -n "$orig_owner" ] && [ -n "$orig_group" ]; then
                    chmod "$orig_perms" /etc/ssh/sshd_config 2>/dev/null
                    chown "$orig_owner:$orig_group" /etc/ssh/sshd_config 2>/dev/null
                    log_success "Restored SSH config permissions"
                    ((SUCCESS_ROLLBACKS++))
                fi
            fi
            mark_rollback_executed "$policy_id"
            ;;
            
        AC-6.a.ii|AC-6.a.iii)
            # SSH key permissions - restore from backup if needed
            log_warn "SSH key permissions rollback requires manual verification"
            ((SUCCESS_ROLLBACKS++))
            mark_rollback_executed "$policy_id"
            ;;
            
        AC-6.a.*)
            # SSH parameters - restore from backup
            local latest_backup=$(ls -t "$BACKUP_DIR"/sshd_config.* 2>/dev/null | head -1)
            if [ -n "$latest_backup" ] && [ -f "$latest_backup" ]; then
                cp "$latest_backup" /etc/ssh/sshd_config
                log_success "Restored SSH configuration from backup"
                ((SUCCESS_ROLLBACKS++))
            else
                log_warn "No SSH config backup found for $policy_id"
                ((FAILED_ROLLBACKS++))
            fi
            mark_rollback_executed "$policy_id"
            ;;
            
        *)
            log_warn "Unknown SSH policy: $policy_id"
            ((FAILED_ROLLBACKS++))
            ;;
    esac
}

# ============================================================================
# Rollback Sudo Configuration
# ============================================================================
rollback_sudo_config() {
    local policy_id="$1"
    local policy_name="$2"
    local original_value="$3"
    local current_value="$4"

    ((TOTAL_ROLLBACKS++))
    log_info "Rolling back: $policy_name"

    case "$policy_id" in
        AC-6.b.i)
            # Sudo installed - check if it was originally not installed
            if [ "$original_value" = "not installed" ]; then
                apt-get remove -y sudo >/dev/null 2>&1
                log_success "Removed sudo (was not originally installed)"
                ((SUCCESS_ROLLBACKS++))
            else
                log_info "Sudo was originally installed, keeping it"
                ((SUCCESS_ROLLBACKS++))
            fi
            mark_rollback_executed "$policy_id"
            ;;
            
        AC-6.b.ii|AC-6.b.iii|AC-6.b.vi)
            # Sudo configurations - remove from hardening file
            if [ -f /etc/sudoers.d/hardening ]; then
                case "$policy_id" in
                    AC-6.b.ii) sed -i '/use_pty/d' /etc/sudoers.d/hardening 2>/dev/null ;;
                    AC-6.b.iii) sed -i '/logfile=/d' /etc/sudoers.d/hardening 2>/dev/null ;;
                    AC-6.b.vi) sed -i '/timestamp_timeout/d' /etc/sudoers.d/hardening 2>/dev/null ;;
                esac
                log_success "Removed sudo hardening configuration"
                ((SUCCESS_ROLLBACKS++))
            fi
            
            # Restore from backup if exists
            local latest_backup=$(ls -t "$BACKUP_DIR"/sudoers.* 2>/dev/null | head -1)
            if [ -n "$latest_backup" ]; then
                cp "$latest_backup" /etc/sudoers
                log_success "Restored sudoers from backup"
            fi
            mark_rollback_executed "$policy_id"
            ;;
            
        AC-6.b.vii)
            # SU restriction
            local backup=$(ls -t "$BACKUP_DIR"/su.* 2>/dev/null | head -1)
            if [ -n "$backup" ]; then
                cp "$backup" /etc/pam.d/su
                log_success "Restored su configuration from backup"
                ((SUCCESS_ROLLBACKS++))
            else
                sed -i '/pam_wheel.so/d' /etc/pam.d/su 2>/dev/null
                log_success "Removed su restrictions"
                ((SUCCESS_ROLLBACKS++))
            fi
            mark_rollback_executed "$policy_id"
            ;;
            
        AC-6.b.iv|AC-6.b.v)
            # Manual review items - no automatic rollback
            log_info "Manual configuration - no automatic rollback needed"
            ((SUCCESS_ROLLBACKS++))
            mark_rollback_executed "$policy_id"
            ;;
            
        *)
            log_warn "Unknown sudo policy: $policy_id"
            ((FAILED_ROLLBACKS++))
            ;;
    esac
}

# ============================================================================
# Rollback PAM Configuration
# ============================================================================
rollback_pam_config() {
    local policy_id="$1"
    local policy_name="$2"
    local original_value="$3"
    local current_value="$4"

    ((TOTAL_ROLLBACKS++))
    log_info "Rolling back: $policy_name"

    case "$policy_id" in
        AC-6.c.i.1)
            # PAM version - no rollback needed
            log_info "PAM version update - no rollback needed"
            ((SUCCESS_ROLLBACKS++))
            mark_rollback_executed "$policy_id"
            ;;
            
        AC-6.c.i.2|AC-6.c.i.3)
            # PAM packages - check if originally not installed
            local package=""
            case "$policy_id" in
                AC-6.c.i.2) package="libpam-modules" ;;
                AC-6.c.i.3) package="libpam-pwquality" ;;
            esac
            
            if [ "$original_value" = "not installed" ] && [ -n "$package" ]; then
                apt-get remove -y "$package" >/dev/null 2>&1
                log_success "Removed $package (was not originally installed)"
                ((SUCCESS_ROLLBACKS++))
            else
                log_info "$package was originally installed, keeping it"
                ((SUCCESS_ROLLBACKS++))
            fi
            mark_rollback_executed "$policy_id"
            ;;
            
        AC-6.c.ii.*)
            # PAM module enablement - restore from backup
            local backup_pwd=$(ls -t "$BACKUP_DIR"/common-password.* 2>/dev/null | head -1)
            if [ -n "$backup_pwd" ]; then
                cp "$backup_pwd" /etc/pam.d/common-password
                log_success "Restored /etc/pam.d/common-password"
                ((SUCCESS_ROLLBACKS++))
            fi
            mark_rollback_executed "$policy_id"
            ;;
            
        AC-6.c.iii.*|AC-6.c.iv.*|AC-6.c.v.*)
            # PAM configurations - restore from backups
            local pwquality_backup=$(ls -t "$BACKUP_DIR"/pwquality.conf.* 2>/dev/null | head -1)
            local common_pwd_backup=$(ls -t "$BACKUP_DIR"/common-password.* 2>/dev/null | head -1)
            local common_auth_backup=$(ls -t "$BACKUP_DIR"/common-auth.* 2>/dev/null | head -1)
            local common_acc_backup=$(ls -t "$BACKUP_DIR"/common-account.* 2>/dev/null | head -1)
            
            if [ -n "$pwquality_backup" ] && [ -f /etc/security/pwquality.conf ]; then
                cp "$pwquality_backup" /etc/security/pwquality.conf
                log_success "Restored pwquality.conf"
            fi
            
            if [ -n "$common_pwd_backup" ]; then
                cp "$common_pwd_backup" /etc/pam.d/common-password
                log_success "Restored common-password"
            fi
            
            if [ -n "$common_auth_backup" ]; then
                cp "$common_auth_backup" /etc/pam.d/common-auth
                log_success "Restored common-auth"
            fi
            
            if [ -n "$common_acc_backup" ]; then
                cp "$common_acc_backup" /etc/pam.d/common-account
                log_success "Restored common-account"
            fi
            
            ((SUCCESS_ROLLBACKS++))
            mark_rollback_executed "$policy_id"
            ;;
            
        *)
            log_warn "Unknown PAM policy: $policy_id"
            ((FAILED_ROLLBACKS++))
            ;;
    esac
}

# ============================================================================
# Route Rollback to Appropriate Handler
# ============================================================================
rollback_fix() {
    local policy_id="$1"
    local policy_name="$2"
    local original_value="$3"
    local current_value="$4"

    # Determine which section the policy belongs to
    if [[ "$policy_id" == AC-6.a.* ]]; then
        rollback_ssh_config "$policy_id" "$policy_name" "$original_value" "$current_value"
    elif [[ "$policy_id" == AC-6.b.* ]]; then
        rollback_sudo_config "$policy_id" "$policy_name" "$original_value" "$current_value"
    elif [[ "$policy_id" == AC-6.c.* ]]; then
        rollback_pam_config "$policy_id" "$policy_name" "$original_value" "$current_value"
    else
        log_warn "Unknown policy ID format: $policy_id"
        ((FAILED_ROLLBACKS++))
    fi
}

# ============================================================================
# Main Rollback
# ============================================================================
main() {
    check_root
    check_database

    echo "========================================================================"
    echo "           Access Control Rollback Script"
    echo "========================================================================"
    echo "Module     : $MODULE_NAME"
    echo "Database   : $DB_PATH"
    echo "Backup Dir : $BACKUP_DIR"
    echo "========================================================================"
    echo ""

    local fixes
    fixes=$(get_pending_rollbacks)

    if [ -z "$fixes" ]; then
        log_info "No Access Control fixes pending rollback."
        exit 0
    fi

    # Count pending rollbacks
    local pending_count=$(echo "$fixes" | wc -l)
    echo "Found $pending_count fix(es) to rollback"
    echo ""
    
    log_warn "╔════════════════════════════════════════════════════════════╗"
    log_warn "║         This will restore original configurations          ║"
    log_warn "║         from backups and database records                  ║"
    log_warn "╚════════════════════════════════════════════════════════════╝"
    echo ""
    
    read -p "Proceed with Access Control rollback? (yes/no): " confirm
    if [[ "$confirm" != "yes" && "$confirm" != "y" ]]; then
        log_info "Rollback cancelled."
        exit 0
    fi
    echo ""

    # Process each fix
    while IFS= read -r fix_json; do
        if [ -n "$fix_json" ]; then
            local policy_id=$(echo "$fix_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['policy_id'])")
            local policy_name=$(echo "$fix_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['policy_name'])")
            local original_value=$(echo "$fix_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['original_value'])")
            local current_value=$(echo "$fix_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['current_value'])")

            rollback_fix "$policy_id" "$policy_name" "$original_value" "$current_value"
        fi
    done <<< "$fixes"

    echo ""
    echo "========================================================================"
    echo "                    ROLLBACK SUMMARY"
    echo "========================================================================"
    echo "Total Rollbacks Attempted : $TOTAL_ROLLBACKS"
    echo "Successful                : $SUCCESS_ROLLBACKS"
    echo "Failed                    : $FAILED_ROLLBACKS"
    echo "========================================================================"
    echo ""
    
    if [ $SUCCESS_ROLLBACKS -gt 0 ]; then
        log_success "Access Control rollback completed"
        echo ""
        log_warn "╔════════════════════════════════════════════════════════════╗"
        log_warn "║         IMPORTANT: Restart services to apply changes       ║"
        log_warn "╚════════════════════════════════════════════════════════════╝"
        log_warn ""
        log_warn "  sudo systemctl restart sshd"
        echo ""
    fi
    
    if [ $FAILED_ROLLBACKS -gt 0 ]; then
        log_warn "$FAILED_ROLLBACKS rollback(s) failed - manual intervention may be required"
    fi
}

main
```

---

# **Summary of Changes:**

## **✅ Database Structure (Correct Now):**

### **scan_results table:**
```
module_name | policy_id | policy_name | expected_value | current_value | status | timestamp
```
- Stores **PASS/FAIL** for each scan
- Compare scan results across time

### **fix_history table:**
```
module_name | policy_id | policy_name | expected_value | original_value | current_value | status | rollback_executed | timestamp
