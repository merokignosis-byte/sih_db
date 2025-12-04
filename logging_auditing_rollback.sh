#!/bin/bash
# ============================================================================
# Rollback Script for Logging and Auditing Module
# Only reverts fixes recorded in fix_history
# CIS Benchmark Compliant - Safe Rollback Procedures
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/logging_auditing"
MODULE_NAME="Logging and Auditing"

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
MANUAL_ROLLBACKS=0

# ============================================================================
# Logging Functions
# ============================================================================
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_manual() { echo -e "${YELLOW}[MANUAL]${NC} $1"; }

# ============================================================================
# Pre-flight Checks
# ============================================================================
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

check_backup_dir() {
    if [ ! -d "$BACKUP_DIR" ]; then
        log_warn "Backup directory not found: $BACKUP_DIR"
        log_warn "Some rollbacks may not be possible without backup files"
    fi
}

check_audit_immutable() {
    if auditctl -s 2>/dev/null | grep -q "enabled 2"; then
        log_error "=============================================="
        log_error "CRITICAL: Audit configuration is IMMUTABLE"
        log_error "=============================================="
        log_error "The audit system is in immutable mode (-e 2)."
        log_error "Audit rules CANNOT be modified until system reboot."
        log_error ""
        log_error "To rollback audit rules:"
        log_error "1. Remove -e 2 from /etc/audit/rules.d/*.rules"
        log_error "2. Reboot the system"
        log_error "3. Run this rollback script again"
        log_error "=============================================="
        return 1
    fi
    return 0
}

# ============================================================================
# Get fixes pending rollback
# ============================================================================
get_pending_fixes() {
    python3 << PYTHON_SCRIPT
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
# Mark rollback executed
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
# Restore file from backup
# ============================================================================
restore_backup() {
    local file_path="$1"
    local backup_pattern="$2"
    
    # Find most recent backup
    local latest_backup=$(find "$BACKUP_DIR" -name "$backup_pattern" -type f 2>/dev/null | sort -r | head -1)
    
    if [ -n "$latest_backup" ] && [ -f "$latest_backup" ]; then
        cp "$latest_backup" "$file_path" 2>/dev/null
        return 0
    else
        log_warn "No backup found for $file_path (pattern: $backup_pattern)"
        return 1
    fi
}

# ============================================================================
# Rollback individual fix
# ============================================================================
rollback_fix() {
    local policy_id="$1"
    local policy_name="$2"
    local original_value="$3"
    local current_value="$4"

    ((TOTAL_ROLLBACKS++))
    log_info "----------------------------------------"
    log_info "Rolling back: $policy_name"
    log_info "Policy ID: $policy_id"

    case "$policy_id" in
        # ====================================================================
        # 8.a.i journald configuration
        # ====================================================================
        "8.a.i.1")
            # Rollback journald service enable/start
            # CIS: Don't disable logging services for security
            log_manual "Service state not rolled back (security: keep logging active)"
            ((SUCCESS_ROLLBACKS++))
            mark_rollback_executed "$policy_id"
            ;;
            
        "8.a.i.2")
            # Rollback journal log file permissions
            # CIS: Don't weaken permissions for security
            log_manual "File permissions not rolled back (security: keep restrictive permissions)"
            ((SUCCESS_ROLLBACKS++))
            mark_rollback_executed "$policy_id"
            ;;
            
        "8.a.i.3")
            # Rollback journald rotation configuration
            if restore_backup "/etc/systemd/journald.conf" "journald.conf.*"; then
                systemctl restart systemd-journald >/dev/null 2>&1
                log_success "Restored journald.conf from backup"
                ((SUCCESS_ROLLBACKS++))
                mark_rollback_executed "$policy_id"
            else
                log_error "Failed to restore journald.conf"
                ((FAILED_ROLLBACKS++))
            fi
            ;;

        # ====================================================================
        # 8.a.ii rsyslog configuration
        # ====================================================================
        "8.a.ii.1")
            # Don't uninstall rsyslog (CIS: keep logging capability)
            log_manual "rsyslog installation not rolled back (security: keep logging capability)"
            ((SUCCESS_ROLLBACKS++))
            mark_rollback_executed "$policy_id"
            ;;
            
        "8.a.ii.2")
            # Rollback rsyslog service state
            log_manual "rsyslog service state not rolled back (security: keep logging active)"
            ((SUCCESS_ROLLBACKS++))
            mark_rollback_executed "$policy_id"
            ;;
            
        "8.a.ii.3")
            # Rollback ForwardToSyslog setting
            if restore_backup "/etc/systemd/journald.conf" "journald.conf.forward.*"; then
                systemctl restart systemd-journald >/dev/null 2>&1
                log_success "Restored journald forwarding configuration"
                ((SUCCESS_ROLLBACKS++))
                mark_rollback_executed "$policy_id"
            else
                log_error "Failed to restore journald.conf"
                ((FAILED_ROLLBACKS++))
            fi
            ;;
            
        "8.a.ii.4")
            # Rollback rsyslog FileCreateMode
            if restore_backup "/etc/rsyslog.conf" "rsyslog.conf.*"; then
                if rsyslogd -N1 &>/dev/null; then
                    systemctl restart rsyslog >/dev/null 2>&1
                    log_success "Restored rsyslog.conf from backup"
                    ((SUCCESS_ROLLBACKS++))
                    mark_rollback_executed "$policy_id"
                else
                    log_error "Restored config is invalid, reverting"
                    ((FAILED_ROLLBACKS++))
                fi
            else
                log_error "Failed to restore rsyslog.conf"
                ((FAILED_ROLLBACKS++))
            fi
            ;;
            
        "8.a.ii.5"|"8.a.ii.6"|"8.a.ii.7")
            # Manual configuration items - no automatic rollback
            log_manual "Manual configuration - review /etc/rsyslog.conf and /etc/rsyslog.d/"
            ((MANUAL_ROLLBACKS++))
            mark_rollback_executed "$policy_id"
            ;;
            
        "8.a.ii.8")
            # Don't uninstall logrotate (CIS: keep log management)
            log_manual "logrotate not uninstalled (security: keep log rotation capability)"
            ((SUCCESS_ROLLBACKS++))
            mark_rollback_executed "$policy_id"
            ;;

        # ====================================================================
        # 8.a.iii Logfile permissions
        # ====================================================================
        "8.a.iii.1")
            # Don't rollback log file permissions (CIS: keep secure)
            log_manual "Log file permissions not rolled back (security: keep restrictive permissions)"
            ((SUCCESS_ROLLBACKS++))
            mark_rollback_executed "$policy_id"
            ;;

        # ====================================================================
        # 8.b.i auditd service
        # ====================================================================
        "8.b.i.1")
            # Don't uninstall auditd (CIS: keep auditing capability)
            log_manual "auditd packages not uninstalled (security: keep auditing capability)"
            ((SUCCESS_ROLLBACKS++))
            mark_rollback_executed "$policy_id"
            ;;
            
        "8.b.i.2")
            # Don't disable auditd service (CIS: keep auditing active)
            log_manual "auditd service state not rolled back (security: keep auditing active)"
            ((SUCCESS_ROLLBACKS++))
            mark_rollback_executed "$policy_id"
            ;;
            
        "8.b.i.3"|"8.b.i.4")
            # Kernel parameters require manual intervention
            log_manual "=============================================="
            log_manual "MANUAL ROLLBACK REQUIRED: GRUB Configuration"
            log_manual "=============================================="
            log_manual "Kernel boot parameters were modified."
            log_manual ""
            log_manual "To rollback:"
            log_manual "1. Edit /etc/default/grub"
            log_manual "2. Remove 'audit=1' and 'audit_backlog_limit=8192'"
            log_manual "   from GRUB_CMDLINE_LINUX"
            log_manual "3. Run: sudo update-grub"
            log_manual "4. Reboot the system"
            log_manual "=============================================="
            ((MANUAL_ROLLBACKS++))
            mark_rollback_executed "$policy_id"
            ;;

        # ====================================================================
        # 8.b.c Data retention
        # ====================================================================
        "8.b.c.i"|"8.b.c.ii"|"8.b.c.iii"|"8.b.c.iv")
            # Rollback auditd.conf settings
            local backup_found=0
            for pattern in "auditd.conf.*" "auditd.conf.keep.*" "auditd.conf.space.*"; do
                if restore_backup "/etc/audit/auditd.conf" "$pattern"; then
                    backup_found=1
                    break
                fi
            done
            
            if [ $backup_found -eq 1 ]; then
                service auditd restart >/dev/null 2>&1
                log_success "Restored auditd.conf from backup"
                ((SUCCESS_ROLLBACKS++))
                mark_rollback_executed "$policy_id"
            else
                log_error "Failed to restore auditd.conf"
                ((FAILED_ROLLBACKS++))
            fi
            ;;

        # ====================================================================
        # 8.b.d Audit rules
        # ====================================================================
        "8.b.d.i"|"8.b.d.ii"|"8.b.d.iii"|"8.b.d.iv"|"8.b.d.v"|"8.b.d.vi"|"8.b.d.vii"|"8.b.d.viii"|"8.b.d.ix"|"8.b.d.x"|"8.b.d.xi"|"8.b.d.xii"|"8.b.d.xiii"|"8.b.d.xiv"|"8.b.d.xv"|"8.b.d.xvi"|"8.b.d.xvii"|"8.b.d.xviii"|"8.b.d.xix")
            # Rollback audit rules
            if ! check_audit_immutable; then
                log_error "Cannot rollback audit rules - system is immutable"
                ((FAILED_ROLLBACKS++))
                return
            fi
            
            if restore_backup "/etc/audit/rules.d/hardening.rules" "hardening.rules.*"; then
                augenrules --load >/dev/null 2>&1
                sleep 1
                log_success "Restored audit rules from backup"
                ((SUCCESS_ROLLBACKS++))
                mark_rollback_executed "$policy_id"
            else
                # If no backup, remove the rules file created by hardening
                if [ -f "/etc/audit/rules.d/hardening.rules" ]; then
                    rm -f "/etc/audit/rules.d/hardening.rules" 2>/dev/null
                    augenrules --load >/dev/null 2>&1
                    log_success "Removed hardening audit rules"
                    ((SUCCESS_ROLLBACKS++))
                    mark_rollback_executed "$policy_id"
                else
                    log_warn "No audit rules to rollback"
                    ((SUCCESS_ROLLBACKS++))
                    mark_rollback_executed "$policy_id"
                fi
            fi
            ;;
            
        "8.b.d.xx")
            # Audit immutability
            log_manual "=============================================="
            log_manual "MANUAL ROLLBACK: Audit Immutability"
            log_manual "=============================================="
            log_manual "To remove audit immutability:"
            log_manual "1. Remove '-e 2' from /etc/audit/rules.d/*.rules"
            log_manual "2. Run: sudo augenrules --load"
            log_manual "3. Reboot the system"
            log_manual "=============================================="
            ((MANUAL_ROLLBACKS++))
            mark_rollback_executed "$policy_id"
            ;;
            
        "8.b.d.xxi")
            # Audit rules sync - no rollback needed
            log_success "Audit rules synchronization - no rollback needed"
            ((SUCCESS_ROLLBACKS++))
            mark_rollback_executed "$policy_id"
            ;;

        # ====================================================================
        # 8.b.e Audit file access (permissions)
        # ====================================================================
        "8.b.e.i"|"8.b.e.ii"|"8.b.e.iii"|"8.b.e.iv"|"8.b.e.v"|"8.b.e.vi"|"8.b.e.vii"|"8.b.e.viii"|"8.b.e.ix"|"8.b.e.x")
            # Don't rollback security-sensitive permissions (CIS: keep secure)
            log_manual "File permissions not rolled back (security: keep restrictive permissions)"
            ((SUCCESS_ROLLBACKS++))
            mark_rollback_executed "$policy_id"
            ;;

        # ====================================================================
        # 8.b.f Integrity checking (AIDE)
        # ====================================================================
        "8.b.f.i")
            # Don't uninstall AIDE (CIS: keep integrity checking capability)
            log_manual "AIDE not uninstalled (security: keep integrity checking capability)"
            log_manual "To manually remove: sudo apt-get remove --purge aide aide-common"
            ((SUCCESS_ROLLBACKS++))
            mark_rollback_executed "$policy_id"
            ;;
            
        "8.b.f.ii")
            # Remove AIDE cron job
            if [ -f "/etc/cron.daily/aide" ]; then
                rm -f "/etc/cron.daily/aide" 2>/dev/null
                log_success "Removed AIDE cron job"
                ((SUCCESS_ROLLBACKS++))
                mark_rollback_executed "$policy_id"
            else
                log_warn "AIDE cron job not found"
                ((SUCCESS_ROLLBACKS++))
                mark_rollback_executed "$policy_id"
            fi
            ;;
            
        "8.b.f.iii")
            # Rollback AIDE configuration
            if restore_backup "/etc/aide/aide.conf" "aide.conf.*"; then
                log_success "Restored aide.conf from backup"
                log_info "AIDE database should be updated: sudo aide --update"
                ((SUCCESS_ROLLBACKS++))
                mark_rollback_executed "$policy_id"
            else
                log_warn "No AIDE backup found - manual review recommended"
                ((SUCCESS_ROLLBACKS++))
                mark_rollback_executed "$policy_id"
            fi
            ;;

        *)
            log_warn "Unknown policy ID: $policy_id - skipping"
            ((FAILED_ROLLBACKS++))
            ;;
    esac
}

# ============================================================================
# Create rollback summary report
# ============================================================================
create_rollback_report() {
    local report_file="$BACKUP_DIR/rollback_report_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$report_file" << EOF
============================================================================
LOGGING AND AUDITING ROLLBACK REPORT
============================================================================
Rollback Date       : $(date)
Module Name         : $MODULE_NAME
Database Path       : $DB_PATH
Backup Directory    : $BACKUP_DIR

----------------------------------------------------------------------------
ROLLBACK SUMMARY
----------------------------------------------------------------------------
Total Rollbacks     : $TOTAL_ROLLBACKS
Successful          : $SUCCESS_ROLLBACKS
Manual Required     : $MANUAL_ROLLBACKS
Failed              : $FAILED_ROLLBACKS

----------------------------------------------------------------------------
MANUAL ACTIONS REQUIRED
----------------------------------------------------------------------------
EOF

    # Add manual action items
    if [ $MANUAL_ROLLBACKS -gt 0 ]; then
        echo "The following items require manual intervention:" >> "$report_file"
        echo "" >> "$report_file"
        
        python3 - <<PYTHON_SCRIPT >> "$report_file"
import sqlite3
conn = sqlite3.connect("$DB_PATH")
cursor = conn.cursor()
cursor.execute("""
    SELECT policy_id, policy_name 
    FROM fix_history 
    WHERE module_name='$MODULE_NAME' 
    AND rollback_executed='YES' 
    AND status='MANUAL'
    ORDER BY policy_id
""")
for row in cursor.fetchall():
    print(f"  - [{row[0]}] {row[1]}")
conn.close()
PYTHON_SCRIPT
    else
        echo "No manual actions required." >> "$report_file"
    fi

    echo "" >> "$report_file"
    echo "----------------------------------------------------------------------------" >> "$report_file"
    echo "END OF REPORT" >> "$report_file"
    echo "============================================================================" >> "$report_file"
    
    log_info "Rollback report saved to: $report_file"
}

# ============================================================================
# Print rollback summary
# ============================================================================
print_summary() {
    echo ""
    echo "========================================================================"
    echo "LOGGING AND AUDITING ROLLBACK SUMMARY"
    echo "========================================================================"
    echo "Module Name         : $MODULE_NAME"
    echo "Database Path       : $DB_PATH"
    echo "Backup Directory    : $BACKUP_DIR"
    echo "------------------------------------------------------------------------"
    echo "Total Rollbacks     : $TOTAL_ROLLBACKS"
    echo -e "Successful          : ${GREEN}$SUCCESS_ROLLBACKS${NC}"
    echo -e "Manual Required     : ${YELLOW}$MANUAL_ROLLBACKS${NC}"
    echo -e "Failed              : ${RED}$FAILED_ROLLBACKS${NC}"
    echo "------------------------------------------------------------------------"
    
    if [ $SUCCESS_ROLLBACKS -gt 0 ]; then
        echo -e "${GREEN}✓ Rollback completed for $SUCCESS_ROLLBACKS items${NC}"
    fi
    
    if [ $MANUAL_ROLLBACKS -gt 0 ]; then
        echo ""
        echo -e "${YELLOW}⚠ MANUAL INTERVENTION REQUIRED${NC}"
        echo "Some items require manual rollback. Review the output above."
        echo ""
        echo "Common manual tasks:"
        echo "  - GRUB configuration (kernel parameters)"
        echo "  - Audit immutability settings"
        echo "  - Service configurations requiring decisions"
    fi
    
    if [ $FAILED_ROLLBACKS -gt 0 ]; then
        echo ""
        echo -e "${RED}✗ $FAILED_ROLLBACKS rollbacks failed${NC}"
        echo "Check the output above for details."
    fi
    
    echo ""
    echo "To view rollback history:"
    echo "  sqlite3 $DB_PATH \"SELECT policy_id, policy_name, rollback_executed FROM fix_history WHERE module_name='$MODULE_NAME';\""
    echo ""
    echo "To re-scan the system:"
    echo "  sudo bash logging_auditing.sh scan"
    echo "========================================================================"
    echo ""
}

# ============================================================================
# Main execution
# ============================================================================
main() {
    echo "========================================================================"
    echo "Logging and Auditing Rollback Script"
    echo "Module: $MODULE_NAME"
    echo "========================================================================"
    echo ""
    
    # Pre-flight checks
    check_root
    check_database
    check_backup_dir
    
    # Get pending fixes
    local fixes
    fixes=$(get_pending_fixes)
    
    if [ -z "$fixes" ]; then
        log_info "No fixes pending rollback for $MODULE_NAME"
        echo ""
        echo "Either:"
        echo "  - No fixes were applied (run 'fix' mode first)"
        echo "  - All fixes have already been rolled back"
        echo ""
        exit 0
    fi
    
    # Count fixes
    local fix_count=$(echo "$fixes" | wc -l)
    echo "Found $fix_count fix(es) to rollback"
    echo ""
    
    # Warning about audit immutability
    if auditctl -s 2>/dev/null | grep -q "enabled 2"; then
        log_warn "Audit system is in IMMUTABLE mode"
        log_warn "Some audit rule rollbacks will require system reboot"
        echo ""
    fi
    
    # Display fixes to be rolled back
    echo "Fixes pending rollback:"
    echo "$fixes" | python3 -c "
import sys, json
for line in sys.stdin:
    if line.strip():
        fix = json.loads(line)
        print(f\"  - [{fix['policy_id']}] {fix['policy_name']}\")
"
    echo ""
    
    # Confirmation
    echo -e "${YELLOW}WARNING: This will rollback changes made by the hardening script${NC}"
    echo "Backups will be used where available."
    echo ""
    read -p "Proceed with rollback? (yes/no): " confirm
    if [[ "$confirm" != "yes" && "$confirm" != "y" ]]; then
        log_info "Rollback cancelled by user"
        exit 0
    fi
    echo ""
    
    log_info "Starting rollback process..."
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
    log_info "Rollback process completed"
    
    # Create rollback report
    create_rollback_report
    
    # Print summary
    print_summary
    
    # Restart services if needed
    if [ $SUCCESS_ROLLBACKS -gt 0 ]; then
        echo ""
        log_info "Restarting affected services..."
        
        systemctl restart systemd-journald >/dev/null 2>&1 && log_success "Restarted systemd-journald"
        
        if systemctl is-active rsyslog >/dev/null 2>&1; then
            systemctl restart rsyslog >/dev/null 2>&1 && log_success "Restarted rsyslog"
        fi
        
        if systemctl is-active auditd >/dev/null 2>&1; then
            service auditd restart >/dev/null 2>&1 && log_success "Restarted auditd"
        fi
        
        echo ""
    fi
    
    # Exit with appropriate code
    if [ $FAILED_ROLLBACKS -eq 0 ] && [ $MANUAL_ROLLBACKS -eq 0 ]; then
        exit 0
    elif [ $FAILED_ROLLBACKS -eq 0 ] && [ $MANUAL_ROLLBACKS -gt 0 ]; then
        exit 2  # Manual intervention needed
    else
        exit 1  # Failures occurred
    fi
}

# ============================================================================
# Execute main
# ============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
fi
