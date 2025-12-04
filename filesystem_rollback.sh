#!/bin/bash
# Rollback Script for System Hardening
# Reads from database and restores original configurations

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/hardening.db"
BACKUP_DIR="$SCRIPT_DIR/backups"

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

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Check if database exists
check_database() {
    if [ ! -f "$DB_PATH" ]; then
        log_error "Database not found: $DB_PATH"
        log_error "No fixes have been applied yet or database is missing"
        exit 1
    fi
}

# Get all modules that have fixes to rollback
get_modules_to_rollback() {
    python3 -c "
import sqlite3
import sys

try:
    conn = sqlite3.connect('$DB_PATH')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT DISTINCT module_name 
        FROM fix_history 
        WHERE rollback_executed = 'NO'
        ORDER BY module_name
    ''')
    
    modules = cursor.fetchall()
    conn.close()
    
    if modules:
        for module in modules:
            print(module[0])
    
except sqlite3.Error as e:
    print(f'Database error: {e}', file=sys.stderr)
    sys.exit(1)
"
}

# Get fixes for specific module
get_module_fixes() {
    local module_name="$1"
    
    python3 << PYTHON_SCRIPT
import sqlite3
import sys
import json

try:
    conn = sqlite3.connect('$DB_PATH')
    cursor = conn.cursor()
    
    # Get all fixes with comparison to original scan
    cursor.execute('''
        SELECT 
            f.policy_id,
            f.policy_name,
            f.expected_value,
            f.original_value,
            f.current_value,
            s.status as scan_status,
            s.current_value as scan_current_value
        FROM fix_history f
        LEFT JOIN scan_results s ON f.module_name = s.module_name AND f.policy_id = s.policy_id
        WHERE f.module_name = ? AND f.rollback_executed = 'NO'
        ORDER BY f.policy_id
    ''', ('$module_name',))
    
    fixes = cursor.fetchall()
    conn.close()
    
    for fix in fixes:
        print(json.dumps({
            'policy_id': fix[0],
            'policy_name': fix[1],
            'expected_value': fix[2],
            'original_value': fix[3],
            'current_value': fix[4],
            'scan_status': fix[5] if fix[5] else 'UNKNOWN',
            'scan_current_value': fix[6] if fix[6] else ''
        }))
    
except sqlite3.Error as e:
    print(f'Database error: {e}', file=sys.stderr)
    sys.exit(1)
PYTHON_SCRIPT
}

# Mark rollback as executed
mark_rollback_executed() {
    local policy_id="$1"
    local module_name="$2"
    
    python3 -c "
import sqlite3
import sys

try:
    conn = sqlite3.connect('$DB_PATH')
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE fix_history 
        SET rollback_executed = 'YES'
        WHERE module_name = ? AND policy_id = ?
    ''', ('$module_name', '$policy_id'))
    
    conn.commit()
    conn.close()
    
except sqlite3.Error as e:
    print(f'Database error: {e}', file=sys.stderr)
    sys.exit(1)
"
}

# Rollback kernel module
rollback_kernel_module() {
    local policy_id="$1"
    local policy_name="$2"
    local original_value="$3"
    local module_name="$4"
    
    ((TOTAL_ROLLBACKS++))
    
    log_info "Rollback: $policy_name"
    
    # Check if module was originally not blacklisted
    if echo "$original_value" | grep -q "Blacklisted: No"; then
        local modprobe_file="/etc/modprobe.d/${module_name}-blacklist.conf"
        
        if [ -f "$modprobe_file" ]; then
            # Backup before removing
            cp "$modprobe_file" "$BACKUP_DIR/filesystem/${module_name}-blacklist.conf.rollback.$(date +%Y%m%d_%H%M%S)"
            
            rm -f "$modprobe_file"
            
            if [ $? -eq 0 ]; then
                log_success "Removed blacklist for $module_name module"
                ((SUCCESS_ROLLBACKS++))
                mark_rollback_executed "$policy_id" "Filesystem"
                return 0
            else
                log_error "Failed to remove blacklist for $module_name"
                ((FAILED_ROLLBACKS++))
                return 1
            fi
        else
            log_warn "Blacklist file not found for $module_name (already removed or never existed)"
            ((SUCCESS_ROLLBACKS++))
            mark_rollback_executed "$policy_id" "Filesystem"
            return 0
        fi
    else
        log_info "Module $module_name was originally blacklisted, keeping blacklist"
        ((SUCCESS_ROLLBACKS++))
        mark_rollback_executed "$policy_id" "Filesystem"
        return 0
    fi
}

# Rollback partition option
rollback_partition_option() {
    local policy_id="$1"
    local policy_name="$2"
    local original_value="$3"
    local scan_status="$4"
    local partition="$5"
    local option="$6"
    
    ((TOTAL_ROLLBACKS++))
    
    log_info "Rollback: $policy_name"
    
    # Check if original scan showed FAIL or option was not set
    if [ "$scan_status" = "FAIL" ] || echo "$original_value" | grep -qi "not set"; then
        
        # Find latest fstab backup
        local latest_backup
        latest_backup=$(ls -t "$BACKUP_DIR/filesystem"/fstab.* 2>/dev/null | head -1)
        
        if [ -z "$latest_backup" ]; then
            log_error "No fstab backup found"
            ((FAILED_ROLLBACKS++))
            return 1
        fi
        
        # Check if partition exists in backup
        if ! grep -q "[[:space:]]$partition[[:space:]]" "$latest_backup"; then
            log_warn "Partition $partition not found in backup fstab"
            ((FAILED_ROLLBACKS++))
            return 1
        fi
        
        # Backup current fstab before rollback
        cp /etc/fstab "$BACKUP_DIR/filesystem/fstab.before_rollback.$(date +%Y%m%d_%H%M%S)"
        
        # Extract the line for this partition from backup
        local backup_line
        backup_line=$(grep "[[:space:]]$partition[[:space:]]" "$latest_backup" | head -1)
        
        # Replace the line in current fstab
        local temp_file
        temp_file=$(mktemp)
        
        # Remove current line for partition and add backup line
        grep -v "[[:space:]]$partition[[:space:]]" /etc/fstab > "$temp_file"
        echo "$backup_line" >> "$temp_file"
        
        mv "$temp_file" /etc/fstab
        
        if [ $? -eq 0 ]; then
            log_success "Restored fstab entry for $partition"
            
            # Try to remount if partition is currently mounted
            if mount | grep -q " on $partition "; then
                if mount -o remount "$partition" 2>/dev/null; then
                    log_success "Remounted $partition with original options"
                else
                    log_warn "Could not remount $partition (may require reboot)"
                fi
            fi
            
            ((SUCCESS_ROLLBACKS++))
            mark_rollback_executed "$policy_id" "Filesystem"
            return 0
        else
            log_error "Failed to restore fstab entry for $partition"
            ((FAILED_ROLLBACKS++))
            return 1
        fi
    else
        log_info "Partition $partition/$option was originally set, keeping configuration"
        ((SUCCESS_ROLLBACKS++))
        mark_rollback_executed "$policy_id" "Filesystem"
        return 0
    fi
}

# Rollback filesystem module
rollback_filesystem_module() {
    log_info "=========================================="
    log_info "Rolling back Filesystem Module"
    log_info "=========================================="
    
    local fixes
    fixes=$(get_module_fixes "Filesystem")
    
    if [ -z "$fixes" ]; then
        log_warn "No fixes found for Filesystem module"
        return 0
    fi
    
    while IFS= read -r fix_json; do
        local policy_id=$(echo "$fix_json" | python3 -c "import sys, json; print(json.load(sys.stdin)['policy_id'])")
        local policy_name=$(echo "$fix_json" | python3 -c "import sys, json; print(json.load(sys.stdin)['policy_name'])")
        local original_value=$(echo "$fix_json" | python3 -c "import sys, json; print(json.load(sys.stdin)['original_value'])")
        local scan_status=$(echo "$fix_json" | python3 -c "import sys, json; print(json.load(sys.stdin)['scan_status'])")
        
        echo ""
        
        # Determine type of fix and rollback accordingly
        if echo "$policy_name" | grep -qi "kernel module"; then
            # Extract module name
            local module_name=$(echo "$policy_name" | awk '{print $2}')
            rollback_kernel_module "$policy_id" "$policy_name" "$original_value" "$module_name"
            
        elif echo "$policy_name" | grep -qi "option set on.*partition"; then
            # Extract partition and option
            local partition=$(echo "$policy_name" | sed -n 's/.*option set on \(.*\) partition.*/\1/p')
            local option=$(echo "$policy_name" | sed -n 's/.*Ensure \(.*\) option set on.*/\1/p')
            
            rollback_partition_option "$policy_id" "$policy_name" "$original_value" "$scan_status" "$partition" "$option"
            
        elif echo "$policy_name" | grep -qi "separate partition"; then
            log_info "Skipping: $policy_name (requires manual intervention)"
            mark_rollback_executed "$policy_id" "Filesystem"
            
        else
            log_warn "Unknown fix type: $policy_name"
            ((FAILED_ROLLBACKS++))
        fi
        
    done <<< "$fixes"
}

# Display rollback summary
display_summary() {
    echo ""
    echo "=========================================="
    echo "Rollback Summary"
    echo "=========================================="
    echo "Total Rollback Operations: $TOTAL_ROLLBACKS"
    echo "Successful: $SUCCESS_ROLLBACKS"
    echo "Failed: $FAILED_ROLLBACKS"
    echo "=========================================="
    
    if [ $FAILED_ROLLBACKS -eq 0 ]; then
        log_success "All rollback operations completed successfully!"
    else
        log_warn "$FAILED_ROLLBACKS rollback operations failed"
    fi
}

# List what will be rolled back
list_rollback_items() {
    echo "=========================================="
    echo "Items to be rolled back:"
    echo "=========================================="
    
    python3 << PYTHON_SCRIPT
import sqlite3
import sys

try:
    conn = sqlite3.connect('$DB_PATH')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT module_name, policy_id, policy_name, original_value
        FROM fix_history
        WHERE rollback_executed = 'NO'
        ORDER BY module_name, policy_id
    ''')
    
    fixes = cursor.fetchall()
    conn.close()
    
    if not fixes:
        print("No items found to rollback")
    else:
        for fix in fixes:
            print(f"")
            print(f"Module: {fix[0]}")
            print(f"Policy ID: {fix[1]}")
            print(f"Policy: {fix[2]}")
            print(f"Original Value: {fix[3]}")
            print(f"-" * 40)
    
except sqlite3.Error as e:
    print(f'Database error: {e}', file=sys.stderr)
    sys.exit(1)
PYTHON_SCRIPT
}

# Main function
main() {
    echo "========================================================================"
    echo "System Hardening Rollback Script"
    echo "========================================================================"
    
    check_root
    check_database
    
    # Check if there's anything to rollback
    local modules
    modules=$(get_modules_to_rollback)
    
    if [ -z "$modules" ]; then
        log_info "No fixes found to rollback. All changes have been rolled back or no fixes were applied."
        exit 0
    fi
    
    # List items to rollback
    list_rollback_items
    
    echo ""
    read -p "Do you want to proceed with rollback? (yes/no): " confirm
    
    if [ "$confirm" != "yes" ] && [ "$confirm" != "y" ]; then
        log_info "Rollback cancelled by user"
        exit 0
    fi
    
    echo ""
    log_info "Starting rollback process..."
    echo ""
    
    # Rollback each module
    while IFS= read -r module; do
        case "$module" in
            "Filesystem")
                rollback_filesystem_module
                ;;
            *)
                log_warn "Unknown module: $module"
                ;;
        esac
    done <<< "$modules"
    
    # Display summary
    display_summary
    
    # Verify fstab and remount if needed
    if mount -a --test 2>/dev/null; then
        log_success "fstab syntax is valid after rollback"
    else
        log_error "fstab syntax check failed! Please review /etc/fstab manually"
    fi
    
    echo ""
    log_info "Rollback completed!"
    log_info "Some changes may require a system reboot to take full effect."
}

# Run main
main
