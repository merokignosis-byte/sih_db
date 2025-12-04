#!/bin/bash
# Filesystem Hardening Script
# Module: Filesystem
# Supports: scan, fix, rollback modes

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/filesystem"
ROLLBACK_SCRIPT="$SCRIPT_DIR/../rollback.bash"
TOPIC="Filesystem"
MODULE_NAME="Filesystem"

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
log_manual() { echo -e "${BLUE}[FIXED]${NC} $1"; }

# Track if fstab was modified
FSTAB_MODIFIED=false
# Initialize Database
init_database() {
    python3 -c "
import sqlite3
import sys

try:
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
    print('Database initialized successfully')
    
except sqlite3.Error as e:
    print(f'Database error: {e}', file=sys.stderr)
    sys.exit(1)
"
}

print_check_result() {
    local policy_id="$1"
    local policy_name="$2"
    local expected="$3"
    local current="$4"
    local status="$5"
    
    # Apply color
    local status_colored="$status"
    case "$status" in
        PASS) status_colored="${GREEN}$status${NC}" ;;
        FAIL) status_colored="${RED}$status${NC}" ;;
        FIXED) status_colored="${BLUE}$status${NC}" ;;
        WARN) status_colored="${YELLOW}$status${NC}" ;;
    esac
    
    echo "=============================================="
    echo "Module Name    : $MODULE_NAME"
    echo "Policy ID      : $policy_id"
    echo "Policy Name    : $policy_name"
    echo "Expected Value : $expected"
    echo "Current Value  : $current"
    echo -e "Status         : $status_colored"
    echo "=============================================="
}

# Save to scan_results table
save_scan_result() {
    local policy_id="$1"
    local policy_name="$2"
    local expected_value="$3"
    local current_value="$4"
    local status="$5"
    
    python3 -c "
import sqlite3
import sys

try:
    conn = sqlite3.connect('$DB_PATH')
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO scan_results 
        (module_name, policy_id, policy_name, expected_value, current_value, status, scan_timestamp)
        VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    ''', ('$MODULE_NAME', '$policy_id', '''$policy_name''', '''$expected_value''', '''$current_value''', '$status'))
    
    conn.commit()
    conn.close()
    
except sqlite3.Error as e:
    print(f'Database error: {e}', file=sys.stderr)
    sys.exit(1)
"
}

# Save to fix_history table
save_fix_result() {
    local policy_id="$1"
    local policy_name="$2"
    local expected_value="$3"
    local original_value="$4"
    local current_value="$5"
    local status="$6"
    
    python3 -c "
import sqlite3
import sys

try:
    conn = sqlite3.connect('$DB_PATH')
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO fix_history 
        (module_name, policy_id, policy_name, expected_value, original_value, current_value, status, fix_timestamp, rollback_executed)
        VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), 'NO')
    ''', ('$MODULE_NAME', '$policy_id', '''$policy_name''', '''$expected_value''', '''$original_value''', '''$current_value''', '$status'))
    
    conn.commit()
    conn.close()
    
except sqlite3.Error as e:
    print(f'Database error: {e}', file=sys.stderr)
    sys.exit(1)
"
}

# Get scan result from database
get_scan_result() {
    local policy_id="$1"
    python3 -c "
import sqlite3
import sys
import json

try:
    conn = sqlite3.connect('$DB_PATH')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT current_value, status 
        FROM scan_results 
        WHERE module_name=? AND policy_id=?
    ''', ('$MODULE_NAME', '$policy_id'))
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        print(json.dumps({'current_value': result[0], 'status': result[1]}))
    else:
        print(json.dumps({'current_value': '', 'status': ''}))
        
except Exception as e:
    print(json.dumps({'current_value': '', 'status': ''}), file=sys.stderr)
" 2>/dev/null
}

# Check if directory is on root filesystem
is_on_root_filesystem() {
    local dir="$1"
    
    if [ ! -d "$dir" ]; then
        return 2
    fi
    
    local dir_device
    local root_device
    dir_device=$(df "$dir" 2>/dev/null | tail -1 | awk '{print $1}')
    root_device=$(df / 2>/dev/null | tail -1 | awk '{print $1}')
    
    if [ -z "$dir_device" ] || [ -z "$root_device" ]; then
        return 2
    fi
    
    if [ "$dir_device" = "$root_device" ]; then
        return 0
    else
        return 1
    fi
}

# Check if directory exists in fstab
fstab_has_entry() {
    local partition="$1"
    grep -q "^[^#]*[[:space:]]$partition[[:space:]]" /etc/fstab 2>/dev/null
}

# Get current mount options
get_mount_options() {
    local partition="$1"
    mount | grep " on $partition " | sed 's/.*(\(.*\))/\1/' 2>/dev/null
}

# Check if mount has specific option
has_mount_option() {
    local options_list="$1"
    local option="$2"
    echo "$options_list" | grep -qw "$option"
}

# Check if partition is mounted
is_mounted() {
    local partition="$1"
    mount | grep -q " on $partition " 2>/dev/null
}

# ============================================================================
# 1.1 Filesystem Kernel Modules
# ============================================================================

check_kernel_module() {
    local module="$1"
    local policy_num="$2"
    local rule_id="FS-1.a.${policy_num}"
    local rule_name="Ensure $module kernel module is not available"
    local expected="Module not loaded and blacklisted"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local is_loaded="No"
        local is_blacklisted="No"
        local status="FAIL"
        
        # Check if module is loaded
        if lsmod | grep -q "^$module "; then
            is_loaded="Yes"
        fi
        
        # Check if install directive exists
        if grep -rq "^[[:space:]]*install[[:space:]]\+$module[[:space:]]\+/bin/\(false\|true\)" /etc/modprobe.d/ 2>/dev/null; then
            is_blacklisted="Yes"
        fi
        
        local current="Loaded: $is_loaded, Blacklisted: $is_blacklisted"
        
        if [ "$is_loaded" = "No" ] && [ "$is_blacklisted" = "Yes" ]; then
            status="PASS"
            ((PASSED_CHECKS++))
        else
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$rule_id" "$rule_name" "$expected" "$current" "$status"
        save_scan_result "$rule_id" "$rule_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        # Get original state from scan
        local scan_data
        scan_data=$(get_scan_result "$rule_id")
        local original_value=$(echo "$scan_data" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('current_value', ''))")
        
        if [ -z "$original_value" ]; then
            # No scan data, get current state
            local is_loaded="No"
            local is_blacklisted="No"
            if lsmod | grep -q "^$module "; then
                is_loaded="Yes"
            fi
            if grep -rq "^[[:space:]]*install[[:space:]]\+$module[[:space:]]\+/bin/\(false\|true\)" /etc/modprobe.d/ 2>/dev/null; then
                is_blacklisted="Yes"
            fi
            original_value="Loaded: $is_loaded, Blacklisted: $is_blacklisted"
        fi
        
        local modprobe_file="/etc/modprobe.d/$module-blacklist.conf"
        
        # Backup original modprobe config if exists
        if [ -f "$modprobe_file" ]; then
            cp "$modprobe_file" "$BACKUP_DIR/$module-blacklist.conf.bak.$(date +%Y%m%d_%H%M%S)"
        fi
        
        cat > "$modprobe_file" << EOF
# Disable $module module - Added by hardening script
install $module /bin/false
blacklist $module
EOF
        
        if [ $? -eq 0 ]; then
            log_info "Created blacklist configuration: $modprobe_file"
            
            if lsmod | grep -q "^$module "; then
                if rmmod "$module" 2>/dev/null || modprobe -r "$module" 2>/dev/null; then
                    log_info "Module $module unloaded successfully"
                else
                    log_warn "Could not unload module $module (may require reboot)"
                fi
            fi
            
            local current_value="Loaded: No, Blacklisted: Yes"
            local status="PASS"
            
            log_pass "Module $module has been disabled"
            save_fix_result "$rule_id" "$rule_name" "$expected" "$original_value" "$current_value" "$status"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Checking rollback for $module module..."
        # Rollback logic will be handled by generate_rollback_script
    fi
}

check_all_kernel_modules() {
    log_info "=== 1.a Configure Filesystem Kernel Modules ==="
    
    check_kernel_module "cramfs" "i"
    check_kernel_module "freevxfs" "ii"
    check_kernel_module "hfs" "iii"
    check_kernel_module "hfsplus" "iv"
    check_kernel_module "jffs2" "v"
    check_kernel_module "overlayfs" "vi"
    check_kernel_module "squashfs" "vii"
    check_kernel_module "udf" "viii"
    check_kernel_module "usb-storage" "ix"
}

# ============================================================================
# Partition Checks
# ============================================================================

check_partition_exists() {
    local partition="$1"
    local policy_id="$2"
    local rule_name="Ensure $partition is a separate partition"
    local expected="Separate partition"
    
    ((TOTAL_CHECKS++))
    
    if [ ! -d "$partition" ]; then
        if [ "$MODE" = "scan" ]; then
            local current="Directory does not exist"
            print_check_result "$policy_id" "$rule_name" "$expected" "$current" "FAIL"
            save_scan_result "$policy_id" "$rule_name" "$expected" "$current" "FAIL"
            ((FAILED_CHECKS++))
        fi
        return 2
    fi
    
    if [ "$MODE" = "scan" ] || [ "$MODE" = "fix" ]; then
        local status="FAIL"
        local current="On root filesystem"
        
        if is_mounted "$partition"; then
            if is_on_root_filesystem "$partition"; then
                current="On root filesystem (not separate)"
            else
                status="PASS"
                current="Separate partition"
                ((PASSED_CHECKS++))
            fi
        else
            current="Not mounted"
        fi
        
        if [ "$status" = "FAIL" ]; then
            ((FAILED_CHECKS++))
        fi
        
        if [ "$MODE" = "scan" ]; then
            print_check_result "$policy_id" "$rule_name" "$expected" "$current" "$status"
            save_scan_result "$policy_id" "$rule_name" "$expected" "$current" "$status"
        fi
    fi
}

check_partition_option() {
    local partition="$1"
    local option="$2"
    local policy_id="$3"
    local rule_name="Ensure $option option set on $partition partition"
    local expected="$option"
    
    ((TOTAL_CHECKS++))
    
    if [ ! -d "$partition" ] && [ "$partition" != "/dev/shm" ]; then
        if [ "$MODE" = "scan" ]; then
            local current="Directory does not exist"
            print_check_result "$policy_id" "$rule_name" "$expected" "$current" "FAIL"
            save_scan_result "$policy_id" "$rule_name" "$expected" "$current" "FAIL"
            ((FAILED_CHECKS++))
        fi
        return 2
    fi
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local current="Not set"
        
        if ! is_mounted "$partition"; then
            current="Not mounted"
        else
            local current_options
            current_options=$(get_mount_options "$partition")
            
            if has_mount_option "$current_options" "$option"; then
                status="PASS"
                current="$option"
                ((PASSED_CHECKS++))
            else
                current="Option not set (current: $current_options)"
            fi
        fi
        
        if [ "$status" = "FAIL" ]; then
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$rule_name" "$expected" "$current" "$status"
        save_scan_result "$policy_id" "$rule_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        if ! is_mounted "$partition"; then
            log_error "Cannot fix: $partition is not mounted"
            return 1
        fi
        
        if ! fstab_has_entry "$partition"; then
            log_error "Cannot fix: No fstab entry found for $partition"
            ((MANUAL_CHECKS++))
            return 1
        fi
        
        local current_options
        current_options=$(get_mount_options "$partition")
        
        if has_mount_option "$current_options" "$option"; then
            log_pass "$partition already has $option option set"
            return 0
        fi
        
        # Get original state from scan
        local scan_data
        scan_data=$(get_scan_result "$policy_id")
        local original_value=$(echo "$scan_data" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('current_value', ''))")
        
        if [ -z "$original_value" ]; then
            original_value="Option not set (current: $current_options)"
        fi
        
        # Backup fstab
        cp /etc/fstab "$BACKUP_DIR/fstab.$(date +%Y%m%d_%H%M%S)"
        
        # Save original fstab line
        local original_fstab_line
        original_fstab_line=$(grep "^[^#]*[[:space:]]$partition[[:space:]]" /etc/fstab)
        
        local temp_file
        temp_file=$(mktemp)
        awk -v partition="$partition" -v opt="$option" '
        $2 == partition {
            if ($4 == "defaults") {
                $4 = "defaults," opt
            } else if ($4 !~ opt) {
                $4 = $4 "," opt
            }
        }
        { print }
        ' /etc/fstab > "$temp_file" && mv "$temp_file" /etc/fstab
        
        if [ $? -eq 0 ]; then
            log_info "Added $option to $partition in fstab"
            FSTAB_MODIFIED=true
            
            local current_value="$option"
            local status="PASS"
            
            save_fix_result "$policy_id" "$rule_name" "$expected" "$original_value" "$current_value" "$status"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Checking rollback for $partition $option..."
        # Rollback logic will be handled by generate_rollback_script
    fi
}

# Configure /tmp
check_tmp_partition() {
    log_info "=== 1.b Configure /tmp ==="
    check_partition_exists "/tmp" "FS-1.b.i"
    check_partition_option "/tmp" "nodev" "FS-1.b.ii"
    check_partition_option "/tmp" "nosuid" "FS-1.b.iii"
    check_partition_option "/tmp" "noexec" "FS-1.b.iv"
}

# Configure /dev/shm
check_dev_shm_partition() {
    log_info "=== 1.c Configure /dev/shm ==="
    check_partition_exists "/dev/shm" "FS-1.c.i"
    check_partition_option "/dev/shm" "nodev" "FS-1.c.ii"
    check_partition_option "/dev/shm" "nosuid" "FS-1.c.iii"
    check_partition_option "/dev/shm" "noexec" "FS-1.c.iv"
}

# Configure /home
check_home_partition() {
    log_info "=== 1.d Configure /home ==="
    check_partition_exists "/home" "FS-1.d.i"
    check_partition_option "/home" "nodev" "FS-1.d.ii"
    check_partition_option "/home" "nosuid" "FS-1.d.iii"
}

# Configure /var
check_var_partition() {
    log_info "=== 1.e Configure /var ==="
    check_partition_exists "/var" "FS-1.e.i"
    check_partition_option "/var" "nodev" "FS-1.e.ii"
    check_partition_option "/var" "nosuid" "FS-1.e.iii"
}

# Configure /var/tmp
check_var_tmp_partition() {
    log_info "=== 1.f Configure /var/tmp ==="
    check_partition_exists "/var/tmp" "FS-1.f.i"
    check_partition_option "/var/tmp" "nodev" "FS-1.f.ii"
    check_partition_option "/var/tmp" "nosuid" "FS-1.f.iii"
    check_partition_option "/var/tmp" "noexec" "FS-1.f.iv"
}

# Configure /var/log
check_var_log_partition() {
    log_info "=== 1.g Configure /var/log ==="
    check_partition_exists "/var/log" "FS-1.g.i"
    check_partition_option "/var/log" "nodev" "FS-1.g.ii"
    check_partition_option "/var/log" "nosuid" "FS-1.g.iii"
    check_partition_option "/var/log" "noexec" "FS-1.g.iv"
}

# Configure /var/log/audit
check_var_log_audit_partition() {
    log_info "=== 1.h Configure /var/log/audit ==="
    check_partition_exists "/var/log/audit" "FS-1.h"
    check_partition_option "/var/log/audit" "nodev" "FS-1.h.i"
    check_partition_option "/var/log/audit" "nosuid" "FS-1.h.ii"
    check_partition_option "/var/log/audit" "noexec" "FS-1.h.iii"
}

# ============================================================================
# Generate Rollback Script
# ============================================================================

generate_rollback_script() {
    log_info "Generating rollback script..."
    
    python3 << 'PYTHON_SCRIPT'
import sqlite3
import sys
import os

DB_PATH = os.environ.get('DB_PATH')
ROLLBACK_SCRIPT = os.environ.get('ROLLBACK_SCRIPT')
MODULE_NAME = os.environ.get('MODULE_NAME')
BACKUP_DIR = os.environ.get('BACKUP_DIR')

try:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get all items that were fixed but need rollback
    cursor.execute('''
        SELECT f.policy_id, f.policy_name, f.original_value, s.current_value, s.status
        FROM fix_history f
        LEFT JOIN scan_results s ON f.module_name = s.module_name AND f.policy_id = s.policy_id
        WHERE f.module_name = ? AND f.rollback_executed = 'NO'
    ''', (MODULE_NAME,))
    
    fixes = cursor.fetchall()
    
    if not fixes:
        print("No fixes found to rollback")
        conn.close()
        sys.exit(0)
    
    # Generate rollback script
    script_content = '''#!/bin/bash
# Auto-generated Rollback Script for Filesystem Module
# Generated at: $(date)

BACKUP_DIR="''' + BACKUP_DIR + '''"
MODULE="''' + MODULE_NAME + '''"

echo "========================================================================"
echo "Rollback Script for $MODULE Module"
echo "========================================================================"

'''
    
    for fix in fixes:
        policy_id, policy_name, original_value, scan_current, scan_status = fix
        
        # Kernel modules rollback
        if 'kernel module' in policy_name.lower():
            module_name = policy_name.split()[1]
            if 'not available' in policy_name:
                if 'Blacklisted: No' in original_value or 'Blacklisted: Yes' not in original_value:
                    script_content += f'''
# Rollback: {policy_name}
echo "Rolling back {module_name} module..."
if [ -f "/etc/modprobe.d/{module_name}-blacklist.conf" ]; then
    rm -f "/etc/modprobe.d/{module_name}-blacklist.conf"
    echo "Removed blacklist for {module_name}"
fi

'''
        
        # Partition options rollback
        elif 'option set on' in policy_name.lower():
            partition = policy_name.split('on')[1].split('partition')[0].strip()
            option = policy_name.split('Ensure')[1].split('option')[0].strip()
            
            if 'not set' in original_value.lower() or 'FAIL' in scan_status:
                script_content += f'''
# Rollback: {policy_name}
echo "Rolling back {option} option on {partition}..."
LATEST_BACKUP=$(ls -t "$BACKUP_DIR"/fstab.* 2>/dev/null | head -1)
if [ -n "$LATEST_BACKUP" ]; then
    cp "$LATEST_BACKUP" /etc/fstab
    echo "Restored fstab from backup"
    mount -o remount {partition} 2>/dev/null
    echo "Remounted {partition}"
fi

'''
    
    script_content += '''
echo "========================================================================"
echo "Rollback completed"
echo "========================================================================"

# Mark rollback as executed in database
python3 << 'EOF'
import sqlite3
DB_PATH = "''' + DB_PATH + '''"
try:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE fix_history SET rollback_executed='YES' WHERE module_name=? AND rollback_executed='NO'", ("''' + MODULE_NAME + '''",))
    conn.commit()
    conn.close()
    print("Database updated: Rollback marked as executed")
except Exception as e:
    print(f"Error updating database: {e}")
EOF
'''
    
    # Write rollback script
    with open(ROLLBACK_SCRIPT, 'w') as f:
        f.write(script_content)
    
    os.chmod(ROLLBACK_SCRIPT, 0o755)
    print(f"Rollback script generated: {ROLLBACK_SCRIPT}")
    
    conn.close()
    
except sqlite3.Error as e:
    print(f'Database error: {e}', file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f'Error: {e}', file=sys.stderr)
    sys.exit(1)

PYTHON_SCRIPT
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    echo "========================================================================"
    echo "Filesystem Hardening Script"
    echo "Module: $MODULE_NAME"
    echo "Mode: $MODE"
    echo "========================================================================"
    
    # Initialize database
    init_database
    
    if [ "$MODE" = "fix" ] || [ "$MODE" = "rollback" ]; then
        if [ "$EUID" -ne 0 ]; then
            log_error "This script must be run as root for $MODE mode"
            exit 1
        fi
    fi
    
    if [ "$MODE" = "scan" ] || [ "$MODE" = "fix" ]; then
        check_all_kernel_modules
        check_tmp_partition
        check_dev_shm_partition
        check_home_partition
        check_var_partition
        check_var_tmp_partition
        check_var_log_partition
        check_var_log_audit_partition
        
        if [ "$MODE" = "fix" ]; then
            # Generate rollback script after fixes
            generate_rollback_script
            
            if [ "$FSTAB_MODIFIED" = "true" ]; then
                echo ""
                log_info "Applying fstab changes..."
                
                if mount -a --test 2>/dev/null; then
                    log_info "fstab syntax is valid"
                    
                    for part in /var/log/audit /var/log /var/tmp /var /home /tmp /dev/shm; do
                        if is_mounted "$part" && fstab_has_entry "$part"; then
                            if mount -o remount "$part" 2>/dev/null; then
                                log_pass "Remounted $part with new options"
                            fi
                        fi
                    done
                fi
            fi
        fi
        
        echo ""
        echo "========================================================================"
        echo "Summary"
        echo "========================================================================"
        echo "Total Checks: $TOTAL_CHECKS"
        
        if [ "$MODE" = "scan" ]; then
            echo "Passed: $PASSED_CHECKS"
            echo "Failed: $FAILED_CHECKS"
            
            if [ $FAILED_CHECKS -eq 0 ]; then
                log_pass "All filesystem checks passed!"
            else
                log_warn "$FAILED_CHECKS checks failed. Run with 'fix' mode to remediate."
            fi
        else
            echo "Fixed: $FIXED_CHECKS"
            echo "Manual Actions Required: $MANUAL_CHECKS"
            
            if [ $FIXED_CHECKS -gt 0 ]; then
                echo ""
                log_info "Rollback script has been generated at: $ROLLBACK_SCRIPT"
                log_info "To rollback changes, run: sudo bash $ROLLBACK_SCRIPT"
            fi
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        if [ -f "$ROLLBACK_SCRIPT" ]; then
            log_info "Executing rollback script: $ROLLBACK_SCRIPT"
            bash "$ROLLBACK_SCRIPT"
        else
            log_error "Rollback script not found: $ROLLBACK_SCRIPT"
            log_info "Attempting to generate rollback script from database..."
            generate_rollback_script
            
            if [ -f "$ROLLBACK_SCRIPT" ]; then
                log_info "Executing generated rollback script..."
                bash "$ROLLBACK_SCRIPT"
            else
                log_error "Failed to generate rollback script"
                exit 1
            fi
        fi
        
    else
        echo "Usage: $0 {scan|fix|rollback}"
        exit 1
    fi
}

main
