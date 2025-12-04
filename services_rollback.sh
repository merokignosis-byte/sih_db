#!/bin/bash
# Services Rollback Script
# Module: Services
# Purpose: Rollback hardening changes to original state

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/services"
MODULE_NAME="Services"

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
SKIPPED_ROLLBACKS=0

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

log_skip() {
    echo -e "${BLUE}[SKIP]${NC} $1"
}

# =========================
# Database Functions
# =========================
get_fix_history() {
    python3 -c "
import sqlite3
import json
import sys

try:
    conn = sqlite3.connect('$DB_PATH')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT policy_id, policy_name, original_value, current_value, rollback_executed
        FROM fix_history
        WHERE module_name = ? AND rollback_executed = 'NO'
        ORDER BY id DESC
    ''', ('$MODULE_NAME',))
    
    results = cursor.fetchall()
    conn.close()
    
    fixes = []
    for row in results:
        fixes.append({
            'policy_id': row[0],
            'policy_name': row[1],
            'original_value': row[2],
            'current_value': row[3],
            'rollback_executed': row[4]
        })
    
    print(json.dumps(fixes))
    
except Exception as e:
    print('[]', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null
}

mark_rollback_executed() {
    local policy_id="$1"
    local status="$2"
    
    python3 -c "
import sqlite3
import sys

try:
    conn = sqlite3.connect('$DB_PATH')
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE fix_history
        SET rollback_executed = ?
        WHERE module_name = ? AND policy_id = ?
    ''', ('$status', '$MODULE_NAME', '$policy_id'))
    
    conn.commit()
    conn.close()
    
except sqlite3.Error as e:
    print(f'Database error: {e}', file=sys.stderr)
    sys.exit(1)
"
}

# =========================
# Service Rollback Functions
# =========================
rollback_service() {
    local policy_id="$1"
    local service="$2"
    local original_state="$3"
    
    ((TOTAL_ROLLBACKS++))
    
    local backup_file="$BACKUP_DIR/${service}_status.txt"
    
    if [ ! -f "$backup_file" ]; then
        log_warn "No backup found for $service, using original state: $original_state"
    else
        original_state=$(grep "^original_state=" "$backup_file" | cut -d'=' -f2)
    fi
    
    log_info "Rolling back $service to state: $original_state"
    
    case "$original_state" in
        enabled)
            systemctl unmask "$service" 2>/dev/null
            systemctl enable "$service" 2>/dev/null
            systemctl start "$service" 2>/dev/null
            ;;
        disabled)
            systemctl unmask "$service" 2>/dev/null
            systemctl disable "$service" 2>/dev/null
            systemctl stop "$service" 2>/dev/null
            ;;
        masked)
            systemctl mask "$service" 2>/dev/null
            ;;
        static|indirect)
            systemctl unmask "$service" 2>/dev/null
            ;;
        not-found)
            log_skip "$service was not installed originally"
            ((SKIPPED_ROLLBACKS++))
            mark_rollback_executed "$policy_id" "SKIPPED"
            return
            ;;
    esac
    
    local current_state=$(systemctl is-enabled "$service" 2>/dev/null || echo "not-found")
    
    if [ "$current_state" = "$original_state" ] || [ "$original_state" = "not-found" ]; then
        log_success "Successfully rolled back $service"
        ((SUCCESS_ROLLBACKS++))
        mark_rollback_executed "$policy_id" "YES"
    else
        log_error "Failed to rollback $service (expected: $original_state, got: $current_state)"
        ((FAILED_ROLLBACKS++))
        mark_rollback_executed "$policy_id" "FAILED"
    fi
}

# =========================
# Package Rollback Functions
# =========================
rollback_package() {
    local policy_id="$1"
    local package="$2"
    local original_state="$3"
    
    ((TOTAL_ROLLBACKS++))
    
    log_info "Rolling back package $package (original state: $original_state)"
    
    if [ "$original_state" = "installed" ]; then
        local backup_file="$BACKUP_DIR/${package}_backup.txt"
        
        if [ ! -f "$backup_file" ]; then
            log_warn "No backup found for $package, attempting reinstall"
        fi
        
        apt install -y "$package" >/dev/null 2>&1
        
        if dpkg -l 2>/dev/null | grep -q "^ii.*$package"; then
            log_success "Successfully reinstalled $package"
            ((SUCCESS_ROLLBACKS++))
            mark_rollback_executed "$policy_id" "YES"
        else
            log_error "Failed to reinstall $package"
            ((FAILED_ROLLBACKS++))
            mark_rollback_executed "$policy_id" "FAILED"
        fi
    else
        log_skip "$package was not installed originally"
        ((SKIPPED_ROLLBACKS++))
        mark_rollback_executed "$policy_id" "SKIPPED"
    fi
}

# =========================
# File Permission Rollback
# =========================
rollback_file_permissions() {
    local policy_id="$1"
    local file_path="$2"
    local original_value="$3"
    
    ((TOTAL_ROLLBACKS++))
    
    local backup_file="$BACKUP_DIR/$(basename $file_path)_perms.txt"
    
    if [ ! -f "$backup_file" ]; then
        log_warn "No backup found for $file_path permissions"
        ((SKIPPED_ROLLBACKS++))
        mark_rollback_executed "$policy_id" "SKIPPED"
        return
    fi
    
    log_info "Rolling back permissions for $file_path"
    
    local perms=$(awk '{print $1}' "$backup_file")
    local owner=$(awk '{print $2}' "$backup_file")
    
    if [ -e "$file_path" ]; then
        chmod "$perms" "$file_path" 2>/dev/null
        chown "$owner" "$file_path" 2>/dev/null
        
        local current_perms=$(stat -c "%a" "$file_path" 2>/dev/null)
        local current_owner=$(stat -c "%U:%G" "$file_path" 2>/dev/null)
        
        if [ "$current_perms" = "$perms" ] && [ "$current_owner" = "$owner" ]; then
            log_success "Successfully rolled back permissions for $file_path"
            ((SUCCESS_ROLLBACKS++))
            mark_rollback_executed "$policy_id" "YES"
        else
            log_error "Failed to rollback permissions for $file_path"
            ((FAILED_ROLLBACKS++))
            mark_rollback_executed "$policy_id" "FAILED"
        fi
    else
        log_warn "$file_path does not exist"
        ((SKIPPED_ROLLBACKS++))
        mark_rollback_executed "$policy_id" "SKIPPED"
    fi
}

# =========================
# Configuration File Rollback
# =========================
rollback_config_file() {
    local policy_id="$1"
    local config_file="$2"
    local description="$3"
    
    ((TOTAL_ROLLBACKS++))
    
    # Find the most recent backup
    local backup_file=$(ls -t "$BACKUP_DIR"/$(basename "$config_file").* 2>/dev/null | head -1)
    
    if [ -z "$backup_file" ]; then
        log_warn "No backup found for $config_file"
        ((SKIPPED_ROLLBACKS++))
        mark_rollback_executed "$policy_id" "SKIPPED"
        return
    fi
    
    log_info "Rolling back $description: $config_file"
    
    cp "$backup_file" "$config_file" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        log_success "Successfully rolled back $config_file"
        ((SUCCESS_ROLLBACKS++))
        mark_rollback_executed "$policy_id" "YES"
    else
        log_error "Failed to rollback $config_file"
        ((FAILED_ROLLBACKS++))
        mark_rollback_executed "$policy_id" "FAILED"
    fi
}

# =========================
# Time Synchronization Rollback
# =========================
rollback_time_sync() {
    local policy_id="$1"
    local original_value="$2"
    
    ((TOTAL_ROLLBACKS++))
    
    log_info "Rolling back time synchronization (original: $original_value)"
    
    if [[ "$original_value" == *"systemd-timesyncd"* ]]; then
        # Restore systemd-timesyncd
        systemctl unmask systemd-timesyncd 2>/dev/null
        systemctl enable systemd-timesyncd 2>/dev/null
        systemctl start systemd-timesyncd 2>/dev/null
        
        # Stop chrony if it was installed by fix
        systemctl stop chrony 2>/dev/null
        systemctl disable chrony 2>/dev/null
        
        # Restore timesyncd config if backup exists
        local backup_file=$(ls -t "$BACKUP_DIR"/timesyncd.conf.* 2>/dev/null | head -1)
        if [ -n "$backup_file" ]; then
            cp "$backup_file" /etc/systemd/timesyncd.conf
        fi
        
        log_success "Restored systemd-timesyncd"
        ((SUCCESS_ROLLBACKS++))
        mark_rollback_executed "$policy_id" "YES"
        
    elif [[ "$original_value" == *"no time sync"* ]]; then
        # Stop and disable all time sync services
        systemctl stop chrony 2>/dev/null
        systemctl disable chrony 2>/dev/null
        systemctl stop systemd-timesyncd 2>/dev/null
        systemctl disable systemd-timesyncd 2>/dev/null
        
        log_success "Disabled time synchronization services"
        ((SUCCESS_ROLLBACKS++))
        mark_rollback_executed "$policy_id" "YES"
    else
        log_skip "Time sync already in desired state"
        ((SKIPPED_ROLLBACKS++))
        mark_rollback_executed "$policy_id" "SKIPPED"
    fi
}

# =========================
# Cron Allow/Deny Rollback
# =========================
rollback_cron_allow_deny() {
    local policy_id="$1"
    local original_value="$2"
    
    ((TOTAL_ROLLBACKS++))
    
    log_info "Rolling back cron/at allow/deny configuration"
    
    # Restore backed up files
    for file in cron.deny at.deny cron.allow at.allow; do
        local backup_file=$(ls -t "$BACKUP_DIR"/${file}.* 2>/dev/null | head -1)
        if [ -n "$backup_file" ]; then
            cp "$backup_file" /etc/$file
            log_info "Restored /etc/$file"
        fi
    done
    
    # If original state had deny files, remove allow files that were created
    if [[ "$original_value" == *"cron.deny:true"* ]]; then
        # Only remove if they were created by the fix (check if they're empty or have default content)
        if [ -f /etc/cron.allow ] && [ ! -s /etc/cron.allow ]; then
            rm -f /etc/cron.allow
        fi
        if [ -f /etc/at.allow ] && [ ! -s /etc/at.allow ]; then
            rm -f /etc/at.allow
        fi
    fi
    
    log_success "Rolled back cron/at configuration"
    ((SUCCESS_ROLLBACKS++))
    mark_rollback_executed "$policy_id" "YES"
}

# =========================
# Sudo Configuration Rollback
# =========================
rollback_sudoers() {
    local policy_id="$1"
    local policy_name="$2"
    
    ((TOTAL_ROLLBACKS++))
    
    # Find the most recent sudoers backup
    local backup_file=$(ls -t "$BACKUP_DIR"/sudoers.* 2>/dev/null | head -1)
    
    if [ -z "$backup_file" ]; then
        log_warn "No backup found for sudoers"
        ((SKIPPED_ROLLBACKS++))
        mark_rollback_executed "$policy_id" "SKIPPED"
        return
    fi
    
    log_info "Rolling back sudoers configuration: $policy_name"
    
    # Validate backup file before restoring
    visudo -c -f "$backup_file" >/dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        cp "$backup_file" /etc/sudoers
        log_success "Successfully rolled back /etc/sudoers"
        ((SUCCESS_ROLLBACKS++))
        mark_rollback_executed "$policy_id" "YES"
    else
        log_error "Backup sudoers file is invalid, skipping rollback for safety"
        ((FAILED_ROLLBACKS++))
        mark_rollback_executed "$policy_id" "FAILED"
    fi
}

# =========================
# Main Rollback Logic
# =========================
rollback_by_policy() {
    local policy_id="$1"
    local policy_name="$2"
    local original_value="$3"
    
    echo ""
    echo "=============================================="
    echo "Rolling back: $policy_name"
    echo "Policy ID: $policy_id"
    echo "Original Value: $original_value"
    echo "=============================================="
    
    case "$policy_id" in
        # Server Services
        SRV-3.a.*)
            local service=$(echo "$policy_name" | grep -oP '(?<=Ensure ).*(?= services are not in use)' | sed 's/ daemon//')
            case "$policy_id" in
                SRV-3.a.i) rollback_service "$policy_id" "autofs" "$original_value" ;;
                SRV-3.a.ii) rollback_service "$policy_id" "avahi-daemon" "$original_value" ;;
                SRV-3.a.iii) rollback_service "$policy_id" "isc-dhcp-server" "$original_value" ;;
                SRV-3.a.iv) rollback_service "$policy_id" "bind9" "$original_value" ;;
                SRV-3.a.v) rollback_service "$policy_id" "dnsmasq" "$original_value" ;;
                SRV-3.a.vi) rollback_service "$policy_id" "vsftpd" "$original_value" ;;
                SRV-3.a.vii) rollback_service "$policy_id" "slapd" "$original_value" ;;
                SRV-3.a.viii) rollback_service "$policy_id" "dovecot" "$original_value" ;;
                SRV-3.a.ix) rollback_service "$policy_id" "nfs-kernel-server" "$original_value" ;;
                SRV-3.a.x) rollback_service "$policy_id" "nis" "$original_value" ;;
                SRV-3.a.xi) rollback_service "$policy_id" "cups" "$original_value" ;;
                SRV-3.a.xii) rollback_service "$policy_id" "rpcbind" "$original_value" ;;
                SRV-3.a.xiii) rollback_service "$policy_id" "rsync" "$original_value" ;;
                SRV-3.a.xiv) rollback_service "$policy_id" "smbd" "$original_value" ;;
                SRV-3.a.xv) rollback_service "$policy_id" "snmpd" "$original_value" ;;
                SRV-3.a.xvi) rollback_service "$policy_id" "tftpd-hpa" "$original_value" ;;
                SRV-3.a.xvii) rollback_service "$policy_id" "squid" "$original_value" ;;
                SRV-3.a.xviii) rollback_service "$policy_id" "apache2" "$original_value" ;;
                SRV-3.a.xix) rollback_service "$policy_id" "xinetd" "$original_value" ;;
                SRV-3.a.xx) rollback_service "$policy_id" "gdm" "$original_value" ;;
            esac
            ;;
            
        # Client Services (Packages)
        SRV-3.b.*)
            case "$policy_id" in
                SRV-3.b.i) rollback_package "$policy_id" "nis" "$original_value" ;;
                SRV-3.b.ii) rollback_package "$policy_id" "rsh-client" "$original_value" ;;
                SRV-3.b.iii) rollback_package "$policy_id" "talk" "$original_value" ;;
                SRV-3.b.iv) rollback_package "$policy_id" "telnet" "$original_value" ;;
                SRV-3.b.v) rollback_package "$policy_id" "ldap-utils" "$original_value" ;;
                SRV-3.b.vi) rollback_package "$policy_id" "ftp" "$original_value" ;;
            esac
            ;;
            
        # Time Synchronization
        SRV-3.c)
            rollback_time_sync "$policy_id" "$original_value"
            ;;
            
        SRV-3.c.i)
            rollback_time_sync "$policy_id" "$original_value"
            ;;
            
        # Chrony
        SRV-3.e.iii)
            rollback_service "$policy_id" "chrony" "$original_value"
            ;;
            
        # Cron
        SRV-3.f.i)
            rollback_service "$policy_id" "cron" "$original_value"
            ;;
            
        SRV-3.f.ii)
            rollback_file_permissions "$policy_id" "/etc/crontab" "$original_value"
            ;;
            
        SRV-3.f.iii)
            rollback_file_permissions "$policy_id" "/etc/cron.hourly" "$original_value"
            ;;
            
        SRV-3.f.iv)
            rollback_file_permissions "$policy_id" "/etc/cron.daily" "$original_value"
            ;;
            
        SRV-3.f.v)
            rollback_file_permissions "$policy_id" "/etc/cron.weekly" "$original_value"
            ;;
            
        SRV-3.f.vi)
            rollback_file_permissions "$policy_id" "/etc/cron.monthly" "$original_value"
            ;;
            
        SRV-3.f.vii)
            rollback_cron_allow_deny "$policy_id" "$original_value"
            ;;
            
        # SSH
        SRV-3.g.i)
            rollback_file_permissions "$policy_id" "/etc/ssh/sshd_config" "$original_value"
            ;;
            
        SRV-3.g.ii)
            # SSH private keys - rollback all found keys
            for keyfile in /etc/ssh/ssh_host_*_key; do
                if [ -f "$keyfile" ]; then
                    rollback_file_permissions "$policy_id" "$keyfile" "$original_value"
                fi
            done
            ;;
            
        SRV-3.g.iii)
            # SSH public keys - rollback all found keys
            for keyfile in /etc/ssh/ssh_host_*_key.pub; do
                if [ -f "$keyfile" ]; then
                    rollback_file_permissions "$policy_id" "$keyfile" "$original_value"
                fi
            done
            ;;
            
        # Sudo
        SRV-3.h.i)
            # Don't remove sudo as it could break the system
            log_skip "Skipping sudo package removal for system safety"
            ((SKIPPED_ROLLBACKS++))
            mark_rollback_executed "$policy_id" "SKIPPED"
            ;;
            
        SRV-3.h.ii|SRV-3.h.iii)
            rollback_sudoers "$policy_id" "$policy_name"
            ;;
            
        *)
            log_warn "Unknown policy ID: $policy_id"
            ((SKIPPED_ROLLBACKS++))
            ;;
    esac
}

# =========================
# Main Function
# =========================
main() {
    log_info "========================================"
    log_info "Services Rollback Script"
    log_info "Module: $MODULE_NAME"
    log_info "========================================"
    
    # Check if database exists
    if [ ! -f "$DB_PATH" ]; then
        log_error "Database not found at $DB_PATH"
        log_error "No hardening has been performed yet"
        exit 1
    fi
    
    # Check if backup directory exists
    if [ ! -d "$BACKUP_DIR" ]; then
        log_error "Backup directory not found at $BACKUP_DIR"
        log_error "No backups available for rollback"
        exit 1
    fi
    
    # Get fix history from database
    log_info "Retrieving fix history from database..."
    local fix_history=$(get_fix_history)
    
    if [ "$fix_history" = "[]" ] || [ -z "$fix_history" ]; then
        log_info "No fixes found to rollback"
        exit 0
    fi
    
    # Count total fixes
    local total_fixes=$(echo "$fix_history" | python3 -c "import sys, json; print(len(json.load(sys.stdin)))")
    log_info "Found $total_fixes fixes to rollback"
    
    # Ask for confirmation
    echo ""
    read -p "Do you want to proceed with rollback? (yes/no): " confirmation
    if [ "$confirmation" != "yes" ]; then
        log_info "Rollback cancelled by user"
        exit 0
    fi
    
    echo ""
    log_info "Starting rollback process..."
    echo ""
    
    # Process each fix
    echo "$fix_history" | python3 -c "
import sys
import json

fixes = json.load(sys.stdin)
for fix in fixes:
    print(f\"{fix['policy_id']}|{fix['policy_name']}|{fix['original_value']}\")
" | while IFS='|' read -r policy_id policy_name original_value; do
        rollback_by_policy "$policy_id" "$policy_name" "$original_value"
    done
    
    # Print summary
    echo ""
    log_info "========================================"
    log_info "Rollback Summary"
    log_info "========================================"
    log_info "Total Rollbacks Attempted: $TOTAL_ROLLBACKS"
    log_success "Successful: $SUCCESS_ROLLBACKS"
    log_error "Failed: $FAILED_ROLLBACKS"
    log_skip "Skipped: $SKIPPED_ROLLBACKS"
    log_info "========================================"
    
    # Restart services that might need it
    log_info ""
    log_info "Restarting affected services..."
    systemctl restart cron 2>/dev/null && log_success "Restarted cron" || log_warn "Could not restart cron"
    systemctl restart sshd 2>/dev/null && log_success "Restarted sshd" || log_warn "Could not restart sshd"
    
    log_info ""
    log_info "Rollback completed!"
    log_info "Please review the output above for any errors"
}

# Run main function
main
