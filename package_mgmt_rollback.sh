#!/bin/bash
# ============================================================================
# Rollback Script for Package Management Module (Updated)
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="$SCRIPT_DIR/../backups/package_mgmt"
DB_PATH="$SCRIPT_DIR/../hardening.db"

# Colors
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

# ----------------------------------------------------------------------------
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Must be run as root"
        exit 1
    fi
}

check_database() {
    if [ ! -f "$DB_PATH" ]; then
        log_error "Database not found: $DB_PATH"
        exit 1
    fi
}

get_fixes() {
    python3 << PY
import sqlite3, json
conn = sqlite3.connect('$DB_PATH')
cur = conn.cursor()
cur.execute("""
SELECT policy_id, policy_name, original_value, current_value
FROM fix_history
WHERE module_name='Package Management' AND rollback_executed='NO'
ORDER BY policy_id
""")
rows = cur.fetchall()
conn.close()
print(json.dumps(rows))
PY
}

mark_rollback_executed() {
    local policy_id="$1"
    python3 - << PY
import sqlite3
conn = sqlite3.connect('$DB_PATH')
cur = conn.cursor()
cur.execute("UPDATE fix_history SET rollback_executed='YES' WHERE module_name='Package Management' AND policy_id=?", ('$policy_id',))
conn.commit()
conn.close()
PY
}

# ----------------------------------------------------------------------------
rollback_file() {
    local file="$1"
    local policy_id="$2"
    # Determine exact basename for backup
    local base
    case "$file" in
        /boot/grub/grub.cfg) base="grub.cfg.bak" ;;
        /etc/issue) base="issue.bak" ;;
        /etc/issue.net) base="issue.net.bak" ;;
        /etc/motd) base="motd.bak" ;;
        *) base="$(basename "$file").bak" ;;
    esac

    # Find latest backup for this file
    local backup_file
    backup_file=$(ls -1t "$BACKUP_DIR/$base".* 2>/dev/null | head -n1)

    if [ -f "$backup_file" ]; then
        cp "$backup_file" "$file"
        if [ $? -eq 0 ]; then
            log_success "Restored $file from $backup_file"
            ((SUCCESS_ROLLBACKS++))
            mark_rollback_executed "$policy_id"
        else
            log_error "Failed to restore $file"
            ((FAILED_ROLLBACKS++))
        fi
    else
        log_warn "No backup found for $file"
        ((FAILED_ROLLBACKS++))
    fi
    ((TOTAL_ROLLBACKS++))
}

rollback_sysctl() {
    local key="$1"
    local value="$2"
    local policy_id="$3"
    # Restore runtime value
    sysctl -w "$key=$value" >/dev/null 2>&1
    # Restore /etc/sysctl.conf
    if grep -q "^$key" /etc/sysctl.conf 2>/dev/null; then
        sed -i "s/^$key.*/$key = $value/" /etc/sysctl.conf
    else
        echo "$key = $value" >> /etc/sysctl.conf
    fi
    log_success "Restored $key to $value"
    ((SUCCESS_ROLLBACKS++))
    mark_rollback_executed "$policy_id"
    ((TOTAL_ROLLBACKS++))
}

rollback_remove_package() {
    local pkg="$1"
    local policy_id="$2"
    if dpkg -l | grep -qw "$pkg"; then
        log_warn "$pkg is installed, cannot remove automatically"
        ((FAILED_ROLLBACKS++))
    else
        log_success "$pkg is not installed (original state preserved)"
        ((SUCCESS_ROLLBACKS++))
        mark_rollback_executed "$policy_id"
    fi
    ((TOTAL_ROLLBACKS++))
}

# ----------------------------------------------------------------------------
main() {
    check_root
    check_database

    fixes=$(get_fixes)
    if [ "$fixes" = "[]" ]; then
        log_info "No fixes to rollback"
        exit 0
    fi

    echo "========================================================================"
    echo "Package Management Rollback Script"
    echo "========================================================================"
    echo "The following items will be rolled back:"
    echo "$fixes" | python3 -c "import sys,json; [print(f'Policy ID: {i[0]} | Name: {i[1]} | Original Value: {i[2]}') for i in json.load(sys.stdin)]"
    echo "========================================================================"
    read -p "Proceed with rollback? (yes/no): " confirm
    if [[ "$confirm" != "yes" && "$confirm" != "y" ]]; then
        log_info "Rollback cancelled"
        exit 0
    fi

    echo ""
    log_info "Starting rollback..."
    echo ""

    echo "$fixes" | python3 -c "import sys,json; [print('|'.join(map(str,i))) for i in json.load(sys.stdin)]" | while IFS='|' read -r pid pname orig curr; do
        case "$pname" in
            "Ensure bootloader password is set"|"Ensure access to bootloader config is configured")
                rollback_file "/boot/grub/grub.cfg" "$pid"
                ;;
            "Ensure address space layout randomization is enabled")
                rollback_sysctl "kernel.randomize_va_space" "$orig" "$pid"
                ;;
            "Ensure ptrace_scope is restricted")
                rollback_sysctl "kernel.yama.ptrace_scope" "$orig" "$pid"
                ;;
            "Ensure core dumps are restricted")
                rollback_sysctl "fs.suid_dumpable" "${orig%% *}" "$pid"
                ;;
            "Ensure prelink is not installed")
                rollback_remove_package "prelink" "$pid"
                ;;
            "Ensure Automatic Error Reporting is not enabled")
                rollback_remove_package "apport" "$pid"
                ;;
            "Ensure local login warning banner is configured properly")
                rollback_file "/etc/issue" "$pid"
                ;;
            "Ensure remote login warning banner is configured properly")
                rollback_file "/etc/issue.net" "$pid"
                ;;
            "Ensure access to /etc/motd is configured")
                rollback_file "/etc/motd" "$pid"
                ;;
            "Ensure access to /etc/issue is configured")
                rollback_file "/etc/issue" "$pid"
                ;;
            "Ensure access to /etc/issue.net is configured")
                rollback_file "/etc/issue.net" "$pid"
                ;;
            *)
                log_warn "No rollback logic for $pname"
                ((TOTAL_ROLLBACKS++))
                ((FAILED_ROLLBACKS++))
                ;;
        esac
    done

    echo ""
    echo "========================================================================"
    echo "Rollback Summary"
    echo "========================================================================"
    echo "Total Rollback Operations: $TOTAL_ROLLBACKS"
    echo "Successful: $SUCCESS_ROLLBACKS"
    echo "Failed: $FAILED_ROLLBACKS"
    echo "========================================================================"
    log_info "Rollback completed for Package Management module"
}

main

