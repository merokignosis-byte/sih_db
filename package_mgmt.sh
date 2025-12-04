#!/usr/bin/env bash
# ============================================================================
# Package Management Hardening Script
# Module: Package Management
# Supports: scan | fix
# ============================================================================
MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/package_mgmt"
MODULE_NAME="Package Management"

mkdir -p "$BACKUP_DIR"

# ----------------------------------------------------------------------------
# Colors & Counters
# ----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0
MANUAL_CHECKS=0

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED_CHECKS++)); }
log_fixed() { echo -e "${BLUE}[FIXED]${NC} $1"; ((FIXED_CHECKS++)); }
log_manual(){ echo -e "${BLUE}[MANUAL]${NC} $1"; ((MANUAL_CHECKS++)); }

# ============================================================================
# Database initialization (creates scan_results and fix_history tables if missing)
# ============================================================================
init_database() {
python3 - <<'PY'
import sqlite3,sys,os
DB=os.environ.get('DB_PATH')
if not DB:
    print("DB_PATH not set", file=sys.stderr); sys.exit(1)
conn=sqlite3.connect(DB)
cur=conn.cursor()
cur.execute('''
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
cur.execute('''
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
conn.commit(); conn.close()
PY
}

export DB_PATH MODULE_NAME

# ============================================================================
# DB helpers: save_scan_result and save_fix_result (use parameterized inserts)
# ============================================================================
save_scan_result() {
    local pid="$1"; local pname="$2"; local expected="$3"; local current="$4"; local status="$5"
    python3 - <<PY
import sqlite3,os
DB=os.environ['DB_PATH']; MODULE=os.environ['MODULE_NAME']
conn=sqlite3.connect(DB)
cur=conn.cursor()
cur.execute('''
    INSERT OR REPLACE INTO scan_results
    (module_name, policy_id, policy_name, expected_value, current_value, status, scan_timestamp)
    VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
''', (MODULE, "$pid", "$pname", "$expected", "$current", "$status"))
conn.commit(); conn.close()
PY
}

save_fix_result() {
    local pid="$1"; local pname="$2"; local expected="$3"; local original="$4"; local current="$5"; local status="$6"
    python3 - <<PY
import sqlite3,os
DB=os.environ['DB_PATH']; MODULE=os.environ['MODULE_NAME']
conn=sqlite3.connect(DB)
cur=conn.cursor()
cur.execute('''
    INSERT OR REPLACE INTO fix_history
    (module_name, policy_id, policy_name, expected_value, original_value, current_value, status, fix_timestamp, rollback_executed)
    VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), 'NO')
''', (MODULE, "$pid", "$pname", "$expected", "$original", "$current", "$status"))
conn.commit(); conn.close()
PY
}

get_scan_value() {
    # returns the current_value from scan_results for a given policy_id (or empty)
    local pid="$1"
    python3 - <<PY
import sqlite3,os,sys,json
DB=os.environ['DB_PATH']; MODULE=os.environ['MODULE_NAME']
conn=sqlite3.connect(DB)
cur=conn.cursor()
cur.execute("SELECT current_value FROM scan_results WHERE module_name=? AND policy_id=?", (MODULE, "$pid"))
r=cur.fetchone()
conn.close()
print(r[0] if r else "")
PY
}

# ----------------------------------------------------------------------------
# Pretty-print result (network.sh style)
# ----------------------------------------------------------------------------
print_check_result() {
    local policy_id="$1"
    local policy_name="$2"
    local expected="$3"
    local current="$4"
    local status="$5"

    echo "=============================================="
    echo "Module Name    : $MODULE_NAME"
    echo "Policy ID      : $policy_id"
    echo "Policy Name    : $policy_name"
    echo "Expected Value : $expected"
    echo "Current Value  : $current"
    if [[ "$status" == "PASS" ]]; then
        echo -e "Status         : ${GREEN}$status${NC}"
    elif [[ "$status" == "FAIL" ]]; then
        echo -e "Status         : ${RED}$status${NC}"
    else
        echo -e "Status         : ${YELLOW}$status${NC}"
    fi
    echo "=============================================="
}

# ============================================================================
# ----------------------- PACKAGE MANAGEMENT POLICIES ------------------------
# 12 rules: PM-1-a.i .. PM-1-c.v
# ----------------------------------------------------------------------------

# -------------------------
# a. Configure Bootloader
# -------------------------
check_bootloader_password() {
    local policy_id="PM-1-a.i"
    local policy_name="Ensure bootloader password is set"
    local expected="password_pbkdf2 entry in grub config or /etc/grub.d/40_custom"
    ((TOTAL_CHECKS++))

    local found=""
    found="$(grep -R --line-number '^password_pbkdf2' /boot 2>/dev/null || true)"
    if grep -q '^password_pbkdf2' /etc/grub.d/40_custom 2>/dev/null; then
        found="40_custom"
    fi

    local current status
    if [ -n "$found" ]; then
        current="Bootloader password configured"
        status="PASS"
        log_pass "$policy_name"
        save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    else
        current="Bootloader password not configured"
        status="FAIL"
        log_error "$policy_name: $current"
        save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        ((FAILED_CHECKS++))
    fi
    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

fix_bootloader_password() {
    local policy_id="PM-1-a.i"
    local policy_name="Ensure bootloader password is set"
    local expected="password_pbkdf2 entry present"

    local orig="$(get_scan_value "$policy_id")"

    log_manual "Manual step required to set GRUB bootloader password."
    echo ""
    echo "Run these exact commands (interactive) to create and install a PBKDF2 hash:"
    echo "-----------------------------------------------------------------------"
    echo "sudo grub-mkpasswd-pbkdf2"
    echo " # copy the generated 'grub.pbkdf2.sha512...' hash"
    echo "sudo bash -c 'cat >> /etc/grub.d/40_custom <<EOF'"
    echo "set superusers=\"root\""
    echo "password_pbkdf2 root <paste-hash-here>"
    echo "EOF"
    echo "sudo chmod +x /etc/grub.d/40_custom"
    echo "sudo update-grub"
    echo "-----------------------------------------------------------------------"
    save_fix_result "$policy_id" "$policy_name" "$expected" "$orig" "Manual change required" "MANUAL"
}

check_bootloader_permissions() {
    local policy_id="PM-1-a.ii"
    local policy_name="Ensure access to bootloader config is configured"
    local expected="grub config owned by root:root and mode 400"
    ((TOTAL_CHECKS++))

    local files=( /boot/grub/grub.cfg /boot/grub2/grub.cfg /boot/efi/EFI/*/grub.cfg )
    local found=""
    for f in "${files[@]}"; do
        [ -f "$f" ] && { found="$f"; break; }
    done

    local current status
    if [ -z "$found" ]; then
        current="No grub config found"
        status="FAIL"
        log_error "$policy_name: $current"
        ((FAILED_CHECKS++))
    else
        perms=$(stat -c %a "$found" 2>/dev/null || echo "")
        owner=$(stat -c %U "$found" 2>/dev/null || echo "")
        group=$(stat -c %G "$found" 2>/dev/null || echo "")
        current="$perms $owner:$group"
        if [ "$perms" = "400" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
            status="PASS"
            log_pass "$policy_name"
        else
            status="FAIL"
            log_error "$policy_name: $current"
            ((FAILED_CHECKS++))
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

fix_bootloader_permissions() {
    local policy_id="PM-1-a.ii"
    local policy_name="Ensure access to bootloader config is configured"
    local expected="400 root:root"

    local orig="$(get_scan_value "$policy_id")"

    local files=( /boot/grub/grub.cfg /boot/grub2/grub.cfg /boot/efi/EFI/*/grub.cfg )
    local found=""
    for f in "${files[@]}"; do
        [ -f "$f" ] && { found="$f"; break; }
    done

    if [ -z "$found" ]; then
        log_error "GRUB config not found; cannot fix automatically"
        save_fix_result "$policy_id" "$policy_name" "$expected" "$orig" "Not found" "FAIL"
        ((FAILED_CHECKS++))
        return 1
    fi

    cp "$found" "$BACKUP_DIR/$(basename "$found").bak.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
    chown root:root "$found"
    chmod 400 "$found"
    log_fixed "Set $found to 400 root:root"
    save_fix_result "$policy_id" "$policy_name" "$expected" "$orig" "400 root:root" "FIXED"
}

# -------------------------
# b. Configure Additional Process Hardening
# -------------------------
check_aslr() {
    local policy_id="PM-1-b.i"
    local policy_name="Ensure address space layout randomization is enabled"
    local expected="kernel.randomize_va_space = 2"
    ((TOTAL_CHECKS++))

    local val
    val=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "")
    local current status
    current="$val"
    if [ "$val" = "2" ]; then
        status="PASS"
        log_pass "$policy_name"
    else
        status="FAIL"
        log_error "$policy_name: current=$val"
        ((FAILED_CHECKS++))
    fi
    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

fix_aslr() {
    local policy_id="PM-1-b.i"
    local policy_name="Ensure address space layout randomization is enabled"
    local expected="kernel.randomize_va_space = 2"

    local orig="$(get_scan_value "$policy_id")"

    sysctl -w kernel.randomize_va_space=2 >/dev/null 2>&1
    if grep -q "^kernel.randomize_va_space" /etc/sysctl.conf 2>/dev/null; then
        sed -i 's/^kernel.randomize_va_space.*/kernel.randomize_va_space = 2/' /etc/sysctl.conf
    else
        echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
    fi
    log_fixed "ASLR set to 2"
    save_fix_result "$policy_id" "$policy_name" "$expected" "$orig" "2" "FIXED"
}

check_ptrace_scope() {
    local policy_id="PM-1-b.ii"
    local policy_name="Ensure ptrace_scope is restricted"
    local expected="kernel.yama.ptrace_scope = 1 (or 2)"
    ((TOTAL_CHECKS++))

    local val
    val=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null || echo "")
    local current status
    current="$val"
    if [ "$val" = "1" ] || [ "$val" = "2" ]; then
        status="PASS"
        log_pass "$policy_name"
    else
        status="FAIL"
        log_error "$policy_name: current=$val"
        ((FAILED_CHECKS++))
    fi
    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

fix_ptrace_scope() {
    local policy_id="PM-1-b.ii"
    local policy_name="Ensure ptrace_scope is restricted"
    local expected="kernel.yama.ptrace_scope = 1"

    local orig="$(get_scan_value "$policy_id")"

    sysctl -w kernel.yama.ptrace_scope=1 >/dev/null 2>&1
    if grep -q "^kernel.yama.ptrace_scope" /etc/sysctl.conf 2>/dev/null; then
        sed -i 's/^kernel.yama.ptrace_scope.*/kernel.yama.ptrace_scope = 1/' /etc/sysctl.conf
    else
        echo "kernel.yama.ptrace_scope = 1" >> /etc/sysctl.conf
    fi
    log_fixed "ptrace_scope set to 1"
    save_fix_result "$policy_id" "$policy_name" "$expected" "$orig" "1" "FIXED"
}

check_core_dumps() {
    local policy_id="PM-1-b.iii"
    local policy_name="Ensure core dumps are restricted"
    local expected="fs.suid_dumpable = 0 and * hard core 0 in /etc/security/limits.conf"
    ((TOTAL_CHECKS++))

    local suid limits_ok
    suid=$(sysctl -n fs.suid_dumpable 2>/dev/null || echo "")
    if grep -q "^[^#]*\*.*hard.*core.*0" /etc/security/limits.conf 2>/dev/null; then
        limits_ok="yes"
    else
        limits_ok="no"
    fi

    local current status
    current="suid_dumpable=$suid limits_core0=$limits_ok"
    if [ "$suid" = "0" ] && [ "$limits_ok" = "yes" ]; then
        status="PASS"
        log_pass "$policy_name"
    else
        status="FAIL"
        log_error "$policy_name: $current"
        ((FAILED_CHECKS++))
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

fix_core_dumps() {
    local policy_id="PM-1-b.iii"
    local policy_name="Ensure core dumps are restricted"
    local expected="fs.suid_dumpable = 0 and * hard core 0"

    local orig="$(get_scan_value "$policy_id")"

    cp /etc/security/limits.conf "$BACKUP_DIR/limits.conf.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
    grep -q "^[^#]*\*.*hard.*core.*0" /etc/security/limits.conf 2>/dev/null || echo "* hard core 0" >> /etc/security/limits.conf
    sysctl -w fs.suid_dumpable=0 >/dev/null 2>&1
    if grep -q "^fs.suid_dumpable" /etc/sysctl.conf 2>/dev/null; then
        sed -i 's/^fs.suid_dumpable.*/fs.suid_dumpable = 0/' /etc/sysctl.conf
    else
        echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
    fi
    log_fixed "Core dumps restricted"
    save_fix_result "$policy_id" "$policy_name" "$expected" "$orig" "suid_dumpable=0; core=0" "FIXED"
}

check_prelink() {
    local policy_id="PM-1-b.iv"
    local policy_name="Ensure prelink is not installed"
    local expected="prelink not installed"
    ((TOTAL_CHECKS++))

    if dpkg -l 2>/dev/null | grep -q "^ii.*prelink"; then
        log_error "$policy_name: prelink installed"
        save_scan_result "$policy_id" "$policy_name" "$expected" "installed" "FAIL"
        ((FAILED_CHECKS++))
        print_check_result "$policy_id" "$policy_name" "$expected" "installed" "FAIL"
    else
        log_pass "$policy_name"
        save_scan_result "$policy_id" "$policy_name" "$expected" "not_installed" "PASS"
        print_check_result "$policy_id" "$policy_name" "$expected" "not_installed" "PASS"
    fi
}

fix_prelink() {
    local policy_id="PM-1-b.iv"
    local policy_name="Ensure prelink is not installed"
    local expected="prelink removed"

    local orig="$(get_scan_value "$policy_id")"

    if dpkg -l 2>/dev/null | grep -q "^ii.*prelink"; then
        apt-get remove -y prelink >/dev/null 2>&1 && log_fixed "prelink removed" || log_warn "Failed to remove prelink automatically"
        save_fix_result "$policy_id" "$policy_name" "$expected" "$orig" "removed" "FIXED"
    else
        log_info "prelink not present"
        save_fix_result "$policy_id" "$policy_name" "$expected" "$orig" "not_installed" "FIXED"
    fi
}

check_apport() {
    local policy_id="PM-1-b.v"
    local policy_name="Ensure Automatic Error Reporting is not enabled"
    local expected="apport disabled"
    ((TOTAL_CHECKS++))

    local enabled
    enabled=$(systemctl is-enabled apport 2>/dev/null || echo "missing")
    local current status
    if echo "$enabled" | grep -q "enabled"; then
        current="enabled"
        status="FAIL"
        log_error "$policy_name: $current"
        ((FAILED_CHECKS++))
    else
        current="disabled_or_missing"
        status="PASS"
        log_pass "$policy_name"
    fi
    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

fix_apport() {
    local policy_id="PM-1-b.v"
    local policy_name="Ensure Automatic Error Reporting is not enabled"
    local expected="apport disabled"

    local orig="$(get_scan_value "$policy_id")"

    if systemctl is-enabled apport 2>/dev/null | grep -q "enabled"; then
        systemctl disable --now apport >/dev/null 2>&1 && log_fixed "apport disabled" || log_warn "Could not disable apport automatically"
        save_fix_result "$policy_id" "$policy_name" "$expected" "$orig" "disabled" "FIXED"
    else
        save_fix_result "$policy_id" "$policy_name" "$expected" "$orig" "already_disabled" "FIXED"
    fi
}

# -------------------------
# c. Configure Command Line Warning Banners & access
# -------------------------
check_issue_banner() {
    local policy_id="PM-1-c.i"
    local policy_name="Ensure local login warning banner is configured properly"
    local expected="/etc/issue non-empty and sanitized"
    ((TOTAL_CHECKS++))

    local current status
    if [ -f /etc/issue ] && [ -s /etc/issue ] && ! grep -qE '\\v|\\r|\\m|\\s' /etc/issue 2>/dev/null; then
        current="/etc/issue configured"
        status="PASS"
        log_pass "$policy_name"
    else
        current="/etc/issue missing or misconfigured"
        status="FAIL"
        log_error "$policy_name: $current"
        ((FAILED_CHECKS++))
    fi
    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

fix_issue_banner() {
    local policy_id="PM-1-c.i"
    local policy_name="Ensure local login warning banner is configured properly"
    local expected="/etc/issue set to default banner"

    local orig="$(get_scan_value "$policy_id")"

    cp /etc/issue "$BACKUP_DIR/issue.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
    cat > /etc/issue <<'EOF'
***************************************************************************
                            NOTICE TO USERS
This computer system is for authorized use only.
***************************************************************************
EOF
    chmod 644 /etc/issue
    log_fixed "/etc/issue banner configured"
    save_fix_result "$policy_id" "$policy_name" "$expected" "$orig" "/etc/issue configured" "FIXED"
}

check_issue_net_banner() {
    local policy_id="PM-1-c.ii"
    local policy_name="Ensure remote login warning banner is configured properly"
    local expected="/etc/issue.net non-empty and sanitized"
    ((TOTAL_CHECKS++))

    local current status
    if [ -f /etc/issue.net ] && [ -s /etc/issue.net ] && ! grep -qE '\\v|\\r|\\m|\\s' /etc/issue.net 2>/dev/null; then
        current="/etc/issue.net configured"
        status="PASS"
        log_pass "$policy_name"
    else
        current="/etc/issue.net missing or misconfigured"
        status="FAIL"
        log_error "$policy_name: $current"
        ((FAILED_CHECKS++))
    fi
    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

fix_issue_net_banner() {
    local policy_id="PM-1-c.ii"
    local policy_name="Ensure remote login warning banner is configured properly"
    local expected="/etc/issue.net set to default banner"

    local orig="$(get_scan_value "$policy_id")"

    cp /etc/issue.net "$BACKUP_DIR/issue.net.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
    cat > /etc/issue.net <<'EOF'
***************************************************************************
                            NOTICE TO REMOTE USERS
This system is for authorized use only.
***************************************************************************
EOF
    chmod 644 /etc/issue.net
    log_fixed "/etc/issue.net banner configured"
    save_fix_result "$policy_id" "$policy_name" "$expected" "$orig" "/etc/issue.net configured" "FIXED"
}

check_motd_access() {
    local policy_id="PM-1-c.iii"
    local policy_name="Ensure access to /etc/motd is configured"
    local expected="/etc/motd owned by root and readable"
    ((TOTAL_CHECKS++))

    local current status
    if [ -f /etc/motd ]; then
        perms=$(stat -c %a /etc/motd 2>/dev/null || echo "")
        owner=$(stat -c %U /etc/motd 2>/dev/null || echo "")
        current="$perms $owner"
        if [ "$owner" = "root" ]; then
            status="PASS"
            log_pass "$policy_name"
        else
            status="FAIL"
            log_error "$policy_name: $current"
            ((FAILED_CHECKS++))
        fi
    else
        current="missing"
        status="FAIL"
        log_error "$policy_name: $current"
        ((FAILED_CHECKS++))
    fi
    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

fix_motd_access() {
    local policy_id="PM-1-c.iii"
    local policy_name="Ensure access to /etc/motd is configured"
    local expected="root:root 644"

    local orig="$(get_scan_value "$policy_id")"

    if [ ! -f /etc/motd ]; then
        echo "Welcome to this system." > /etc/motd
    fi
    chown root:root /etc/motd
    chmod 644 /etc/motd
    log_fixed "/etc/motd ownership & perms set"
    save_fix_result "$policy_id" "$policy_name" "$expected" "$orig" "root:root 644" "FIXED"
}

check_issue_access() {
    local policy_id="PM-1-c.iv"
    local policy_name="Ensure access to /etc/issue is configured"
    local expected="/etc/issue owned by root and readable"
    ((TOTAL_CHECKS++))

    local current status
    if [ -f /etc/issue ]; then
        perms=$(stat -c %a /etc/issue 2>/dev/null || echo "")
        owner=$(stat -c %U /etc/issue 2>/dev/null || echo "")
        current="$perms $owner"
        if [ "$owner" = "root" ]; then
            status="PASS"
            log_pass "$policy_name"
        else
            status="FAIL"
            log_error "$policy_name: $current"
            ((FAILED_CHECKS++))
        fi
    else
        current="missing"
        status="FAIL"
        log_error "$policy_name: $current"
        ((FAILED_CHECKS++))
    fi
    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

fix_issue_access() {
    local policy_id="PM-1-c.iv"
    local policy_name="Ensure access to /etc/issue is configured"
    local expected="root:root 644"

    local orig="$(get_scan_value "$policy_id")"

    if [ ! -f /etc/issue ]; then
        echo "NOTICE TO USERS" > /etc/issue
    fi
    chown root:root /etc/issue
    chmod 644 /etc/issue
    log_fixed "/etc/issue ownership & perms set"
    save_fix_result "$policy_id" "$policy_name" "$expected" "$orig" "root:root 644" "FIXED"
}

check_issue_net_access() {
    local policy_id="PM-1-c.v"
    local policy_name="Ensure access to /etc/issue.net is configured"
    local expected="/etc/issue.net owned by root and readable"
    ((TOTAL_CHECKS++))

    local current status
    if [ -f /etc/issue.net ]; then
        perms=$(stat -c %a /etc/issue.net 2>/dev/null || echo "")
        owner=$(stat -c %U /etc/issue.net 2>/dev/null || echo "")
        current="$perms $owner"
        if [ "$owner" = "root" ]; then
            status="PASS"
            log_pass "$policy_name"
        else
            status="FAIL"
            log_error "$policy_name: $current"
            ((FAILED_CHECKS++))
        fi
    else
        current="missing"
        status="FAIL"
        log_error "$policy_name: $current"
        ((FAILED_CHECKS++))
    fi
    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

fix_issue_net_access() {
    local policy_id="PM-1-c.v"
    local policy_name="Ensure access to /etc/issue.net is configured"
    local expected="root:root 644"

    local orig="$(get_scan_value "$policy_id")"

    if [ ! -f /etc/issue.net ]; then
        echo "NOTICE TO REMOTE USERS" > /etc/issue.net
    fi
    chown root:root /etc/issue.net
    chmod 644 /etc/issue.net
    log_fixed "/etc/issue.net ownership & perms set"
    save_fix_result "$policy_id" "$policy_name" "$expected" "$orig" "root:root 644" "FIXED"
}

# ============================================================================
# Main Execution
# ============================================================================
main() {
    echo "========================================================================"
    echo "Package Management Hardening Script"
    echo "Module: $MODULE_NAME"
    echo "Mode: $MODE"
    echo "========================================================================"

    init_database

    if [ "$MODE" = "fix" ] && [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root for fix mode"
        exit 1
    fi

    # SCAN functions
    check_bootloader_password
    check_bootloader_permissions

    check_aslr
    check_ptrace_scope
    check_core_dumps
    check_prelink
    check_apport

    check_issue_banner
    check_issue_net_banner
    check_motd_access
    check_issue_access
    check_issue_net_access

    # If fix mode, attempt remediation and log fixes using fix_history schema
    if [ "$MODE" = "fix" ]; then
        # Bootloader password remains manual (security reasons)
        fix_bootloader_password
        fix_bootloader_permissions

        fix_aslr
        fix_ptrace_scope
        fix_core_dumps
        fix_prelink
        fix_apport

        fix_issue_banner
        fix_issue_net_banner
        fix_motd_access
        fix_issue_access
        fix_issue_net_access
    fi

    # Summary
    echo ""
    echo "========================================================================"
    echo "Package Management Hardening Summary"
    echo "========================================================================"
    echo "Total Checks: $TOTAL_CHECKS"
    echo "Passed: $PASSED_CHECKS"
    echo "Failed: $FAILED_CHECKS"
    echo "Fixed:  $FIXED_CHECKS"
    echo "Manual Actions Required: $MANUAL_CHECKS"
    echo "========================================================================"
}

main

