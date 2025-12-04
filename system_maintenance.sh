#!/usr/bin/env bash

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/system_maintenance"
MODULE_NAME="System Maintenance"

# Ensure backup dir exists
mkdir -p "$BACKUP_DIR"
mkdir -p "$(dirname "$DB_PATH")"

# Colors (match network.sh scheme)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
TOTAL_CHECKS=23
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0
MANUAL_CHECKS=0

# Counter increment helpers
inc_pass()   { ((PASSED_CHECKS++)); }
inc_fail()   { ((FAILED_CHECKS++)); }
inc_fixed()  { ((FIXED_CHECKS++)); }
inc_manual() { ((MANUAL_CHECKS++)); }

# Print colored header and footer like network.sh example
print_header() {
    echo -e "${BLUE}========================================================================${NC}"
    echo -e "${BLUE}${MODULE_NAME} Hardening - Module: ${MODULE_NAME}${NC}"
    echo -e "${BLUE}Mode: $MODE${NC}"
    echo -e "${BLUE}========================================================================${NC}"
}

print_footer() {
    echo -e "${BLUE}========================================================================${NC}"
}

# Standard boxed output (exact layout)
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
    # Color the status token itself for easier reading, but keep layout identical
    if [ "$status" = "PASS" ]; then
        echo -e "Status         : ${GREEN}$status${NC}"
    elif [ "$status" = "FAIL" ]; then
        echo -e "Status         : ${RED}$status${NC}"
    elif [ "$status" = "FIXED" ]; then
        echo -e "Status         : ${BLUE}$status${NC}"
    elif [ "$status" = "MANUAL" ]; then
        echo -e "Status         : ${YELLOW}$status${NC}"
    else
        echo "Status         : $status"
    fi
    echo "=============================================="
}

# Initialize DB tables (scan_results, fix_history)
initialize_db() {
    # Create DB file if missing
    if [ ! -f "$DB_PATH" ]; then
        sqlite3 "$DB_PATH" "VACUUM;" 2>/dev/null || true
    fi

    sqlite3 "$DB_PATH" "CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            module_name TEXT NOT NULL,
            policy_id TEXT NOT NULL,
            policy_name TEXT NOT NULL,
            expected_value TEXT NOT NULL,
            current_value TEXT NOT NULL,
            status TEXT NOT NULL,
            scan_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(module_name, policy_id)
        );" 2>/dev/null || true

    sqlite3 "$DB_PATH" "CREATE TABLE IF NOT EXISTS fix_history (
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
        );" 2>/dev/null || true
}

# Save scan result (insert or replace by module+policy)
save_scan_result() {
    local pid="$1"; local pname="$2"; local expected="$3"; local current="$4"; local status="$5"
    python3 - <<PY 2>/dev/null
import sqlite3
conn = sqlite3.connect(r"$DB_PATH")
c = conn.cursor()
c.execute("""
INSERT OR REPLACE INTO scan_results
(module_name, policy_id, policy_name, expected_value, current_value, status)
VALUES (?, ?, ?, ?, ?, ?)
""", (r"$MODULE_NAME", r"$pid", r"$pname", r"$expected", r"$current", r"$status"))
conn.commit()
conn.close()
PY
}

# Save fix result
save_fix_result() {
    local pid="$1"; local pname="$2"; local expected="$3"; local original="$4"; local current="$5"; local status="$6"
    python3 - <<PY 2>/dev/null
import sqlite3
conn = sqlite3.connect(r"$DB_PATH")
c = conn.cursor()
c.execute("""
INSERT OR REPLACE INTO fix_history
(module_name, policy_id, policy_name, expected_value, original_value, current_value, status)
VALUES (?, ?, ?, ?, ?, ?, ?)
""", (r"$MODULE_NAME", r"$pid", r"$pname", r"$expected", r"$original", r"$current", r"$status"))
conn.commit()
conn.close()
PY
}

# Utility helpers
file_exists() { [ -e "$1" ]; }
get_mode() { stat -c "%a" "$1" 2>/dev/null || echo "missing"; }

# Default expected modes - you allowed either; choose 600 for shadow/gshadow (sensible and safe)
EXPECTED_PASSWD="644"
EXPECTED_PASSWD_DASH="600,644"
EXPECTED_GROUP="644"
EXPECTED_GROUP_DASH="600,644"
EXPECTED_SHADOW="600,640"
EXPECTED_SHADOW_DASH="600"
EXPECTED_GSHADOW="600,640"
EXPECTED_GSHADOW_DASH="600"
EXPECTED_SHELLS="644"
EXPECTED_OPASSWD="600,644"

# ---------------------------
# Policy functions (23)
# ---------------------------

# 1) SM-9.a.i Ensure permissions on /etc/passwd are configured
check_sm_9_a_i() {
    local pid="SM-9.a.i"
    local pname="Ensure permissions on /etc/passwd are configured"
    local expected="$EXPECTED_PASSWD"
    if [ "$MODE" = "scan" ]; then
        if ! file_exists "/etc/passwd"; then
            local current="file not found"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAIL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "FAIL"
            inc_fail
            return
        fi
        local current
        current="$(get_mode /etc/passwd)"
        # Accept only one mode (644)
        if [ "$current" = "644" ]; then
            print_check_result "$pid" "$pname" "$expected" "$current" "PASS"
            save_scan_result "$pid" "$pname" "$expected" "$current" "PASS"
            inc_pass
        else
            print_check_result "$pid" "$pname" "$expected" "$current" "FAIL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "FAIL"
            inc_fail
        fi
    else # fix
        if ! file_exists "/etc/passwd"; then
            current="file not found"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAILED"
            save_fix_result "$pid" "$pname" "$expected" "missing" "missing" "FAILED"
            inc_fail
            return
        fi
        local original
        original="$(get_mode /etc/passwd)"
        if chmod 644 /etc/passwd 2>/dev/null; then
            local current
            current="$(get_mode /etc/passwd)"
            print_check_result "$pid" "$pname" "$expected" "$current" "FIXED"
            save_fix_result "$pid" "$pname" "$expected" "$original" "$current" "FIXED"
            inc_fixed
        else
            local current
            current="$original"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAILED"
            save_fix_result "$pid" "$pname" "$expected" "$original" "$current" "FAILED"
            inc_fail
        fi
    fi
}

# 2) SM-9.a.ii Ensure permissions on /etc/passwd- are configured
check_sm_9_a_ii() {
    local pid="SM-9.a.ii"
    local pname="Ensure permissions on /etc/passwd- are configured"
    local expected="$EXPECTED_PASSWD_DASH"
    if [ "$MODE" = "scan" ]; then
        if ! file_exists "/etc/passwd-"; then
            local current="file not found"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAIL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "FAIL"
            inc_fail
            return
        fi
        local current
        current="$(get_mode /etc/passwd-)"
        # Accept 600 or 644
        if [ "$current" = "600" ] || [ "$current" = "644" ]; then
            print_check_result "$pid" "$pname" "$expected" "$current" "PASS"
            save_scan_result "$pid" "$pname" "$expected" "$current" "PASS"
            inc_pass
        else
            print_check_result "$pid" "$pname" "$expected" "$current" "FAIL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "FAIL"
            inc_fail
        fi
    else
        if ! file_exists "/etc/passwd-"; then
            current="file not found"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAILED"
            save_fix_result "$pid" "$pname" "$expected" "missing" "missing" "FAILED"
            inc_fail
            return
        fi
        local original
        original="$(get_mode /etc/passwd-)"
        # prefer 600 as strict mode
        if chmod 600 /etc/passwd- 2>/dev/null; then
            local current
            current="$(get_mode /etc/passwd-)"
            print_check_result "$pid" "$pname" "$expected" "$current" "FIXED"
            save_fix_result "$pid" "$pname" "$expected" "$original" "$current" "FIXED"
            inc_fixed
        else
            current="$original"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAILED"
            save_fix_result "$pid" "$pname" "$expected" "$original" "$current" "FAILED"
            inc_fail
        fi
    fi
}

# 3) SM-9.a.iii Ensure permissions on /etc/group are configured
check_sm_9_a_iii() {
    local pid="SM-9.a.iii"
    local pname="Ensure permissions on /etc/group are configured"
    local expected="$EXPECTED_GROUP"
    if [ "$MODE" = "scan" ]; then
        if ! file_exists "/etc/group"; then
            current="file not found"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAIL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "FAIL"
            inc_fail
            return
        fi
        current="$(get_mode /etc/group)"
        if [ "$current" = "644" ]; then
            print_check_result "$pid" "$pname" "$expected" "$current" "PASS"
            save_scan_result "$pid" "$pname" "$expected" "$current" "PASS"
            inc_pass
        else
            print_check_result "$pid" "$pname" "$expected" "$current" "FAIL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "FAIL"
            inc_fail
        fi
    else
        if ! file_exists "/etc/group"; then
            current="file not found"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAILED"
            save_fix_result "$pid" "$pname" "$expected" "missing" "missing" "FAILED"
            inc_fail
            return
        fi
        original="$(get_mode /etc/group)"
        if chmod 644 /etc/group 2>/dev/null; then
            current="$(get_mode /etc/group)"
            print_check_result "$pid" "$pname" "$expected" "$current" "FIXED"
            save_fix_result "$pid" "$pname" "$expected" "$original" "$current" "FIXED"
            inc_fixed
        else
            current="$original"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAILED"
            save_fix_result "$pid" "$pname" "$expected" "$original" "$current" "FAILED"
            inc_fail
        fi
    fi
}

# 4) SM-9.a.iv Ensure permissions on /etc/group- are configured
check_sm_9_a_iv() {
    local pid="SM-9.a.iv"
    local pname="Ensure permissions on /etc/group- are configured"
    local expected="$EXPECTED_GROUP_DASH"
    if [ "$MODE" = "scan" ]; then
        if ! file_exists "/etc/group-"; then
            current="file not found"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAIL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "FAIL"
            inc_fail
            return
        fi
        current="$(get_mode /etc/group-)"
        if [ "$current" = "600" ] || [ "$current" = "644" ]; then
            print_check_result "$pid" "$pname" "$expected" "$current" "PASS"
            save_scan_result "$pid" "$pname" "$expected" "$current" "PASS"
            inc_pass
        else
            print_check_result "$pid" "$pname" "$expected" "$current" "FAIL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "FAIL"
            inc_fail
        fi
    else
        if ! file_exists "/etc/group-"; then
            current="file not found"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAILED"
            save_fix_result "$pid" "$pname" "$expected" "missing" "missing" "FAILED"
            inc_fail
            return
        fi
        original="$(get_mode /etc/group-)"
        if chmod 600 /etc/group- 2>/dev/null; then
            current="$(get_mode /etc/group-)"
            print_check_result "$pid" "$pname" "$expected" "$current" "FIXED"
            save_fix_result "$pid" "$pname" "$expected" "$original" "$current" "FIXED"
            inc_fixed
        else
            current="$original"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAILED"
            save_fix_result "$pid" "$pname" "$expected" "$original" "$current" "FAILED"
            inc_fail
        fi
    fi
}

# 5) SM-9.a.v Ensure permissions on /etc/shadow are configured
check_sm_9_a_v() {
    local pid="SM-9.a.v"
    local pname="Ensure permissions on /etc/shadow are configured"
    local expected="$EXPECTED_SHADOW"
    if [ "$MODE" = "scan" ]; then
        if ! file_exists "/etc/shadow"; then
            current="file not found"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAIL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "FAIL"
            inc_fail
            return
        fi
        current="$(get_mode /etc/shadow)"
        # Accept 600 or 640
        if [ "$current" = "600" ] || [ "$current" = "640" ]; then
            print_check_result "$pid" "$pname" "$expected" "$current" "PASS"
            save_scan_result "$pid" "$pname" "$expected" "$current" "PASS"
            inc_pass
        else
            print_check_result "$pid" "$pname" "$expected" "$current" "FAIL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "FAIL"
            inc_fail
        fi
    else
        if ! file_exists "/etc/shadow"; then
            current="file not found"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAILED"
            save_fix_result "$pid" "$pname" "$expected" "missing" "missing" "FAILED"
            inc_fail
            return
        fi
        original="$(get_mode /etc/shadow)"
        # Prefer 600; change to 600
        if chmod 600 /etc/shadow 2>/dev/null; then
            current="$(get_mode /etc/shadow)"
            print_check_result "$pid" "$pname" "$expected" "$current" "FIXED"
            save_fix_result "$pid" "$pname" "$expected" "$original" "$current" "FIXED"
            inc_fixed
        else
            current="$original"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAILED"
            save_fix_result "$pid" "$pname" "$expected" "$original" "$current" "FAILED"
            inc_fail
        fi
    fi
}

# 6) SM-9.a.vi Ensure permissions on /etc/shadow- are configured
check_sm_9_a_vi() {
    local pid="SM-9.a.vi"
    local pname="Ensure permissions on /etc/shadow- are configured"
    local expected="$EXPECTED_SHADOW_DASH"
    if [ "$MODE" = "scan" ]; then
        if ! file_exists "/etc/shadow-"; then
            current="file not found"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAIL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "FAIL"
            inc_fail
            return
        fi
        current="$(get_mode /etc/shadow-)"
        if [ "$current" = "600" ]; then
            print_check_result "$pid" "$pname" "$expected" "$current" "PASS"
            save_scan_result "$pid" "$pname" "$expected" "$current" "PASS"
            inc_pass
        else
            print_check_result "$pid" "$pname" "$expected" "$current" "FAIL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "FAIL"
            inc_fail
        fi
    else
        if ! file_exists "/etc/shadow-"; then
            current="file not found"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAILED"
            save_fix_result "$pid" "$pname" "$expected" "missing" "missing" "FAILED"
            inc_fail
            return
        fi
        original="$(get_mode /etc/shadow-)"
        if chmod 600 /etc/shadow- 2>/dev/null; then
            current="$(get_mode /etc/shadow-)"
            print_check_result "$pid" "$pname" "$expected" "$current" "FIXED"
            save_fix_result "$pid" "$pname" "$expected" "$original" "$current" "FIXED"
            inc_fixed
        else
            current="$original"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAILED"
            save_fix_result "$pid" "$pname" "$expected" "$original" "$current" "FAILED"
            inc_fail
        fi
    fi
}

# 7) SM-9.a.vii Ensure permissions on /etc/gshadow are configured
check_sm_9_a_vii() {
    local pid="SM-9.a.vii"
    local pname="Ensure permissions on /etc/gshadow are configured"
    local expected="$EXPECTED_GSHADOW"
    if [ "$MODE" = "scan" ]; then
        if ! file_exists "/etc/gshadow"; then
            current="file not found"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAIL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "FAIL"
            inc_fail
            return
        fi
        current="$(get_mode /etc/gshadow)"
        if [ "$current" = "600" ] || [ "$current" = "640" ]; then
            print_check_result "$pid" "$pname" "$expected" "$current" "PASS"
            save_scan_result "$pid" "$pname" "$expected" "$current" "PASS"
            inc_pass
        else
            print_check_result "$pid" "$pname" "$expected" "$current" "FAIL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "FAIL"
            inc_fail
        fi
    else
        if ! file_exists "/etc/gshadow"; then
            current="file not found"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAILED"
            save_fix_result "$pid" "$pname" "$expected" "missing" "missing" "FAILED"
            inc_fail
            return
        fi
        original="$(get_mode /etc/gshadow)"
        if chmod 600 /etc/gshadow 2>/dev/null; then
            current="$(get_mode /etc/gshadow)"
            print_check_result "$pid" "$pname" "$expected" "$current" "FIXED"
            save_fix_result "$pid" "$pname" "$expected" "$original" "$current" "FIXED"
            inc_fixed
        else
            current="$original"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAILED"
            save_fix_result "$pid" "$pname" "$expected" "$original" "$current" "FAILED"
            inc_fail
        fi
    fi
}

# 8) SM-9.a.viii Ensure permissions on /etc/gshadow- are configured
check_sm_9_a_viii() {
    local pid="SM-9.a.viii"
    local pname="Ensure permissions on /etc/gshadow- are configured"
    local expected="$EXPECTED_GSHADOW_DASH"
    if [ "$MODE" = "scan" ]; then
        if ! file_exists "/etc/gshadow-"; then
            current="file not found"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAIL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "FAIL"
            inc_fail
            return
        fi
        current="$(get_mode /etc/gshadow-)"
        if [ "$current" = "600" ]; then
            print_check_result "$pid" "$pname" "$expected" "$current" "PASS"
            save_scan_result "$pid" "$pname" "$expected" "$current" "PASS"
            inc_pass
        else
            print_check_result "$pid" "$pname" "$expected" "$current" "FAIL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "FAIL"
            inc_fail
        fi
    else
        if ! file_exists "/etc/gshadow-"; then
            current="file not found"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAILED"
            save_fix_result "$pid" "$pname" "$expected" "missing" "missing" "FAILED"
            inc_fail
            return
        fi
        original="$(get_mode /etc/gshadow-)"
        if chmod 600 /etc/gshadow- 2>/dev/null; then
            current="$(get_mode /etc/gshadow-)"
            print_check_result "$pid" "$pname" "$expected" "$current" "FIXED"
            save_fix_result "$pid" "$pname" "$expected" "$original" "$current" "FIXED"
            inc_fixed
        else
            current="$original"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAILED"
            save_fix_result "$pid" "$pname" "$expected" "$original" "$current" "FAILED"
            inc_fail
        fi
    fi
}

# 9) SM-9.a.ix Ensure permissions on /etc/shells are configured
check_sm_9_a_ix() {
    local pid="SM-9.a.ix"
    local pname="Ensure permissions on /etc/shells are configured"
    local expected="$EXPECTED_SHELLS"
    if [ "$MODE" = "scan" ]; then
        if ! file_exists "/etc/shells"; then
            current="file not found"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAIL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "FAIL"
            inc_fail
            return
        fi
        current="$(get_mode /etc/shells)"
        if [ "$current" = "644" ]; then
            print_check_result "$pid" "$pname" "$expected" "$current" "PASS"
            save_scan_result "$pid" "$pname" "$expected" "$current" "PASS"
            inc_pass
        else
            print_check_result "$pid" "$pname" "$expected" "$current" "FAIL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "FAIL"
            inc_fail
        fi
    else
        if ! file_exists "/etc/shells"; then
            current="file not found"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAILED"
            save_fix_result "$pid" "$pname" "$expected" "missing" "missing" "FAILED"
            inc_fail
            return
        fi
        original="$(get_mode /etc/shells)"
        if chmod 644 /etc/shells 2>/dev/null; then
            current="$(get_mode /etc/shells)"
            print_check_result "$pid" "$pname" "$expected" "$current" "FIXED"
            save_fix_result "$pid" "$pname" "$expected" "$original" "$current" "FIXED"
            inc_fixed
        else
            current="$original"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAILED"
            save_fix_result "$pid" "$pname" "$expected" "$original" "$current" "FAILED"
            inc_fail
        fi
    fi
}

# 10) SM-9.a.x Ensure permissions on /etc/security/opasswd are configured
check_sm_9_a_x() {
    local pid="SM-9.a.x"
    local pname="Ensure permissions on /etc/security/opasswd are configured"
    local expected="$EXPECTED_OPASSWD"
    if [ "$MODE" = "scan" ]; then
        if ! file_exists "/etc/security/opasswd"; then
            current="file not found"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAIL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "FAIL"
            inc_fail
            return
        fi
        current="$(get_mode /etc/security/opasswd)"
        # Accept 600 or 644 per earlier table
        if [ "$current" = "600" ] || [ "$current" = "644" ]; then
            print_check_result "$pid" "$pname" "$expected" "$current" "PASS"
            save_scan_result "$pid" "$pname" "$expected" "$current" "PASS"
            inc_pass
        else
            print_check_result "$pid" "$pname" "$expected" "$current" "FAIL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "FAIL"
            inc_fail
        fi
    else
        if ! file_exists "/etc/security/opasswd"; then
            current="file not found"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAILED"
            save_fix_result "$pid" "$pname" "$expected" "missing" "missing" "FAILED"
            inc_fail
            return
        fi
        original="$(get_mode /etc/security/opasswd)"
        if chmod 600 /etc/security/opasswd 2>/dev/null; then
            current="$(get_mode /etc/security/opasswd)"
            print_check_result "$pid" "$pname" "$expected" "$current" "FIXED"
            save_fix_result "$pid" "$pname" "$expected" "$original" "$current" "FIXED"
            inc_fixed
        else
            current="$original"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAILED"
            save_fix_result "$pid" "$pname" "$expected" "$original" "$current" "FAILED"
            inc_fail
        fi
    fi
}

# 11) SM-9.a.xi Ensure world writable files and directories are secured
check_sm_9_a_xi() {
    local pid="SM-9.a.xi"
    local pname="Ensure world writable files and directories are secured"
    local expected="no world-writable files"
    if [ "$MODE" = "scan" ]; then
        count=$(find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -path /run -prune -o -path /tmp -prune -o -path /var/tmp -prune -o -type f -perm -0002 -print 2>/dev/null | wc -l)
        current="$count files found"
        if [ "$count" -eq 0 ]; then
            print_check_result "$pid" "$pname" "$expected" "$current" "PASS"
            save_scan_result "$pid" "$pname" "$expected" "$current" "PASS"
            inc_pass
        else
            print_check_result "$pid" "$pname" "$expected" "$current" "FAIL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "FAIL"
            inc_fail
        fi
    else
        # Try to remove o+w on files found (safe)
        original="has_world_writable"
        find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -path /run -prune -o -path /tmp -prune -o -path /var/tmp -prune -o -type f -perm -0002 -exec chmod o-w {} \; 2>/dev/null || true
        current="removed world-writable bits where found"
        print_check_result "$pid" "$pname" "$expected" "$current" "FIXED"
        save_fix_result "$pid" "$pname" "$expected" "$original" "$current" "FIXED"
        inc_fixed
    fi
}

# 12) SM-9.a.xii Ensure no files or directories without an owner and a group exist
check_sm_9_a_xii() {
    local pid="SM-9.a.xii"
    local pname="Ensure no files or directories without an owner and a group exist"
    local expected="all files have owner and group"
    if [ "$MODE" = "scan" ]; then
        count=$(find / -path /home -prune -o -path /tmp -prune -o -path /var/tmp -prune -o -path /run/user -prune -o -path /proc -prune -o -path /sys -prune -o -path /run -prune -o -path /dev -prune -o \( -nouser -o -nogroup \) -print 2>/dev/null | wc -l)
        current="$count files without owner/group"
        if [ "$count" -eq 0 ]; then
            print_check_result "$pid" "$pname" "$expected" "$current" "PASS"
            save_scan_result "$pid" "$pname" "$expected" "$current" "PASS"
            inc_pass
        else
            print_check_result "$pid" "$pname" "$expected" "$current" "MANUAL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "MANUAL"
            inc_manual
        fi
    else
        # Unsafe to auto-chown unidentified files; require manual
        current="requires manual review"
        print_check_result "$pid" "$pname" "$expected" "$current" "MANUAL"
        save_fix_result "$pid" "$pname" "$expected" "requires_manual" "requires_manual" "MANUAL"
        inc_manual
    fi
}

# 13) SM-9.a.xiii Ensure SUID and SGID files are reviewed (Manual)
check_sm_9_a_xiii() {
    local pid="SM-9.a.xiii"
    local pname="Ensure SUID and SGID files are reviewed"
    local expected="manual review"
    if [ "$MODE" = "scan" ]; then
        suid_count=$(find / -xdev -perm -4000 2>/dev/null | wc -l)
        sgid_count=$(find / -xdev -perm -2000 2>/dev/null | wc -l)
        current="$suid_count SUID files, $sgid_count SGID files"
        print_check_result "$pid" "$pname" "$expected" "$current" "PASS"
        save_scan_result "$pid" "$pname" "$expected" "$current" "PASS"
        inc_pass
    else
        # Manual only
        current="manual review required"
        print_check_result "$pid" "$pname" "$expected" "$current" "MANUAL"
        save_fix_result "$pid" "$pname" "$expected" "requires_manual" "requires_manual" "MANUAL"
        inc_manual
    fi
}

# 14) SM-9.a.xiv Ensure accounts in /etc/passwd use shadowed passwords
check_sm_9_a_xiv() {
    local pid="SM-9.a.xiv"
    local pname="Ensure accounts in /etc/passwd use shadowed passwords"
    local expected="all accounts use shadow passwords"
    if [ "$MODE" = "scan" ]; then
        if pwck -r 2>&1 | grep -q "no shadow"; then
            current="some accounts not using shadow"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAIL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "FAIL"
            inc_fail
        else
            current="all accounts use shadow"
            print_check_result "$pid" "$pname" "$expected" "$current" "PASS"
            save_scan_result "$pid" "$pname" "$expected" "$current" "PASS"
            inc_pass
        fi
    else
        if command -v pwconv >/dev/null 2>&1; then
            original="pre_pwconv"
            pwconv 2>/dev/null || true
            current="shadow conversion attempted"
            print_check_result "$pid" "$pname" "$expected" "$current" "FIXED"
            save_fix_result "$pid" "$pname" "$expected" "$original" "$current" "FIXED"
            inc_fixed
        else
            current="pwconv missing"
            print_check_result "$pid" "$pname" "$expected" "$current" "MANUAL"
            save_fix_result "$pid" "$pname" "$expected" "pwconv_missing" "requires_manual" "MANUAL"
            inc_manual
        fi
    fi
}

# 15) SM-9.a.xv Ensure /etc/shadow password fields are not empty
check_sm_9_a_xv() {
    local pid="SM-9.a.xv"
    local pname="Ensure /etc/shadow password fields are not empty"
    local expected="no empty password fields"
    if [ "$MODE" = "scan" ]; then
        empty_list=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null || true)
        if [ -z "$empty_list" ]; then
            current="no empty password fields"
            print_check_result "$pid" "$pname" "$expected" "$current" "PASS"
            save_scan_result "$pid" "$pname" "$expected" "$current" "PASS"
            inc_pass
        else
            current="empty fields found: $empty_list"
            print_check_result "$pid" "$pname" "$expected" "$current" "MANUAL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "MANUAL"
            inc_manual
        fi
    else
        empty_list=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null || true)
        if [ -z "$empty_list" ]; then
            current="none"
            print_check_result "$pid" "$pname" "$expected" "$current" "FIXED"
            save_fix_result "$pid" "$pname" "$expected" "none" "none" "FIXED"
            inc_fixed
        else
            original="$empty_list"
            for u in $empty_list; do
                passwd -l "$u" 2>/dev/null || true
            done
            current="locked:$empty_list"
            print_check_result "$pid" "$pname" "$expected" "$current" "FIXED"
            save_fix_result "$pid" "$pname" "$expected" "$original" "$current" "FIXED"
            inc_fixed
        fi
    fi
}

# 16) SM-9.a.xvi Ensure all groups in /etc/passwd exist in /etc/group
check_sm_9_a_xvi() {
    local pid="SM-9.a.xvi"
    local pname="Ensure all groups in /etc/passwd exist in /etc/group"
    local expected="all groups exist"
    if [ "$MODE" = "scan" ]; then
        missing=""
        while IFS=: read -r _ _ _ gid _ _ _; do
            if ! getent group "$gid" >/dev/null 2>&1; then
                missing="$missing $gid"
            fi
        done < /etc/passwd
        if [ -z "$missing" ]; then
            current="all groups valid"
            print_check_result "$pid" "$pname" "$expected" "$current" "PASS"
            save_scan_result "$pid" "$pname" "$expected" "$current" "PASS"
            inc_pass
        else
            current="missing GIDs:$missing"
            print_check_result "$pid" "$pname" "$expected" "$current" "MANUAL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "MANUAL"
            inc_manual
        fi
    else
        current="mapping to names required - manual"
        print_check_result "$pid" "$pname" "$expected" "$current" "MANUAL"
        save_fix_result "$pid" "$pname" "$expected" "requires_manual" "requires_manual" "MANUAL"
        inc_manual
    fi
}

# 17) SM-9.a.xvii Ensure shadow group is empty
check_sm_9_a_xvii() {
    local pid="SM-9.a.xvii"
    local pname="Ensure shadow group is empty"
    local expected="shadow group empty"
    if [ "$MODE" = "scan" ]; then
        members=$(getent group shadow 2>/dev/null | cut -d: -f4 || true)
        if [ -z "$members" ]; then
            current="shadow group empty"
            print_check_result "$pid" "$pname" "$expected" "$current" "PASS"
            save_scan_result "$pid" "$pname" "$expected" "$current" "PASS"
            inc_pass
        else
            current="members: $members"
            print_check_result "$pid" "$pname" "$expected" "$current" "FAIL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "FAIL"
            inc_fail
        fi
    else
        members=$(getent group shadow 2>/dev/null | cut -d: -f4 || true)
        if [ -z "$members" ]; then
            current="none"
            print_check_result "$pid" "$pname" "$expected" "$current" "FIXED"
            save_fix_result "$pid" "$pname" "$expected" "none" "none" "FIXED"
            inc_fixed
        else
            original="$members"
            for u in $(echo "$members" | tr ',' ' '); do
                gpasswd -d "$u" shadow 2>/dev/null || true
            done
            current="removed:$members"
            print_check_result "$pid" "$pname" "$expected" "$current" "FIXED"
            save_fix_result "$pid" "$pname" "$expected" "$original" "$current" "FIXED"
            inc_fixed
        fi
    fi
}

# 18) SM-9.a.xviii Ensure no duplicate UIDs exist
check_sm_9_a_xviii() {
    local pid="SM-9.a.xviii"
    local pname="Ensure no duplicate UIDs exist"
    local expected="no duplicate UIDs"
    if [ "$MODE" = "scan" ]; then
        dup=$(awk -F: '($3 >= 1000){print $3}' /etc/passwd | sort -n | uniq -d || true)
        if [ -z "$dup" ]; then
            current="no duplicates"
            print_check_result "$pid" "$pname" "$expected" "$current" "PASS"
            save_scan_result "$pid" "$pname" "$expected" "$current" "PASS"
            inc_pass
        else
            current="duplicates: $dup"
            print_check_result "$pid" "$pname" "$expected" "$current" "MANUAL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "MANUAL"
            inc_manual
        fi
    else
        current="automatic resolution unsafe - manual required"
        print_check_result "$pid" "$pname" "$expected" "$current" "MANUAL"
        save_fix_result "$pid" "$pname" "$expected" "requires_manual" "requires_manual" "MANUAL"
        inc_manual
    fi
}

# 19) SM-9.a.xix Ensure no duplicate GIDs exist
check_sm_9_a_xix() {
    local pid="SM-9.a.xix"
    local pname="Ensure no duplicate GIDs exist"
    local expected="no duplicate GIDs"
    if [ "$MODE" = "scan" ]; then
        dup=$(awk -F: '($3 >= 1000){print $3}' /etc/group | sort -n | uniq -d || true)
        if [ -z "$dup" ]; then
            current="no duplicates"
            print_check_result "$pid" "$pname" "$expected" "$current" "PASS"
            save_scan_result "$pid" "$pname" "$expected" "$current" "PASS"
            inc_pass
        else
            current="duplicates: $dup"
            print_check_result "$pid" "$pname" "$expected" "$current" "MANUAL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "MANUAL"
            inc_manual
        fi
    else
        current="automatic resolution unsafe - manual required"
        print_check_result "$pid" "$pname" "$expected" "$current" "MANUAL"
        save_fix_result "$pid" "$pname" "$expected" "requires_manual" "requires_manual" "MANUAL"
        inc_manual
    fi
}

# 20) SM-9.a.xx Ensure no duplicate user names exist
check_sm_9_a_xx() {
    local pid="SM-9.a.xx"
    local pname="Ensure no duplicate user names exist"
    local expected="no duplicate usernames"
    if [ "$MODE" = "scan" ]; then
        dup=$(awk -F: '{print $1}' /etc/passwd | sort | uniq -d || true)
        if [ -z "$dup" ]; then
            current="no duplicates"
            print_check_result "$pid" "$pname" "$expected" "$current" "PASS"
            save_scan_result "$pid" "$pname" "$expected" "$current" "PASS"
            inc_pass
        else
            current="duplicates: $dup"
            print_check_result "$pid" "$pname" "$expected" "$current" "MANUAL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "MANUAL"
            inc_manual
        fi
    else
        current="automatic renaming unsafe - manual required"
        print_check_result "$pid" "$pname" "$expected" "$current" "MANUAL"
        save_fix_result "$pid" "$pname" "$expected" "requires_manual" "requires_manual" "MANUAL"
        inc_manual
    fi
}

# 21) SM-9.a.xxi Ensure no duplicate group names exist
check_sm_9_a_xxi() {
    local pid="SM-9.a.xxi"
    local pname="Ensure no duplicate group names exist"
    local expected="no duplicate group names"
    if [ "$MODE" = "scan" ]; then
        dup=$(awk -F: '{print $1}' /etc/group | sort | uniq -d || true)
        if [ -z "$dup" ]; then
            current="no duplicates"
            print_check_result "$pid" "$pname" "$expected" "$current" "PASS"
            save_scan_result "$pid" "$pname" "$expected" "$current" "PASS"
            inc_pass
        else
            current="duplicates: $dup"
            print_check_result "$pid" "$pname" "$expected" "$current" "MANUAL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "MANUAL"
            inc_manual
        fi
    else
        current="automatic renaming unsafe - manual required"
        print_check_result "$pid" "$pname" "$expected" "$current" "MANUAL"
        save_fix_result "$pid" "$pname" "$expected" "requires_manual" "requires_manual" "MANUAL"
        inc_manual
    fi
}

# 22) SM-9.a.xxii Ensure local interactive user home directories are configured
check_sm_9_a_xxii() {
    local pid="SM-9.a.xxii"
    local pname="Ensure local interactive user home directories are configured"
    local expected="all home directories exist and have correct permissions"
    if [ "$MODE" = "scan" ]; then
        issues=0; missing_list=""
        while IFS=: read -r user _ uid _ _ home _; do
            if [ "$uid" -ge 1000 ] && [ "$user" != "nobody" ]; then
                if [ ! -d "$home" ]; then
                    ((issues++))
                    missing_list="$missing_list $user:$home"
                fi
            fi
        done < /etc/passwd
        if [ "$issues" -eq 0 ]; then
            current="all home directories configured"
            print_check_result "$pid" "$pname" "$expected" "$current" "PASS"
            save_scan_result "$pid" "$pname" "$expected" "$current" "PASS"
            inc_pass
        else
            current="$issues home directories missing or misconfigured:$missing_list"
            print_check_result "$pid" "$pname" "$expected" "$current" "MANUAL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "MANUAL"
            inc_manual
        fi
    else
        # Attempt safe auto-fix: create missing home dirs and set owner/perm
        created=()
        while IFS=: read -r user _ uid _ _ home _; do
            if [ "$uid" -ge 1000 ] && [ "$user" != "nobody" ]; then
                if [ ! -d "$home" ]; then
                    mkdir -p "$home" 2>/dev/null || true
                    chown "$user":"$user" "$home" 2>/dev/null || true
                    chmod 700 "$home" 2>/dev/null || true
                    created+=("$user:$home")
                fi
            fi
        done < /etc/passwd
        if [ "${#created[@]}" -eq 0 ]; then
            current="none"
            print_check_result "$pid" "$pname" "$expected" "$current" "FIXED"
            save_fix_result "$pid" "$pname" "$expected" "none" "none" "FIXED"
            inc_fixed
        else
            current="created:${created[*]}"
            print_check_result "$pid" "$pname" "$expected" "$current" "FIXED"
            save_fix_result "$pid" "$pname" "$expected" "created" "$current" "FIXED"
            inc_fixed
        fi
    fi
}

# 23) SM-9.a.xxiii Ensure local interactive user dot files access is configured
check_sm_9_a_xxiii() {
    local pid="SM-9.a.xxiii"
    local pname="Ensure local interactive user dot files access is configured"
    local expected="no dangerous dotfile permissions"
    if [ "$MODE" = "scan" ]; then
        count=$(find /home -maxdepth 3 -type f -name ".*" -perm /022 2>/dev/null | wc -l || echo 0)
        current="$count files with dangerous permissions"
        if [ "$count" -eq 0 ]; then
            print_check_result "$pid" "$pname" "$expected" "$current" "PASS"
            save_scan_result "$pid" "$pname" "$expected" "$current" "PASS"
            inc_pass
        else
            print_check_result "$pid" "$pname" "$expected" "$current" "FAIL"
            save_scan_result "$pid" "$pname" "$expected" "$current" "FAIL"
            inc_fail
        fi
    else
        original="has_dangerous_perms"
        find /home -maxdepth 3 -type f -name ".*" -perm /022 -exec chmod go-w {} \; 2>/dev/null || true
        current="removed group/other write where found"
        print_check_result "$pid" "$pname" "$expected" "$current" "FIXED"
        save_fix_result "$pid" "$pname" "$expected" "$original" "$current" "FIXED"
        inc_fixed
    fi
}

# -------------------------
# Main execution
# -------------------------
main() {
    # Colored header matching Network example
    echo -e "${BLUE}========================================================================${NC}"
    echo -e "${BLUE}System Maintenance Hardening - Module: ${MODULE_NAME}${NC}"
    echo -e "${BLUE}Mode: $MODE${NC}"
    echo -e "${BLUE}========================================================================${NC}"

    initialize_db

    # Run all 23 checks in order
    check_sm_9_a_i
    check_sm_9_a_ii
    check_sm_9_a_iii
    check_sm_9_a_iv
    check_sm_9_a_v
    check_sm_9_a_vi
    check_sm_9_a_vii
    check_sm_9_a_viii
    check_sm_9_a_ix
    check_sm_9_a_x

    echo ""
    echo "=== Additional System Maintenance Checks ==="

    check_sm_9_a_xi
    check_sm_9_a_xii
    check_sm_9_a_xiii

    echo ""
    echo "=== User and Group Validation ==="

    check_sm_9_a_xiv
    check_sm_9_a_xv
    check_sm_9_a_xvi
    check_sm_9_a_xvii
    check_sm_9_a_xviii
    check_sm_9_a_xix
    check_sm_9_a_xx
    check_sm_9_a_xxi
    check_sm_9_a_xxii
    check_sm_9_a_xxiii

    echo ""
    echo -e "========================================================================"
    echo -e "System Maintenance Summary"
    echo -e "========================================================================"
    echo "Total Checks: $TOTAL_CHECKS"
    if [ "$MODE" = "scan" ]; then
        echo "Passed: $PASSED_CHECKS"
        echo "Failed: $FAILED_CHECKS"
        echo "Manual Actions Required: $MANUAL_CHECKS"
    else
        echo "Fixed:  $FIXED_CHECKS"
        echo "Manual Actions Required: $MANUAL_CHECKS"
    fi
    echo -e "========================================================================"
    # Final colored pass/fail banner
    if [ "$FAILED_CHECKS" -gt 0 ]; then
        echo -e "${RED}[FAIL] Some checks failed.${NC}"
    else
        echo -e "${GREEN}[PASS] All checks passed or require manual review.${NC}"
    fi
}

main

