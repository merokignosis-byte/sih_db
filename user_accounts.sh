#!/bin/bash

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/user_accounts"
MODULE_NAME="User Accounts"

mkdir -p "$BACKUP_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ============================================================================
# Counters
# ============================================================================
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0
MANUAL_CHECKS=0

# ============================================================================
# Logging Functions
# ============================================================================
log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fixed() { echo -e "${BLUE}[FIXED]${NC} $1"; }
log_manual() { echo -e "${YELLOW}[MANUAL]${NC} $1"; }

# ============================================================================
# Database Functions
# ============================================================================
init_database() {
    python3 - <<EOF
import sqlite3
conn = sqlite3.connect('$DB_PATH')
cursor = conn.cursor()
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
)
''')
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
)
''')
conn.commit()
conn.close()
EOF
}

save_scan_result() {
    local policy_id="$1"
    local policy_name="$2"
    local expected="$3"
    local current="$4"
    local status="$5"

    python3 - <<EOF
import sqlite3
conn = sqlite3.connect('$DB_PATH')
cursor = conn.cursor()
cursor.execute("""
    INSERT OR REPLACE INTO scan_results
    (module_name, policy_id, policy_name, expected_value, current_value, status, scan_timestamp)
    VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
""", ('$MODULE_NAME', '$policy_id', '''$policy_name''', '''$expected''', '''$current''', '$status'))
conn.commit()
conn.close()
EOF
}

save_fix_result() {
    local policy_id="$1"
    local policy_name="$2"
    local expected="$3"
    local original="$4"
    local current="$5"
    local status="$6"

    python3 - <<EOF
import sqlite3
conn = sqlite3.connect('$DB_PATH')
cursor = conn.cursor()
cursor.execute("""
    INSERT OR REPLACE INTO fix_history
    (module_name, policy_id, policy_name, expected_value, original_value, current_value, status, rollback_executed)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'NO')
""", ('$MODULE_NAME', '$policy_id', '''$policy_name''', '''$expected''', '''$original''', '''$current''', '$status'))
conn.commit()
conn.close()
EOF
}

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
    elif [[ "$status" == "MANUAL" ]]; then
        echo -e "Status         : ${YELLOW}$status${NC}"
    else
        echo -e "Status         : ${BLUE}$status${NC}"
    fi
    echo "=============================================="
}

# ============================================================================
# Section 7.a - Shadow Password Suite Parameters
# ============================================================================

check_password_expiration() {
    local policy_id="UA-7.a.i"
    local policy_name="Ensure password expiration is configured"
    local expected="365 days or less"
    ((TOTAL_CHECKS++))

    local current status original
    if [ -f /etc/login.defs ]; then
        current=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
        original="$current"
        
        if [ -z "$current" ]; then
            current="not set"
            status="FAIL"
            ((FAILED_CHECKS++))
        elif [ "$current" -le 365 ] 2>/dev/null && [ "$current" -gt 0 ]; then
            status="PASS"
            ((PASSED_CHECKS++))
        else
            status="FAIL"
            ((FAILED_CHECKS++))
        fi
    else
        current="file not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    if [[ "$MODE" == "fix" ]] && [[ "$status" == "FAIL" ]]; then
        cp /etc/login.defs "$BACKUP_DIR/login.defs.$(date +%Y%m%d_%H%M%S)"
        
        if grep -q "^PASS_MAX_DAYS" /etc/login.defs; then
            sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t365/' /etc/login.defs
        else
            echo -e "\nPASS_MAX_DAYS\t365" >> /etc/login.defs
        fi
        
        current="365"
        status="FIXED"
        ((FIXED_CHECKS++))
        log_fixed "Set PASS_MAX_DAYS to 365"
        save_fix_result "$policy_id" "$policy_name" "$expected" "$original" "$current" "$status"
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

check_minimum_password_days() {
    local policy_id="UA-7.a.ii"
    local policy_name="Ensure minimum password days is configured"
    local expected="1 day or more"
    ((TOTAL_CHECKS++))

    local current status original
    if [ -f /etc/login.defs ]; then
        current=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}')
        original="$current"
        
        if [ -z "$current" ]; then
            current="not set"
            status="FAIL"
            ((FAILED_CHECKS++))
        elif [ "$current" -ge 1 ] 2>/dev/null; then
            status="PASS"
            ((PASSED_CHECKS++))
        else
            status="FAIL"
            ((FAILED_CHECKS++))
        fi
    else
        current="file not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    if [[ "$MODE" == "fix" ]] && [[ "$status" == "FAIL" ]]; then
        cp /etc/login.defs "$BACKUP_DIR/login.defs.mindays.$(date +%Y%m%d_%H%M%S)"
        
        if grep -q "^PASS_MIN_DAYS" /etc/login.defs; then
            sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/' /etc/login.defs
        else
            echo -e "\nPASS_MIN_DAYS\t1" >> /etc/login.defs
        fi
        
        current="1"
        status="FIXED"
        ((FIXED_CHECKS++))
        log_fixed "Set PASS_MIN_DAYS to 1"
        save_fix_result "$policy_id" "$policy_name" "$expected" "$original" "$current" "$status"
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

check_password_warning_days() {
    local policy_id="UA-7.a.iii"
    local policy_name="Ensure password expiration warning days is configured"
    local expected="7 days or more"
    ((TOTAL_CHECKS++))

    local current status original
    if [ -f /etc/login.defs ]; then
        current=$(grep "^PASS_WARN_AGE" /etc/login.defs | awk '{print $2}')
        original="$current"
        
        if [ -z "$current" ]; then
            current="not set"
            status="FAIL"
            ((FAILED_CHECKS++))
        elif [ "$current" -ge 7 ] 2>/dev/null; then
            status="PASS"
            ((PASSED_CHECKS++))
        else
            status="FAIL"
            ((FAILED_CHECKS++))
        fi
    else
        current="file not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    if [[ "$MODE" == "fix" ]] && [[ "$status" == "FAIL" ]]; then
        cp /etc/login.defs "$BACKUP_DIR/login.defs.warnage.$(date +%Y%m%d_%H%M%S)"
        
        if grep -q "^PASS_WARN_AGE" /etc/login.defs; then
            sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t7/' /etc/login.defs
        else
            echo -e "\nPASS_WARN_AGE\t7" >> /etc/login.defs
        fi
        
        current="7"
        status="FIXED"
        ((FIXED_CHECKS++))
        log_fixed "Set PASS_WARN_AGE to 7"
        save_fix_result "$policy_id" "$policy_name" "$expected" "$original" "$current" "$status"
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

check_password_hashing() {
    local policy_id="UA-7.a.iv"
    local policy_name="Ensure strong password hashing algorithm is configured"
    local expected="SHA512 or yescrypt"
    ((TOTAL_CHECKS++))

    local current status original
    if [ -f /etc/login.defs ]; then
        current=$(grep "^ENCRYPT_METHOD" /etc/login.defs | awk '{print $2}')
        original="$current"
        
        if [ -z "$current" ]; then
            current="not set"
            status="FAIL"
            ((FAILED_CHECKS++))
        elif [ "$current" = "SHA512" ] || [ "$current" = "yescrypt" ]; then
            status="PASS"
            ((PASSED_CHECKS++))
        else
            status="FAIL"
            ((FAILED_CHECKS++))
        fi
    else
        current="file not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    if [[ "$MODE" == "fix" ]] && [[ "$status" == "FAIL" ]]; then
        cp /etc/login.defs "$BACKUP_DIR/login.defs.encrypt.$(date +%Y%m%d_%H%M%S)"
        
        if grep -q "^ENCRYPT_METHOD" /etc/login.defs; then
            sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
        else
            echo -e "\nENCRYPT_METHOD SHA512" >> /etc/login.defs
        fi
        
        current="SHA512"
        status="FIXED"
        ((FIXED_CHECKS++))
        log_fixed "Set ENCRYPT_METHOD to SHA512"
        save_fix_result "$policy_id" "$policy_name" "$expected" "$original" "$current" "$status"
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

check_inactive_password_lock() {
    local policy_id="UA-7.a.v"
    local policy_name="Ensure inactive password lock is configured"
    local expected="30 days or less"
    ((TOTAL_CHECKS++))

    local current status original
    current=$(useradd -D 2>/dev/null | grep INACTIVE | cut -d= -f2)
    original="$current"
    
    if [ -z "$current" ] || [ "$current" = "-1" ]; then
        current="not set"
        status="FAIL"
        ((FAILED_CHECKS++))
    elif [ "$current" -le 30 ] && [ "$current" -gt 0 ] 2>/dev/null; then
        status="PASS"
        ((PASSED_CHECKS++))
    else
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    if [[ "$MODE" == "fix" ]] && [[ "$status" == "FAIL" ]]; then
        useradd -D -f 30 >/dev/null 2>&1
        current="30"
        status="FIXED"
        ((FIXED_CHECKS++))
        log_fixed "Set inactive password lock to 30 days"
        save_fix_result "$policy_id" "$policy_name" "$expected" "$original" "$current" "$status"
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

check_password_change_dates() {
    local policy_id="UA-7.a.vi"
    local policy_name="Ensure all users last password change date is in the past"
    local expected="all dates in past"
    ((TOTAL_CHECKS++))

    local invalid_users=""
    local current_date=$(date +%s)
    
    while IFS=: read -r username password lastchange rest; do
        if [[ "$username" != "#"* ]] && [ -n "$lastchange" ] && [ "$lastchange" != "0" ]; then
            local change_date=$((lastchange * 86400))
            if [ "$change_date" -gt "$current_date" ]; then
                invalid_users="${invalid_users}${username} "
            fi
        fi
    done < /etc/shadow

    local current status
    if [ -z "$invalid_users" ]; then
        current="all valid"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="invalid: $invalid_users"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    if [[ "$MODE" == "fix" ]] && [[ "$status" == "FAIL" ]]; then
        local users_fixed=""
        local current_days=$(($(date +%s) / 86400))
        
        for user in $invalid_users; do
            chage -d 0 "$user" 2>/dev/null && users_fixed="${users_fixed}${user} "
        done
        
        if [ -n "$users_fixed" ]; then
            current="fixed: $users_fixed"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Reset password change dates for: $users_fixed"
            save_fix_result "$policy_id" "$policy_name" "$expected" "$invalid_users" "$current" "$status"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

# ============================================================================
# Section 7.a.vii to 7.a.xiv - Root and System Accounts
# ============================================================================

check_root_uid_zero() {
    local policy_id="UA-7.a.vii"
    local policy_name="Ensure root is the only UID 0 account"
    local expected="root only"
    ((TOTAL_CHECKS++))

    local uid_zero_accounts=$(awk -F: '($3 == 0) { print $1 }' /etc/passwd)
    local current status

    if [ "$uid_zero_accounts" = "root" ]; then
        current="root only"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="$uid_zero_accounts"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    if [[ "$MODE" == "fix" ]] && [[ "$status" == "FAIL" ]]; then
        status="MANUAL"
        ((MANUAL_CHECKS++))
        log_manual "Found non-root UID 0 accounts: $uid_zero_accounts"
        log_manual "ACTION REQUIRED: Manually review and modify these accounts"
        log_manual "Use: usermod -u <new_uid> <username> for each non-root account"
        save_fix_result "$policy_id" "$policy_name" "$expected" "$current" "$current" "$status"
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

check_root_gid_zero() {
    local policy_id="UA-7.a.viii"
    local policy_name="Ensure root is the only GID 0 account"
    local expected="root only"
    ((TOTAL_CHECKS++))

    local gid_zero_accounts=$(awk -F: '($4 == 0 && $1 != "root") { print $1 }' /etc/passwd)
    local current status

    if [ -z "$gid_zero_accounts" ]; then
        current="root only"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="$gid_zero_accounts"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    if [[ "$MODE" == "fix" ]] && [[ "$status" == "FAIL" ]]; then
        status="MANUAL"
        ((MANUAL_CHECKS++))
        log_manual "Found non-root GID 0 accounts: $gid_zero_accounts"
        log_manual "ACTION REQUIRED: Manually review and modify these accounts"
        log_manual "Use: usermod -g <new_gid> <username> for each account"
        save_fix_result "$policy_id" "$policy_name" "$expected" "$current" "$current" "$status"
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

check_group_root_gid_zero() {
    local policy_id="UA-7.a.ix"
    local policy_name="Ensure group root is the only GID 0 group"
    local expected="root group only"
    ((TOTAL_CHECKS++))

    local gid_zero_groups=$(awk -F: '($3 == 0) { print $1 }' /etc/group)
    local current status

    if [ "$gid_zero_groups" = "root" ]; then
        current="root only"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="$gid_zero_groups"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    if [[ "$MODE" == "fix" ]] && [[ "$status" == "FAIL" ]]; then
        status="MANUAL"
        ((MANUAL_CHECKS++))
        log_manual "Found non-root GID 0 groups: $gid_zero_groups"
        log_manual "ACTION REQUIRED: Manually review and modify /etc/group"
        save_fix_result "$policy_id" "$policy_name" "$expected" "$current" "$current" "$status"
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

check_root_access_controlled() {
    local policy_id="UA-7.a.x"
    local policy_name="Ensure root account access is controlled"
    local expected="SSH disabled for root"
    ((TOTAL_CHECKS++))

    local current status original
    local ssh_root_login="unknown"
    
    if [ -f /etc/ssh/sshd_config ]; then
        ssh_root_login=$(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}')
        [ -z "$ssh_root_login" ] && ssh_root_login="default"
        original="$ssh_root_login"
        
        if [ "$ssh_root_login" = "no" ] || [ "$ssh_root_login" = "prohibit-password" ]; then
            current="disabled"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="enabled"
            status="FAIL"
            ((FAILED_CHECKS++))
        fi
    else
        current="sshd_config not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    if [[ "$MODE" == "fix" ]] && [[ "$status" == "FAIL" ]]; then
        if [ -f /etc/ssh/sshd_config ]; then
            cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.$(date +%Y%m%d_%H%M%S)"
            
            if grep -q "^PermitRootLogin" /etc/ssh/sshd_config; then
                sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
            else
                echo "PermitRootLogin no" >> /etc/ssh/sshd_config
            fi
            
            systemctl reload sshd 2>/dev/null || service ssh reload 2>/dev/null
            
            current="disabled"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Disabled root SSH login"
            save_fix_result "$policy_id" "$policy_name" "$expected" "$original" "$current" "$status"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

check_root_path_integrity() {
    local policy_id="UA-7.a.xi"
    local policy_name="Ensure root path integrity"
    local expected="no empty dirs, no . in PATH, all dirs owned by root"
    ((TOTAL_CHECKS++))

    local issues=""
    local root_path=$(echo "$PATH" | grep -E "^/root" || su - root -c 'echo $PATH' 2>/dev/null)
    
    # Check for empty directory entries
    if echo "$root_path" | grep -q "::"; then
        issues="${issues}empty_dir "
    fi
    
    # Check for trailing colon
    if echo "$root_path" | grep -q ":$"; then
        issues="${issues}trailing_colon "
    fi
    
    # Check for current directory (.)
    if echo "$root_path" | grep -q "\."; then
        issues="${issues}dot_in_path "
    fi

    local current status
    if [ -z "$issues" ]; then
        current="secure"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="issues: $issues"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    if [[ "$MODE" == "fix" ]] && [[ "$status" == "FAIL" ]]; then
        status="MANUAL"
        ((MANUAL_CHECKS++))
        log_manual "Root PATH integrity issues found: $issues"
        log_manual "ACTION REQUIRED: Edit /root/.bashrc, /root/.bash_profile"
        log_manual "Remove: empty dirs (::), trailing colons, and dots (.)"
        save_fix_result "$policy_id" "$policy_name" "$expected" "$current" "$current" "$status"
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

check_root_umask() {
    local policy_id="UA-7.a.xii"
    local policy_name="Ensure root user umask is configured"
    local expected="027 or 077"
    ((TOTAL_CHECKS++))

    local current status original
    local found_umask=""
    
    for file in /root/.bashrc /root/.bash_profile /root/.profile; do
        if [ -f "$file" ]; then
            found_umask=$(grep "^umask" "$file" 2>/dev/null | head -1 | awk '{print $2}')
            if [ -n "$found_umask" ]; then
                break
            fi
        fi
    done
    
    original="$found_umask"
    
    if [ -z "$found_umask" ]; then
        current="not set"
        status="FAIL"
        ((FAILED_CHECKS++))
    elif [ "$found_umask" = "027" ] || [ "$found_umask" = "077" ]; then
        current="$found_umask"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="$found_umask"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    if [[ "$MODE" == "fix" ]] && [[ "$status" == "FAIL" ]]; then
        for file in /root/.bashrc /root/.bash_profile; do
            if [ -f "$file" ]; then
                cp "$file" "$BACKUP_DIR/$(basename $file).$(date +%Y%m%d_%H%M%S)"
                
                if grep -q "^umask" "$file"; then
                    sed -i 's/^umask.*/umask 027/' "$file"
                else
                    echo "umask 027" >> "$file"
                fi
            fi
        done
        
        current="027"
        status="FIXED"
        ((FIXED_CHECKS++))
        log_fixed "Set root umask to 027"
        save_fix_result "$policy_id" "$policy_name" "$expected" "$original" "$current" "$status"
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

check_system_accounts_nologin() {
    local policy_id="UA-7.a.xiii"
    local policy_name="Ensure system accounts do not have a valid login shell"
    local expected="nologin or false"
    ((TOTAL_CHECKS++))

    local system_with_shell=$(awk -F: '($3 < 1000 && $1 != "root" && $7 !~ /nologin|false/) {print $1}' /etc/passwd)
    local current status

    if [ -z "$system_with_shell" ]; then
        current="all correct"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="$system_with_shell"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    if [[ "$MODE" == "fix" ]] && [[ "$status" == "FAIL" ]]; then
        cp /etc/passwd "$BACKUP_DIR/passwd.$(date +%Y%m%d_%H%M%S)"
        
        local fixed_accounts=""
        for account in $system_with_shell; do
            usermod -s /usr/sbin/nologin "$account" 2>/dev/null || \
            usermod -s /sbin/nologin "$account" 2>/dev/null
            fixed_accounts="${fixed_accounts}${account} "
        done
        
        current="fixed: $fixed_accounts"
        status="FIXED"
        ((FIXED_CHECKS++))
        log_fixed "Set nologin shell for: $fixed_accounts"
        save_fix_result "$policy_id" "$policy_name" "$expected" "$system_with_shell" "$current" "$status"
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}
check_accounts_without_valid_shell_locked() {
    local policy_id="UA-7.a.xiv"
    local policy_name="Ensure accounts without a valid login shell are locked"
    local expected="all nologin/false accounts locked"
    ((TOTAL_CHECKS++))

    local unlocked_accounts=""
    
    while IFS=: read -r username password uid gid gecos home shell; do
        if [[ "$shell" =~ (nologin|false) ]] && [ "$username" != "root" ]; then
            # Check if password is locked (starts with ! or *)
            local pwd_status=$(grep "^${username}:" /etc/shadow | cut -d: -f2)
            if [[ ! "$pwd_status" =~ ^[\!\*] ]]; then
                unlocked_accounts="${unlocked_accounts}${username} "
            fi
        fi
    done < /etc/passwd

    local current status
    if [ -z "$unlocked_accounts" ]; then
        current="all locked"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="unlocked: $unlocked_accounts"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    if [[ "$MODE" == "fix" ]] && [[ "$status" == "FAIL" ]]; then
        cp /etc/shadow "$BACKUP_DIR/shadow.$(date +%Y%m%d_%H%M%S)"
        
        local locked_accounts=""
        for account in $unlocked_accounts; do
            passwd -l "$account" >/dev/null 2>&1 && locked_accounts="${locked_accounts}${account} "
        done
        
        if [ -n "$locked_accounts" ]; then
            current="locked: $locked_accounts"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Locked accounts: $locked_accounts"
            save_fix_result "$policy_id" "$policy_name" "$expected" "$unlocked_accounts" "$current" "$status"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

# ============================================================================
# Section 7.b - User Default Environment
# ============================================================================

check_nologin_not_in_shells() {
    local policy_id="UA-7.b.i"
    local policy_name="Ensure nologin is not listed in /etc/shells"
    local expected="not present"
    ((TOTAL_CHECKS++))

    local current status original="not present"
    
    if grep -q "nologin" /etc/shells 2>/dev/null; then
        current="present"
        original="present"
        status="FAIL"
        ((FAILED_CHECKS++))
    else
        current="not present"
        status="PASS"
        ((PASSED_CHECKS++))
    fi

    if [[ "$MODE" == "fix" ]] && [[ "$status" == "FAIL" ]]; then
        cp /etc/shells "$BACKUP_DIR/shells.$(date +%Y%m%d_%H%M%S)"
        
        sed -i '/nologin/d' /etc/shells
        current="removed"
        status="FIXED"
        ((FIXED_CHECKS++))
        log_fixed "Removed nologin from /etc/shells"
        save_fix_result "$policy_id" "$policy_name" "$expected" "$original" "$current" "$status"
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

check_shell_timeout() {
    local policy_id="UA-7.b.ii"
    local policy_name="Ensure default user shell timeout is configured"
    local expected="TMOUT=900 or less"
    ((TOTAL_CHECKS++))

    local current status original
    local found_timeout=""
    
    for file in /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh; do
        if [ -f "$file" ]; then
            found_timeout=$(grep "^TMOUT=" "$file" 2>/dev/null | head -1 | cut -d= -f2)
            if [ -n "$found_timeout" ]; then
                break
            fi
        fi
    done
    
    original="$found_timeout"
    
    if [ -z "$found_timeout" ]; then
        current="not set"
        status="FAIL"
        ((FAILED_CHECKS++))
    elif [ "$found_timeout" -le 900 ] 2>/dev/null; then
        current="$found_timeout"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="$found_timeout"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    if [[ "$MODE" == "fix" ]] && [[ "$status" == "FAIL" ]]; then
        cat > /etc/profile.d/tmout.sh << 'EOF'
TMOUT=900
readonly TMOUT
export TMOUT
EOF
        
        chmod 644 /etc/profile.d/tmout.sh
        current="900"
        status="FIXED"
        ((FIXED_CHECKS++))
        log_fixed "Configured shell timeout to 900 seconds"
        save_fix_result "$policy_id" "$policy_name" "$expected" "$original" "$current" "$status"
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

check_default_user_umask() {
    local policy_id="UA-7.b.iii"
    local policy_name="Ensure default user umask is configured"
    local expected="027 or 077"
    ((TOTAL_CHECKS++))

    local current status original
    local found_umask=""
    
    for file in /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh; do
        if [ -f "$file" ]; then
            found_umask=$(grep "^umask" "$file" 2>/dev/null | head -1 | awk '{print $2}')
            if [ -n "$found_umask" ]; then
                break
            fi
        fi
    done
    
    original="$found_umask"
    
    if [ -z "$found_umask" ]; then
        current="not set"
        status="FAIL"
        ((FAILED_CHECKS++))
    elif [ "$found_umask" = "027" ] || [ "$found_umask" = "077" ]; then
        current="$found_umask"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="$found_umask"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    if [[ "$MODE" == "fix" ]] && [[ "$status" == "FAIL" ]]; then
        cat > /etc/profile.d/umask.sh << 'EOF'
umask 027
EOF
        
        chmod 644 /etc/profile.d/umask.sh
        current="027"
        status="FIXED"
        ((FIXED_CHECKS++))
        log_fixed "Configured default user umask to 027"
        save_fix_result "$policy_id" "$policy_name" "$expected" "$original" "$current" "$status"
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

# ============================================================================
# Main Execution
# ============================================================================
main() {
    echo "========================================================================"
    echo "User Accounts and Environment Hardening Script"
    echo "Module: $MODULE_NAME"
    echo "Mode: $MODE"
    echo "========================================================================"

    init_database

    if [[ "$MODE" == "fix" ]] && [[ "$EUID" -ne 0 ]]; then
        log_error "This script must be run as root for fix mode"
        exit 1
    fi

    # Execute all checks - Section 7.a: Shadow Password Suite Parameters
    check_password_expiration
    check_minimum_password_days
    check_password_warning_days
    check_password_hashing
    check_inactive_password_lock
    check_password_change_dates
    
    # Section 7.a: Root and System Accounts
    check_root_uid_zero
    check_root_gid_zero
    check_group_root_gid_zero
    check_root_access_controlled
    check_root_path_integrity
    check_root_umask
    check_system_accounts_nologin
    check_accounts_without_valid_shell_locked
    
    # Section 7.b: User Default Environment
    check_nologin_not_in_shells
    check_shell_timeout
    check_default_user_umask

    # Summary
    echo ""
    echo "========================================================================"
    echo "User Accounts Hardening Summary"
    echo "========================================================================"
    echo "Total Checks: $TOTAL_CHECKS"
    echo "Passed: $PASSED_CHECKS"
    echo "Failed: $FAILED_CHECKS"
    echo "Fixed:  $FIXED_CHECKS"
    echo "Manual Actions Required: $MANUAL_CHECKS"
    echo "========================================================================"
}

main
