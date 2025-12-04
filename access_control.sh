#!/bin/bash

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/access_control"
MODULE_NAME="Access Control"

mkdir -p "$BACKUP_DIR"

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
log_pass()  { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fixed() { echo -e "${BLUE}[FIXED]${NC} $1"; }
log_manual() { echo -e "${BLUE}[MANUAL]${NC} $1"; }

check_root_privileges() {
    if [ "$EUID" -ne 0 ]; then
        echo ""
        log_error "This script must be run as root or with sudo privileges"
        log_info "Please run: sudo $0 $MODE"
        echo ""
        exit 1
    fi
}

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

get_original_value() {
    local policy_id="$1"
    python3 - <<EOF
import sqlite3
conn = sqlite3.connect('$DB_PATH')
cursor = conn.cursor()
cursor.execute("SELECT original_value FROM fix_history WHERE module_name=? AND policy_id=?", ('$MODULE_NAME', '$policy_id'))
result = cursor.fetchone()
conn.close()
print(result[0] if result else '')
EOF
}

mark_rollback_executed() {
    local policy_id="$1"
    python3 - <<EOF
import sqlite3
conn = sqlite3.connect('$DB_PATH')
cursor = conn.cursor()
cursor.execute("UPDATE fix_history SET rollback_executed='YES' WHERE module_name=? AND policy_id=?", ('$MODULE_NAME', '$policy_id'))
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

    echo ""
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

# 6.a.i - SSH Config Permissions
check_ssh_config_permissions() {
    local policy_id="AC-6.a.i"
    local policy_name="Ensure permissions on /etc/ssh/sshd_config are configured"
    local expected="600 root:root"
    ((TOTAL_CHECKS++))

    local current status
    if [ -f /etc/ssh/sshd_config ]; then
        local perms=$(stat -c %a /etc/ssh/sshd_config 2>/dev/null)
        local owner=$(stat -c %U /etc/ssh/sshd_config 2>/dev/null)
        local group=$(stat -c %G /etc/ssh/sshd_config 2>/dev/null)
        current="$perms $owner:$group"
        
        if [ "$perms" = "600" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
            status="PASS"
            ((PASSED_CHECKS++))
        else
            status="FAIL"
            ((FAILED_CHECKS++))
            if [[ "$MODE" == "fix" ]]; then
                cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.$(date +%Y%m%d_%H%M%S)"
                chown root:root /etc/ssh/sshd_config
                chmod 600 /etc/ssh/sshd_config
                current="600 root:root"
                status="PASS"
                ((FIXED_CHECKS++))
                log_fixed "Set SSH config permissions to 600 root:root"
            fi
        fi
    else
        current="File not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "varied" "$current" "$status"
}

# 6.a.ii - SSH Private Host Key Permissions
check_ssh_private_keys() {
    local policy_id="AC-6.a.ii"
    local policy_name="Ensure permissions on SSH private host key files are configured"
    local expected="600 root:root"
    ((TOTAL_CHECKS++))

    local current status
    local failed_keys=0
    local total_keys=0
    
    if [ -d /etc/ssh ]; then
        while IFS= read -r keyfile; do
            if [ -f "$keyfile" ]; then
                ((total_keys++))
                local perms=$(stat -c %a "$keyfile" 2>/dev/null)
                local owner=$(stat -c %U "$keyfile" 2>/dev/null)
                local group=$(stat -c %G "$keyfile" 2>/dev/null)
                
                if [ "$perms" != "600" ] || [ "$owner" != "root" ] || [ "$group" != "root" ]; then
                    ((failed_keys++))
                    if [[ "$MODE" == "fix" ]]; then
                        chown root:root "$keyfile"
                        chmod 600 "$keyfile"
                        log_fixed "Fixed permissions on $keyfile"
                    fi
                fi
            fi
        done < <(find /etc/ssh -type f -name 'ssh_host_*_key' ! -name '*.pub')
        
        if [ $failed_keys -eq 0 ]; then
            current="All $total_keys private keys secured"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            if [[ "$MODE" == "fix" ]]; then
                current="Fixed $failed_keys of $total_keys keys"
                status="PASS"
                ((FIXED_CHECKS++))
            else
                current="$failed_keys of $total_keys keys misconfigured"
                status="FAIL"
                ((FAILED_CHECKS++))
            fi
        fi
    else
        current="SSH directory not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "misconfigured" "$current" "$status"
}

# 6.a.iii - SSH Public Host Key Permissions
check_ssh_public_keys() {
    local policy_id="AC-6.a.iii"
    local policy_name="Ensure permissions on SSH public host key files are configured"
    local expected="644 root:root"
    ((TOTAL_CHECKS++))

    local current status
    local failed_keys=0
    local total_keys=0
    
    if [ -d /etc/ssh ]; then
        while IFS= read -r keyfile; do
            if [ -f "$keyfile" ]; then
                ((total_keys++))
                local perms=$(stat -c %a "$keyfile" 2>/dev/null)
                local owner=$(stat -c %U "$keyfile" 2>/dev/null)
                local group=$(stat -c %G "$keyfile" 2>/dev/null)
                
                if [ "$perms" != "644" ] || [ "$owner" != "root" ] || [ "$group" != "root" ]; then
                    ((failed_keys++))
                    if [[ "$MODE" == "fix" ]]; then
                        chown root:root "$keyfile"
                        chmod 644 "$keyfile"
                        log_fixed "Fixed permissions on $keyfile"
                    fi
                fi
            fi
        done < <(find /etc/ssh -type f -name 'ssh_host_*_key.pub')
        
        if [ $failed_keys -eq 0 ]; then
            current="All $total_keys public keys secured"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            if [[ "$MODE" == "fix" ]]; then
                current="Fixed $failed_keys of $total_keys keys"
                status="PASS"
                ((FIXED_CHECKS++))
            else
                current="$failed_keys of $total_keys keys misconfigured"
                status="FAIL"
                ((FAILED_CHECKS++))
            fi
        fi
    else
        current="SSH directory not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "misconfigured" "$current" "$status"
}

# 6.a.iv - SSH Access Configuration
check_ssh_access() {
    local policy_id="AC-6.a.iv"
    local policy_name="Ensure sshd access is configured"
    local expected="AllowUsers/AllowGroups or DenyUsers/DenyGroups set"
    ((TOTAL_CHECKS++))

    local current status
    if [ -f /etc/ssh/sshd_config ]; then
        if grep -qE "^(AllowUsers|AllowGroups|DenyUsers|DenyGroups)" /etc/ssh/sshd_config; then
            current="SSH access restrictions configured"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="No SSH access restrictions"
            status="FAIL"
            ((FAILED_CHECKS++))
            if [[ "$MODE" == "fix" ]]; then
                ((MANUAL_CHECKS++))
                log_manual "Manual configuration required for SSH access control"
                log_manual "Add one of the following to /etc/ssh/sshd_config:"
                log_manual "  AllowUsers user1 user2"
                log_manual "  AllowGroups sshusers"
                log_manual "  DenyUsers baduser1 baduser2"
                log_manual "  DenyGroups nossh"
            fi
        fi
    else
        current="SSH config not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

# Generic SSH Parameter Check Function
check_sshd_parameter() {
    local param="$1"
    local expected_value="$2"
    local policy_id="$3"
    local policy_name="$4"
    
    ((TOTAL_CHECKS++))

    local current status
    if ! command -v sshd >/dev/null 2>&1; then
        current="sshd not installed"
        status="FAIL"
        ((FAILED_CHECKS++))
        print_check_result "$policy_id" "$policy_name" "$expected_value" "$current" "$status"
        [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected_value" "$current" "$status"
        return 1
    fi
    
    # Get current value using sshd -T
    current=$(sshd -T 2>/dev/null | grep -i "^$param " | awk '{print $2}')
    
    # If sshd -T fails, try to read from config file
    if [ -z "$current" ]; then
        current=$(grep -i "^$param " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    fi
    
    if [ -z "$current" ]; then
        current="not set"
        status="FAIL"
        ((FAILED_CHECKS++))
        
        if [[ "$MODE" == "fix" ]]; then
            if [ ! -f /etc/ssh/sshd_config ]; then
                log_error "Cannot fix: SSH config file not found"
            else
                cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
                echo "${param} ${expected_value}" >> /etc/ssh/sshd_config
                current="$expected_value"
                status="PASS"
                ((FIXED_CHECKS++))
                log_fixed "Set SSH $param = $expected_value"
            fi
        fi
    elif [ "$current" = "$expected_value" ]; then
        status="PASS"
        ((PASSED_CHECKS++))
    else
        status="FAIL"
        ((FAILED_CHECKS++))
        
        if [[ "$MODE" == "fix" ]]; then
            if [ ! -f /etc/ssh/sshd_config ]; then
                log_error "Cannot fix: SSH config file not found"
            else
                cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
                
                # Update or add parameter
                if grep -iq "^$param " /etc/ssh/sshd_config; then
                    sed -i "s/^${param} .*/${param} ${expected_value}/I" /etc/ssh/sshd_config
                elif grep -iq "^#${param} " /etc/ssh/sshd_config; then
                    sed -i "s/^#${param} .*/${param} ${expected_value}/I" /etc/ssh/sshd_config
                else
                    echo "${param} ${expected_value}" >> /etc/ssh/sshd_config
                fi
                
                current="$expected_value"
                status="PASS"
                ((FIXED_CHECKS++))
                log_fixed "Updated SSH $param = $expected_value"
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected_value" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected_value" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected_value" "not set" "$current" "$status"
}

# 6.a.v - SSH Banner
check_ssh_banner() {
    check_sshd_parameter "Banner" "/etc/issue.net" "AC-6.a.v" "Ensure sshd Banner is configured"
}

# 6.a.vi - SSH Ciphers
check_ssh_ciphers() {
    local policy_id="AC-6.a.vi"
    local policy_name="Ensure sshd Ciphers are configured"
    local expected="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
    ((TOTAL_CHECKS++))

    local current status
    if ! command -v sshd >/dev/null 2>&1; then
        current="sshd not installed"
        status="FAIL"
        ((FAILED_CHECKS++))
    else
        current=$(sshd -T 2>/dev/null | grep -i "^ciphers " | cut -d' ' -f2-)
        
        if [ -z "$current" ]; then
            current=$(grep -i "^Ciphers " /etc/ssh/sshd_config 2>/dev/null | cut -d' ' -f2-)
        fi
        
        if [ -z "$current" ]; then
            current="not set (using defaults)"
            status="FAIL"
            ((FAILED_CHECKS++))
            
            if [[ "$MODE" == "fix" ]]; then
                cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
                echo "Ciphers $expected" >> /etc/ssh/sshd_config
                current="$expected"
                status="PASS"
                ((FIXED_CHECKS++))
                log_fixed "Configured SSH Ciphers"
            fi
        else
            # Check if current ciphers are secure (simplified check)
            if echo "$current" | grep -qE "(chacha20-poly1305|aes256-gcm|aes128-gcm)"; then
                status="PASS"
                ((PASSED_CHECKS++))
            else
                status="FAIL"
                ((FAILED_CHECKS++))
                
                if [[ "$MODE" == "fix" ]]; then
                    cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
                    sed -i "s/^Ciphers .*/Ciphers $expected/I" /etc/ssh/sshd_config
                    current="$expected"
                    status="PASS"
                    ((FIXED_CHECKS++))
                    log_fixed "Updated SSH Ciphers"
                fi
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "weak/not set" "$current" "$status"
}

# 6.a.vii - SSH ClientAlive Settings
check_ssh_clientalive() {
    local policy_id="AC-6.a.vii"
    local policy_name="Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured"
    local expected="ClientAliveInterval 300, ClientAliveCountMax 3"
    ((TOTAL_CHECKS++))

    local current status
    local interval=$(sshd -T 2>/dev/null | grep -i "^clientaliveinterval " | awk '{print $2}')
    local countmax=$(sshd -T 2>/dev/null | grep -i "^clientalivecountmax " | awk '{print $2}')
    
    current="Interval:$interval, CountMax:$countmax"
    
    if [ "$interval" = "300" ] && [ "$countmax" = "3" ]; then
        status="PASS"
        ((PASSED_CHECKS++))
    else
        status="FAIL"
        ((FAILED_CHECKS++))
        
        if [[ "$MODE" == "fix" ]]; then
            cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
            
            if grep -iq "^ClientAliveInterval " /etc/ssh/sshd_config; then
                sed -i "s/^ClientAliveInterval .*/ClientAliveInterval 300/I" /etc/ssh/sshd_config
            else
                echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
            fi
            
            if grep -iq "^ClientAliveCountMax " /etc/ssh/sshd_config; then
                sed -i "s/^ClientAliveCountMax .*/ClientAliveCountMax 3/I" /etc/ssh/sshd_config
            else
                echo "ClientAliveCountMax 3" >> /etc/ssh/sshd_config
            fi
            
            current="Interval:300, CountMax:3"
            status="PASS"
            ((FIXED_CHECKS++))
            log_fixed "Configured SSH ClientAlive settings"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "$current" "300,3" "$status"
}

# 6.a.viii - SSH DisableForwarding
check_ssh_disableforwarding() {
    check_sshd_parameter "DisableForwarding" "yes" "AC-6.a.viii" "Ensure sshd DisableForwarding is enabled"
}

# 6.a.ix - SSH GSSAPIAuthentication
check_ssh_gssapi() {
    check_sshd_parameter "GSSAPIAuthentication" "no" "AC-6.a.ix" "Ensure sshd GSSAPIAuthentication is disabled"
}

# 6.a.x - SSH HostbasedAuthentication
check_ssh_hostbased() {
    check_sshd_parameter "HostbasedAuthentication" "no" "AC-6.a.x" "Ensure sshd HostbasedAuthentication is disabled"
}

# 6.a.xi - SSH IgnoreRhosts
check_ssh_ignorerhosts() {
    check_sshd_parameter "IgnoreRhosts" "yes" "AC-6.a.xi" "Ensure sshd IgnoreRhosts is enabled"
}

# 6.a.xii - SSH KexAlgorithms
check_ssh_kex() {
    local policy_id="AC-6.a.xii"
    local policy_name="Ensure sshd KexAlgorithms is configured"
    local expected="curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256"
    ((TOTAL_CHECKS++))

    local current status
    if ! command -v sshd >/dev/null 2>&1; then
        current="sshd not installed"
        status="FAIL"
        ((FAILED_CHECKS++))
    else
        current=$(sshd -T 2>/dev/null | grep -i "^kexalgorithms " | cut -d' ' -f2-)
        
        if [ -z "$current" ]; then
            current=$(grep -i "^KexAlgorithms " /etc/ssh/sshd_config 2>/dev/null | cut -d' ' -f2-)
        fi
        
        if [ -z "$current" ]; then
            current="not set (using defaults)"
            status="FAIL"
            ((FAILED_CHECKS++))
            
            if [[ "$MODE" == "fix" ]]; then
                cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
                echo "KexAlgorithms $expected" >> /etc/ssh/sshd_config
                current="$expected"
                status="PASS"
                ((FIXED_CHECKS++))
                log_fixed "Configured SSH KexAlgorithms"
            fi
        else
            # Check if current algorithms are secure
            if echo "$current" | grep -qE "(curve25519|ecdh-sha2)"; then
                status="PASS"
                ((PASSED_CHECKS++))
            else
                status="FAIL"
                ((FAILED_CHECKS++))
                
                if [[ "$MODE" == "fix" ]]; then
                    cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
                    sed -i "s/^KexAlgorithms .*/KexAlgorithms $expected/I" /etc/ssh/sshd_config
                    current="$expected"
                    status="PASS"
                    ((FIXED_CHECKS++))
                    log_fixed "Updated SSH KexAlgorithms"
                fi
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "weak/not set" "$current" "$status"
}
# 6.a.xiii - SSH LoginGraceTime
check_ssh_logingracetime() {
    check_sshd_parameter "LoginGraceTime" "60" "AC-6.a.xiii" "Ensure sshd LoginGraceTime is configured"
}

# 6.a.xiv - SSH LogLevel
check_ssh_loglevel() {
    check_sshd_parameter "LogLevel" "INFO" "AC-6.a.xiv" "Ensure sshd LogLevel is configured"
}

# 6.a.xv - SSH MACs
check_ssh_macs() {
    local policy_id="AC-6.a.xv"
    local policy_name="Ensure sshd MACs are configured"
    local expected="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
    ((TOTAL_CHECKS++))

    local current status
    if ! command -v sshd >/dev/null 2>&1; then
        current="sshd not installed"
        status="FAIL"
        ((FAILED_CHECKS++))
    else
        current=$(sshd -T 2>/dev/null | grep -i "^macs " | cut -d' ' -f2-)
        
        if [ -z "$current" ]; then
            current=$(grep -i "^MACs " /etc/ssh/sshd_config 2>/dev/null | cut -d' ' -f2-)
        fi
        
        if [ -z "$current" ]; then
            current="not set (using defaults)"
            status="FAIL"
            ((FAILED_CHECKS++))
            
            if [[ "$MODE" == "fix" ]]; then
                cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
                echo "MACs $expected" >> /etc/ssh/sshd_config
                current="$expected"
                status="PASS"
                ((FIXED_CHECKS++))
                log_fixed "Configured SSH MACs"
            fi
        else
            # Check if current MACs are secure
            if echo "$current" | grep -qE "(hmac-sha2-512|hmac-sha2-256)"; then
                status="PASS"
                ((PASSED_CHECKS++))
            else
                status="FAIL"
                ((FAILED_CHECKS++))
                
                if [[ "$MODE" == "fix" ]]; then
                    cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
                    sed -i "s/^MACs .*/MACs $expected/I" /etc/ssh/sshd_config
                    current="$expected"
                    status="PASS"
                    ((FIXED_CHECKS++))
                    log_fixed "Updated SSH MACs"
                fi
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "weak/not set" "$current" "$status"
}

# 6.a.xvi - SSH MaxAuthTries
check_ssh_maxauthtries() {
    check_sshd_parameter "MaxAuthTries" "4" "AC-6.a.xvi" "Ensure sshd MaxAuthTries is configured"
}

# 6.a.xvii - SSH MaxSessions
check_ssh_maxsessions() {
    check_sshd_parameter "MaxSessions" "10" "AC-6.a.xvii" "Ensure sshd MaxSessions is configured"
}

# 6.a.xviii - SSH MaxStartups
check_ssh_maxstartups() {
    check_sshd_parameter "MaxStartups" "10:30:60" "AC-6.a.xviii" "Ensure sshd MaxStartups is configured"
}

# 6.a.xix - SSH PermitEmptyPasswords
check_ssh_permitemptypasswords() {
    check_sshd_parameter "PermitEmptyPasswords" "no" "AC-6.a.xix" "Ensure sshd PermitEmptyPasswords is disabled"
}

# 6.a.xx - SSH PermitRootLogin
check_ssh_permitrootlogin() {
    check_sshd_parameter "PermitRootLogin" "no" "AC-6.a.xx" "Ensure sshd PermitRootLogin is disabled"
}

# 6.a.xxi - SSH PermitUserEnvironment
check_ssh_permituserenvironment() {
    check_sshd_parameter "PermitUserEnvironment" "no" "AC-6.a.xxi" "Ensure sshd PermitUserEnvironment is disabled"
}

# 6.a.xxii - SSH UsePAM
check_ssh_usepam() {
    check_sshd_parameter "UsePAM" "yes" "AC-6.a.xxii" "Ensure sshd UsePAM is enabled"
}

# ============================================================================
# SECTION 6.b - PRIVILEGE ESCALATION
# ============================================================================

# 6.b.i - Sudo Installed
check_sudo_installed() {
    local policy_id="AC-6.b.i"
    local policy_name="Ensure sudo is installed"
    local expected="sudo installed"
    ((TOTAL_CHECKS++))

    local current status
    if command -v sudo >/dev/null 2>&1; then
        current="sudo installed"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="sudo not installed"
        status="FAIL"
        ((FAILED_CHECKS++))
        
        if [[ "$MODE" == "fix" ]]; then
            log_info "Installing sudo..."
            if apt-get update >/dev/null 2>&1 && apt-get install -y sudo >/dev/null 2>&1; then
                current="sudo installed"
                status="PASS"
                ((FIXED_CHECKS++))
                log_fixed "Successfully installed sudo"
            else
                log_error "Failed to install sudo"
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "not installed" "$current" "$status"
}

# 6.b.ii - Sudo Use PTY
check_sudo_use_pty() {
    local policy_id="AC-6.b.ii"
    local policy_name="Ensure sudo commands use pty"
    local expected="Defaults use_pty configured"
    ((TOTAL_CHECKS++))

    local current status
    if grep -rq "^Defaults.*use_pty" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        current="use_pty configured"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="use_pty not configured"
        status="FAIL"
        ((FAILED_CHECKS++))
        
        if [[ "$MODE" == "fix" ]]; then
            cp /etc/sudoers "$BACKUP_DIR/sudoers.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
            
            if [ ! -f /etc/sudoers.d/hardening ]; then
                touch /etc/sudoers.d/hardening
                chmod 440 /etc/sudoers.d/hardening
            fi
            
            if ! grep -q "^Defaults.*use_pty" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
                echo "Defaults use_pty" >> /etc/sudoers.d/hardening
                current="use_pty configured"
                status="PASS"
                ((FIXED_CHECKS++))
                log_fixed "Configured sudo use_pty"
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "not configured" "$current" "$status"
}

# 6.b.iii - Sudo Log File
check_sudo_logfile() {
    local policy_id="AC-6.b.iii"
    local policy_name="Ensure sudo log file exists"
    local expected="Defaults logfile configured"
    ((TOTAL_CHECKS++))

    local current status
    if grep -rq "^Defaults.*logfile=" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        current="logfile configured"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="logfile not configured"
        status="FAIL"
        ((FAILED_CHECKS++))
        
        if [[ "$MODE" == "fix" ]]; then
            if [ ! -f /etc/sudoers.d/hardening ]; then
                touch /etc/sudoers.d/hardening
                chmod 440 /etc/sudoers.d/hardening
            fi
            
            if ! grep -rq "^Defaults.*logfile=" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
                echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers.d/hardening
                current="logfile=/var/log/sudo.log"
                status="PASS"
                ((FIXED_CHECKS++))
                log_fixed "Configured sudo logfile at /var/log/sudo.log"
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "not configured" "$current" "$status"
}

# 6.b.iv - Users Must Provide Password
check_sudo_password_required() {
    local policy_id="AC-6.b.iv"
    local policy_name="Ensure users must provide password for privilege escalation"
    local expected="No NOPASSWD entries"
    ((TOTAL_CHECKS++))

    local current status
    local nopasswd_count=$(grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#" | wc -l)
    
    if [ "$nopasswd_count" -eq 0 ]; then
        current="No NOPASSWD entries found"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="$nopasswd_count NOPASSWD entries found"
        status="FAIL"
        ((FAILED_CHECKS++))
        
        if [[ "$MODE" == "fix" ]]; then
            ((MANUAL_CHECKS++))
            log_manual "Manual review required for NOPASSWD entries"
            log_manual "Found NOPASSWD entries in:"
            grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#" | while read line; do
                log_manual "  $line"
            done
            log_manual "Review and remove NOPASSWD if not required for automation"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

# 6.b.v - Re-authentication Not Disabled
check_sudo_reauthentication() {
    local policy_id="AC-6.b.v"
    local policy_name="Ensure re-authentication for privilege escalation is not disabled globally"
    local expected="No global !authenticate"
    ((TOTAL_CHECKS++))

    local current status
    if grep -rq "^Defaults.*!authenticate" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        current="Global !authenticate found"
        status="FAIL"
        ((FAILED_CHECKS++))
        
        if [[ "$MODE" == "fix" ]]; then
            ((MANUAL_CHECKS++))
            log_manual "Manual review required for !authenticate directive"
            log_manual "Found in:"
            grep -r "^Defaults.*!authenticate" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | while read line; do
                log_manual "  $line"
            done
            log_manual "Remove or comment out these lines"
        fi
    else
        current="No global !authenticate"
        status="PASS"
        ((PASSED_CHECKS++))
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

# 6.b.vi - Sudo Authentication Timeout
check_sudo_timeout() {
    local policy_id="AC-6.b.vi"
    local policy_name="Ensure sudo authentication timeout is configured correctly"
    local expected="timestamp_timeout <= 15"
    ((TOTAL_CHECKS++))

    local current status
    local timeout=$(grep -r "^Defaults.*timestamp_timeout" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -o "timestamp_timeout=[0-9]*" | cut -d= -f2 | head -1)
    
    if [ -z "$timeout" ]; then
        current="timestamp_timeout not set (default 15)"
        status="PASS"
        ((PASSED_CHECKS++))
    elif [ "$timeout" -le 15 ]; then
        current="timestamp_timeout=$timeout"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="timestamp_timeout=$timeout (too high)"
        status="FAIL"
        ((FAILED_CHECKS++))
        
        if [[ "$MODE" == "fix" ]]; then
            if [ ! -f /etc/sudoers.d/hardening ]; then
                touch /etc/sudoers.d/hardening
                chmod 440 /etc/sudoers.d/hardening
            fi
            
            # Remove existing timeout settings
            sed -i '/timestamp_timeout/d' /etc/sudoers.d/hardening 2>/dev/null
            echo "Defaults timestamp_timeout=5" >> /etc/sudoers.d/hardening
            
            current="timestamp_timeout=5"
            status="PASS"
            ((FIXED_CHECKS++))
            log_fixed "Set sudo timestamp_timeout to 5 minutes"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "$timeout" "$current" "$status"
}

# 6.b.vii - SU Command Restricted
check_su_restricted() {
    local policy_id="AC-6.b.vii"
    local policy_name="Ensure access to the su command is restricted"
    local expected="pam_wheel.so required"
    ((TOTAL_CHECKS++))

    local current status
    if grep -q "^auth.*required.*pam_wheel.so" /etc/pam.d/su 2>/dev/null; then
        current="su restricted to wheel group"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="su not restricted"
        status="FAIL"
        ((FAILED_CHECKS++))
        
        if [[ "$MODE" == "fix" ]]; then
            cp /etc/pam.d/su "$BACKUP_DIR/su.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
            
            if ! grep -q "^auth.*required.*pam_wheel.so" /etc/pam.d/su 2>/dev/null; then
                echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su
                current="su restricted to wheel group"
                status="PASS"
                ((FIXED_CHECKS++))
                log_fixed "Restricted su command to wheel group"
            fi
            
            # Create wheel group if doesn't exist
            if ! getent group wheel >/dev/null; then
                groupadd wheel
                log_info "Created wheel group"
            fi
            
            ((MANUAL_CHECKS++))
            echo ""
            log_manual "╔════════════════════════════════════════════════════════════╗"
            log_manual "║ MANUAL ACTION REQUIRED: Add authorized users to wheel     ║"
            log_manual "║ group to allow them to use 'su' command:                  ║"
            log_manual "║                                                            ║"
            log_manual "║   sudo usermod -aG wheel <username>                        ║"
            log_manual "║                                                            ║"
            log_manual "║ Users not in the wheel group will NOT be able to use su   ║"
            log_manual "╚════════════════════════════════════════════════════════════╝"
            echo ""
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "not restricted" "$current" "$status"
}

# 6.c.i.1 - Latest PAM Version
check_pam_latest() {
    local policy_id="AC-6.c.i.1"
    local policy_name="Ensure latest version of pam is installed"
    local expected="Latest pam version"
    ((TOTAL_CHECKS++))

    local current status
    if dpkg -l | grep -q "^ii.*libpam0g"; then
        local version=$(dpkg -l | grep "^ii.*libpam0g" | awk '{print $3}')
        current="libpam0g version $version"
        
        # Check for updates
        apt-get update >/dev/null 2>&1
        local updates=$(apt-cache policy libpam0g | grep -A1 "Installed:" | grep "Candidate:" | awk '{print $2}')
        local installed=$(apt-cache policy libpam0g | grep "Installed:" | awk '{print $2}')
        
        if [ "$installed" = "$updates" ]; then
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="Installed: $installed, Available: $updates"
            status="FAIL"
            ((FAILED_CHECKS++))
            
            if [[ "$MODE" == "fix" ]]; then
                log_info "Updating libpam0g..."
                if apt-get install -y --only-upgrade libpam0g >/dev/null 2>&1; then
                    current="Updated to $updates"
                    status="PASS"
                    ((FIXED_CHECKS++))
                    log_fixed "Updated PAM to latest version"
                else
                    log_error "Failed to update PAM"
                fi
            fi
        fi
    else
        current="libpam0g not installed"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "$installed" "$current" "$status"
}

# 6.c.i.2 - libpam-modules Installed
check_pam_modules() {
    local policy_id="AC-6.c.i.2"
    local policy_name="Ensure libpam-modules is installed"
    local expected="libpam-modules installed"
    ((TOTAL_CHECKS++))

    local current status
    if dpkg -l 2>/dev/null | grep -q "^ii.*libpam-modules"; then
        current="libpam-modules installed"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="libpam-modules not installed"
        status="FAIL"
        ((FAILED_CHECKS++))
        
        if [[ "$MODE" == "fix" ]]; then
            log_info "Installing libpam-modules..."
            if apt-get update >/dev/null 2>&1 && apt-get install -y libpam-modules >/dev/null 2>&1; then
                current="libpam-modules installed"
                status="PASS"
                ((FIXED_CHECKS++))
                log_fixed "Successfully installed libpam-modules"
            else
                log_error "Failed to install libpam-modules"
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "not installed" "$current" "$status"
}

# 6.c.i.3 - libpam-pwquality Installed
check_pam_pwquality_installed() {
    local policy_id="AC-6.c.i.3"
    local policy_name="Ensure libpam-pwquality is installed"
    local expected="libpam-pwquality installed"
    ((TOTAL_CHECKS++))

    local current status
    if dpkg -l 2>/dev/null | grep -q "^ii.*libpam-pwquality"; then
        current="libpam-pwquality installed"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="libpam-pwquality not installed"
        status="FAIL"
        ((FAILED_CHECKS++))
        
        if [[ "$MODE" == "fix" ]]; then
            log_info "Installing libpam-pwquality..."
            if apt-get update >/dev/null 2>&1 && apt-get install -y libpam-pwquality >/dev/null 2>&1; then
                current="libpam-pwquality installed"
                status="PASS"
                ((FIXED_CHECKS++))
                log_fixed "Successfully installed libpam-pwquality"
            else
                log_error "Failed to install libpam-pwquality"
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "not installed" "$current" "$status"
}

# 6.c.ii.1 - pam_unix Module Enabled
check_pam_unix_enabled() {
    local policy_id="AC-6.c.ii.1"
    local policy_name="Ensure pam_unix module is enabled"
    local expected="pam_unix.so present in PAM config"
    ((TOTAL_CHECKS++))

    local current status
    if grep -r "pam_unix.so" /etc/pam.d/ 2>/dev/null | grep -qv "^#"; then
        current="pam_unix.so enabled"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="pam_unix.so not found"
        status="FAIL"
        ((FAILED_CHECKS++))
        
        if [[ "$MODE" == "fix" ]]; then
            ((MANUAL_CHECKS++))
            log_manual "Manual configuration required for pam_unix"
            log_manual "This is a critical PAM module and should be configured by system"
            log_manual "Run: pam-auth-update to configure PAM modules"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

# 6.c.ii.2 - pam_faillock Module Enabled
check_pam_faillock_enabled() {
    local policy_id="AC-6.c.ii.2"
    local policy_name="Ensure pam_faillock module is enabled"
    local expected="pam_faillock.so present in PAM config"
    ((TOTAL_CHECKS++))

    local current status
    if grep -r "pam_faillock.so" /etc/pam.d/ 2>/dev/null | grep -qv "^#"; then
        current="pam_faillock.so enabled"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="pam_faillock.so not configured"
        status="FAIL"
        ((FAILED_CHECKS++))
        
        if [[ "$MODE" == "fix" ]]; then
            ((MANUAL_CHECKS++))
            echo ""
            log_manual "╔════════════════════════════════════════════════════════════╗"
            log_manual "║ MANUAL ACTION REQUIRED: Configure pam_faillock            ║"
            log_manual "╚════════════════════════════════════════════════════════════╝"
            log_manual ""
            log_manual "Account lockout requires manual PAM configuration."
            log_manual "Run the following commands to configure:"
            log_manual ""
            log_manual "1. Edit /etc/pam.d/common-auth and add BEFORE pam_unix.so:"
            log_manual "   auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900"
            log_manual ""
            log_manual "2. Edit /etc/pam.d/common-auth and add AFTER pam_unix.so:"
            log_manual "   auth required pam_faillock.so authfail audit deny=5 unlock_time=900"
            log_manual ""
            log_manual "3. Edit /etc/pam.d/common-account and add:"
            log_manual "   account required pam_faillock.so"
            log_manual ""
            log_manual "This will lock accounts after 5 failed attempts for 15 minutes."
            echo ""
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

# 6.c.ii.3 - pam_pwquality Module Enabled
check_pam_pwquality_enabled() {
    local policy_id="AC-6.c.ii.3"
    local policy_name="Ensure pam_pwquality module is enabled"
    local expected="pam_pwquality.so present in PAM config"
    ((TOTAL_CHECKS++))

    local current status
    if grep -r "pam_pwquality.so" /etc/pam.d/ 2>/dev/null | grep -qv "^#"; then
        current="pam_pwquality.so enabled"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="pam_pwquality.so not configured"
        status="FAIL"
        ((FAILED_CHECKS++))
        
        if [[ "$MODE" == "fix" ]]; then
            cp /etc/pam.d/common-password "$BACKUP_DIR/common-password.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
            
            if ! grep -q "pam_pwquality.so" /etc/pam.d/common-password 2>/dev/null; then
                # Add pam_pwquality before pam_unix
                sed -i '/pam_unix.so/i password requisite pam_pwquality.so retry=3' /etc/pam.d/common-password
                current="pam_pwquality.so enabled"
                status="PASS"
                ((FIXED_CHECKS++))
                log_fixed "Enabled pam_pwquality module"
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "not configured" "$current" "$status"
}

# 6.c.ii.4 - pam_pwhistory Module Enabled
check_pam_pwhistory_enabled() {
    local policy_id="AC-6.c.ii.4"
    local policy_name="Ensure pam_pwhistory module is enabled"
    local expected="pam_pwhistory.so present in PAM config"
    ((TOTAL_CHECKS++))

    local current status
    if grep -r "pam_pwhistory.so" /etc/pam.d/ 2>/dev/null | grep -qv "^#"; then
        current="pam_pwhistory.so enabled"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="pam_pwhistory.so not configured"
        status="FAIL"
        ((FAILED_CHECKS++))
        
        if [[ "$MODE" == "fix" ]]; then
            cp /etc/pam.d/common-password "$BACKUP_DIR/common-password.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
            
            if ! grep -q "pam_pwhistory.so" /etc/pam.d/common-password 2>/dev/null; then
                # Add pam_pwhistory before pam_unix
                sed -i '/pam_unix.so/i password required pam_pwhistory.so remember=5 use_authtok' /etc/pam.d/common-password
                current="pam_pwhistory.so enabled"
                status="PASS"
                ((FIXED_CHECKS++))
                log_fixed "Enabled pam_pwhistory module"
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "not configured" "$current" "$status"
}

# 6.c.iii.1 - Password Failed Attempts Lockout
check_pam_faillock_attempts() {
    local policy_id="AC-6.c.iii.1"
    local policy_name="Ensure password failed attempts lockout is configured"
    local expected="deny=5 or less"
    ((TOTAL_CHECKS++))

    local current status
    local deny_value=$(grep -r "pam_faillock.so" /etc/pam.d/ 2>/dev/null | grep -v "^#" | grep -o "deny=[0-9]*" | cut -d= -f2 | head -1)
    
    if [ -z "$deny_value" ]; then
        current="deny not configured"
        status="FAIL"
        ((FAILED_CHECKS++))
    elif [ "$deny_value" -le 5 ]; then
        current="deny=$deny_value"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="deny=$deny_value (too high)"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    if [[ "$MODE" == "fix" ]] && [[ "$status" == "FAIL" ]]; then
        ((MANUAL_CHECKS++))
        log_manual "Refer to pam_faillock configuration in check AC-6.c.ii.2"
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

# 6.c.iii.2 - Password Unlock Time
check_pam_faillock_unlock() {
    local policy_id="AC-6.c.iii.2"
    local policy_name="Ensure password unlock time is configured"
    local expected="unlock_time=900 or higher"
    ((TOTAL_CHECKS++))

    local current status
    local unlock_value=$(grep -r "pam_faillock.so" /etc/pam.d/ 2>/dev/null | grep -v "^#" | grep -o "unlock_time=[0-9]*" | cut -d= -f2 | head -1)
    
    if [ -z "$unlock_value" ]; then
        current="unlock_time not configured"
        status="FAIL"
        ((FAILED_CHECKS++))
    elif [ "$unlock_value" -ge 900 ]; then
        current="unlock_time=$unlock_value"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="unlock_time=$unlock_value (too low)"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    if [[ "$MODE" == "fix" ]] && [[ "$status" == "FAIL" ]]; then
        ((MANUAL_CHECKS++))
        log_manual "Refer to pam_faillock configuration in check AC-6.c.ii.2"
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}
# 6.c.iii.3 - Faillock Includes Root Account
check_pam_faillock_root() {
    local policy_id="AC-6.c.iii.3"
    local policy_name="Ensure password failed attempts lockout includes root account"
    local expected="even_deny_root configured"
    ((TOTAL_CHECKS++))

    local current status
    if grep -r "pam_faillock.so" /etc/pam.d/ 2>/dev/null | grep -v "^#" | grep -q "even_deny_root"; then
        current="even_deny_root configured"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="even_deny_root not configured"
        status="FAIL"
        ((FAILED_CHECKS++))
        
        if [[ "$MODE" == "fix" ]]; then
            ((MANUAL_CHECKS++))
            log_manual "To include root in faillock, add 'even_deny_root' parameter"
            log_manual "to pam_faillock.so lines in /etc/pam.d/common-auth"
            log_manual "Example: auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900 even_deny_root"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}

# 6.c.iv.1 - Password Number of Changed Characters
check_pam_difok() {
    local policy_id="AC-6.c.iv.1"
    local policy_name="Ensure password number of changed characters is configured"
    local expected="difok >= 5"
    ((TOTAL_CHECKS++))

    local current status
    if [ ! -f /etc/security/pwquality.conf ]; then
        current="pwquality.conf not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    else
        local difok=$(grep "^difok" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
        
        if [ -z "$difok" ]; then
            difok=1  # default value
        fi
        
        if [ "$difok" -ge 5 ]; then
            current="difok=$difok"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="difok=$difok (too low)"
            status="FAIL"
            ((FAILED_CHECKS++))
            
            if [[ "$MODE" == "fix" ]]; then
                cp /etc/security/pwquality.conf "$BACKUP_DIR/pwquality.conf.$(date +%Y%m%d_%H%M%S)"
                
                if grep -q "^difok" /etc/security/pwquality.conf; then
                    sed -i 's/^difok.*/difok = 5/' /etc/security/pwquality.conf
                else
                    sed -i 's/^# difok.*/difok = 5/' /etc/security/pwquality.conf
                fi
                
                current="difok=5"
                status="PASS"
                ((FIXED_CHECKS++))
                log_fixed "Set difok=5 in pwquality.conf"
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "$difok" "$current" "$status"
}

# 6.c.iv.2 - Minimum Password Length
check_pam_minlen() {
    local policy_id="AC-6.c.iv.2"
    local policy_name="Ensure minimum password length is configured"
    local expected="minlen >= 14"
    ((TOTAL_CHECKS++))

    local current status
    if [ ! -f /etc/security/pwquality.conf ]; then
        current="pwquality.conf not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    else
        local minlen=$(grep "^minlen" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
        
        if [ -z "$minlen" ]; then
            minlen=0
        fi
        
        if [ "$minlen" -ge 14 ]; then
            current="minlen=$minlen"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="minlen=$minlen (too low)"
            status="FAIL"
            ((FAILED_CHECKS++))
            
            if [[ "$MODE" == "fix" ]]; then
                cp /etc/security/pwquality.conf "$BACKUP_DIR/pwquality.conf.$(date +%Y%m%d_%H%M%S)"
                
                if grep -q "^minlen" /etc/security/pwquality.conf; then
                    sed -i 's/^minlen.*/minlen = 14/' /etc/security/pwquality.conf
                else
                    sed -i 's/^# minlen.*/minlen = 14/' /etc/security/pwquality.conf
                fi
                
                current="minlen=14"
                status="PASS"
                ((FIXED_CHECKS++))
                log_fixed "Set minlen=14 in pwquality.conf"
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "$minlen" "$current" "$status"
}

# 6.c.iv.3 - Password Same Consecutive Characters
check_pam_maxrepeat() {
    local policy_id="AC-6.c.iv.3"
    local policy_name="Ensure password same consecutive characters is configured"
    local expected="maxrepeat <= 3"
    ((TOTAL_CHECKS++))

    local current status
    if [ ! -f /etc/security/pwquality.conf ]; then
        current="pwquality.conf not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    else
        local maxrepeat=$(grep "^maxrepeat" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
        
        if [ -z "$maxrepeat" ]; then
            current="maxrepeat not set"
            status="FAIL"
            ((FAILED_CHECKS++))
        elif [ "$maxrepeat" -le 3 ]; then
            current="maxrepeat=$maxrepeat"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="maxrepeat=$maxrepeat (too high)"
            status="FAIL"
            ((FAILED_CHECKS++))
        fi
        
        if [[ "$MODE" == "fix" ]] && [[ "$status" == "FAIL" ]]; then
            cp /etc/security/pwquality.conf "$BACKUP_DIR/pwquality.conf.$(date +%Y%m%d_%H%M%S)"
            
            if grep -q "^maxrepeat" /etc/security/pwquality.conf; then
                sed -i 's/^maxrepeat.*/maxrepeat = 3/' /etc/security/pwquality.conf
            else
                sed -i 's/^# maxrepeat.*/maxrepeat = 3/' /etc/security/pwquality.conf
            fi
            
            current="maxrepeat=3"
            status="PASS"
            ((FIXED_CHECKS++))
            log_fixed "Set maxrepeat=3 in pwquality.conf"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "$maxrepeat" "$current" "$status"
}

# 6.c.iv.4 - Password Maximum Sequential Characters
check_pam_maxsequence() {
    local policy_id="AC-6.c.iv.4"
    local policy_name="Ensure password maximum sequential characters is configured"
    local expected="maxsequence <= 3"
    ((TOTAL_CHECKS++))

    local current status
    if [ ! -f /etc/security/pwquality.conf ]; then
        current="pwquality.conf not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    else
        local maxsequence=$(grep "^maxsequence" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
        
        if [ -z "$maxsequence" ]; then
            current="maxsequence not set"
            status="FAIL"
            ((FAILED_CHECKS++))
        elif [ "$maxsequence" -le 3 ]; then
            current="maxsequence=$maxsequence"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="maxsequence=$maxsequence (too high)"
            status="FAIL"
            ((FAILED_CHECKS++))
        fi
        
        if [[ "$MODE" == "fix" ]] && [[ "$status" == "FAIL" ]]; then
            cp /etc/security/pwquality.conf "$BACKUP_DIR/pwquality.conf.$(date +%Y%m%d_%H%M%S)"
            
            if grep -q "^maxsequence" /etc/security/pwquality.conf; then
                sed -i 's/^maxsequence.*/maxsequence = 3/' /etc/security/pwquality.conf
            else
                sed -i 's/^# maxsequence.*/maxsequence = 3/' /etc/security/pwquality.conf
            fi
            
            current="maxsequence=3"
            status="PASS"
            ((FIXED_CHECKS++))
            log_fixed "Set maxsequence=3 in pwquality.conf"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "$maxsequence" "$current" "$status"
}

# 6.c.iv.5 - Password Dictionary Check
check_pam_dictcheck() {
    local policy_id="AC-6.c.iv.5"
    local policy_name="Ensure password dictionary check is enabled"
    local expected="dictcheck=1"
    ((TOTAL_CHECKS++))

    local current status
    if [ ! -f /etc/security/pwquality.conf ]; then
        current="pwquality.conf not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    else
        local dictcheck=$(grep "^dictcheck" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
        
        if [ "$dictcheck" = "1" ]; then
            current="dictcheck=1"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="dictcheck=${dictcheck:-not set}"
            status="FAIL"
            ((FAILED_CHECKS++))
            
            if [[ "$MODE" == "fix" ]]; then
                cp /etc/security/pwquality.conf "$BACKUP_DIR/pwquality.conf.$(date +%Y%m%d_%H%M%S)"
                
                if grep -q "^dictcheck" /etc/security/pwquality.conf; then
                    sed -i 's/^dictcheck.*/dictcheck = 1/' /etc/security/pwquality.conf
                else
                    sed -i 's/^# dictcheck.*/dictcheck = 1/' /etc/security/pwquality.conf
                fi
                
                current="dictcheck=1"
                status="PASS"
                ((FIXED_CHECKS++))
                log_fixed "Enabled dictcheck in pwquality.conf"
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "$dictcheck" "$current" "$status"
}

# 6.c.iv.6 - Password Quality Checking Enforced
check_pam_enforcing() {
    local policy_id="AC-6.c.iv.6"
    local policy_name="Ensure password quality checking is enforced"
    local expected="enforcing=1"
    ((TOTAL_CHECKS++))

    local current status
    if [ ! -f /etc/security/pwquality.conf ]; then
        current="pwquality.conf not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    else
        local enforcing=$(grep "^enforcing" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
        
        if [ "$enforcing" = "1" ] || [ -z "$enforcing" ]; then
            current="enforcing=${enforcing:-1 (default)}"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="enforcing=$enforcing"
            status="FAIL"
            ((FAILED_CHECKS++))
            
            if [[ "$MODE" == "fix" ]]; then
                cp /etc/security/pwquality.conf "$BACKUP_DIR/pwquality.conf.$(date +%Y%m%d_%H%M%S)"
                
                if grep -q "^enforcing" /etc/security/pwquality.conf; then
                    sed -i 's/^enforcing.*/enforcing = 1/' /etc/security/pwquality.conf
                else
                    echo "enforcing = 1" >> /etc/security/pwquality.conf
                fi
                
                current="enforcing=1"
                status="PASS"
                ((FIXED_CHECKS++))
                log_fixed "Set enforcing=1 in pwquality.conf"
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "$enforcing" "$current" "$status"
}

# 6.c.iv.7 - Password Quality Enforced for Root
check_pam_enforce_for_root() {
    local policy_id="AC-6.c.iv.7"
    local policy_name="Ensure password quality is enforced for the root user"
    local expected="enforce_for_root configured"
    ((TOTAL_CHECKS++))

    local current status
    if [ ! -f /etc/security/pwquality.conf ]; then
        current="pwquality.conf not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    else
        if grep -q "^enforce_for_root" /etc/security/pwquality.conf 2>/dev/null; then
            current="enforce_for_root configured"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="enforce_for_root not configured"
            status="FAIL"
            ((FAILED_CHECKS++))
            
            if [[ "$MODE" == "fix" ]]; then
                cp /etc/security/pwquality.conf "$BACKUP_DIR/pwquality.conf.$(date +%Y%m%d_%H%M%S)"
                echo "enforce_for_root" >> /etc/security/pwquality.conf
                
                current="enforce_for_root configured"
                status="PASS"
                ((FIXED_CHECKS++))
                log_fixed "Enabled enforce_for_root in pwquality.conf"
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "not configured" "$current" "$status"
}

# 6.c.v.1 - Password History Remember
check_pam_pwhistory_remember() {
    local policy_id="AC-6.c.v.1"
    local policy_name="Ensure password history remember is configured"
    local expected="remember >= 5"
    ((TOTAL_CHECKS++))

    local current status
    local remember=$(grep -r "pam_pwhistory.so" /etc/pam.d/ 2>/dev/null | grep -v "^#" | grep -o "remember=[0-9]*" | cut -d= -f2 | head -1)
    
    if [ -z "$remember" ]; then
        current="remember not configured"
        status="FAIL"
        ((FAILED_CHECKS++))
        
        if [[ "$MODE" == "fix" ]]; then
            # Already handled in pam_pwhistory_enabled check
            ((MANUAL_CHECKS++))
            log_manual "Password history configured via pam_pwhistory module enablement"
        fi
    elif [ "$remember" -ge 5 ]; then
        current="remember=$remember"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="remember=$remember (too low)"
        status="FAIL"
        ((FAILED_CHECKS++))
        
        if [[ "$MODE" == "fix" ]]; then
            cp /etc/pam.d/common-password "$BACKUP_DIR/common-password.$(date +%Y%m%d_%H%M%S)"
            sed -i "s/remember=[0-9]*/remember=5/" /etc/pam.d/common-password
            
            current="remember=5"
            status="PASS"
            ((FIXED_CHECKS++))
            log_fixed "Updated password history remember to 5"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "$remember" "$current" "$status"
}

# 6.c.v.2 - Password History Enforced for Root
check_pam_pwhistory_root() {
    local policy_id="AC-6.c.v.2"
    local policy_name="Ensure password history is enforced for the root user"
    local expected="enforce_for_root in pam_pwhistory"
    ((TOTAL_CHECKS++))

    local current status
    if grep -r "pam_pwhistory.so" /etc/pam.d/ 2>/dev/null | grep -v "^#" | grep -q "enforce_for_root"; then
        current="enforce_for_root configured"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="enforce_for_root not configured"
        status="FAIL"
        ((FAILED_CHECKS++))
        
        if [[ "$MODE" == "fix" ]]; then
            cp /etc/pam.d/common-password "$BACKUP_DIR/common-password.$(date +%Y%m%d_%H%M%S)"
            
            # Add enforce_for_root to pam_pwhistory line
            if grep -q "pam_pwhistory.so" /etc/pam.d/common-password; then
                sed -i '/pam_pwhistory.so/ s/$/ enforce_for_root/' /etc/pam.d/common-password
                current="enforce_for_root configured"
                status="PASS"
                ((FIXED_CHECKS++))
                log_fixed "Added enforce_for_root to pam_pwhistory"
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "not configured" "$current" "$status"
}

# 6.c.v.3 - pam_pwhistory Includes use_authtok
check_pam_pwhistory_authtok() {
    local policy_id="AC-6.c.v.3"
    local policy_name="Ensure pam_pwhistory includes use_authtok"
    local expected="use_authtok in pam_pwhistory"
    ((TOTAL_CHECKS++))

    local current status
    if grep -r "pam_pwhistory.so" /etc/pam.d/ 2>/dev/null | grep -v "^#" | grep -q "use_authtok"; then
        current="use_authtok configured"
        status="PASS"
        ((PASSED_CHECKS++))
    else
        current="use_authtok not configured"
        status="FAIL"
        ((FAILED_CHECKS++))
        
        if [[ "$MODE" == "fix" ]]; then
            # Already handled in pam_pwhistory_enabled check
            log_info "use_authtok should be configured via pam_pwhistory module enablement"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
}
# ============================================================================
# MAIN EXECUTION FUNCTIONS
# ============================================================================

run_all_ssh_checks() {
    echo ""
    log_info "         SECTION 6.a - SSH SERVER CONFIGURATION             "
    
    check_ssh_config_permissions
    check_ssh_private_keys
    check_ssh_public_keys
    check_ssh_access
    check_ssh_banner
    check_ssh_ciphers
    check_ssh_clientalive
    check_ssh_disableforwarding
    check_ssh_gssapi
    check_ssh_hostbased
    check_ssh_ignorerhosts
    check_ssh_kex
    check_ssh_logingracetime
    check_ssh_loglevel
    check_ssh_macs
    check_ssh_maxauthtries
    check_ssh_maxsessions
    check_ssh_maxstartups
    check_ssh_permitemptypasswords
    check_ssh_permitrootlogin
    check_ssh_permituserenvironment
    check_ssh_usepam
}

run_all_sudo_checks() {
    echo ""
    log_info "       SECTION 6.b - PRIVILEGE ESCALATION                   "
    check_sudo_installed
    check_sudo_use_pty
    check_sudo_logfile
    check_sudo_password_required
    check_sudo_reauthentication
    check_sudo_timeout
    check_su_restricted
}

run_all_pam_checks() {
    echo ""
    log_info "   SECTION 6.c - PLUGGABLE AUTHENTICATION MODULES (PAM)     "
    check_pam_latest
    check_pam_modules
    check_pam_pwquality_installed
    
    # PAM Modules Enabled
    check_pam_unix_enabled
    check_pam_faillock_enabled
    check_pam_pwquality_enabled
    check_pam_pwhistory_enabled
    
    # PAM Faillock Configuration
    check_pam_faillock_attempts
    check_pam_faillock_unlock
    check_pam_faillock_root
    
    # PAM Password Quality
    check_pam_difok
    check_pam_minlen
    check_pam_maxrepeat
    check_pam_maxsequence
    check_pam_dictcheck
    check_pam_enforcing
    check_pam_enforce_for_root
    
    # PAM Password History
    check_pam_pwhistory_remember
    check_pam_pwhistory_root
    check_pam_pwhistory_authtok
}

print_summary() {
    echo ""
    echo "========================================================================"
    echo "                    ACCESS CONTROL HARDENING SUMMARY"
    echo "========================================================================"
    echo "Total Checks Performed : $TOTAL_CHECKS"
    
    if [ "$MODE" = "scan" ]; then
        echo "Checks Passed          : $PASSED_CHECKS"
        echo "Checks Failed          : $FAILED_CHECKS"
        echo ""
        
        if [ $FAILED_CHECKS -eq 0 ]; then
            log_pass "✓ All access control checks passed!"
        else
            local pass_percentage=$((PASSED_CHECKS * 100 / TOTAL_CHECKS))
            echo "Compliance Level       : ${pass_percentage}%"
            echo ""
            log_warn "✗ $FAILED_CHECKS checks failed"
            echo ""
            log_info "To fix issues automatically, run:"
            log_info "  sudo $0 fix"
            echo ""
            log_info "To view detailed scan results:"
            log_info "  sqlite3 $DB_PATH 'SELECT policy_id, policy_name, status FROM scan_results WHERE module_name=\"$MODULE_NAME\"'"
        fi
        
    elif [ "$MODE" = "fix" ]; then
        echo "Checks Fixed           : $FIXED_CHECKS"
        echo "Manual Actions Required: $MANUAL_CHECKS"
        echo ""
        
        if [ $FIXED_CHECKS -gt 0 ]; then
            log_info "✓ Fixes applied successfully"
            echo ""
            log_warn "╔════════════════════════════════════════════════════════════╗"
            log_warn "║         IMPORTANT: Services need to be restarted           ║"
            log_warn "╚════════════════════════════════════════════════════════════╝"
            log_warn ""
            log_warn "Run the following commands to apply changes:"
            log_warn ""
            log_warn "  sudo systemctl restart sshd"
            log_warn ""
            log_warn "After restarting services, run scan to verify:"
            log_warn "  sudo $0 scan"
            echo ""
        fi
        
        if [ $MANUAL_CHECKS -gt 0 ]; then
            echo ""
            log_manual "╔════════════════════════════════════════════════════════════╗"
            log_manual "║  $MANUAL_CHECKS manual configuration(s) required                    ║"
            log_manual "║  Review the warnings above for details                     ║"
            log_manual "╚════════════════════════════════════════════════════════════╝"
            echo ""
        fi
        
        echo ""
        log_info "Fix history saved to database"
        log_info "To view fix history:"
        log_info "  sqlite3 $DB_PATH 'SELECT policy_id, policy_name, status FROM fix_history WHERE module_name=\"$MODULE_NAME\"'"
        echo ""
        log_info "To rollback changes, run:"
        log_info "  sudo ./access_control_rollback.sh"
    fi
    
    echo "========================================================================"
}

main() {
    echo "========================================================================"
    echo "Access Control Hardening Script"
    echo "Module: $MODULE_NAME"
    echo "Mode: $MODE"
    echo "========================================================================"

    init_database

    if [ "$MODE" = "fix" ] && [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root for fix mode"
        exit 1
    fi
    run_all_ssh_checks
    run_all_sudo_checks
    run_all_pam_checks
    echo ""
    echo "========================================================================"
    echo "Access Control Hardening Summary"
    echo "========================================================================"
    echo "Total Checks: $TOTAL_CHECKS"
    echo "Passed: $PASSED_CHECKS"
    echo "Failed: $FAILED_CHECKS"
    echo "Fixed:  $FIXED_CHECKS"
    echo "Manual Actions Required: $MANUAL_CHECKS"
    echo "========================================================================"
}

main
