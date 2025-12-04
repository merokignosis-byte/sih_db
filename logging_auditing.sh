#!/bin/bash
# ============================================================================
# Logging and Auditing Hardening Script
# Module: Logging and Auditing
# Modes: scan | fix | rollback
# CIS Benchmark Compliant - Complete Implementation
# ============================================================================
MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/logging_auditing"
MODULE_NAME="Logging and Auditing"

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
# 8.a.i System Logging - journald
# ============================================================================

check_8_a_i_1() {
    local policy_id="8.a.i.1"
    local policy_name="Ensure journald service is enabled and active"
    local expected="active"
    ((TOTAL_CHECKS++))

    local current status
    if systemctl is-active systemd-journald 2>/dev/null | grep -q "active"; then
        current="active"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "journald is active"
    else
        current="inactive"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "journald is not active"
        
        if [[ "$MODE" == "fix" ]]; then
            systemctl enable systemd-journald >/dev/null 2>&1
            systemctl start systemd-journald >/dev/null 2>&1
            current="active"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Enabled and started journald"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "inactive" "$current" "FIXED"
}

check_8_a_i_2() {
    local policy_id="8.a.i.2"
    local policy_name="Ensure journald log file access is configured"
    local expected="0640 or more restrictive"
    ((TOTAL_CHECKS++))

    local current status
    if [ -d /var/log/journal ]; then
        local perms=$(find /var/log/journal -type f -exec stat -c "%a" {} \; 2>/dev/null | sort -u)
        local bad_perms=$(find /var/log/journal -type f -perm /027 2>/dev/null | wc -l)
        
        if [ "$bad_perms" -eq 0 ]; then
            current="Properly configured (0640)"
            status="PASS"
            ((PASSED_CHECKS++))
            log_pass "Journal log file permissions are correct"
        else
            current="Insecure permissions found on $bad_perms files"
            status="FAIL"
            ((FAILED_CHECKS++))
            log_error "Journal log files have incorrect permissions"
            
            if [[ "$MODE" == "fix" ]]; then
                find /var/log/journal -type f -exec chmod 0640 {} \; 2>/dev/null
                current="Fixed to 0640"
                status="FIXED"
                ((FIXED_CHECKS++))
                log_fixed "Fixed journal log file permissions"
            fi
        fi
    else
        current="Journal directory not found"
        status="PASS"
        ((PASSED_CHECKS++))
        log_warn "Journal persistent storage not configured"
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Insecure permissions" "$current" "FIXED"
}

check_8_a_i_3() {
    local policy_id="8.a.i.3"
    local policy_name="Ensure journald log file rotation is configured"
    local expected="Compress=yes and rotation configured"
    ((TOTAL_CHECKS++))

    local current status original_config=""
    if [ -f /etc/systemd/journald.conf ]; then
        local compress=$(grep "^Compress=" /etc/systemd/journald.conf 2>/dev/null | cut -d= -f2)
        local max_file_sec=$(grep "^MaxFileSec=" /etc/systemd/journald.conf 2>/dev/null | cut -d= -f2)
        local sys_max_use=$(grep "^SystemMaxUse=" /etc/systemd/journald.conf 2>/dev/null | cut -d= -f2)
        
        original_config="Compress=${compress:-not_set} MaxFileSec=${max_file_sec:-not_set} SystemMaxUse=${sys_max_use:-not_set}"
        
        if [ "$compress" = "yes" ] || [ -n "$max_file_sec" ]; then
            current="Configured (Compress=$compress, MaxFileSec=$max_file_sec)"
            status="PASS"
            ((PASSED_CHECKS++))
            log_pass "journald rotation is configured"
        else
            current="Not configured"
            status="FAIL"
            ((FAILED_CHECKS++))
            log_error "journald rotation not configured"
            
            if [[ "$MODE" == "fix" ]]; then
                cp /etc/systemd/journald.conf "$BACKUP_DIR/journald.conf.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
                
                sed -i 's/^#Compress=.*/Compress=yes/' /etc/systemd/journald.conf
                sed -i 's/^Compress=.*/Compress=yes/' /etc/systemd/journald.conf
                
                if ! grep -q "^Compress=" /etc/systemd/journald.conf; then
                    echo "Compress=yes" >> /etc/systemd/journald.conf
                fi
                
                sed -i 's/^#SystemMaxUse=.*/SystemMaxUse=1G/' /etc/systemd/journald.conf
                if ! grep -q "^SystemMaxUse=" /etc/systemd/journald.conf; then
                    echo "SystemMaxUse=1G" >> /etc/systemd/journald.conf
                fi
                
                sed -i 's/^#MaxFileSec=.*/MaxFileSec=1month/' /etc/systemd/journald.conf
                if ! grep -q "^MaxFileSec=" /etc/systemd/journald.conf; then
                    echo "MaxFileSec=1month" >> /etc/systemd/journald.conf
                fi
                
                systemctl restart systemd-journald >/dev/null 2>&1
                current="Configured (Compress=yes, MaxFileSec=1month, SystemMaxUse=1G)"
                status="FIXED"
                ((FIXED_CHECKS++))
                log_fixed "Configured journald rotation"
            fi
        fi
    else
        current="journald.conf not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "$original_config" "$current" "FIXED"
}

check_8_a_i_4() {
    local policy_id="8.a.i.4"
    local policy_name="Ensure only one logging system is in use"
    local expected="Either journald OR rsyslog active (not both conflicting)"
    ((TOTAL_CHECKS++))

    local current status
    local journald_active=$(systemctl is-active systemd-journald 2>/dev/null)
    local rsyslog_installed=$(dpkg -l | grep -c "^ii.*rsyslog")
    local rsyslog_active=$(systemctl is-active rsyslog 2>/dev/null)
    
    if [ "$journald_active" = "active" ] && [ "$rsyslog_active" = "active" ]; then
        # Both active - check if properly integrated
        local forward_to_syslog=$(grep "^ForwardToSyslog=" /etc/systemd/journald.conf 2>/dev/null | cut -d= -f2)
        if [ "$forward_to_syslog" = "yes" ]; then
            current="Both active with proper integration (journald forwards to rsyslog)"
            status="PASS"
            ((PASSED_CHECKS++))
            log_pass "Dual logging properly configured"
        else
            current="Both active without integration"
            status="FAIL"
            ((FAILED_CHECKS++))
            log_error "Both logging systems active without proper integration"
        fi
    elif [ "$journald_active" = "active" ] && [ "$rsyslog_active" != "active" ]; then
        current="journald active (modern approach)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "Using journald for logging"
    elif [ "$rsyslog_active" = "active" ] && [ "$journald_active" != "active" ]; then
        current="rsyslog active only"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "Using rsyslog for logging"
    else
        current="No logging system active"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "No logging system is active"
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    # This is informational check, no auto-fix
}

# ============================================================================
# 8.a.ii System Logging - rsyslog
# ============================================================================

check_8_a_ii_1() {
    local policy_id="8.a.ii.1"
    local policy_name="Ensure rsyslog is installed"
    local expected="rsyslog installed"
    ((TOTAL_CHECKS++))

    local current status
    if dpkg -l | grep -q "^ii.*rsyslog"; then
        current="Installed"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "rsyslog is installed"
    else
        current="Not installed"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "rsyslog is not installed"
        
        if [[ "$MODE" == "fix" ]]; then
            log_manual "=============================================="
            log_manual "MANUAL DECISION REQUIRED: rsyslog Installation"
            log_manual "=============================================="
            log_manual "rsyslog is not installed. Modern systems use systemd-journald."
            log_manual ""
            log_manual "OPTIONS:"
            log_manual "1. Keep systemd-journald only (RECOMMENDED)"
            log_manual "   - No action needed"
            log_manual "   - Sufficient for most use cases"
            log_manual ""
            log_manual "2. Install rsyslog (if required by policy)"
            log_manual "   sudo apt-get install -y rsyslog"
            log_manual "   sudo systemctl enable rsyslog"
            log_manual "   sudo systemctl start rsyslog"
            log_manual "=============================================="
            current="Manual intervention required"
            status="MANUAL"
            ((MANUAL_CHECKS++))
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "MANUAL" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not installed" "$current" "MANUAL"
}

check_8_a_ii_2() {
    local policy_id="8.a.ii.2"
    local policy_name="Ensure rsyslog service is enabled and active"
    local expected="enabled and active"
    ((TOTAL_CHECKS++))

    local current status
    if ! dpkg -l | grep -q "^ii.*rsyslog"; then
        current="rsyslog not installed - skipped"
        status="PASS"
        ((PASSED_CHECKS++))
        log_warn "rsyslog not installed - skipping service check"
    else
        if systemctl is-enabled rsyslog 2>&1 | grep -q "masked"; then
            current="masked (conflict with journald)"
            status="FAIL"
            ((FAILED_CHECKS++))
            log_error "rsyslog service is masked"
            
            if [[ "$MODE" == "fix" ]]; then
                log_manual "=============================================="
                log_manual "MANUAL DECISION: rsyslog is masked"
                log_manual "=============================================="
                log_manual "Your system is using systemd-journald for logging."
                log_manual "Both rsyslog and systemd-journald provide logging services."
                log_manual ""
                log_manual "OPTIONS:"
                log_manual "1. Keep systemd-journald (RECOMMENDED)"
                log_manual "   - No action needed"
                log_manual ""
                log_manual "2. Switch to rsyslog"
                log_manual "   sudo systemctl unmask rsyslog"
                log_manual "   sudo systemctl enable rsyslog"
                log_manual "   sudo systemctl start rsyslog"
                log_manual ""
                log_manual "3. Use both (dual logging)"
                log_manual "   sudo systemctl unmask rsyslog"
                log_manual "   sudo systemctl enable rsyslog"
                log_manual "   sudo systemctl start rsyslog"
                log_manual "   echo 'ForwardToSyslog=yes' >> /etc/systemd/journald.conf"
                log_manual "   sudo systemctl restart systemd-journald"
                log_manual "=============================================="
                current="Manual intervention required"
                status="MANUAL"
                ((MANUAL_CHECKS++))
            fi
        elif systemctl is-enabled rsyslog 2>/dev/null | grep -q "enabled" && \
             systemctl is-active rsyslog 2>/dev/null | grep -q "active"; then
            current="enabled and active"
            status="PASS"
            ((PASSED_CHECKS++))
            log_pass "rsyslog is enabled and active"
        else
            local enabled_status=$(systemctl is-enabled rsyslog 2>&1)
            local active_status=$(systemctl is-active rsyslog 2>&1)
            current="enabled: $enabled_status, active: $active_status"
            status="FAIL"
            ((FAILED_CHECKS++))
            log_error "rsyslog service not properly configured"
            
            if [[ "$MODE" == "fix" ]]; then
                systemctl enable rsyslog >/dev/null 2>&1
                systemctl start rsyslog >/dev/null 2>&1
                current="enabled and active"
                status="FIXED"
                ((FIXED_CHECKS++))
                log_fixed "Enabled and started rsyslog"
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "disabled or inactive" "$current" "$status"
}

check_8_a_ii_3() {
    local policy_id="8.a.ii.3"
    local policy_name="Ensure journald is configured to send logs to rsyslog"
    local expected="ForwardToSyslog=yes"
    ((TOTAL_CHECKS++))

    local current status
    if ! dpkg -l | grep -q "^ii.*rsyslog"; then
        current="rsyslog not installed - not applicable"
        status="PASS"
        ((PASSED_CHECKS++))
        log_warn "rsyslog not installed - forwarding not needed"
    elif [ -f /etc/systemd/journald.conf ]; then
        local forward=$(grep "^ForwardToSyslog=" /etc/systemd/journald.conf 2>/dev/null | cut -d= -f2)
        
        if [ "$forward" = "yes" ]; then
            current="yes"
            status="PASS"
            ((PASSED_CHECKS++))
            log_pass "journald forwards to rsyslog"
        else
            current="${forward:-not set}"
            status="FAIL"
            ((FAILED_CHECKS++))
            log_error "journald not configured to forward to rsyslog"
            
            if [[ "$MODE" == "fix" ]]; then
                cp /etc/systemd/journald.conf "$BACKUP_DIR/journald.conf.forward.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
                
                sed -i 's/^#ForwardToSyslog=.*/ForwardToSyslog=yes/' /etc/systemd/journald.conf
                sed -i 's/^ForwardToSyslog=.*/ForwardToSyslog=yes/' /etc/systemd/journald.conf
                
                if ! grep -q "^ForwardToSyslog=" /etc/systemd/journald.conf; then
                    echo "ForwardToSyslog=yes" >> /etc/systemd/journald.conf
                fi
                
                systemctl restart systemd-journald >/dev/null 2>&1
                current="yes"
                status="FIXED"
                ((FIXED_CHECKS++))
                log_fixed "Configured journald to forward to rsyslog"
            fi
        fi
    else
        current="journald.conf not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "not set" "$current" "FIXED"
}

check_8_a_ii_4() {
    local policy_id="8.a.ii.4"
    local policy_name="Ensure rsyslog log file creation mode is configured"
    local expected="$FileCreateMode 0640"
    ((TOTAL_CHECKS++))

    local current status
    if ! command -v rsyslogd &> /dev/null; then
        current="rsyslog not installed - skipped"
        status="PASS"
        ((PASSED_CHECKS++))
        log_warn "rsyslog not installed - skipping"
    elif [ ! -f /etc/rsyslog.conf ]; then
        current="rsyslog.conf not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    else
        if grep -q '^\$FileCreateMode 0640' /etc/rsyslog.conf 2>/dev/null || \
           grep -rq '^\$FileCreateMode 0640' /etc/rsyslog.d/ 2>/dev/null; then
            current="0640"
            status="PASS"
            ((PASSED_CHECKS++))
            log_pass "rsyslog file creation mode is 0640"
        else
            local existing=$(grep '^\$FileCreateMode' /etc/rsyslog.conf 2>/dev/null | head -1)
            current="${existing:-not set}"
            status="FAIL"
            ((FAILED_CHECKS++))
            log_error "rsyslog file creation mode not configured"
            
            if [[ "$MODE" == "fix" ]]; then
                cp /etc/rsyslog.conf "$BACKUP_DIR/rsyslog.conf.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
                
                if grep -q '^\$FileCreateMode' /etc/rsyslog.conf; then
                    sed -i 's/^\$FileCreateMode.*/$FileCreateMode 0640/' /etc/rsyslog.conf
                else
                    sed -i '1a\\n# Set default permissions for log files\n$FileCreateMode 0640' /etc/rsyslog.conf
                fi
                
                if rsyslogd -N1 &>/dev/null; then
                    systemctl restart rsyslog >/dev/null 2>&1
                    current="0640"
                    status="FIXED"
                    ((FIXED_CHECKS++))
                    log_fixed "Configured rsyslog file creation mode"
                else
                    log_error "rsyslog configuration validation failed"
                    cp "$BACKUP_DIR/rsyslog.conf.$(date +%Y%m%d_%H%M%S)" /etc/rsyslog.conf 2>/dev/null
                    status="FAIL"
                fi
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "not set" "$current" "FIXED"
}

# END OF PART 1
# Continue with Part 2 for remaining checks...
# ============================================================================
# PART 2 - Continuing from Part 1
# ============================================================================

check_8_a_ii_5() {
    local policy_id="8.a.ii.5"
    local policy_name="Ensure rsyslog logging is configured"
    local expected="Log facilities properly configured"
    ((TOTAL_CHECKS++))

    local current status
    if ! command -v rsyslogd &> /dev/null; then
        current="rsyslog not installed - skipped"
        status="PASS"
        ((PASSED_CHECKS++))
        log_warn "rsyslog not installed - skipping"
    elif [ ! -f /etc/rsyslog.conf ]; then
        current="rsyslog.conf not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    else
        # Check for common log facilities
        local has_auth=$(grep -E '^\s*auth,authpriv\.\*' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | wc -l)
        local has_kern=$(grep -E '^\s*kern\.\*' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | wc -l)
        local has_mail=$(grep -E '^\s*mail\.\*' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | wc -l)
        
        if [ "$has_auth" -gt 0 ] && [ "$has_kern" -gt 0 ]; then
            current="Configured (auth, kern, and other facilities)"
            status="PASS"
            ((PASSED_CHECKS++))
            log_pass "rsyslog logging facilities configured"
        else
            current="Missing required log facilities"
            status="FAIL"
            ((FAILED_CHECKS++))
            log_error "rsyslog logging not properly configured"
            
            if [[ "$MODE" == "fix" ]]; then
                log_manual "=============================================="
                log_manual "MANUAL REVIEW REQUIRED: rsyslog Logging Configuration"
                log_manual "=============================================="
                log_manual "rsyslog logging facilities need to be configured."
                log_manual ""
                log_manual "Verify /etc/rsyslog.conf and /etc/rsyslog.d/*.conf contain:"
                log_manual "  auth,authpriv.*     /var/log/auth.log"
                log_manual "  kern.*              /var/log/kern.log"
                log_manual "  mail.*              /var/log/mail.log"
                log_manual "  *.info;*.notice     /var/log/messages"
                log_manual ""
                log_manual "Default Ubuntu/Debian configs usually have these."
                log_manual "Check: cat /etc/rsyslog.d/50-default.conf"
                log_manual "=============================================="
                current="Manual review required"
                status="MANUAL"
                ((MANUAL_CHECKS++))
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "MANUAL" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not properly configured" "$current" "MANUAL"
}

check_8_a_ii_6() {
    local policy_id="8.a.ii.6"
    local policy_name="Ensure rsyslog is configured to send logs to a remote log host"
    local expected="Remote logging configured"
    ((TOTAL_CHECKS++))

    local current status
    if ! command -v rsyslogd &> /dev/null; then
        current="rsyslog not installed - skipped"
        status="PASS"
        ((PASSED_CHECKS++))
        log_warn "rsyslog not installed - skipping"
    else
        if grep -qE '^\*\.\*[[:space:]]+@' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
            local remote_host=$(grep -E '^\*\.\*[[:space:]]+@' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | head -1)
            current="Configured: $remote_host"
            status="PASS"
            ((PASSED_CHECKS++))
            log_pass "rsyslog remote logging is configured"
        else
            current="Not configured"
            status="FAIL"
            ((FAILED_CHECKS++))
            log_error "rsyslog remote logging not configured"
            
            if [[ "$MODE" == "fix" ]]; then
                log_manual "=============================================="
                log_manual "MANUAL CONFIGURATION REQUIRED: Remote Log Server"
                log_manual "=============================================="
                log_manual "Remote logging requires a log server IP/hostname."
                log_manual ""
                log_manual "To configure remote logging:"
                log_manual "1. Determine your remote log server address"
                log_manual "2. Create /etc/rsyslog.d/50-remote.conf"
                log_manual "3. Add one of these lines:"
                log_manual ""
                log_manual "   For UDP (standard):"
                log_manual "   *.* @logserver.example.com:514"
                log_manual ""
                log_manual "   For TCP (reliable):"
                log_manual "   *.* @@logserver.example.com:514"
                log_manual ""
                log_manual "4. Restart rsyslog:"
                log_manual "   sudo systemctl restart rsyslog"
                log_manual "=============================================="
                current="Manual configuration required"
                status="MANUAL"
                ((MANUAL_CHECKS++))
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "MANUAL" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not configured" "$current" "MANUAL"
}

check_8_a_ii_7() {
    local policy_id="8.a.ii.7"
    local policy_name="Ensure rsyslog is not configured to receive logs from a remote client"
    local expected="Not configured as log server"
    ((TOTAL_CHECKS++))

    local current status
    if ! command -v rsyslogd &> /dev/null; then
        current="rsyslog not installed - skipped"
        status="PASS"
        ((PASSED_CHECKS++))
        log_warn "rsyslog not installed - skipping"
    else
        # Check for input modules that receive remote logs
        local has_imtcp=$(grep -E '^\s*module\(load="imtcp"\)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null)
        local has_imudp=$(grep -E '^\s*module\(load="imudp"\)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null)
        local has_input=$(grep -E '^\s*input\(type="(imtcp|imudp)"' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null)
        
        if [ -z "$has_imtcp" ] && [ -z "$has_imudp" ] && [ -z "$has_input" ]; then
            current="Not configured as log server"
            status="PASS"
            ((PASSED_CHECKS++))
            log_pass "rsyslog not receiving remote logs"
        else
            current="Configured to receive remote logs"
            status="FAIL"
            ((FAILED_CHECKS++))
            log_error "rsyslog is configured as a remote log server"
            
            if [[ "$MODE" == "fix" ]]; then
                log_manual "=============================================="
                log_manual "MANUAL REVIEW REQUIRED: Remote Log Reception"
                log_manual "=============================================="
                log_manual "rsyslog is configured to receive remote logs."
                log_manual ""
                log_manual "Found configurations:"
                log_manual "$has_imtcp"
                log_manual "$has_imudp"
                log_manual "$has_input"
                log_manual ""
                log_manual "If this system should NOT be a log server:"
                log_manual "1. Remove or comment these lines in rsyslog configs"
                log_manual "2. Restart rsyslog: sudo systemctl restart rsyslog"
                log_manual ""
                log_manual "If this IS a designated log server, this is expected."
                log_manual "=============================================="
                current="Manual review required"
                status="MANUAL"
                ((MANUAL_CHECKS++))
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "MANUAL" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Configured as log server" "$current" "MANUAL"
}

check_8_a_ii_8() {
    local policy_id="8.a.ii.8"
    local policy_name="Ensure logrotate is configured"
    local expected="logrotate installed and configured"
    ((TOTAL_CHECKS++))

    local current status
    if [ -f /etc/logrotate.conf ] && [ -d /etc/logrotate.d ]; then
        current="Configured"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "logrotate is configured"
    else
        current="Not properly configured"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "logrotate is not properly configured"
        
        if [[ "$MODE" == "fix" ]]; then
            if ! command -v logrotate >/dev/null; then
                apt-get update -y >/dev/null 2>&1
                apt-get install -y logrotate >/dev/null 2>&1
                current="Installed and configured"
                status="FIXED"
                ((FIXED_CHECKS++))
                log_fixed "Installed logrotate"
            else
                current="Already installed"
                status="PASS"
                ((PASSED_CHECKS++))
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not installed" "$current" "FIXED"
}

# ============================================================================
# 8.a.iii Configure Logfiles
# ============================================================================

check_8_a_iii_1() {
    local policy_id="8.a.iii.1"
    local policy_name="Ensure access to all logfiles has been configured"
    local expected="0640 or more restrictive"
    ((TOTAL_CHECKS++))

    local current status
    local bad_perms=$(find /var/log -type f -perm /027 2>/dev/null | wc -l)
    
    if [ "$bad_perms" -eq 0 ]; then
        current="All log files properly secured"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "Log file permissions are correct"
    else
        current="$bad_perms files with incorrect permissions"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "Found $bad_perms log files with incorrect permissions"
        
        if [[ "$MODE" == "fix" ]]; then
            find /var/log -type f -exec chmod g-wx,o-rwx {} \; 2>/dev/null
            current="Fixed permissions on all log files"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Fixed log file permissions (removed group write/execute and other access)"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Insecure permissions" "$current" "FIXED"
}

# ============================================================================
# 8.b.i System Auditing - auditd Service
# ============================================================================

check_8_b_i_1() {
    local policy_id="8.b.i.1"
    local policy_name="Ensure auditd packages are installed"
    local expected="auditd and audispd-plugins installed"
    ((TOTAL_CHECKS++))

    local current status
    if dpkg -l | grep -q "^ii.*auditd" && dpkg -l | grep -q "^ii.*audispd-plugins"; then
        current="Installed"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "auditd packages are installed"
    else
        current="Not installed"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "auditd packages are not installed"
        
        if [[ "$MODE" == "fix" ]]; then
            apt-get update -y >/dev/null 2>&1
            apt-get install -y auditd audispd-plugins >/dev/null 2>&1
            current="Installed"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Installed auditd and audispd-plugins"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not installed" "$current" "FIXED"
}

check_8_b_i_2() {
    local policy_id="8.b.i.2"
    local policy_name="Ensure auditd service is enabled and active"
    local expected="enabled and active"
    ((TOTAL_CHECKS++))

    local current status
    if systemctl is-enabled auditd 2>/dev/null | grep -q "enabled" && \
       systemctl is-active auditd 2>/dev/null | grep -q "active"; then
        current="enabled and active"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "auditd is enabled and active"
    else
        local enabled_status=$(systemctl is-enabled auditd 2>&1)
        local active_status=$(systemctl is-active auditd 2>&1)
        current="enabled: $enabled_status, active: $active_status"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "auditd is not properly configured"
        
        if [[ "$MODE" == "fix" ]]; then
            systemctl enable auditd >/dev/null 2>&1
            systemctl start auditd >/dev/null 2>&1
            current="enabled and active"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Enabled and started auditd"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "disabled or inactive" "$current" "FIXED"
}

check_8_b_i_3() {
    local policy_id="8.b.i.3"
    local policy_name="Ensure auditing for processes that start prior to auditd is enabled"
    local expected="audit=1 in kernel parameters"
    ((TOTAL_CHECKS++))

    local current status
    if grep -q "audit=1" /proc/cmdline 2>/dev/null; then
        current="audit=1 set"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "Boot parameter audit=1 is set"
    else
        current="audit=1 not set"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "Boot parameter audit=1 is not set"
        
        if [[ "$MODE" == "fix" ]]; then
            log_manual "=============================================="
            log_manual "MANUAL CONFIGURATION REQUIRED: GRUB Boot Parameters"
            log_manual "=============================================="
            log_manual "To enable auditing from boot, modify GRUB configuration."
            log_manual ""
            log_manual "STEPS:"
            log_manual "1. Edit /etc/default/grub"
            log_manual "2. Find line: GRUB_CMDLINE_LINUX=\"...\""
            log_manual "3. Add 'audit=1' inside the quotes"
            log_manual "   Example: GRUB_CMDLINE_LINUX=\"quiet splash audit=1\""
            log_manual "4. Update GRUB:"
            log_manual "   sudo update-grub"
            log_manual "5. Reboot the system"
            log_manual ""
            log_manual "VERIFICATION:"
            log_manual "After reboot: grep audit=1 /proc/cmdline"
            log_manual "=============================================="
            current="Manual configuration required"
            status="MANUAL"
            ((MANUAL_CHECKS++))
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "MANUAL" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "not set" "$current" "MANUAL"
}

check_8_b_i_4() {
    local policy_id="8.b.i.4"
    local policy_name="Ensure audit_backlog_limit is sufficient"
    local expected="audit_backlog_limit >= 8192"
    ((TOTAL_CHECKS++))

    local current status
    local backlog=$(grep -o "audit_backlog_limit=[0-9]*" /proc/cmdline 2>/dev/null | cut -d= -f2)
    
    if [ -n "$backlog" ] && [ "$backlog" -ge 8192 ]; then
        current="$backlog"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "audit_backlog_limit is sufficient ($backlog)"
    else
        current="${backlog:-not set}"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "audit_backlog_limit not set or insufficient"
        
        if [[ "$MODE" == "fix" ]]; then
            log_manual "=============================================="
            log_manual "MANUAL CONFIGURATION REQUIRED: Audit Backlog Limit"
            log_manual "=============================================="
            log_manual "Set audit_backlog_limit in GRUB for busy systems."
            log_manual ""
            log_manual "STEPS:"
            log_manual "1. Edit /etc/default/grub"
            log_manual "2. Find line: GRUB_CMDLINE_LINUX=\"...\""
            log_manual "3. Add 'audit_backlog_limit=8192' inside quotes"
            log_manual "   Example: GRUB_CMDLINE_LINUX=\"quiet audit=1 audit_backlog_limit=8192\""
            log_manual "4. Update GRUB: sudo update-grub"
            log_manual "5. Reboot the system"
            log_manual "=============================================="
            current="Manual configuration required"
            status="MANUAL"
            ((MANUAL_CHECKS++))
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "MANUAL" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "not set" "$current" "MANUAL"
}

# ============================================================================
# 8.b.c Configure Data Retention
# ============================================================================

check_8_b_c_i() {
    local policy_id="8.b.c.i"
    local policy_name="Ensure audit log storage size is configured"
    local expected="max_log_file >= 8 MB"
    ((TOTAL_CHECKS++))

    local current status
    if [ -f /etc/audit/auditd.conf ]; then
        local max_log_file=$(grep "^max_log_file " /etc/audit/auditd.conf 2>/dev/null | awk '{print $3}')
        
        if [ -n "$max_log_file" ] && [ "$max_log_file" -ge 8 ]; then
            current="${max_log_file}MB"
            status="PASS"
            ((PASSED_CHECKS++))
            log_pass "Audit log storage configured: ${max_log_file}MB"
        else
            current="${max_log_file:-not set}MB"
            status="FAIL"
            ((FAILED_CHECKS++))
            log_error "Audit log storage not properly configured"
            
            if [[ "$MODE" == "fix" ]]; then
                cp /etc/audit/auditd.conf "$BACKUP_DIR/auditd.conf.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
                
                sed -i 's/^max_log_file .*/max_log_file = 10/' /etc/audit/auditd.conf
                
                service auditd restart >/dev/null 2>&1
                current="10MB"
                status="FIXED"
                ((FIXED_CHECKS++))
                log_fixed "Configured audit log storage (10MB)"
            fi
        fi
    else
        current="auditd.conf not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "not configured" "$current" "FIXED"
}

check_8_b_c_ii() {
    local policy_id="8.b.c.ii"
    local policy_name="Ensure audit logs are not automatically deleted"
    local expected="max_log_file_action = keep_logs"
    ((TOTAL_CHECKS++))

    local current status
    if [ -f /etc/audit/auditd.conf ]; then
        local max_action=$(grep "^max_log_file_action" /etc/audit/auditd.conf 2>/dev/null | awk '{print $3}')
        
        if [ "$max_action" = "keep_logs" ]; then
            current="keep_logs"
            status="PASS"
            ((PASSED_CHECKS++))
            log_pass "Audit logs are kept (not deleted)"
        else
            current="${max_action:-not set}"
            status="FAIL"
            ((FAILED_CHECKS++))
            log_error "Audit logs may be automatically deleted"
            
            if [[ "$MODE" == "fix" ]]; then
                cp /etc/audit/auditd.conf "$BACKUP_DIR/auditd.conf.keep.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
                
                sed -i 's/^max_log_file_action .*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf
                
                service auditd restart >/dev/null 2>&1
                current="keep_logs"
                status="FIXED"
                ((FIXED_CHECKS++))
                log_fixed "Configured to keep audit logs"
            fi
        fi
    else
        current="auditd.conf not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "not configured" "$current" "FIXED"
}

check_8_b_c_iii() {
    local policy_id="8.b.c.iii"
    local policy_name="Ensure system is disabled when audit logs are full"
    local expected="admin_space_left_action = halt or single"
    ((TOTAL_CHECKS++))

    local current status
    if [ -f /etc/audit/auditd.conf ]; then
        local space_left_action=$(grep "^space_left_action" /etc/audit/auditd.conf 2>/dev/null | awk '{print $3}')
        local action_mail_acct=$(grep "^action_mail_acct" /etc/audit/auditd.conf 2>/dev/null | awk '{print $3}')
        local admin_space_left_action=$(grep "^admin_space_left_action" /etc/audit/auditd.conf 2>/dev/null | awk '{print $3}')
        
        current="space_left=$space_left_action, admin_action=$admin_space_left_action"
        
        if [ "$admin_space_left_action" = "halt" ] || [ "$admin_space_left_action" = "single" ]; then
            status="PASS"
            ((PASSED_CHECKS++))
            log_pass "System will be disabled when audit logs are full"
        else
            status="FAIL"
            ((FAILED_CHECKS++))
            log_error "System not configured to disable when audit logs full"
            
            if [[ "$MODE" == "fix" ]]; then
                log_manual "=============================================="
                log_manual "MANUAL CONFIGURATION REQUIRED: Audit Disk Full Actions"
                log_manual "=============================================="
                log_manual "Configure what happens when audit logs fill the disk."
                log_manual ""
                log_manual "WARNING: admin_space_left_action = halt will HALT the system!"
                log_manual "This is CIS recommended but may not suit all environments."
                log_manual ""
                log_manual "Edit /etc/audit/auditd.conf and configure:"
                log_manual "  space_left_action = email"
                log_manual "  action_mail_acct = root"
                log_manual "  admin_space_left_action = halt"
                log_manual ""
                log_manual "Alternative (less disruptive):"
                log_manual "  admin_space_left_action = single"
                log_manual ""
                log_manual "Then restart: sudo service auditd restart"
                log_manual "=============================================="
                current="Manual configuration required"
                status="MANUAL"
                ((MANUAL_CHECKS++))
            fi
        fi
    else
        current="auditd.conf not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "MANUAL" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "not configured" "$current" "MANUAL"
}

check_8_b_c_iv() {
    local policy_id="8.b.c.iv"
    local policy_name="Ensure system warns when audit logs are low on space"
    local expected="space_left configured with email action"
    ((TOTAL_CHECKS++))

    local current status
    if [ -f /etc/audit/auditd.conf ]; then
        local space_left=$(grep "^space_left " /etc/audit/auditd.conf 2>/dev/null | awk '{print $3}')
        local space_left_action=$(grep "^space_left_action" /etc/audit/auditd.conf 2>/dev/null | awk '{print $3}')
        
        if [ -n "$space_left" ] && [ "$space_left_action" = "email" ]; then
            current="space_left=${space_left}MB, action=email"
            status="PASS"
            ((PASSED_CHECKS++))
            log_pass "System will warn when audit logs are low on space"
        else
            current="space_left=${space_left:-not set}, action=${space_left_action:-not set}"
            status="FAIL"
            ((FAILED_CHECKS++))
            log_error "Warning for low audit log space not configured"
            
            if [[ "$MODE" == "fix" ]]; then
                cp /etc/audit/auditd.conf "$BACKUP_DIR/auditd.conf.space.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
                
                sed -i 's/^space_left_action .*/space_left_action = email/' /etc/audit/auditd.conf
                
                # Set space_left to 25% of max_log_file if not set
                if [ -z "$space_left" ]; then
                    sed -i 's/^space_left .*/space_left = 75/' /etc/audit/auditd.conf
                fi
                
                service auditd restart >/dev/null 2>&1
                current="Configured with email notification"
                status="FIXED"
                ((FIXED_CHECKS++))
                log_fixed "Configured low space warning"
            fi
        fi
    else
        current="auditd.conf not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    # ============================================================================
# PART 2 - CONTINUATION (Rest of Part 2)
# Starting from completing check_8_b_c_iv() and adding all 8.b.d checks
# ============================================================================

# First, complete the check_8_b_c_iv() function (it was incomplete)
# Add these lines to complete it:

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "not configured" "$current" "FIXED"
}

# ============================================================================
# 8.b.d Configure auditd Rules
# ============================================================================

check_8_b_d_i() {
    local policy_id="8.b.d.i"
    local policy_name="Ensure changes to system administration scope (sudoers) is collected"
    local expected="Audit rules for /etc/sudoers and /etc/sudoers.d/"
    ((TOTAL_CHECKS++))

    local current status
    local rules_file="/etc/audit/rules.d/hardening.rules"
    
    # Check on-disk rules
    local has_sudoers=$(grep -E "^\-w /etc/sudoers" "$rules_file" 2>/dev/null | wc -l)
    local has_sudoers_d=$(grep -E "^\-w /etc/sudoers.d/" "$rules_file" 2>/dev/null | wc -l)
    
    # Check running rules
    local running_sudoers=$(auditctl -l 2>/dev/null | grep -E "/etc/sudoers" | wc -l)
    
    if [ "$has_sudoers" -gt 0 ] && [ "$has_sudoers_d" -gt 0 ] && [ "$running_sudoers" -gt 0 ]; then
        current="Configured (on-disk and running)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "sudoers audit rules are configured"
    else
        current="Not configured (on-disk: $has_sudoers rules, running: $running_sudoers rules)"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "sudoers audit rules not configured"
        
        if [[ "$MODE" == "fix" ]]; then
            # Backup if file exists
            if [ -f "$rules_file" ]; then
                cp "$rules_file" "$BACKUP_DIR/hardening.rules.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
            fi
            
            # Ensure directory exists
            mkdir -p /etc/audit/rules.d
            
            # Add sudoers rules if not present
            if [ "$has_sudoers" -eq 0 ]; then
                echo "-w /etc/sudoers -p wa -k scope" >> "$rules_file"
            fi
            if [ "$has_sudoers_d" -eq 0 ]; then
                echo "-w /etc/sudoers.d/ -p wa -k scope" >> "$rules_file"
            fi
            
            # Load rules
            augenrules --load >/dev/null 2>&1
            
            current="Rules added and loaded"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Configured sudoers audit rules"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not configured" "$current" "FIXED"
}

check_8_b_d_ii() {
    local policy_id="8.b.d.ii"
    local policy_name="Ensure actions as another user are always logged"
    local expected="Audit rules for privilege escalation (execve)"
    ((TOTAL_CHECKS++))

    local current status
    local rules_file="/etc/audit/rules.d/hardening.rules"
    
    # Check for execve audit rules (actions as another user)
    local has_b64=$(grep -E "^\-a always,exit.*\-S execve.*\-k actions" "$rules_file" 2>/dev/null | grep "b64" | wc -l)
    local has_b32=$(grep -E "^\-a always,exit.*\-S execve.*\-k actions" "$rules_file" 2>/dev/null | grep "b32" | wc -l)
    local running=$(auditctl -l 2>/dev/null | grep "execve" | grep "actions" | wc -l)
    
    if [ "$has_b64" -gt 0 ] && [ "$has_b32" -gt 0 ] && [ "$running" -gt 0 ]; then
        current="Configured (b64 and b32 rules active)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "Actions as another user are audited"
    else
        current="Not configured (b64: $has_b64, b32: $has_b32, running: $running)"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "Actions as another user not audited"
        
        if [[ "$MODE" == "fix" ]]; then
            if [ -f "$rules_file" ]; then
                cp "$rules_file" "$BACKUP_DIR/hardening.rules.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
            fi
            
            mkdir -p /etc/audit/rules.d
            
            if [ "$has_b64" -eq 0 ]; then
                echo "-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -F auid>=1000 -F auid!=4294967295 -S execve -k actions" >> "$rules_file"
            fi
            if [ "$has_b32" -eq 0 ]; then
                echo "-a always,exit -F arch=b32 -C euid!=uid -F euid=0 -F auid>=1000 -F auid!=4294967295 -S execve -k actions" >> "$rules_file"
            fi
            
            augenrules --load >/dev/null 2>&1
            
            current="Rules added and loaded"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Configured audit rules for actions as another user"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not configured" "$current" "FIXED"
}

check_8_b_d_iii() {
    local policy_id="8.b.d.iii"
    local policy_name="Ensure events that modify the sudo log file are collected"
    local expected="Audit rule for sudo log file"
    ((TOTAL_CHECKS++))

    local current status
    local rules_file="/etc/audit/rules.d/hardening.rules"
    
    # Find sudo log file location
    local sudo_log=$(grep -r "^Defaults.*logfile=" /etc/sudoers* 2>/dev/null | sed 's/.*logfile=//;s/"//g' | head -1)
    sudo_log="${sudo_log:-/var/log/sudo.log}"
    
    # Check if rule exists for sudo log
    local has_rule=$(grep -E "^\-w.*sudo.*log" "$rules_file" 2>/dev/null | wc -l)
    local running=$(auditctl -l 2>/dev/null | grep -i "sudo" | grep "log" | wc -l)
    
    if [ "$has_rule" -gt 0 ] && [ "$running" -gt 0 ]; then
        current="Configured (monitoring $sudo_log)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "Sudo log file is monitored"
    else
        current="Not configured"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "Sudo log file not monitored"
        
        if [[ "$MODE" == "fix" ]]; then
            if [ -f "$rules_file" ]; then
                cp "$rules_file" "$BACKUP_DIR/hardening.rules.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
            fi
            
            mkdir -p /etc/audit/rules.d
            
            if [ "$has_rule" -eq 0 ]; then
                echo "-w $sudo_log -p wa -k sudo_log_file" >> "$rules_file"
            fi
            
            augenrules --load >/dev/null 2>&1
            
            current="Rule added for $sudo_log"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Configured audit rule for sudo log file"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not configured" "$current" "FIXED"
}

check_8_b_d_iv() {
    local policy_id="8.b.d.iv"
    local policy_name="Ensure events that modify date and time information are collected"
    local expected="Audit rules for time changes"
    ((TOTAL_CHECKS++))

    local current status
    local rules_file="/etc/audit/rules.d/hardening.rules"
    
    # Check for time-related syscalls and files
    local has_adjtimex=$(grep -E "adjtimex|settimeofday" "$rules_file" 2>/dev/null | grep "time-change" | wc -l)
    local has_clock_settime=$(grep -E "clock_settime" "$rules_file" 2>/dev/null | grep "time-change" | wc -l)
    local has_localtime=$(grep -E "/etc/localtime" "$rules_file" 2>/dev/null | wc -l)
    local running=$(auditctl -l 2>/dev/null | grep "time-change" | wc -l)
    
    if [ "$has_adjtimex" -gt 0 ] && [ "$has_clock_settime" -gt 0 ] && [ "$has_localtime" -gt 0 ] && [ "$running" -gt 0 ]; then
        current="Configured (syscalls and files monitored)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "Date/time modification events are audited"
    else
        current="Not configured (adjtimex: $has_adjtimex, clock: $has_clock_settime, running: $running)"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "Date/time modification events not audited"
        
        if [[ "$MODE" == "fix" ]]; then
            if [ -f "$rules_file" ]; then
                cp "$rules_file" "$BACKUP_DIR/hardening.rules.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
            fi
            
            mkdir -p /etc/audit/rules.d
            
            # Add time change rules
            cat >> "$rules_file" << 'EOF'

## Time changes
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
EOF
            
            augenrules --load >/dev/null 2>&1
            
            current="Time change rules added and loaded"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Configured audit rules for date/time changes"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not configured" "$current" "FIXED"
}

check_8_b_d_v() {
    local policy_id="8.b.d.v"
    local policy_name="Ensure events that modify the system's network environment are collected"
    local expected="Audit rules for network changes"
    ((TOTAL_CHECKS++))

    local current status
    local rules_file="/etc/audit/rules.d/hardening.rules"
    
    # Check for network-related syscalls and files
    local has_hostname=$(grep -E "sethostname|setdomainname" "$rules_file" 2>/dev/null | grep "system-locale" | wc -l)
    local has_issue=$(grep -E "/etc/issue" "$rules_file" 2>/dev/null | wc -l)
    local has_hosts=$(grep -E "/etc/hosts" "$rules_file" 2>/dev/null | wc -l)
    local has_network=$(grep -E "/etc/network" "$rules_file" 2>/dev/null | wc -l)
    local running=$(auditctl -l 2>/dev/null | grep "system-locale" | wc -l)
    
    if [ "$has_hostname" -gt 0 ] && [ "$has_issue" -gt 0 ] && [ "$has_hosts" -gt 0 ] && [ "$running" -gt 0 ]; then
        current="Configured (syscalls and files monitored)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "Network environment changes are audited"
    else
        current="Not configured (hostname: $has_hostname, files: $has_hosts, running: $running)"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "Network environment changes not audited"
        
        if [[ "$MODE" == "fix" ]]; then
            if [ -f "$rules_file" ]; then
                cp "$rules_file" "$BACKUP_DIR/hardening.rules.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
            fi
            
            mkdir -p /etc/audit/rules.d
            
            cat >> "$rules_file" << 'EOF'

## Network environment changes
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale
-w /etc/networks -p wa -k system-locale
EOF
            
            augenrules --load >/dev/null 2>&1
            
            current="Network environment rules added and loaded"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Configured audit rules for network environment changes"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not configured" "$current" "FIXED"
}

check_8_b_d_vi() {
    local policy_id="8.b.d.vi"
    local policy_name="Ensure use of privileged commands are collected"
    local expected="Audit rules for privileged commands"
    ((TOTAL_CHECKS++))

    local current status
    local rules_file="/etc/audit/rules.d/hardening.rules"
    
    # Find all SUID/SGID binaries (privileged commands)
    local priv_count=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | wc -l)
    
    # Check if we have rules for privileged commands
    local has_rules=$(grep -E "^\-a always,exit.*perm_mod" "$rules_file" 2>/dev/null | wc -l)
    local running=$(auditctl -l 2>/dev/null | grep "perm_mod" | wc -l)
    
    if [ "$has_rules" -gt 0 ] && [ "$running" -gt 0 ]; then
        current="Configured (monitoring privileged commands)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "Privileged command usage is audited"
    else
        current="Not configured (found $priv_count privileged commands)"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "Privileged command usage not audited"
        
        if [[ "$MODE" == "fix" ]]; then
            log_manual "=============================================="
            log_manual "MANUAL CONFIGURATION: Privileged Commands"
            log_manual "=============================================="
            log_manual "System has $priv_count SUID/SGID binaries."
            log_manual ""
            log_manual "To audit specific privileged commands:"
            log_manual "1. Find all privileged commands:"
            log_manual "   find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f"
            log_manual ""
            log_manual "2. Add rules to $rules_file:"
            log_manual "   -a always,exit -F path=/path/to/command -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged"
            log_manual ""
            log_manual "3. Reload rules:"
            log_manual "   sudo augenrules --load"
            log_manual ""
            log_manual "NOTE: Too many rules may impact performance."
            log_manual "Focus on critical commands like: sudo, su, passwd, etc."
            log_manual "=============================================="
            current="Manual configuration required"
            status="MANUAL"
            ((MANUAL_CHECKS++))
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "MANUAL" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not configured" "$current" "MANUAL"
}

check_8_b_d_vii() {
    local policy_id="8.b.d.vii"
    local policy_name="Ensure unsuccessful file access attempts are collected"
    local expected="Audit rules for failed file access (EACCES, EPERM)"
    ((TOTAL_CHECKS++))

    local current status
    local rules_file="/etc/audit/rules.d/hardening.rules"
    
    # Check for unsuccessful access rules
    local has_eacces=$(grep -E "exit=-EACCES.*\-k access" "$rules_file" 2>/dev/null | wc -l)
    local has_eperm=$(grep -E "exit=-EPERM.*\-k access" "$rules_file" 2>/dev/null | wc -l)
    local running=$(auditctl -l 2>/dev/null | grep "access" | wc -l)
    
    if [ "$has_eacces" -ge 2 ] && [ "$has_eperm" -ge 2 ] && [ "$running" -gt 0 ]; then
        current="Configured (EACCES and EPERM monitored)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "Unsuccessful file access attempts are audited"
    else
        current="Not configured (EACCES: $has_eacces, EPERM: $has_eperm)"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "Unsuccessful file access attempts not audited"
        
        if [[ "$MODE" == "fix" ]]; then
            if [ -f "$rules_file" ]; then
                cp "$rules_file" "$BACKUP_DIR/hardening.rules.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
            fi
            
            mkdir -p /etc/audit/rules.d
            
            cat >> "$rules_file" << 'EOF'

## Unauthorized file access attempts
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
EOF
            
            augenrules --load >/dev/null 2>&1
            
            current="Unsuccessful access rules added and loaded"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Configured audit rules for unsuccessful file access"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not configured" "$current" "FIXED"
}

check_8_b_d_viii() {
    local policy_id="8.b.d.viii"
    local policy_name="Ensure events that modify user/group information are collected"
    local expected="Audit rules for /etc/passwd, /etc/group, /etc/shadow"
    ((TOTAL_CHECKS++))

    local current status
    local rules_file="/etc/audit/rules.d/hardening.rules"
    
    # Check for user/group file monitoring
    local has_passwd=$(grep -E "/etc/passwd" "$rules_file" 2>/dev/null | grep "identity" | wc -l)
    local has_group=$(grep -E "/etc/group" "$rules_file" 2>/dev/null | grep "identity" | wc -l)
    local has_shadow=$(grep -E "/etc/shadow" "$rules_file" 2>/dev/null | grep "identity" | wc -l)
    local has_gshadow=$(grep -E "/etc/gshadow" "$rules_file" 2>/dev/null | grep "identity" | wc -l)
    local running=$(auditctl -l 2>/dev/null | grep "identity" | wc -l)
    
    if [ "$has_passwd" -gt 0 ] && [ "$has_group" -gt 0 ] && [ "$has_shadow" -gt 0 ] && [ "$running" -gt 0 ]; then
        current="Configured (passwd, group, shadow monitored)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "User/group information changes are audited"
    else
        current="Not configured (passwd: $has_passwd, group: $has_group, shadow: $has_shadow)"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "User/group information changes not audited"
        
        if [[ "$MODE" == "fix" ]]; then
            if [ -f "$rules_file" ]; then
                cp "$rules_file" "$BACKUP_DIR/hardening.rules.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
            fi
            
            mkdir -p /etc/audit/rules.d
            
            cat >> "$rules_file" << 'EOF'

## User/Group information changes
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
EOF
            
            augenrules --load >/dev/null 2>&1
            
            current="User/group information rules added and loaded"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Configured audit rules for user/group information"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not configured" "$current" "FIXED"
}

check_8_b_d_ix() {
    local policy_id="8.b.d.ix"
    local policy_name="Ensure discretionary access control permission modification events are collected"
    local expected="Audit rules for chmod, chown, setxattr"
    ((TOTAL_CHECKS++))

    local current status
    local rules_file="/etc/audit/rules.d/hardening.rules"
    
    # Check for DAC permission modification syscalls
    local has_chmod=$(grep -E "chmod|fchmod|fchmodat" "$rules_file" 2>/dev/null | grep "perm_mod" | wc -l)
    local has_chown=$(grep -E "chown|fchown|lchown" "$rules_file" 2>/dev/null | grep "perm_mod" | wc -l)
    local has_setxattr=$(grep -E "setxattr|lsetxattr|fsetxattr" "$rules_file" 2>/dev/null | grep "perm_mod" | wc -l)
    local running=$(auditctl -l 2>/dev/null | grep "perm_mod" | wc -l)
    
    if [ "$has_chmod" -ge 2 ] && [ "$has_chown" -ge 2 ] && [ "$has_setxattr" -ge 2 ] && [ "$running" -gt 0 ]; then
        current="Configured (chmod, chown, setxattr monitored)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "DAC permission modifications are audited"
    else
        current="Not configured (chmod: $has_chmod, chown: $has_chown, setxattr: $has_setxattr)"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "DAC permission modifications not audited"
        
        if [[ "$MODE" == "fix" ]]; then
            if [ -f "$rules_file" ]; then
                cp "$rules_file" "$BACKUP_DIR/hardening.rules.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
            fi
            
            mkdir -p /etc/audit/rules.d
            
            cat >> "$rules_file" << 'EOF'

## Discretionary Access Control (DAC) modifications
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
EOF
            
            augenrules --load >/dev/null 2>&1
            
            current="DAC permission rules added and loaded"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Configured audit rules for DAC permission modifications"
        fi
    fi
    
    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "not configured" "$current" "FIXED"
}

# ============================================================================
# 8.b.d.x through 8.b.d.xxi - Remaining Audit Rules
# ============================================================================

check_8_b_d_x() {
    local policy_id="8.b.d.x"
    local policy_name="Ensure successful file system mounts are collected"
    local expected="Audit rules for mount syscall"
    ((TOTAL_CHECKS++))

    local current status
    local rules_file="/etc/audit/rules.d/hardening.rules"
    
    local has_b64=$(grep -E "^\-a always,exit.*\-S mount.*\-k mounts" "$rules_file" 2>/dev/null | grep "b64" | wc -l)
    local has_b32=$(grep -E "^\-a always,exit.*\-S mount.*\-k mounts" "$rules_file" 2>/dev/null | grep "b32" | wc -l)
    local running=$(auditctl -l 2>/dev/null | grep "mount" | grep "mounts" | wc -l)
    
    if [ "$has_b64" -gt 0 ] && [ "$has_b32" -gt 0 ] && [ "$running" -gt 0 ]; then
        current="Configured (b64 and b32 mount rules)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "File system mounts are audited"
    else
        current="Not configured (b64: $has_b64, b32: $has_b32)"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "File system mounts not audited"
        
        if [[ "$MODE" == "fix" ]]; then
            if [ -f "$rules_file" ]; then
                cp "$rules_file" "$BACKUP_DIR/hardening.rules.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
            fi
            
            mkdir -p /etc/audit/rules.d
            
            cat >> "$rules_file" << 'EOF'

## Successful file system mounts
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
EOF
            
            augenrules --load >/dev/null 2>&1
            
            current="Mount audit rules added and loaded"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Configured audit rules for file system mounts"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not configured" "$current" "FIXED"
}

check_8_b_d_xi() {
    local policy_id="8.b.d.xi"
    local policy_name="Ensure session initiation information is collected"
    local expected="Audit rules for session files (utmp, wtmp, btmp)"
    ((TOTAL_CHECKS++))

    local current status
    local rules_file="/etc/audit/rules.d/hardening.rules"
    
    local has_utmp=$(grep -E "^\-w /var/run/utmp" "$rules_file" 2>/dev/null | wc -l)
    local has_wtmp=$(grep -E "^\-w /var/log/wtmp" "$rules_file" 2>/dev/null | wc -l)
    local has_btmp=$(grep -E "^\-w /var/log/btmp" "$rules_file" 2>/dev/null | wc -l)
    local running=$(auditctl -l 2>/dev/null | grep -E "utmp|wtmp|btmp" | wc -l)
    
    if [ "$has_utmp" -gt 0 ] && [ "$has_wtmp" -gt 0 ] && [ "$has_btmp" -gt 0 ] && [ "$running" -gt 0 ]; then
        current="Configured (utmp, wtmp, btmp monitored)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "Session initiation is audited"
    else
        current="Not configured (utmp: $has_utmp, wtmp: $has_wtmp, btmp: $has_btmp)"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "Session initiation not audited"
        
        if [[ "$MODE" == "fix" ]]; then
            if [ -f "$rules_file" ]; then
                cp "$rules_file" "$BACKUP_DIR/hardening.rules.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
            fi
            
            mkdir -p /etc/audit/rules.d
            
            cat >> "$rules_file" << 'EOF'

## Session initiation information
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
EOF
            
            augenrules --load >/dev/null 2>&1
            
            current="Session audit rules added and loaded"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Configured audit rules for session initiation"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not configured" "$current" "FIXED"
}

check_8_b_d_xii() {
    local policy_id="8.b.d.xii"
    local policy_name="Ensure login and logout events are collected"
    local expected="Audit rules for login/logout (faillog, lastlog)"
    ((TOTAL_CHECKS++))

    local current status
    local rules_file="/etc/audit/rules.d/hardening.rules"
    
    local has_faillog=$(grep -E "^\-w /var/log/faillog" "$rules_file" 2>/dev/null | wc -l)
    local has_lastlog=$(grep -E "^\-w /var/log/lastlog" "$rules_file" 2>/dev/null | wc -l)
    local running=$(auditctl -l 2>/dev/null | grep -E "faillog|lastlog" | wc -l)
    
    if [ "$has_faillog" -gt 0 ] && [ "$has_lastlog" -gt 0 ] && [ "$running" -gt 0 ]; then
        current="Configured (faillog and lastlog monitored)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "Login/logout events are audited"
    else
        current="Not configured (faillog: $has_faillog, lastlog: $has_lastlog)"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "Login/logout events not audited"
        
        if [[ "$MODE" == "fix" ]]; then
            if [ -f "$rules_file" ]; then
                cp "$rules_file" "$BACKUP_DIR/hardening.rules.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
            fi
            
            mkdir -p /etc/audit/rules.d
            
            cat >> "$rules_file" << 'EOF'

## Login and logout events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
EOF
            
            augenrules --load >/dev/null 2>&1
            
            current="Login/logout audit rules added and loaded"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Configured audit rules for login/logout events"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not configured" "$current" "FIXED"
}

check_8_b_d_xiii() {
    local policy_id="8.b.d.xiii"
    local policy_name="Ensure file deletion events by users are collected"
    local expected="Audit rules for unlink, rename syscalls"
    ((TOTAL_CHECKS++))

    local current status
    local rules_file="/etc/audit/rules.d/hardening.rules"
    
    local has_b64=$(grep -E "^\-a always,exit.*\-S.*unlink.*\-k delete" "$rules_file" 2>/dev/null | grep "b64" | wc -l)
    local has_b32=$(grep -E "^\-a always,exit.*\-S.*unlink.*\-k delete" "$rules_file" 2>/dev/null | grep "b32" | wc -l)
    local running=$(auditctl -l 2>/dev/null | grep "delete" | wc -l)
    
    if [ "$has_b64" -gt 0 ] && [ "$has_b32" -gt 0 ] && [ "$running" -gt 0 ]; then
        current="Configured (unlink/rename monitored)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "File deletion events are audited"
    else
        current="Not configured (b64: $has_b64, b32: $has_b32)"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "File deletion events not audited"
        
        if [[ "$MODE" == "fix" ]]; then
            if [ -f "$rules_file" ]; then
                cp "$rules_file" "$BACKUP_DIR/hardening.rules.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
            fi
            
            mkdir -p /etc/audit/rules.d
            
            cat >> "$rules_file" << 'EOF'

## File deletion events
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
EOF
            
            augenrules --load >/dev/null 2>&1
            
            current="File deletion rules added and loaded"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Configured audit rules for file deletions"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not configured" "$current" "FIXED"
}

check_8_b_d_xiv() {
    local policy_id="8.b.d.xiv"
    local policy_name="Ensure events that modify the system's Mandatory Access Controls are collected"
    local expected="Audit rules for SELinux/AppArmor changes"
    ((TOTAL_CHECKS++))

    local current status
    local rules_file="/etc/audit/rules.d/hardening.rules"
    
    local has_selinux=$(grep -E "^\-w /etc/selinux" "$rules_file" 2>/dev/null | wc -l)
    local has_apparmor=$(grep -E "^\-w /etc/apparmor" "$rules_file" 2>/dev/null | wc -l)
    local running=$(auditctl -l 2>/dev/null | grep "MAC-policy" | wc -l)
    
    if [ "$has_apparmor" -gt 0 ] && [ "$running" -gt 0 ]; then
        current="Configured (MAC policies monitored)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "MAC modification events are audited"
    else
        current="Not configured"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "MAC modification events not audited"
        
        if [[ "$MODE" == "fix" ]]; then
            if [ -f "$rules_file" ]; then
                cp "$rules_file" "$BACKUP_DIR/hardening.rules.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
            fi
            
            mkdir -p /etc/audit/rules.d
            
            cat >> "$rules_file" << 'EOF'

## Mandatory Access Controls (MAC) changes
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/share/selinux/ -p wa -k MAC-policy
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
EOF
            
            augenrules --load >/dev/null 2>&1
            
            current="MAC policy rules added and loaded"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Configured audit rules for MAC modifications"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not configured" "$current" "FIXED"
}

check_8_b_d_xv() {
    local policy_id="8.b.d.xv"
    local policy_name="Ensure successful and unsuccessful attempts to use the chcon command are collected"
    local expected="Audit rules for chcon command"
    ((TOTAL_CHECKS++))

    local current status
    local rules_file="/etc/audit/rules.d/hardening.rules"
    
    local has_b64=$(grep -E "^\-a always,exit.*chcon.*\-k perm_chng" "$rules_file" 2>/dev/null | grep "b64" | wc -l)
    local has_b32=$(grep -E "^\-a always,exit.*chcon.*\-k perm_chng" "$rules_file" 2>/dev/null | grep "b32" | wc -l)
    local running=$(auditctl -l 2>/dev/null | grep "chcon" | wc -l)
    
    if [ "$has_b64" -gt 0 ] && [ "$has_b32" -gt 0 ] && [ "$running" -gt 0 ]; then
        current="Configured (chcon monitored)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "chcon command usage is audited"
    else
        current="Not configured"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "chcon command not audited"
        
        if [[ "$MODE" == "fix" ]]; then
            if [ -f "$rules_file" ]; then
                cp "$rules_file" "$BACKUP_DIR/hardening.rules.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
            fi
            
            mkdir -p /etc/audit/rules.d
            
            cat >> "$rules_file" << 'EOF'

## chcon command attempts
-a always,exit -F arch=b64 -S chmod -F path=/usr/bin/chcon -F auid>=1000 -F auid!=4294967295 -k perm_chng
-a always,exit -F arch=b32 -S chmod -F path=/usr/bin/chcon -F auid>=1000 -F auid!=4294967295 -k perm_chng
EOF
            
            augenrules --load >/dev/null 2>&1
            
            current="chcon audit rules added and loaded"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Configured audit rules for chcon command"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not configured" "$current" "FIXED"
}

check_8_b_d_xvi() {
    local policy_id="8.b.d.xvi"
    local policy_name="Ensure successful and unsuccessful attempts to use the setfacl command are collected"
    local expected="Audit rules for setfacl command"
    ((TOTAL_CHECKS++))

    local current status
    local rules_file="/etc/audit/rules.d/hardening.rules"
    
    local has_b64=$(grep -E "^\-a always,exit.*setfacl.*\-k priv_cmd" "$rules_file" 2>/dev/null | grep "b64" | wc -l)
    local has_b32=$(grep -E "^\-a always,exit.*setfacl.*\-k priv_cmd" "$rules_file" 2>/dev/null | grep "b32" | wc -l)
    local running=$(auditctl -l 2>/dev/null | grep "setfacl" | wc -l)
    
    if [ "$has_b64" -gt 0 ] && [ "$has_b32" -gt 0 ] && [ "$running" -gt 0 ]; then
        current="Configured (setfacl monitored)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "setfacl command usage is audited"
    else
        current="Not configured"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "setfacl command not audited"
        
        if [[ "$MODE" == "fix" ]]; then
            if [ -f "$rules_file" ]; then
                cp "$rules_file" "$BACKUP_DIR/hardening.rules.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
            fi
            
            mkdir -p /etc/audit/rules.d
            
            cat >> "$rules_file" << 'EOF'

## setfacl command attempts
-a always,exit -F arch=b64 -S chmod -F path=/usr/bin/setfacl -F auid>=1000 -F auid!=4294967295 -k priv_cmd
-a always,exit -F arch=b32 -S chmod -F path=/usr/bin/setfacl -F auid>=1000 -F auid!=4294967295 -k priv_cmd
EOF
            
            augenrules --load >/dev/null 2>&1
            
            current="setfacl audit rules added and loaded"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Configured audit rules for setfacl command"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not configured" "$current" "FIXED"
}

check_8_b_d_xvii() {
    local policy_id="8.b.d.xvii"
    local policy_name="Ensure successful and unsuccessful attempts to use the chacl command are collected"
    local expected="Audit rules for chacl command"
    ((TOTAL_CHECKS++))

    local current status
    local rules_file="/etc/audit/rules.d/hardening.rules"
    
    local has_b64=$(grep -E "^\-a always,exit.*chacl.*\-k priv_cmd" "$rules_file" 2>/dev/null | grep "b64" | wc -l)
    local has_b32=$(grep -E "^\-a always,exit.*chacl.*\-k priv_cmd" "$rules_file" 2>/dev/null | grep "b32" | wc -l)
    local running=$(auditctl -l 2>/dev/null | grep "chacl" | wc -l)
    
    if [ "$has_b64" -gt 0 ] && [ "$has_b32" -gt 0 ] && [ "$running" -gt 0 ]; then
        current="Configured (chacl monitored)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "chacl command usage is audited"
    else
        current="Not configured"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "chacl command not audited"
        
        if [[ "$MODE" == "fix" ]]; then
            if [ -f "$rules_file" ]; then
                cp "$rules_file" "$BACKUP_DIR/hardening.rules.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
            fi
            
            mkdir -p /etc/audit/rules.d
            
            cat >> "$rules_file" << 'EOF'

## chacl command attempts
-a always,exit -F arch=b64 -S chmod -F path=/usr/bin/chacl -F auid>=1000 -F auid!=4294967295 -k priv_cmd
-a always,exit -F arch=b32 -S chmod -F path=/usr/bin/chacl -F auid>=1000 -F auid!=4294967295 -k priv_cmd
EOF
            
            augenrules --load >/dev/null 2>&1
            
            current="chacl audit rules added and loaded"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Configured audit rules for chacl command"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not configured" "$current" "FIXED"
}

check_8_b_d_xviii() {
    local policy_id="8.b.d.xviii"
    local policy_name="Ensure successful and unsuccessful attempts to use the usermod command are collected"
    local expected="Audit rules for usermod command"
    ((TOTAL_CHECKS++))

    local current status
    local rules_file="/etc/audit/rules.d/hardening.rules"
    
    local has_b64=$(grep -E "^\-a always,exit.*usermod.*\-k usermod" "$rules_file" 2>/dev/null | grep "b64" | wc -l)
    local has_b32=$(grep -E "^\-a always,exit.*usermod.*\-k usermod" "$rules_file" 2>/dev/null | grep "b32" | wc -l)
    local running=$(auditctl -l 2>/dev/null | grep "usermod" | wc -l)
    
    if [ "$has_b64" -gt 0 ] && [ "$has_b32" -gt 0 ] && [ "$running" -gt 0 ]; then
        current="Configured (usermod monitored)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "usermod command usage is audited"
    else
        current="Not configured"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "usermod command not audited"
        
        if [[ "$MODE" == "fix" ]]; then
            if [ -f "$rules_file" ]; then
                cp "$rules_file" "$BACKUP_DIR/hardening.rules.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
            fi
            
            mkdir -p /etc/audit/rules.d
            
            cat >> "$rules_file" << 'EOF'

## usermod command attempts
-a always,exit -F arch=b64 -S chmod -F path=/usr/sbin/usermod -F auid>=1000 -F auid!=4294967295 -k usermod
-a always,exit -F arch=b32 -S chmod -F path=/usr/sbin/usermod -F auid>=1000 -F auid!=4294967295 -k usermod
EOF
            
            augenrules --load >/dev/null 2>&1
            
            current="usermod audit rules added and loaded"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Configured audit rules for usermod command"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not configured" "$current" "FIXED"
}

check_8_b_d_xix() {
    local policy_id="8.b.d.xix"
    local policy_name="Ensure kernel module loading unloading and modification is collected"
    local expected="Audit rules for kernel module operations"
    ((TOTAL_CHECKS++))

    local current status
    local rules_file="/etc/audit/rules.d/hardening.rules"
    
    local has_insmod=$(grep -E "^\-w /sbin/insmod" "$rules_file" 2>/dev/null | wc -l)
    local has_rmmod=$(grep -E "^\-w /sbin/rmmod" "$rules_file" 2>/dev/null | wc -l)
    local has_modprobe=$(grep -E "^\-w /sbin/modprobe" "$rules_file" 2>/dev/null | wc -l)
    local has_syscalls=$(grep -E "init_module|delete_module" "$rules_file" 2>/dev/null | grep "modules" | wc -l)
    local running=$(auditctl -l 2>/dev/null | grep "modules" | wc -l)
    
    if [ "$has_insmod" -gt 0 ] && [ "$has_rmmod" -gt 0 ] && [ "$has_modprobe" -gt 0 ] && [ "$has_syscalls" -gt 0 ] && [ "$running" -gt 0 ]; then
        current="Configured (all module operations monitored)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "Kernel module operations are audited"
    else
        current="Not configured (insmod: $has_insmod, rmmod: $has_rmmod, modprobe: $has_modprobe)"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "Kernel module operations not audited"
        
        if [[ "$MODE" == "fix" ]]; then
            if [ -f "$rules_file" ]; then
                cp "$rules_file" "$BACKUP_DIR/hardening.rules.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
            fi
            
            mkdir -p /etc/audit/rules.d
            
            cat >> "$rules_file" << 'EOF'

## Kernel module loading and unloading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F arch=b32 -S init_module -S delete_module -k modules
EOF
            
            augenrules --load >/dev/null 2>&1
            
            current="Kernel module rules added and loaded"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Configured audit rules for kernel module operations"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "not configured" "$current" "FIXED"
}
# ============================================================================
# PART 3 - Completing Remaining Audit Checks
# Add this after check_8_b_d_xix() in your existing script
# 8.b.d.xx-xxi, 8.b.e (i-x), 8.b.f (i-iii)
# ============================================================================

check_8_b_d_xx() {
    local policy_id="8.b.d.xx"
    local policy_name="Ensure the audit configuration is immutable"
    local expected="-e 2 in audit rules (immutable)"
    ((TOTAL_CHECKS++))

    local current status
    local rules_file="/etc/audit/rules.d/hardening.rules"
    
    # Check if immutable flag is set
    local has_immutable=$(grep -E "^\-e 2" "$rules_file" 2>/dev/null | wc -l)
    local running=$(auditctl -l 2>/dev/null | grep -E "^enabled" | grep "2" | wc -l)
    
    if [ "$has_immutable" -gt 0 ] && [ "$running" -gt 0 ]; then
        current="Immutable (audit config locked)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "Audit configuration is immutable"
    else
        current="Not immutable"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "Audit configuration is not immutable"
        
        if [[ "$MODE" == "fix" ]]; then
            log_manual "=============================================="
            log_manual "MANUAL CONFIGURATION: Audit Immutability"
            log_manual "=============================================="
            log_manual "Making audit config immutable requires system reboot."
            log_manual ""
            log_manual "WARNING: After adding -e 2, audit rules CANNOT be"
            log_manual "modified until system reboot!"
            log_manual ""
            log_manual "To enable immutability:"
            log_manual "1. Add to end of $rules_file:"
            log_manual "   echo '-e 2' >> $rules_file"
            log_manual ""
            log_manual "2. Reload rules:"
            log_manual "   sudo augenrules --load"
            log_manual ""
            log_manual "3. Verify after reboot:"
            log_manual "   sudo auditctl -l | grep enabled"
            log_manual ""
            log_manual "This prevents runtime changes to audit configuration."
            log_manual "=============================================="
            current="Manual configuration required"
            status="MANUAL"
            ((MANUAL_CHECKS++))
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "MANUAL" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not immutable" "$current" "MANUAL"
}

check_8_b_d_xxi() {
    local policy_id="8.b.d.xxi"
    local policy_name="Ensure the running and on disk configuration is the same"
    local expected="Running audit rules match on-disk rules"
    ((TOTAL_CHECKS++))

    local current status
    
    # Get count of running rules
    local running_count=$(auditctl -l 2>/dev/null | grep -v "^No rules" | grep -v "^AUDIT" | wc -l)
    
    # Get count of on-disk rules
    local disk_count=$(grep -E "^-[aw]" /etc/audit/rules.d/*.rules 2>/dev/null | wc -l)
    
    # Compare if they are similar (allow some variance for system rules)
    local diff=$((running_count - disk_count))
    if [ ${diff#-} -le 5 ]; then
        current="Synchronized (running: $running_count, disk: $disk_count)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "Running and on-disk audit rules are synchronized"
    else
        current="Not synchronized (running: $running_count, disk: $disk_count)"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "Running audit rules don't match on-disk configuration"
        
        if [[ "$MODE" == "fix" ]]; then
            augenrules --load >/dev/null 2>&1
            sleep 2
            local new_running=$(auditctl -l 2>/dev/null | grep -v "^No rules" | grep -v "^AUDIT" | wc -l)
            current="Synchronized after reload (running: $new_running, disk: $disk_count)"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Reloaded audit rules to synchronize"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not synchronized" "$current" "FIXED"
}

# ============================================================================
# 8.b.e Configure auditd File Access
# ============================================================================

check_8_b_e_i() {
    local policy_id="8.b.e.i"
    local policy_name="Ensure audit log files mode is configured"
    local expected="0600 or more restrictive"
    ((TOTAL_CHECKS++))

    local current status
    local log_dir=$(grep "^log_file" /etc/audit/auditd.conf 2>/dev/null | awk '{print $3}' | xargs dirname)
    log_dir="${log_dir:-/var/log/audit}"
    
    if [ -d "$log_dir" ]; then
        local bad_perms=$(find "$log_dir" -type f -name "audit.log*" ! -perm 0600 2>/dev/null | wc -l)
        
        if [ "$bad_perms" -eq 0 ]; then
            current="0600 (properly configured)"
            status="PASS"
            ((PASSED_CHECKS++))
            log_pass "Audit log files have correct permissions"
        else
            current="$bad_perms files with incorrect permissions"
            status="FAIL"
            ((FAILED_CHECKS++))
            log_error "Audit log files have incorrect permissions"
            
            if [[ "$MODE" == "fix" ]]; then
                find "$log_dir" -type f -name "audit.log*" -exec chmod 0600 {} \; 2>/dev/null
                current="Fixed to 0600"
                status="FIXED"
                ((FIXED_CHECKS++))
                log_fixed "Fixed audit log file permissions to 0600"
            fi
        fi
    else
        current="Audit log directory not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Incorrect permissions" "$current" "FIXED"
}

check_8_b_e_ii() {
    local policy_id="8.b.e.ii"
    local policy_name="Ensure audit log files owner is configured"
    local expected="Owner: root"
    ((TOTAL_CHECKS++))

    local current status
    local log_dir=$(grep "^log_file" /etc/audit/auditd.conf 2>/dev/null | awk '{print $3}' | xargs dirname)
    log_dir="${log_dir:-/var/log/audit}"
    
    if [ -d "$log_dir" ]; then
        local bad_owner=$(find "$log_dir" -type f -name "audit.log*" ! -user root 2>/dev/null | wc -l)
        
        if [ "$bad_owner" -eq 0 ]; then
            current="root (properly configured)"
            status="PASS"
            ((PASSED_CHECKS++))
            log_pass "Audit log files owned by root"
        else
            current="$bad_owner files with incorrect owner"
            status="FAIL"
            ((FAILED_CHECKS++))
            log_error "Audit log files not owned by root"
            
            if [[ "$MODE" == "fix" ]]; then
                find "$log_dir" -type f -name "audit.log*" -exec chown root {} \; 2>/dev/null
                current="Fixed to root"
                status="FIXED"
                ((FIXED_CHECKS++))
                log_fixed "Fixed audit log file ownership to root"
            fi
        fi
    else
        current="Audit log directory not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Incorrect owner" "$current" "FIXED"
}

check_8_b_e_iii() {
    local policy_id="8.b.e.iii"
    local policy_name="Ensure audit log files group owner is configured"
    local expected="Group: root"
    ((TOTAL_CHECKS++))

    local current status
    local log_dir=$(grep "^log_file" /etc/audit/auditd.conf 2>/dev/null | awk '{print $3}' | xargs dirname)
    log_dir="${log_dir:-/var/log/audit}"
    
    if [ -d "$log_dir" ]; then
        local bad_group=$(find "$log_dir" -type f -name "audit.log*" ! -group root 2>/dev/null | wc -l)
        
        if [ "$bad_group" -eq 0 ]; then
            current="root (properly configured)"
            status="PASS"
            ((PASSED_CHECKS++))
            log_pass "Audit log files group owned by root"
        else
            current="$bad_group files with incorrect group"
            status="FAIL"
            ((FAILED_CHECKS++))
            log_error "Audit log files not group owned by root"
            
            if [[ "$MODE" == "fix" ]]; then
                find "$log_dir" -type f -name "audit.log*" -exec chgrp root {} \; 2>/dev/null
                current="Fixed to root"
                status="FIXED"
                ((FIXED_CHECKS++))
                log_fixed "Fixed audit log file group ownership to root"
            fi
        fi
    else
        current="Audit log directory not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Incorrect group" "$current" "FIXED"
}

check_8_b_e_iv() {
    local policy_id="8.b.e.iv"
    local policy_name="Ensure the audit log file directory mode is configured"
    local expected="0750 or more restrictive"
    ((TOTAL_CHECKS++))

    local current status
    local log_dir=$(grep "^log_file" /etc/audit/auditd.conf 2>/dev/null | awk '{print $3}' | xargs dirname)
    log_dir="${log_dir:-/var/log/audit}"
    
    if [ -d "$log_dir" ]; then
        local dir_perms=$(stat -c "%a" "$log_dir" 2>/dev/null)
        
        # Check if permissions are 0750 or more restrictive (no world/group write)
        if [ "$dir_perms" = "750" ] || [ "$dir_perms" = "700" ]; then
            current="$dir_perms (properly configured)"
            status="PASS"
            ((PASSED_CHECKS++))
            log_pass "Audit log directory has correct permissions"
        else
            current="$dir_perms (too permissive)"
            status="FAIL"
            ((FAILED_CHECKS++))
            log_error "Audit log directory permissions too permissive"
            
            if [[ "$MODE" == "fix" ]]; then
                chmod 0750 "$log_dir" 2>/dev/null
                current="0750 (fixed)"
                status="FIXED"
                ((FIXED_CHECKS++))
                log_fixed "Fixed audit log directory permissions to 0750"
            fi
        fi
    else
        current="Audit log directory not found"
        status="FAIL"
        ((FAILED_CHECKS++))
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "$dir_perms" "$current" "FIXED"
}

check_8_b_e_v() {
    local policy_id="8.b.e.v"
    local policy_name="Ensure audit configuration files mode is configured"
    local expected="0640 or more restrictive"
    ((TOTAL_CHECKS++))

    local current status
    local bad_perms=$(find /etc/audit -type f \( -name "*.conf" -o -name "*.rules" \) ! -perm 0640 ! -perm 0600 2>/dev/null | wc -l)
    
    if [ "$bad_perms" -eq 0 ]; then
        current="0640 or more restrictive (properly configured)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "Audit configuration files have correct permissions"
    else
        current="$bad_perms files with incorrect permissions"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "Audit configuration files have incorrect permissions"
        
        if [[ "$MODE" == "fix" ]]; then
            find /etc/audit -type f \( -name "*.conf" -o -name "*.rules" \) -exec chmod 0640 {} \; 2>/dev/null
            current="Fixed to 0640"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Fixed audit configuration file permissions to 0640"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Incorrect permissions" "$current" "FIXED"
}

check_8_b_e_vi() {
    local policy_id="8.b.e.vi"
    local policy_name="Ensure audit configuration files owner is configured"
    local expected="Owner: root"
    ((TOTAL_CHECKS++))

    local current status
    local bad_owner=$(find /etc/audit -type f \( -name "*.conf" -o -name "*.rules" \) ! -user root 2>/dev/null | wc -l)
    
    if [ "$bad_owner" -eq 0 ]; then
        current="root (properly configured)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "Audit configuration files owned by root"
    else
        current="$bad_owner files with incorrect owner"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "Audit configuration files not owned by root"
        
        if [[ "$MODE" == "fix" ]]; then
            find /etc/audit -type f \( -name "*.conf" -o -name "*.rules" \) -exec chown root {} \; 2>/dev/null
            current="Fixed to root"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Fixed audit configuration file ownership to root"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Incorrect owner" "$current" "FIXED"
}

check_8_b_e_vii() {
    local policy_id="8.b.e.vii"
    local policy_name="Ensure audit configuration files group owner is configured"
    local expected="Group: root"
    ((TOTAL_CHECKS++))

    local current status
    local bad_group=$(find /etc/audit -type f \( -name "*.conf" -o -name "*.rules" \) ! -group root 2>/dev/null | wc -l)
    
    if [ "$bad_group" -eq 0 ]; then
        current="root (properly configured)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "Audit configuration files group owned by root"
    else
        current="$bad_group files with incorrect group"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "Audit configuration files not group owned by root"
        
        if [[ "$MODE" == "fix" ]]; then
            find /etc/audit -type f \( -name "*.conf" -o -name "*.rules" \) -exec chgrp root {} \; 2>/dev/null
            current="Fixed to root"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Fixed audit configuration file group ownership to root"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Incorrect group" "$current" "FIXED"
}

check_8_b_e_viii() {
    local policy_id="8.b.e.viii"
    local policy_name="Ensure audit tools mode is configured"
    local expected="0755 or more restrictive"
    ((TOTAL_CHECKS++))

    local current status
    local tools=("/sbin/auditctl" "/sbin/aureport" "/sbin/ausearch" "/sbin/autrace" "/sbin/auditd" "/sbin/augenrules")
    local bad_perms=0
    
    for tool in "${tools[@]}"; do
        if [ -f "$tool" ]; then
            local perms=$(stat -c "%a" "$tool" 2>/dev/null)
            if [ "$perms" != "755" ] && [ "$perms" != "750" ] && [ "$perms" != "700" ]; then
                ((bad_perms++))
            fi
        fi
    done
    
    if [ "$bad_perms" -eq 0 ]; then
        current="0755 or more restrictive (properly configured)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "Audit tools have correct permissions"
    else
        current="$bad_perms tools with incorrect permissions"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "Audit tools have incorrect permissions"
        
        if [[ "$MODE" == "fix" ]]; then
            for tool in "${tools[@]}"; do
                if [ -f "$tool" ]; then
                    chmod 0755 "$tool" 2>/dev/null
                fi
            done
            current="Fixed to 0755"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Fixed audit tools permissions to 0755"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Incorrect permissions" "$current" "FIXED"
}

check_8_b_e_ix() {
    local policy_id="8.b.e.ix"
    local policy_name="Ensure audit tools owner is configured"
    local expected="Owner: root"
    ((TOTAL_CHECKS++))

    local current status
    local tools=("/sbin/auditctl" "/sbin/aureport" "/sbin/ausearch" "/sbin/autrace" "/sbin/auditd" "/sbin/augenrules")
    local bad_owner=0
    
    for tool in "${tools[@]}"; do
        if [ -f "$tool" ]; then
            local owner=$(stat -c "%U" "$tool" 2>/dev/null)
            if [ "$owner" != "root" ]; then
                ((bad_owner++))
            fi
        fi
    done
    
    if [ "$bad_owner" -eq 0 ]; then
        current="root (properly configured)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "Audit tools owned by root"
    else
        current="$bad_owner tools with incorrect owner"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "Audit tools not owned by root"
        
        if [[ "$MODE" == "fix" ]]; then
            for tool in "${tools[@]}"; do
                if [ -f "$tool" ]; then
                    chown root "$tool" 2>/dev/null
                fi
            done
            current="Fixed to root"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Fixed audit tools ownership to root"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Incorrect owner" "$current" "FIXED"
}

check_8_b_e_x() {
    local policy_id="8.b.e.x"
    local policy_name="Ensure audit tools group owner is configured"
    local expected="Group: root"
    ((TOTAL_CHECKS++))

    local current status
    local tools=("/sbin/auditctl" "/sbin/aureport" "/sbin/ausearch" "/sbin/autrace" "/sbin/auditd" "/sbin/augenrules")
    local bad_group=0
    
    for tool in "${tools[@]}"; do
        if [ -f "$tool" ]; then
            local group=$(stat -c "%G" "$tool" 2>/dev/null)
            if [ "$group" != "root" ]; then
                ((bad_group++))
            fi
        fi
    done
    
    if [ "$bad_group" -eq 0 ]; then
        current="root (properly configured)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "Audit tools group owned by root"
    else
        current="$bad_group tools with incorrect group"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "Audit tools not group owned by root"
        
        if [[ "$MODE" == "fix" ]]; then
            for tool in "${tools[@]}"; do
                if [ -f "$tool" ]; then
                    chgrp root "$tool" 2>/dev/null
                fi
            done
            current="Fixed to root"
            status="FIXED"
            ((FIXED_CHECKS++))
            log_fixed "Fixed audit tools group ownership to root"
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Incorrect group" "$current" "FIXED"
}

# ============================================================================
# 8.b.f Configure Integrity Checking
# ============================================================================

check_8_b_f_i() {
    local policy_id="8.b.f.i"
    local policy_name="Ensure AIDE is installed"
    local expected="AIDE installed"
    ((TOTAL_CHECKS++))

    local current status
    if dpkg -l | grep -q "^ii.*aide\s"; then
        current="Installed"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "AIDE is installed"
    else
        current="Not installed"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "AIDE is not installed"
        
        if [[ "$MODE" == "fix" ]]; then
            apt-get update -y >/dev/null 2>&1
            apt-get install -y aide aide-common >/dev/null 2>&1
            
            if dpkg -l | grep -q "^ii.*aide\s"; then
                log_info "Initializing AIDE database (this may take several minutes)..."
                aideinit >/dev/null 2>&1
                
                if [ -f /var/lib/aide/aide.db.new ]; then
                    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null
                    current="Installed and initialized"
                    status="FIXED"
                    ((FIXED_CHECKS++))
                    log_fixed "Installed and initialized AIDE"
                else
                    current="Installed but initialization failed"
                    status="MANUAL"
                    ((MANUAL_CHECKS++))
                    log_manual "AIDE installed but needs manual initialization: sudo aideinit"
                fi
            else
                current="Installation failed"
                status="FAIL"
                log_error "Failed to install AIDE"
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not installed" "$current" "$status"
}

check_8_b_f_ii() {
    local policy_id="8.b.f.ii"
    local policy_name="Ensure filesystem integrity is regularly checked"
    local expected="AIDE check scheduled (cron/systemd)"
    ((TOTAL_CHECKS++))

    local current status
    
    # Check for cron job
    local has_cron=$(grep -r "aide" /etc/cron* /etc/crontab 2>/dev/null | grep -v "^#" | wc -l)
    
    # Check for systemd timer
    local has_timer=0
    if systemctl list-timers 2>/dev/null | grep -q "aide"; then
        has_timer=1
    fi
    
    if [ "$has_cron" -gt 0 ] || [ "$has_timer" -gt 0 ]; then
        current="Scheduled (cron: $has_cron, timer: $has_timer)"
        status="PASS"
        ((PASSED_CHECKS++))
        log_pass "AIDE filesystem integrity checks are scheduled"
    else
        current="Not scheduled"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "AIDE filesystem integrity checks not scheduled"
        
        if [[ "$MODE" == "fix" ]]; then
            if ! command -v aide >/dev/null 2>&1; then
                log_warn "AIDE not installed, skipping cron configuration"
                current="AIDE not installed"
                status="FAIL"
            else
                # Create daily cron job
                cat > /etc/cron.daily/aide << 'EOFAIDE'
#!/bin/bash
# AIDE filesystem integrity check
/usr/bin/aide --check | mail -s "AIDE Integrity Check" root
EOFAIDE
                chmod 0755 /etc/cron.daily/aide 2>/dev/null
                
                current="Scheduled (daily cron job created)"
                status="FIXED"
                ((FIXED_CHECKS++))
                log_fixed "Created daily AIDE integrity check cron job"
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not scheduled" "$current" "FIXED"
}

check_8_b_f_iii() {
    local policy_id="8.b.f.iii"
    local policy_name="Ensure cryptographic mechanisms are used to protect the integrity of audit tools"
    local expected="AIDE configured to monitor audit tools"
    ((TOTAL_CHECKS++))

    local current status
    
    if ! command -v aide >/dev/null 2>&1; then
        current="AIDE not installed"
        status="FAIL"
        ((FAILED_CHECKS++))
        log_error "AIDE not installed - cannot protect audit tools"
    else
        # Check if audit tools are in AIDE configuration
        local aide_conf="/etc/aide/aide.conf"
        local has_audit_tools=$(grep -E "/sbin/audit" "$aide_conf" 2>/dev/null | grep -v "^#" | wc -l)
        
        if [ "$has_audit_tools" -gt 0 ]; then
            current="Configured (audit tools monitored by AIDE)"
            status="PASS"
            ((PASSED_CHECKS++))
            log_pass "AIDE configured to monitor audit tools"
        else
            current="Not configured"
            status="FAIL"
            ((FAILED_CHECKS++))
            log_error "AIDE not configured to monitor audit tools"
            
            if [[ "$MODE" == "fix" ]]; then
                if [ -f "$aide_conf" ]; then
                    cp "$aide_conf" "$BACKUP_DIR/aide.conf.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
                    
                    # Add audit tools monitoring to AIDE config
                    cat >> "$aide_conf" << 'EOFAIDE'

# Audit Tools Integrity
/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512
EOFAIDE
                    
                    # Update AIDE database
                    log_info "Updating AIDE database (this may take time)..."
                    aide --update >/dev/null 2>&1
                    
                    if [ -f /var/lib/aide/aide.db.new ]; then
                        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null
                    fi
                    
                    current="Configured and database updated"
                    status="FIXED"
                    ((FIXED_CHECKS++))
                    log_fixed "Configured AIDE to monitor audit tools"
                else
                    current="AIDE config file not found"
                    status="FAIL"
                fi
            fi
        fi
    fi

    print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "scan" ]] && save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    [[ "$MODE" == "fix" && "$status" == "FIXED" ]] && save_fix_result "$policy_id" "$policy_name" "$expected" "Not configured" "$current" "FIXED"
}

# ============================================================================
# Main Execution Function - Add to your existing main() function
# ============================================================================

run_all_checks() {
    echo "=============================================="
    echo "Logging and Auditing Hardening - Part 3"
    echo "Mode: $MODE"
    echo "=============================================="
    echo ""

    # Run Part 3 checks
    check_8_b_d_xx
    check_8_b_d_xxi
    
    # 8.b.e - Configure auditd File Access
    check_8_b_e_i
    check_8_b_e_ii
    check_8_b_e_iii
    check_8_b_e_iv
    check_8_b_e_v
    check_8_b_e_vi
    check_8_b_e_vii
    check_8_b_e_viii
    check_8_b_e_ix
    check_8_b_e_x
    
    # 8.b.f - Configure Integrity Checking
    check_8_b_f_i
    check_8_b_f_ii
    check_8_b_f_iii
}

# ============================================================================
# Summary Report
# ============================================================================

print_summary() {
    echo ""
    echo "=============================================="
    echo "LOGGING AND AUDITING HARDENING SUMMARY"
    echo "=============================================="
    echo -e "Total Checks    : $TOTAL_CHECKS"
    echo -e "${GREEN}Passed Checks${NC}   : $PASSED_CHECKS"
    echo -e "${RED}Failed Checks${NC}   : $FAILED_CHECKS"
    echo -e "${BLUE}Fixed Checks${NC}    : $FIXED_CHECKS"
    echo -e "${YELLOW}Manual Checks${NC}   : $MANUAL_CHECKS"
    echo "=============================================="
    
    if [ "$MANUAL_CHECKS" -gt 0 ]; then
        echo ""
        echo -e "${YELLOW}ATTENTION:${NC} $MANUAL_CHECKS checks require manual intervention."
        echo "Review the MANUAL messages above for instructions."
    fi
    
    if [ "$FAILED_CHECKS" -gt 0 ] && [ "$MODE" == "scan" ]; then
        echo ""
        echo -e "${YELLOW}TIP:${NC} Run with 'fix' mode to automatically fix issues:"
        echo "  sudo $0 fix"
    fi
    echo ""
}

# ============================================================================
# Execute if run as main script
# ============================================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Check for root
    if [ "$EUID" -ne 0 ]; then
        echo "Please run as root or with sudo"
        exit 1
    fi
    
    init_database
    run_all_checks
    print_summary
fi
