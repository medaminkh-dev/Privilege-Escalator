# Privilege Escalation Analyzer v4.0

A comprehensive Linux privilege escalation assessment framework for authorized security testing and vulnerability research.

## Overview

**Privilege Escalation Analyzer** is a professional security testing tool designed to identify and assess potential privilege escalation vulnerabilities in Linux systems. It performs deep system analysis, detects misconfigurations, and evaluates known CVE exploits.

### Key Features

- **35+ CVE Detection**: Identifies known kernel vulnerabilities (2017-2025)
- **24 Security Plugins**: Modular exploit detection and analysis
- **Multi-Format Reporting**: HTML, JSON, Markdown, and CSV reports
- **Ghost Mode**: Anti-forensics and cleanup capabilities
- **Intelligent Analysis**: Automatic vulnerability assessment and chaining
- **Cross-Platform Support**: Linux, WSL, and compatible Unix systems

## Installation

### Prerequisites

```bash
# Required utilities
sudo apt-get install -y curl wget grep sed awk find

# Optional but recommended
sudo apt-get install -y gcc make python3 nikto
```

### Setup

```bash
# Clone or download the tool
git clone https://github.com/medaminkh-dev/Privilege-Escalator.git
cd Privilege-Escalator

# Make executable
chmod +x privesc_analyzer.sh

# (Optional) Install globally
sudo cp privesc_analyzer.sh /usr/local/bin/Privilege-Escalator
```

## Usage

### Basic Execution

```bash
# Standard scan
./privesc_analyzer.sh

# With timeout (recommended)
timeout 60 ./privesc_analyzer.sh

# Verbose output
./privesc_analyzer.sh -v
```

### Command Options

```bash
# Show help
./privesc_analyzer.sh -h

# Enable ghost mode (cleanup traces)
./privesc_analyzer.sh --ghost

# Custom report directory
./privesc_analyzer.sh --output /path/to/reports

# Quiet mode (minimal output)
./privesc_analyzer.sh -q
```

### Output

The tool generates reports in multiple formats:

```
/tmp/.peu_reports_[TIMESTAMP]/
├── privesc_report_[TIMESTAMP].html      # Interactive HTML report
├── privesc_report_[TIMESTAMP].json      # Machine-readable JSON
├── privesc_report_[TIMESTAMP].md        # Markdown documentation
└── privesc_report_[TIMESTAMP].csv       # CSV data export
```

## Understanding the Analysis

### Scanning Phases

The analyzer performs 10 sequential assessment phases:

| Phase | Description |
|-------|-------------|
| 1 | System Enumeration (OS, kernel, user context) |
| 2 | SUID/SGID Binary Analysis |
| 3 | Capability Analysis |
| 4 | Cron Job Enumeration |
| 5 | Writable File Detection |
| 6 | Service Configuration Review |
| 7 | Docker/Container Escape Assessment |
| 8 | Network Configuration Analysis |
| 9 | Credential Discovery |
| 10 | Report Generation |

### Vulnerability Categories

#### Critical (Immediate Action Required)
- Kernel exploits with high success rates
- Unsafe sudo configurations
- World-writable SUID binaries

#### High (Priority)
- Misconfigured capabilities
- Insecure container configurations
- Unencrypted credentials

#### Medium (Review)
- Non-standard service permissions
- Potential capability abuse
- Credential storage issues

#### Low (Monitor)
- Informational findings
- Configuration notes
- Best practice recommendations

### CVE Detection

The analyzer identifies vulnerabilities including:

- **Kernel Exploits**: CVE-2024-1086, CVE-2022-0492, CVE-2022-25636
- **Sudo Issues**: CVE-2019-14287, CVE-2019-18634
- **eBPF/Netfilter**: CVE-2022-0185, CVE-2017-16995
- **Container Escape**: CVE-2019-13272, CVE-2017-1000112
- **Dirty COW**: CVE-2016-5195
- **DirtyCow**: CVE-2020-14386

## Case Studies

### Case Study 1: Misconfigured Sudo

**Scenario**: A system administrator grants sudo access without proper restrictions.

```bash
# Analysis Output
[+] CRITICAL: User 'kali' can run /bin/bash with NOPASSWD
    Impact: Full root privilege escalation
    Remediation: Remove NOPASSWD or restrict binaries
```

**Exploitation Path**:
```bash
sudo /bin/bash          # Instant root access
```

**Prevention**:
- Use password requirement for sudo
- Restrict allowed commands with sudoedit
- Monitor sudo logs for unauthorized use

---

### Case Study 2: SUID Binary Vulnerability

**Scenario**: A vulnerable SUID binary with known exploit.

```bash
# Analysis Output
[+] SUID Binary: /usr/bin/vulnerable_app (4755)
    Known CVE: CVE-2024-XXXXX
    Exploitation: Possible through race condition
```

**Fix**:
```bash
# Remove SUID bit or update application
sudo chmod u-s /usr/bin/vulnerable_app
# OR
sudo apt-get update && sudo apt-get upgrade vulnerable-app
```

---

### Case Study 3: Writable System Files

**Scenario**: System files are world-writable, allowing modification.

```bash
# Analysis Output
[!] WRITABLE: /etc/ld.so.preload
    Risk: LD_PRELOAD privilege escalation
    Recommendation: chmod 644 /etc/ld.so.preload
```

**Attack Chain**:
1. Write malicious library to writable path
2. Set LD_PRELOAD to point to library
3. Execute any system binary
4. Gain root privileges via library functions

**Mitigation**:
```bash
# Proper permissions
sudo chmod 644 /etc/ld.so.preload
sudo chown root:root /etc/ld.so.preload
```

---

### Case Study 4: Kernel CVE Exploitation

**Scenario**: System running outdated kernel with known exploits.

```bash
# Analysis Output
[+] CRITICAL: Kernel 5.10.0 vulnerable to CVE-2024-1086
    Type: eBPF Map Local Privilege Escalation
    Success Rate: High (95%)
    Remediation: Update kernel to 5.15.0 or later
```

**Remediation Steps**:
```bash
# Check current kernel
uname -r

# Update system
sudo apt-get update && sudo apt-get upgrade

# Optionally build new kernel
sudo apt-get install linux-image-generic linux-headers-generic
```

---

### Case Study 5: Docker Escape

**Scenario**: User in docker group without proper restrictions.

```bash
# Analysis Output
[+] HIGH: User 'dev' in docker group
    Risk: Docker socket access allows container escape
    Impact: Full system compromise
```

**Attack Vector**:
```bash
docker run -v /:/rootfs -it alpine
# Mount root filesystem and modify /etc/passwd
```

**Prevention**:
```bash
# Remove user from docker group
sudo delgroup dev docker

# OR restrict docker socket
sudo chmod 660 /var/run/docker.sock
sudo chown root:docker /var/run/docker.sock
```

## Report Interpretation

### HTML Report

The HTML report provides an interactive dashboard with:
- System overview and risk summary
- Detailed vulnerability breakdown
- Executive findings chart
- Remediation recommendations

**Access**: Open in any web browser
```bash
firefox /tmp/.peu_reports_*/privesc_report_*.html
```

### JSON Report

Machine-readable format for integration with other tools:

```json
{
  "metadata": {
    "scan_time": "2026-02-03T20:04:40Z",
    "hostname": "kali",
    "kernel": "6.12.38+kali-amd64"
  },
  "findings": [
    {
      "severity": "CRITICAL",
      "type": "SUID_BINARY",
      "description": "Vulnerable SUID binary detected"
    }
  ]
}
```

### CSV Report

For spreadsheet analysis and tracking:

```
Severity,Type,Description,Location,Remediation
CRITICAL,SUID_BINARY,Vulnerable binary,/usr/bin/app,Remove SUID bit
HIGH,SUDO_CONFIG,No password required,kali ALL=(ALL) NOPASSWD,Require password
```

## Remediation Guide

### Priority Matrix

```
┌─────────────────────────────────────┐
│    CRITICALITY vs DIFFICULTY        │
├─────────────────────────────────────┤
│ Quick Wins (High Impact/Easy)       │
│ - Fix sudo configurations           │
│ - Change file permissions           │
│                                     │
│ Strategic (High Impact/Hard)        │
│ - Kernel patching                   │
│ - Application updates               │
│                                     │
│ Low Priority (Low Impact/Easy)      │
│ - Documentation updates             │
│ - Monitoring improvements           │
└─────────────────────────────────────┘
```

### Common Fixes

#### 1. Fix Unsafe Sudo Configuration
```bash
# Remove NOPASSWD
sudo visudo  # Edit and remove NOPASSWD entries

# Restrict commands
# Instead of: kali ALL=(ALL) ALL
# Use: kali ALL=(ALL) /bin/ls, /bin/cat
```

#### 2. Remove SUID from Unsafe Binaries
```bash
sudo find / -perm -4000 -type f 2>/dev/null | while read bin; do
    # Review each binary
    ls -la "$bin"
done

# Remove SUID if unnecessary
sudo chmod u-s /path/to/binary
```

#### 3. Fix World-Writable System Files
```bash
# Find problematic permissions
find /etc /usr/bin /usr/sbin -perm -002 -type f 2>/dev/null

# Fix permissions
sudo chmod o-w /path/to/file
```

#### 4. System Hardening
```bash
# Kernel parameter hardening (sysctl)
sudo sysctl kernel.unprivileged_userns_clone=0
sudo sysctl kernel.unprivileged_bpf_disabled=1

# Make permanent
echo "kernel.unprivileged_userns_clone=0" | sudo tee -a /etc/sysctl.conf
```

## Disclaimer & Legal

### Authorization Required

This tool is designed for **authorized security testing only**. Unauthorized access to computer systems is illegal.

**Required Conditions**:
- ✅ Written authorization from system owner
- ✅ Scope clearly defined
- ✅ Testing performed on systems you own or have permission to test
- ✅ All activities documented and reported

### Prohibited Uses

- ❌ Unauthorized system access
- ❌ Privilege escalation without permission
- ❌ Data theft or modification
- ❌ Denial of service attacks
- ❌ Reverse engineering without license

### Liability

The authors and maintainers are **NOT responsible** for:
- Misuse of this tool
- Unauthorized system access
- Data loss or corruption
- Any legal consequences

Users assume all responsibility for their actions.

## Troubleshooting

### Script Hangs on Execution

**Problem**: Script appears to freeze during enumeration.

**Solution**:
```bash
# Use timeout to limit execution
timeout 60 ./privesc_analyzer.sh

# Or press Ctrl+C to interrupt
```

### Permission Denied Errors

**Problem**: Script cannot read certain system files.

**Solution**:
```bash
# Run with elevated privileges
sudo ./privesc_analyzer.sh

# Note: Some findings require root access
```

### Reports Not Generated

**Problem**: No report files created.

**Solution**:
```bash
# Check /tmp directory
ls -la /tmp/.peu_reports_*/

# Verify disk space
df -h /tmp

# Check script permissions
chmod +x privesc_analyzer.sh
```

## Output Examples

### Execution Summary

```
[+] Duration: 23s
[+] Plugins Loaded: 24
[+] Critical Findings: 42
[+] Total Findings: 168
[+] Vulnerabilities Found: 42
[+] Exploits Attempted: 0
[+] Exploits Successful: 0
```

### System Information

```
[+] Operating System:
    Type                : linux
    Distribution        : Kali GNU/Linux
    Version             : 2025.3
    Kernel              : 6.12.38+kali-amd64
    Architecture        : x86_64

[+] User Context:
    Username            : kali
    UID/GID             : 1000/1000
    Groups              : kali,adm,dialout,sudo,...
    Home Directory      : /home/kali
```

## Best Practices

### For Security Teams
- Schedule regular assessments
- Track remediation progress
- Establish baselines
- Document all findings
- Keep tool updated

### For System Administrators
- Run on test systems first
- Review findings carefully
- Create remediation plans
- Implement fixes systematically
- Verify fixes are effective

### For Penetration Testers
- Always obtain authorization
- Keep detailed logs
- Report findings professionally
- Provide remediation guidance
- Follow responsible disclosure

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed description
4. Ensure code follows project standards

## License

MIT License - See LICENSE file for details

## Authors

- Security Research Team

---

**⚠️ FOR AUTHORIZED SECURITY TESTING ONLY ⚠️**

This tool is provided for defensive security assessment. Ensure you have explicit authorization before testing any systems.

**Last Updated**: February 3, 2026  
**Version**: 4.0.0
