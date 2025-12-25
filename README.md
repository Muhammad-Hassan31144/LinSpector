<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue?style=for-the-badge" alt="Version">
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
git clone https://github.com/yourusername/Linspector.git
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
