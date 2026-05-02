#!/bin/bash
# ================================================================
# LIVE OS FORENSIC AGENT v5.0
# Academic Forensics Project — Evidence Collection Tool
# Usage: sudo bash agent.sh --consent [--server http://IP:5000]
# ================================================================

VERSION="5.0"
SCRIPT_NAME="Live OS Forensic Agent"

# ── Colours ──────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

# ── Defaults ─────────────────────────────────────────────────────
CONSENT=false
C2_SERVER=""
OUTPUT_DIR="./forensic-evidence"
REPORT_FILE=""
UPLOAD=false

# ── Argument parsing ─────────────────────────────────────────────
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --consent)       CONSENT=true ;;
        --server)        C2_SERVER="$2"; UPLOAD=true; shift ;;
        --output)        OUTPUT_DIR="$2"; shift ;;
        --help|-h)
            echo -e "${CYAN}${BOLD}$SCRIPT_NAME v$VERSION${NC}"
            echo ""
            echo "  Usage: sudo bash agent.sh --consent [OPTIONS]"
            echo ""
            echo "  Options:"
            echo "    --consent            Required: explicit consent to collect evidence"
            echo "    --server <URL>       Optional: C2 dashboard URL (e.g. http://192.168.1.10:5000)"
            echo "    --output <dir>       Output directory (default: ./forensic-evidence)"
            echo "    --help               Show this help"
            echo ""
            echo "  Example:"
            echo "    sudo bash agent.sh --consent --server http://192.168.153.1:5000"
            exit 0 ;;
        *) echo -e "${RED}Unknown option: $1${NC}"; exit 1 ;;
    esac
    shift
done

# ── Must have --consent ───────────────────────────────────────────
if [ "$CONSENT" != true ]; then
    echo ""
    echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}${BOLD}║         CONSENT REQUIRED — CANNOT PROCEED                ║${NC}"
    echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}This tool collects system evidence from the current machine.${NC}"
    echo -e "${YELLOW}It must only be run on systems you own or have permission to analyse.${NC}"
    echo ""
    echo -e "  Re-run with: ${CYAN}sudo bash agent.sh --consent${NC}"
    echo ""
    exit 1
fi

# ── Root check ───────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}[WARN] Not running as root — some artifacts may be unavailable.${NC}"
    echo -e "${YELLOW}       For full evidence, use: sudo bash agent.sh --consent${NC}"
    echo ""
fi

# ── Banner ───────────────────────────────────────────────────────
clear
echo ""
echo -e "${CYAN}${BOLD}"
echo "  ██╗     ██╗██╗   ██╗███████╗      ██████╗ ███████╗"
echo "  ██║     ██║██║   ██║██╔════╝     ██╔═══██╗██╔════╝"
echo "  ██║     ██║██║   ██║█████╗       ██║   ██║███████╗"
echo "  ██║     ██║╚██╗ ██╔╝██╔══╝       ██║   ██║╚════██║"
echo "  ███████╗██║ ╚████╔╝ ███████╗     ╚██████╔╝███████║"
echo "  ╚══════╝╚═╝  ╚═══╝  ╚══════╝      ╚═════╝ ╚══════╝"
echo -e "${NC}"
echo -e "  ${BOLD}FORENSIC EVIDENCE COLLECTOR${NC}  ${BLUE}v$VERSION${NC}"
echo -e "  ${YELLOW}Academic Project — Authorised Use Only${NC}"
echo ""
echo -e "  ${GREEN}✔ Consent confirmed${NC}"
[ -n "$C2_SERVER" ] && echo -e "  ${GREEN}✔ Server: $C2_SERVER${NC}"
echo ""

# ── Setup output directory ────────────────────────────────────────
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16 2>/dev/null || echo "$(date +%s)-$$")
SESSION_DIR="$OUTPUT_DIR/session_${TIMESTAMP}"
mkdir -p "$SESSION_DIR"
REPORT_FILE="$SESSION_DIR/evidence_${TIMESTAMP}.json"
LOG_FILE="$SESSION_DIR/collection.log"

log() { echo "[$(date +%H:%M:%S)] $*" >> "$LOG_FILE"; }
step() { echo -e "  ${CYAN}▸${NC} $*"; log "STEP: $*"; }
ok()   { echo -e "  ${GREEN}✔${NC} $*"; log "OK: $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $*"; log "WARN: $*"; }

log "=== FORENSIC SESSION STARTED ==="
log "UUID: $UUID | Timestamp: $TIMESTAMP"
log "Consent: explicit --consent flag | Operator: $(whoami)"

echo -e "${BOLD}  ── Phase 1: System Identity ────────────────────────────${NC}"

# ── 1. OS IDENTIFICATION ──────────────────────────────────────────
step "Collecting OS identification..."
if [ -f /etc/os-release ]; then
    OS_NAME=$(grep '^NAME=' /etc/os-release | cut -d'"' -f2 | head -1)
    OS_VERSION=$(grep '^VERSION=' /etc/os-release | cut -d'"' -f2 | head -1)
    OS_ID=$(grep '^ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"' | head -1)
    OS_PRETTY=$(grep '^PRETTY_NAME=' /etc/os-release | cut -d'"' -f2 | head -1)
else
    OS_NAME="Linux"; OS_VERSION="unknown"; OS_ID="unknown"; OS_PRETTY="Linux"
fi

KERNEL=$(uname -r 2>/dev/null || echo "unknown")
ARCH=$(uname -m 2>/dev/null || echo "unknown")
HOSTNAME=$(hostname 2>/dev/null || echo "unknown")
BOOT_TIME=$(who -b 2>/dev/null | awk '{print $3, $4}' || uptime -s 2>/dev/null || echo "unknown")
UPTIME_SEC=$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo 0)
ok "OS: $OS_PRETTY | Kernel: $KERNEL"

# Classify OS type
case "$OS_ID" in
    "tails")         OS_TYPE="PRIVACY_AMNESIC" ;;
    "kali")          OS_TYPE="SECURITY_TESTING" ;;
    "parrot")        OS_TYPE="SECURITY_TESTING" ;;
    "ubuntu"|"debian") OS_TYPE="GENERAL_PURPOSE" ;;
    "fedora"|"rhel"|"centos") OS_TYPE="ENTERPRISE" ;;
    *)               OS_TYPE="GENERAL_PURPOSE" ;;
esac

# ── 2. HARDWARE FINGERPRINT ───────────────────────────────────────
step "Collecting hardware fingerprint..."
CPU_MODEL=$(grep 'model name' /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | sed 's/^ *//' | sed 's/["\\/]/ /g' | tr -d '\n\r')
CPU_CORES=$(nproc 2>/dev/null | tr -d '[:space:]' || grep -c '^processor' /proc/cpuinfo 2>/dev/null | tr -d '[:space:]' || echo 0)
TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0)
TOTAL_RAM_MB=$(( TOTAL_RAM_KB / 1024 ))
FREE_RAM_KB=$(grep MemAvailable /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0)
FREE_RAM_MB=$(( FREE_RAM_KB / 1024 ))

MACHINE_ID=""
[ -r /etc/machine-id ] && MACHINE_ID=$(cat /etc/machine-id 2>/dev/null | head -c 32)
[ -z "$MACHINE_ID" ] && MACHINE_ID="unavailable"

ok "CPU: $CPU_CORES cores | RAM: ${FREE_RAM_MB}MB free / ${TOTAL_RAM_MB}MB total"

# ── 3. FORENSIC BOOT MODE ─────────────────────────────────────────
step "Detecting boot mode and forensic flags..."
CMDLINE=$(cat /proc/cmdline 2>/dev/null || echo "unavailable")
FORENSIC_MODE="STANDARD"
grep -qi "forensic" /proc/cmdline 2>/dev/null && FORENSIC_MODE="FORENSIC_MODE_ACTIVE"
grep -qi "live"     /proc/cmdline 2>/dev/null && BOOT_TYPE="LIVE_BOOT" || BOOT_TYPE="INSTALLED"
grep -qi "toram"    /proc/cmdline 2>/dev/null && RAM_BOOT="yes" || RAM_BOOT="no"
ok "Boot: $BOOT_TYPE | Forensic mode: $FORENSIC_MODE"

echo ""
echo -e "${BOLD}  ── Phase 2: Volatile Evidence ─────────────────────────${NC}"

# ── 4. RUNNING PROCESSES ──────────────────────────────────────────
step "Capturing running process list..."
PROCESS_COUNT=0
PROCESS_LIST="[]"
if command -v ps >/dev/null 2>&1; then
    PROCESS_COUNT=$(ps aux 2>/dev/null | tail -n +2 | wc -l | tr -d '[:space:]')
    # Top 20 processes by CPU — sanitize cmd to remove quotes/backslashes
    TOP_PROCS=$(ps aux --sort=-%cpu 2>/dev/null | head -21 | tail -20 | \
        awk '{cmd=substr($0,index($0,$11),40); gsub(/["\\]/,"",cmd); gsub(/\t/," ",cmd); printf "{\"pid\":\"%s\",\"user\":\"%s\",\"cpu\":\"%s\",\"mem\":\"%s\",\"cmd\":\"%s\"},", $2,$1,$3,$4,cmd}' | \
        sed 's/,$//')
    PROCESS_LIST="[$TOP_PROCS]"
    ok "$PROCESS_COUNT total processes captured"
else
    warn "ps not available"
fi

# ── 5. NETWORK STATE ──────────────────────────────────────────────
step "Capturing network state..."
INTERFACES="unknown"
IP_ADDRESSES=""
if [ -r /proc/net/dev ]; then
    INTERFACES=$(awk 'NR>2 && $1!~/lo:/ {gsub(/:/, "", $1); printf "%s,", $1}' /proc/net/dev | sed 's/,$//')
fi

# IP addresses via /proc (no ip command needed)
if [ -r /proc/net/fib_trie ]; then
    IP_ADDRESSES=$(awk '/32 HOST/{print f} {f=$2}' /proc/net/fib_trie 2>/dev/null | \
        grep -v '127\.' | sort -u | head -5 | tr '\n' ',' | sed 's/,$//')
fi

# Active connections
ACTIVE_CONNECTIONS=0
if [ -r /proc/net/tcp ]; then
    ACTIVE_CONNECTIONS=$(awk 'NR>1 && $4=="01000000" {count++} END {print count+0}' /proc/net/tcp)
fi

# TOR detection (process-based, not assumed)
TOR_ACTIVE=false
TOR_PIDS=0
if command -v pgrep >/dev/null 2>&1; then
    TOR_PIDS=$(pgrep -c -x tor 2>/dev/null | tr -d '[:space:]' || echo 0)
    TOR_PIDS=${TOR_PIDS:-0}
    [[ "$TOR_PIDS" =~ ^[0-9]+$ ]] && [ "$TOR_PIDS" -gt 0 ] && TOR_ACTIVE=true
fi

# VPN detection
VPN_ACTIVE=false
ls /sys/class/net/ 2>/dev/null | grep -qE "^tun|^tap|^wg" && VPN_ACTIVE=true

DNS_SERVERS=$(grep '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | head -3 | tr '\n' ',' | sed 's/,$//')
ok "Interfaces: $INTERFACES | IPs: $IP_ADDRESSES | Connections: $ACTIVE_CONNECTIONS"

# ── 6. LOGGED-IN USERS ────────────────────────────────────────────
step "Collecting logged-in user evidence..."
LOGGED_USERS="unknown"
LOGIN_COUNT=0
if command -v who >/dev/null 2>&1; then
    LOGGED_USERS=$(who 2>/dev/null | awk '{printf "%s(%s) ", $1,$2}' | sed 's/ $//')
    LOGIN_COUNT=$(who 2>/dev/null | wc -l)
fi
CURRENT_USER=$(whoami 2>/dev/null || echo "unknown")
ok "Current user: $CURRENT_USER | Active sessions: $LOGIN_COUNT"

# ── 7. MOUNTED DEVICES & STORAGE ────────────────────────────────
step "Collecting storage and mount evidence..."
MOUNT_POINTS=$(mount 2>/dev/null | grep -v "^cgroup\|^sys\|^proc\|^tmpfs\|^devtmpfs\|^udev" | \
    awk '{printf "{\"device\":\"%s\",\"mount\":\"%s\",\"fs\":\"%s\"},", $1,$3,$5}' | sed 's/,$//')
MOUNT_POINTS="[$MOUNT_POINTS]"

BLOCK_DEVICES="unavailable"
if command -v lsblk >/dev/null 2>&1; then
    BLOCK_DEVICES=$(lsblk -o NAME,SIZE,TYPE,MOUNTPOINT 2>/dev/null | tail -n +2 | \
        awk '{printf "%s(%s/%s) ", $1,$2,$3}' | sed 's/ $//')
fi

DISK_USAGE=$(df -h / 2>/dev/null | tail -1 | awk '{printf "total:%s used:%s free:%s", $2,$3,$4}' || echo "unavailable")
ok "Block devices: $BLOCK_DEVICES"

echo ""
echo -e "${BOLD}  ── Phase 3: Security Profiling ────────────────────────${NC}"

# ── 8. SECURITY TOOL DETECTION (process + binary, no assumptions) ──
step "Scanning for installed security tools..."
TOOLS_FOUND=()
TOOLS_RUNNING=()

TOOL_LIST="nmap nikto sqlmap aircrack-ng john hashcat hydra wireshark msfconsole \
msfvenom recon-ng wpscan gobuster dirbuster dnsrecon theharvester \
netcat nc ncat tcpdump tshark volatility autopsy sleuthkit foremost \
binwalk radare2 gdb ltrace strace"

for TOOL in $TOOL_LIST; do
    command -v "$TOOL" >/dev/null 2>&1 && TOOLS_FOUND+=("$TOOL")
done

# Check which tools are ACTIVELY running (much more meaningful)
for TOOL in nmap hydra hashcat aircrack-ng john sqlmap msfconsole wireshark tshark tcpdump; do
    pgrep -x "$TOOL" >/dev/null 2>&1 && TOOLS_RUNNING+=("$TOOL")
done

TOOLS_FOUND_STR=$(IFS=','; echo "${TOOLS_FOUND[*]}")
TOOLS_RUNNING_STR=$(IFS=','; echo "${TOOLS_RUNNING[*]}")
TOOL_COUNT=${#TOOLS_FOUND[@]}
RUNNING_COUNT=${#TOOLS_RUNNING[@]}

[ $TOOL_COUNT -gt 0 ] && ok "$TOOL_COUNT security tools installed: $TOOLS_FOUND_STR" || ok "No common security tools detected"
[ $RUNNING_COUNT -gt 0 ] && warn "$RUNNING_COUNT currently RUNNING: $TOOLS_RUNNING_STR"

# ── 9. FIREWALL & SECURITY STATE ─────────────────────────────────
step "Checking firewall and security configuration..."
FIREWALL_ACTIVE=false
SELINUX_STATUS="unavailable"
APPARMOR_STATUS="unavailable"

command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "active" && FIREWALL_ACTIVE=true
command -v iptables >/dev/null 2>&1 && iptables -L 2>/dev/null | grep -qv "^$\|^Chain\|^target" && FIREWALL_ACTIVE=true

command -v getenforce >/dev/null 2>&1 && SELINUX_STATUS=$(getenforce 2>/dev/null || echo "unavailable")
[ -f /sys/kernel/security/apparmor/profiles ] && APPARMOR_STATUS="active" || APPARMOR_STATUS="inactive"

ok "Firewall: $FIREWALL_ACTIVE | SELinux: $SELINUX_STATUS | AppArmor: $APPARMOR_STATUS"

# ── 10. RECENTLY MODIFIED FILES ───────────────────────────────────
step "Finding recently modified files (last 1 hour)..."
RECENT_FILES="unavailable"
if command -v find >/dev/null 2>&1; then
    RECENT_FILES=$(find /tmp /var/tmp /home 2>/dev/null -mmin -60 -type f ! -name "*.log" | \
        head -15 | tr '\n' ',' | sed 's/,$//' || echo "unavailable")
fi
ok "Recent file scan complete"

# ── 11. SUSPICIOUS INDICATORS ────────────────────────────────────
step "Checking for suspicious indicators..."
INDICATORS=()

# World-writable files in sensitive locations
find /tmp /var/tmp 2>/dev/null -perm -o+w -type f | grep -qE "\.(sh|py|pl|rb|elf)$" && \
    INDICATORS+=("executable-in-tmp")

# SUID/SGID binaries (outside standard paths)
find /tmp /home /var/tmp 2>/dev/null -perm /4000 -type f 2>/dev/null | grep -q . && \
    INDICATORS+=("suid-in-tmp")

# Listening on unusual high ports
if [ -r /proc/net/tcp ]; then
    HIGH_PORTS=$(awk 'NR>1 {port=strtonum("0x"substr($2,index($2,":")+1)); if(port>1024 && port<65535 && $4=="0A") print port}' \
        /proc/net/tcp 2>/dev/null | sort -u | head -5 | tr '\n' ',')
    [ -n "$HIGH_PORTS" ] && INDICATORS+=("listening-high-ports:${HIGH_PORTS%,}")
fi

# Deleted but open files (common malware indicator)
if command -v lsof >/dev/null 2>&1; then
    lsof 2>/dev/null | grep -q "(deleted)" && INDICATORS+=("deleted-open-files")
fi

INDICATORS_STR=$(IFS=','; echo "${INDICATORS[*]}")
INDICATOR_COUNT=${#INDICATORS[@]}
[ $INDICATOR_COUNT -gt 0 ] && warn "$INDICATOR_COUNT indicators: $INDICATORS_STR" || ok "No suspicious indicators found"

echo ""
echo -e "${BOLD}  ── Phase 4: Risk Assessment ────────────────────────────${NC}"

# ── 12. RISK SCORING (evidence-based) ────────────────────────────
step "Calculating evidence-based risk score..."
RISK=10

# Each scoring factor is logged with reason
RISK_FACTORS=()

[ "$TOR_ACTIVE" = true ] && { RISK=$((RISK + 20)); RISK_FACTORS+=("tor-active:+20"); }
[ "$VPN_ACTIVE" = true ] && { RISK=$((RISK + 10)); RISK_FACTORS+=("vpn-detected:+10"); }
[ "$OS_TYPE" = "SECURITY_TESTING" ] && { RISK=$((RISK + 20)); RISK_FACTORS+=("security-os:+20"); }
[ "$FORENSIC_MODE" = "FORENSIC_MODE_ACTIVE" ] && { RISK=$((RISK + 5)); RISK_FACTORS+=("forensic-boot:+5"); }
[ "$BOOT_TYPE" = "LIVE_BOOT" ] && { RISK=$((RISK + 15)); RISK_FACTORS+=("live-boot:+15"); }
[ $RUNNING_COUNT -gt 0 ] && { RISK=$((RISK + RUNNING_COUNT * 10)); RISK_FACTORS+=("active-tools:+$((RUNNING_COUNT*10))"); }
[ $TOOL_COUNT -gt 10 ] && { RISK=$((RISK + 15)); RISK_FACTORS+=("many-tools-installed:+15"); }
[ $INDICATOR_COUNT -gt 0 ] && { RISK=$((RISK + INDICATOR_COUNT * 8)); RISK_FACTORS+=("indicators:+$((INDICATOR_COUNT*8))"); }

RISK=$(( RISK > 100 ? 100 : RISK ))
RISK_FACTORS_STR=$(IFS=','; echo "${RISK_FACTORS[*]}")

if   [ $RISK -ge 80 ]; then THREAT_LEVEL="CRITICAL"
elif [ $RISK -ge 60 ]; then THREAT_LEVEL="HIGH"
elif [ $RISK -ge 40 ]; then THREAT_LEVEL="MEDIUM"
else                        THREAT_LEVEL="LOW"
fi

ok "Risk Score: $RISK/100 | Threat Level: $THREAT_LEVEL"
ok "Factors: $RISK_FACTORS_STR"

echo ""
echo -e "${BOLD}  ── Phase 5: Saving Evidence ────────────────────────────${NC}"

# ── 13. BUILD JSON REPORT ────────────────────────────────────────
step "Writing evidence to JSON..."

# ── Sanitize all string fields before writing JSON ──────────────
json_safe() { echo "$1" | sed 's/["\\/]/ /g' | tr -d '\n\r\t' | head -c 300; }

CPU_MODEL_S=$(json_safe "$CPU_MODEL")
HOSTNAME_S=$(json_safe "$HOSTNAME")
OS_NAME_S=$(json_safe "$OS_NAME")
OS_VERSION_S=$(json_safe "$OS_VERSION")
OS_PRETTY_S=$(json_safe "$OS_PRETTY")
MACHINE_ID_S=$(json_safe "$MACHINE_ID")
BOOT_TIME_S=$(json_safe "$BOOT_TIME")
CMDLINE_S=$(echo "$CMDLINE" | sed 's/["\\/]/ /g' | tr -d '\n\r' | head -c 200)
INTERFACES_S=$(json_safe "$INTERFACES")
IP_ADDRESSES_S=$(json_safe "$IP_ADDRESSES")
DNS_SERVERS_S=$(json_safe "$DNS_SERVERS")
LOGGED_USERS_S=$(json_safe "$LOGGED_USERS")
CURRENT_USER_S=$(json_safe "$CURRENT_USER")
BLOCK_DEVICES_S=$(json_safe "$BLOCK_DEVICES")
DISK_USAGE_S=$(json_safe "$DISK_USAGE")
RECENT_FILES_S=$(json_safe "$RECENT_FILES")
TOOLS_FOUND_S=$(json_safe "$TOOLS_FOUND_STR")
TOOLS_RUNNING_S=$(json_safe "$TOOLS_RUNNING_STR")
INDICATORS_S=$(json_safe "$INDICATORS_STR")
RISK_FACTORS_S=$(json_safe "$RISK_FACTORS_STR")

# Ensure numeric values are clean integers
PROCESS_COUNT=$(echo "$PROCESS_COUNT" | tr -d '[:space:]' | grep -o '^[0-9]*' || echo 0)
LOGIN_COUNT=$(echo "$LOGIN_COUNT"     | tr -d '[:space:]' | grep -o '^[0-9]*' || echo 0)
ACTIVE_CONNECTIONS=$(echo "$ACTIVE_CONNECTIONS" | tr -d '[:space:]' | grep -o '^[0-9]*' || echo 0)
TOR_PIDS=$(echo "$TOR_PIDS"           | tr -d '[:space:]' | grep -o '^[0-9]*' || echo 0)
UPTIME_SEC=$(echo "$UPTIME_SEC"       | tr -d '[:space:]' | grep -o '^[0-9]*' || echo 0)
CPU_CORES=$(echo "$CPU_CORES"         | tr -d '[:space:]' | grep -o '^[0-9]*' || echo 0)
TOTAL_RAM_MB=$(echo "$TOTAL_RAM_MB"   | tr -d '[:space:]' | grep -o '^[0-9]*' || echo 0)
FREE_RAM_MB=$(echo "$FREE_RAM_MB"     | tr -d '[:space:]' | grep -o '^[0-9]*' || echo 0)
TOOL_COUNT=$(echo "$TOOL_COUNT"       | tr -d '[:space:]' | grep -o '^[0-9]*' || echo 0)
RUNNING_COUNT=$(echo "$RUNNING_COUNT" | tr -d '[:space:]' | grep -o '^[0-9]*' || echo 0)
INDICATOR_COUNT=$(echo "$INDICATOR_COUNT" | tr -d '[:space:]' | grep -o '^[0-9]*' || echo 0)

cat > "$REPORT_FILE" << JSONEOF
{
  "meta": {
    "tool": "Live OS Forensic Agent",
    "version": "$VERSION",
    "uuid": "$UUID",
    "collection_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)",
    "operator": "$CURRENT_USER_S",
    "consent": true,
    "academic_project": true
  },
  "system": {
    "hostname": "$HOSTNAME_S",
    "machine_id": "$MACHINE_ID_S",
    "os": {
      "name": "$OS_NAME_S",
      "version": "$OS_VERSION_S",
      "pretty": "$OS_PRETTY_S",
      "id": "$OS_ID",
      "type": "$OS_TYPE",
      "kernel": "$KERNEL",
      "architecture": "$ARCH"
    },
    "hardware": {
      "cpu_model": "$CPU_MODEL_S",
      "cpu_cores": $CPU_CORES,
      "ram_total_mb": $TOTAL_RAM_MB,
      "ram_free_mb": $FREE_RAM_MB
    },
    "boot": {
      "type": "$BOOT_TYPE",
      "time": "$BOOT_TIME_S",
      "uptime_seconds": $UPTIME_SEC,
      "forensic_mode": "$FORENSIC_MODE",
      "ram_boot": "$RAM_BOOT",
      "cmdline": "$CMDLINE_S"
    },
    "storage": {
      "block_devices": "$BLOCK_DEVICES_S",
      "disk_usage_root": "$DISK_USAGE_S"
    }
  },
  "volatile_evidence": {
    "processes": {
      "total_count": $PROCESS_COUNT,
      "top_by_cpu": $PROCESS_LIST
    },
    "users": {
      "current": "$CURRENT_USER_S",
      "logged_in": "$LOGGED_USERS_S",
      "session_count": $LOGIN_COUNT
    },
    "mounts": $MOUNT_POINTS,
    "recent_files_modified": "$RECENT_FILES_S"
  },
  "network": {
    "interfaces": "$INTERFACES",
    "ip_addresses": "$IP_ADDRESSES",
    "dns_servers": "$DNS_SERVERS",
    "active_connections": $ACTIVE_CONNECTIONS,
    "tor_active": $TOR_ACTIVE,
    "tor_processes": $TOR_PIDS,
    "vpn_detected": $VPN_ACTIVE
  },
  "security_profile": {
    "tools_installed": {
      "count": $TOOL_COUNT,
      "list": "$TOOLS_FOUND_S"
    },
    "tools_running": {
      "count": $RUNNING_COUNT,
      "list": "$TOOLS_RUNNING_S"
    },
    "firewall_active": $FIREWALL_ACTIVE,
    "selinux": "$SELINUX_STATUS",
    "apparmor": "$APPARMOR_STATUS",
    "suspicious_indicators": {
      "count": $INDICATOR_COUNT,
      "list": "$INDICATORS_S"
    }
  },
  "risk_assessment": {
    "score": $RISK,
    "level": "$THREAT_LEVEL",
    "factors": "$RISK_FACTORS_S",
    "note": "Score based on observed evidence, not assumptions about OS type alone"
  }
}
JSONEOF

ok "Evidence saved: $REPORT_FILE"

# ── 14. UPLOAD (only if --server given, with explicit notice) ──────
if [ "$UPLOAD" = true ] && [ -n "$C2_SERVER" ]; then
    echo ""
    echo -e "${BOLD}  ── Phase 6: Transmitting to Dashboard ─────────────────${NC}"
    step "Testing connectivity to $C2_SERVER..."

    if curl -sf --connect-timeout 5 --max-time 10 \
        "${C2_SERVER%/capture}/health" >/dev/null 2>&1; then

        step "Uploading evidence..."
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST "$C2_SERVER" \
            -H "Content-Type: application/json" \
            -d @"$REPORT_FILE" \
            --connect-timeout 10 --max-time 30 2>/dev/null)

        if [ "$HTTP_CODE" = "200" ]; then
            ok "Transmitted successfully (HTTP 200)"
        else
            warn "Upload failed (HTTP $HTTP_CODE) — evidence retained locally"
        fi
    else
        warn "Server unreachable — evidence retained locally at $REPORT_FILE"
        echo -e "  ${CYAN}Tip:${NC} Start server: python server/c2-server.py"
    fi
fi

# ── Summary ──────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}  ╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}  ║             COLLECTION COMPLETE                      ║${NC}"
echo -e "${CYAN}${BOLD}  ╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}System:${NC}     $OS_PRETTY ($HOSTNAME)"
echo -e "  ${BOLD}Boot:${NC}       $BOOT_TYPE | Uptime: ${UPTIME_SEC}s"
echo -e "  ${BOLD}Network:${NC}    $INTERFACES | TOR: $TOR_ACTIVE | VPN: $VPN_ACTIVE"
echo -e "  ${BOLD}Processes:${NC}  $PROCESS_COUNT total | $RUNNING_COUNT attack tools active"
echo -e "  ${BOLD}Risk:${NC}       ${BOLD}$RISK/100${NC} — $THREAT_LEVEL"
echo ""
echo -e "  ${GREEN}Evidence:${NC}   $REPORT_FILE"
echo -e "  ${GREEN}Log:${NC}        $LOG_FILE"
echo ""
log "=== COLLECTION COMPLETE | Risk: $RISK | Level: $THREAT_LEVEL ==="
