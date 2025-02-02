#!/bin/bash

# Custom Banner
function banner() {
    echo -e "\e[1;36m"  # Cyan color for neon effect
    echo "     ☠️  RECON IN PROGRESS ☠️"
    echo -e "\e[1;33m"  # Yellow for the emoji style
    echo "        😎"
    echo "     🎩  TOP HAT HACKER  🎩"
    echo -e "\e[1;31m"  # Red for the smoke effect
    echo "          ~~~~~"
    echo -e "\e[1;36m"  # Back to cyan
    echo "    SCANNING TARGET: $1"
    echo "     ⚡ STAY LEGAL ⚡"
    echo -e "\e[0m"
}

# Run the banner
banner

# Progress monitoring function
function show_progress() {
    local results_dir="$1"
    clear
    
    # Define colors
    local RED='\e[1;31m'
    local GREEN='\e[1;32m'
    local YELLOW='\e[1;33m'
    local BLUE='\e[1;34m'
    local MAGENTA='\e[1;35m'
    local CYAN='\e[1;36m'
    local WHITE='\e[1;37m'
    local RESET='\e[0m'
    local BOLD='\e[1m'
    
    # Header
    echo -e "${CYAN}╔════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║${BOLD}         🎯 RECON PROGRESS MONITOR 🎯        ${CYAN}║${RESET}"
    echo -e "${CYAN}║${WHITE}          Target: $DOMAIN          ${CYAN}║${RESET}"
    echo -e "${CYAN}╚════════════════════════════════════════════╝${RESET}"
    echo

    # Subdomain Section
    echo -e "${BLUE}[+] Subdomain Enumeration${RESET}"
    echo -e "${WHITE}├─── Subfinder: ${GREEN}$(wc -l < "$results_dir/subfinder.txt" 2>/dev/null || echo "0") domains${RESET}"
    echo -e "${WHITE}├─── Amass:    ${GREEN}$(wc -l < "$results_dir/amass.txt" 2>/dev/null || echo "0") domains${RESET}"
    echo -e "${WHITE}└─── Crt.sh:   ${GREEN}$(wc -l < "$results_dir/crtsh.txt" 2>/dev/null || echo "0") domains${RESET}"
    echo

    # Live Hosts Section
    echo -e "${MAGENTA}[+] Live Hosts Detection${RESET}"
    echo -e "${WHITE}├─── Active Subdomains: ${GREEN}$(wc -l < "$results_dir/live_subdomains.txt" 2>/dev/null || echo "0")${RESET}"
    echo -e "${WHITE}└─── Open Ports:        ${GREEN}$(wc -l < "$results_dir/ports.txt" 2>/dev/null || echo "0")${RESET}"
    echo

    # Assets Section
    echo -e "${YELLOW}[+] Asset Discovery${RESET}"
    echo -e "${WHITE}├─── JavaScript Files: ${GREEN}$(wc -l < "$results_dir/js-files/all_js.txt" 2>/dev/null || echo "0")${RESET}"
    echo -e "${WHITE}└─── Directories:      ${GREEN}$(find "$results_dir/content-discovery" -type f -exec cat {} \; 2>/dev/null | wc -l || echo "0")${RESET}"
    echo

    # Vulnerabilities Section
    local nuclei_findings=$(find "$results_dir" -name "nuclei_*.txt" -exec cat {} \; 2>/dev/null | wc -l || echo "0")
    echo -e "${RED}[+] Security Findings${RESET}"
    echo -e "${WHITE}├─── Nuclei Findings:   ${nuclei_findings}${RESET}"
    if [ "$nuclei_findings" -gt 0 ]; then
        echo -e "${WHITE}└─── Latest Findings:${RESET}"
        find "$results_dir" -name "nuclei_*.txt" -exec tail -n 3 {} \; 2>/dev/null | \
            while read -r line; do
                echo -e "${RED}    └─── $line${RESET}"
            done
    fi
    echo

    # API/Endpoints Section
    echo -e "${GREEN}[+] API & Endpoints${RESET}"
    echo -e "${WHITE}├─── GraphQL Endpoints: ${GREEN}$(wc -l < "$results_dir/graphql/endpoints.txt" 2>/dev/null || echo "0")${RESET}"
    echo -e "${WHITE}└─── API Endpoints:     ${GREEN}$(find "$results_dir/api" -type f -name "*.txt" -exec cat {} \; 2>/dev/null | wc -l || echo "0")${RESET}"
    echo

    # Status Indicators
    echo -e "${CYAN}╔════════════════════════════════════════════╗${RESET}"
    if [ ! -z "$RATE_LIMIT" ]; then
        echo -e "${CYAN}║${YELLOW} Rate Limit: ${GREEN}$RATE_LIMIT req/sec${CYAN}                   ║${RESET}"
    fi
    if [ "$TOOL_DELAY" -gt 0 ]; then
        echo -e "${CYAN}║${YELLOW} Tool Delay: ${GREEN}${TOOL_DELAY}s${CYAN}                          ║${RESET}"
    fi
    echo -e "${CYAN}║${WHITE} Press ${RED}Ctrl+C${WHITE} to exit monitoring              ${CYAN}║${RESET}"
    echo -e "${CYAN}╚════════════════════════════════════════════╝${RESET}"

    # Time stamp
    echo -e "\n${WHITE}Last Updated: $(date '+%H:%M:%S')${RESET}"
}

# Help menu
function show_help() {
    echo "Usage: $0 [options] <target-domain>"
    echo
    echo "Options:"
    echo "  -h, --help            Show this help message"
    echo "  -s, --shodan          Specify Shodan API key"
    echo "  -w, --wp              Specify WPScan API key"
    echo "  -m, --monitor         Enable live progress monitoring"
    echo "  -r, --rate-limit      Rate limit requests (requests per second, default: none)"
    echo "  -d, --delay           Add delay between tools (seconds, default: 0)"
    echo
    echo "Examples:"
    echo "  $0 example.com"
    echo "  $0 -s YOUR_SHODAN_KEY example.com"
    echo "  $0 -m -r 10 example.com        # Monitor progress with 10 req/sec limit"
    echo "  $0 -d 2 example.com            # Add 2 second delay between tools"
    exit 0
}

# Parse command line arguments
POSITIONAL_ARGS=()
MONITOR_MODE=false
RATE_LIMIT=""
TOOL_DELAY=0

while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help)
      show_help
      ;;
    -s|--shodan)
      SHODAN_API_KEY="$2"
      shift
      shift
      ;;
    -w|--wp)
      WPSCAN_API_KEY="$2"
      shift
      shift
      ;;
    -m|--monitor)
      MONITOR_MODE=true
      shift
      ;;
    -r|--rate-limit)
      RATE_LIMIT="$2"
      shift
      shift
      ;;
    -d|--delay)
      TOOL_DELAY="$2"
      shift
      shift
      ;;
    -*|--*)
      echo "Unknown option $1"
      show_help
      ;;
    *)
      POSITIONAL_ARGS+=("$1")
      shift
      ;;
  esac
done

# Restore positional parameters
set -- "${POSITIONAL_ARGS[@]}"

# Check if domain is provided
if [ -z "$1" ]; then
    echo "Error: No target domain specified"
    show_help
fi

# Validate domain format (basic check)
if ! echo "$1" | grep -qP '(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)'; then
    echo "Error: Invalid domain format. Please provide a valid domain (e.g., example.com)"
    exit 1
fi

# Configuration
DOMAIN=$1
WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
DIR_WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"
RESOLVERS="resolvers.txt"
RESULTS_DIR="results/$DOMAIN"

# API Keys
SHODAN_API_KEY="YOUR_SHODAN_API_KEY"  # Replace with your Shodan API key

echo "[+] Starting full bug bounty reconnaissance for: $DOMAIN"
mkdir -p $RESULTS_DIR/{screenshots,content-discovery,js-files,params,api,wordpress,graphql}

# Rate limiting function
function rate_limit_cmd() {
    if [ ! -z "$RATE_LIMIT" ]; then
        echo "[+] Rate limiting enabled: $RATE_LIMIT requests/second"
        # Add rate limiting parameters to tools that support it
        RATE_PARAM="--rate-limit $RATE_LIMIT"
    else
        RATE_PARAM=""
    fi
}

# Tool delay function
function tool_delay() {
    if [ "$TOOL_DELAY" -gt 0 ]; then
        echo "[+] Waiting $TOOL_DELAY seconds before next tool..."
        sleep "$TOOL_DELAY"
    fi
}

# Start monitoring in background if enabled
if [ "$MONITOR_MODE" = true ]; then
    while true; do
        show_progress "$RESULTS_DIR"
        sleep 5
    done &
    MONITOR_PID=$!
    # Trap to kill monitoring on script exit
    trap 'kill $MONITOR_PID 2>/dev/null' EXIT
fi

# 1️⃣ Subdomain Enumeration
echo "[+] Running subfinder..."
subfinder -d $DOMAIN -o $RESULTS_DIR/subfinder.txt

echo "[+] Running amass..."
amass enum -passive -d $DOMAIN -o $RESULTS_DIR/amass.txt

echo "[+] Fetching subdomains from crt.sh..."
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > $RESULTS_DIR/crtsh.txt

# 2️⃣ Brute-Force Subdomains
echo "[+] Fetching fresh resolvers..."
curl -s https://public-dns.info/nameservers.txt -o $RESOLVERS

# Check if puredns is installed
if command -v puredns &> /dev/null; then
    echo "[+] Running puredns brute-force..."
    puredns bruteforce $WORDLIST $DOMAIN -r $RESOLVERS -o $RESULTS_DIR/puredns.txt
else
    echo "[!] puredns not found - skipping brute-force step"
    touch $RESULTS_DIR/puredns.txt  # Create empty file to prevent cat errors
fi

# 3️⃣ Merge & Deduplicate
echo "[+] Merging all subdomains..."
cat $RESULTS_DIR/subfinder.txt $RESULTS_DIR/amass.txt $RESULTS_DIR/crtsh.txt $RESULTS_DIR/puredns.txt 2>/dev/null | sort -u > $RESULTS_DIR/all_subdomains.txt

# 4️⃣ Check Live Subdomains
echo "[+] Checking for live subdomains..."
if command -v httpx &> /dev/null; then
    cat $RESULTS_DIR/all_subdomains.txt | httpx -silent -o $RESULTS_DIR/live_subdomains.txt
else
    echo "[!] httpx not found - copying all subdomains as live"
    cp $RESULTS_DIR/all_subdomains.txt $RESULTS_DIR/live_subdomains.txt
fi

# 5️⃣ Port Scanning & Shodan Enumeration
echo "[+] Running naabu and Shodan scans..."

# Shodan enumeration
echo "[+] Querying Shodan for: $DOMAIN"
if [ ! -z "$SHODAN_API_KEY" ]; then
    curl -s "https://api.shodan.io/shodan/host/search?key=$SHODAN_API_KEY&query=hostname:$DOMAIN" \
        | jq '.' > "$RESULTS_DIR/shodan_results.json"
    
    # Extract IPs and ports from Shodan results
    if [ -f "$RESULTS_DIR/shodan_results.json" ]; then
        jq -r '.matches[].ip_str' "$RESULTS_DIR/shodan_results.json" > "$RESULTS_DIR/shodan_ips.txt"
        jq -r '.matches[].ports[]' "$RESULTS_DIR/shodan_results.json" 2>/dev/null >> "$RESULTS_DIR/ports.txt"
    fi
    echo "[+] Shodan results saved to: $RESULTS_DIR/shodan_results.json"
else
    echo "[!] Shodan API key not configured - skipping Shodan enumeration"
fi

# Naabu port scanning
if command -v naabu &> /dev/null; then
    naabu -iL $RESULTS_DIR/live_subdomains.txt -o $RESULTS_DIR/ports.txt
else
    echo "[!] naabu not found - skipping port scanning"
    touch $RESULTS_DIR/ports.txt
fi

# 6️⃣ Screenshots
echo "[+] Capturing screenshots..."
if command -v gowitness &> /dev/null; then
    gowitness file -f $RESULTS_DIR/live_subdomains.txt --screenshot-path $RESULTS_DIR/screenshots/
else
    echo "[!] gowitness not found - skipping screenshots"
fi

# 7️⃣ Content Discovery
echo "[+] Running gobuster..."
if [ -f "$RESULTS_DIR/live_subdomains.txt" ]; then
    while read url; do
        gobuster dir -u $url -w $DIR_WORDLIST -o "$RESULTS_DIR/content-discovery/gobuster-$(echo $url | cut -d/ -f3).txt"
    done < $RESULTS_DIR/live_subdomains.txt
fi

echo "[+] Running dirsearch..."
if [ -f "$RESULTS_DIR/live_subdomains.txt" ]; then
    while read url; do
        dirsearch -u $url -w $DIR_WORDLIST -o "$RESULTS_DIR/content-discovery/dirsearch-$(echo $url | cut -d/ -f3).txt"
    done < $RESULTS_DIR/live_subdomains.txt
fi

# 8️⃣ JavaScript Enumeration
echo "[+] Extracting JS files..."
if command -v katana &> /dev/null; then
    katana -list $RESULTS_DIR/live_subdomains.txt -jc -kf -o $RESULTS_DIR/js-files/all_js.txt
else
    echo "[!] katana not found - skipping JS extraction"
    touch $RESULTS_DIR/js-files/all_js.txt
fi

echo "[+] Running getJS..."
if [ -f "$RESULTS_DIR/live_subdomains.txt" ]; then
    while read url; do
        if command -v getJS &> /dev/null; then
            getJS --url $url | tee -a $RESULTS_DIR/js-files/getjs_$(echo $url | cut -d/ -f3).txt
        fi
    done < $RESULTS_DIR/live_subdomains.txt
fi

# 9️⃣ Parameter Discovery
echo "[+] Running ParamSpider..."
if [ -f "$RESULTS_DIR/live_subdomains.txt" ]; then
    while read url; do
        if [ -f ~/tools/ParamSpider/paramspider.py ]; then
            python3 ~/tools/ParamSpider/paramspider.py -d $(echo $url | cut -d/ -f3) --output "$RESULTS_DIR/params/$(echo $url | cut -d/ -f3).txt"
        fi
    done < $RESULTS_DIR/live_subdomains.txt
fi

# 🔟 API Enumeration
echo "[+] Running waybackurls & gau..."
if [ -f "$RESULTS_DIR/live_subdomains.txt" ]; then
    while read url; do
        if command -v waybackurls &> /dev/null; then
            echo $url | waybackurls | tee -a $RESULTS_DIR/api/wayback_$(echo $url | cut -d/ -f3).txt
        fi
        if command -v gau &> /dev/null; then
            echo $url | gau | tee -a $RESULTS_DIR/api/gau_$(echo $url | cut -d/ -f3).txt
        fi
    done < $RESULTS_DIR/live_subdomains.txt
fi

# 1️⃣1️⃣ WordPress Scanning
echo "[+] Running WPScan..."
if [ -f "$RESULTS_DIR/live_subdomains.txt" ]; then
    while read url; do
        if command -v wpscan &> /dev/null; then
            wpscan --url $url --enumerate vp,ap,u --api-token YOUR_WPSCAN_API_KEY -o "$RESULTS_DIR/wordpress/wpscan_$(echo $url | cut -d/ -f3).txt"
        fi
    done < $RESULTS_DIR/live_subdomains.txt
fi

# 1️⃣2️⃣ GraphQL Detection & Exploitation
echo "[+] Searching for GraphQL endpoints..."
if [ -f "$RESULTS_DIR/live_subdomains.txt" ]; then
    while read url; do
        if curl -s "$url/graphql" | grep -q "GraphQL"; then
            echo "$url/graphql" | tee -a $RESULTS_DIR/graphql/endpoints.txt
            if command -v graphqlmap &> /dev/null; then
                graphqlmap -u "$url/graphql" --json -o "$RESULTS_DIR/graphql/graphqlmap_$(echo $url | cut -d/ -f3).json"
            fi
        fi
    done < $RESULTS_DIR/live_subdomains.txt
fi

# 1️⃣3️⃣ Vulnerability Scanning
echo "[+] Running nuclei..."
if command -v nuclei &> /dev/null; then
    if [ -f "$RESULTS_DIR/live_subdomains.txt" ]; then
        nuclei -l $RESULTS_DIR/live_subdomains.txt -t cves/ -o $RESULTS_DIR/nuclei_cves.txt
        nuclei -l $RESULTS_DIR/live_subdomains.txt -t misconfiguration/ -o $RESULTS_DIR/nuclei_misconfig.txt
        nuclei -l $RESULTS_DIR/live_subdomains.txt -t vulnerabilities/ -o $RESULTS_DIR/nuclei_vulns.txt
    fi
else
    echo "[!] nuclei not found - skipping vulnerability scanning"
fi

# 🚀 Summary
echo "[+] Recon complete for: $DOMAIN"
echo "[+] Shodan data: $RESULTS_DIR/shodan_results.json"
echo "[+] Total subdomains: $(wc -l < $RESULTS_DIR/all_subdomains.txt 2>/dev/null || echo '0')"
echo "[+] Live subdomains: $(wc -l < $RESULTS_DIR/live_subdomains.txt 2>/dev/null || echo '0')"
echo "[+] Open ports: $(wc -l < $RESULTS_DIR/ports.txt 2>/dev/null || echo '0')"
echo "[+] JS files: $(wc -l < $RESULTS_DIR/js-files/all_js.txt 2>/dev/null || echo '0')"
echo "[+] API endpoints: $(find $RESULTS_DIR/api/ -type f -name "wayback_*.txt" -exec wc -l {} + 2>/dev/null | awk '{sum+=$1} END {print sum}' || echo '0')"
echo "[+] WordPress reports: $RESULTS_DIR/wordpress/"
echo "[+] GraphQL reports: $RESULTS_DIR/graphql/"
echo "[+] Screenshots saved in: $RESULTS_DIR/screenshots/"
echo "[+] Content Discovery: $RESULTS_DIR/content-discovery/"
echo "[+] Nuclei vulnerability results: $RESULTS_DIR/"

exit 0
