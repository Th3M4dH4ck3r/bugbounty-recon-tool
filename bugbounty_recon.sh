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

# Check if domain is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <target-domain>"
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
