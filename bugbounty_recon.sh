#!/bin/bash

# Custom Banner
function banner() {
    echo -e "\e[1;34m"
    echo "##############################################"
    echo "#                                            #"
    echo "#  You've just been probed by Th3M4dH4ck3r!  #"
    echo "#                                            #"
    echo "##############################################"
    echo -e "\e[0m"
    echo -e "\e[1;32m$(cat <<EOF
              🤖
      🌀    H4X IN PROGRESS    🌀
EOF
)\e[0m"
}

# Run the banner
banner

# Check if domain is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <target-domain>"
    exit 1
fi

DOMAIN=$1
WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
DIR_WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"
RESOLVERS="resolvers.txt"
RESULTS_DIR="results/$DOMAIN"

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

echo "[+] Running puredns brute-force..."
puredns bruteforce $WORDLIST $DOMAIN -r $RESOLVERS -o $RESULTS_DIR/puredns.txt

# 3️⃣ Merge & Deduplicate
echo "[+] Merging all subdomains..."
cat $RESULTS_DIR/subfinder.txt $RESULTS_DIR/amass.txt $RESULTS_DIR/crtsh.txt $RESULTS_DIR/puredns.txt | sort -u > $RESULTS_DIR/all_subdomains.txt

# 4️⃣ Check Live Subdomains
echo "[+] Checking for live subdomains..."
cat $RESULTS_DIR/all_subdomains.txt | httpx -silent -o $RESULTS_DIR/live_subdomains.txt

# 5️⃣ Port Scanning
echo "[+] Running naabu..."
naabu -iL $RESULTS_DIR/live_subdomains.txt -o $RESULTS_DIR/ports.txt

# 6️⃣ Screenshots
echo "[+] Capturing screenshots..."
gowitness file -f $RESULTS_DIR/live_subdomains.txt -o $RESULTS_DIR/screenshots/

# 7️⃣ Content Discovery
echo "[+] Running gobuster..."
while read url; do
    gobuster dir -u $url -w $DIR_WORDLIST -o "$RESULTS_DIR/content-discovery/gobuster-$(echo $url | cut -d/ -f3).txt"
done < $RESULTS_DIR/live_subdomains.txt

echo "[+] Running dirsearch..."
while read url; do
    dirsearch -u $url -w $DIR_WORDLIST -o "$RESULTS_DIR/content-discovery/dirsearch-$(echo $url | cut -d/ -f3).txt"
done < $RESULTS_DIR/live_subdomains.txt

# 8️⃣ JavaScript Enumeration
echo "[+] Extracting JS files..."
katana -list $RESULTS_DIR/live_subdomains.txt -jc -kf -o $RESULTS_DIR/js-files/all_js.txt

echo "[+] Running getJS..."
while read url; do
    getJS --url $url | tee -a $RESULTS_DIR/js-files/getjs_$(echo $url | cut -d/ -f3).txt
done < $RESULTS_DIR/live_subdomains.txt

# 9️⃣ Parameter Discovery
echo "[+] Running ParamSpider..."
while read url; do
    python3 ~/tools/ParamSpider/paramspider.py -d $(echo $url | cut -d/ -f3) --output "$RESULTS_DIR/params/$(echo $url | cut -d/ -f3).txt"
done < $RESULTS_DIR/live_subdomains.txt

# 🔟 API Enumeration
echo "[+] Running waybackurls & gau..."
while read url; do
    echo $url | waybackurls | tee -a $RESULTS_DIR/api/wayback_$(echo $url | cut -d/ -f3).txt
    echo $url | gau | tee -a $RESULTS_DIR/api/gau_$(echo $url | cut -d/ -f3).txt
done < $RESULTS_DIR/live_subdomains.txt

# 1️⃣1️⃣ WordPress Scanning
echo "[+] Running WPScan..."
while read url; do
    wpscan --url $url --enumerate vp,ap,u --api-token YOUR_WPSCAN_API_KEY -o "$RESULTS_DIR/wordpress/wpscan_$(echo $url | cut -d/ -f3).txt"
done < $RESULTS_DIR/live_subdomains.txt

# 1️⃣2️⃣ GraphQL Detection & Exploitation
echo "[+] Searching for GraphQL endpoints..."
while read url; do
    if curl -s "$url/graphql" | grep -q "GraphQL"; then
        echo "$url/graphql" | tee -a $RESULTS_DIR/graphql/endpoints.txt
        graphqlmap -u "$url/graphql" --json -o "$RESULTS_DIR/graphql/graphqlmap_$(echo $url | cut -d/ -f3).json"
    fi
done < $RESULTS_DIR/live_subdomains.txt

# 1️⃣3️⃣ Vulnerability Scanning
echo "[+] Running nuclei..."
nuclei -l $RESULTS_DIR/live_subdomains.txt -t cves/ -o $RESULTS_DIR/nuclei_cves.txt
nuclei -l $RESULTS_DIR/live_subdomains.txt -t misconfiguration/ -o $RESULTS_DIR/nuclei_misconfig.txt
nuclei -l $RESULTS_DIR/live_subdomains.txt -t vulnerabilities/ -o $RESULTS_DIR/nuclei_vulns.txt

# 🚀 Summary
echo "[+] Recon complete for: $DOMAIN"
echo "[+] Total subdomains: $(wc -l < $RESULTS_DIR/all_subdomains.txt)"
echo "[+] Live subdomains: $(wc -l < $RESULTS_DIR/live_subdomains.txt)"
echo "[+] Open ports: $(wc -l < $RESULTS_DIR/ports.txt)"
echo "[+] JS files: $(wc -l < $RESULTS_DIR/js-files/all_js.txt)"
echo "[+] API endpoints: $(wc -l < $RESULTS_DIR/api/wayback_*.txt)"
echo "[+] WordPress reports: $RESULTS_DIR/wordpress/"
echo "[+] GraphQL reports: $RESULTS_DIR/graphql/"
echo "[+] Screenshots saved in: $RESULTS_DIR/screenshots/"
echo "[+] Content Discovery: $RESULTS_DIR/content-discovery/"
echo "[+] Nuclei vulnerability results: $RESULTS_DIR/"

exit 0
