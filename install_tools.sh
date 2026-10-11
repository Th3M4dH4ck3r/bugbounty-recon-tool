#!/bin/bash
# Bug Bounty Recon Tool - Automated Installer
# Installs all required tools for comprehensive reconnaissance

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║       🛠️  BUG BOUNTY RECON TOOL - INSTALLER  🛠️              ║"
echo "║                                                              ║"
echo "║          Installing all required tools...                    ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "⚠️  Don't run as root! Run as normal user and we'll use sudo when needed."
   exit 1
fi

# Create tools directory
TOOLS_DIR=~/tools/bin
mkdir -p $TOOLS_DIR

echo "[1/15] Installing Go (if not already installed)..."
if ! command -v go &> /dev/null; then
    echo "  → Installing Go..."
    sudo apt update && sudo apt install -y golang-go
else
    echo "  ✅ Go already installed"
fi

# Add Go bin to PATH if not already
if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
    echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
    export PATH=$PATH:$HOME/go/bin
fi

echo "[2/15] Installing subfinder (subdomain enumeration)..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "[3/15] Installing httpx (HTTP probe)..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

echo "[4/15] Installing nuclei (vulnerability scanner)..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo "[5/15] Installing naabu (port scanner)..."
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

echo "[6/15] Installing katana (web crawler)..."
go install github.com/projectdiscovery/katana/cmd/katana@latest

echo "[7/15] Installing waybackurls (archive URLs)..."
go install github.com/tomnomnom/waybackurls@latest

echo "[8/15] Installing gau (URL enumeration)..."
go install github.com/lc/gau/v2/cmd/gau@latest

echo "[9/15] Installing gobuster (directory brute-force)..."
sudo apt install -y gobuster || go install github.com/OJ/gobuster/v3@latest

echo "[10/15] Installing dirsearch (directory scanner)..."
if [ ! -d ~/tools/dirsearch ]; then
    cd ~/tools
    git clone https://github.com/maurosoria/dirsearch.git
    cd dirsearch
    pip3 install -r requirements.txt --user
else
    echo "  ✅ dirsearch already installed"
fi

echo "[11/15] Installing wpscan (WordPress scanner)..."
sudo apt install -y ruby ruby-dev
sudo gem install wpscan

echo "[12/15] Installing gowitness (screenshots)..."
go install github.com/sensepost/gowitness@latest

echo "[13/15] Installing amass (advanced subdomain enum)..."
go install -v github.com/owasp-amass/amass/v4/...@master

echo "[14/15] Installing ParamSpider (parameter discovery)..."
if [ ! -d ~/tools/ParamSpider ]; then
    cd ~/tools
    git clone https://github.com/devanshbatham/ParamSpider
    cd ParamSpider
    pip3 install -r requirements.txt --user
else
    echo "  ✅ ParamSpider already installed"
fi

echo "[15/15] Installing graphqlmap (GraphQL exploitation)..."
if [ ! -d ~/tools/graphqlmap ]; then
    cd ~/tools
    git clone https://github.com/swisskyrepo/GraphQLmap
    cd GraphQLmap
    pip3 install -r requirements.txt --user
else
    echo "  ✅ graphqlmap already installed"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║            ✅ INSTALLATION COMPLETE! ✅                       ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "📋 Installed Tools:"
echo "  ✅ subfinder    - Subdomain enumeration"
echo "  ✅ amass        - Advanced subdomain discovery"
echo "  ✅ httpx        - HTTP probing"
echo "  ✅ naabu        - Port scanning"
echo "  ✅ nuclei       - Vulnerability scanning"
echo "  ✅ katana       - Web crawling"
echo "  ✅ waybackurls  - Archive URL discovery"
echo "  ✅ gau          - URL enumeration"
echo "  ✅ gobuster     - Directory brute-forcing"
echo "  ✅ dirsearch    - Directory scanning"
echo "  ✅ wpscan       - WordPress scanning"
echo "  ✅ gowitness    - Screenshot capture"
echo "  ✅ ParamSpider  - Parameter discovery"
echo "  ✅ graphqlmap   - GraphQL testing"
echo ""
echo "🚀 Usage:"
echo "  cd ~/Scarif/bugbounty-recon-tool"
echo "  ./bugbounty_recon.sh target.com"
echo ""
echo "⚠️  Remember: Only scan targets you have permission to test!"
echo ""
echo "💡 Tip: Run 'source ~/.bashrc' to update your PATH"
