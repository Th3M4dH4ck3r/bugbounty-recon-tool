# 🎯 Bug Bounty Recon Tool - Setup Guide

## Location
`~/Scarif/bugbounty-recon-tool/`

---

## 🚀 Quick Start

### Option 1: Automated Installation (Recommended)
```bash
cd ~/Scarif/bugbounty-recon-tool
./install_tools.sh
```

This will install ALL required tools automatically (~15-20 minutes).

### Option 2: Manual Installation
Install tools individually:
```bash
# Go-based tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# ... (see install_tools.sh for complete list)
```

---

## 📦 What Gets Installed

| Tool | Purpose | Language |
|------|---------|----------|
| **subfinder** | Subdomain enumeration | Go |
| **amass** | Advanced subdomain discovery | Go |
| **httpx** | HTTP probing | Go |
| **naabu** | Port scanning | Go |
| **nuclei** | Vulnerability scanning | Go |
| **katana** | Web crawling | Go |
| **waybackurls** | Archive URL discovery | Go |
| **gau** | URL enumeration | Go |
| **gobuster** | Directory brute-forcing | Go |
| **dirsearch** | Directory scanning | Python |
| **wpscan** | WordPress scanning | Ruby |
| **gowitness** | Screenshot capture | Go |
| **ParamSpider** | Parameter discovery | Python |
| **graphqlmap** | GraphQL testing | Python |

---

## 🎯 Usage

### Basic Scan
```bash
cd ~/Scarif/bugbounty-recon-tool
./bugbounty_recon.sh example.com
```

### Advanced Options
```bash
# With custom options
./bugbounty_recon.sh -r 100 -d 2 example.com

# Options:
#   -r <rate>   Rate limit (requests/sec)
#   -d <delay>  Delay between tools (seconds)
#   -h          Show help
```

### Results
Results are saved to: `./recon-results/<domain>/`

Structure:
```
recon-results/
└── example.com/
    ├── subfinder.txt          # Subdomains from subfinder
    ├── amass.txt              # Subdomains from amass
    ├── live_subdomains.txt    # Active subdomains
    ├── ports.txt              # Open ports
    ├── screenshots/           # Screenshot captures
    ├── content-discovery/     # Discovered directories
    ├── nuclei_*.txt           # Vulnerability findings
    ├── js-files/              # JavaScript files
    ├── api/                   # API endpoints
    └── graphql/               # GraphQL endpoints
```

---

## 🔍 What It Does

### Phase 1: Subdomain Enumeration
- Runs **subfinder**, **amass**, and **crt.sh**
- Combines and deduplicates results
- Probes live subdomains with **httpx**

### Phase 2: Port Scanning
- Scans live hosts with **naabu**
- Identifies open ports and services

### Phase 3: Screenshot Capture
- Takes screenshots of live web services
- Uses **gowitness**

### Phase 4: Content Discovery
- Directory brute-forcing with **gobuster** and **dirsearch**
- Finds hidden endpoints

### Phase 5: JavaScript Analysis
- Enumerates JS files with **katana** and **getJS**
- Extracts potential endpoints and secrets

### Phase 6: Vulnerability Scanning
- Runs **nuclei** with all templates
- Checks for known vulnerabilities

### Phase 7: Parameter Discovery
- Uses **ParamSpider** to find parameters
- Discovers potential injection points

### Phase 8: WordPress Scanning
- Detects WordPress sites
- Runs **wpscan** on WP targets

### Phase 9: API Discovery
- Uses **waybackurls** and **gau**
- Finds historical API endpoints

### Phase 10: GraphQL Detection
- Identifies GraphQL endpoints
- Tests with **graphqlmap**

---

## ⚠️ Legal Notice

**IMPORTANT**: Only use this tool on:
- Targets you OWN
- Bug bounty programs where you're authorized
- Systems you have WRITTEN PERMISSION to test

**Unauthorized scanning is ILLEGAL!**

---

## 💡 Pro Tips

1. **Start with passive recon** - Use subfinder/amass first
2. **Respect rate limits** - Don't hammer targets
3. **Use VPN** - Consider OpSec
4. **Check scope** - Always verify bug bounty program scope
5. **Take notes** - Document findings as you go
6. **Report responsibly** - Follow disclosure guidelines

---

## 🐛 Troubleshooting

**"Command not found" errors:**
```bash
source ~/.bashrc  # Reload PATH
```

**Go tools not working:**
```bash
echo $PATH | grep go/bin  # Check if Go bin is in PATH
export PATH=$PATH:$HOME/go/bin  # Add if missing
```

**Permission errors:**
```bash
chmod +x bugbounty_recon.sh
chmod +x install_tools.sh
```

---

## 📚 Resources

- **Bug Bounty Platforms:**
  - HackerOne: https://hackerone.com
  - Bugcrowd: https://bugcrowd.com
  - Intigriti: https://intigriti.com
  - YesWeHack: https://yeswehack.com

- **Learning:**
  - OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
  - PortSwigger Academy: https://portswigger.net/web-security
  - HackTricks: https://book.hacktricks.xyz/

---

## 🔄 Updates

To update installed tools:
```bash
# Update Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# etc...

# Update git-based tools
cd ~/tools/dirsearch && git pull
cd ~/tools/ParamSpider && git pull
cd ~/tools/GraphQLmap && git pull
```

---

**Happy Hunting! 🎯**

*Remember: With great power comes great responsibility. Hunt bugs, not trouble!*
