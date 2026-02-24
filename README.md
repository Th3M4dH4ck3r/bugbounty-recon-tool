# Bug Bounty Recon Tool

**The Ultimate Bug Bounty Recon Tool for Penetration Testers**

A fully automated reconnaissance pipeline that chains together the best open-source tools for bug bounty hunting. Run a single command against a target domain and get subdomains, live hosts, open ports, screenshots, JS files, API endpoints, vulnerability scans, and more — all organized in a clean results directory.

---

## Features

| Phase | Tools | Description |
|-------|-------|-------------|
| Subdomain Enumeration | `subfinder`, `amass`, `crt.sh` | Passive subdomain discovery from multiple sources |
| Subdomain Brute-Force | `puredns` | DNS brute-forcing with fresh resolvers |
| Live Host Detection | `httpx` | Probe subdomains and identify live web servers |
| Port Scanning | `naabu`, Shodan API | Discover open ports and exposed services |
| Screenshots | `gowitness` | Capture visual snapshots of all live hosts |
| Content Discovery | `gobuster`, `dirsearch` | Directory and file brute-forcing |
| JavaScript Enumeration | `katana`, `getJS` | Extract and collect JS files for analysis |
| Parameter Discovery | `ParamSpider` | Find URL parameters for injection testing |
| API Enumeration | `waybackurls`, `gau` | Historical URL and endpoint discovery |
| WordPress Scanning | `wpscan` | Detect WP vulnerabilities, plugins, and users |
| GraphQL Detection | `graphqlmap` | Find and enumerate GraphQL endpoints |
| Vulnerability Scanning | `nuclei` | Scan for CVEs, misconfigs, and known vulns |

---

## Installation

### Clone the repo

```bash
git clone https://github.com/Th3M4dH4ck3r/bugbounty-recon-tool.git
cd bugbounty-recon-tool
chmod +x bugbounty_recon.sh
```

### Required Tools

Install these tools before running. Most are available via `go install` or your package manager.

**Go-based tools:**

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/d3mondev/puredns/v2@latest
go install -v github.com/sensepost/gowitness@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
```

**Other tools:**

```bash
# Amass
go install -v github.com/owasp-amass/amass/v4/...@master

# Gobuster
go install github.com/OJ/gobuster/v3@latest

# dirsearch
pip3 install dirsearch

# getJS
go install github.com/003random/getJS/v2@latest

# ParamSpider
git clone https://github.com/devanshbatham/ParamSpider ~/tools/ParamSpider
pip3 install -r ~/tools/ParamSpider/requirements.txt

# WPScan
gem install wpscan

# graphqlmap
pip3 install graphqlmap
```

**Wordlists:**

The script uses SecLists by default. Install with:

```bash
sudo apt install seclists
```

Or clone manually:

```bash
git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

---

## Usage

```
Usage: ./bugbounty_recon.sh [options] <target-domain>

Options:
  -h, --help            Show help message
  -s, --shodan KEY      Shodan API key for host/port enumeration
  -w, --wp KEY          WPScan API key for vulnerability data
  -m, --monitor         Enable live progress monitoring dashboard
  -r, --rate-limit N    Rate limit requests (requests per second)
  -d, --delay N         Add delay between tools (seconds)
```

### Examples

**Basic scan:**

```bash
./bugbounty_recon.sh example.com
```

**Full scan with API keys:**

```bash
./bugbounty_recon.sh -s YOUR_SHODAN_KEY -w YOUR_WPSCAN_KEY example.com
```

**Stealth mode — rate limited with delays between tools:**

```bash
./bugbounty_recon.sh -r 10 -d 5 example.com
```

**Live monitoring dashboard:**

```bash
./bugbounty_recon.sh -m example.com
```

**All options combined:**

```bash
./bugbounty_recon.sh -s SHODAN_KEY -w WPSCAN_KEY -m -r 10 -d 3 example.com
```

---

## Output Structure

All results are saved to `results/<domain>/`:

```
results/example.com/
├── subfinder.txt              # Subfinder subdomains
├── amass.txt                  # Amass subdomains
├── crtsh.txt                  # crt.sh subdomains
├── puredns.txt                # Brute-forced subdomains
├── all_subdomains.txt         # Merged & deduplicated subdomains
├── live_subdomains.txt        # Confirmed live hosts
├── ports.txt                  # Open ports (naabu + Shodan)
├── shodan_results.json        # Raw Shodan data
├── shodan_ips.txt             # IPs from Shodan
├── nuclei_cves.txt            # CVE findings
├── nuclei_misconfig.txt       # Misconfiguration findings
├── nuclei_vulns.txt           # Vulnerability findings
├── screenshots/               # Gowitness screenshots
├── content-discovery/         # Gobuster & dirsearch results
│   ├── gobuster-*.txt
│   └── dirsearch-*.txt
├── js-files/                  # JavaScript files
│   ├── all_js.txt
│   └── getjs_*.txt
├── params/                    # ParamSpider results
├── api/                       # Waybackurls & gau results
│   ├── wayback_*.txt
│   └── gau_*.txt
├── wordpress/                 # WPScan reports
└── graphql/                   # GraphQL endpoints & enumeration
    ├── endpoints.txt
    └── graphqlmap_*.json
```

---

## Tool Availability

The script gracefully handles missing tools — if a tool isn't installed, it skips that phase and continues with the rest. You'll see `[!] toolname not found - skipping` messages for anything that's missing. This means you can run the script with only a subset of tools installed and still get useful results.

---

## Tips

- **API keys make a difference.** Shodan gives you port/service data you won't get from active scanning alone. WPScan's API provides detailed vulnerability data for WordPress plugins and themes.
- **Rate limiting is your friend.** Use `-r` to avoid getting blocked by WAFs and rate limiters. Use `-d` to space out tool execution.
- **Monitor mode** (`-m`) gives you a live dashboard showing progress across all phases — useful for long-running scans.
- **Run from a VPS** for better performance and to avoid scanning from your home IP.

---

## Disclaimer

This tool is intended for authorized security testing and bug bounty programs only. Always ensure you have written permission before testing any target. The authors are not responsible for any misuse of this tool.

---

## Author

**Th3M4dH4ck3r** — [GitHub](https://github.com/Th3M4dH4ck3r)
