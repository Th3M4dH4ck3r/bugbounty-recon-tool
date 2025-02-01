# Bug Bounty Recon Tool

🚀 **The Ultimate Bug Bounty Recon Tool**  
This tool automates bug bounty reconnaissance with the following features:
- Subdomain enumeration (`subfinder`, `amass`, `crt.sh`, `puredns`)
- Live subdomain checking (`httpx`)
- Port scanning (`naabu`)
- Screenshot capturing (`gowitness`)
- Content discovery (`gobuster`, `dirsearch`)
- Vulnerability scanning (`nuclei`)
- JavaScript enumeration (`katana`, `getJS`)
- Parameter discovery (`ParamSpider`)
- WordPress scanning (`wpscan`)
- API discovery (`waybackurls`, `gau`)
- GraphQL detection & exploitation (`graphqlmap`)

---

## Usage

### **Install Required Tools**
Ensure you have the following tools installed:
- `subfinder`
- `amass`
- `crt.sh` integration
- `puredns`
- `httpx`
- `naabu`
- `gowitness`
- `gobuster`
- `dirsearch`
- `katana`
- `getJS`
- `ParamSpider`
- `wpscan`
- `nuclei`
- `graphqlmap`

### **Run the Script**
```bash
./bugbounty_recon.sh <target-domain>
