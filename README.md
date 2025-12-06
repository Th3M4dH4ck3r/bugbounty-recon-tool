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
- **CVE-2025-55182 Testing** - React Server Components RCE vulnerability scanner

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

### **Run the Main Recon Script**
```bash
./bugbounty_recon.sh <target-domain>
```

### **CVE-2025-55182 - React Server Components RCE Tester**

Test for CVE-2025-55182, a critical pre-authentication remote code execution vulnerability in React Server Components (versions 19.0.0 - 19.2.0).

#### **Affected Packages:**
- `react-server-dom-webpack`
- `react-server-dom-turbopack`
- `react-server-dom-parcel`

#### **Usage:**
```bash
# Test a single target
python3 cve-2025-55182.py -u https://target.com

# Test with custom endpoint
python3 cve-2025-55182.py -u https://target.com -p /api/server-action

# Test multiple targets from file
python3 cve-2025-55182.py -l targets.txt

# Fingerprint only (no exploit payloads)
python3 cve-2025-55182.py -u https://target.com --fingerprint-only

# Use proxy (e.g., Burp Suite)
python3 cve-2025-55182.py -u https://target.com --proxy http://127.0.0.1:8080

# Verbose output
python3 cve-2025-55182.py -u https://target.com -v
```

#### **Features:**
- 🔍 Automatic fingerprinting of React Server Components
- 🎯 Version detection for vulnerable packages
- 🔎 Automatic endpoint discovery
- 🧪 Safe deserialization testing
- 📊 Detailed vulnerability reporting
- 🚀 Multi-threaded batch testing
- 🔐 Proxy support for traffic inspection

#### **Reference:**
- CVE: CVE-2025-55182
- Advisory: https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components

---

## **Disclaimer**

⚠️ **IMPORTANT**: This toolkit is intended for authorized security testing only. Always ensure you have explicit permission before testing any target. Unauthorized access to computer systems is illegal
