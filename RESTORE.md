# Restore — bugbounty-recon-tool

See README.md → **Required Tools** for the full tool list. Quick path:

### Arch / Omarchy
```bash
sudo pacman -S --needed git github-cli go nmap jq python-pipx
gh repo clone Th3M4dH4ck3r/bugbounty-recon-tool ~/Scarif/bugbounty-recon-tool
go install github.com/projectdiscovery/pdtm/cmd/pdtm@latest && ~/go/bin/pdtm -ia   # subfinder, httpx, nuclei, katana, ...
yay -S --needed amass gobuster wpscan                                             # AUR / extra
```

### Ubuntu
```bash
sudo apt install -y git gh golang-go nmap jq pipx gobuster
gh repo clone Th3M4dH4ck3r/bugbounty-recon-tool ~/Scarif/bugbounty-recon-tool
go install github.com/projectdiscovery/pdtm/cmd/pdtm@latest && ~/go/bin/pdtm -ia
sudo snap install amass; sudo gem install wpscan
```
API keys (Shodan, WPScan) are passed as flags or come from `~/.secrets.env`. Never hardcode them in the script.
