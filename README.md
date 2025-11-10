# Scout - Smart Contract Security Scanner

**A comprehensive, modular security scanner for EVM smart contracts - your Swiss Army knife for bug bounty hunting**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Overview

Scout is a full-stack security analysis tool designed for smart contract bug bounty hunters. It combines multiple analysis techniques with automated PoC generation and professional reporting.

### Key Features

- 🔍 **Multi-Source Collection** - Etherscan, GitHub, local filesystem
- 🛡️ **Comprehensive Analysis** - Static rules, Slither, MythX, bytecode analysis
- ⚡ **Automated PoC Generation** - Hardhat & Foundry test templates
- 📊 **Professional Reporting** - Markdown, JSON with CVSS scoring
- 🔗 **Integrations** - Slack/Discord, REST API, GitHub Actions

---

## Quick Start

```bash
# Install
npm install && npm run build

# Analyze contracts
npm run dev -- analyze static --source ./contracts

# Generate PoCs  
npm run dev -- poc --input ./reports/findings.json --output ./pocs

# Create report
npm run dev -- report --input ./reports/findings.json --output ./reports/report.md
```

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `scout collect` | Collect contract sources from Etherscan/GitHub/local |
| `scout analyze` | Run static/dynamic/symbolic analysis |
| `scout poc` | Generate exploit PoCs |
| `scout report` | Generate security reports |
| `scout scan` | Complete workflow (collect → analyze → poc → report) |
| `scout server` | Start REST API server |

---

## Example Usage

### Analyze Local Contracts

```bash
scout scan --target ./contracts --output ./reports
```

### From Etherscan

```bash
export ETHERSCAN_API_KEY="your-key"
scout collect --target etherscan:0xContractAddress --network mainnet
scout analyze static --source ./sources
```

### With Docker

```bash
docker-compose build
docker-compose run scout scan --target ./contracts
```

---

## Sample Output

The tool detects vulnerabilities such as:

1. **Reentrancy** - HIGH severity
2. **Missing Access Control** - CRITICAL
3. **Integer Overflow** - HIGH
4. **tx.origin Authentication** - MEDIUM
5. **Unchecked External Calls** - MEDIUM

Each finding includes:
- Detailed description and impact
- Exact location (file:line)  
- Automated PoC script
- Fix recommendations
- References

---

## Configuration

Create `.env`:

```env
ETHERSCAN_API_KEY=your_key
MYTHX_API_KEY=your_mythx_key
ETHEREUM_RPC_URL=your_rpc_url
ALLOW_LIVE_TX=false
```

Add custom rules in `config/rules.yaml`:

```yaml
- id: CUSTOM-001
  name: Custom Vulnerability
  severity: high
  pattern: 'regex-pattern'
  recommendation: How to fix
```

---

## Testing

```bash
npm test                  # Run tests
npm run test:coverage    # With coverage
make demo                # Run demo workflow
```

---

## Security Notice

⚠️ **IMPORTANT**:
- All PoCs are simulated (safe by default)
- Never use ALLOW_LIVE_TX=true without understanding risks
- Follow responsible disclosure
- Test only on authorized targets

---

## Architecture

```
scout/
├── collectors/      # Source collection
├── analyzers/       # Security analysis
├── poc/             # PoC generation
├── report/          # Report generation
├── server/          # REST API
└── tests/           # Test suite
```

---

## API Server

```bash
scout server --port 3000
```

Endpoints:
- `POST /api/scan` - Start scan
- `GET /api/findings` - List findings
- `POST /api/poc/:id` - Generate PoC

---

## Contributing

1. Fork repository
2. Create feature branch
3. Add tests
4. Submit PR

See CONTRIBUTING.md for guidelines.

---

## License

MIT License

---

**Happy Bug Hunting! 🔍🛡️**
