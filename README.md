<div align="center">

```
 ██╗  ██╗██╗████████╗███████╗██╗███╗   ██╗██████╗
 ██║ ██╔╝██║╚══██╔══╝██╔════╝██║████╗  ██║██╔══██╗
 █████╔╝ ██║   ██║   █████╗  ██║██╔██╗ ██║██║  ██║
 ██╔═██╗ ██║   ██║   ██╔══╝  ██║██║╚██╗██║██║  ██║
 ██║  ██╗██║   ██║   ██║     ██║██║ ╚████║██████╔╝
 ╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝
```

### Security Reconnaissance Tool — CLI & TUI

**DNS Recon • SSL/TLS Review • HTTP Security Headers • Tech Fingerprinting • Risk Scoring**

[![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](#installation)
[![CI](https://img.shields.io/github/actions/workflow/status/kitfind/kitfind/ci.yml?branch=main&label=CI)](.github/workflows/ci.yml)
[![Authorized Use Only](https://img.shields.io/badge/Use-Authorized%20Only-red)](#-legal--ethical-use)

[Installation](#-installation) •
[Usage](#-usage) •
[Modules](#-modules) •
[TUI](#-interactive-tui) •
[Contributing](#-contributing)

</div>

---

## ⚠️ Legal & Ethical Use

**KitFind is built exclusively for authorized security assessment.** Only run this tool against:

- Infrastructure **you own**
- Targets with **explicit written permission** (e.g. bug bounty programs, signed pentest scope)

This project intentionally **does not implement** exploitation, brute-force, credential attacks, payload delivery, or any offensive capability. It is a **reconnaissance and observation** tool only — built in the spirit of Nmap, Lynis, and Gobuster, but scoped strictly to passive/defensive analysis.

Unauthorized scanning of systems you don't own or have permission to test may violate computer misuse laws in your jurisdiction.

---

## ✨ Features

| Category | Capability |
|---|---|
| **DNS Recon** | A/AAAA/MX/NS/TXT/CNAME/SOA/CAA records, subdomain enumeration, global propagation check (7 resolvers), SPF/DMARC parsing |
| **SSL/TLS Review** | Certificate chain inspection, expiry tracking, cipher suite analysis, vulnerability detection (POODLE/BEAST/SWEET32/RC4), A+–F grading |
| **HTTP Security** | 8 security header checks (HSTS, CSP, X-Frame-Options, etc.), cookie security audit, CORS review, redirect chain tracing |
| **Tech Fingerprinting** | 50+ signatures — web servers, CMS, JS frameworks, CDNs, analytics, e-commerce platforms |
| **Risk Scoring** | Aggregated 0–100 risk score with A–F grade across all findings |
| **Reporting** | Export to HTML (styled), JSON, CSV, or plain text |
| **Dual Interface** | Full-featured CLI **and** an interactive terminal UI (TUI) |
| **Cross-Platform** | Single static binary for Linux, macOS, and Windows |

--- 

## 📦 Installation

### Prerequisites

- [Go 1.21+](https://go.dev/dl/)
- (Optional) Python 3.8+ for supplementary analysis modules

### Build from Source

```bash
git clone https://github.com/fawwazhakeeeem19/Kitfind
cd kitfind

go mod tidy
go build -o kitfind ./cmd/kitfind/

./kitfind --help
```

### One-Step Install Script

```bash
chmod +x scripts/install.sh
./scripts/install.sh          # builds + installs to /usr/local/bin

./scripts/install.sh --no-install   # build only, skip system install
```

### Cross-Platform Build

```bash
./scripts/build.sh
# Output binaries in ./dist/
#   kitfind-linux-amd64
#   kitfind-linux-arm64
#   kitfind-darwin-amd64
#   kitfind-darwin-arm64
#   kitfind-windows-amd64.exe
```

### Docker

```bash
docker build -f docker/Dockerfile -t kitfind .
docker run --rm kitfind scan example.com

# or with docker-compose
cd docker && docker compose run kitfind scan example.com
```

### Makefile Shortcuts

```bash
make build        # build for current OS
make install       # build + install to /usr/local/bin
make test          # run unit tests (no network)
make cross         # cross-platform build
make docker-build  # build Docker image
```

---

## 🚀 Usage

### Quick Start — Full Scan

```bash
kitfind scan example.com
```

Runs DNS + SSL + HTTP + Technology fingerprinting in one pass and prints an aggregated risk score.

### Module-Specific Commands

```bash
 DNS reconnaissance
kitfind dns example.com
kitfind dns example.com --subdomains
kitfind dns example.com --propagation
kitfind dns example.com --subdomains --propagation

 SSL/TLS certificate inspection
kitfind ssl example.com

 HTTP security header analysis
kitfind http example.com

 Technology stack fingerprinting
kitfind tech example.com

 Generate a report
kitfind report example.com -f html
kitfind report example.com -f json
kitfind report example.com -f csv
kitfind report example.com -f txt
kitfind report example.com -f html -o ./my-reports
```

### Global Flags

| Flag | Description |
|---|---|
| `--json` | Output raw JSON instead of formatted text |
| `--quiet` | Suppress the ASCII banner |
| `--timeout <seconds>` | Per-module timeout (default: 30) |
| `-h, --help` | Show help for any command |

### Scripting Example

```bash
!/bin/bash
domains=("site1.com" "site2.com" "site3.com")

for d in "${domains[@]}"; do
  kitfind scan "$d" --json --quiet > "results-$d.json"
done
```

---

## 🖥️ Interactive TUI

Launch a full-screen terminal dashboard with sidebar navigation, built with [Bubbletea](https://github.com/charmbracelet/bubbletea):

```bash
kitfind tui
```

| Key | Action |
|---|---|
| `↑↓` / `j k` | Navigate menu |
| `Enter` | Select |
| `s` | Scan screen |
| `d` | DNS analysis view |
| `l` | SSL review view |
| `h` | HTTP headers view |
| `t` | Tech fingerprint view |
| `r` | Scan history |
| `?` | Help |
| `q` / `Esc` | Back / quit |

---

## 🧩 Modules

```
kitfind/
├── cmd/kitfind/              
├── internal/
│   ├── dns/                  
│   ├── ssl/                  
│   ├── http/                 
│   ├── fingerprint/          
│   ├── scanner/              
│   ├── report/              
│   ├── tui/                  
│   └── output/               
├── modules/python/          
├── configs/                 
├── tests/unit/               
├── docker/                   
├── scripts/                 
└── .github/workflows/        
```

| Module | Responsibility |
|---|---|
| `internal/dns` | Concurrent DNS queries, 50+ subdomain wordlist, global propagation across 7 resolvers (US/EU/RU/CN), SPF/DMARC parsing |
| `internal/ssl` | TLS handshake inspection, certificate chain parsing, expiry alerts, known-vulnerability detection |
| `internal/http` | Header presence & config scoring, CSP directive analysis, cookie attribute auditing, CORS review |
| `internal/fingerprint` | Pattern-matching against header/body/cookie signatures for servers, CMS, frameworks, CDNs |
| `internal/scanner` | Coordinates all modules, aggregates findings, computes overall risk score (0–100, A–F) |
| `internal/report` | Renders results into HTML (dark theme), JSON, CSV, or plain text |
| `internal/tui` | Multi-screen terminal dashboard with live scan progress |

---

## ⚙️ Configuration

Config file search order:

1. `./configs/kitfind.yaml`
2. `~/.kitfind/kitfind.yaml`
3. `/etc/kitfind/kitfind.yaml`

Environment variable override prefix: `KITFIND_` (e.g. `KITFIND_SCANNER_TIMEOUT=60s`)

```yaml
scanner:
  timeout: 30s
  max_concurrency: 30
  dns_resolvers:
    - "8.8.8.8:53"
    - "1.1.1.1:53"
report:
  output_dir: "./kitfind-reports"
```

---

## 🐍 Python Analysis Module

For supplementary cross-checks:

```bash
pip3 install -r modules/python/requirements.txt

python3 modules/python/analyzer.py example.com
python3 modules/python/analyzer.py example.com --module dns
python3 modules/python/analyzer.py example.com --json
```

---

## 🧪 Testing

```bash
 Unit tests only (no network required)
go test -short -v ./tests/unit/...

 Full suite (requires internet)
go test -v ./tests/unit/...

 With race detector
go test -race ./tests/unit/...

 Coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

---

## 🤝 Contributing

Contributions are welcome for **defensive and observational** features only. Please do not submit PRs that add:

- Exploitation or payload delivery
- Brute-force / credential attack logic
- Authentication bypass techniques
- Any automated attack capability

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Run `make test` and `make lint` before committing
4. Open a Pull Request describing the change and its purpose

---

## 📄 License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for details.

---

## 🙏 Acknowledgments

Built with: [Cobra](https://github.com/spf13/cobra) · [Bubbletea](https://github.com/charmbracelet/bubbletea) · [miekg/dns](https://github.com/miekg/dns) · [goquery](https://github.com/PuerkitoBio/goquery)

Inspired by the workflow and clarity of **Nmap**, **Lynis**, **Gobuster**, and **Metasploit**'s reconnaissance modules.

---

<div align="center">

**KitFind** — Built for defenders, by defenders.

</div>
