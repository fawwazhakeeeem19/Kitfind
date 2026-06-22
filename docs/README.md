# KitFind

```
 ██╗  ██╗██╗████████╗███████╗██╗███╗   ██╗██████╗
 ██║ ██╔╝██║╚══██╔══╝██╔════╝██║████╗  ██║██╔══██╗
 █████╔╝ ██║   ██║   █████╗  ██║██╔██╗ ██║██║  ██║
 ██╔═██╗ ██║   ██║   ██╔══╝  ██║██║╚██╗██║██║  ██║
 ██║  ██╗██║   ██║   ██║     ██║██║ ╚████║██████╔╝
 ╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝
```

**Security Reconnaissance Tool** — CLI & TUI interface for authorized security assessment.

> ⚠️ **AUTHORIZED USE ONLY.** Only scan systems you own or have explicit written permission to assess. Unauthorized scanning is illegal.

---

## Features

| Module | Description |
|--------|-------------|
| `scan` | Full security scan — DNS + SSL + HTTP + Tech fingerprinting |
| `dns` | DNS records, subdomain enumeration, propagation check |
| `ssl` | TLS certificate inspection, cipher suite analysis |
| `http` | Security headers, CSP, cookie security |
| `tech` | Technology stack fingerprinting (50+ signatures) |
| `report` | Export reports in HTML, JSON, CSV, TXT |
| `tui` | Interactive terminal UI |

---

## Installation

### From Source (Recommended)

```bash
# Prerequisites: Go 1.21+
git clone https://github.com/kitfind/kitfind.git
cd kitfind

# Install (builds and copies to /usr/local/bin)
chmod +x scripts/install.sh
./scripts/install.sh

# Or build only (no install)
./scripts/install.sh --no-install
./kitfind --help
```

### Docker

```bash
# Build
docker build -f docker/Dockerfile -t kitfind .

# Run
docker run --rm kitfind scan example.com

# With docker-compose
cd docker && docker compose run kitfind scan example.com
```

### Cross-Platform Build

```bash
# Build for all platforms
./scripts/build.sh

# Binaries in ./dist/
ls dist/
# kitfind-linux-amd64
# kitfind-linux-arm64
# kitfind-darwin-amd64
# kitfind-darwin-arm64
# kitfind-windows-amd64.exe
```

---

## Usage

### Full Security Scan

```bash
kitfind scan example.com
kitfind scan example.com --timeout 60
kitfind scan example.com --json | jq .risk_score
```

### DNS Analysis

```bash
# Basic DNS records
kitfind dns example.com

# With subdomain enumeration
kitfind dns example.com --subdomains

# With propagation check
kitfind dns example.com --propagation

# All features
kitfind dns example.com --subdomains --propagation
```

### SSL/TLS Inspection

```bash
kitfind ssl example.com
kitfind ssl example.com --json
```

### HTTP Security Headers

```bash
kitfind http example.com
kitfind http https://example.com --json
```

### Technology Fingerprinting

```bash
kitfind tech example.com
kitfind tech example.com --json
```

### Report Generation

```bash
# HTML report (default)
kitfind report example.com

# JSON report
kitfind report example.com -f json

# CSV findings export
kitfind report example.com -f csv

# Plain text report
kitfind report example.com -f txt

# Custom output directory
kitfind report example.com -f html -o /tmp/reports
```

### Interactive TUI

```bash
kitfind tui
```

**TUI Keyboard Shortcuts:**

| Key | Action |
|-----|--------|
| `↑`/`↓` or `k`/`j` | Navigate menu |
| `Enter` | Select / confirm |
| `s` | Open Scan screen |
| `d` | DNS Analysis view |
| `l` | SSL Review view |
| `h` | HTTP Headers view |
| `t` | Technology Fingerprint view |
| `r` | Scan history |
| `?` | Help screen |
| `q` / `Esc` | Back / quit |
| `Ctrl+C` | Exit |

---

## Python Analysis Module

For supplementary analysis:

```bash
# Install Python dependencies
pip3 install -r modules/python/requirements.txt

# Run Python analyzer
python3 modules/python/analyzer.py example.com
python3 modules/python/analyzer.py example.com --module dns
python3 modules/python/analyzer.py example.com --json
```

---

## Project Structure

```
kitfind/
├── cmd/
│   └── kitfind/
│       └── main.go          # CLI entrypoint, all commands
├── internal/
│   ├── dns/
│   │   └── dns.go           # DNS analysis & subdomain enumeration
│   ├── ssl/
│   │   └── ssl.go           # TLS certificate inspection
│   ├── http/
│   │   └── http.go          # HTTP header & cookie analysis
│   ├── fingerprint/
│   │   └── fingerprint.go   # Technology detection (50+ signatures)
│   ├── scanner/
│   │   └── scanner.go       # Scan orchestration & risk scoring
│   ├── report/
│   │   └── report.go        # HTML, JSON, CSV, TXT report generation
│   ├── tui/
│   │   └── tui.go           # Bubbletea interactive TUI
│   └── output/
│       └── output.go        # CLI output rendering
├── modules/
│   └── python/
│       ├── analyzer.py      # Python supplementary analysis
│       └── requirements.txt
├── configs/
│   └── kitfind.yaml         # Default configuration
├── tests/
│   └── unit/                # Unit & integration tests
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── scripts/
│   ├── install.sh           # Installation script
│   └── build.sh             # Cross-platform build script
├── docs/
│   └── README.md            # This file
└── .github/
    └── workflows/
        └── ci.yml           # GitHub Actions CI/CD
```

---

## Module Documentation

### `internal/dns` — DNS Analysis
- Concurrent query for A, AAAA, MX, NS, TXT, CNAME, SOA, CAA records
- Common subdomain wordlist enumeration (50+ prefixes)
- Global DNS propagation check (7 resolvers across US/EU/Asia)
- SPF and DMARC email security record parsing

### `internal/ssl` — TLS Inspection
- TLS 1.0/1.1/1.2/1.3 version detection
- Certificate chain parsing
- Expiry tracking with early warning (30-day threshold)
- Vulnerability detection (POODLE, BEAST, SWEET32, RC4)
- Grading: A+ / A / B / C / F

### `internal/http` — HTTP Analysis
- Security header presence and configuration scoring
- Content Security Policy directive parsing and risk analysis
- Cookie security attribute auditing (Secure, HttpOnly, SameSite)
- CORS configuration review
- Server/technology disclosure detection
- Redirect chain tracking

### `internal/fingerprint` — Technology Detection
50+ technology signatures across:
- Web Servers: Nginx, Apache, IIS, Caddy
- CDN: Cloudflare, Fastly, AWS CloudFront
- CMS: WordPress, Drupal, Joomla, Ghost
- E-commerce: Shopify, WooCommerce, Magento
- JS Frameworks: React, Vue.js, Angular, Next.js, Nuxt.js, Svelte
- Backend: Laravel, Django, Ruby on Rails, Express.js
- Languages: PHP, ASP.NET
- Libraries: jQuery, Bootstrap, Tailwind CSS
- Analytics: Google Analytics, Google Tag Manager

### `internal/scanner` — Orchestration
- Module pipeline management
- Risk scoring: 0–100 (higher = more risk)
- Risk grading: A (0-19) → B (20-39) → C (40-59) → D (60-79) → F (80-100)
- Concurrent module execution

### `internal/report` — Report Generation
- **HTML**: Styled dark-theme report with full findings
- **JSON**: Machine-readable complete scan data
- **CSV**: Flat findings export for spreadsheet import
- **TXT**: Plain-text report for offline review

### `internal/tui` — Terminal UI
Built with [Bubbletea](https://github.com/charmbracelet/bubbletea) + [Lipgloss](https://github.com/charmbracelet/lipgloss):
- Multi-screen navigation with sidebar
- Live scan progress log
- Per-module result views
- In-session scan history

---

## Configuration

Config file locations (searched in order):
1. `./configs/kitfind.yaml`
2. `~/.kitfind/kitfind.yaml`
3. `/etc/kitfind/kitfind.yaml`

Environment variables: prefix `KITFIND_` (e.g. `KITFIND_SCANNER_TIMEOUT=60s`)

---

## Running Tests

```bash
# Unit tests only (no network required)
go test -short ./tests/unit/...

# All tests (requires internet)
go test -v ./tests/unit/...

# With race detector
go test -race ./tests/unit/...

# With coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

---

## Legal

This tool is intended for:
- System administrators assessing their own infrastructure
- Bug bounty hunters with explicit program authorization
- Penetration testers with signed statements of work

**Do not use this tool on systems without explicit written authorization.**

---

*KitFind v1.0.0 — Built with Go 1.22*
