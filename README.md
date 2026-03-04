# VibeCrack

Open source security scanner for web applications. Scan your sites for vulnerabilities in seconds.

## Quick Start

```bash
pip install vibecrack
vibecrack https://your-site.com
```

That's it. No accounts, no config files, no Docker.

## What It Scans

VibeCrack runs 15 security scanners against your target:

| Scanner | What it checks |
|---------|---------------|
| **Crawler** | Discovers pages, forms, parameters, JS files, API endpoints |
| **Recon** | Technology detection, HTTP methods, cookies |
| **Subdomains** | DNS brute-force + Certificate Transparency logs |
| **SSL/TLS** | Certificate validity, TLS versions, HTTPS redirect |
| **Headers** | HSTS, CSP, X-Frame-Options, and other security headers |
| **Secrets** | API keys, tokens, credentials exposed in JavaScript |
| **Directories** | Sensitive files (.env, .git, admin panels) |
| **XSS** | Reflected cross-site scripting in forms and URL params |
| **SQLi** | Error-based, blind boolean, and time-based SQL injection |
| **CSRF** | Missing CSRF token protection |
| **SSRF** | Server-side request forgery with OAST |
| **Endpoints** | API discovery and authentication testing |
| **Access Control** | BOLA, BFLA, and IDOR vulnerabilities |
| **XSS Browser** | Confirmed XSS with headless Chromium (requires `[full]`) |
| **ZAP** | OWASP ZAP passive scanning (requires ZAP running) |

## Usage

```bash
# Full scan
vibecrack https://example.com

# Quick scan (SSL + headers + recon only)
vibecrack https://example.com --quick

# Pick specific modules
vibecrack https://example.com --modules ssl,headers,xss,sqli

# Export results
vibecrack https://example.com --json results.json
vibecrack https://example.com --html report.html
vibecrack https://example.com --pdf report.pdf

# Verbose output
vibecrack https://example.com -v
```

## Output

VibeCrack gives you:

- **Terminal** - Real-time progress with colored findings and a score table
- **JSON** - Machine-readable results (auto-saved if no output specified)
- **HTML** - Self-contained dark-themed report you can share
- **PDF** - Professional report (requires `pip install vibecrack[full]`)

## Scoring

Every scan produces a security score from 0 to 100 with grades A+ through F, broken down by category:

- SSL/TLS (15%)
- Security Headers (15%)
- Injection (20%)
- Authentication (15%)
- Secrets Exposure (15%)
- Configuration (10%)
- Information Disclosure (10%)

## AI Analysis

Set your Anthropic API key to get AI-powered analysis and exploit verification:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
vibecrack https://example.com
```

## Install Extras

```bash
# Full install (PDF reports, deep TLS, browser XSS, AI analysis)
pip install vibecrack[full]
```

## Safe by Design

- **Circuit breaker** prevents accidental DoS against your target
- **Rate limiting** between requests (configurable delay)
- **Non-destructive** testing only - no data modification
- **Same-domain filtering** - won't scan third-party endpoints

## VibeCrack Cloud

Want dashboards, scan history, team features, and scheduled scans without any setup?

**[Try VibeCrack Cloud](https://vibecrack.com)**

## License

MIT
