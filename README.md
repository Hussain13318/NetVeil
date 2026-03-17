# ⬡ NetVeil
> **OSINT & Threat Recon Intelligence Tool**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

NetVeil is an open-source OSINT (Open Source Intelligence) and threat reconnaissance CLI tool built for **security researchers, penetration testers, and bug bounty hunters**. It aggregates intelligence from multiple sources into a single, clean terminal interface — and optionally exports a full **HTML report**.

---

## Features

| Module | Description |
|---|---|
| **DNS Enumeration** | Queries A, AAAA, MX, NS, TXT, CNAME, SOA records |
| **WHOIS Lookup** | Registrar, creation/expiry dates, name servers, org info |
| **Subdomain Discovery** | Multi-threaded brute-force using a customisable wordlist |
| **IP Geolocation** | Country, city, ISP, ASN — no API key required |
| **SSL Analysis** | Certificate validity, issuer, SANs, expiry countdown |
| **VirusTotal Reputation** | Malicious/suspicious engine counts, risk rating |
| **Shodan Intelligence** | Open ports, services, OS fingerprint, known CVEs |
| **HTML Report** | Auto-generated dark-themed report saved locally |

---

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/NetVeil.git
cd NetVeil

# Install dependencies
pip install -r requirements.txt
```

> Runs natively on **Kali Linux**, Ubuntu, Windows, and macOS.

---

## Configuration (API Keys)

Use environment variables (recommended):

```bash
# Linux/macOS
export VIRUSTOTAL_API_KEY="your_key_here"
export SHODAN_API_KEY="your_key_here"

# Windows PowerShell
$env:VIRUSTOTAL_API_KEY="your_key_here"
$env:SHODAN_API_KEY="your_key_here"
```

You can also keep fallback values in `config.py`, but environment variables are safer for GitHub projects.

> Both APIs are **free**. VirusTotal gives 500 requests/day. Shodan free tier covers host lookups.

---

## Usage

```bash
# Run all modules
python netveil.py -t example.com --full

# Run specific modules
python netveil.py -t example.com --dns --whois --ssl

# Scan an IP address
python netveil.py -t 8.8.8.8 --geo --shodan

# Full scan + save HTML report
python netveil.py -t example.com --full --report

# Custom wordlist and thread count
python netveil.py -t example.com --subdomain --wordlist wordlists/subdomains.txt --threads 20
```

### All Flags

| Flag | Description |
|---|---|
| `-t`, `--target` | **Required.** Target domain or IP |
| `--dns` | DNS record enumeration |
| `--whois` | WHOIS lookup |
| `--subdomain` | Subdomain brute-force |
| `--geo` | IP geolocation |
| `--ssl` | SSL certificate analysis |
| `--vt` | VirusTotal reputation check |
| `--shodan` | Shodan host intelligence |
| `--full` | Run **all** modules |
| `--report` | Save HTML report to `reports/` |
| `--threads` | Thread count for subdomain scan (default: 15) |
| `--wordlist` | Custom wordlist path |

---

## Example Output

```
  _   _      _  __     __   _ _
 | \ | | ___| |_\ \   / /__(_) |
 |  \| |/ _ \ __\ \ / / _ \ | |
 | |\  |  __/ |_ \ V /  __/ | |
 |_| \_|\___|\__| \_/ \___|_|_|

      OSINT & Threat Recon Intelligence Tool
      Version 1.0

  [*] Target   : example.com
  [*] Timestamp: 2026-03-17 14:30:00

 ╭─ DNS Record Enumeration ──────────────────╮
  A       → 93.184.216.34
  MX      → 0 .
  NS      → a.iana-servers.net., b.iana-servers.net.
  TXT     → v=spf1 -all
 
 ╭─ SSL Certificate Analysis ────────────────╮
  Common Name     example.com
  Issued By       DigiCert Inc
  Valid Until     Nov 28 23:59:59 2026 GMT  [ 256 days remaining ]
  TLS Version     TLSv1.3
  Alt Names       example.com, www.example.com
```

---

## Project Structure

```
NetVeil/
├── netveil.py           # Main CLI entry point
├── config.py            # API key configuration
├── requirements.txt     # Python dependencies
├── modules/
│   ├── dns_enum.py      # DNS enumeration
│   ├── whois_lookup.py  # WHOIS lookup
│   ├── subdomain.py     # Subdomain discovery
│   ├── geo_ip.py        # IP geolocation
│   ├── ssl_check.py     # SSL analysis
│   ├── virustotal.py    # VirusTotal reputation
│   ├── shodan_scan.py   # Shodan intelligence
│   └── reporter.py      # HTML report generator
├── wordlists/
│   └── subdomains.txt   # Default subdomain wordlist
└── reports/             # Generated HTML reports
```

---

## Ethical Use

> **NetVeil is built for educational purposes and authorised security assessments only.**
> Always obtain proper written permission before scanning any system you do not own.
> Unauthorised scanning may be illegal in your jurisdiction.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Author

Built by **[Your Name]**
- GitHub: [@yourusername](https://github.com/yourusername)
- LinkedIn: [linkedin.com/in/yourprofile](https://linkedin.com/in/yourprofile)
