# 🔍 Web Vulnerability Scanner — Mini Project

> **Educational use only.** Only scan targets you own or have explicit written permission to test.

---

## 🚀 Quick Start

```bash
# Basic scan
python scanner.py example.com

# Full scan with HTML + JSON reports
python scanner.py example.com --export json html

# Skip port scanning (faster)
python scanner.py example.com --no-ports

# All options
python scanner.py example.com --no-ports --no-ssl --no-paths --export html --output-dir ./reports
```

**No external libraries required** — uses only Python standard library (`socket`, `ssl`, `urllib`, `concurrent.futures`).

---

## 🧩 Modules

| Module | What it checks |
|--------|---------------|
| **DNS Resolution** | Resolves hostname → IP address |
| **Port Scanner** | 17 common ports using concurrent TCP connect |
| **SSL/TLS Analyzer** | Protocol version, cipher, cert expiry, issuer |
| **HTTP Header Analyzer** | 7 security headers (HSTS, CSP, X-Frame-Options, etc.) |
| **Version Fingerprinting** | Apache, nginx, PHP, IIS, Tomcat, Express, etc. |
| **Cookie Security** | Checks HttpOnly, Secure, SameSite flags |
| **Path Probing** | 11 sensitive paths (`.env`, `.git`, `admin`, etc.) |
| **Report Generator** | Terminal + JSON + HTML exports |

---

## 📊 Severity Levels

| Level | Score Weight | Example |
|-------|-------------|---------|
| 🔴 CRITICAL | 40 pts | Expired SSL cert, `.git` exposed |
| 🟠 HIGH | 20 pts | Missing HSTS/CSP, outdated PHP, Telnet open |
| 🟡 MEDIUM | 10 pts | Missing X-Frame-Options, phpMyAdmin exposed |
| 🔵 LOW | 3 pts | Missing Referrer-Policy |
| ℹ️ INFO | 0 pts | robots.txt found, valid SSL |

---

## 🎓 Concepts Learned

- **Port scanning** — TCP connect scan using `socket.create_connection`
- **SSL/TLS** — Certificate parsing with Python's `ssl` module
- **HTTP Security Headers** — HSTS, CSP, X-Frame-Options explained
- **Information Disclosure** — How server banners leak version info
- **Entropy & Risk Scoring** — Weighted scoring model for risk prioritization
- **Concurrent scanning** — `ThreadPoolExecutor` for parallel port probing
- **Cryptography basics** — SSL certificate chain, cipher suites

---

## 📁 Output Example

```
Target    : https://example.com
IP        : 93.184.216.34
Open Ports: 80, 443
SSL/TLS   : TLSv1.3 | Expires in 182 days

[CRITICAL] Certificate EXPIRED
[HIGH    ] Missing header: Content-Security-Policy
[HIGH    ] Missing header: Strict-Transport-Security
[MEDIUM  ] Server version disclosed via X-Powered-By
[LOW     ] Missing header: Referrer-Policy
```

---

## ⚠️ Legal Notice

This tool is for **educational and authorized testing only**.  
Scanning systems without permission may violate laws including the Computer Fraud and Abuse Act (CFAA) and similar legislation worldwide.
