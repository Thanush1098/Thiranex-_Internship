#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║        🔍  Web Vulnerability Scanner  (Mini)            ║
║        Educational use only — scan only targets         ║
║        you own or have explicit permission to test.      ║
╚══════════════════════════════════════════════════════════╝

Features:
  • HTTP Security Header analysis
  • SSL/TLS certificate checks
  • Open port detection (common web ports)
  • Software version fingerprinting
  • Cookie security flags check
  • Common misconfiguration detection
  • Directory traversal probe (safe)
  • Generates a colour-coded terminal report + JSON/HTML export
"""

import socket
import ssl
import json
import sys
import re
import time
import datetime
import argparse
import urllib.request
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Optional

# ── ANSI Colours ────────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    MAGENTA= "\033[95m"
    WHITE  = "\033[97m"
    DIM    = "\033[2m"

def clr(text, *codes): return "".join(codes) + str(text) + C.RESET

# ── Data Models ─────────────────────────────────────────────
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

@dataclass
class Finding:
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category: str
    title: str
    detail: str
    recommendation: str
    evidence: str = ""

@dataclass
class ScanResult:
    target: str
    timestamp: str
    duration: float
    resolved_ip: str = ""
    ssl_info: dict = field(default_factory=dict)
    open_ports: list = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

# ── Severity Helpers ─────────────────────────────────────────
SEV_COLOUR = {
    "CRITICAL": C.RED + C.BOLD,
    "HIGH":     C.RED,
    "MEDIUM":   C.YELLOW,
    "LOW":      C.BLUE,
    "INFO":     C.CYAN,
}

SEV_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "ℹ️ ",
}

def sev_label(s):
    return clr(f"[{s:^8}]", SEV_COLOUR.get(s, ""))

# ── Banner ───────────────────────────────────────────────────
BANNER = f"""
{C.CYAN}{C.BOLD}
  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██║   ██║██║   ██║██║     ████╗  ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║   ██║██║   ██║██║     ██╔██╗ ██║    ███████╗██║     ███████║██╔██╗ ██║
  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║    ╚════██║██║     ██╔══██║██║╚██╗██║
   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║    ███████║╚██████╗██║  ██║██║ ╚████║
    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{C.RESET}{C.DIM}           Web Vulnerability Scanner — Educational Edition v1.0{C.RESET}
"""

# ════════════════════════════════════════════════════════════
#  MODULE 1 — DNS / IP Resolution
# ════════════════════════════════════════════════════════════
def resolve_host(hostname: str) -> str:
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.gaierror:
        return "Unresolvable"

# ════════════════════════════════════════════════════════════
#  MODULE 2 — Port Scanner
# ════════════════════════════════════════════════════════════
COMMON_PORTS = {
    21: "FTP",   22: "SSH",   23: "Telnet",  25: "SMTP",
    53: "DNS",   80: "HTTP",  110: "POP3",   143: "IMAP",
    443: "HTTPS",445: "SMB",  3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}

RISKY_PORTS = {23, 21, 3389, 445, 6379, 27017}

def scan_port(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def scan_ports(host: str, ports: dict, result: ScanResult, findings: list):
    print(clr(f"\n[*] Scanning {len(ports)} common ports on {host}…", C.DIM))
    open_ports = []

    with ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(scan_port, host, port): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                service = ports[port]
                open_ports.append({"port": port, "service": service})
                icon = "⚠️ " if port in RISKY_PORTS else "✅"
                print(f"    {icon}  Port {clr(port, C.BOLD)} / {service} — {clr('OPEN', C.GREEN)}")

                if port in RISKY_PORTS:
                    sev = "HIGH" if port in {23, 3389, 6379, 27017} else "MEDIUM"
                    findings.append(Finding(
                        severity=sev,
                        category="Open Ports",
                        title=f"Risky port open: {port}/{service}",
                        detail=f"Port {port} ({service}) is publicly accessible. This service is commonly targeted by attackers.",
                        recommendation=f"Restrict access to port {port} using firewall rules. "
                                       f"{'Disable Telnet and use SSH instead.' if port==23 else ''}"
                                       f"{'Use VPN or IP whitelist for RDP.' if port==3389 else ''}"
                                       f"{'Redis should never be exposed publicly.' if port==6379 else ''}"
                                       f"{'MongoDB should be authenticated and firewalled.' if port==27017 else ''}",
                        evidence=f"TCP connect to {host}:{port} succeeded"
                    ))

    result.open_ports = sorted(open_ports, key=lambda x: x["port"])
    if not open_ports:
        print(clr("    No common ports found open.", C.DIM))

# ════════════════════════════════════════════════════════════
#  MODULE 3 — SSL/TLS Analysis
# ════════════════════════════════════════════════════════════
def check_ssl(hostname: str, result: ScanResult, findings: list):
    print(clr("\n[*] Checking SSL/TLS certificate…", C.DIM))
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            proto = s.version()
            cipher = s.cipher()

        # Parse expiry
        exp_str = cert.get("notAfter", "")
        exp_dt = None
        if exp_str:
            exp_dt = datetime.datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp_dt - datetime.datetime.utcnow()).days
        else:
            days_left = None

        # Subject
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer",  []))
        san     = [v for _, v in cert.get("subjectAltName", [])]

        result.ssl_info = {
            "protocol":   proto,
            "cipher":     cipher[0] if cipher else "Unknown",
            "expires":    exp_str,
            "days_left":  days_left,
            "subject_cn": subject.get("commonName", ""),
            "issuer_cn":  issuer.get("commonName",  ""),
            "san_count":  len(san),
        }

        print(f"    Protocol : {clr(proto, C.GREEN)}")
        print(f"    Cipher   : {clr(cipher[0] if cipher else '?', C.GREEN)}")
        print(f"    Expires  : {clr(exp_str, C.GREEN)}  ({days_left} days left)")
        print(f"    Issuer   : {clr(issuer.get('commonName','?'), C.GREEN)}")

        # Findings
        if days_left is not None:
            if days_left < 0:
                findings.append(Finding("CRITICAL","SSL/TLS","Certificate EXPIRED",
                    f"The SSL certificate expired {abs(days_left)} days ago.",
                    "Renew the SSL certificate immediately.",
                    f"notAfter: {exp_str}"))
            elif days_left < 14:
                findings.append(Finding("HIGH","SSL/TLS","Certificate expiring very soon",
                    f"Certificate expires in {days_left} days.",
                    "Renew the SSL certificate as soon as possible.",
                    f"notAfter: {exp_str}"))
            elif days_left < 30:
                findings.append(Finding("MEDIUM","SSL/TLS","Certificate expiring soon",
                    f"Certificate expires in {days_left} days.",
                    "Plan certificate renewal within the next two weeks.",
                    f"notAfter: {exp_str}"))

        if proto in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
            findings.append(Finding("HIGH","SSL/TLS",f"Outdated protocol: {proto}",
                f"{proto} is deprecated and has known vulnerabilities (POODLE, BEAST, etc.).",
                "Disable TLS 1.0/1.1 and enforce TLS 1.2 or TLS 1.3.",
                f"Negotiated protocol: {proto}"))

        findings.append(Finding("INFO","SSL/TLS","SSL/TLS certificate valid",
            f"Certificate is valid for {days_left} more days. Issuer: {issuer.get('commonName','?')}.",
            "Continue monitoring certificate expiry.",
            f"Protocol: {proto}, Cipher: {cipher[0] if cipher else '?'}"))

    except ssl.SSLCertVerificationError as e:
        findings.append(Finding("CRITICAL","SSL/TLS","SSL Certificate verification failed",
            str(e), "Fix the SSL certificate immediately.", str(e)))
        print(clr("    SSL verification FAILED — certificate may be self-signed or invalid.", C.RED))
    except (socket.timeout, ConnectionRefusedError, OSError):
        findings.append(Finding("INFO","SSL/TLS","HTTPS not available on port 443",
            "Port 443 is closed or unreachable.", "Enable HTTPS for all traffic.", ""))
        print(clr("    HTTPS not available (port 443 closed).", C.YELLOW))

# ════════════════════════════════════════════════════════════
#  MODULE 4 — HTTP Security Headers
# ════════════════════════════════════════════════════════════
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "desc": "HSTS is missing. Browsers won't enforce HTTPS, enabling downgrade attacks.",
        "rec": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "desc": "CSP is missing. The site is vulnerable to Cross-Site Scripting (XSS) attacks.",
        "rec": "Define a strict Content-Security-Policy header to whitelist trusted sources.",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "desc": "X-Frame-Options is missing. The site may be vulnerable to Clickjacking.",
        "rec": "Add: X-Frame-Options: DENY  or use CSP frame-ancestors directive.",
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "desc": "X-Content-Type-Options missing. Browsers may MIME-sniff responses.",
        "rec": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "desc": "Referrer-Policy missing. Sensitive URL data may leak to third parties.",
        "rec": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "desc": "Permissions-Policy missing. Browser features (camera, mic, GPS) are unrestricted.",
        "rec": "Add Permissions-Policy to disable unneeded browser features.",
    },
    "X-XSS-Protection": {
        "severity": "LOW",
        "desc": "X-XSS-Protection missing (legacy header, but still useful for older browsers).",
        "rec": "Add: X-XSS-Protection: 1; mode=block",
    },
}

LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator", "X-Runtime"]

VERSION_PATTERNS = [
    (re.compile(r"Apache[/ ]([\d.]+)", re.I), "Apache"),
    (re.compile(r"nginx[/ ]([\d.]+)", re.I), "nginx"),
    (re.compile(r"PHP[/ ]([\d.]+)", re.I), "PHP"),
    (re.compile(r"Express[/ ]([\d.]+)", re.I), "Express"),
    (re.compile(r"IIS[/ ]([\d.]+)", re.I), "IIS"),
    (re.compile(r"Tomcat[/ ]([\d.]+)", re.I), "Tomcat"),
    (re.compile(r"Django[/ ]([\d.]+)", re.I), "Django"),
    (re.compile(r"Rails[/ ]([\d.]+)", re.I), "Rails"),
]

def fetch_headers(url: str) -> tuple[int, dict, str]:
    """Returns (status_code, headers_dict, redirect_url)"""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VulnScanner/1.0 (Educational)"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.status, dict(resp.headers), resp.url
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), url
    except Exception:
        return 0, {}, url

def check_headers(base_url: str, result: ScanResult, findings: list):
    print(clr("\n[*] Analysing HTTP security headers…", C.DIM))
    status, headers, final_url = fetch_headers(base_url)
    result.headers = headers

    if status == 0:
        findings.append(Finding("HIGH","HTTP","Target unreachable",
            f"Could not connect to {base_url}.",
            "Verify the URL is correct and the server is running.", ""))
        print(clr("    Could not fetch headers — is the target reachable?", C.RED))
        return

    print(f"    HTTP Status : {clr(status, C.GREEN if 200<=status<300 else C.YELLOW)}")
    print(f"    Final URL   : {clr(final_url, C.CYAN)}")

    # Redirect HTTP→HTTPS check
    if base_url.startswith("http://"):
        if "https://" in final_url:
            findings.append(Finding("INFO","HTTP","HTTP redirects to HTTPS",
                "The server correctly redirects HTTP to HTTPS.",
                "Ensure HSTS is also set.", f"Redirected to {final_url}"))
        else:
            findings.append(Finding("HIGH","HTTP","No HTTPS redirect",
                "The server does not redirect HTTP to HTTPS.",
                "Configure the server to redirect all HTTP traffic to HTTPS.", ""))

    # Security headers
    header_keys_lower = {k.lower(): v for k, v in headers.items()}
    for hdr, meta in SECURITY_HEADERS.items():
        present = hdr.lower() in header_keys_lower
        if present:
            val = header_keys_lower[hdr.lower()]
            print(f"    {clr('✅', C.GREEN)} {hdr}: {clr(val[:80], C.DIM)}")
            findings.append(Finding("INFO","Security Headers",f"{hdr} present",
                f"Value: {val}", "Review the value for correctness.", f"{hdr}: {val}"))
        else:
            print(f"    {clr('❌', C.RED)} {hdr}: {clr('MISSING', C.RED)}")
            findings.append(Finding(meta["severity"],"Security Headers",
                f"Missing header: {hdr}", meta["desc"], meta["rec"], "Header not present in response"))

    # Leaky headers / version disclosure
    for hdr in LEAKY_HEADERS:
        val = header_keys_lower.get(hdr.lower(), "")
        if val:
            print(f"    {clr('⚠️ ', C.YELLOW)} {hdr}: {clr(val, C.YELLOW)}")
            findings.append(Finding("MEDIUM","Information Disclosure",
                f"Server version disclosed via {hdr}",
                f"The header '{hdr}: {val}' reveals server software details useful to attackers.",
                f"Remove or obscure the '{hdr}' response header.",
                f"{hdr}: {val}"))

    # Cookie analysis
    raw_cookies = [v for k, v in headers.items() if k.lower() == "set-cookie"]
    for cookie in raw_cookies:
        missing_flags = []
        if "HttpOnly" not in cookie:  missing_flags.append("HttpOnly")
        if "Secure"   not in cookie:  missing_flags.append("Secure")
        if "SameSite" not in cookie:  missing_flags.append("SameSite")
        if missing_flags:
            findings.append(Finding("MEDIUM","Cookies",
                f"Cookie missing flags: {', '.join(missing_flags)}",
                f"Cookie '{cookie[:60]}…' is missing security flags: {', '.join(missing_flags)}.",
                f"Set {', '.join(missing_flags)} flags on all cookies.",
                cookie[:120]))

# ════════════════════════════════════════════════════════════
#  MODULE 5 — Software Version Fingerprinting
# ════════════════════════════════════════════════════════════
# Simplified known-outdated version database (for demo)
OUTDATED_DB = {
    "Apache": {"safe": "2.4.58", "danger_below": "2.4.50"},
    "nginx":  {"safe": "1.25.3", "danger_below": "1.18.0"},
    "PHP":    {"safe": "8.2.0",  "danger_below": "7.4.0"},
    "IIS":    {"safe": "10.0",   "danger_below": "8.0"},
}

def check_versions(headers: dict, findings: list):
    print(clr("\n[*] Fingerprinting software versions…", C.DIM))
    all_vals = " ".join(headers.values())
    found_any = False

    for pattern, name in VERSION_PATTERNS:
        m = pattern.search(all_vals)
        if m:
            ver = m.group(1)
            found_any = True
            print(f"    Detected: {clr(name, C.BOLD)} {clr(ver, C.CYAN)}")

            db = OUTDATED_DB.get(name)
            if db:
                def ver_tuple(v):
                    try: return tuple(int(x) for x in v.split(".")[:3])
                    except: return (0,)
                if ver_tuple(ver) < ver_tuple(db["danger_below"]):
                    findings.append(Finding("HIGH","Outdated Software",
                        f"{name} version {ver} is significantly outdated",
                        f"Detected {name}/{ver}. Versions below {db['danger_below']} have known critical CVEs.",
                        f"Upgrade {name} to {db['safe']} or newer.",
                        f"Detected in headers: {name}/{ver}"))
                elif ver_tuple(ver) < ver_tuple(db["safe"]):
                    findings.append(Finding("MEDIUM","Outdated Software",
                        f"{name} version {ver} may be outdated",
                        f"Detected {name}/{ver}. Latest stable is {db['safe']}.",
                        f"Consider upgrading {name} to {db['safe']}.",
                        f"Detected in headers: {name}/{ver}"))
                else:
                    findings.append(Finding("INFO","Software Version",
                        f"{name}/{ver} appears up-to-date",
                        f"Detected version {ver} matches or exceeds recommended {db['safe']}.",
                        "Continue monitoring for new releases.", f"{name}/{ver}"))

    if not found_any:
        print(clr("    No version strings detected in headers (good practice).", C.GREEN))

# ════════════════════════════════════════════════════════════
#  MODULE 6 — Common Path Probes
# ════════════════════════════════════════════════════════════
SENSITIVE_PATHS = [
    ("/.env",             "HIGH",   "Environment file exposed — may contain secrets/API keys."),
    ("/.git/config",      "CRITICAL","Git repository exposed — source code may be downloadable."),
    ("/wp-login.php",     "MEDIUM", "WordPress login page detected."),
    ("/admin",            "MEDIUM", "Admin panel accessible without authentication check."),
    ("/phpmyadmin",       "HIGH",   "phpMyAdmin panel exposed publicly."),
    ("/server-status",    "MEDIUM", "Apache server-status exposed — reveals internal info."),
    ("/config.php",       "HIGH",   "Config file may be accessible."),
    ("/backup.zip",       "HIGH",   "Backup archive accessible — may contain sensitive data."),
    ("/robots.txt",       "INFO",   "robots.txt found — review for sensitive path disclosures."),
    ("/sitemap.xml",      "INFO",   "sitemap.xml found."),
    ("/.well-known/security.txt","INFO","security.txt found — good security practice."),
]

def probe_paths(base_url: str, findings: list):
    print(clr("\n[*] Probing sensitive paths…", C.DIM))
    base = base_url.rstrip("/")

    def probe(path_info):
        path, severity, desc = path_info
        url = base + path
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "VulnScanner/1.0 (Educational)"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                code = resp.status
        except urllib.error.HTTPError as e:
            code = e.code
        except Exception:
            code = 0
        return path, severity, desc, code

    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = [ex.submit(probe, p) for p in SENSITIVE_PATHS]
        for fut in as_completed(futures):
            path, severity, desc, code = fut.result()
            if code in (200, 301, 302, 403):
                icon = "⚠️ " if severity not in ("INFO",) else "ℹ️ "
                colour = C.RED if severity in ("CRITICAL","HIGH") else C.YELLOW if severity=="MEDIUM" else C.CYAN
                print(f"    {icon} [{clr(code, colour)}] {path} — {clr(desc[:60], C.DIM)}")
                findings.append(Finding(severity,"Path Probing",
                    f"Sensitive path accessible: {path}",
                    f"HTTP {code} — {desc}",
                    f"Restrict access to {path} via server config or firewall rules.",
                    f"GET {path} → HTTP {code}"))

# ════════════════════════════════════════════════════════════
#  REPORT GENERATOR
# ════════════════════════════════════════════════════════════
def severity_counts(findings):
    counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts

def risk_score(counts):
    return counts["CRITICAL"]*40 + counts["HIGH"]*20 + counts["MEDIUM"]*10 + counts["LOW"]*3 + counts["INFO"]*0

def risk_label(score):
    if score >= 80: return ("CRITICAL", C.RED + C.BOLD)
    if score >= 40: return ("HIGH",     C.RED)
    if score >= 20: return ("MEDIUM",   C.YELLOW)
    if score >= 5:  return ("LOW",      C.BLUE)
    return ("MINIMAL", C.GREEN)

def print_report(result: ScanResult):
    findings = sorted(result.findings, key=lambda f: -SEVERITY_ORDER.get(f.severity, 0))
    counts   = severity_counts(findings)
    score    = risk_score(counts)
    rlabel, rcolour = risk_label(score)

    sep = clr("═" * 65, C.DIM)
    print(f"\n{sep}")
    print(clr(f"  📋  VULNERABILITY REPORT", C.BOLD + C.WHITE))
    print(sep)
    print(f"  Target    : {clr(result.target, C.CYAN)}")
    print(f"  IP        : {clr(result.resolved_ip, C.CYAN)}")
    print(f"  Scanned   : {clr(result.timestamp, C.DIM)}")
    print(f"  Duration  : {clr(f'{result.duration:.1f}s', C.DIM)}")
    print(f"  Open Ports: {clr(', '.join(str(p['port']) for p in result.open_ports) or 'None found', C.CYAN)}")
    if result.ssl_info:
        si = result.ssl_info
        print(f"  SSL/TLS   : {clr(si.get('protocol','?'), C.GREEN)}  |  Expires in {clr(si.get('days_left','?'), C.GREEN)} days")

    print(sep)
    print(clr("  FINDING SUMMARY", C.BOLD))
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        n = counts[sev]
        colour = SEV_COLOUR[sev]
        bar = "█" * min(n, 30)
        print(f"  {clr(f'{sev:<8}', colour)} {clr(bar, colour)} {clr(n, C.BOLD)}")

    print(f"\n  Overall Risk Score : {clr(score, rcolour + C.BOLD)} / 200+")
    print(f"  Risk Level         : {clr(rlabel, rcolour + C.BOLD)}")
    print(sep)

    print(clr("\n  DETAILED FINDINGS\n", C.BOLD))
    for i, f in enumerate(findings, 1):
        if f.severity == "INFO": continue   # group info at end
        print(f"  {i:02d}. {sev_label(f.severity)}  {clr(f.title, C.BOLD)}")
        print(f"       Category : {clr(f.category, C.MAGENTA)}")
        print(f"       Detail   : {f.detail}")
        print(f"       Fix      : {clr(f.recommendation, C.GREEN)}")
        if f.evidence:
            print(f"       Evidence : {clr(f.evidence[:100], C.DIM)}")
        print()

    # Info findings
    info_finds = [f for f in findings if f.severity=="INFO"]
    if info_finds:
        print(clr("  ℹ️  INFORMATIONAL FINDINGS", C.CYAN + C.BOLD))
        for f in info_finds:
            print(f"       • {f.title} — {clr(f.detail[:80], C.DIM)}")

    print(f"\n{sep}\n")

# ════════════════════════════════════════════════════════════
#  JSON EXPORT
# ════════════════════════════════════════════════════════════
def export_json(result: ScanResult, path: str):
    data = {
        "target":       result.target,
        "timestamp":    result.timestamp,
        "duration":     result.duration,
        "resolved_ip":  result.resolved_ip,
        "ssl_info":     result.ssl_info,
        "open_ports":   result.open_ports,
        "findings":     [asdict(f) for f in result.findings],
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    print(clr(f"  💾 JSON report saved → {path}", C.GREEN))

# ════════════════════════════════════════════════════════════
#  HTML EXPORT
# ════════════════════════════════════════════════════════════
def export_html(result: ScanResult, path: str):
    findings = sorted(result.findings, key=lambda f: -SEVERITY_ORDER.get(f.severity, 0))
    counts   = severity_counts(findings)
    score    = risk_score(counts)
    rlabel, _ = risk_label(score)

    sev_colours = {
        "CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#eab308",
        "LOW":"#60a5fa","INFO":"#a0a0c0"
    }

    rows = ""
    for i, f in enumerate(findings, 1):
        clrval = sev_colours.get(f.severity, "#aaa")
        rows += f"""
        <tr>
          <td style="color:{clrval};font-weight:700;">{f.severity}</td>
          <td>{f.category}</td>
          <td><strong>{f.title}</strong><br><small style="color:#aaa;">{f.detail[:200]}</small></td>
          <td style="color:#86efac;">{f.recommendation[:160]}</td>
          <td><code style="font-size:.75rem;color:#fbbf24;">{f.evidence[:80]}</code></td>
        </tr>"""

    port_rows = "".join(
        f"<tr><td>{p['port']}</td><td>{p['service']}</td>"
        f"<td style='color:#{'ef4444' if p['port'] in RISKY_PORTS else '22c55e'}'>{'RISKY' if p['port'] in RISKY_PORTS else 'OK'}</td></tr>"
        for p in result.open_ports
    ) or "<tr><td colspan='3' style='color:#666;'>No common ports open</td></tr>"

    si = result.ssl_info
    ssl_block = f"""
      <p>Protocol: <strong>{si.get('protocol','—')}</strong> &nbsp;|&nbsp;
         Cipher: <strong>{si.get('cipher','—')}</strong> &nbsp;|&nbsp;
         Expires in: <strong style="color:{'#22c55e' if (si.get('days_left') or 0)>30 else '#ef4444'};">{si.get('days_left','—')} days</strong><br>
         Issuer: {si.get('issuer_cn','—')} &nbsp;|&nbsp; SANs: {si.get('san_count','—')}</p>
    """ if si else "<p style='color:#888;'>SSL not available or not checked.</p>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Vulnerability Report — {result.target}</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0;}}
    body{{font-family:'Segoe UI',sans-serif;background:#0f0f1a;color:#e0e0f0;padding:32px 24px;}}
    h1{{font-size:1.8rem;background:linear-gradient(135deg,#a78bfa,#60a5fa);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:6px;}}
    .meta{{color:#8888aa;font-size:.85rem;margin-bottom:28px;}}
    .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:28px;}}
    .stat{{background:#1a1a2e;border:1px solid #2a2a45;border-radius:12px;padding:16px;text-align:center;}}
    .stat .val{{font-size:2rem;font-weight:800;}}
    .stat .key{{font-size:.75rem;color:#8888aa;margin-top:4px;text-transform:uppercase;letter-spacing:.05em;}}
    .section{{background:#1a1a2e;border:1px solid #2a2a45;border-radius:12px;padding:20px;margin-bottom:20px;}}
    .section h2{{font-size:1rem;color:#a78bfa;text-transform:uppercase;letter-spacing:.07em;margin-bottom:14px;}}
    table{{width:100%;border-collapse:collapse;font-size:.83rem;}}
    th{{text-align:left;color:#8888aa;font-weight:600;padding:8px 10px;border-bottom:1px solid #2a2a45;text-transform:uppercase;font-size:.72rem;letter-spacing:.05em;}}
    td{{padding:10px;border-bottom:1px solid #1e1e35;vertical-align:top;}}
    tr:last-child td{{border-bottom:none;}}
    .badge{{display:inline-block;padding:2px 10px;border-radius:999px;font-size:.75rem;font-weight:700;}}
    .risk{{font-size:1.4rem;font-weight:800;}}
  </style>
</head>
<body>
  <h1>🔍 Vulnerability Report</h1>
  <div class="meta">
    Target: <strong style="color:#60a5fa;">{result.target}</strong> &nbsp;|&nbsp;
    IP: <strong>{result.resolved_ip}</strong> &nbsp;|&nbsp;
    Scanned: {result.timestamp} &nbsp;|&nbsp;
    Duration: {result.duration:.1f}s
  </div>

  <div class="grid">
    <div class="stat"><div class="val" style="color:#ef4444;">{counts['CRITICAL']}</div><div class="key">Critical</div></div>
    <div class="stat"><div class="val" style="color:#f97316;">{counts['HIGH']}</div><div class="key">High</div></div>
    <div class="stat"><div class="val" style="color:#eab308;">{counts['MEDIUM']}</div><div class="key">Medium</div></div>
    <div class="stat"><div class="val" style="color:#60a5fa;">{counts['LOW']}</div><div class="key">Low</div></div>
    <div class="stat"><div class="val" style="color:#{'ef4444' if rlabel in ('CRITICAL','HIGH') else 'eab308' if rlabel=='MEDIUM' else '22c55e'};">{score}</div><div class="key">Risk Score</div></div>
    <div class="stat"><div class="val" style="color:#{'ef4444' if rlabel in ('CRITICAL','HIGH') else 'eab308' if rlabel=='MEDIUM' else '22c55e'};">{rlabel}</div><div class="key">Risk Level</div></div>
  </div>

  <div class="section">
    <h2>🔒 SSL / TLS</h2>
    {ssl_block}
  </div>

  <div class="section">
    <h2>🌐 Open Ports</h2>
    <table><thead><tr><th>Port</th><th>Service</th><th>Risk</th></tr></thead>
    <tbody>{port_rows}</tbody></table>
  </div>

  <div class="section">
    <h2>📋 All Findings</h2>
    <table>
      <thead><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Recommendation</th><th>Evidence</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>

  <p style="color:#4a4a6a;font-size:.75rem;margin-top:20px;">
    ⚠️ This report is for educational purposes only. Only scan systems you own or have explicit written permission to test.
  </p>
</body>
</html>"""

    with open(path, "w") as fh:
        fh.write(html)
    print(clr(f"  🌐 HTML report saved → {path}", C.GREEN))

# ════════════════════════════════════════════════════════════
#  MAIN ORCHESTRATOR
# ════════════════════════════════════════════════════════════
def normalize_url(target: str) -> tuple[str, str]:
    """Returns (base_url, hostname)"""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    parsed = urllib.parse.urlparse(target)
    return target.rstrip("/"), parsed.hostname or target

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Web Vulnerability Scanner — Educational Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python scanner.py example.com\n"
               "  python scanner.py https://example.com --no-ports\n"
               "  python scanner.py example.com --export json html\n\n"
               "⚠️  Only scan targets you own or have explicit written permission to test."
    )
    parser.add_argument("target", help="Target URL or domain (e.g. example.com)")
    parser.add_argument("--no-ports",  action="store_true", help="Skip port scanning")
    parser.add_argument("--no-paths",  action="store_true", help="Skip path probing")
    parser.add_argument("--no-ssl",    action="store_true", help="Skip SSL check")
    parser.add_argument("--export", nargs="*", choices=["json","html"], default=[],
                        help="Export report as json and/or html")
    parser.add_argument("--output-dir", default=".", help="Directory for exported reports")
    args = parser.parse_args()

    base_url, hostname = normalize_url(args.target)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    start = time.time()

    print(clr(f"  Target  : {base_url}", C.CYAN + C.BOLD))
    print(clr(f"  Started : {timestamp}\n", C.DIM))
    print(clr("  ⚠️  Scan only targets you own or have written permission to test.", C.YELLOW))

    findings: list[Finding] = []
    result = ScanResult(
        target    = base_url,
        timestamp = timestamp,
        duration  = 0.0,
    )

    # DNS
    print(clr("\n[*] Resolving hostname…", C.DIM))
    ip = resolve_host(hostname)
    result.resolved_ip = ip
    print(f"    {hostname} → {clr(ip, C.CYAN)}")

    if ip == "Unresolvable":
        print(clr("\n  ❌ Could not resolve hostname. Aborting.", C.RED))
        sys.exit(1)

    # Port scan
    if not args.no_ports:
        scan_ports(ip, COMMON_PORTS, result, findings)

    # SSL
    if not args.no_ssl:
        check_ssl(hostname, result, findings)

    # HTTP headers
    check_headers(base_url, result, findings)

    # Version fingerprinting
    check_versions(result.headers, findings)

    # Path probing
    if not args.no_paths:
        probe_paths(base_url, findings)

    result.findings = findings
    result.duration = round(time.time() - start, 2)

    # Terminal report
    print_report(result)

    # Exports
    slug = re.sub(r"[^\w]", "_", hostname)
    ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    if "json" in args.export:
        export_json(result, f"{args.output_dir}/{slug}_{ts}.json")
    if "html" in args.export:
        export_html(result, f"{args.output_dir}/{slug}_{ts}.html")

    if args.export:
        print()

if __name__ == "__main__":
    main()
