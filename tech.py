#!/usr/bin/env python3
"""
tech.py - Massive Infrastructure & Security Profiler
Usage: python3 tech.py example.com
Output: Automatically saves to tech.txt
"""

import socket
import subprocess
import shutil
import sys
import re
import json
import os
import time
import ssl
import datetime
import ipaddress
import warnings
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from concurrent.futures import ThreadPoolExecutor, as_completed

# ANSI color palette for terminal output (no-op when TTY is unavailable)
def _supports_color() -> bool:
    """Returns True only when output goes to a real color-capable terminal.

    Explicitly disabled inside the opencode TUI (OPENCODE=1), which does not
    render ANSI escapes and would show raw '\\033[..m' sequences. Override with
    FORCE_COLOR=1 (on) or NO_COLOR=1 (off).
    """
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("OPENCODE"):
        return False
    if not sys.stdout.isatty():
        return False
    return os.environ.get("TERM") != "dumb"


_COLOR = _supports_color()

RESET = "\033[0m" if _COLOR else ""
BOLD = "\033[1m" if _COLOR else ""
DIM = "\033[2m" if _COLOR else ""
RED = "\033[31m" if _COLOR else ""
GREEN = "\033[32m" if _COLOR else ""
YELLOW = "\033[33m" if _COLOR else ""
BLUE = "\033[34m" if _COLOR else ""
MAGENTA = "\033[35m" if _COLOR else ""
CYAN = "\033[36m" if _COLOR else ""
WHITE = "\033[37m" if _COLOR else ""

# ssl.TLSVersion.TLSv1/TLSv1_1 are deprecated in newer Pythons but are needed
# to detect legacy protocol support; silence the noise.
warnings.filterwarnings("ignore", category=DeprecationWarning, module="ssl")


def _paint_report(text: str) -> str:
    """Colorizes the report for terminal display only (tech.txt stays plain)."""
    if not _COLOR:
        return text
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            out.append(line)
            continue
        if stripped.startswith("-"):
            if "[MISSING]" in line:
                out.append(f"{RED}{line}{RESET}")
            elif "[Present]" in line:
                out.append(f"{GREEN}{line}{RESET}")
            elif "TLS Expiry:" in line:
                m = re.search(r"\((\d+) days left\)", line)
                if m:
                    days = int(m.group(1))
                    color = RED if days < 30 else (YELLOW if days < 90 else GREEN)
                    out.append(f"{color}{line}{RESET}")
                else:
                    out.append(f"{DIM}{line}{RESET}")
            elif "Supported Protocols:" in line:
                color = RED if any(v in line for v in ("TLSv1.0", "TLSv1.1")) else GREEN
                out.append(f"{color}{line}{RESET}")
            elif "Legacy/Weak Ciphers Accepted:" in line:
                color = GREEN if "None" in line else RED
                out.append(f"{color}{line}{RESET}")
            else:
                out.append(f"{DIM}{line}{RESET}")
        elif ":" in line:
            label, _, value = line.partition(":")
            value = value.strip()
            label = label.strip()
            painted = f"{BOLD}{CYAN}{label}:{RESET}"
            if label == "Status Code":
                try:
                    code = int(value)
                    painted += f" {GREEN if code < 400 else RED}{value}{RESET}"
                except ValueError:
                    painted += f" {WHITE}{value}{RESET}"
            elif label in ("WAF Confidence", "Firewall", "CDN", "Cache Status"):
                color = RED if value in ("CONFIRMED", "None Detected") else (YELLOW if value == "LIKELY" else GREEN)
                painted += f" {color}{value}{RESET}"
            elif label == "TLS Expiry":
                m = re.search(r"\((\d+) days left\)", value)
                if m:
                    days = int(m.group(1))
                    color = RED if days < 30 else (YELLOW if days < 90 else GREEN)
                    painted += f" {color}{value}{RESET}"
                else:
                    painted += f" {WHITE}{value}{RESET}"
            elif label == "Supported Protocols":
                color = RED if any(v in value for v in ("TLSv1.0", "TLSv1.1")) else GREEN
                painted += f" {color}{value}{RESET}"
            elif label == "Legacy/Weak Ciphers Accepted":
                color = GREEN if value.startswith("None") else RED
                painted += f" {color}{value}{RESET}"
            elif value:
                painted += f" {WHITE}{value}{RESET}"
            out.append(painted)
        else:
            out.append(f"{BOLD}{BLUE}{line}{RESET}")
    return "\n".join(out)

# Configuration
HTTP_TIMEOUT = 5
PORT_TIMEOUT = 0.5
TOP_PORTS = [21,22,23,25,53,80,110,111,135,139,143,179,199,443,445,465,514,515,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1521,1522,1720,1723,1755,1900,2000,2049,2121,2483,2484,2717,3000,3128,3306,33060,3389,3986,4899,5000,5009,50000,5060,5101,5190,5357,5432,5433,5631,5666,5800,5900,5984,6000,6001,6379,6380,6646,7070,8000,8008,8009,8080,8081,8082,8086,8443,8888,9042,9100,9200,9300,9999,10000,11211,11212,27017,27018,27019,32768,49152,49153,49154,49155,49156,49157]

WAF_BYPASSES = {
    "Cloudflare": ["Test HTTP/2 request smuggling (H2.TE/H2.TC)", "Use alternate HTTP methods (PUT/PATCH/DELETE)", "Manipulate Host header or X-Forwarded-Host", "Test /cdn-cgi/ endpoints for misconfigs", "Use UTF-8 BOM payload encoding", "Test JSON payloads with invalid UTF-8 characters"],
    "AWS WAF": ["Test boundary delimiters in JSON POST data", "Use HTTP Parameter Pollution (HPP)", "Obfuscate payloads with URL encoding double slashes", "Test unmatched Content-Type vs Body parsing"],
    "Akamai": ["Spoof true client IP via X-Forwarded-For", "Use chunked transfer encoding mismatches", "Manipulate Akamai specific cookies (AKA_A2)", "Test case-insensitive header bypasses"],
    "Imperva (Incapsula)": ["Spoof X-Forwarded-For headers", "Test special characters in URL path normalization", "Try different Content-Type headers on POST requests", "Test for X-Forwarded-For IP whitelist bypass"],
    "ModSecurity": ["Bypass using nested payloads", "Use Unicode normalization tricks (e.g., full-width chars)", "Test whitespace variations (tabs, newlines, %0a)", "Use multipart/form-data instead of POST body"],
    "Sucuri": ["Bypass via HTTP/1.0 requests", "Test unusual HTTP methods", "Manipulate X-Forwarded-For headers", "Try sending POST to GET endpoints"],
    "F5 ASM": ["Test JSON payloads with null bytes", "Use HTTP parameter pollution", "Test chunked transfer encoding", "Bypass via URL path normalization mismatches"]
}

UA_STRING = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"

DB_PORTS = {
    1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB",
    6379: "Redis", 6380: "Redis", 9200: "Elasticsearch", 9300: "Elasticsearch",
    11211: "Memcached", 11212: "Memcached", 1521: "Oracle", 1522: "Oracle",
    2483: "Oracle", 2484: "Oracle", 5984: "CouchDB", 8086: "InfluxDB",
    9042: "Cassandra", 5433: "PostgreSQL", 33060: "MySQL X", 50000: "DB2",
    27018: "MongoDB", 27019: "MongoDB",
}
HTTP_DB_PORTS = {5984, 8086, 9200, 9300}

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS"),
    ("X-Frame-Options", "Clickjacking protection"),
    ("X-Content-Type-Options", "MIME sniffing protection"),
    ("Referrer-Policy", "Referrer leak prevention"),
    ("Permissions-Policy", "Browser feature restrictions"),
    ("Feature-Policy", "Legacy feature restrictions"),
    ("Content-Security-Policy", "Content injection protection"),
    ("X-XSS-Protection", "Legacy XSS filter"),
    ("X-Permitted-Cross-Domain-Policies", "Cross-domain policy"),
    ("Cross-Origin-Resource-Policy", "CORP"),
    ("Cross-Origin-Opener-Policy", "COOP"),
    ("Cross-Origin-Embedder-Policy", "COEP"),
]

TLS_VERSION_MAP = {
    "TLSv1.0": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}

WEAK_CIPHERS = [
    "AES128-SHA", "AES256-SHA", "AES128-SHA256", "AES256-SHA256",
    "ECDHE-RSA-AES128-SHA", "ECDHE-RSA-AES256-SHA",
    "DHE-RSA-AES128-SHA", "DHE-RSA-AES256-SHA",
    "CAMELLIA128-SHA", "CAMELLIA256-SHA",
]

WEB_PATHS = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/security.txt", "/server-status", "/.git/config", "/.env"]

HTTP_METHODS = ["OPTIONS", "TRACE", "PUT", "DELETE", "PATCH", "PROPFIND"]

def run_cmd(cmd, timeout=15):
    try:
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=timeout)
        return proc.stdout.strip()
    except Exception:
        return ""

def check_tool(tool):
    return shutil.which(tool) is not None

def resolve_ips(target):
    ips = set()
    try:
        records = socket.gethostbyname_ex(target)
        for ip in records[2]:
            if not ip.startswith(("127.", "0.", "169.254.")):
                ips.add(ip)
    except (socket.gaierror, socket.herror):
        pass
    return list(ips)

def get_origin_candidates(target):
    origins = []
    # Technique 1: MX Records (Mail is rarely behind the web CDN)
    dig_cmd = run_cmd(f"dig +short MX {target}")
    if dig_cmd:
        for line in dig_cmd.splitlines():
            mx_host = line.split()[-1].rstrip('.')
            if mx_host != target:
                mx_ips = resolve_ips(mx_host)
                for ip in mx_ips:
                    origins.append({"ip": ip, "source": f"MX Record ({mx_host})", "type": "POSSIBLE ORIGIN"})
    
    # Technique 2: SPF Records (Includes often point to origin infrastructure)
    dig_txt = run_cmd(f"dig +short TXT {target}")
    if dig_txt:
        for line in dig_txt.splitlines():
            if "v=spf1" in line.lower():
                includes = re.findall(r'include:([^\s]+)', line)
                for inc_domain in includes:
                    inc_ips = resolve_ips(inc_domain)
                    for ip in inc_ips:
                        origins.append({"ip": ip, "source": f"SPF Include ({inc_domain})", "type": "POSSIBLE ORIGIN"})
    
    # Technique 3: Historical/Direct CNAME bypass (if it points to origin-like infra)
    dig_cname = run_cmd(f"dig +short CNAME {target}")
    if dig_cname and "cdn" not in dig_cname.lower() and "cloudflare" not in dig_cname.lower():
        cname_ip = resolve_ips(dig_cname.rstrip('.'))
        for ip in cname_ip:
             origins.append({"ip": ip, "source": f"Direct CNAME ({dig_cname})", "type": "LIKELY ORIGIN"})
             
    return origins

def scan_ports_massive(ips):
    open_ports = set()
    ip_list = ", ".join(ips)
    
    # Priority 1: Naabu (Insanely fast all-port scanner)
    if check_tool("naabu"):
        cmd = f"naabu -host {ip_list} -p - -silent -json 2>/dev/null"
        output = run_cmd(cmd, timeout=120)
        if output:
            try:
                for line in output.splitlines():
                    data = json.loads(line)
                    if data.get("port"): open_ports.add(int(data["port"]))
                return sorted(list(open_ports))
            except json.JSONDecodeError:
                pass
                
    # Priority 2: Nmap
    if check_tool("nmap"):
        cmd = f"nmap -Pn -T4 -p- {ip_list} --open --min-rate 1000 2>/dev/null | grep '^[0-9]'"
        output = run_cmd(cmd, timeout=180)
        if output:
            for line in output.splitlines():
                match = re.match(r'^(\d+)/tcp', line)
                if match: open_ports.add(int(match.group(1)))
            if open_ports: return sorted(list(open_ports))

    # Priority 3: Python Fallback (Top 100 common ports only, doing 65k in python is too slow)
    def scan(ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(PORT_TIMEOUT)
            if s.connect_ex((ip, port)) == 0: return port
        except: pass
        finally:
            try: s.close()
            except: pass
        return None

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan, ip, port) for ip in ips for port in TOP_PORTS]
        for future in as_completed(futures):
            res = future.result()
            if res: open_ports.add(res)
            
    return sorted(list(open_ports))

def grab_http_data(target):
    data = {"status": "N/A", "title": "N/A", "headers": {}, "body": ""}
    url = target if target.startswith("http") else f"https://{target}"
    
    # Try httpx first for deep tech detection
    if check_tool("httpx-toolkit") or check_tool("httpx"):
        bin_name = "httpx-toolkit" if check_tool("httpx-toolkit") else "httpx"
        cmd = f"{bin_name} -u {url} -json -silent -tech-detect -title -server -cdn -status-code -tls-grab -follow-redirects"
        output = run_cmd(cmd, timeout=HTTP_TIMEOUT)
        if output:
            try:
                j = json.loads(output)
                data["status"] = j.get("status_code", "N/A")
                data["title"] = j.get("title", "N/A")
                data["headers"] = j.get("header", {})
                data["tech"] = j.get("tech", [])
                data["cdn"] = j.get("cdn_name") or j.get("cdn", "N/A")
                return data
            except: pass

    # Fallback to urllib
    try:
        req = Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'})
        with urlopen(req, timeout=HTTP_TIMEOUT) as response:
            data["status"] = response.getcode()
            data["headers"] = dict(response.headers)
            data["body"] = response.read(10000).decode('utf-8', errors='ignore')
            match = re.search(r'<title>(.*?)</title>', data["body"], re.I)
            if match: data["title"] = match.group(1).strip()
    except HTTPError as e:
        data["status"] = e.code
        data["headers"] = dict(e.headers) if e.headers else {}
        try: data["body"] = e.read(10000).decode('utf-8', errors='ignore')
        except: pass
    except: pass
    
    return data

def analyze_waf_confidence(headers, body, cdn_name):
    waf = "None Detected"
    confidence = "UNCONFIRMED"
    evidence = []
    h_lower = {k.lower(): v for k, v in headers.items()}
    
    # Cloudflare Checks
    if "cf-ray" in h_lower or cdn_name.lower() == "cloudflare":
        waf = "Cloudflare"
        confidence = "LIKELY"
        evidence.append("CF-Ray header present")
        if "__cfduid" in h_lower or "cf-app-version" in h_lower: evidence.append("Cloudflare cookies")
        if "cloudflare" in str(h_lower.get("server", "")).lower(): evidence.append("Cloudflare Server header")
        if "jschallenge" in body or "cf-browser-verification" in body or "Please Wait... | Cloudflare" in body:
            confidence = "CONFIRMED"
            evidence.append("Cloudflare JS Challenge/Block page detected in HTML body")
            
    # AWS WAF Checks
    elif "x-amzn-requestid" in h_lower or "x-amz-cf-id" in h_lower:
        waf = "AWS WAF"
        confidence = "LIKELY"
        evidence.append("AWS specific headers")
        if "awswaf" in body.lower() or "requestblocked" in body.lower():
            confidence = "CONFIRMED"
            evidence.append("AWS WAF Block signature in body")
            
    # Akamai Checks
    elif "x-akamai" in h_lower or ("x-cache" in h_lower and "akamai" in h_lower.get("x-cache", "").lower()):
        waf = "Akamai"
        confidence = "LIKELY"
        evidence.append("Akamai cache/ID headers")
        if "akamai" in body.lower():
            confidence = "CONFIRMED"
            evidence.append("Akamai block page detected in body")
            
    # Imperva Checks
    elif "x-iinfo" in h_lower or "visid_incap" in h_lower:
        waf = "Imperva (Incapsula)"
        confidence = "CONFIRMED"
        evidence.append("Incapsula tracking cookies/headers")
        
    # Sucuri Checks
    elif "x-sucuri-id" in h_lower or "sucuri" in str(h_lower.get("x-proxy-id", "")).lower():
        waf = "Sucuri"
        confidence = "CONFIRMED"
        evidence.append("Sucuri proxy headers")
        
    # ModSecurity / Generic
    elif "mod_security" in str(h_lower).lower() or "noindex" in body and "mod_security" in body:
        waf = "ModSecurity"
        confidence = "LIKELY"
        evidence.append("ModSecurity signatures")

    return waf, confidence, evidence

def analyze_cache(headers):
    cache = "None Detected"
    provider = "N/A"
    h_lower = {k.lower(): v for k, v in headers.items()}
    
    if "cf-cache-status" in h_lower:
        cache = "Detected"
        provider = f"Cloudflare (Status: {h_lower['cf-cache-status']})"
    elif "x-varnish" in h_lower:
        cache = "Detected"
        provider = "Varnish"
    elif "x-fastly-request-id" in h_lower:
        cache = "Detected"
        provider = "Fastly"
    elif "x-cache" in h_lower:
        cache = "Detected"
        provider = h_lower['x-cache']
    elif "x-cache-hits" in h_lower:
        cache = "Detected"
        provider = f"Generic Cache (Hits: {h_lower['x-cache-hits']})"
    elif "via" in h_lower:
        cache = "Detected"
        provider = h_lower['via']
    elif "age" in h_lower:
        cache = "Detected"
        provider = "Generic (Age header present)"
        
    return cache, provider

def resolve_ipv6(target):
    """Returns sorted IPv6 (AAAA) addresses for the target."""
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_INET6)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []

def get_dns_records(target):
    """Collects A/AAAA/MX/NS/TXT/CNAME/SOA records via dig (host/python fallback)."""
    records = {}
    if check_tool("dig"):
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
            out = run_cmd(f"dig +short {rtype} {target}", timeout=10)
            if out:
                records[rtype] = out.splitlines()
    else:
        if check_tool("host"):
            out = run_cmd(f"host -a {target}", timeout=10)
            for line in out.splitlines():
                line = line.strip()
                if "has address" in line:
                    records.setdefault("A", []).append(line.split()[-1])
                elif "has IPv6 address" in line:
                    records.setdefault("AAAA", []).append(line.split()[-1])
                elif "mail is handled by" in line:
                    records.setdefault("MX", []).append(line.split("mail is handled by")[1].strip().split()[0])
                elif "name server" in line:
                    records.setdefault("NS", []).append(line.split()[-1])
                elif "descriptive text" in line:
                    records.setdefault("TXT", []).append(line.split("descriptive text")[1].strip())
                elif "is an alias for" in line:
                    records.setdefault("CNAME", []).append(line.split()[-1])
                elif "start of authority" in line:
                    records.setdefault("SOA", []).append(line.split("start of authority")[1].strip())
    try:
        for family, rtype in ((socket.AF_INET, "A"), (socket.AF_INET6, "AAAA")):
            if not records.get(rtype):
                records[rtype] = list({i[4][0] for i in socket.getaddrinfo(target, None, family)})
    except Exception:
        pass
    return records

def get_email_security(target):
    """SPF / DMARC / DKIM posture via DNS TXT lookups."""
    out = []
    txt = run_cmd(f"dig +short TXT {target}", timeout=10)
    spf_found = False
    for line in txt.splitlines():
        if "v=spf1" in line.lower():
            out.append(f" - SPF: {line.strip()}")
            spf_found = True
    if not spf_found:
        out.append(" - SPF: None")
    dmarc = run_cmd(f"dig +short TXT _dmarc.{target}", timeout=10)
    out.append(f" - DMARC: {dmarc.strip() if dmarc else 'None'}")
    for selector in ("default", "google", "selector1", "selector2"):
        dkim = run_cmd(f"dig +short TXT {selector}._domainkey.{target}", timeout=10)
        if dkim and "v=dkim" in dkim.lower():
            out.append(f" - DKIM ({selector}): {dkim.strip()}")
    return out

def get_reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

def whois_intel(ip):
    try:
        a = ipaddress.ip_address(ip)
        if a.is_private or a.is_reserved or a.is_loopback or a.is_link_local or a.is_multicast:
            return None
    except ValueError:
        return None
    if not check_tool("whois"):
        return None
    out = run_cmd(f"whois {ip}", timeout=20)
    if not out:
        return None
    def grab(regex):
        m = re.search(regex, out, re.MULTILINE | re.IGNORECASE)
        return m.group(1).strip() if m else None
    netname = grab(r'^net(?:[- ])?name:\s*(.+)$')
    org = grab(r'^(?:org(?:[- ])?name|organization|owner|descr):\s*(.+)$')
    country = grab(r'^country:\s*(.+)$')
    asn = grab(r'^(?:origin(?:[- ]as)?|autonomous system number):\s*(.+)$')
    cidr = grab(r'^(?:inetnum|netrange|cidr|route):\s*(.+)$')
    parts = [f"{label}: {val}" for label, val in
             (("NetName", netname), ("Org", org), ("Country", country), ("ASN", asn), ("Range", cidr)) if val]
    return f" - {ip}: " + ", ".join(parts) if parts else None

def rdap_intel(ip):
    try:
        req = Request(f"https://rdap.org/ip/{ip}", headers={"User-Agent": UA_STRING})
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
    except Exception:
        return None
    parts = []
    if data.get("name"):
        parts.append(f"NetName: {data['name']}")
    if data.get("country"):
        parts.append(f"Country: {data['country']}")
    if data.get("startAddress") and data.get("endAddress"):
        parts.append(f"Range: {data['startAddress']} - {data['endAddress']}")
    if data.get("handle"):
        parts.append(f"Handle: {data['handle']}")
    orgs = []
    for ent in data.get("entities", []):
        try:
            vcard = ent.get("vcardArray", (None, []))[1]
            for item in vcard:
                if item[0] == "fn" and item[3].strip() not in ("Abuse", "Admin", "NOC", "Tech", "Routing", "Point of Contact"):
                    orgs.append(item[3])
        except Exception:
            pass
    for org in dict.fromkeys(orgs):
        parts.append(f"Org: {org}")
    return f" - {ip}: " + ", ".join(parts) if parts else None

def get_ip_intel(ips):
    out = []
    for ip in ips:
        rdns = get_reverse_dns(ip)
        out.append(f" - {ip} rDNS: {rdns if rdns else 'None'}")
    for ip in ips:
        info = whois_intel(ip) or rdap_intel(ip)
        if info:
            out.append(info)
    return out

def probe_database(ip, port):
    """Best-effort service identification on a database port."""
    service = DB_PORTS.get(port, "Unknown")
    hint = None
    try:
        if port in HTTP_DB_PORTS:
            try:
                req = Request(f"http://{ip}:{port}/", headers={"User-Agent": UA_STRING})
                with urlopen(req, timeout=3) as resp:
                    data = resp.read(1000).decode("utf-8", errors="ignore")
                    if "couchdb" in data.lower():
                        hint = "CouchDB"
                    elif "influxdb" in data.lower():
                        hint = "InfluxDB"
                    elif "cassandra" in data.lower():
                        hint = "Cassandra"
                    elif "cluster_name" in data or '"version"' in data:
                        hint = "Elasticsearch"
                    if hint:
                        try:
                            j = json.loads(data)
                            v = j.get("version", j.get("couchdb"))
                            if isinstance(v, dict):
                                v = v.get("number", v)
                            if v:
                                hint += f" v{v}"
                        except Exception:
                            pass
            except Exception:
                pass
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            if s.connect_ex((ip, port)) == 0:
                banner = b""
                try:
                    try:
                        banner = s.recv(512)
                    except socket.timeout:
                        banner = b""
                    if not banner:
                        if service == "Redis":
                            s.sendall(b"INFO\r\n")
                        elif service == "Memcached":
                            s.sendall(b"version\r\n")
                        else:
                            s.sendall(b"\r\n\r\n")
                        try:
                            banner = s.recv(512)
                        except socket.timeout:
                            pass
                except Exception:
                    pass
                finally:
                    try:
                        s.close()
                    except Exception:
                        pass
                if banner:
                    text = banner.decode("utf-8", errors="ignore")
                    if service == "Redis":
                        hint = "Redis"
                    elif service == "Memcached" and "VERSION" in text.upper():
                        hint = "Memcached " + text.strip()
                    elif service == "MySQL":
                        m = re.search(r"([0-9]+\.[0-9]+\.[0-9]+)", text)
                        hint = "MySQL" + (f" v{m.group(1)}" if m else "")
                    elif service == "PostgreSQL":
                        hint = "PostgreSQL"
                    elif service == "MSSQL":
                        hint = "MSSQL"
                    elif service == "Oracle":
                        hint = "Oracle"
                    elif service == "MongoDB":
                        hint = "MongoDB"
                    else:
                        hint = f"{service} (banner: {text.strip()[:40]})"
    except Exception:
        pass
    return {"port": port, "service": service, "banner": hint} if hint else None

def analyze_tls(target, port=443):
    """Extracts certificate, version and cipher details via a TLS handshake."""
    results = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.verify_callback = lambda conn, cert, errno, depth, ok: True
        with socket.create_connection((target, port), timeout=HTTP_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as tls:
                cert = tls.getpeercert() or {}
                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                results.append(f" - TLS Certificate CN: {subject.get('commonName', 'N/A')}")
                if subject.get("organizationName"):
                    results.append(f" - TLS Certificate Org: {subject['organizationName']}")
                results.append(f" - TLS Certificate Issuer: {issuer.get('commonName', issuer.get('organizationName', 'N/A'))}")
                san = cert.get("subjectAltName", ())
                if san:
                    listed = ", ".join(v for _, v in san[:10])
                    if len(san) > 10:
                        listed += f" (+{len(san) - 10} more)"
                    results.append(f" - TLS SANs: {listed}")
                na = cert.get("notAfter", "")
                if na:
                    try:
                        exp = datetime.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
                        days = (exp - datetime.datetime.utcnow()).days
                        results.append(f" - TLS Expiry: {na} ({days} days left)")
                    except Exception:
                        results.append(f" - TLS Expiry: {na}")
                results.append(f" - TLS Protocol Version: {tls.version()}")
                cipher = tls.cipher()
                results.append(f" - TLS Cipher: {cipher[0] if cipher else 'N/A'}")
    except Exception as e:
        results.append(f" - TLS Handshake Failed: {str(e)[:60]}")
    return results

def test_tls_protocols(target, port=443):
    supported = []
    for name, ver in TLS_VERSION_MAP.items():
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            with socket.create_connection((target, port), timeout=HTTP_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=target):
                    supported.append(name)
        except Exception:
            pass
    return supported

def test_weak_ciphers(target, port=443):
    weak = []
    for cipher in WEAK_CIPHERS:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            ctx.set_ciphers(cipher + ":@SECLEVEL=0")
            with socket.create_connection((target, port), timeout=HTTP_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=target):
                    weak.append(cipher)
        except Exception:
            pass
    return weak

def audit_security_headers(headers):
    h_lower = {k.lower(): v for k, v in headers.items()}
    present, missing = [], []
    for name, _ in SECURITY_HEADERS:
        if name.lower() in h_lower:
            present.append(f"{name}: {h_lower[name.lower()][:80]}")
        else:
            missing.append(name)
    notes = []
    if "strict-transport-security" in h_lower:
        sts = h_lower["strict-transport-security"]
        if "max-age" not in sts.lower():
            notes.append("HSTS missing max-age directive")
        if "includeSubDomains" not in sts:
            notes.append("HSTS missing includeSubDomains")
        if "preload" in sts.lower():
            notes.append("HSTS preload requested")
        else:
            notes.append("HSTS preload not requested")
    if "content-security-policy" in h_lower:
        csp = h_lower["content-security-policy"].lower()
        if "unsafe-inline" in csp:
            notes.append("CSP allows unsafe-inline")
        if "unsafe-eval" in csp:
            notes.append("CSP allows unsafe-eval")
    cookie_notes = []
    cookies = h_lower.get("set-cookie", "")
    if cookies:
        if "secure" not in cookies.lower():
            cookie_notes.append("Cookies missing Secure flag")
        if "httponly" not in cookies.lower():
            cookie_notes.append("Cookies missing HttpOnly flag")
        if "samesite" not in cookies.lower():
            cookie_notes.append("Cookies missing SameSite attribute")
    return present, missing, notes, cookie_notes

def _method_check(url, method):
    try:
        req = Request(url, method=method, headers={"User-Agent": UA_STRING})
        with urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return f" - {method}: {resp.getcode()}"
    except HTTPError as e:
        return f" - {method}: {e.code}"
    except Exception:
        return f" - {method}: N/A"

def check_http_methods(target):
    base = target if target.startswith("http") else f"https://{target}"
    results = []
    with ThreadPoolExecutor(max_workers=len(HTTP_METHODS)) as executor:
        futures = [executor.submit(_method_check, base, m) for m in HTTP_METHODS]
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results)

def _path_check(url, path):
    try:
        req = Request(url + path, headers={"User-Agent": UA_STRING})
        with urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            data = resp.read(200).decode("utf-8", errors="ignore").replace("\n", " ")
            return f" - {path} -> {resp.getcode()} ({data[:60]})"
    except HTTPError as e:
        return f" - {path} -> {e.code}"
    except Exception:
        return f" - {path} -> N/A"

def check_web_files(target):
    base = target if target.startswith("http") else f"https://{target}"
    results = []
    with ThreadPoolExecutor(max_workers=len(WEB_PATHS)) as executor:
        futures = [executor.submit(_path_check, base, p) for p in WEB_PATHS]
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results)

def main():
    if len(sys.argv) != 2:
        print(f"{BOLD}{GREEN}Usage:{RESET} {WHITE}python3 tech.py example.com{RESET}")
        sys.exit(1)

    target = sys.argv[1].strip().split('/')[0] # Strip paths/protocols if passed
    out_lines = []

    out_lines.append(f"Target: {target}")

    # 1. IP Resolution
    ips = resolve_ips(target)
    out_lines.append(f"IPs: {', '.join(ips) if ips else 'N/A'}")

    # 2. IPv6 Resolution
    ipv6 = resolve_ipv6(target)
    out_lines.append(f"IPv6: {', '.join(ipv6) if ipv6 else 'None'}")

    # 3. Full DNS Records
    out_lines.append("DNS Records:")
    dns = get_dns_records(target)
    if dns:
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
            if dns.get(rtype):
                vals = "; ".join(dns[rtype])
                out_lines.append(f" - {rtype}: {vals[:150] + '...' if len(vals) > 150 else vals}")
    else:
        out_lines.append(" - No DNS records found")

    # 4. Email Security (SPF / DMARC / DKIM)
    out_lines.append("Email Security:")
    out_lines.extend(get_email_security(target))

    # 5. Origin IP Discovery (Passive Infrastructure Analysis)
    out_lines.append("Origin IP Discovery:")
    origins = get_origin_candidates(target)
    if origins:
        # Filter out IPs that are exactly the same as the CDN IPs to reduce noise
        cdn_ips = set(ips)
        seen_origins = set()
        for orig in origins:
            if orig["ip"] not in cdn_ips and orig["ip"] not in seen_origins:
                out_lines.append(f" - {orig['ip']} ({orig['type']}, Source: {orig['source']})")
                seen_origins.add(orig["ip"])
        if not seen_origins:
            out_lines.append(" - No separate origin IPs found via MX/SPF records")
    else:
        out_lines.append(" - No origin indicators found (Target may be fully masked or records missing)")

    # 6. Reverse DNS & IP Intel
    if ips:
        out_lines.append("Reverse DNS & IP Intel:")
        out_lines.extend(get_ip_intel(ips))

    # 7. Massive Port Scanning
    out_lines.append("Scanning Ports (Naabu -> Nmap -> Python Fallback)...")
    open_ports = scan_ports_massive(ips) if ips else []
    out_lines.append(f"Open Ports: {', '.join(map(str, open_ports)) if open_ports else 'None found'}")

    # 8. Database Discovery
    if open_ports:
        db_ports = [p for p in open_ports if p in DB_PORTS]
        if db_ports:
            out_lines.append("Database Discovery:")
            db_hits = []
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(probe_database, ip, p) for ip in ips for p in db_ports]
                for future in as_completed(futures):
                    res = future.result()
                    if res:
                        db_hits.append(res)
            if db_hits:
                for r in sorted(db_hits, key=lambda x: x["port"]):
                    out_lines.append(f" - {r['service']} on {r['port']}: {r['banner']}")
            else:
                out_lines.append(" - No database services identified on open DB ports")

    # 9. HTTP Grabbing & Analysis
    out_lines.append("Grabbing HTTP Headers & Body...")
    http_data = grab_http_data(target)
    if http_data.get("status") == "N/A":
        time.sleep(1)
        http_data = grab_http_data(target)

    status = http_data.get("status", "N/A")
    title = http_data.get("title", "N/A")
    headers = http_data.get("headers", {})
    body = http_data.get("body", "")
    tech = http_data.get("tech", [])
    cdn = http_data.get("cdn", "None Detected")

    out_lines.append(f"Status Code: {status}")
    out_lines.append(f"Title: {title}")
    out_lines.append(f"Server: {headers.get('Server', 'N/A')}")
    out_lines.append(f"Technologies: {', '.join(tech) if tech else 'N/A'}")

    # 10. CDN Analysis
    out_lines.append(f"CDN: {cdn}")

    # 11. WAF Analysis (Deep body + header analysis)
    waf_name, waf_conf, waf_evidence = analyze_waf_confidence(headers, body, cdn)
    out_lines.append(f"Firewall: {waf_name}")
    out_lines.append(f"WAF Confidence: {waf_conf}")
    if waf_evidence:
        out_lines.append(f"WAF Evidence: {', '.join(waf_evidence)}")

    # 12. Cache Analysis
    cache_status, cache_provider = analyze_cache(headers)
    out_lines.append(f"Cache Status: {cache_status}")
    if cache_status != "None Detected":
        out_lines.append(f"Cache Provider: {cache_provider}")

    # 13. Interesting Headers
    out_lines.append(f"X-Powered-By: {headers.get('X-Powered-By', 'N/A')}")
    out_lines.append(f"CSP: {headers.get('Content-Security-Policy', 'N/A')}")
    out_lines.append(f"HSTS: {headers.get('Strict-Transport-Security', 'N/A')}")

    # 14. Security Headers Audit
    out_lines.append("Security Headers Audit:")
    present_h, missing_h, header_notes, cookie_notes = audit_security_headers(headers)
    for h in present_h:
        out_lines.append(f" - [Present] {h}")
    for m in missing_h:
        out_lines.append(f" - [MISSING] {m}")
    for n in header_notes:
        out_lines.append(f" - Note: {n}")
    for c in cookie_notes:
        out_lines.append(f" - Cookie Note: {c}")

    # 15. HTTP Methods & Web Files
    out_lines.append("HTTP Methods:")
    out_lines.extend(check_http_methods(target))
    out_lines.append("Web Files:")
    out_lines.extend(check_web_files(target))

    # 16. TLS/SSL Analysis
    out_lines.append("TLS/SSL Analysis:")
    if open_ports and 443 not in open_ports:
        out_lines.append(" - Port 443 not open, skipping TLS analysis")
    else:
        out_lines.extend(analyze_tls(target))
        supported = test_tls_protocols(target)
        out_lines.append(f" - Supported Protocols: {', '.join(supported) if supported else 'Handshake failed'}")
        weak = test_weak_ciphers(target)
        out_lines.append(f" - Legacy/Weak Ciphers Accepted: {', '.join(weak) if weak else 'None detected'}")

    # 17. WAF Bypass Suggestions
    out_lines.append("WAF Bypass Suggestions:")
    if waf_name in WAF_BYPASSES:
        for tip in WAF_BYPASSES[waf_name]:
            out_lines.append(f" - {tip}")
    else:
        out_lines.append(" - N/A (No WAF detected)")

    # Write and Print
    file_output = "\n".join(out_lines)
    with open("tech.txt", "w", encoding="utf-8") as f:
        f.write(file_output + "\n")

    print(_paint_report(file_output))

if __name__ == "__main__":
    main()
