# Recon Pipeline

Subdomain enumeration → URL collection → JS asset extraction → JS download & compile → cache poisoning → vuln scanning → infra fingerprinting.

## Requirements

```
subfinder assetfinder findomain waybackurls gau katana waymore gospider httpx-toolkit naabu nmap dig whois
```

Install via [GoReleases](https://github.com/offensive-security/goaudit/blob/master/README.md) or [PentestTools](https://pentest-tools.com). Only the tools you have installed will be used — missing ones are skipped automatically.

## Scripts

| Script | Purpose | Output |
|--------|---------|--------|
| `subs.py` | Subdomain enumeration | `subs.txt` |
| `urls.py` | URL collection from recon tools | `urls.txt` |
| `jsfilter.py` | Extract first-party JS URLs | `js_urls.txt` |
| `jsdownloader.py` | Download & compile JS files | `js_files.txt` |
| `cache.py` | Cache endpoint discovery | `cache.txt` |
| `find.py` | 60+ vulnerability checks | `vulns.txt` |
| `tech.py` | Infra fingerprinting & profiling | `tech.txt` |

## Usage Flow

```
Phase 1 — Recon
  subs.py        → enumerate subdomains
  urls.py        → collect live URLs

Phase 2 — JS Analysis
  jsfilter.py    → extract .js URLs from urls.txt
  jsdownloader.py → download all JS into one file

Phase 3 — Targeted Scans
  cache.py       → find cacheable endpoints & poisoning vectors
  find.py        → run 60+ vuln checks against the target
  tech.py        → fingerprint stack, ports, WAF, TLS, DNS
```

### Step 1 — Subdomains

```bash
python3 subs.py example.com
# output → subs.txt
```

### Step 2 — URLs

```bash
python3 urls.py example.com
# output → urls.txt
```

Or scope to a specific subdomain from step 1:
```bash
python3 urls.py api.example.com
```

### Step 3 — Filter JS URLs

```bash
python3 jsfilter.py urls.txt
# output → js_urls.txt
```

Filters out CDN, analytics, tracking scripts. Only keeps first-party `.js` and `.js.map` files.

### Step 4 — Download JS

```bash
python3 jsdownloader.py js_urls.txt
# output → js_files.txt
```

Compiles all JS into a single file, formatted with delimiters for easy grepping.

### Step 5 — Cache Endpoints

```bash
python3 cache.py example.com
# output → cache.txt
```

Finds cacheable URLs via waybackurls/gau, probes them for cache headers (Age, X-Cache, CF-Cache-Status, Varnish, etc.), and flags HIT vs CACHEABLE endpoints for cache poisoning research.

### Step 6 — Vulnerability Scan

```bash
python3 find.py example.com
# output → vulns.txt
```

Runs 60+ checks: exposed files (.git, .env, backups), security headers, CORS, HTTP methods, request smuggling (CL.TE/TE.CL/TE.TE), XSS, open redirect, CRLF, SSTI, SQLi, command injection, path traversal, cache poisoning, TLS weak ciphers, and more.

### Step 7 — Tech Fingerprinting

```bash
python3 tech.py example.com
# output → tech.txt
```

DNS records, IP/IPv6 resolution, origin IP discovery (MX/SPF bypass), port scanning (naabu → nmap → python fallback), database discovery, WAF detection with confidence level, cache provider, security header audit, TLS certificate & protocol analysis, weak cipher detection, HTTP methods, and WAF bypass suggestions.

## Flags

| Script | Flag | Effect |
|--------|------|--------|
| `subs.py` | `-q` | Quiet mode |
| `cache.py` | `-q` | Quiet mode |
| `jsfilter.py` | `-v` | Verbose mode |
| `jsfilter.py` | `-o <file>` | Custom output filename |

## Full Recon Example

```bash
# recon chain
python3 subs.py bugbounty.com
python3 urls.py bugbounty.com
python3 jsfilter.py urls.txt
python3 jsdownloader.py js_urls.txt

# targeted scans
python3 cache.py bugbounty.com
python3 find.py bugbounty.com
python3 tech.py bugbounty.com

# grep for secrets in JS
grep -i "api[_-]\?key\|secret\|token\|password" js_files.txt
grep -i "firebase\|aws\|graphql" js_files.txt

# review cache poisoning surface
cat cache.txt

# review findings
cat vulns.txt
cat tech.txt
```
