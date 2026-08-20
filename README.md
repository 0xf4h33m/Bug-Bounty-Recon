# Recon Pipeline

Subdomain enumeration → URL collection → JS asset extraction → JS download & compile.

## Requirements

```
subfinder assetfinder findomain waybackurls gau katana waymore gospider httpx-toolkit
```

Install via [GoReleases](https://github.com/offensive-security/goaudit/blob/master/README.md) or [PentestTools](https://pentest-tools.com). Only the tools you have installed will be used — missing ones are skipped automatically.

## Usage Flow

```
1. subs.py        → enumerate subdomains of target
2. urls.py        → collect live URLs from those subdomains
3. jsfilter.py    → extract first-party .js URLs from urls.txt
4. jsdownloader.py → download all JS files into one compiled file
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

Or scope it to a specific subdomain from step 1:
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

## Flags

| Script | Flag | Effect |
|--------|------|--------|
| `subs.py` | `-q` | Quiet mode (hides debug output) |
| `jsfilter.py` | `-v` | Verbose mode |
| `jsfilter.py` | `-o <file>` | Custom output filename |

## Full Example

```bash
python3 subs.py bugbounty.com
python3 urls.py bugbounty.com
python3 jsfilter.py urls.txt
python3 jsdownloader.py js_urls.txt

# now grep for secrets
grep -i "api[_-]\?key\|secret\|token\|password" js_files.txt
grep -i "firebase\|aws\|graphql" js_files.txt
```
