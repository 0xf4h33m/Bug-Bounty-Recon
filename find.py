#!/usr/bin/env python3

from __future__ import annotations

import concurrent.futures
import datetime
import ipaddress
import logging
import os
import re
import socket
import ssl
import sys
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def _supports_color() -> bool:
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

LOG_FORMAT = "%(asctime)s │ %(levelname)-8s │ %(message)s"
DATE_FORMAT = "%H:%M:%S"


class ColoredFormatter(logging.Formatter):
    LEVEL_COLORS = {
        logging.DEBUG: CYAN,
        logging.INFO: GREEN,
        logging.WARNING: YELLOW,
        logging.ERROR: RED,
        logging.CRITICAL: MAGENTA + BOLD,
    }

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        if not _COLOR:
            return message
        color = self.LEVEL_COLORS.get(record.levelno, "")
        return f"{color}{message}{RESET}" if color else message


_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(ColoredFormatter(LOG_FORMAT, datefmt=DATE_FORMAT))
logging.basicConfig(level=logging.INFO, handlers=[_handler])
logger = logging.getLogger("FindScanner")

SEV_STYLE = {
    "CRITICAL": MAGENTA + BOLD,
    "HIGH": RED + BOLD,
    "MEDIUM": YELLOW + BOLD,
    "LOW": BLUE + BOLD,
    "INFO": CYAN,
}

@dataclass
class Finding:
    severity: str
    title: str
    url: str = ""
    evidence: str = ""
    recommendation: str = ""
    detail: str = ""

    def render_console(self) -> str:
        color = SEV_STYLE.get(self.severity, "")
        head = f"{color}[{self.severity}]{RESET} {BOLD}{self.title}{RESET}"
        lines = [head]
        if self.url:
            lines.append(f"       URL : {self.url}")
        if self.evidence:
            lines.append(f"       Evidence : {self.evidence[:300]}")
        if self.recommendation:
            lines.append(f"       Fix    : {self.recommendation}")
        if self.detail:
            lines.append(f"       Detail : {self.detail[:300]}")
        return "\n".join(lines)

    def render_file(self) -> str:
        sep = "-" * 80
        out = [sep, f"[{self.severity}] {self.title}"]
        if self.url:
            out.append(f"  URL       : {self.url}")
        if self.evidence:
            out.append(f"  Evidence  : {self.evidence}")
        if self.recommendation:
            out.append(f"  Fix       : {self.recommendation}")
        if self.detail:
            out.append(f"  Detail    : {self.detail}")
        return "\n".join(out)


@dataclass
class ScanConfig:
    host: str
    port: int = 443
    output_filename: str = "vulns.txt"
    threads: int = 12
    timeout: int = 10
    max_body_bytes: int = 65536
    use_http2: bool = True


@dataclass
class BaseUrls:
    https: Optional[str] = None
    http: Optional[str] = None

    @property
    def primary(self) -> Optional[str]:
        return self.https or self.http


class Report:
    """Collects findings, streams them to console AND appends to vulns.txt live."""

    def __init__(self, output_path: Path):
        self.output_path = output_path
        self.findings: List[Finding] = []

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)
        print()
        print(finding.render_console())
        with self.output_path.open("a", encoding="utf-8") as f:
            f.write(finding.render_file() + "\n")

    def add_bulk(self, findings: List[Finding]) -> None:
        for f in findings:
            self.add(f)

    def init_file(self, target: str) -> None:
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        banner = (
            "=" * 100 + "\n"
            f" VULNERABILITY SCAN REPORT\n"
            f" Target     : {target}\n"
            f" Started    : {now}\n"
            " Generated  : find.py\n"
            + "=" * 100 + "\n"
        )
        self.output_path.write_text(banner, encoding="utf-8")

    def finalize(self, duration: float) -> None:
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        summary = ["", "=" * 100, " SUMMARY", "=" * 100]
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            summary.append(f"  {sev:<9}: {counts.get(sev, 0)}")
        summary.append(f"  {'TOTAL':<9}: {len(self.findings)}")
        summary.append(f"  Duration  : {duration:.1f}s")
        summary.append("=" * 100 + "\n")
        block = "\n".join(summary)
        print(block)
        with self.output_path.open("a", encoding="utf-8") as f:
            f.write(block)
        logger.info(f"Results saved to -> {self.output_path.resolve()}")


class TargetParser:
    @staticmethod
    def parse(target_input: str) -> Tuple[str, int]:
        raw = target_input.strip()
        port = 443
        if raw.startswith("http://"):
            parsed = urlparse(raw)
            return parsed.hostname or raw, parsed.port or 80
        if raw.startswith("https://"):
            parsed = urlparse(raw)
            return parsed.hostname or raw, parsed.port or 443
        if ":" in raw.split("/")[0]:
            host, _, port_str = raw.rpartition(":")
            if host and port_str.isdigit():
                return host, int(port_str)
        return raw, port


class HttpEngine:
    """Thin wrapper around requests with retries, streaming and body truncation."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.session = requests.Session()
        retry = Retry(total=1, backoff_factor=0.4, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=30)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/125.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
        })
        self.session.verify = True

    def fetch(self, url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None,
              data=None, max_bytes: Optional[int] = None, allow_redirects: bool = True
              ) -> Tuple[Optional[int], Dict[str, str], bytes, int]:
        max_bytes = max_bytes or self.config.max_body_bytes
        try:
            with self.session.request(method, url, stream=True, timeout=self.config.timeout,
                                      headers=headers, data=data, allow_redirects=allow_redirects) as r:
                hdrs = {k.lower(): v for k, v in r.headers.items()}
                chunks: List[bytes] = []
                total = 0
                for chunk in r.iter_content(8192):
                    chunks.append(chunk)
                    total += len(chunk)
                    if total >= max_bytes:
                        break
                return r.status_code, hdrs, b"".join(chunks), total
        except Exception:
            return None, {}, b"", 0

    def status(self, url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None) -> Tuple[Optional[int], Dict[str, str]]:
        code, hdrs, _, _ = self.fetch(url, method=method, headers=headers, max_bytes=1024)
        return code, hdrs


class BaselineScanner:
    """Probes root on both schemes, fingerprints the stack and redirect behaviour."""

    def __init__(self, engine: HttpEngine, config: ScanConfig, report: Report):
        self.engine = engine
        self.config = config
        self.report = report
        self.base = BaseUrls()

    def run(self) -> BaseUrls:
        host = self.config.host
        http_url = f"http://{host}:{self.config.port}" if self.config.port not in (443, 80) else f"http://{host}/"
        https_url = f"https://{host}:{self.config.port}" if self.config.port not in (443, 80) else f"https://{host}/"

        code, hdrs, body, size = self.engine.fetch(https_url)
        if code:
            self.base.https = https_url
            self._fingerprint(hdrs, https_url)
            self._redirect_checks(https_url)
        else:
            logger.warning("HTTPS unreachable, trying HTTP only...")

        code, hdrs, body, size = self.engine.fetch(http_url)
        if code:
            self.base.http = http_url
            if not self.base.https:
                logger.warning("Target is HTTP-only (HTTPS unreachable).")
                self.report.add(Finding(
                    "HIGH", "HTTP-only target (no TLS)", url=http_url,
                    evidence="HTTPS connection failed; target only speaks plaintext HTTP.",
                    recommendation="Serve the service exclusively over HTTPS."))
            if self.base.https:
                final = self.engine.fetch(http_url)
                if final[0] is not None and final[0] not in (301, 302, 307, 308):
                    self.report.add(Finding(
                        "MEDIUM", "HTTP does not redirect to HTTPS", url=http_url,
                        evidence=f"GET http://{host}/ returned {final[0]}, not a 3xx redirect.",
                        recommendation="Redirect all HTTP traffic to HTTPS via 301."))

        if not self.base.primary:
            logger.error("Both HTTP and HTTPS are unreachable. Aborting.")
            sys.exit(1)

        logger.info(f"Primary base: {self.base.primary}")
        return self.base

    def _fingerprint(self, hdrs: Dict[str, str], url: str) -> None:
        server = hdrs.get("server")
        powered = hdrs.get("x-powered-by")
        if server:
            logger.info(f"Server: {server}")
        if powered:
            self.report.add(Finding(
                "LOW", "X-Powered-By header disclosure", url=url,
                evidence=f"X-Powered-By: {powered}",
                recommendation="Remove X-Powered-By / disable server signatures."))
        for h in ("via", "x-backend-server", "x-served-by", "x-aspnet-version", "x-runtime"):
            if hdrs.get(h):
                logger.info(f"Info header {h}: {hdrs[h]}")
        if re.search(r"\d+\.\d+", server or ""):
            self.report.add(Finding(
                "LOW", "Server version disclosure", url=url,
                evidence=f"Server: {server}",
                recommendation="Hide the Server banner / version string."))

    def _redirect_checks(self, url: str) -> None:
        hdrs = self.engine.session.get(url, timeout=self.config.timeout).headers
        hdrs = {k.lower(): v for k, v in hdrs.items()}
        sts = hdrs.get("strict-transport-security", "")
        if not sts:
            self.report.add(Finding(
                "MEDIUM", "Missing HSTS header", url=url,
                evidence="No Strict-Transport-Security present.",
                recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."))
        elif "includeSubDomains" not in sts:
            self.report.add(Finding(
                "LOW", "HSTS missing includeSubDomains", url=url,
                evidence=f"Strict-Transport-Security: {sts}",
                recommendation="Add includeSubDomains to HSTS."))
        m = re.search(r"max-age=(\d+)", sts)
        if m and int(m.group(1)) < 31536000:
            self.report.add(Finding(
                "LOW", "HSTS max-age too short", url=url,
                evidence=f"Strict-Transport-Security: {sts}",
                recommendation="Set HSTS max-age to at least 31536000 (1 year)."))


# (path, label, regex signature) — regex matched against the first bytes of body
FILE_SIGNATURES: List[Tuple[str, str, str]] = [
    ("/robots.txt", "robots.txt", r"user-agent"),
    ("/sitemap.xml", "sitemap.xml", r"<urlset|<sitemapindex|url>"),
    ("/sitemap_index.xml", "sitemap_index.xml", r"<sitemapindex"),
    ("/sitemap.txt", "sitemap.txt", r"^https?://"),
    ("/.well-known/security.txt", "security.txt", r"contact\s*:"),
    ("/security.txt", "security.txt", r"contact\s*:"),
    ("/humans.txt", "humans.txt", r"team|site|thanks|author"),
    ("/crossdomain.xml", "crossdomain.xml", r"cross-domain-policy|allow-access-from"),
    ("/.git/HEAD", ".git/HEAD", r"^ref:"),
    ("/.git/config", ".git/config", r"\[core\]|\[remote"),
    ("/.gitignore", ".gitignore", r"node_modules|\.env|dist/"),
    ("/.svn/entries", ".svn/entries", r"\d{1,2}\s*$|^12"),
    ("/.svn/wc.db", ".svn/wc.db", r"SQLite"),
    ("/.hg/store", ".hg/store", r"requires"),
    ("/.DS_Store", ".DS_Store", r"Bud1"),
    ("/.htaccess", ".htaccess", r"rewriteengine|order\s+deny|require"),
    ("/.htpasswd", ".htpasswd", r"^[^:]+:\$"),
    ("/web.config", "web.config", r"<configuration>|system.web"),
    ("/web.config.txt", "web.config.txt", r"<configuration>"),
    ("/.env", ".env", r"(DB_|API_KEY|SECRET|PASSWORD|TOKEN|AWS_)"),
    ("/.env.bak", ".env.bak", r"(DB_|API_KEY|SECRET|PASSWORD|TOKEN)"),
    ("/.env.local", ".env.local", r"(DB_|API_KEY|SECRET|PASSWORD|TOKEN)"),
    ("/.env.production", ".env.production", r"(DB_|API_KEY|SECRET|PASSWORD|TOKEN)"),
    ("/.env.example", ".env.example", r"(DB_|API_KEY|SECRET)"),
    ("/config.json", "config.json", r"[\"'](key|secret|password|token)[\"']"),
    ("/config.js", "config.js", r"[\"'](api[_-]?key|secret|token)[\"']"),
    ("/config.php", "config.php", r"<\?php|\$config"),
    ("/configuration.php", "configuration.php", r"<\?php|\$config"),
    ("/wp-config.php", "wp-config.php", r"DB_PASSWORD|DB_USER"),
    ("/wp-config.php.bak", "wp-config.php.bak", r"DB_PASSWORD"),
    ("/application.properties", "application.properties", r"(password|secret|jdbc:mysql)"),
    ("/application.yml", "application.yml", r"(password|secret|jdbc:)"),
    ("/appsettings.json", "appsettings.json", r"[\"'](DefaultConnection|Secret|Key)"),
    ("/composer.json", "composer.json", r"\"require\"|packages"),
    ("/package.json", "package.json", r"\"dependencies\"|\"scripts\""),
    ("/package-lock.json", "package-lock.json", r"\"lockfileVersion\""),
    ("/yarn.lock", "yarn.lock", r"^# yarn lockfile"),
    ("/requirements.txt", "requirements.txt", r"==|>=|flask|django"),
    ("/Pipfile", "Pipfile", r"\[packages\]|\[dev-packages\]"),
    ("/Dockerfile", "Dockerfile", r"^FROM |^RUN "),
    ("/docker-compose.yml", "docker-compose.yml", r"^services:|version:"),
    ("/.travis.yml", ".travis.yml", r"language:|script:"),
    ("/.circleci/config.yml", ".circleci/config.yml", r"version:\s*\d"),
    ("/.github/workflows/main.yml", "github workflow", r"^on:"),
    ("/.aws/credentials", "AWS credentials", r"aws_access_key_id|aws_secret_access_key"),
    ("/.aws/config", "AWS config", r"\[default\]|region"),
    ("/.ssh/id_rsa", "SSH private key", r"BEGIN.*RSA PRIVATE KEY"),
    ("/id_rsa", "SSH private key", r"BEGIN.*RSA PRIVATE KEY"),
    ("/key.pem", "PEM private key", r"BEGIN.*PRIVATE KEY"),
    ("/credentials.json", "credentials.json", r"client_secret|client_id"),
    ("/client_secret.json", "client_secret.json", r"client_secret"),
    ("/service-account.json", "service-account.json", r"private_key"),
    ("/.npmrc", ".npmrc", r"_auth|registry"),
    ("/.netrc", ".netrc", r"login|password"),
    ("/.gitconfig", ".gitconfig", r"\[user\]|\[core\]"),
    ("/phpinfo.php", "phpinfo.php", r"phpinfo\(\)|php version"),
    ("/info.php", "info.php", r"phpinfo\(\)|php version"),
    ("/test.php", "test.php", r"<\?php|phpinfo"),
    ("/index.php.bak", "index.php.bak", r"<\?php"),
    ("/index.php.old", "index.php.old", r"<\?php"),
    ("/index.php~", "index.php~", r"<\?php"),
    ("/index.php.swp", "index.php.swp", r"<\?php|Vim"),
    ("/config.php.bak", "config.php.bak", r"<\?php|\$config"),
    ("/config.old", "config.old", r"<\?php|\$config"),
    ("/config.save", "config.save", r"<\?php|\$config"),
    ("/backup.zip", "backup.zip", ""),
    ("/backup.tar.gz", "backup.tar.gz", ""),
    ("/backup.sql", "backup.sql", r"CREATE TABLE|INSERT INTO|DROP TABLE"),
    ("/db.sql", "db.sql", r"CREATE TABLE|INSERT INTO"),
    ("/database.sql", "database.sql", r"CREATE TABLE|INSERT INTO"),
    ("/dump.sql", "dump.sql", r"CREATE TABLE|INSERT INTO"),
    ("/data.sql", "data.sql", r"CREATE TABLE|INSERT INTO"),
    ("/db_backup.sql", "db_backup.sql", r"CREATE TABLE|INSERT INTO"),
    ("/database-backup.zip", "database-backup.zip", ""),
    ("/site.tar.gz", "site.tar.gz", ""),
    ("/www.zip", "www.zip", ""),
    ("/web.zip", "web.zip", ""),
    ("/admin.zip", "admin.zip", ""),
    ("/access.log", "access.log", r"\d+\.\d+\.\d+\.\d+.*\"(GET|POST)"),
    ("/error.log", "error.log", r"\[.*(error|fatal|warning)\]"),
    ("/debug.log", "debug.log", r"debug|error"),
    ("/logs/error.log", "logs/error.log", r"error|warning"),
    ("/server-status", "server-status", r"apache server status|server uptime"),
    ("/server-info", "server-info", r"apache server information|server settings"),
    ("/cgi-bin/printenv", "printenv", r"HTTP_HOST|SERVER_SOFTWARE"),
    ("/cgi-bin/test-cgi", "cgi-bin test-cgi", r"Content-type|argv"),
    ("/swagger-ui.html", "swagger-ui", r"swagger"),
    ("/swagger/index.html", "swagger-ui", r"swagger"),
    ("/swagger/v2/api-docs", "swagger api-docs", r"swagger|\"paths\""),
    ("/swagger/v3/api-docs", "swagger api-docs", r"swagger|openapi"),
    ("/v2/api-docs", "api-docs", r"\"paths\"|\"swagger\""),
    ("/v3/api-docs", "api-docs", r"openapi|\"paths\""),
    ("/openapi.json", "openapi.json", r"openapi|\"paths\""),
    ("/api-docs", "api-docs", r"swagger|openapi|\"paths\""),
    ("/graphql", "graphql", r"graphql"),
    ("/graphiql", "graphiql", r"graphiql|graphql"),
    ("/graph", "graph", r"graphql"),
    ("/actuator", "spring actuator", r"_links|status"),
    ("/actuator/health", "actuator health", r"\"status\"|UP"),
    ("/actuator/env", "actuator env", r"\"propertySources\"|\"environment\""),
    ("/actuator/heapdump", "actuator heapdump", ""),
    ("/actuator/mappings", "actuator mappings", r"\"handler\"|\"method\""),
    ("/actuator/beans", "actuator beans", r"\"bean\""),
    ("/actuator/configprops", "actuator configprops", r"\"properties\""),
    ("/.well-known/assetlinks.json", "assetlinks.json", r"\["),
    ("/.well-known/apple-app-site-association", "apple-app-site-association", r"applinks|apps"),
    ("/.well-known/change-password", "change-password", r"form|password"),
    ("/adminer.php", "adminer", r"adminer"),
    ("/phpmyadmin", "phpmyadmin", r"phpmyadmin"),
    ("/pma", "phpmyadmin", r"phpmyadmin"),
    ("/dbadmin", "dbadmin", r"adminer|phpmyadmin|login"),
    ("/console", "console", r"login|shell|console"),
    ("/manager/html", "tomcat manager", r"tomcat|manager"),
    ("/jenkins", "jenkins", r"jenkins"),
    ("/vendor/composer/installed.json", "composer installed", r"packages|name"),
    ("/vite.config.js", "vite config", r"export default"),
    ("/next.config.js", "next config", r"module\.exports"),
    ("/.well-known/openid-configuration", "openid config", r"issuer|jwks_uri"),
    ("/favicon.ico", "favicon", ""),
    ("/elb-status", "aws elb status", r"ok"),
]

# paths that usually indicate an admin/portal area (status alone is enough)
ADMIN_PATHS: List[str] = [
    "/admin", "/administrator", "/admin/login", "/admin.php", "/login", "/login.php",
    "/signin", "/user/login", "/account/login", "/portal", "/manage", "/management",
    "/dashboard", "/cp", "/cpanel", "/plesk", "/webmin", "/user", "/member",
    "/account", "/wp-admin", "/wp-login.php", "/wp-content/", "/wp-json/wp/v2/users",
]

# directory paths that may allow listing
DIR_LISTING_PATHS: List[str] = [
    "/uploads/", "/upload/", "/files/", "/static/", "/img/", "/images/", "/css/",
    "/js/", "/assets/", "/backup/", "/backups/", "/downloads/", "/download/",
    "/media/", "/tmp/", "/data/", "/logs/", "/public/", "/content/", "/admin/uploads/",
]

ERROR_SIGNATURES: List[str] = [
    "fatal error", "stack trace", "exception in", "sqlstate", "odbc driver",
    "syntax error", "undefined variable", "cannot connect", "mysql_",
]


class ContentDiscovery:
    """Sweeps FILE_SIGNATURES + ADMIN_PATHS + DIR_LISTING in parallel."""

    def __init__(self, engine: HttpEngine, config: ScanConfig, base: BaseUrls, report: Report):
        self.engine = engine
        self.config = config
        self.base = base
        self.report = report
        self.found_urls: Set[str] = set()

    def run(self) -> None:
        base = self.base.primary
        if not base:
            return
        logger.info(f"Content discovery on {len(FILE_SIGNATURES) + len(ADMIN_PATHS) + len(DIR_LISTING_PATHS)} paths...")
        tasks = [p for p, _, _ in FILE_SIGNATURES] + ADMIN_PATHS + DIR_LISTING_PATHS
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.threads) as ex:
            futures = {ex.submit(self._probe, base, p): p for p in tasks}
            for fut in concurrent.futures.as_completed(futures):
                try:
                    fut.result()
                except Exception:
                    pass

    def _probe(self, base: str, path: str) -> None:
        url = urljoin(base, path)
        code, hdrs, body, size = self.engine.fetch(url)
        if code is None:
            return
        self.found_urls.add(url)

        sig_match = None
        for p, label, sig in FILE_SIGNATURES:
            if path == p:
                sig_match = (label, sig)
                break

        if sig_match and code in (200, 301):
            label, sig = sig_match
            text = body[:4096].decode("utf-8", "ignore")
            ctype = hdrs.get("content-type", "")
            matched = (not sig) or re.search(sig, text, re.IGNORECASE)
            archive_hit = sig == "" and (re.search(r"zip|gzip|x-tar|octet-stream", ctype) or size > 5000)
            if matched or archive_hit:
                logger.info(f"{GREEN}[+]{RESET} {code} {url} ({size} B) -> {label}")
                sev = "HIGH" if label in (".git/HEAD", ".git/config", ".env", ".aws credentials",
                                          "SSH private key", "database", "backup") else "MEDIUM"
                self.report.add(Finding(
                    sev, f"Exposed file: {label}", url=url,
                    evidence=f"HTTP {code}, {size} bytes. Content-Type: {ctype}",
                    recommendation="Remove the file from the web root or block it on the WAF/CDN."))
                return

        if path in ADMIN_PATHS and code in (200, 302, 303):
            text = body[:2048].decode("utf-8", "ignore").lower()
            login_hint = any(k in text for k in ("password", "username", "login", "sign in", "csrf"))
            if login_hint or code == 200:
                logger.info(f"{GREEN}[+]{RESET} {code} {url} -> admin/login area")
                self.report.add(Finding(
                    "MEDIUM", f"Admin/login panel exposed: {path}", url=url,
                    evidence=f"HTTP {code}, {size} bytes.",
                    recommendation="Restrict admin areas by IP / VPN and enforce MFA."))

        if path in DIR_LISTING_PATHS and code == 200:
            text = body[:4096].decode("utf-8", "ignore")
            if re.search(r"index of|<title>.*listing|to parent directory", text, re.IGNORECASE):
                logger.info(f"{GREEN}[+]{RESET} {code} {url} -> directory listing")
                self.report.add(Finding(
                    "HIGH", "Directory listing enabled", url=url,
                    evidence="Response contains an 'Index of' / directory listing page.",
                    recommendation="Disable autoindex / directory browsing on the web server."))

        # verbose error detection on any 500/404
        if code in (500, 501, 502) and re.search("|".join(ERROR_SIGNATURES),
                                                 body[:4096].decode("utf-8", "ignore"), re.IGNORECASE):
            self.report.add(Finding(
                "LOW", "Verbose error page leaks internals", url=url,
                evidence=f"HTTP {code} body contains stack trace / framework error.",
                recommendation="Enable custom error pages and disable detailed errors in production."))

    def parse_robots(self) -> List[str]:
        """Extract Disallow paths from robots.txt if present."""
        base = self.base.primary
        if not base:
            return []
        code, hdrs, body, _ = self.engine.fetch(urljoin(base, "/robots.txt"))
        if code != 200:
            return []
        paths = []
        for line in body.decode("utf-8", "ignore").splitlines():
            line = line.strip()
            if line.lower().startswith(("disallow:", "allow:")):
                p = line.split(":", 1)[1].strip()
                if p and not p.startswith(("*", "/")):
                    continue
                if p and p != "/" and len(p) < 100:
                    paths.append(p)
        return paths[:20]


class HeaderScanner:
    """Checks missing security headers, cookie flags, CORS, cache headers."""

    REQUIRED = {
        "content-security-policy": ("Missing Content-Security-Policy", "MEDIUM"),
        "x-frame-options": ("Missing X-Frame-Options (clickjacking)", "MEDIUM"),
        "x-content-type-options": ("Missing X-Content-Type-Options", "LOW"),
        "referrer-policy": ("Missing Referrer-Policy", "LOW"),
        "permissions-policy": ("Missing Permissions-Policy", "LOW"),
    }

    def __init__(self, engine: HttpEngine, config: ScanConfig, base: BaseUrls, report: Report):
        self.engine = engine
        self.config = config
        self.base = base
        self.report = report

    def run(self) -> None:
        url = self.base.primary
        if not url:
            return
        logger.info("Scanning security headers, cookies, CORS and cache headers...")
        code, hdrs, body, size = self.engine.fetch(url)

        if code is None:
            return

        for hdr, (title, sev) in self.REQUIRED.items():
            if hdr not in hdrs:
                self.report.add(Finding(sev, title, url=url,
                    evidence=f"Response has no '{hdr}' header.",
                    recommendation=f"Set the '{hdr}' header."))

        csp = hdrs.get("content-security-policy", "")
        if "frame-ancestors" in csp and "x-frame-options" not in hdrs:
            self.report.add(Finding("INFO", "CSP frame-ancestors present (XFO absent)", url=url,
                evidence="CSP frame-ancestors mitigates clickjacking even without X-Frame-Options."))

        if hdrs.get("x-xss-protection") == "0":
            self.report.add(Finding("INFO", "X-XSS-Protection explicitly disabled", url=url,
                evidence="X-XSS-Protection: 0",
                recommendation="Modern sites use CSP; consider removing this header instead of disabling."))

        # ---- cookie flags ----
        for ck in hdrs.get("set-cookie", "").split(", "):
            ck = ck.strip()
            if not ck or "=" not in ck:
                continue
            name = ck.split("=", 1)[0].strip()
            flags = ck.lower()
            if "httponly" not in flags:
                self.report.add(Finding("LOW", f"Cookie '{name}' missing HttpOnly", url=url,
                    evidence=ck, recommendation="Add the HttpOnly flag."))
            if self.base.https and "secure" not in flags:
                self.report.add(Finding("LOW", f"Cookie '{name}' missing Secure flag", url=url,
                    evidence=ck, recommendation="Add the Secure flag (cookie sent over TLS only)."))
            if "samesite" not in flags:
                self.report.add(Finding("LOW", f"Cookie '{name}' missing SameSite attribute", url=url,
                    evidence=ck, recommendation="Set SameSite=Lax or Strict to mitigate CSRF."))

        # ---- cache behaviour ----
        cc = hdrs.get("cache-control", "")
        age = hdrs.get("age")
        xcache = hdrs.get("x-cache")
        if age or xcache or re.search(r"public|s-maxage|max-age", cc):
            logger.info(f"{YELLOW}[!]{RESET} Caching layer detected: cache-control={cc or '-'} age={age or '-'} x-cache={xcache or '-'}")
            self.report.add(Finding("INFO", "Edge/cache layer detected", url=url,
                evidence=f"cache-control={cc} age={age} x-cache={xcache}",
                recommendation="If this page is personalized, ensure it is excluded from the cache."))
        if "no-cache" not in cc and "no-store" not in cc and code == 200 and self._is_sensitive(url):
            self.report.add(Finding("LOW", "Missing Cache-Control on sensitive page", url=url,
                evidence=f"cache-control: {cc or '(absent)'}",
                recommendation="Set 'Cache-Control: no-store' on authenticated pages."))
        m = re.search(r"max-age=(\d+)", cc)
        if m and int(m.group(1)) > 31536000:
            self.report.add(Finding("LOW", "Excessive cache max-age", url=url,
                evidence=f"cache-control: {cc}",
                recommendation="Reduce max-age or use no-store for dynamic content."))

        # ---- CORS ----
        self._cors(url)

    def _is_sensitive(self, url: str) -> bool:
        return re.search(r"(account|login|profile|cart|checkout|payment|dashboard)", url, re.IGNORECASE) is not None

    def _cors(self, url: str) -> None:
        evil = "https://evil.example.com"
        code, hdrs, _, _ = self.engine.fetch(url, headers={"Origin": evil})
        if code is None:
            return
        acao = hdrs.get("access-control-allow-origin", "")
        acac = hdrs.get("access-control-allow-credentials", "").lower()
        if acao == evil and acac == "true":
            self.report.add(Finding("HIGH", "CORS reflects arbitrary Origin with credentials", url=url,
                evidence=f"Origin: {evil} -> Access-Control-Allow-Origin: {acao}, Allow-Credentials: {acac}",
                recommendation="Whitelist specific origins; never reflect Origin with credentials."))
        elif acao == "*" and acac == "true":
            self.report.add(Finding("HIGH", "CORS wildcard with credentials", url=url,
                evidence="Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true",
                recommendation="Wildcard origin must not be combined with credentials."))
        elif acao == evil:
            self.report.add(Finding("MEDIUM", "CORS reflects arbitrary Origin", url=url,
                evidence=f"Access-Control-Allow-Origin: {acao}",
                recommendation="Whitelist specific origins."))
        elif acao:
            logger.info(f"  CORS policy present: {acao} (credentials={acac})")


class MethodScanner:
    def __init__(self, engine: HttpEngine, config: ScanConfig, base: BaseUrls, report: Report):
        self.engine = engine
        self.config = config
        self.base = base
        self.report = report

    def run(self) -> None:
        url = self.base.primary
        if not url:
            return
        logger.info("Auditing HTTP methods (TRACE, PUT, DELETE, OPTIONS)...")

        code, hdrs, body, _ = self.engine.fetch(url, method="TRACE")
        if code == 200 and re.search(r"TRACE|X-Requested-With", body.decode("utf-8", "ignore"), re.IGNORECASE):
            self.report.add(Finding("HIGH", "TRACE method enabled (XST risk)", url=url,
                evidence="TRACE returned 200 with echoed request body.",
                recommendation="Disable the TRACE method on the web server."))
        elif code and code not in (405, 403, 400):
            logger.info(f"  TRACE -> {code}")

        code, hdrs, body, _ = self.engine.fetch(url, method="OPTIONS")
        allow = hdrs.get("allow", "")
        if allow:
            methods = [m.strip() for m in allow.split(",")]
            for dangerous in ("PUT", "DELETE", "PATCH", "CONNECT"):
                if dangerous in methods:
                    self.report.add(Finding("MEDIUM", f"{dangerous} method allowed", url=url,
                        evidence=f"Allow: {allow}",
                        recommendation=f"Disable the {dangerous} method unless explicitly required."))
            logger.info(f"  Allow: {allow}")

        for method in ("PUT", "DELETE"):
            code, _, _, _ = self.engine.fetch(url, method=method, data="find.py-probe")
            if code in (200, 201, 204):
                self.report.add(Finding("MEDIUM", f"{method} method accepted (potential file write/delete)",
                    url=url, evidence=f"{method} returned {code}.",
                    recommendation=f"Disable {method} on this path."))
            elif code and code not in (405, 403, 400):
                logger.info(f"  {method} -> {code}")


UNKEYED_HEADERS = [
    "X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "X-Forwarded-Proto",
    "X-Forwarded-Scheme", "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Prefix",
]


class CacheScanner:
    def __init__(self, engine: HttpEngine, config: ScanConfig, base: BaseUrls, report: Report):
        self.engine = engine
        self.config = config
        self.base = base
        self.report = report

    def run(self) -> None:
        url = self.base.primary
        if not url:
            return
        logger.info("Scanning for cache layer and cache poisoning vectors...")

        nonce = f"findpy{int(time.time())}"
        poison_host = f"poison-{nonce}.example.com"

        # 1. Does this URL get cached at all?
        code1, hdrs1, body1, _ = self.engine.fetch(url)
        code2, hdrs2, body2, _ = self.engine.fetch(url)
        cachey = bool(hdrs1.get("age") or hdrs2.get("age") or hdrs1.get("x-cache")
                      or hdrs2.get("x-cache") or "public" in hdrs1.get("cache-control", ""))
        vary = hdrs1.get("vary", "")
        if cachey:
            self.report.add(Finding("INFO", "Response appears cacheable (cache poisoning surface)",
                url=url,
                evidence=f"age={hdrs2.get('age')} x-cache={hdrs2.get('x-cache')} cache-control={hdrs1.get('cache-control')} vary={vary}",
                recommendation="If any unkeyed input is reflected, restrict cache keys to safe headers."))
        else:
            logger.info("  No edge caching detected (no age/x-cache); poisoning surface limited.")

        # 2. Unkeyed header reflection test
        reflected = []
        for h in UNKEYED_HEADERS:
            code, hdrs, body, _ = self.engine.fetch(url, headers={h: poison_host})
            if code is None:
                continue
            if poison_host.lower() in body.decode("utf-8", "ignore").lower():
                reflected.append(h)
                logger.info(f"{YELLOW}[!]{RESET} {h} reflected in response body -> potential cache poisoning")
                self.report.add(Finding(
                    "HIGH" if cachey else "MEDIUM",
                    f"Unkeyed header '{h}' reflected in response",
                    url=url,
                    evidence=f"Sending '{h}: {poison_host}' reflects the value in the response body.",
                    recommendation="Never echo request headers into the response unless they are cache keys."))

        # 3. Do reflected headers get stored in cache? (second-request confirmation)
        for h in reflected:
            codeA, _, _, _ = self.engine.fetch(url)
            self.engine.fetch(url, headers={h: poison_host})
            codeB, _, bodyB, _ = self.engine.fetch(url)
            if codeB and poison_host in bodyB.decode("utf-8", "ignore"):
                self.report.add(Finding("CRITICAL", "Web cache poisoning (stored poisoned response)",
                    url=url,
                    evidence=f"Header '{h}' reflected AND persisted across a subsequent clean request.",
                    recommendation="Treat the header as a cache key or strip it before caching."))

        # 4. Nginx alias traversal quick probe on a few paths (only a 200/30x is a signal)
        for p in ("/static../", "/css../", "/uploads../", "/img../"):
            code, hdrs, body, _ = self.engine.fetch(urljoin(url, p))
            if code in (200, 301, 302, 303, 307, 308) and len(body) > 0:
                self.report.add(Finding("INFO", f"Potential nginx alias traversal on '{p}'", url=url,
                    evidence=f"{p} returned {code} ({len(body)} bytes).",
                    recommendation="Verify manually with encoded '../' payloads."))


def _read_responses(host: str, port: int, tls: bool, payloads: List[bytes], read_timeout: float = 8.0) -> bytes:
    """Open one connection, send payloads, read until timeout/close. Returns raw bytes."""
    ctx = ssl.create_default_context() if tls else None
    sock = socket.create_connection((host, port), timeout=10)
    try:
        if tls:
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(10)
        for p in payloads:
            sock.sendall(p)
        sock.settimeout(read_timeout)
        data = b""
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
    except Exception:
        data = b""
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return data


class SmugglingScanner:
    """
    Detects CL.TE / TE.CL / TE.TE request smuggling via raw socket probes.

    Detection strategy (response-count + response-content oracle):
      * We send the crafted probe + a follow-up request (GET /robots.txt).
      * If the front/back disagree on message framing, the follow-up response
        gets displaced by the smuggled request's 404 -> we observe a 4xx with
        our nonce (CL.TE), or a 4xx for a mangled method (TE.CL/TE.TE).
      * A consistent parser forwards the smuggled bytes as an extra real request,
        yielding 3 responses (200, 404, 200) -> correctly classified as NOT vuln.
    """

    def __init__(self, config: ScanConfig, base: BaseUrls, report: Report):
        self.config = config
        self.base = base
        self.report = report

    @staticmethod
    def _split_responses(raw: bytes) -> List[Tuple[bytes, bytes]]:
        """Split raw bytes into (status, block) tuples per HTTP response."""
        pos = [(m.start(), m.group(1)) for m in re.finditer(rb"HTTP/\d\.\d (\d{3})", raw)]
        blocks = []
        for i, (start, status) in enumerate(pos):
            end = pos[i + 1][0] if i + 1 < len(pos) else len(raw)
            blocks.append((status, raw[start:end]))
        return blocks

    def _probe(self, host: str, port: int, tls: bool, req: bytes, follow: bytes) -> List[Tuple[bytes, bytes]]:
        raw = _read_responses(host, port, tls, [req, follow])
        return self._split_responses(raw)

    def run(self) -> None:
        host = self.config.host
        tls = bool(self.base.https)
        port = self.config.port if self.config.port not in (80, 443) else (443 if tls else 80)
        logger.info("Testing for HTTP request smuggling (CL.TE / TE.CL / TE.TE)...")

        nonce = f"smug{int(time.time())}"
        hosthdr = host.encode()
        follow = b"GET / HTTP/1.1\r\nHost: " + hosthdr + b"\r\nConnection: close\r\n\r\n"

        # Baseline sanity: two normal requests must yield exactly two 200s.
        baseline = self._probe(host, port, tls,
                               b"GET / HTTP/1.1\r\nHost: " + hosthdr + b"\r\n\r\n", follow)
        if not (len(baseline) == 2 and baseline[-1][0] == b"200"):
            logger.warning("  Smuggling baseline unexpected (%s); results may be unreliable.",
                           [b[0].decode() for b in baseline] or "no response")
            return

        # ---- CL.TE: front-end trusts Content-Length, back-end trusts Transfer-Encoding ----
        tail = b"GET /" + nonce.encode() + b" HTTP/1.1\r\nHost: " + hosthdr + b"\r\nX: x\r\n\r\n"
        body = b"0\r\n\r\n" + tail
        clte = (b"POST / HTTP/1.1\r\nHost: " + hosthdr
                + b"\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                + b"Content-Length: " + str(len(body)).encode()
                + b"\r\nTransfer-Encoding: chunked\r\n\r\n" + body)
        blocks = self._probe(host, port, tls, clte, follow)
        if (len(blocks) == 2 and blocks[0][0] == b"200"
                and blocks[-1][0] in (b"400", b"403", b"404", b"405")
                and nonce.encode() in blocks[-1][1]):
            self.report.add(Finding("HIGH", "Request smuggling: CL.TE",
                url=f"{'https' if tls else 'http'}://{host}/",
                evidence=f"Probe with mismatched CL/TE displaced the follow-up request with a 404 referencing /{nonce}.",
                recommendation="Normalize CL/TE handling: reject requests where both are present, use HTTP/2 with strict parsing."))
        else:
            logger.info("  CL.TE: not detected")

        # ---- TE.CL: front-end trusts Transfer-Encoding, back-end trusts Content-Length ----
        # Body '0\\r\\n\\r\\nG' (CL=6): a CL-using back-end reads it whole, leaving 'G' to
        # mangle the next request method ('G' + 'ET /...' -> 'ET' -> 4xx).
        tecl_body = b"0\r\n\r\nG"
        tecl = (b"POST / HTTP/1.1\r\nHost: " + hosthdr
                + b"\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                + b"Content-Length: " + str(len(tecl_body)).encode()
                + b"\r\nTransfer-Encoding: chunked\r\n\r\n" + tecl_body)
        blocks = self._probe(host, port, tls, tecl, follow)
        if len(blocks) == 2 and blocks[0][0] == b"200" and blocks[-1][0] in (b"400", b"403", b"404", b"405"):
            self.report.add(Finding("HIGH", "Request smuggling: TE.CL",
                url=f"{'https' if tls else 'http'}://{host}/",
                evidence="Mismatched TE/CL probe caused the follow-up request to be answered with a 4xx.",
                recommendation="Reject requests that contain both CL and TE; enforce one framing method."))
        else:
            logger.info("  TE.CL: not detected")

        # ---- TE.TE: obfuscated Transfer-Encoding headers (duplicate / empty value) ----
        tet_variants = (
            b"Transfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n",
            b"Transfer-Encoding: chunked\r\nTransfer-Encoding:\r\n",
            b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
        )
        for idx, te_headers in enumerate(tet_variants, start=1):
            tet = (b"POST / HTTP/1.1\r\nHost: " + hosthdr
                   + b"\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                   + b"Content-Length: " + str(len(tecl_body)).encode()
                   + b"\r\n" + te_headers + b"\r\n" + tecl_body)
            blocks = self._probe(host, port, tls, tet, follow)
            if len(blocks) == 2 and blocks[0][0] == b"200" and blocks[-1][0] in (b"400", b"403", b"404", b"405"):
                self.report.add(Finding("HIGH", "Request smuggling: TE.TE (obfuscated TE)",
                    url=f"{'https' if tls else 'http'}://{host}/",
                    evidence=f"Duplicate/obfuscated Transfer-Encoding probe variant {idx} was honored.",
                    recommendation="Drop requests with multiple or malformed Transfer-Encoding headers."))
                break
        else:
            logger.info("  TE.TE: not detected")


XSS_PAYLOAD = "<script>alert(document.domain)</script>"
SSTI_PAYLOAD = "{{7*7}}"
SQ_PAYLOAD = "' OR '1'='1"
CMDI_PAYLOAD = ";id;echo findpycmdi;"
TRAV_PAYLOAD = "../../../../../../etc/passwd"


class InjectionScanner:
    def __init__(self, engine: HttpEngine, config: ScanConfig, base: BaseUrls, report: Report, paths: List[str]):
        self.engine = engine
        self.config = config
        self.base = base
        self.report = report
        self.targets = self._build_targets(paths)

    def _build_targets(self, paths: Set[str]) -> List[str]:
        base = self.base.primary
        if not base:
            return []
        ordered = sorted(paths) if isinstance(paths, (set, frozenset)) else list(paths)
        urls = [base] + [urljoin(base, p) for p in ordered[:10]]
        return urls

    def run(self) -> None:
        logger.info("Probing reflection & injection vectors...")
        if self.targets:
            self._host_header(self.targets[0])
        for url in self.targets:
            self._reflect_xss(url)
            self._open_redirect(url)
            self._crlf(url)
            self._ssti(url)
            self._sqli(url)
            self._traversal(url)
            self._cmdi(url)

    def _reflect_xss(self, url: str) -> None:
        code, hdrs, body, _ = self.engine.fetch(url, headers={"X-Requested-With": "XMLHttpRequest"})
        if code != 200:
            return
        for param in ("q", "search", "query", "id", "name", "url", "page", "redirect", "return", "next"):
            resp_code, _, resp_body, _ = self.engine.fetch(url + ("" if "?" in url else "?") + f"{param}={XSS_PAYLOAD}")
            if resp_code != 200:
                continue
            text = resp_body.decode("utf-8", "ignore")
            if XSS_PAYLOAD in text:
                self.report.add(Finding(
                    "HIGH", "Reflected XSS (unencoded payload in response)", url=url + f"?{param}={XSS_PAYLOAD}",
                    evidence=f"Payload {XSS_PAYLOAD} appears verbatim in the response.",
                    recommendation="Encode/escape user input in the HTTP response."))
                return

    def _open_redirect(self, url: str) -> None:
        for param in ("url", "redirect", "next", "return", "returnUrl", "target", "dest", "redir", "redirect_uri"):
            target = f"//evil.example.com/{int(time.time())}"
            code, hdrs, _, _ = self.engine.fetch(url + ("" if "?" in url else "?") + f"{param}={target}", allow_redirects=False)
            loc = hdrs.get("location", "")
            if code in (301, 302, 303, 307, 308) and "evil.example.com" in loc:
                self.report.add(Finding("MEDIUM", "Open redirect", url=url,
                    evidence=f"{param}={target} -> {code} Location: {loc}",
                    recommendation="Validate redirect targets against an allow-list."))
                return

    def _crlf(self, url: str) -> None:
        payload = "crlf%0d%0aX-Injected:findpy"
        code, hdrs, _, _ = self.engine.fetch(url + ("" if "?" in url else "?") + "x=" + payload, allow_redirects=False)
        if "findpy" in str(hdrs).lower():
            self.report.add(Finding("HIGH", "CRLF injection in header", url=url,
                evidence="Encoded CRLF in query parameter injected a response header.",
                recommendation="Sanitize CR/LF characters from all user input."))

    def _host_header(self, url: str) -> None:
        evil = f"evil-{int(time.time())}.example.com"
        code, hdrs, body, _ = self.engine.fetch(url, headers={"Host": evil})
        if code is None:
            return
        text = body.decode("utf-8", "ignore") + " " + str(hdrs)
        if evil.lower() not in text.lower():
            return
        # CDN/edge error pages (Cloudflare "Origin DNS error", nginx, etc.) echo the Host
        # header into an error template - this is not an application-level injection.
        if re.search(r"(origin dns error|cloudflare|error 5\d\d|bad request|invalid host|"
                     r"nginx|varnish|application gateway|is not configured|web server)", text, re.IGNORECASE):
            logger.info(f"  Host header echoed only in an edge/error page (ignored): {evil}")
            return
        # Require the value to be embedded in a URL-bearing context of an app response.
        if code in (200, 301, 302, 303, 307, 308):
            loc = hdrs.get("location", "")
            if evil in loc or re.search(
                    rf'(?:href|src|action|data-href|data-url)=["\'][^"\']*{re.escape(evil)}',
                    text, re.IGNORECASE):
                self.report.add(Finding("HIGH", "Host header injection", url=url,
                    evidence=f"Sending 'Host: {evil}' reflects it into response URLs (can poison links/password reset).",
                    recommendation="Validate the Host header against the configured hostname."))
            else:
                logger.info(f"  Host header reflected in body only (not in URL context; ignored): {evil}")

    def _ssti(self, url: str) -> None:
        for param in ("name", "id", "user", "username", "message"):
            code, _, body, _ = self.engine.fetch(url + ("" if "?" in url else "?") + f"{param}={SSTI_PAYLOAD}")
            if code != 200:
                continue
            text = body.decode("utf-8", "ignore")
            if "49" in text and SSTI_PAYLOAD in text:
                self.report.add(Finding("HIGH", "Possible Server-Side Template Injection", url=url,
                    evidence=f"{param}={SSTI_PAYLOAD} evaluates to 49 (7*7) in the response.",
                    recommendation="Validate whether templates are evaluated server-side; do not interpolate user input."))
                return

    def _sqli(self, url: str) -> None:
        for param in ("id", "user", "username", "name", "item", "product", "category"):
            code, _, body, _ = self.engine.fetch(url + ("" if "?" in url else "?") + f"{param}={SQ_PAYLOAD}")
            if code is None:
                continue
            text = body[:8192].decode("utf-8", "ignore")
            if re.search(r"(sqlsyntax|you have an error in your sql|unclosed quotation|sqlstate|odbc|microsoft.*ole db|mysql_fetch|pg_query)", text, re.IGNORECASE):
                self.report.add(Finding("HIGH", "Error-based SQL injection", url=url,
                    evidence=f"Param '{param}' with '{SQ_PAYLOAD}' triggers a SQL error in the response.",
                    recommendation="Use parameterized queries / prepared statements."))
                return

    def _traversal(self, url: str) -> None:
        for param in ("file", "path", "page", "dir", "template", "doc"):
            code, _, body, _ = self.engine.fetch(url + ("" if "?" in url else "?") + f"{param}={TRAV_PAYLOAD}")
            if code == 200 and b"root:x:0:0" in body[:4096]:
                self.report.add(Finding("HIGH", "Path traversal / LFI", url=url,
                    evidence=f"{param}={TRAV_PAYLOAD} returned /etc/passwd content.",
                    recommendation="Validate file paths against an allow-list; never concatenate user input."))
                return

    def _cmdi(self, url: str) -> None:
        for param in ("cmd", "command", "exec", "ping", "ip", "host"):
            code, _, body, _ = self.engine.fetch(url + ("" if "?" in url else "?") + f"{param}={CMDI_PAYLOAD}")
            if code == 200 and b"findpycmdi" in body[:4096]:
                self.report.add(Finding("CRITICAL", "Command injection", url=url,
                    evidence=f"{param}={CMDI_PAYLOAD} executed and echoed output.",
                    recommendation="Never pass user input to shell exec functions; use strict allow-lists."))
                return


class TlsScanner:
    def __init__(self, config: ScanConfig, base: BaseUrls, report: Report):
        self.config = config
        self.base = base
        self.report = report

    def run(self) -> None:
        if not self.base.https:
            return
        logger.info("Checking TLS protocol versions...")
        host = self.config.host
        port = self.config.port if self.config.port not in (80, 443) else 443
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            for version, label in ((ssl.TLSVersion.TLSv1, "TLSv1.0"),
                                   (ssl.TLSVersion.TLSv1_1, "TLSv1.1")):
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.minimum_version = version
                    ctx.maximum_version = version
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((host, port), timeout=8) as sock:
                        with ctx.wrap_socket(sock, server_hostname=host):
                            self.report.add(Finding("MEDIUM", f"Legacy TLS protocol enabled: {label}",
                                url=f"https://{host}/",
                                evidence=f"Server accepted a {label} handshake.",
                                recommendation=f"Disable {label}; require TLSv1.2+."))
                            return
                except Exception:
                    logger.info(f"  {label}: not supported")


class MiscScanner:
    def __init__(self, engine: HttpEngine, config: ScanConfig, base: BaseUrls, report: Report):
        self.engine = engine
        self.config = config
        self.base = base
        self.report = report

    def run(self) -> None:
        url = self.base.primary
        if not url:
            return
        logger.info("Running misc checks (mixed content, source maps, upload, etc.)...")

        code, hdrs, body, _ = self.engine.fetch(url)
        if code != 200:
            return
        text = body.decode("utf-8", "ignore")

        # mixed content
        if self.base.https:
            insecure = set(re.findall(r'(?:src|href)="(http://[^"<]+)"', text))
            if insecure:
                self.report.add(Finding("LOW", "Mixed content (HTTP resources on HTTPS page)", url=url,
                    evidence=", ".join(sorted(insecure)[:3]),
                    recommendation="Serve all subresources over HTTPS."))

        # source maps
        for m in re.finditer(r'sourceMappingURL=([^\s,;"\']+)', text):
            srcmap = m.group(1)
            if not srcmap.startswith("http"):
                srcmap = urljoin(url, srcmap)
            sm_code, _, sm_body, _ = self.engine.fetch(srcmap)
            if sm_code == 200 and b'"sources"' in sm_body[:4096]:
                self.report.add(Finding("MEDIUM", "Source map file exposed", url=srcmap,
                    evidence="Source map discloses original source code.",
                    recommendation="Do not publish .map files in production."))

        # upload endpoint detection (JS hint)
        if re.search(r'(enctype\s*=\s*["\']?multipart/form-data|type=["\']file["\'])', text, re.IGNORECASE):
            self.report.add(Finding("INFO", "File upload form present", url=url,
                evidence="Found a multipart/form-data file input in the page.",
                recommendation="Validate uploads (extension, MIME, size) and store outside webroot."))

        # login exposure
        if re.search(r'<form[^>]+action=["\']?[^"\']*(login|signin)[^"\']*', text, re.IGNORECASE):
            self.report.add(Finding("INFO", "Login form found", url=url,
                evidence="Login form present; verify rate limiting, lockout and brute-force controls."))

        # password field over http
        if not self.base.https and re.search(r'type=["\']password["\']', text, re.IGNORECASE):
            self.report.add(Finding("HIGH", "Password field transmitted over plain HTTP", url=url,
                evidence="A password input exists on a non-TLS page.",
                recommendation="Force HTTPS on all authentication pages."))

        # verbose error / tech leakage on a nonexistent path
        nf_url = urljoin(url, f"/findpy-non-existent-{int(time.time())}")
        nf_code, _, nf_body, _ = self.engine.fetch(nf_url)
        if nf_code == 500 and re.search("|".join(ERROR_SIGNATURES), nf_body[:4096].decode("utf-8", "ignore"), re.IGNORECASE):
            self.report.add(Finding("LOW", "Verbose error on unknown path", url=nf_url,
                evidence=f"HTTP 500 with framework/database error text.",
                recommendation="Enable friendly error pages."))

        # HPP
        for param in ("q", "search", "id"):
            base_url = url + ("" if "?" in url else "?")
            code1, _, b1, _ = self.engine.fetch(base_url + f"{param}=a")
            code2, _, b2, _ = self.engine.fetch(base_url + f"{param}=a&{param}=b")
            if b1 and b2 and b"b" in b2[:8192] and b"a" in b2[:8192] and b"b" not in b1[:8192]:
                self.report.add(Finding("LOW", "HTTP parameter pollution", url=url,
                    evidence=f"Duplicate '{param}' param concatenated into the response.",
                    recommendation="Reject or explicitly handle duplicate parameters."))
                break


class Director:
    def __init__(self, target_input: str):
        self.host, self.port = TargetParser.parse(target_input)
        self.config = ScanConfig(host=self.host, port=self.port)
        self.engine = HttpEngine(self.config)
        self.output_path = Path(self.config.output_filename)
        self.report = Report(self.output_path)

    def execute(self) -> None:
        start = time.time()
        self.report.init_file(self.host)

        logger.info(f"Scanning target: {self.host} (port {self.port})")

        base = BaselineScanner(self.engine, self.config, self.report).run()

        discovery = ContentDiscovery(self.engine, self.config, base, self.report)
        discovery.run()

        # test robots-discovered paths too
        robot_paths = discovery.parse_robots()
        if robot_paths:
            logger.info(f"Probing {len(robot_paths)} paths from robots.txt...")
            for p in robot_paths:
                code, _, body, _ = self.engine.fetch(urljoin(base.primary, p))
                if code == 200 and re.search("|".join(ERROR_SIGNATURES), body[:4096].decode("utf-8", "ignore"), re.IGNORECASE):
                    self.report.add(Finding("LOW", "Verbose error on robots.txt path", url=urljoin(base.primary, p),
                        evidence=f"HTTP 200 with error text.",
                        recommendation="Fix the underlying error and enable friendly error pages."))

        HeaderScanner(self.engine, self.config, base, self.report).run()
        MethodScanner(self.engine, self.config, base, self.report).run()
        CacheScanner(self.engine, self.config, base, self.report).run()
        SmugglingScanner(self.config, base, self.report).run()
        InjectionScanner(self.engine, self.config, base, self.report, discovery.found_urls).run()
        TlsScanner(self.config, base, self.report).run()
        MiscScanner(self.engine, self.config, base, self.report).run()

        duration = time.time() - start
        logger.info(f"Scan finished in {duration:.1f}s.")
        self.report.finalize(duration)


def main():
    if len(sys.argv) != 2:
        print(f"\n  {BOLD}{GREEN}Usage:{RESET} {WHITE}python3 {sys.argv[0]} <target>{RESET}")
        print(f"  {BOLD}{GREEN}Example:{RESET} {WHITE}python3 {sys.argv[0]} example.com{RESET}")
        print(f"  {BOLD}{GREEN}Example:{RESET} {WHITE}python3 {sys.argv[0]} https://example.com:8443{RESET}\n")
        sys.exit(1)

    try:
        director = Director(sys.argv[1])
        director.execute()
    except KeyboardInterrupt:
        logger.info("\n[!] Execution interrupted by user (SIGINT).")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
