#!/usr/bin/env python3

from __future__ import annotations

import concurrent.futures
import http.client
import logging
import os
import queue
import re
import shutil
import signal
import ssl
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Generator, List, Optional, Set, Tuple
from urllib.parse import urlparse


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
logger = logging.getLogger("CacheScanner")


class CacheScannerError(Exception):
    pass

class TargetValidationError(CacheScannerError):
    pass


@dataclass(frozen=True)
class TargetScope:
    raw_input: str
    scope_hostname: str
    crawl_url: str

@dataclass
class ProbeResult:
    url: str
    status: int
    label: str
    evidence: str

@dataclass
class CacheConfig:
    output_filename: str = "cache.txt"
    max_workers: int = 50
    probe_timeout: int = 12
    tool_timeout_seconds: int = 300
    max_probe_urls: int = 2000
    hostname_regex: re.Pattern = field(
        default_factory=lambda: re.compile(r"^[a-zA-Z0-9._-]+$")
    )
    url_regex: re.Pattern = field(
        default_factory=lambda: re.compile(r"^https?://\S+$")
    )
    required_tools: List[str] = field(default_factory=lambda: ["waybackurls", "gau"])


class TargetParser:

    @staticmethod
    def parse(target_input: str) -> TargetScope:
        raw = target_input.strip().lower()
        clean_base = raw.lstrip("*.")

        if not clean_base.startswith(("http://", "https://")):
            clean_base = f"https://{clean_base}"

        parsed = urlparse(clean_base)
        hostname = parsed.hostname or ""

        if not hostname or '.' not in hostname:
            raise TargetValidationError(f"Invalid target format: {target_input}")

        port = parsed.port
        netloc = f"{hostname}:{port}" if port else hostname

        return TargetScope(
            raw_input=raw,
            scope_hostname=hostname,
            crawl_url=f"https://{netloc}"
        )


class SubprocessStreamer:

    @staticmethod
    def _kill_tree(process) -> None:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass

    @staticmethod
    def yield_output(command: str, timeout: int, label: str = "") -> Generator[str, None, None]:
        process = None
        reader = None
        try:
            logger.debug(f"  [{label.upper():^12}] CMD: {command}")
            process = subprocess.Popen(
                command, shell=True, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, preexec_fn=os.setsid
            )

            q: queue.Queue = queue.Queue(maxsize=1024)
            reader_done = threading.Event()

            def _read() -> None:
                try:
                    for line in process.stdout:
                        line = line.strip()
                        if line:
                            try:
                                q.put(line, block=False)
                            except queue.Full:
                                pass
                except Exception:
                    pass
                finally:
                    try:
                        q.put(None, block=False)
                    except queue.Full:
                        pass
                    reader_done.set()

            reader = threading.Thread(target=_read, daemon=True, name=f"streamer-{label or 'tool'}")
            reader.start()

            deadline = time.monotonic() + timeout
            timed_out = False
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                try:
                    item = q.get(timeout=remaining)
                except queue.Empty:
                    if reader_done.is_set():
                        break
                    timed_out = True
                    break
                if item is None:
                    break
                if label:
                    logger.debug(f"  [{label.upper():^12}] {item}")
                yield item

            if timed_out:
                logger.warning(f"  [{label.upper():^12}] Timed out after {timeout}s, killing process tree")
                SubprocessStreamer._kill_tree(process)

            if reader and reader.is_alive():
                try:
                    process.stdout.close()
                except Exception:
                    pass
                reader.join(timeout=2)

        except Exception:
            pass
        finally:
            if process:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    SubprocessStreamer._kill_tree(process)
                except Exception:
                    pass


COMMON_CACHEABLE_PATHS: List[str] = [
    "/", "/favicon.ico", "/apple-touch-icon.png", "/robots.txt", "/sitemap.xml",
    "/sitemap_index.xml", "/manifest.json", "/sw.js", "/static/", "/assets/",
    "/static/css/", "/static/js/", "/static/images/", "/static/img/",
    "/css/", "/js/", "/images/", "/img/", "/fonts/", "/media/", "/public/",
    "/uploads/", "/wp-content/", "/wp-content/uploads/", "/wp-includes/",
    "/__/chrome/", "/pwabuilder-sw.js",
]

STATIC_EXT_RE = re.compile(
    r"\.(?:css|js|mjs|cjs|png|jpe?g|gif|svg|webp|ico|bmp|avif|woff2?|ttf|eot|otf|"
    r"pdf|txt|xml|json|map|webmanifest|mp4|webm|mp3|ogg|wav|zip|gz|br)(?:[?#]|$)",
    re.IGNORECASE,
)

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)


class UrlCollector:

    def __init__(self, config: CacheConfig, target: TargetScope):
        self.config = config
        self.target = target
        self._available = ToolChecker.get_available(config.required_tools)

    def _run_waybackurls(self) -> Set[str]:
        if not self._available.get("waybackurls"):
            return set()
        return set(SubprocessStreamer.yield_output(
            f"echo {self.target.scope_hostname} | waybackurls",
            self.config.tool_timeout_seconds, label="waybackurls"
        ))

    def _run_gau(self) -> Set[str]:
        if not self._available.get("gau"):
            return set()
        return set(SubprocessStreamer.yield_output(
            f"gau --subs {self.target.raw_input} --threads 5 --timeout 30",
            self.config.tool_timeout_seconds, label="gau"
        ))

    def _in_scope(self, url: str) -> bool:
        try:
            host = urlparse(url).hostname or ""
            scope = self.target.scope_hostname
            return host == scope or host.endswith("." + scope)
        except Exception:
            return False

    def _normalize(self, url: str) -> Optional[str]:
        url = url.strip()
        if not self.config.url_regex.match(url):
            return None
        url = url.split("#")[0]
        if not url:
            return None
        try:
            if not self._in_scope(url):
                return None
        except Exception:
            return None
        return url

    def collect(self) -> List[str]:
        logger.info("Phase 1/3: Collecting candidate URLs (passive sources)...")
        raw: Set[str] = set()

        tasks = {
            "waybackurls": self._run_waybackurls,
            "gau": self._run_gau,
        }
        active = {name: fn for name, fn in tasks.items() if self._available.get(name)}
        if active:
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(active)) as executor:
                future_map = {executor.submit(fn): name for name, fn in active.items()}
                for future in concurrent.futures.as_completed(future_map):
                    name = future_map[future]
                    try:
                        result = future.result()
                        logger.info(f"  [{name.upper():^12}] Collected -> {len(result):,} raw URLs")
                        raw.update(result)
                    except Exception as e:
                        logger.error(f"  [{name.upper():^12}] Failed -> {e}")
        else:
            logger.warning("No URL sources available (waybackurls / gau not found in $PATH).")

        raw.update(f"{self.target.crawl_url}{p}" for p in COMMON_CACHEABLE_PATHS)

        normalized: Set[str] = set()
        for u in raw:
            n = self._normalize(u)
            if n:
                normalized.add(n)

        if not normalized:
            logger.warning("No URLs collected; nothing to probe.")
            return []

        statics = sorted(u for u in normalized if STATIC_EXT_RE.search(urlparse(u).path))
        others = sorted(u for u in normalized if u not in statics)
        ranked = statics + others
        ranked = ranked[: self.config.max_probe_urls]

        logger.info(
            f"  [    SCOPE    ] {len(normalized):,} in-scope URLs "
            f"({len(statics):,} static-asset candidates); probing top {len(ranked):,}"
        )
        return ranked


class CacheAnalyzer:

    _CF_HIT_STATES = {"hit", "expired", "stale", "revalidated", "updating"}

    @staticmethod
    def _as_int(value: Optional[str]) -> Optional[int]:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @classmethod
    def analyze(cls, headers: Dict[str, str]) -> Tuple[str, List[str]]:
        h = {k.lower(): v for k, v in headers.items()}
        ev: List[str] = []
        hit = False
        cacheable = False

        if (n := cls._as_int(h.get("age"))) is not None and n > 0:
            hit = True
            ev.append(f"Age: {h['age']}")

        if (v := h.get("cf-cache-status")):
            if v.strip().lower() in cls._CF_HIT_STATES:
                hit = True
            ev.append(f"CF-Cache-Status: {v}")

        if (v := h.get("x-cache")):
            if "hit" in v.lower():
                hit = True
            ev.append(f"X-Cache: {v}")

        if (v := h.get("x-cache-hits")):
            if (cls._as_int(v) or 0) > 0:
                hit = True
            ev.append(f"X-Cache-Hits: {v}")

        if (v := h.get("x-cache-lookup")):
            if "hit" in v.lower():
                hit = True
            ev.append(f"X-Cache-Lookup: {v}")

        if (v := h.get("x-fastly-cache")):
            if "hit" in v.lower():
                hit = True
            ev.append(f"X-Fastly-Cache: {v}")

        if (v := h.get("x-varnish")):
            hit = True
            ev.append(f"X-Varnish: {v}")

        if (v := h.get("x-served-by")) and "cache-" in v.lower():
            hit = True
            ev.append(f"X-Served-By: {v}")

        if (v := h.get("x-akamai")):
            hit = True
            ev.append(f"X-Akamai: {v}")

        if (v := h.get("x-qwik-cache")):
            if "hit" in v.lower():
                hit = True
            ev.append(f"X-Qwik-Cache: {v}")

        cc = h.get("cache-control", "")
        directives = [p.strip().lower() for p in re.split(r",\s*", cc) if p.strip()]
        no_store = "no-store" in directives
        private = "private" in directives
        pos_max_age = 0
        pos_smax_age = 0
        for d in directives:
            if (m := re.match(r"s-maxage\s*=\s*(\d+)", d)):
                pos_smax_age = int(m.group(1))
            elif (m := re.match(r"max-age\s*=\s*(\d+)", d)):
                pos_max_age = int(m.group(1))

        origin_allows = (
            "public" in directives or "immutable" in directives
            or pos_max_age > 0 or pos_smax_age > 0
        ) and not no_store and not private

        if origin_allows:
            cacheable = True
            ev.append(f"Cache-Control: {cc}")

        if (v := h.get("cdn-cache-control")):
            cacheable = True
            ev.append(f"CDN-Cache-Control: {v}")

        if (v := h.get("expires")):
            cacheable = True
            ev.append(f"Expires: {v}")

        if not cacheable and not no_store and not private and "set-cookie" not in h:
            if (v := h.get("etag")):
                cacheable = True
                ev.append(f"ETag: {v}")
            if (v := h.get("last-modified")):
                cacheable = True
                ev.append(f"Last-Modified: {v}")

        if hit:
            return "HIT", ev
        if cacheable:
            return "CACHEABLE", ev
        return "NONE", ev


class CacheProber:

    def __init__(self, config: CacheConfig):
        self.config = config
        self._tls_ctx = ssl.create_default_context()
        self._tls_ctx.check_hostname = False
        self._tls_ctx.verify_mode = ssl.CERT_NONE

    def _probe_one(self, url: str) -> Optional[ProbeResult]:
        try:
            u = urlparse(url)
            scheme = u.scheme.lower()
            host = u.hostname
            if not host:
                return None
            port = u.port
            path = u.path or "/"
            if u.query:
                path += "?" + u.query

            if scheme == "https":
                conn = http.client.HTTPSConnection(
                    host, port or 443, timeout=self.config.probe_timeout, context=self._tls_ctx
                )
            else:
                conn = http.client.HTTPConnection(
                    host, port or 80, timeout=self.config.probe_timeout
                )

            try:
                conn.request(
                    "GET", path,
                    headers={"User-Agent": DEFAULT_UA, "Accept": "*/*", "Accept-Encoding": "identity"}
                )
                resp = conn.getresponse()
                status = resp.status
                headers = {k: v for k, v in resp.getheaders()}
                resp.read()
            finally:
                conn.close()
        except Exception:
            return None

        label, evidence = CacheAnalyzer.analyze(headers)
        if label == "NONE":
            return None
        return ProbeResult(url=url, status=status, label=label, evidence=" | ".join(evidence))

    def probe(self, urls: List[str]) -> List[ProbeResult]:
        logger.info(
            f"Phase 2/3: Probing {len(urls):,} URLs for cache evidence "
            f"({self.config.max_workers} workers)..."
        )
        results: List[ProbeResult] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            future_map = {executor.submit(self._probe_one, u): u for u in urls}
            for future in concurrent.futures.as_completed(future_map):
                try:
                    res = future.result()
                except Exception:
                    continue
                if res:
                    results.append(res)

        results.sort(key=lambda r: (r.label != "HIT", r.url))
        return results


class ToolChecker:
    @staticmethod
    def get_available(required: List[str]) -> Dict[str, bool]:
        return {tool: shutil.which(tool) is not None for tool in required}


class OutputWriter:
    @staticmethod
    def write(results: List[ProbeResult], path: Path) -> None:
        lines = [
            f"{r.url}\t{r.status}\t{r.label}\t{r.evidence}"
            for r in results
        ]
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    @staticmethod
    def report(results: List[ProbeResult]) -> None:
        hits = [r for r in results if r.label == "HIT"]
        cacheable = [r for r in results if r.label == "CACHEABLE"]
        for r in results:
            if r.label == "HIT":
                logger.info(f"{MAGENTA}  [ CACHE-HIT ] {r.url}  [{r.status}]  {r.evidence}{RESET}")
            else:
                logger.info(f"{YELLOW}  [ CACHEABLE ] {r.url}  [{r.status}]  {r.evidence}{RESET}")
        logger.info(f"Summary: {len(hits):,} HIT + {len(cacheable):,} CACHEABLE = {len(results):,} cacheable endpoints")


class Director:

    def __init__(self, target_input: str):
        self.config = CacheConfig()
        self.target = TargetParser.parse(target_input)
        self.collector = UrlCollector(self.config, self.target)
        self.prober = CacheProber(self.config)
        self.output_path = Path(self.config.output_filename)

    def _log_missing_tools(self):
        available = ToolChecker.get_available(self.config.required_tools)
        missing = [t for t, is_avail in available.items() if not is_avail]
        if missing:
            logger.warning(f"Missing tools (skipping source): {', '.join(missing)}")

    def execute(self) -> None:
        start_time = time.time()

        logger.info(f"Initializing Cache Scanner │ Target: {self.target.raw_input} │ Scope: {self.target.scope_hostname}")
        self._log_missing_tools()

        urls = self.collector.collect()
        if not urls:
            logger.warning("No candidate URLs. Nothing to probe.")
            sys.exit(0)

        results = self.prober.probe(urls)
        OutputWriter.write(results, self.output_path)
        OutputWriter.report(results)

        elapsed = time.time() - start_time
        logger.info(f"Pipeline completed in {elapsed:.2f} seconds. Results saved to -> {self.output_path.resolve()}")


def main():
    args = sys.argv[1:]
    if "-q" in args or "--quiet" in args:
        args = [a for a in args if a not in ("-q", "--quiet")]
        logger.setLevel(logging.INFO)
        logger.info("Quiet mode: debug output suppressed.")

    if len(args) != 1:
        print(f"\n  {BOLD}{GREEN}Usage:{RESET} {WHITE}{sys.argv[0]} <target>{RESET}")
        print(f"  {BOLD}{GREEN}Example:{RESET} {WHITE}{sys.argv[0]} example.com{RESET}")
        print(f"  {BOLD}{GREEN}Quiet:{RESET}   {WHITE}{sys.argv[0]} -q example.com{RESET}\n")
        sys.exit(1)

    try:
        director = Director(target_input=args[0])
        director.execute()
    except TargetValidationError as e:
        logger.error(str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("\n[!] Execution interrupted by user (SIGINT).")
        sys.exit(0)

if __name__ == "__main__":
    main()
