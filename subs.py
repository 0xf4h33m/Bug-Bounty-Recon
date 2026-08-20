#!/usr/bin/env python3

from __future__ import annotations

import concurrent.futures
import logging
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import tempfile
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
logger = logging.getLogger("SubPipeline")


class PipelineExecutionError(Exception):
    pass

class TargetValidationError(PipelineExecutionError):
    pass


@dataclass(frozen=True)
class TargetScope:
    raw_input: str
    scope_hostname: str
    is_wildcard: bool = False

@dataclass
class PipelineConfig:
    output_filename: str = "subs.txt"
    max_threads: int = 10
    tool_timeout_seconds: int = 300
    hostname_regex: re.Pattern = field(
        default_factory=lambda: re.compile(r"^[a-zA-Z0-9._-]+$")
    )
    required_tools: List[str] = field(default_factory=lambda: [
        "subfinder", "assetfinder", "findomain", "waybackurls"
    ])


class TargetParser:

    @staticmethod
    def parse(target_input: str) -> TargetScope:
        raw = target_input.strip().lower()
        is_wildcard = raw.startswith("*.")
        clean_base = raw.lstrip("*.")

        if not clean_base.startswith(("http://", "https://")):
            clean_base = f"https://{clean_base}"

        parsed = urlparse(clean_base)
        hostname = parsed.hostname or ""

        if not hostname or '.' not in hostname:
            raise TargetValidationError(f"Invalid target format: {target_input}")

        return TargetScope(
            raw_input=raw,
            scope_hostname=hostname,
            is_wildcard=is_wildcard
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

class ToolChecker:
    @staticmethod
    def get_available(required: List[str]) -> Dict[str, bool]:
        return {tool: shutil.which(tool) is not None for tool in required}


class PassiveEnumerator:

    def __init__(self, config: PipelineConfig, target: TargetScope):
        self.config = config
        self.target = target
        self.tools = ToolChecker.get_available(config.required_tools)
        self.httpx_bin = shutil.which("httpx-toolkit") or shutil.which("httpx")

    def _extract_hostname(self, url: str) -> Optional[str]:
        try:
            if url.startswith(("http://", "https://")):
                return urlparse(url).hostname
            if self.config.hostname_regex.match(url):
                return url.lower()
        except Exception:
            pass
        return None

    def _run_subfinder(self) -> Set[str]:
        if not self.tools.get("subfinder"): return set()
        return set(SubprocessStreamer.yield_output(
            f"subfinder -silent -d {self.target.scope_hostname}", self.config.tool_timeout_seconds, label="subfinder"
        ))

    def _run_assetfinder(self) -> Set[str]:
        if not self.tools.get("assetfinder"): return set()
        return set(SubprocessStreamer.yield_output(
            f"assetfinder --subs-only {self.target.scope_hostname}", self.config.tool_timeout_seconds, label="assetfinder"
        ))

    def _run_findomain(self) -> Set[str]:
        if not self.tools.get("findomain"): return set()
        return set(SubprocessStreamer.yield_output(
            f"findomain -q -t {self.target.scope_hostname}", self.config.tool_timeout_seconds, label="findomain"
        ))

    def _run_waybackurls(self) -> Set[str]:
        if not self.tools.get("waybackurls"): return set()
        hosts = set()
        for line in SubprocessStreamer.yield_output(
            f"echo {self.target.scope_hostname} | waybackurls", self.config.tool_timeout_seconds, label="waybackurls"
        ):
            host = self._extract_hostname(line)
            if host:
                hosts.add(host)
            else:
                logger.debug(f"  [ WAYBACKURLS ] Skipping non-hostname line: {line}")
        return hosts

    def execute_parallel(self) -> Set[str]:
        tasks = {
            "subfinder": self._run_subfinder,
            "assetfinder": self._run_assetfinder,
            "findomain": self._run_findomain,
            "waybackurls": self._run_waybackurls,
        }

        active_tasks = {k: v for k, v in tasks.items()}

        if not any([self.tools.get(t) for t in active_tasks]):
            raise PipelineExecutionError("No passive tools are available in $PATH.")

        active_names = [t for t in active_tasks if self.tools.get(t)]
        logger.info(f"Dispatching {len(active_names)} passive tools in parallel: {', '.join(active_names)}")
        master_set: Set[str] = set()

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
            future_map = {executor.submit(func): name for name, func in active_tasks.items() if self.tools.get(name)}

            overall_deadline = self.config.tool_timeout_seconds + 30
            try:
                for future in concurrent.futures.as_completed(future_map, timeout=overall_deadline):
                    name = future_map[future]
                    try:
                        result = future.result()
                        logger.info(f"  [{name.upper():^12}] Finished -> {len(result):,} hosts")
                        master_set.update(result)
                    except Exception as e:
                        logger.error(f"  [{name.upper():^12}] Failed -> {str(e)}")
            except concurrent.futures.TimeoutError:
                logger.warning(
                    f"Parallel enumeration exceeded overall deadline ({overall_deadline}s); "
                    "cancelling remaining tool(s)."
                )
                for future in future_map:
                    future.cancel()

        return master_set


class ScopeEnforcer:

    def __init__(self, target: TargetScope, config: PipelineConfig):
        self.target = target
        self.config = config

    def enforce(self, raw_hosts: Set[str]) -> List[str]:
        logger.info("Enforcing strict scope boundaries and normalizing data...")
        valid_subs = set()
        rejected = 0
        scope = self.target.scope_hostname
        regex = self.config.hostname_regex

        for host in raw_hosts:
            host = host.strip().lower().rstrip(".")
            host = host.replace("*.", "")

            if not host: continue
            if "*" in host:
                rejected += 1
                logger.debug(f"  [  SCOPE     ] Rejected (wildcard): {host}")
                continue
            if not regex.match(host):
                rejected += 1
                logger.debug(f"  [  SCOPE     ] Rejected (illegal chars): {host}")
                continue

            if host == scope or host.endswith("." + scope):
                valid_subs.add(host)
            else:
                rejected += 1
                logger.debug(f"  [  SCOPE     ] Rejected (out of scope): {host}")

        logger.debug(f"  [  SCOPE     ] Rejected {rejected:,} out-of-scope/invalid hosts.")
        return sorted(valid_subs)


class HttpxProber:

    def __init__(self, config: PipelineConfig):
        self.config = config
        self.binary = shutil.which("httpx-toolkit") or shutil.which("httpx")
        self._supported_flags: Optional[List[str]] = None

    def _detect_flags(self) -> List[str]:
        if self._supported_flags is not None:
            return self._supported_flags

        desired = ["-silent", "-status-code", "-title", "-tech-detect", "-ip", "-cdn", "-web-server", "-content-length", "-location", "-follow-host-redirects"]
        try:
            proc = subprocess.run([self.binary, "-h"], capture_output=True, text=True, timeout=10)
            help_text = proc.stdout + proc.stderr
            self._supported_flags = [f for f in desired if f in help_text] or desired
        except Exception:
            self._supported_flags = desired

        return self._supported_flags

    def probe(self, subdomains: List[str], output_file: Path) -> None:
        if not self.binary:
            logger.error("httpx-toolkit / httpx not found. Cannot probe. Saving raw subdomains to file instead.")
            output_file.write_text("\n".join(subdomains), encoding="utf-8")
            return

        logger.info(f"Probing {len(subdomains)} subdomains with {self.binary}...")

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as tmp:
            tmp.write("\n".join(subdomains))
            tmp_path = tmp.name

        cmd = [self.binary, "-l", tmp_path]
        cmd.extend(self._detect_flags())
        cmd.extend(["-threads", "200", "-timeout", "10", "-retries", "2", "-random-agent"])

        logger.debug(f"  [    HTTPX    ] CMD: {' '.join(cmd)}")
        logger.debug(f"  [    HTTPX    ] Detected flags: {self._detect_flags()}")

        process = None
        probed = 0
        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1, preexec_fn=os.setsid
            )

            with open(output_file, "w", encoding="utf-8") as f:
                for line in process.stdout:
                    line = line.strip()
                    if line:
                        probed += 1
                        logger.debug(f"  [    HTTPX    ] {line}")
                        print(line)
                        f.write(line + "\n")

            process.wait()
            logger.info(f"  [    HTTPX    ] {probed:,} live endpoints streamed to {output_file}")

        except Exception as e:
            logger.error(f"Httpx probing failed: {e}")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            if process and process.poll() is None:
                try: os.killpg(os.getpgid(process.pid), subprocess.SIGKILL)
                except Exception: pass


class Director:

    def __init__(self, target_input: str):
        self.config = PipelineConfig()
        self.target = TargetParser.parse(target_input)
        self.enumerator = PassiveEnumerator(self.config, self.target)
        self.enforcer = ScopeEnforcer(self.target, self.config)
        self.prober = HttpxProber(self.config)
        self.output_path = Path(self.config.output_filename)

    def _log_missing_tools(self):
        available = ToolChecker.get_available(self.config.required_tools)
        missing = [t for t, is_avail in available.items() if not is_avail]
        if missing:
            logger.warning(f"Missing passive tools (skipping): {', '.join(missing)}")
        if not (shutil.which("httpx-toolkit") or shutil.which("httpx")):
            logger.warning("Missing: httpx-toolkit (Results will not be probed for live status).")

    def execute(self) -> None:
        start_time = time.time()

        logger.info(f"Initializing Pipeline │ Target: {self.target.raw_input} │ Scope: {self.target.scope_hostname}")
        self._log_missing_tools()

        logger.info("Phase 1/3: Passive subdomain collection (parallel tools)...")
        raw_hosts = self.enumerator.execute_parallel()
        if not raw_hosts:
            logger.warning("Pipeline finished, but collected 0 raw hosts.")
            sys.exit(0)

        logger.info(f"Raw hosts collected: {len(raw_hosts):,}")

        logger.info("Phase 2/3: Scope enforcement & normalization...")
        valid_subs = self.enforcer.enforce(raw_hosts)
        logger.info(f"Valid in-scope subdomains: {len(valid_subs):,}")
        logger.debug(f"  [  SCOPE     ] First 20 in-scope: {', '.join(valid_subs[:20]) or 'none'}")

        logger.info("Phase 3/3: Active probing with httpx...")
        logger.info(f"Streaming probed results to -> {self.output_path.resolve()}")
        self.prober.probe(valid_subs, self.output_path)

        elapsed = time.time() - start_time
        logger.info(f"Pipeline completed in {elapsed:.2f} seconds.")


def main():
    args = sys.argv[1:]
    if "-q" in args or "--quiet" in args:
        args = [a for a in args if a not in ("-q", "--quiet")]
        logger.setLevel(logging.INFO)
        logger.info("Quiet mode: debug output suppressed.")

    if len(args) != 1:
        print(f"\n  {BOLD}{GREEN}Usage:{RESET} {WHITE}{sys.argv[0]} <target>{RESET}")
        print(f"  {BOLD}{GREEN}Example:{RESET} {WHITE}{sys.argv[0]} example.com{RESET}")
        print(f"  {BOLD}{GREEN}Example:{RESET} {WHITE}{sys.argv[0]} example.dev.ul.com{RESET}")
        print(f"  {BOLD}{GREEN}Quiet:{RESET}   {WHITE}{sys.argv[0]} -q example.com{RESET}\n")
        sys.exit(1)

    try:
        director = Director(target_input=args[0])
        director.execute()
    except TargetValidationError as e:
        logger.error(str(e))
        sys.exit(1)
    except PipelineExecutionError as e:
        logger.error(str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("\n[!] Execution interrupted by user (SIGINT).")
        sys.exit(0)

if __name__ == "__main__":
    main()
