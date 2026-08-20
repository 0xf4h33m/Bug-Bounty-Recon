#!/usr/bin/env python3

from __future__ import annotations

import concurrent.futures
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
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
logger = logging.getLogger("ReconPipeline")


class PipelineExecutionError(Exception):
    pass

class TargetValidationError(PipelineExecutionError):
    pass

class ToolExecutionError(PipelineExecutionError):
    pass


@dataclass(frozen=True)
class TargetScope:
    raw_input: str
    scope_hostname: str
    crawl_url: str
    is_wildcard: bool = False

@dataclass
class PipelineConfig:
    output_filename: str = "urls.txt"
    max_threads: int = 10
    tool_timeout_seconds: int = 600
    url_regex_pattern: re.Pattern = field(
        default_factory=lambda: re.compile(r'^https?://\S+$')
    )
    required_tools: List[str] = field(default_factory=lambda: [
        "gau", "waybackurls", "katana", "waymore", "gospider"
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

        if not hostname or '.' not in hostname and not hostname.replace('.', '').isdigit():
            raise TargetValidationError(f"Invalid target format: {target_input}")

        port = parsed.port
        netloc = f"{hostname}:{port}" if port else hostname
        crawl_url = f"https://{netloc}"

        return TargetScope(
            raw_input=raw,
            scope_hostname=hostname,
            crawl_url=crawl_url,
            is_wildcard=is_wildcard
        )


class SubprocessStreamer:

    @staticmethod
    def yield_output(command: str, timeout: int) -> Generator[str, None, None]:
        process = None
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                preexec_fn=os.setsid
            )

            for line in process.stdout:
                line = line.strip()
                if line:
                    yield line

        except Exception:
            pass
        finally:
            if process:
                try:
                    process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    logger.warning(f"Process timed out, sending SIGKILL to process tree...")
                    try:
                        os.killpg(os.getpgid(process.pid), subprocess.SIGKILL)
                    except ProcessLookupError:
                        pass
                except Exception:
                    pass


class ToolOrchestrator:

    def __init__(self, config: PipelineConfig, target: TargetScope):
        self.config = config
        self.target = target
        self._available_tools: Optional[Dict[str, bool]] = None

    def check_availability(self) -> Dict[str, bool]:
        if self._available_tools is None:
            self._available_tools = {
                tool: shutil.which(tool) is not None
                for tool in self.config.required_tools
            }
        return self._available_tools

    def _run_gau(self) -> Set[str]:
        cmd = f"gau --subs {self.target.raw_input} --threads 5 --timeout 30"
        return set(SubprocessStreamer.yield_output(cmd, self.config.tool_timeout_seconds))

    def _run_waybackurls(self) -> Set[str]:
        cmd = f"echo {self.target.scope_hostname} | waybackurls"
        return set(SubprocessStreamer.yield_output(cmd, self.config.tool_timeout_seconds))

    def _run_katana(self) -> Set[str]:
        cmd = (
            f"katana -u {self.target.crawl_url} -silent -jc -kf all "
            f"-fx -d 3 -c 10 -timeout 30 -aff"
        )
        return set(SubprocessStreamer.yield_output(cmd, self.config.tool_timeout_seconds))

    def _run_waymore(self) -> Set[str]:
        urls = set()
        with tempfile.NamedTemporaryFile(suffix="_waymore.txt", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            cmd = f"waymore -i {self.target.raw_input} -mode U -oU {tmp_path}"
            subprocess.run(
                cmd, shell=True, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=self.config.tool_timeout_seconds
            )

            if os.path.exists(tmp_path):
                with open(tmp_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if line.strip(): urls.add(line.strip())
        except subprocess.TimeoutExpired:
            logger.warning("waymore timed out.")
        except Exception:
            pass
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

        return urls

    def _run_gospider(self) -> Set[str]:
        cmd = (
            f"gospider -s {self.target.crawl_url} -q -d 3 "
            f"--other-source -c 10 -t 15 --no-robots "
            f"-H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\""
        )
        return set(SubprocessStreamer.yield_output(cmd, self.config.tool_timeout_seconds))

    def execute_parallel(self) -> Set[str]:
        tools = self.check_availability()
        active_tools = {
            "gau": self._run_gau,
            "waybackurls": self._run_waybackurls,
            "katana": self._run_katana,
            "waymore": self._run_waymore,
            "gospider": self._run_gospider,
        }

        tasks_to_run = {
            name: func for name, func in active_tools.items() if tools.get(name, False)
        }

        if not tasks_to_run:
            raise ToolExecutionError("No reconnaissance tools are available in $PATH. Cannot proceed.")

        logger.info(f"Dispatching {len(tasks_to_run)} tools in parallel...")
        master_set: Set[str] = set()

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
            future_map = {
                executor.submit(func): name for name, func in tasks_to_run.items()
            }

            for future in concurrent.futures.as_completed(future_map):
                tool_name = future_map[future]
                try:
                    result = future.result()
                    logger.info(f"  [{tool_name.upper():^12}] Finished -> {len(result):,} raw lines")
                    master_set.update(result)
                except Exception as e:
                    logger.error(f"  [{tool_name.upper():^12}] Failed -> {str(e)}")

        return master_set


class ScopeEnforcer:

    def __init__(self, config: PipelineConfig, target: TargetScope):
        self.config = config
        self.target = target
        self.url_regex = config.url_regex_pattern

    def process(self, raw_urls: Set[str]) -> List[str]:
        logger.info("Enforcing strict scope boundaries and normalizing data...")
        scoped_urls = set()
        scope_host = self.target.scope_hostname

        for url in raw_urls:
            if not self.url_regex.match(url):
                continue

            try:
                if url[:8].lower() == "https://":
                    parsed_url = url[8:]
                    scheme = "https://"
                elif url[:7].lower() == "http://":
                    parsed_url = url[7:]
                    scheme = "http://"
                else:
                    continue

                parsed_url = parsed_url.split('#')[0]
                if not parsed_url:
                    continue

                netloc = parsed_url.split('/')[0]
                hostname = netloc.split(':')[0].lower()

                if hostname == scope_host or hostname.endswith("." + scope_host):
                    final_url = f"{scheme}{parsed_url}"
                    scoped_urls.add(final_url)

            except Exception:
                continue

        return sorted(scoped_urls)


class Director:

    def __init__(self, target_input: str):
        self.config = PipelineConfig()
        self.target = TargetParser.parse(target_input)
        self.orchestrator = ToolOrchestrator(self.config, self.target)
        self.enforcer = ScopeEnforcer(self.config, self.target)

    def _log_missing_tools(self):
        available = self.orchestrator.check_availability()
        missing = [t for t, is_avail in available.items() if not is_avail]
        if missing:
            logger.warning(f"Missing tools (skipping): {', '.join(missing)}")

    def execute(self) -> None:
        start_time = time.time()

        logger.info(f"Initializing Pipeline │ Target: {self.target.raw_input} │ Scope: {self.target.scope_hostname}")
        self._log_missing_tools()

        raw_urls = self.orchestrator.execute_parallel()
        if not raw_urls:
            logger.warning("Pipeline finished, but collected 0 raw URLs.")
            sys.exit(0)

        logger.info(f"Raw lines collected: {len(raw_urls):,}")

        final_urls = self.enforcer.process(raw_urls)

        output_path = Path(self.config.output_filename)
        try:
            output_path.write_text("\n".join(final_urls) + ("\n" if final_urls else ""), encoding="utf-8")
            logger.info(f"Successfully wrote {len(final_urls):,} scoped URLs to -> {output_path.resolve()}")
        except OSError as e:
            logger.error(f"Failed to write output file: {e}")
            sys.exit(1)

        elapsed = time.time() - start_time
        logger.info(f"Pipeline completed in {elapsed:.2f} seconds.")


def main():
    if len(sys.argv) != 2:
        print(f"\n  {BOLD}{GREEN}Usage:{RESET} {WHITE}{sys.argv[0]} <target>{RESET}")
        print(f"  {BOLD}{GREEN}Example:{RESET} {WHITE}{sys.argv[0]} example.com{RESET}")
        print(f"  {BOLD}{GREEN}Example:{RESET} {WHITE}{sys.argv[0]} *.example.dev.ul.com{RESET}\n")
        sys.exit(1)

    try:
        director = Director(target_input=sys.argv[1])
        director.execute()
    except TargetValidationError as e:
        logger.error(str(e))
        sys.exit(1)
    except ToolExecutionError as e:
        logger.error(str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("\n[!] Execution interrupted by user (SIGINT).")
        sys.exit(0)

if __name__ == "__main__":
    main()
