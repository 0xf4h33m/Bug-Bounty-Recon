#!/usr/bin/env python3

from __future__ import annotations

import argparse
import logging
import os
import re
import sys
import time
from dataclasses import dataclass
from logging.config import dictConfig
from typing import Dict, Generator, List, Optional, Set, Tuple
from urllib.parse import unquote, urlsplit, urlunsplit


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


LOGGING_CONFIG: Dict = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "()": ColoredFormatter,
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
        "minimal": {
            "()": ColoredFormatter,
            "format": "[%(levelname)s]: %(message)s",
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "minimal",
            "stream": sys.stdout,
        },
    },
    "loggers": {
        "pipeline": {
            "handlers": ["console"],
            "level": logging.INFO,
            "propagate": False,
        }
    },
}

dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("pipeline")


MAX_URL_LENGTH: int = 4096

RAW_URL_PATTERN: re.Pattern = re.compile(
    r'https?://[^\s<>"\'`]+',
    re.IGNORECASE,
)

JS_EXTENSION_PATTERN: re.Pattern = re.compile(
    r'\.js(\.map)?$',
    re.IGNORECASE,
)

WRAPPER_PREFIXES: str = '([<{\'"\u201c\u2018'
WRAPPER_SUFFIXES: str = ')]}>\'"\u201d\u2019'
TRAILING_PUNCTUATION: str = '.,;:!?'

NOISE_DOMAINS: List[str] = [
    "google-analytics.com", "googletagmanager.com", "doubleclick.net",
    "facebook.net", "fbcdn.net", "connect.facebook.net",
    "analytics.twitter.com", "amazon-adsystem.com", "adservice.google.com",
    "hotjar.com", "fullstory.com", "mixpanel.com", "segment.io", "segment.com",
    "clarity.ms", "mouseflow.com", "crazyegg.com", "optimizely.com", "pingdom.net",
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com", "bootstrapcdn.com",
    "ajax.googleapis.com", "cdn.staticfile.org", "cdnjs.com", "jsdelivr.net",
    "cloudflare.com", "cloudflareinsights.com", "speedcurve.com", "fastly.net",
    "ads.yahoo.com", "linkedin.com/li/tracker", "bing.com/api/maps/mapcontrol",
    "fonts.googleapis.com", "fontawesome.com", "fonts.gstatic.com",
]


class PipelineError(Exception):
    pass

class URLSyntaxError(PipelineError):
    pass

class FileProcessingError(PipelineError):
    pass


@dataclass(frozen=True)
class ParsedAsset:
    url: str
    hostname: str

    def __hash__(self) -> int:
        return hash(self.url.lower())


def strip_wrapper_artifacts(raw_string: str) -> str:
    start_idx = 0
    end_idx = len(raw_string)

    while start_idx < end_idx and raw_string[start_idx] in WRAPPER_PREFIXES:
        start_idx += 1

    while end_idx > start_idx and raw_string[end_idx - 1] in WRAPPER_SUFFIXES:
        end_idx -= 1

    while end_idx > start_idx and raw_string[end_idx - 1] in TRAILING_PUNCTUATION:
        end_idx -= 1

    return raw_string[start_idx:end_idx]


def normalize_and_validate_url(raw_url: str) -> Optional[Tuple[str, str]]:
    if not raw_url or len(raw_url) > MAX_URL_LENGTH:
        return None

    try:
        parsed = urlsplit(raw_url)
    except ValueError as e:
        raise URLSyntaxError(f"Failed to parse URL components: {e}")

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        return None

    hostname = parsed.hostname
    if not hostname or not hostname.strip():
        return None

    if any(char.isspace() for char in hostname):
        return None
    if hostname.startswith('.') or hostname.startswith('-'):
        return None

    normalized_url = urlunsplit((
        scheme,
        parsed.netloc,
        parsed.path,
        parsed.query,
        ""
    ))

    return normalized_url, hostname


def validate_js_extension(url: str) -> bool:
    try:
        path = urlsplit(url).path
    except ValueError:
        return False

    if not path:
        return False

    decoded_path = unquote(path).rstrip('/')
    return bool(JS_EXTENSION_PATTERN.search(decoded_path))


def check_domain_reputation(hostname: str) -> bool:
    hostname_lower = hostname.lower()

    for noise_domain in NOISE_DOMAINS:
        if hostname_lower == noise_domain:
            return True
        if hostname_lower.endswith("." + noise_domain):
            return True

    return False


def process_line(line: str) -> Generator[ParsedAsset, None, None]:
    for match in RAW_URL_PATTERN.finditer(line):
        raw_match = match.group(0)

        stripped_url = strip_wrapper_artifacts(raw_match)

        validation_result = normalize_and_validate_url(stripped_url)
        if not validation_result:
            continue

        normalized_url, hostname = validation_result

        if not validate_js_extension(normalized_url):
            continue

        if check_domain_reputation(hostname):
            continue

        yield ParsedAsset(url=normalized_url, hostname=hostname)


def read_input_stream(file_path: str) -> Generator[str, None, None]:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                yield line
    except FileNotFoundError:
        raise FileProcessingError(f"Input file not found: {file_path}")
    except PermissionError:
        raise FileProcessingError(f"Permission denied reading: {file_path}")
    except OSError as e:
        raise FileProcessingError(f"OS error reading file: {e}")


def write_output_stream(file_path: str, assets: Set[ParsedAsset]) -> None:
    try:
        sorted_assets = sorted(assets, key=lambda a: a.url.lower())

        with open(file_path, "w", encoding="utf-8") as f:
            for asset in sorted_assets:
                f.write(f"{asset.url}\n")

    except PermissionError:
        raise FileProcessingError(f"Permission denied writing to: {file_path}")
    except OSError as e:
        raise FileProcessingError(f"OS error writing file: {e}")


def execute_pipeline(input_path: str, output_path: str) -> int:
    start_time = time.time()
    logger.info(f"Initializing pipeline. Reading from: {input_path}")

    unique_assets: Set[ParsedAsset] = set()
    processed_lines = 0
    raw_matches = 0

    try:
        for line in read_input_stream(input_path):
            processed_lines += 1

            for asset in process_line(line):
                raw_matches += 1
                unique_assets.add(asset)

    except FileProcessingError as e:
        logger.error(str(e))
        return 1

    try:
        write_output_stream(output_path, unique_assets)
    except FileProcessingError as e:
        logger.error(str(e))
        return 1

    elapsed_time = time.time() - start_time
    lines_per_sec = processed_lines / elapsed_time if elapsed_time > 0 else 0

    logger.info(f"Pipeline finished successfully in {elapsed_time:.2f} seconds ({lines_per_sec:.0f} lines/sec)")
    logger.info(f"Raw Matches Evaluated: {raw_matches:,}")
    logger.info(f"High-Signal Assets Saved: {len(unique_assets):,}")
    logger.info(f"Output File: {output_path}")

    return 0


def parse_cli_args() -> Tuple[str, str]:
    parser = argparse.ArgumentParser(
        description="Bug Bounty JS Pipeline: Extracts high-signal .js and .js.map URLs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        usage="%(prog)s <input_file.txt>"
    )

    parser.add_argument(
        "input_file",
        help="Path to the raw text file containing URLs."
    )
    parser.add_argument(
        "-o", "--output",
        default="js_urls.txt",
        help="Output filename. (Default: js_urls.txt)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging (DEBUG level)."
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger("pipeline").setLevel(logging.DEBUG)

    return args.input_file, args.output


def main() -> None:
    if len(sys.argv) == 1:
        print(f"{BOLD}{GREEN}Usage:{RESET} {WHITE}{sys.argv[0]} <input_file.txt>{RESET}")
        sys.exit(1)

    input_file, output_file = parse_cli_args()
    exit_code = execute_pipeline(input_file, output_file)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
