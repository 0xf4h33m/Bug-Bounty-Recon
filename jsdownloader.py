#!/usr/bin/env python3

from __future__ import annotations

import concurrent.futures
import logging
import os
import sys
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import unquote, urlparse


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
logger = logging.getLogger("JSDownloader")


class DownloaderConfig:
    output_filename: str = "js_files.txt"
    max_workers: int = 20
    timeout_seconds: int = 15
    max_file_size_bytes: int = 10 * 1024 * 1024
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

    top_delimiter: str = "=================="
    bottom_delimiter: str = "============="


def human_readable_size(size_in_bytes: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_in_bytes < 1024.0:
            return f"{size_in_bytes:.2f} {unit}" if unit != 'B' else f"{size_in_bytes} {unit}"
        size_in_bytes /= 1024.0
    return f"{size_in_bytes:.2f} TB"

def extract_filename(url: str) -> str:
    try:
        path = unquote(urlparse(url).path)
        filename = os.path.basename(path)
        if filename and "." in filename:
            return filename
    except Exception:
        pass
    return "unknown_file.js"


class DownloadWorker:

    def __init__(self, config: DownloaderConfig, file_handle, write_lock: threading.Lock):
        self.config = config
        self.file_handle = file_handle
        self.write_lock = write_lock

    def process_url(self, url: str) -> Tuple[bool, str]:
        filename = extract_filename(url)
        req = urllib.request.Request(url, headers={'User-Agent': self.config.user_agent})

        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as response:
                chunks = []
                bytes_read = 0

                while True:
                    chunk = response.read(8192)
                    if not chunk:
                        break

                    bytes_read += len(chunk)
                    if bytes_read > self.config.max_file_size_bytes:
                        return (False, f"{url} (Skipped: Exceeded {self.config.max_file_size_bytes/1024/1024:.0f}MB limit)")

                    chunks.append(chunk)

                content = b"".join(chunks)
                size_str = human_readable_size(len(content))

                try:
                    js_code = content.decode('utf-8')
                except UnicodeDecodeError:
                    js_code = content.decode('latin-1')

                output_block = (
                    f"{self.config.top_delimiter}\n"
                    f"File: {filename} \n"
                    f" Size: {size_str} \n"
                    f"{js_code}\n"
                    f"{self.config.bottom_delimiter}\n"
                )

                with self.write_lock:
                    self.file_handle.write(output_block)
                    self.file_handle.flush()

                return (True, url)

        except urllib.error.HTTPError as e:
            return (False, f"{url} (HTTP {e.code})")
        except urllib.error.URLError as e:
            return (False, f"{url} (Network Error: {e.reason})")
        except Exception as e:
            return (False, f"{url} (Error: {str(e)[:50]})")


class Director:

    def __init__(self, input_file: str):
        self.config = DownloaderConfig()
        self.input_path = Path(input_file)
        self.output_path = Path(self.config.output_filename)
        self.write_lock = threading.Lock()

    def _load_urls(self) -> List[str]:
        if not self.input_path.exists():
            logger.error(f"Input file not found: {self.input_path}")
            sys.exit(1)

        urls = []
        try:
            with open(self.input_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    url = line.strip()
                    if url.startswith(("http://", "https://")):
                        urls.append(url)
        except OSError as e:
            logger.error(f"Failed to read input file: {e}")
            sys.exit(1)

        return urls

    def execute(self) -> None:
        start_time = time.time()

        logger.info(f"Loading targets from: {self.input_path}")
        urls = self._load_urls()

        if not urls:
            logger.warning("No valid URLs found in the input file.")
            sys.exit(0)

        logger.info(f"Found {len(urls)} URLs. Dispatching {self.config.max_workers} download threads...")

        success_count = 0
        fail_count = 0

        try:
            with open(self.output_path, "w", encoding="utf-8", errors="ignore") as f:
                worker = DownloadWorker(self.config, f, self.write_lock)

                with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
                    future_to_url = {
                        executor.submit(worker.process_url, url): url for url in urls
                    }

                    for future in concurrent.futures.as_completed(future_to_url):
                        success, message = future.result()
                        if success:
                            success_count += 1
                        else:
                            fail_count += 1
                            logger.debug(f"Failed: {message}")

        except OSError as e:
            logger.error(f"Failed to write to output file {self.output_path}: {e}")
            sys.exit(1)

        elapsed = time.time() - start_time
        logger.info(f"Download complete. Success: {success_count} | Failed/Skipped: {fail_count}")
        logger.info(f"Compiled output saved to: {self.output_path.resolve()} ({self.output_path.stat().st_size / 1024:.2f} KB)")
        logger.info(f"Pipeline completed in {elapsed:.2f} seconds.")


def main():
    if len(sys.argv) != 2:
        print(f"\n  {BOLD}{GREEN}Usage:{RESET} {WHITE}{sys.argv[0]} <js_urls.txt>{RESET}")
        print(f"  {BOLD}{GREEN}Example:{RESET} {WHITE}{sys.argv[0]} js_urls.txt{RESET}\n")
        sys.exit(1)

    try:
        director = Director(input_file=sys.argv[1])
        director.execute()
    except KeyboardInterrupt:
        logger.info("\n[!] Execution interrupted by user (SIGINT).")
        sys.exit(0)

if __name__ == "__main__":
    main()
