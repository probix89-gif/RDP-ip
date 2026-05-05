#!/usr/bin/env python3
"""
rdp_recon_turbo.py
================================================================================
  ⚠  A U T H O R I S E D   U S E   O N L Y  ⚠
  This tool performs highly effective network reconnaissance, including
  port scanning, banner grabbing and vulnerability fingerprinting. You
  MUST have explicit written permission from the owner of every target
  system you scan. Unauthorised scanning is illegal and unethical.
  By using this tool you accept full legal responsibility.

  The developer assumes no liability for misuse. Use wisely.
================================================================================

Advanced async RDP reconnaissance platform – collect IPs from multiple public
sources, scan millions of addresses for open ports, fingerprint RDP services
and perform safe vulnerability checks – all at wire speed.

Requirements (install with "pip install -r requirements.txt"):
  aiohttp>=3.8, aiodns>=3.0, aiofiles>=23.0, rich>=13.0, pyyaml>=6.0,
  scapy>=2.5 (optional, for SYN scan without masscan), uvloop>=0.17
"""

import argparse
import asyncio
import csv
import getpass
import ipaddress
import json
import logging
import os
import random
import re
import signal
import socket
import struct
import ssl
import sys
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import aiofiles
import aiohttp
import yaml

# ----------------------------------------------------------------------
# Try optional accelerator
# ----------------------------------------------------------------------
try:
    import uvloop
except ImportError:
    uvloop = None

# ----------------------------------------------------------------------
# Rich ecosystem (must be installed)
# ----------------------------------------------------------------------
from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

console = Console()
error_console = Console(stderr=True)

# ----------------------------------------------------------------------
# Logging (console = INFO, file = DEBUG)
# ----------------------------------------------------------------------
LOG = logging.getLogger("rdp_recon")
LOG.setLevel(logging.DEBUG)

# Rich handler for console (pretty)
rich_handler = logging.StreamHandler(sys.stdout)
rich_handler.setLevel(logging.INFO)
rich_handler.setFormatter(logging.Formatter("%(message)s"))
LOG.addHandler(rich_handler)

FILE_LOG = Path("rdp_recon_debug.log")
file_handler = logging.FileHandler(FILE_LOG, encoding="utf-8")
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(
    logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
)
LOG.addHandler(file_handler)

# ======================================================================
# Async rate limiter (token bucket)
# ======================================================================

class AsyncTokenBucket:
    """Asyncio-compatible token bucket rate limiter."""

    def __init__(self, rate: float):
        self.rate = rate
        self.capacity = rate
        self.tokens = rate
        self._last_fill = time.monotonic()
        self._lock = asyncio.Lock()

    async def consume(self, tokens: int = 1) -> None:
        async with self._lock:
            while True:
                self._add_tokens()
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return
                wait = (tokens - self.tokens) / self.rate
                await asyncio.sleep(wait)

    def _add_tokens(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_fill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self._last_fill = now

# ======================================================================
# Configuration
# ======================================================================

DEFAULT_CONFIG = {
    "global": {
        "cache_dir": "~/.rdp_recon_cache",
        "cache_ttl_hours": 12,
        "output_dir": ".",
    },
    "sources": {
        "enabled": ["shodan", "censys", "generic_http", "file"],
        "shodan": {
            "api_key": None,
            "max_records": 500,
            "query": "port:3389",
            "timeout": 30,
        },
        "censys": {
            "api_id": None,
            "api_secret": None,
            "max_records": 500,
            "query": "services.port: 3389",
            "timeout": 30,
        },
        "generic_http": {
            "urls": [
                "https://raw.githubusercontent.com/",
                "example/honeypot-ips/main/ips.txt"
            ],
            "timeout": 30,
        },
        "file": {
            "paths": []
        },
    },
    "scan": {
        "ports": [3389],
        "timeout": 2.0,
        "concurrency": 1000,
        "jitter_min": 0.001,
        "jitter_max": 0.01,
        "rate_limit": 10000,          # packets per second (global)
        "syn_scan": False,            # require root / masscan
        "masscan_binary": "masscan",
        "masscan_rate": 10000,
        "max_retries": 1,
        "fingerprint": True,
        "vuln_checks": True,
    },
    "report": {
        "formats": ["json", "html"],
        "filename": "rdp_report",
    },
}

def load_config(path: str) -> dict:
    """Load YAML config, creating default if missing."""
    if not os.path.exists(path):
        LOG.warning("Config %s not found, writing default.", path)
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False)
        console.print(f"[yellow]Created default config at {path}. Please add your API keys.[/]")
        return DEFAULT_CONFIG.copy()
    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    # Merge with defaults for missing keys
    merged = DEFAULT_CONFIG.copy()
    merged.update(cfg)
    return merged

def env_override(config: dict) -> dict:
    """Override config with environment variables if present."""
    src = config.setdefault("sources", {})
    if os.getenv("SHODAN_KEY"):
        src.setdefault("shodan", {})["api_key"] = os.environ["SHODAN_KEY"]
    if os.getenv("CENSYS_ID"):
        src.setdefault("censys", {})["api_id"] = os.environ["CENSYS_ID"]
    if os.getenv("CENSYS_SECRET"):
        src.setdefault("censys", {})["api_secret"] = os.environ["CENSYS_SECRET"]
    return config

# ======================================================================
# Async IP Sources (plugin architecture)
# ======================================================================

class AsyncSourceBase(ABC):
    """Abstract async source of IPv4 addresses."""

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    async def fetch(self) -> Set[str]:
        """Return a set of valid IPv4 addresses."""

    def prompt_credentials(self) -> None:
        """Interactively request missing credentials (blocking)."""
        pass

class FileSource(AsyncSourceBase):
    def __init__(self, name: str = "file", paths: List[str] = None):
        super().__init__(name)
        self.paths = paths or []

    def _is_valid_ip(self, addr: str) -> bool:
        try:
            ipaddress.IPv4Address(addr)
            return True
        except ipaddress.AddressValueError:
            return False

    async def fetch(self) -> Set[str]:
        ips = set()
        for fp in self.paths:
            if not os.path.isfile(fp):
                LOG.warning("File %s not found, skipping.", fp)
                continue
            async with aiofiles.open(fp, "r", encoding="utf-8") as f:
                content = await f.read()
            for line in content.splitlines():
                candidate = line.strip()
                if self._is_valid_ip(candidate):
                    ips.add(candidate)
        LOG.info("[%s] collected %d IPs.", self.name, len(ips))
        return ips

class ShodanSource(AsyncSourceBase):
    """Async Shodan API (using aiohttp, respecting rate limits)."""
    BASE = "https://api.shodan.io"

    def __init__(self, name: str = "shodan", api_key: str = None,
                 max_records: int = 500, query: str = "port:3389", timeout: float = 30):
        super().__init__(name)
        self.api_key = api_key
        self.max_records = max_records
        self.query = query
        self.timeout = timeout

    def prompt_credentials(self) -> None:
        if not self.api_key:
            self.api_key = getpass.getpass("Shodan API key: ")

    async def fetch(self) -> Set[str]:
        if not self.api_key:
            LOG.error("Shodan API key missing.")
            return set()
        ips = set()
        url = f"{self.BASE}/shodan/host/search"
        params = {"key": self.api_key, "query": self.query, "fields": "ip_str"}
        headers = {"Accept": "application/json"}
        page = 1
        async with aiohttp.ClientSession() as session:
            while len(ips) < self.max_records:
                params["page"] = page
                try:
                    async with session.get(url, params=params, headers=headers,
                                           timeout=self.timeout) as resp:
                        if resp.status == 429:
                            retry_after = float(resp.headers.get("Retry-After", 5))
                            LOG.warning("Shodan rate limited, waiting %ds", retry_after)
                            await asyncio.sleep(retry_after)
                            continue
                        if resp.status != 200:
                            LOG.error("Shodan error %s: %s", resp.status, await resp.text())
                            break
                        data = await resp.json()
                        matches = data.get("matches", [])
                        if not matches:
                            break
                        for m in matches:
                            ip = m.get("ip_str")
                            if ip:
                                ips.add(ip)
                        page += 1
                except asyncio.TimeoutError:
                    LOG.error("Shodan timeout")
                    break
        LOG.info("[%s] collected %d IPs (max %d).", self.name, len(ips), self.max_records)
        return ips

class CensysSource(AsyncSourceBase):
    """Async Censys v2 search using aiohttp."""
    BASE_URL = "https://search.censys.io/api/v2"

    def __init__(self, name: str = "censys", api_id: str = None, api_secret: str = None,
                 max_records: int = 500, query: str = "services.port: 3389", timeout: float = 30):
        super().__init__(name)
        self.api_id = api_id
        self.api_secret = api_secret
        self.max_records = max_records
        self.query = query
        self.timeout = timeout

    def prompt_credentials(self) -> None:
        if not self.api_id:
            self.api_id = input("Censys API ID: ")
        if not self.api_secret:
            self.api_secret = getpass.getpass("Censys API Secret: ")

    async def fetch(self) -> Set[str]:
        if not self.api_id or not self.api_secret:
            LOG.error("Censys credentials missing.")
            return set()
        ips = set()
        auth = aiohttp.BasicAuth(self.api_id, self.api_secret)
        url = f"{self.BASE_URL}/hosts/search"
        payload = {"q": self.query, "per_page": 100}
        headers = {"Accept": "application/json"}
        page = 1
        async with aiohttp.ClientSession(auth=auth) as session:
            while len(ips) < self.max_records:
                payload["page"] = page
                try:
                    async with session.post(url, json=payload, headers=headers,
                                            timeout=self.timeout) as resp:
                        if resp.status == 429:
                            retry = float(resp.headers.get("Retry-After", 5))
                            LOG.warning("Censys rate limited, waiting %ds", retry)
                            await asyncio.sleep(retry)
                            continue
                        if resp.status != 200:
                            text = await resp.text()
                            LOG.error("Censys error %s: %s", resp.status, text)
                            break
                        data = await resp.json()
                        hits = data.get("result", {}).get("hits", [])
                        if not hits:
                            break
                        for hit in hits:
                            ip = hit.get("ip")
                            if ip:
                                ips.add(ip)
                        page += 1
                except asyncio.TimeoutError:
                    LOG.error("Censys timeout")
                    break
        LOG.info("[%s] collected %d IPs (max %d).", self.name, len(ips), self.max_records)
        return ips

class GenericHTTPSource(AsyncSourceBase):
    """Async fetch text files from URLs, expecting one IP per line."""

    def __init__(self, name: str = "generic_http", urls: List[str] = None, timeout: float = 30):
        super().__init__(name)
        self.urls = urls or []
        self.timeout = timeout

    async def fetch(self) -> Set[str]:
        ips = set()
        async with aiohttp.ClientSession() as session:
            for url in self.urls:
                try:
                    async with session.get(url, timeout=self.timeout) as resp:
                        resp.raise_for_status()
                        text = await resp.text()
                        for line in text.splitlines():
                            line = line.strip()
                            if line and self._is_valid_ip(line):
                                ips.add(line)
                except Exception as e:
                    LOG.error("Failed to fetch %s: %s", url, e)
        LOG.info("[%s] collected %d IPs.", self.name, len(ips))
        return ips

    @staticmethod
    def _is_valid_ip(addr: str) -> bool:
        try:
            ipaddress.IPv4Address(addr)
            return True
        except ipaddress.AddressValueError:
            return False

# ----------------------------------------------------------------------
# Source factory (plugin system can be added later)
# ----------------------------------------------------------------------
SOURCE_REGISTRY = {
    "file": FileSource,
    "shodan": ShodanSource,
    "censys": CensysSource,
    "generic_http": GenericHTTPSource,
}

def create_sources(config: dict, selected: Optional[List[str]] = None) -> List[AsyncSourceBase]:
    src_conf = config.get("sources", {})
    enabled = src_conf.get("enabled", [])
    if selected:
        enabled = [s for s in enabled if s in selected]
    sources = []
    for name in enabled:
        cls = SOURCE_REGISTRY.get(name)
        if not cls:
            LOG.warning("Unknown source '%s', skipping.", name)
            continue
        if name == "shodan":
            cfg = src_conf.get("shodan", {})
            sources.append(ShodanSource(name="shodan", **cfg))
        elif name == "censys":
            cfg = src_conf.get("censys", {})
            sources.append(CensysSource(name="censys", **cfg))
        elif name == "generic_http":
            cfg = src_conf.get("generic_http", {})
            sources.append(GenericHTTPSource(name="generic_http", **cfg))
        elif name == "file":
            cfg = src_conf.get("file", {})
            sources.append(FileSource(name="file", **cfg))
    return sources

# ======================================================================
# IP Collector (async orchestration)
# ======================================================================

class AsyncIPCollector:
    def __init__(self, sources: List[AsyncSourceBase]):
        self.sources = sources

    async def collect(self) -> Set[str]:
        tasks = [src.fetch() for src in self.sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        all_ips = set()
        for src, res in zip(self.sources, results):
            if isinstance(res, Exception):
                LOG.error("Source %s failed: %s", src.name, res)
            else:
                all_ips.update(res)
        LOG.info("Total unique IPs collected: %d", len(all_ips))
        return all_ips

# ======================================================================
# Caching layer (simple JSON file with TTL)
# ======================================================================

class IPCache:
    def __init__(self, path: Path, ttl_hours: int = 12):
        self.path = path.expanduser()
        self.ttl = ttl_hours * 3600
        self.path.parent.mkdir(parents=True, exist_ok=True)

    async def load(self) -> Set[str]:
        if not self.path.exists():
            return set()
        async with aiofiles.open(self.path, "r") as f:
            raw = await f.read()
        try:
            data = json.loads(raw)
        except Exception:
            return set()
        if time.time() - data.get("timestamp", 0) > self.ttl:
            return set()   # expired
        return set(data.get("ips", []))

    async def save(self, ips: Set[str]) -> None:
        data = {"timestamp": time.time(), "ips": list(ips)}
        async with aiofiles.open(self.path, "w") as f:
            await f.write(json.dumps(data))

# ======================================================================
# RDP protocol helpers (banner & vulnerability)
# ======================================================================

# RDP Connection Request (X.224, RFC 905) minimal structure
# TPKT header: version=3, reserved=0, length (big-endian)
# X.224: length indicator, CR (0xE0), DST-REF=0, SRC-REF=0, class=0
# then RDP Negotiation Request (optional): type=0, flags, length, ...
def build_rdp_negotiation_request() -> bytes:
    """Craft a minimal RDP Negotiation Request packet (TCP)."""
    # TPKT header (4 bytes)
    tpkt = struct.pack("!BBH", 3, 0, 19)  # version=3, reserved=0, length=19
    # X.224 Connection Request (CR, class 0)
    x224 = b"\x00\x00\x00\x00\x00\x00"  # length=6, CR=0xe0 ? we need to correctly encode
    # Actually X.224 header: 1 byte length (remaining bytes), 1 byte code (0xe0 for CR),
    # then dst-ref (2 bytes), src-ref (2 bytes), class option (1 byte)
    # Here: length after length field (6+? ), code 0xe0, dst 0, src 0, class 0
    x224 = struct.pack("!BBHHB", 6, 0xe0, 0, 0, 0)   # length=6, CR, dst, src, class
    # RDP Negotiation Request (type 1 = RDP Negotiation Request)
    # Type (1 byte) 1, flags (1 byte) 0, length (2 bytes) 8, requested protocols (4 bytes)
    rdp_neg = struct.pack("<BBHI", 1, 0, 8, 0)  # requesting all protocols (0)
    packet = tpkt + x224 + rdp_neg
    # Fix TPKT length
    total_len = len(packet)
    packet = struct.pack("!BBH", 3, 0, total_len) + packet[4:]
    return packet

def parse_rdp_negotiation_response(data: bytes) -> Dict[str, Any]:
    """Parse server response and extract RDP version info."""
    info = {"raw_hex": data.hex()}
    try:
        if len(data) < 4:
            return info
        tpkt_version, reserved, tpkt_length = struct.unpack("!BBH", data[:4])
        if tpkt_version != 3:
            info["error"] = "Invalid TPKT version"
            return info
        # X.224 part
        x224_len = data[4]
        if data[5] == 0xd0:  # Connection Confirm
            info["type"] = "Connection Confirm"
            # RDP Negotiation Response (if present)
            offset = 4 + 1 + x224_len  # after x224 header (1 byte len + remaining bytes)
            if offset + 2 <= len(data):
                neg_type = data[offset]
                flags = data[offset + 1]
                length = struct.unpack("<H", data[offset+2:offset+4])[0]
                selected_proto = struct.unpack("<I", data[offset+4:offset+8])[0] if offset+8 <= len(data) else 0
                info["neg_type"] = neg_type
                info["selected_protocol"] = selected_proto
                # Protocol mapping
                proto_map = {0: "RDP", 1: "SSL", 2: "NLA", 4: "NLA-ext"}
                info["protocol_name"] = proto_map.get(selected_proto, "Unknown")
                info["nla_supported"] = (selected_proto == 2 or selected_proto == 4)
                # Version from RDP negotiation response may be embedded later
            return info
        else:
            info["type"] = "Other"
    except Exception as e:
        info["parse_error"] = str(e)
    return info

def check_bluekeep(fingerprint: Dict[str, Any]) -> bool:
    """Heuristic BlueKeep detection based on negotiation response."""
    # If server selects RDP (protocol 0) and does not support NLA/SSL,
    # it might be vulnerable. Not foolproof but safe.
    if fingerprint.get("selected_protocol") == 0 and not fingerprint.get("nla_supported", False):
        return True
    return False

# ======================================================================
# Async scanner framework
# ======================================================================

class ScanResult:
    __slots__ = ("ip", "port", "open", "fingerprint", "vulnerabilities", "error")
    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port
        self.open = False
        self.fingerprint: Dict[str, Any] = {}
        self.vulnerabilities: List[str] = []
        self.error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "port": self.port,
            "open": self.open,
            "fingerprint": self.fingerprint,
            "vulnerabilities": self.vulnerabilities,
            "error": self.error,
        }

class AsyncRateLimiter:
    """Combined global + per-host rate limiter."""
    def __init__(self, global_rate: float):
        self.global_bucket = AsyncTokenBucket(global_rate)
        self._per_ip_lock = asyncio.Lock()
        self._last_ip_time: Dict[str, float] = {}

    async def acquire(self, ip: str = "global") -> None:
        await self.global_bucket.consume()

class BaseScanner(ABC):
    def __init__(self, config: dict):
        self.cfg = config.get("scan", {})
        self.ports = self.cfg.get("ports", [3389])
        self.timeout = self.cfg.get("timeout", 2.0)
        self.concurrency = self.cfg.get("concurrency", 1000)
        self.jitter = (self.cfg.get("jitter_min", 0), self.cfg.get("jitter_max", 0))
        self.rate_limiter = AsyncRateLimiter(self.cfg.get("rate_limit", 10000))
        self.fingerprint = self.cfg.get("fingerprint", True)
        self.vuln_checks = self.cfg.get("vuln_checks", True)
        self.semaphore = asyncio.Semaphore(self.concurrency)

    async def scan_batch(self, ips: Set[str], port: int) -> List[ScanResult]:
        """Return results for a single port batch."""
        tasks = [self._single_scan(ip, port) for ip in ips]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        actual_results = []
        for res in results:
            if isinstance(res, ScanResult):
                actual_results.append(res)
            else:
                LOG.error("Scan task exception: %s", res)
        return actual_results

    @abstractmethod
    async def _single_scan(self, ip: str, port: int) -> ScanResult:
        ...

class AsyncTcpConnectScanner(BaseScanner):
    """Fast async TCP connect scan with banner & vuln checks."""
    async def _single_scan(self, ip: str, port: int) -> ScanResult:
        result = ScanResult(ip, port)
        try:
            await self.rate_limiter.acquire(ip)
            # jitter
            if self.jitter[1] > 0:
                await asyncio.sleep(random.uniform(*self.jitter))
            async with self.semaphore:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.timeout
                )
                result.open = True
                if self.fingerprint and port == 3389:
                    # Perform banner grab
                    try:
                        request = build_rdp_negotiation_request()
                        writer.write(request)
                        await writer.drain()
                        # Read response (enough bytes for negotiation)
                        data = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
                        result.fingerprint = parse_rdp_negotiation_response(data)
                    except Exception as e:
                        result.fingerprint = {"error": str(e)}
                writer.close()
                await writer.wait_closed()
        except (asyncio.TimeoutError, OSError, ConnectionRefusedError) as e:
            result.error = str(e)
        except Exception as e:
            result.error = f"Unexpected: {e}"
        # Vulnerability checks on open port
        if result.open and self.vuln_checks and port == 3389:
            if check_bluekeep(result.fingerprint):
                result.vulnerabilities.append("Potential BlueKeep (CVE-2019-0708)")
            # NLA not enforced
            if not result.fingerprint.get("nla_supported", True):
                result.vulnerabilities.append("NLA not enforced (CVE-2018-0886)")
        return result

class MasscanScanner(BaseScanner):
    """Wrapper around masscan (runs as subprocess). Very fast SYN scan."""
    def __init__(self, config: dict):
        super().__init__(config)
        self.binary = self.cfg.get("masscan_binary", "masscan")
        self.rate = self.cfg.get("masscan_rate", 10000)
        # masscan doesn't support real async, we run in thread pool
        self._executor = None

    async def scan_batch(self, ips: Set[str], port: int) -> List[ScanResult]:
        # Write IPs to temp file
        ip_file = Path(f"/tmp/masscan_ips_{os.getpid()}.txt")
        async with aiofiles.open(ip_file, "w") as f:
            await f.write("\n".join(ips))
        cmd = [
            self.binary,
            "-iL", str(ip_file),
            "-p", str(port),
            "--rate", str(self.rate),
            "--open",
            "-oJ", "-",  # JSON output to stdout
            "--wait", "0",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            # Parse masscan JSON
            results = []
            if proc.returncode == 0 and stdout:
                for line in stdout.decode().splitlines():
                    try:
                        entry = json.loads(line)
                        ip = entry.get("ip")
                        p = entry.get("ports", [{}])[0]
                        if ip and p.get("status") == "open":
                            res = ScanResult(ip, port)
                            res.open = True
                            results.append(res)
                    except Exception:
                        pass
            return results
        finally:
            if ip_file.exists():
                ip_file.unlink()

# ======================================================================
# Live display using Rich
# ======================================================================

class LiveStats:
    """Thread-safe stats for live display."""
    def __init__(self):
        self.lock = asyncio.Lock()
        self.collected = 0
        self.scanned = 0
        self.open = 0
        self.errors = 0
        self.start_time = None

    async def update(self, **kwargs):
        async with self.lock:
            for k, v in kwargs.items():
                setattr(self, k, getattr(self, k, 0) + v)

class LiveDisplay:
    def __init__(self, stats: LiveStats):
        self.stats = stats
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        )
        self.task_collect = self.progress.add_task("[cyan]Collecting IPs...", total=None)
        self.task_scan = self.progress.add_task("[green]Scanning...", total=None)
        self.table = Table.grid(padding=(0, 2))
        self.table.add_column(no_wrap=True)
        self.live = Live(Panel(Group(self.progress, self.table)), console=console, refresh_per_second=10)

    async def start(self):
        self.live.start()

    async def stop(self):
        self.live.stop()

    def update_collect_progress(self, done):
        self.progress.update(self.task_collect, completed=done)

    def set_scan_total(self, total):
        self.progress.update(self.task_scan, total=total)

    def update_scan_progress(self, scanned):
        self.progress.update(self.task_scan, completed=scanned)

    async def update_table(self):
        async with self.stats.lock:
            s = self.stats
            self.table = Table.grid(expand=True)
            self.table.add_column(justify="center")
            self.table.add_column(justify="center")
            self.table.add_row("Collected", str(s.collected))
            self.table.add_row("Scanned", str(s.scanned))
            self.table.add_row("Open", f"[bold green]{s.open}[/]")
            self.table.add_row("Errors", f"[red]{s.errors}[/]")
        self.live.update(Panel(Group(self.progress, self.table)))

# ======================================================================
# Main orchestration
# ======================================================================

async def run_collect(config: dict, sources: List[AsyncSourceBase], cache: IPCache,
                      raw_output: Optional[str], live_display: LiveDisplay, stats: LiveStats):
    """Collect IPs from configured sources."""
    collector = AsyncIPCollector(sources)
    # Use cache if enabled
    cached_ips = await cache.load()
    if cached_ips:
        LOG.info("Loaded %d IPs from cache.", len(cached_ips))
    else:
        cached_ips = set()

    # Fetch new IPs
    new_ips = await collector.collect()
    all_ips = cached_ips | new_ips

    # Save to raw file if requested
    if raw_output:
        async with aiofiles.open(raw_output, "w") as f:
            await f.write("\n".join(sorted(all_ips, key=lambda ip: ipaddress.IPv4Address(ip))))

    # Update cache
    await cache.save(all_ips)
    async with stats.lock:
        stats.collected = len(all_ips)
    live_display.update_collect_progress(len(all_ips))
    await live_display.update_table()
    return all_ips

async def run_scan(ips: Set[str], config: dict, output_prefix: str,
                   live_display: LiveDisplay, stats: LiveStats):
    """Run scan on collected IPs."""
    scan_cfg = config["scan"]
    ports = scan_cfg.get("ports", [3389])
    syn_scan = scan_cfg.get("syn_scan", False)
    scanner: BaseScanner
    if syn_scan:
        scanner = MasscanScanner(config)
    else:
        scanner = AsyncTcpConnectScanner(config)

    total_ips = len(ips) * len(ports)
    live_display.set_scan_total(total_ips)
    results: List[ScanResult] = []
    for port in ports:
        batch_results = await scanner.scan_batch(ips, port)
        results.extend(batch_results)
        # Update stats
        scanned = len(batch_results)
        open_count = sum(1 for r in batch_results if r.open)
        errors = sum(1 for r in batch_results if r.error)
        await stats.update(scanned=scanned, open=open_count, errors=errors)
        live_display.update_scan_progress(stats.scanned)
        await live_display.update_table()

    return results

def generate_report(results: List[ScanResult], config: dict, output_prefix: str):
    """Write reports in requested formats."""
    formats = config["report"].get("formats", ["json"])
    base = Path(config["report"].get("filename", "rdp_report")).expanduser()
    base = Path(output_prefix) if output_prefix else base

    if "json" in formats:
        data = [r.to_dict() for r in results]
        with open(f"{base}.json", "w") as f:
            json.dump(data, f, indent=2)

    if "csv" in formats:
        with open(f"{base}.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["ip", "port", "open", "fingerprint", "vulnerabilities", "error"])
            for r in results:
                writer.writerow([r.ip, r.port, r.open, json.dumps(r.fingerprint),
                                 ";".join(r.vulnerabilities), r.error])

    if "html" in formats:
        # simple HTML table
        html = "<html><body><table><tr><th>IP</th><th>Port</th><th>Open</th><th>Vulnerabilities</th></tr>"
        for r in results:
            if r.open:
                vulns = "<br>".join(r.vulnerabilities)
                html += f"<tr><td>{r.ip}</td><td>{r.port}</td><td>{r.open}</td><td>{vulns}</td></tr>"
        html += "</table></body></html>"
        with open(f"{base}.html", "w") as f:
            f.write(html)

# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------

async def main_async(args):
    config = load_config(args.config)
    config = env_override(config)

    # Select sources
    selected_sources = None
    if args.source:
        selected_sources = [s.strip() for s in args.source.split(",") if s.strip()]

    sources = create_sources(config, selected_sources)
    if not sources:
        console.print("[red]No sources configured.[/]")
        return

    # Prompt for missing keys
    for src in sources:
        src.prompt_credentials()

    # Setup cache
    cache_dir = Path(config["global"]["cache_dir"]).expanduser()
    cache_file = cache_dir / "collected_ips.json"
    ttl = config["global"].get("cache_ttl_hours", 12)
    cache = IPCache(cache_file, ttl)

    stats = LiveStats()
    display = LiveDisplay(stats)

    # Phase 1: Collection
    await display.start()
    ips = await run_collect(config, sources, cache, args.raw_output, display, stats)
    if args.collect_only:
        await display.stop()
        console.print(f"[bold green]Collected {len(ips)} IPs. Saved to {args.raw_output or 'cache'}[/]")
        return

    if not ips:
        await display.stop()
        console.print("[yellow]No IPs to scan.[/]")
        return

    # Phase 2: Scanning
    results = await run_scan(ips, config, args.output_prefix, display, stats)
    await display.stop()

    # Generate report
    generate_report(results, config, args.output_prefix)

    # Print summary
    open_ips = [r for r in results if r.open]
    console.print(f"\n[bold]Scan complete.[/] Found {len(open_ips)} open ports.")
    if open_ips:
        console.print("\n[bold underline]Open IPs:[/]")
        for r in open_ips[:20]:
            vuln_str = ", ".join(r.vulnerabilities) if r.vulnerabilities else "none"
            console.print(f"  {r.ip}:{r.port}  vulns: {vuln_str}")
        if len(open_ips) > 20:
            console.print(f"  ... and {len(open_ips)-20} more.")

def main():
    parser = argparse.ArgumentParser(
        description="RDP Recon Turbo – high-speed async reconnaissance. Authorised use only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--authorize", required=True, action="store_true",
                        help="Confirm you have permission to scan target hosts.")
    parser.add_argument("--config", default="rdp_config.yaml", help="Config file (YAML).")
    parser.add_argument("--source", help="Comma-separated sources (e.g. shodan,censys).")
    parser.add_argument("--raw-output", help="Save collected IPs to file.")
    parser.add_argument("--output-prefix", default="rdp_results", help="Prefix for report files.")
    parser.add_argument("--collect-only", action="store_true", help="Only collect IPs, no scanning.")
    args = parser.parse_args()

    # Run async main
    loop = asyncio.new_event_loop()
    if uvloop:
        uvloop.install()
    try:
        loop.run_until_complete(main_async(args))
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted.[/]")
    finally:
        loop.close()

if __name__ == "__main__":
    main()
