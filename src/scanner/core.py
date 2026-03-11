"""
Core scanning engine for the port scanner.

Provides the ScanResult dataclass, ScanMode enum, and the PortScanner
class that drives TCP connect scanning with optional banner grabbing.
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, List, Optional

from tqdm import tqdm

from .utils import TOP_100_PORTS, get_service_name, parse_port_range, sanitize_banner


class ScanMode(Enum):
    """Supported scanning modes."""
    TCP_CONNECT = auto()   # Full TCP handshake (default)
    TOP_100 = auto()       # Scan nmap's top-100 ports
    FULL_RANGE = auto()    # Scan all 65535 ports


@dataclass
class ScanResult:
    """Result for a single scanned port."""
    port: int
    state: str                        # "open" | "closed" | "filtered"
    service: str = "UNKNOWN"
    banner: str = ""
    latency_ms: float = 0.0

    @property
    def is_open(self) -> bool:
        return self.state == "open"


@dataclass
class ScanSummary:
    """Aggregate statistics for a completed scan."""
    target_host: str
    target_ip: str
    total_ports: int
    results: List[ScanResult] = field(default_factory=list)
    scan_duration_s: float = 0.0

    @property
    def open_count(self) -> int:
        return sum(1 for r in self.results if r.state == "open")

    @property
    def closed_count(self) -> int:
        return sum(1 for r in self.results if r.state == "closed")

    @property
    def filtered_count(self) -> int:
        return sum(1 for r in self.results if r.state == "filtered")

    @property
    def open_results(self) -> List[ScanResult]:
        return sorted(
            [r for r in self.results if r.state == "open"],
            key=lambda r: r.port,
        )


# Probes sent to grab banners from common services
_BANNER_PROBES: dict[int, bytes] = {
    21:  b"",                              # FTP sends banner on connect
    22:  b"",                              # SSH sends banner on connect
    25:  b"EHLO scanner\r\n",
    80:  b"HEAD / HTTP/1.0\r\n\r\n",
    110: b"",                              # POP3 sends banner on connect
    143: b"",                              # IMAP sends banner on connect
    443: b"",
    3306: b"",                             # MySQL sends banner on connect
    5432: b"",
    6379: b"PING\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
    27017: b"",
}


class PortScanner:
    """
    Multi-threaded TCP port scanner with optional banner grabbing.

    Args:
        host: Target hostname or IP address.
        timeout: Per-port connection timeout in seconds.
        threads: Maximum number of concurrent worker threads.
        grab_banners: Whether to attempt service banner grabbing on open ports.
        progress_callback: Optional callable invoked after each port is scanned.
    """

    def __init__(
        self,
        host: str,
        timeout: float = 1.0,
        threads: int = 100,
        grab_banners: bool = True,
        progress_callback: Optional[Callable[[ScanResult], None]] = None,
    ) -> None:
        self.host = host
        self.timeout = timeout
        self.threads = threads
        self.grab_banners = grab_banners
        self.progress_callback = progress_callback

    def _scan_port(self, port: int) -> ScanResult:
        """
        Attempt a TCP connect to a single port and return its result.

        Args:
            port: Port number to scan.

        Returns:
            ScanResult with state, service name, optional banner, and latency.
        """
        start = time.perf_counter()
        result = ScanResult(port=port, service=get_service_name(port), state="filtered")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                code = sock.connect_ex((self.host, port))
                latency = (time.perf_counter() - start) * 1000
                result.latency_ms = round(latency, 2)

                if code == 0:
                    result.state = "open"
                    if self.grab_banners:
                        result.banner = self._grab_banner(sock, port)
                else:
                    result.state = "closed"
        except socket.timeout:
            result.state = "filtered"
            result.latency_ms = round(self.timeout * 1000, 2)
        except PermissionError:
            result.state = "filtered"
        except OSError:
            result.state = "closed"

        return result

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """
        Send a probe and read up to 1024 bytes of banner data.

        Args:
            sock: Connected socket (must still be open).
            port: Port number, used to select the appropriate probe.

        Returns:
            Sanitized banner string, or empty string if unavailable.
        """
        try:
            probe = _BANNER_PROBES.get(port, b"")
            if probe:
                sock.sendall(probe)
            sock.settimeout(self.timeout)
            raw = sock.recv(1024)
            return sanitize_banner(raw) if raw else ""
        except OSError:
            return ""

    def scan(self, ports: List[int], show_progress: bool = True) -> ScanSummary:
        """
        Scan a list of ports concurrently and return aggregated results.

        Args:
            ports: Ordered list of port numbers to scan.
            show_progress: Display a tqdm progress bar on stderr.

        Returns:
            ScanSummary containing per-port results and aggregate stats.
        """
        from .utils import resolve_host  # avoid circular at module level

        try:
            ip, _ = resolve_host(self.host)
        except socket.gaierror as exc:
            raise RuntimeError(f"Cannot resolve host '{self.host}': {exc}") from exc

        summary = ScanSummary(
            target_host=self.host,
            target_ip=ip,
            total_ports=len(ports),
        )
        wall_start = time.perf_counter()
        results: List[ScanResult] = []

        bar = tqdm(
            total=len(ports),
            desc="Scanning",
            unit="port",
            disable=not show_progress,
            dynamic_ncols=True,
            colour="cyan",
        )

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._scan_port, p): p for p in ports}
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                bar.update(1)
                if result.is_open:
                    bar.write(
                        f"  \033[32m[OPEN]\033[0m  {result.port:<6} "
                        f"{result.service}"
                    )
                if self.progress_callback:
                    self.progress_callback(result)

        bar.close()
        summary.results = sorted(results, key=lambda r: r.port)
        summary.scan_duration_s = round(time.perf_counter() - wall_start, 2)
        return summary

    @classmethod
    def build_port_list(
        cls,
        mode: ScanMode,
        port_range: Optional[str] = None,
    ) -> List[int]:
        """
        Build a sorted list of ports to scan based on the scan mode.

        Args:
            mode: ScanMode enum value.
            port_range: Port specification string (required for TCP_CONNECT mode).

        Returns:
            Sorted list of port numbers.

        Raises:
            ValueError: If mode is TCP_CONNECT and port_range is not provided.
        """
        if mode == ScanMode.TOP_100:
            return TOP_100_PORTS
        if mode == ScanMode.FULL_RANGE:
            return list(range(1, 65536))
        if port_range is None:
            raise ValueError("port_range is required for TCP_CONNECT mode")
        return parse_port_range(port_range)
