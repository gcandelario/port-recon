"""Unit tests for scanner.core — uses a local echo server to avoid network calls."""

import socket
import threading
import time
import pytest

from scanner.core import PortScanner, ScanMode, ScanResult, ScanSummary


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _start_tcp_server(host: str = "127.0.0.1", banner: bytes = b"TEST-BANNER\r\n") -> int:
    """
    Spin up a tiny one-shot TCP echo server on a random OS-assigned port.
    Returns the port it's listening on.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, 0))
    port = server.getsockname()[1]
    server.listen(5)

    def _serve():
        while True:
            try:
                conn, _ = server.accept()
                with conn:
                    conn.sendall(banner)
            except OSError:
                break

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    return port


@pytest.fixture(scope="module")
def open_port() -> int:
    """A port with a live TCP server running."""
    return _start_tcp_server(banner=b"HELLO\r\n")


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------

class TestScanResult:
    def test_is_open_true(self):
        r = ScanResult(port=80, state="open")
        assert r.is_open is True

    def test_is_open_false_for_closed(self):
        r = ScanResult(port=80, state="closed")
        assert r.is_open is False

    def test_is_open_false_for_filtered(self):
        r = ScanResult(port=80, state="filtered")
        assert r.is_open is False

    def test_defaults(self):
        r = ScanResult(port=443, state="open")
        assert r.service == "UNKNOWN"
        assert r.banner == ""
        assert r.latency_ms == 0.0


# ---------------------------------------------------------------------------
# ScanSummary
# ---------------------------------------------------------------------------

class TestScanSummary:
    def _make_summary(self, states):
        results = [ScanResult(port=i, state=s) for i, s in enumerate(states, 1)]
        s = ScanSummary(target_host="localhost", target_ip="127.0.0.1", total_ports=len(results))
        s.results = results
        return s

    def test_open_count(self):
        s = self._make_summary(["open", "closed", "open", "filtered"])
        assert s.open_count == 2

    def test_closed_count(self):
        s = self._make_summary(["open", "closed", "closed"])
        assert s.closed_count == 2

    def test_filtered_count(self):
        s = self._make_summary(["filtered", "open"])
        assert s.filtered_count == 1

    def test_open_results_sorted(self):
        results = [
            ScanResult(port=443, state="open"),
            ScanResult(port=80, state="open"),
            ScanResult(port=22, state="closed"),
        ]
        s = ScanSummary(target_host="h", target_ip="1.2.3.4", total_ports=3)
        s.results = results
        ports = [r.port for r in s.open_results]
        assert ports == sorted(ports)
        assert 22 not in ports


# ---------------------------------------------------------------------------
# PortScanner.build_port_list
# ---------------------------------------------------------------------------

class TestBuildPortList:
    def test_top_100_returns_list(self):
        ports = PortScanner.build_port_list(ScanMode.TOP_100)
        assert isinstance(ports, list)
        assert len(ports) > 0

    def test_full_range_returns_all_ports(self):
        ports = PortScanner.build_port_list(ScanMode.FULL_RANGE)
        assert ports[0] == 1
        assert ports[-1] == 65535
        assert len(ports) == 65535

    def test_tcp_connect_custom_range(self):
        ports = PortScanner.build_port_list(ScanMode.TCP_CONNECT, port_range="80,443")
        assert ports == [80, 443]

    def test_tcp_connect_without_range_raises(self):
        with pytest.raises(ValueError):
            PortScanner.build_port_list(ScanMode.TCP_CONNECT)


# ---------------------------------------------------------------------------
# PortScanner._scan_port (uses local server)
# ---------------------------------------------------------------------------

class TestScanPort:
    def test_open_port_detected(self, open_port):
        scanner = PortScanner("127.0.0.1", timeout=2.0, threads=1, grab_banners=False)
        result = scanner._scan_port(open_port)
        assert result.state == "open"
        assert result.port == open_port
        assert result.latency_ms >= 0

    def test_closed_port_detected(self):
        # Port 1 is almost certainly closed on loopback
        scanner = PortScanner("127.0.0.1", timeout=1.0, threads=1, grab_banners=False)
        result = scanner._scan_port(1)
        assert result.state in ("closed", "filtered")

    def test_banner_grabbed_on_open_port(self, open_port):
        scanner = PortScanner("127.0.0.1", timeout=2.0, threads=1, grab_banners=True)
        result = scanner._scan_port(open_port)
        assert result.state == "open"
        assert "HELLO" in result.banner

    def test_unresolvable_host_raises(self):
        scanner = PortScanner("this.host.does.not.exist.invalid", timeout=1.0, threads=1)
        with pytest.raises(RuntimeError, match="Cannot resolve"):
            scanner.scan([80], show_progress=False)

    def test_latency_populated(self, open_port):
        scanner = PortScanner("127.0.0.1", timeout=2.0, threads=1, grab_banners=False)
        result = scanner._scan_port(open_port)
        assert result.latency_ms > 0


# ---------------------------------------------------------------------------
# PortScanner.scan (integration, local server)
# ---------------------------------------------------------------------------

class TestScan:
    def test_scan_returns_summary(self, open_port):
        scanner = PortScanner("127.0.0.1", timeout=2.0, threads=10, grab_banners=False)
        summary = scanner.scan([open_port], show_progress=False)
        assert isinstance(summary, ScanSummary)
        assert summary.open_count >= 1

    def test_scan_duration_positive(self, open_port):
        scanner = PortScanner("127.0.0.1", timeout=2.0, threads=5, grab_banners=False)
        summary = scanner.scan([open_port], show_progress=False)
        assert summary.scan_duration_s >= 0  # loopback may round to 0.00s

    def test_scan_total_ports_matches(self, open_port):
        ports = [open_port, 1, 2]
        scanner = PortScanner("127.0.0.1", timeout=1.0, threads=5, grab_banners=False)
        summary = scanner.scan(ports, show_progress=False)
        assert summary.total_ports == len(ports)
        assert len(summary.results) == len(ports)

    def test_progress_callback_called(self, open_port):
        called = []
        scanner = PortScanner(
            "127.0.0.1",
            timeout=2.0,
            threads=5,
            grab_banners=False,
            progress_callback=called.append,
        )
        scanner.scan([open_port], show_progress=False)
        assert len(called) == 1
        assert isinstance(called[0], ScanResult)
