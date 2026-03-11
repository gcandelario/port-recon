"""Unit tests for scanner.utils."""

import pytest
from scanner.utils import (
    get_service_name,
    parse_port_range,
    sanitize_banner,
    TOP_100_PORTS,
)


class TestParsePortRange:
    def test_single_port(self):
        assert parse_port_range("80") == [80]

    def test_range(self):
        assert parse_port_range("1-5") == [1, 2, 3, 4, 5]

    def test_comma_separated(self):
        assert parse_port_range("22,80,443") == [22, 80, 443]

    def test_mixed(self):
        result = parse_port_range("22,80-82,443")
        assert result == [22, 80, 81, 82, 443]

    def test_deduplication(self):
        assert parse_port_range("80,80,80") == [80]

    def test_sorted_output(self):
        result = parse_port_range("443,22,80")
        assert result == sorted(result)

    def test_max_port(self):
        assert parse_port_range("65535") == [65535]

    def test_port_out_of_range_raises(self):
        with pytest.raises(ValueError):
            parse_port_range("65536")

    def test_zero_port_raises(self):
        with pytest.raises(ValueError):
            parse_port_range("0")

    def test_reversed_range_raises(self):
        with pytest.raises(ValueError):
            parse_port_range("100-50")

    def test_invalid_string_raises(self):
        with pytest.raises((ValueError, TypeError)):
            parse_port_range("abc")


class TestGetServiceName:
    def test_http(self):
        assert get_service_name(80) == "HTTP"

    def test_https(self):
        assert get_service_name(443) == "HTTPS"

    def test_ssh(self):
        assert get_service_name(22) == "SSH"

    def test_mysql(self):
        assert get_service_name(3306) == "MYSQL"

    def test_unknown_port(self):
        # Port 59999 is not in SERVICE_NAMES; result is either socket name or UNKNOWN
        name = get_service_name(59999)
        assert isinstance(name, str) and len(name) > 0


class TestSanitizeBanner:
    def test_plain_ascii(self):
        assert sanitize_banner(b"SSH-2.0-OpenSSH_8.9") == "SSH-2.0-OpenSSH_8.9"

    def test_strips_whitespace(self):
        assert sanitize_banner(b"  hello world  ") == "hello world"

    def test_truncation(self):
        long_banner = b"A" * 200
        result = sanitize_banner(long_banner, max_length=10)
        assert result.endswith("...")
        assert len(result) == 13  # 10 chars + "..."

    def test_non_printable_replaced(self):
        result = sanitize_banner(b"hello\x00world")
        assert "\x00" not in result
        assert "hello" in result

    def test_empty_bytes(self):
        assert sanitize_banner(b"") == ""

    def test_utf8_decoding(self):
        result = sanitize_banner("Hello wörld".encode("utf-8"))
        assert "Hello" in result


class TestTop100Ports:
    def test_is_list(self):
        assert isinstance(TOP_100_PORTS, list)

    def test_non_empty(self):
        assert len(TOP_100_PORTS) > 0

    def test_all_valid_ports(self):
        assert all(1 <= p <= 65535 for p in TOP_100_PORTS)

    def test_sorted(self):
        assert TOP_100_PORTS == sorted(TOP_100_PORTS)

    def test_no_duplicates(self):
        assert len(TOP_100_PORTS) == len(set(TOP_100_PORTS))

    def test_contains_common_ports(self):
        for p in (22, 80, 443):
            assert p in TOP_100_PORTS
