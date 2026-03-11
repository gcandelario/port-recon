"""
Utility functions for the port scanner.

Provides hostname resolution, port range parsing, service name lookup,
and the list of top 100 most common ports.
"""

import socket
from typing import List, Tuple


# Top 100 most scanned TCP ports (nmap default)
TOP_100_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 9090, 9200, 27017,
    20, 24, 26, 30, 32, 33, 37, 42, 43, 49, 70, 79, 81, 88, 106, 109,
    113, 119, 123, 137, 138, 144, 179, 199, 389, 427, 444, 465, 513,
    514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3986, 4899, 5000,
    5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800,
    5985, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8081, 8180,
]
TOP_100_PORTS = sorted(set(TOP_100_PORTS))

# IANA service names for well-known ports
SERVICE_NAMES: dict[int, str] = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    88: "KERBEROS", 110: "POP3", 111: "RPCBIND", 119: "NNTP",
    123: "NTP", 135: "MSRPC", 137: "NETBIOS-NS", 138: "NETBIOS-DGM",
    139: "NETBIOS-SSN", 143: "IMAP", 161: "SNMP", 162: "SNMPTRAP",
    179: "BGP", 194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 500: "ISAKMP", 514: "SYSLOG", 515: "LPD",
    520: "RIP", 554: "RTSP", 587: "SMTP-SUBMISSION", 631: "IPP",
    636: "LDAPS", 873: "RSYNC", 902: "VMWARE", 990: "FTPS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OPENVPN",
    1433: "MSSQL", 1521: "ORACLE", 1723: "PPTP", 1883: "MQTT",
    2049: "NFS", 2181: "ZOOKEEPER", 3000: "DEV-SERVER", 3128: "SQUID",
    3268: "LDAP-GC", 3306: "MYSQL", 3389: "RDP", 4444: "METASPLOIT",
    5000: "UPNP", 5432: "POSTGRESQL", 5900: "VNC", 5985: "WINRM",
    6379: "REDIS", 6443: "K8S-API", 7001: "WEBLOGIC", 8080: "HTTP-ALT",
    8443: "HTTPS-ALT", 8888: "JUPYTER", 9090: "PROMETHEUS",
    9092: "KAFKA", 9200: "ELASTICSEARCH", 9300: "ELASTICSEARCH-CLUSTER",
    27017: "MONGODB", 27018: "MONGODB", 50000: "DB2",
}


def resolve_host(host: str) -> Tuple[str, str]:
    """
    Resolve a hostname to its IP address.

    Args:
        host: Hostname or IP address string.

    Returns:
        Tuple of (resolved_ip, canonical_hostname).

    Raises:
        socket.gaierror: If the hostname cannot be resolved.
    """
    ip = socket.gethostbyname(host)
    try:
        canonical = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        canonical = host
    return ip, canonical


def parse_port_range(port_str: str) -> List[int]:
    """
    Parse a port specification string into a sorted list of ports.

    Accepts single ports (80), ranges (1-1024), and comma-separated
    combinations (22,80,443,8000-8080).

    Args:
        port_str: Port specification string.

    Returns:
        Sorted list of port numbers.

    Raises:
        ValueError: If the port string is malformed or contains out-of-range ports.
    """
    ports: List[int] = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s.strip()), int(end_s.strip())
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValueError(f"Port out of range: {part}")
            if start > end:
                raise ValueError(f"Invalid range (start > end): {part}")
            ports.extend(range(start, end + 1))
        else:
            port = int(part)
            if not 1 <= port <= 65535:
                raise ValueError(f"Port out of range: {port}")
            ports.append(port)
    return sorted(set(ports))


def get_service_name(port: int) -> str:
    """
    Return a human-readable service name for a port number.

    Checks the local SERVICE_NAMES dict first, then falls back to
    the system's socket.getservbyport().

    Args:
        port: TCP port number.

    Returns:
        Service name string, or 'UNKNOWN' if not found.
    """
    if port in SERVICE_NAMES:
        return SERVICE_NAMES[port]
    try:
        return socket.getservbyport(port, "tcp").upper()
    except OSError:
        return "UNKNOWN"


def sanitize_banner(banner: bytes, max_length: int = 80) -> str:
    """
    Decode and sanitize a raw banner byte string for display.

    Args:
        banner: Raw bytes received from the service.
        max_length: Maximum characters to include.

    Returns:
        Cleaned, printable ASCII string.
    """
    text = banner.decode("utf-8", errors="replace").strip()
    # Remove non-printable characters except common whitespace
    text = "".join(c if c.isprintable() else " " for c in text)
    # Collapse whitespace and truncate
    text = " ".join(text.split())
    return text[:max_length] + ("..." if len(text) > max_length else "")
