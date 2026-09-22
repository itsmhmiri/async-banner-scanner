"""Target and port parsing utilities for Async Banner Scanner."""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
from typing import Iterable, Iterator, List, Optional, Sequence, Set

from async_banner_scanner.models import Target, TransportProtocol

logger = logging.getLogger(__name__)

# Top 100 most commonly scanned TCP ports (derived from standard Nmap service frequency table)
TOP_100_PORTS: List[int] = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152,
    49153, 49154, 49155, 49156, 49157,
]

# Top 100 most commonly scanned UDP ports (DNS, DHCP, TFTP, NTP, SNMP, NetBIOS, SSDP, etc.)
TOP_100_UDP_PORTS: List[int] = [
    7, 9, 13, 17, 19, 37, 42, 49, 53, 67, 68, 69, 88, 111, 118, 123, 135, 136,
    137, 138, 139, 143, 156, 161, 162, 177, 201, 213, 220, 389, 443, 445, 464,
    500, 513, 514, 515, 517, 518, 520, 521, 525, 533, 546, 547, 631, 996, 997,
    998, 999, 1025, 1026, 1027, 1028, 1029, 1030, 1433, 1434, 1645, 1646, 1701,
    1718, 1719, 1812, 1813, 1900, 2000, 2049, 2222, 2223, 3283, 3478, 4045, 4500,
    5000, 5060, 5353, 5683, 6000, 6001, 7000, 7070, 8000, 8080, 8443, 8888, 9200,
    10000, 11211, 17185, 20031, 27017, 30718, 31337, 32768, 32769, 32770, 32771,
    33434, 49152, 49153, 49154, 49155, 49156,
][:100]

# Additional ports to form Top 1000 most common ports
_ADDITIONAL_TOP_1000_PORTS: List[int] = [
    1, 3, 4, 6, 17, 19, 20, 32, 42, 43, 49, 57, 67, 68, 69, 70, 82, 83, 84, 85,
    88, 89, 90, 99, 100, 102, 109, 117, 123, 137, 138, 146, 161, 162, 163, 164,
    175, 180, 201, 211, 212, 220, 222, 245, 264, 280, 306, 311, 366, 387, 407,
    416, 417, 425, 464, 497, 500, 512, 520, 524, 541, 545, 547, 555, 563, 581,
    593, 616, 617, 625, 636, 666, 688, 691, 700, 705, 711, 714, 720, 722, 726,
    749, 765, 777, 783, 787, 800, 801, 808, 843, 888, 898, 900, 901, 902, 903,
    911, 912, 981, 987, 992, 1000, 1001, 1002, 1008, 1010, 1011, 1023, 1024,
    1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042,
    1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055,
    1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068,
    1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081,
    1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094,
    1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108, 1111,
    1112, 1113, 1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132,
    1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165,
    1166, 1169, 1174, 1175, 1183, 1185, 1186, 1187, 1192, 1198, 1199, 1201, 1211,
    1212, 1213, 1214, 1216, 1217, 1218, 1233, 1234, 1236, 1244, 1247, 1248, 1259,
    1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328, 1334,
    1352, 1417, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503, 1512, 1521, 1524,
    1533, 1556, 1580, 1583, 1590, 1594, 1600, 1650, 1666, 1677, 1687, 1688, 1699,
    1700, 1717, 1718, 1719, 1721, 1755, 1761, 1782, 1783, 1801, 1805, 1812, 1813,
    1863, 1864, 1875, 1900, 1914, 1935, 1970, 1971, 1972, 1974, 1984, 1998, 1999,
    2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2013, 2020, 2021, 2022,
    2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048,
    2065, 2068, 2082, 2083, 2086, 2087, 2095, 2096, 2105, 2106, 2160, 2161, 2170,
    2179, 2181, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366,
    2381, 2382, 2383, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604,
    2605, 2607, 2608, 2638, 2701, 2702, 2710, 2718, 2725, 2809, 2869, 2875, 2910,
    2920, 2967, 2968, 2998, 3001, 3003, 3005, 3006, 3007, 3011, 3017, 3030, 3031,
    3050, 3052, 3071, 3077, 3123, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3322,
    3323, 3324, 3325, 3333, 3351, 3367, 3372, 3388, 3390, 3404, 3476, 3493, 3517,
    3527, 3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801,
    3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914,
    3918, 3920, 3945, 3971, 3995, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006,
    4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445,
    4446, 4449, 4550, 4567, 4662, 4848, 4894, 4998, 5001, 5002, 5003, 5004, 5050,
    5080, 5120, 5190, 5222, 5225, 5226, 5269, 5280, 5298, 5351, 5353, 5355, 5405,
    5433, 5500, 5510, 5544, 5555, 5632, 5678, 5679, 5722, 5801, 5802, 5810, 5811,
    5850, 5859, 5877, 5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922,
    5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5984, 5985, 5986, 5987, 5988,
    5989, 5998, 5999, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100,
    6101, 6106, 6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547, 6565,
    6566, 6567, 6580, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789,
    6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007, 7019, 7025, 7070,
    7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512, 7547, 7625, 7627,
    7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8001, 8002,
    8007, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8082, 8083, 8084, 8085, 8086,
    8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8200, 8222, 8254, 8290,
    8291, 8292, 8300, 8332, 8333, 8400, 8402, 8500, 8554, 8600, 8649, 8651, 8652,
    8654, 8701, 8800, 8873, 8880, 8889, 8899, 8901, 8902, 8903, 8910, 8990, 8999,
    9000, 9001, 9002, 9010, 9020, 9030, 9040, 9050, 9071, 9080, 9081, 9090, 9091,
    9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290, 9418, 9485, 9500, 9502,
    9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900,
    9917, 9929, 9943, 9944, 9968, 9998, 10001, 10002, 10003, 10004, 10009, 10010,
    10012, 10024, 10025, 10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621,
    10626, 10628, 10629, 10809, 11000, 11110, 11111, 11211, 11371, 12000, 12174,
    12265, 12345, 13456, 13722, 13782, 13783, 14000, 14238, 14441, 14442, 15000,
    15002, 15003, 15004, 15660, 16000, 16001, 16012, 16016, 16018, 16080, 16113,
    16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283, 19315, 19350,
    19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571, 22939,
    23502, 24444, 24800, 25734, 25735, 26214, 27000, 27015, 27017, 27374, 27665,
    28282, 28784, 30000, 30718, 31099, 32769, 32770, 32771, 32772, 32773, 32774,
    32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785,
    33354, 33899, 34571, 35500, 38292, 40193, 40911, 41511, 42510, 44176, 44442,
    44443, 44501, 45100, 48080, 49158, 49159, 49160, 49161, 49163, 49165, 49167,
    49175, 49176, 49400, 49999, 50000, 50001, 50002, 50003, 50006, 50300, 50500,
    50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055,
    55056, 55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532,
    62078, 63331, 64623, 64680, 65000, 65129, 65389,
    2, 5, 8, 10, 11, 12, 14, 15, 16, 18, 24, 27, 28, 29, 30, 31, 33, 34, 35, 36, 38, 39, 40, 41, 44,
]

TOP_1000_PORTS: List[int] = sorted(list(set(TOP_100_PORTS + _ADDITIONAL_TOP_1000_PORTS)))[:1000]


def parse_ports(
    ports_spec: Optional[str] = None,
    top_ports: Optional[int] = None,
    protocol: TransportProtocol = TransportProtocol.TCP,
) -> List[int]:
    """Parse port string, range, or top-ports preset into a sorted list of unique port numbers.

    Supported formats:
        - Single port: "80"
        - Comma list: "21,22,80,443"
        - Ranges: "80-85", "8000-8010"
        - Combinations: "22,80-82,443,8080-8085"
        - Presets: top_ports=100 or top_ports=1000

    Args:
        ports_spec: Port list or range string (e.g., "80,443,8000-8080").
        top_ports: Scan top N ports (100 or 1000).
        protocol: Transport protocol (TCP or UDP) for selecting corresponding top ports preset.

    Returns:
        Sorted list of unique valid integer port numbers (1-65535).

    Raises:
        ValueError: If a port number is invalid, outside 1-65535, or range start > end.
    """
    if top_ports is not None:
        if top_ports == 100:
            if protocol == TransportProtocol.UDP:
                return sorted(list(set(TOP_100_UDP_PORTS)))
            return sorted(list(set(TOP_100_PORTS)))
        elif top_ports == 1000:
            return sorted(list(set(TOP_1000_PORTS)))
        else:
            raise ValueError(f"Invalid --top-ports value: {top_ports}. Supported presets: 100, 1000.")

    if not ports_spec:
        # Default to Top 100 ports if neither -p nor --top-ports is given
        if protocol == TransportProtocol.UDP:
            return sorted(list(set(TOP_100_UDP_PORTS)))
        return sorted(list(set(TOP_100_PORTS)))

    ports: Set[int] = set()
    chunks = [c.strip() for c in ports_spec.split(",") if c.strip()]
    if not chunks:
        raise ValueError(f"No valid ports found in specification: '{ports_spec}'")

    for chunk in chunks:
        if "-" in chunk:
            parts = chunk.split("-")
            if len(parts) != 2:
                raise ValueError(f"Invalid port range syntax: '{chunk}'")
            try:
                start = int(parts[0].strip())
                end = int(parts[1].strip())
            except ValueError:
                raise ValueError(f"Port range must contain valid integers: '{chunk}'")

            if start > end:
                raise ValueError(f"Invalid port range: start ({start}) must be <= end ({end})")
            if start < 1 or end > 65535:
                raise ValueError(f"Port range out of bounds [1-65535]: '{chunk}'")

            ports.update(range(start, end + 1))
        else:
            try:
                port = int(chunk)
            except ValueError:
                raise ValueError(f"Invalid port number: '{chunk}'")
            if port < 1 or port > 65535:
                raise ValueError(f"Port out of bounds [1-65535]: {port}")
            ports.add(port)

    return sorted(list(ports))


def _resolve_hostname(hostname: str) -> List[str]:
    """Resolve a hostname/FQDN to IPv4/IPv6 address strings.

    Args:
        hostname: Domain name or FQDN string.

    Returns:
        List of resolved IP addresses. Empty list if resolution fails.
    """
    try:
        # Resolve address info for TCP socket
        addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        ips: Set[str] = set()
        for family, _, _, _, sockaddr in addr_info:
            if family == socket.AF_INET:
                ips.add(sockaddr[0])
            elif family == socket.AF_INET6:
                ips.add(sockaddr[0])
        return sorted(list(ips))
    except socket.gaierror as err:
        logger.warning(f"Failed to resolve hostname '{hostname}': {err}")
        return []


def parse_targets(target_spec: str) -> Iterator[str]:
    """Parse target specification into an iterator of IP address strings.

    Supported targets:
        - Single IPv4 / IPv6 (e.g., '192.168.1.1', '::1')
        - CIDR blocks (e.g., '192.168.1.0/24', '10.0.0.0/30')
        - Hostname / FQDN (e.g., 'scanme.nmap.org', 'localhost')
        - Target input file (path to file containing IP, CIDR, or hostnames)
        - Comma-separated combination (e.g., '192.168.1.1,192.168.1.2')

    Args:
        target_spec: Target string or path to targets file.

    Yields:
        Individual IP address strings.
    """
    cleaned = target_spec.strip()
    if not cleaned:
        return

    # Check if target_spec is an existing file path
    if os.path.isfile(cleaned):
        with open(cleaned, "r", encoding="utf-8") as f:
            for line in f:
                line_clean = line.strip()
                # Skip comments and blank lines
                if not line_clean or line_clean.startswith("#"):
                    continue
                yield from parse_targets(line_clean)
        return

    # Handle comma-separated target entries
    if "," in cleaned:
        for item in cleaned.split(","):
            item_clean = item.strip()
            if item_clean:
                yield from parse_targets(item_clean)
        return

    # Attempt to parse as IP address or CIDR network
    try:
        network = ipaddress.ip_network(cleaned, strict=False)
        for ip in network:
            yield str(ip)
        return
    except ValueError:
        # Not a valid IP or CIDR network; treat as hostname / FQDN
        pass

    # Resolve as hostname / FQDN
    resolved_ips = _resolve_hostname(cleaned)
    for ip in resolved_ips:
        yield ip


def generate_targets(
    target_spec: str,
    ports_spec: Optional[str] = None,
    top_ports: Optional[int] = None,
    protocols: Sequence[TransportProtocol] = (TransportProtocol.TCP,),
) -> Iterator[Target]:
    """Generate Target(host, port, protocol) tuples from target and port specifications.

    Args:
        target_spec: Target string (IP, CIDR, hostname, file path).
        ports_spec: Port list/range specification.
        top_ports: Top ports preset (100 or 1000).
        protocols: Sequence of transport protocols to scan (e.g. TCP, UDP, or both).

    Yields:
        Target objects with host, port, and protocol.
    """
    for host in parse_targets(target_spec):
        for proto in protocols:
            ports = parse_ports(ports_spec=ports_spec, top_ports=top_ports, protocol=proto)
            for port in ports:
                yield Target(host=host, port=port, protocol=proto)
