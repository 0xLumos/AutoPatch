"""
Layer 5: Network Behavior Monitor for AutoPatch.

Starts a patched container, exercises it to trigger dormant payloads,
captures network traffic via tcpdump, and analyzes it for C2 indicators.

Five detectors run against the captured traffic:
  1. Threat intel matching (URLhaus + ThreatFox)
  2. DGA detection (Shannon entropy on DNS queries)
  3. Beaconing detection (periodic outbound connections)
  4. Unusual port detection (non-standard outbound ports)
  5. DNS tunneling detection (TXT queries, large payloads, high frequency)
"""

import json
import logging
import math
import os
import re
import shutil
import struct
import subprocess
import tempfile
import time
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .utils import run_cmd

logger = logging.getLogger("docker_patch_tool")

# Default allowed outbound ports
DEFAULT_ALLOWED_PORTS: List[int] = [
    80, 443, 53, 8080, 8443,  # Web / DNS
    3306, 5432, 6379, 27017,  # Databases
    9200, 5672, 11211,        # Search / MQ / Cache
]

# Default CDN/cloud domain allowlist for DGA detector
DEFAULT_DOMAIN_ALLOWLIST: Set[str] = {
    "amazonaws.com", "cloudfront.net", "googleapis.com",
    "azurewebsites.net", "azure.com", "microsoft.com",
    "docker.io", "docker.com", "registry.npmjs.org",
    "pypi.org", "github.com", "githubusercontent.com",
    "gitlab.com", "bitbucket.org", "cloudflare.com",
    "fastly.net", "akamai.net", "akamaiedge.net",
    "googlevideo.com", "gstatic.com", "google.com",
    "ubuntu.com", "debian.org", "centos.org",
    "fedoraproject.org", "alpinelinux.org",
    "npmjs.com", "yarnpkg.com", "rubygems.org",
    "crates.io", "nuget.org", "packagist.org",
    "localhost", "local", "internal",
}

# Risk score weights per detector
RISK_WEIGHTS = {
    "threat_intel_match": 80,
    "dga_detection": 40,
    "beaconing_detection": 30,
    "unusual_port": 15,
    "dns_tunnel": 35,
}

# DGA entropy threshold (bits)
DGA_ENTROPY_THRESHOLD = 3.9
DGA_LABEL_LENGTH_THRESHOLD = 24
DGA_SUBDOMAIN_DEPTH_THRESHOLD = 4


# ============================================================================
# Data structures
# ============================================================================

@dataclass
class DNSQuery:
    """A DNS query observed in the capture."""
    domain: str
    query_type: str  # A, AAAA, TXT, CNAME, MX, etc.
    timestamp: float


@dataclass
class TCPConnection:
    """A TCP SYN packet observed in the capture."""
    dst_ip: str
    dst_port: int
    timestamp: float


@dataclass
class UDPPacket:
    """A UDP packet observed in the capture."""
    dst_ip: str
    dst_port: int
    payload_size: int
    timestamp: float


@dataclass
class HTTPRequest:
    """An HTTP request observed in unencrypted traffic."""
    method: str
    host: str
    path: str
    timestamp: float


@dataclass
class NetworkProfile:
    """Complete network profile from the capture."""
    dns_queries: List[DNSQuery] = field(default_factory=list)
    tcp_connections: List[TCPConnection] = field(default_factory=list)
    udp_packets: List[UDPPacket] = field(default_factory=list)
    http_requests: List[HTTPRequest] = field(default_factory=list)


@dataclass
class NetworkFinding:
    """A finding from one of the five network detectors."""
    detector: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    target: str  # IP or domain
    description: str
    evidence: str


@dataclass
class NetworkAnalysisResult:
    """Aggregate result of network behavior analysis."""
    network_profile: NetworkProfile = field(default_factory=NetworkProfile)
    findings: List[NetworkFinding] = field(default_factory=list)
    capture_duration_seconds: float = 0.0
    packets_captured: int = 0
    overall_risk: str = "SAFE"
    risk_score: int = 0

    def _compute_risk(self) -> None:
        """Recompute risk score from findings."""
        score = 0
        detectors_triggered = set()
        for f in self.findings:
            if f.detector not in detectors_triggered:
                score += RISK_WEIGHTS.get(f.detector, 10)
                detectors_triggered.add(f.detector)
        self.risk_score = min(score, 100)
        if self.risk_score > 80:
            self.overall_risk = "CRITICAL"
        elif self.risk_score > 50:
            self.overall_risk = "HIGH"
        elif self.risk_score > 20:
            self.overall_risk = "MEDIUM"
        elif self.risk_score > 0:
            self.overall_risk = "LOW"
        else:
            self.overall_risk = "SAFE"


# ============================================================================
# Capture phase
# ============================================================================

def _start_container(image_name: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Start a container in the background and return (container_id, container_ip).

    Returns (None, None) on failure.
    """
    container_name = f"autopatch_netmon_{uuid.uuid4().hex[:12]}"

    code, output = run_cmd(
        ["docker", "run", "-d", "--name", container_name,
         "--network=bridge", image_name],
        timeout=60,
    )
    if code != 0:
        logger.warning(f"Failed to start container: {output}")
        return None, None

    container_id = output.strip()

    # Get container IP
    code, ip_output = run_cmd(
        ["docker", "inspect", "--format",
         "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
         container_name],
        timeout=15,
    )
    if code != 0 or not ip_output.strip():
        logger.warning(f"Failed to get container IP: {ip_output}")
        run_cmd(["docker", "rm", "-f", container_name], timeout=15)
        return None, None

    container_ip = ip_output.strip()
    logger.info(f"Container {container_name} started with IP {container_ip}")
    return container_name, container_ip


def _get_exposed_ports(image_name: str, container_name: str) -> List[int]:
    """Get exposed ports from image/container inspect."""
    ports: Set[int] = set()

    # From image config
    code, output = run_cmd(
        ["docker", "inspect", "--format",
         "{{json .Config.ExposedPorts}}", container_name],
        timeout=15,
    )
    if code == 0 and output.strip() and output.strip() != "null":
        try:
            exposed = json.loads(output.strip())
            if isinstance(exposed, dict):
                for port_spec in exposed.keys():
                    # Format: "8080/tcp"
                    port_num = port_spec.split("/")[0]
                    try:
                        ports.add(int(port_num))
                    except ValueError:
                        pass
        except json.JSONDecodeError:
            pass

    return sorted(ports)


def _start_tcpdump(
    container_ip: str,
    pcap_path: str,
    interface: str = "docker0",
) -> Optional[subprocess.Popen]:
    """Start tcpdump capturing traffic for the container IP."""
    if not shutil.which("tcpdump"):
        logger.warning("tcpdump not installed, network capture unavailable")
        return None

    try:
        proc = subprocess.Popen(
            ["tcpdump", "-i", interface, f"host {container_ip}",
             "-w", pcap_path, "-c", "10000"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        # Give tcpdump a moment to start
        time.sleep(1)
        if proc.poll() is not None:
            stderr = proc.stderr.read().decode("utf-8", errors="ignore") if proc.stderr else ""
            logger.warning(f"tcpdump exited immediately: {stderr}")
            # Try with 'any' interface as fallback
            proc = subprocess.Popen(
                ["tcpdump", "-i", "any", f"host {container_ip}",
                 "-w", pcap_path, "-c", "10000"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            time.sleep(1)
            if proc.poll() is not None:
                return None

        return proc
    except (OSError, subprocess.SubprocessError) as e:
        logger.warning(f"Failed to start tcpdump: {e}")
        return None


def _exercise_container(
    container_name: str,
    container_ip: str,
    exposed_ports: List[int],
    test_cmd: Optional[str],
) -> None:
    """Exercise the container to trigger dormant payloads."""
    import urllib.request
    import urllib.error

    test_paths = ["/", "/health", "/api", "/index.html", "/login"]

    for port in exposed_ports:
        for path in test_paths:
            url = f"http://{container_ip}:{port}{path}"
            try:
                req = urllib.request.Request(url, method="GET")
                urllib.request.urlopen(req, timeout=5)
            except (urllib.error.URLError, OSError, Exception):
                pass
            time.sleep(0.2)

        # POST with empty JSON body
        try:
            req = urllib.request.Request(
                f"http://{container_ip}:{port}/",
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=5)
        except (urllib.error.URLError, OSError, Exception):
            pass

    # Run custom test command if provided
    if test_cmd:
        logger.info(f"Running custom test command: {test_cmd}")
        run_cmd(
            ["docker", "exec", container_name, "sh", "-c", test_cmd],
            timeout=30,
        )


# ============================================================================
# Parse phase -- pcap parsing with dpkt
# ============================================================================

def _parse_pcap(pcap_path: str) -> Tuple[NetworkProfile, int]:
    """
    Parse a pcap file and extract DNS queries, TCP connections, UDP packets,
    and HTTP requests.

    Returns (NetworkProfile, packet_count).
    """
    profile = NetworkProfile()
    packet_count = 0

    try:
        import dpkt
    except ImportError:
        logger.warning(
            "dpkt not installed, pcap parsing unavailable. "
            "Install with: pip install dpkt==1.9.8"
        )
        return profile, 0

    if not os.path.exists(pcap_path) or os.path.getsize(pcap_path) == 0:
        return profile, 0

    try:
        with open(pcap_path, "rb") as f:
            pcap_reader = dpkt.pcap.Reader(f)
            for timestamp, buf in pcap_reader:
                packet_count += 1
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                except dpkt.dpkt.UnpackError:
                    # Try as raw IP (some captures on 'any' interface)
                    try:
                        ip = dpkt.ip.IP(buf)
                    except dpkt.dpkt.UnpackError:
                        continue
                    _process_ip_packet(ip, timestamp, profile)
                    continue

                if not isinstance(eth.data, dpkt.ip.IP):
                    continue

                ip = eth.data
                _process_ip_packet(ip, timestamp, profile)

    except Exception as e:
        logger.warning(f"Failed to parse pcap: {e}")

    return profile, packet_count


def _process_ip_packet(ip, timestamp: float, profile: NetworkProfile) -> None:
    """Process a single IP packet and extract relevant data."""
    import dpkt

    dst_ip = _inet_to_str(ip.dst)
    src_ip = _inet_to_str(ip.src)

    if isinstance(ip.data, dpkt.tcp.TCP):
        tcp = ip.data
        # SYN packets (connection initiation)
        if tcp.flags & dpkt.tcp.TH_SYN and not (tcp.flags & dpkt.tcp.TH_ACK):
            profile.tcp_connections.append(TCPConnection(
                dst_ip=dst_ip,
                dst_port=tcp.dport,
                timestamp=timestamp,
            ))

        # Check for HTTP in TCP payload
        if tcp.data and tcp.dport in (80, 8080, 8000, 3000):
            _try_parse_http(tcp.data, timestamp, dst_ip, profile)

    elif isinstance(ip.data, dpkt.udp.UDP):
        udp = ip.data
        profile.udp_packets.append(UDPPacket(
            dst_ip=dst_ip,
            dst_port=udp.dport,
            payload_size=len(udp.data),
            timestamp=timestamp,
        ))

        # Check for DNS
        if udp.dport == 53 or udp.sport == 53:
            _try_parse_dns(udp.data, timestamp, profile)


def _try_parse_http(data: bytes, timestamp: float, host: str, profile: NetworkProfile) -> None:
    """Try to parse HTTP from TCP payload."""
    try:
        import dpkt
        request = dpkt.http.Request(data)
        profile.http_requests.append(HTTPRequest(
            method=request.method,
            host=request.headers.get("host", host),
            path=request.uri,
            timestamp=timestamp,
        ))
    except Exception:
        pass


def _try_parse_dns(data: bytes, timestamp: float, profile: NetworkProfile) -> None:
    """Try to parse DNS from UDP payload."""
    try:
        import dpkt
        dns = dpkt.dns.DNS(data)
        if dns.qr == dpkt.dns.DNS_Q:  # Query
            for q in dns.qd:
                qtype_map = {
                    dpkt.dns.DNS_A: "A",
                    dpkt.dns.DNS_AAAA: "AAAA",
                    dpkt.dns.DNS_CNAME: "CNAME",
                    dpkt.dns.DNS_MX: "MX",
                    dpkt.dns.DNS_TXT: "TXT",
                    dpkt.dns.DNS_NS: "NS",
                    dpkt.dns.DNS_PTR: "PTR",
                    dpkt.dns.DNS_SOA: "SOA",
                    dpkt.dns.DNS_SRV: "SRV",
                }
                qtype = qtype_map.get(q.type, f"TYPE{q.type}")
                profile.dns_queries.append(DNSQuery(
                    domain=q.name,
                    query_type=qtype,
                    timestamp=timestamp,
                ))
    except Exception:
        pass


def _inet_to_str(addr: bytes) -> str:
    """Convert a packed IP address to string."""
    import socket
    try:
        if len(addr) == 4:
            return socket.inet_ntop(socket.AF_INET, addr)
        elif len(addr) == 16:
            return socket.inet_ntop(socket.AF_INET6, addr)
    except Exception:
        pass
    return ""


# ============================================================================
# Analysis phase -- 5 detectors
# ============================================================================

def _detect_threat_intel(
    profile: NetworkProfile,
    threat_intel_dir: str,
    result: NetworkAnalysisResult,
) -> None:
    """Detector 1: Match contacted domains/IPs against threat intel feeds."""
    try:
        from .threat_intel import load_feeds, check_ioc
    except ImportError:
        logger.warning("threat_intel module not available, skipping threat intel check")
        return

    db = load_feeds(threat_intel_dir)
    if db.is_empty:
        logger.info("Threat intel DB is empty, skipping matching")
        return

    # Check DNS query domains
    checked = set()
    for query in profile.dns_queries:
        domain = query.domain.lower()
        if domain in checked:
            continue
        checked.add(domain)

        match = check_ioc(db, domain)
        if match:
            result.findings.append(NetworkFinding(
                detector="threat_intel_match",
                severity="CRITICAL",
                target=domain,
                description=(
                    f"DNS query to known malicious domain '{domain}' "
                    f"(malware family: {match.malware_family}, "
                    f"source: {match.source})"
                ),
                evidence=f"Feed: {match.source}, type: {match.threat_type}, ref: {match.reference}",
            ))

    # Check destination IPs
    for conn in profile.tcp_connections:
        if conn.dst_ip in checked:
            continue
        checked.add(conn.dst_ip)

        match = check_ioc(db, conn.dst_ip)
        if match:
            result.findings.append(NetworkFinding(
                detector="threat_intel_match",
                severity="CRITICAL",
                target=conn.dst_ip,
                description=(
                    f"Connection to known malicious IP {conn.dst_ip}:{conn.dst_port} "
                    f"(malware family: {match.malware_family})"
                ),
                evidence=f"Feed: {match.source}, type: {match.threat_type}",
            ))


def _detect_dga(
    profile: NetworkProfile,
    domain_allowlist: Set[str],
    result: NetworkAnalysisResult,
) -> None:
    """
    Detector 2: DGA detection via Shannon entropy of DNS query domains.

    Flags domains with high entropy in the second-level domain, excessively
    long labels, or deep subdomain nesting.
    """
    checked = set()

    for query in profile.dns_queries:
        domain = query.domain.lower().rstrip(".")
        if domain in checked:
            continue
        checked.add(domain)

        # Skip allowlisted domains
        if _is_allowlisted(domain, domain_allowlist):
            continue

        parts = domain.split(".")
        if len(parts) < 2:
            continue

        # Extract second-level domain (SLD)
        sld = parts[-2] if len(parts) >= 2 else parts[0]

        reasons = []

        # Shannon entropy check
        entropy = _shannon_entropy(sld)
        if entropy > DGA_ENTROPY_THRESHOLD:
            reasons.append(f"high entropy ({entropy:.2f} bits, threshold {DGA_ENTROPY_THRESHOLD})")

        # Label length check
        if len(sld) > DGA_LABEL_LENGTH_THRESHOLD:
            reasons.append(f"long SLD ({len(sld)} chars, threshold {DGA_LABEL_LENGTH_THRESHOLD})")

        # Subdomain depth check
        subdomain_depth = len(parts) - 2  # Exclude SLD and TLD
        if subdomain_depth > DGA_SUBDOMAIN_DEPTH_THRESHOLD:
            reasons.append(f"deep nesting ({subdomain_depth} levels)")

        if reasons:
            result.findings.append(NetworkFinding(
                detector="dga_detection",
                severity="HIGH",
                target=domain,
                description=f"Possible DGA domain: {domain} ({', '.join(reasons)})",
                evidence=f"Query type: {query.query_type}, SLD entropy: {entropy:.2f}",
            ))


def _detect_beaconing(
    profile: NetworkProfile,
    result: NetworkAnalysisResult,
) -> None:
    """
    Detector 3: Beaconing detection via inter-arrival time analysis.

    Groups connections by destination IP:port and flags targets where 3+
    connections have a coefficient of variation < 0.3 (periodic pattern).
    """
    # Group by destination
    groups: Dict[str, List[float]] = defaultdict(list)
    for conn in profile.tcp_connections:
        key = f"{conn.dst_ip}:{conn.dst_port}"
        groups[key].append(conn.timestamp)

    for target, timestamps in groups.items():
        if len(timestamps) < 3:
            continue

        timestamps.sort()
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]

        if not intervals:
            continue

        mean_interval = sum(intervals) / len(intervals)
        if mean_interval <= 0:
            continue

        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        cov = std_dev / mean_interval

        if cov < 0.3:
            result.findings.append(NetworkFinding(
                detector="beaconing_detection",
                severity="HIGH",
                target=target,
                description=(
                    f"Periodic beaconing detected to {target}: "
                    f"{len(timestamps)} connections with CoV={cov:.3f} "
                    f"(mean interval: {mean_interval:.1f}s)"
                ),
                evidence=f"Intervals: {[round(i, 2) for i in intervals[:10]]}",
            ))


def _detect_unusual_ports(
    profile: NetworkProfile,
    allowed_ports: List[int],
    result: NetworkAnalysisResult,
) -> None:
    """Detector 4: Flag outbound connections to non-standard ports."""
    allowed_set = set(allowed_ports)
    flagged: Dict[str, Set[int]] = defaultdict(set)

    for conn in profile.tcp_connections:
        if conn.dst_port not in allowed_set:
            flagged[conn.dst_ip].add(conn.dst_port)

    for udp in profile.udp_packets:
        if udp.dst_port not in allowed_set and udp.dst_port != 53:
            flagged[udp.dst_ip].add(udp.dst_port)

    for ip, ports in flagged.items():
        result.findings.append(NetworkFinding(
            detector="unusual_port",
            severity="MEDIUM",
            target=ip,
            description=f"Outbound connection to {ip} on unusual port(s): {sorted(ports)}",
            evidence=f"Ports not in allowlist: {sorted(ports)}",
        ))


def _detect_dns_tunneling(
    profile: NetworkProfile,
    result: NetworkAnalysisResult,
) -> None:
    """
    Detector 5: DNS tunneling detection.

    Flags: TXT record queries, DNS payloads > 512 bytes, or > 10 queries
    to the same domain within the capture window.
    """
    # TXT queries
    txt_domains: Set[str] = set()
    for query in profile.dns_queries:
        if query.query_type == "TXT":
            txt_domains.add(query.domain)

    if txt_domains:
        result.findings.append(NetworkFinding(
            detector="dns_tunnel",
            severity="MEDIUM",
            target=", ".join(sorted(txt_domains)[:5]),
            description=f"DNS TXT record queries detected for {len(txt_domains)} domain(s)",
            evidence=f"Domains: {sorted(txt_domains)[:10]}",
        ))

    # Large DNS payloads
    large_dns = [p for p in profile.udp_packets if p.dst_port == 53 and p.payload_size > 512]
    if large_dns:
        result.findings.append(NetworkFinding(
            detector="dns_tunnel",
            severity="MEDIUM",
            target="(DNS)",
            description=f"{len(large_dns)} DNS packets with payload > 512 bytes",
            evidence=f"Sizes: {[p.payload_size for p in large_dns[:10]]}",
        ))

    # High-frequency queries to same domain
    domain_counts: Counter = Counter()
    for query in profile.dns_queries:
        domain_counts[query.domain] += 1

    for domain, count in domain_counts.items():
        if count > 10:
            result.findings.append(NetworkFinding(
                detector="dns_tunnel",
                severity="MEDIUM",
                target=domain,
                description=f"{count} DNS queries to '{domain}' in capture window",
                evidence=f"Query count: {count}",
            ))


# ============================================================================
# Utility functions
# ============================================================================

def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy (bits) of a string."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _is_allowlisted(domain: str, allowlist: Set[str]) -> bool:
    """Check if a domain or any of its parent domains is in the allowlist."""
    parts = domain.split(".")
    for i in range(len(parts)):
        candidate = ".".join(parts[i:])
        if candidate in allowlist:
            return True
    return False


# ============================================================================
# Main entry point
# ============================================================================

def analyze_network_behavior(
    image_name: str,
    dockerfile_path: str,
    output_dir: str,
    duration_seconds: int = 60,
    test_cmd: Optional[str] = None,
    threat_intel_dir: str = "~/.autopatch/threat_intel",
    allowed_ports: Optional[List[int]] = None,
    domain_allowlist: Optional[List[str]] = None,
) -> NetworkAnalysisResult:
    """
    Start a container, capture network traffic, and analyze for C2 indicators.

    Args:
        image_name: Docker image to analyze.
        dockerfile_path: Path to Dockerfile (for port detection).
        output_dir: Directory for capture artifacts.
        duration_seconds: How long to capture traffic (default 60s).
        test_cmd: Optional command to run inside the container.
        threat_intel_dir: Directory for cached threat intel feeds.
        allowed_ports: List of allowed outbound ports (default: common web/db ports).
        domain_allowlist: Additional domains to exclude from DGA detection.

    Returns:
        NetworkAnalysisResult with findings and risk assessment.
    """
    result = NetworkAnalysisResult()

    if allowed_ports is None:
        allowed_ports = list(DEFAULT_ALLOWED_PORTS)

    merged_allowlist = set(DEFAULT_DOMAIN_ALLOWLIST)
    if domain_allowlist:
        merged_allowlist.update(d.lower() for d in domain_allowlist)

    threat_intel_dir = os.path.expanduser(threat_intel_dir)
    os.makedirs(output_dir, exist_ok=True)
    pcap_path = os.path.join(output_dir, "network_capture.pcap")

    container_name = None
    tcpdump_proc = None
    start_time = time.time()

    try:
        # Start container
        logger.info(f"Starting container for network analysis: {image_name}")
        container_name, container_ip = _start_container(image_name)
        if not container_name or not container_ip:
            logger.error("Failed to start container for network monitoring")
            result.capture_duration_seconds = time.time() - start_time
            return result

        # Get exposed ports
        exposed_ports = _get_exposed_ports(image_name, container_name)
        if not exposed_ports:
            exposed_ports = [80, 8080, 3000]  # Sensible defaults
        logger.info(f"Exposed ports: {exposed_ports}")

        # Start tcpdump
        logger.info(f"Starting network capture for {duration_seconds}s")
        tcpdump_proc = _start_tcpdump(container_ip, pcap_path)
        if not tcpdump_proc:
            logger.warning("tcpdump unavailable, performing exercise-only analysis")

        # Exercise the container
        logger.info("Exercising container to trigger payloads...")
        _exercise_container(container_name, container_ip, exposed_ports, test_cmd)

        # Wait for remaining capture duration
        elapsed = time.time() - start_time
        remaining = duration_seconds - elapsed
        if remaining > 10:
            # Wait 10 seconds after last stimulus, then remaining time
            logger.info(f"Waiting {remaining:.0f}s for delayed callbacks...")
            time.sleep(min(remaining, 300))  # Cap at 5 minutes
        else:
            time.sleep(10)  # Minimum 10s wait after exercise

    except Exception as e:
        logger.error(f"Network capture failed: {e}")
    finally:
        # Stop tcpdump
        if tcpdump_proc and tcpdump_proc.poll() is None:
            try:
                tcpdump_proc.terminate()
                tcpdump_proc.wait(timeout=10)
            except (subprocess.TimeoutExpired, OSError):
                try:
                    tcpdump_proc.kill()
                except OSError:
                    pass

        # Stop and remove container
        if container_name:
            run_cmd(["docker", "rm", "-f", container_name], timeout=15)

    result.capture_duration_seconds = round(time.time() - start_time, 2)

    # Parse pcap
    logger.info("Parsing network capture...")
    profile, packet_count = _parse_pcap(pcap_path)
    result.network_profile = profile
    result.packets_captured = packet_count

    logger.info(
        f"Captured {packet_count} packets: "
        f"{len(profile.dns_queries)} DNS queries, "
        f"{len(profile.tcp_connections)} TCP connections, "
        f"{len(profile.udp_packets)} UDP packets, "
        f"{len(profile.http_requests)} HTTP requests"
    )

    # Run detectors
    logger.info("Running network behavior detectors...")

    # Detector 1: Threat intel matching
    _detect_threat_intel(profile, threat_intel_dir, result)

    # Detector 2: DGA detection
    _detect_dga(profile, merged_allowlist, result)

    # Detector 3: Beaconing detection
    _detect_beaconing(profile, result)

    # Detector 4: Unusual port detection
    _detect_unusual_ports(profile, allowed_ports, result)

    # Detector 5: DNS tunneling detection
    _detect_dns_tunneling(profile, result)

    # Compute risk score
    result._compute_risk()

    logger.info(
        f"Network analysis complete: {len(result.findings)} findings, "
        f"risk_score={result.risk_score}, overall={result.overall_risk}"
    )

    # Save results
    results_path = os.path.join(output_dir, "network-analysis.json")
    try:
        with open(results_path, "w") as f:
            json.dump(_result_to_dict(result), f, indent=2)
        logger.info(f"Network analysis saved to {results_path}")
    except Exception as e:
        logger.warning(f"Failed to save network analysis: {e}")

    return result


def _result_to_dict(result: NetworkAnalysisResult) -> dict:
    """Convert NetworkAnalysisResult to JSON-serializable dict."""
    return {
        "overall_risk": result.overall_risk,
        "risk_score": result.risk_score,
        "capture_duration_seconds": result.capture_duration_seconds,
        "packets_captured": result.packets_captured,
        "profile_summary": {
            "dns_queries": len(result.network_profile.dns_queries),
            "tcp_connections": len(result.network_profile.tcp_connections),
            "udp_packets": len(result.network_profile.udp_packets),
            "http_requests": len(result.network_profile.http_requests),
        },
        "findings": [
            {
                "detector": f.detector,
                "severity": f.severity,
                "target": f.target,
                "description": f.description,
                "evidence": f.evidence,
            }
            for f in result.findings
        ],
    }
