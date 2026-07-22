from collections import defaultdict

from netscope.models import PacketInfo


def detect_port_scans(
    packets: list[PacketInfo], port_threshold: int = 10) -> list[dict]:
    """
    Flag source IPs that contact many distinct destination ports.
    
    Args:
        packets: Parsed packets.
        port_threshold: Minimum distinct ports to be considered a scan.
    Returns:
        List of findings, one per suspicious source IP.
    """
    ports_by_src: dict[str, set[int]] = defaultdict(set)
    for p in packets:
        if p.dst_port is not None:
            ports_by_src[p.src_ip].add(p.dst_port)
    
    findings = []
    for src_ip, ports in ports_by_src.items():
        if len(ports) >= port_threshold:
            findings.append({
                "type": "port_scan",
                "src_ip": src_ip,
                "distinct_ports": len(ports),
            })
    return sorted(findings, key=lambda f: -f["distinct_ports"])

def detect_traffic_spikes(packets: list[PacketInfo], multiplier: float=3.0) -> list[dict]:
    """
    Flag destination IPs receiving far more packets than average.

    A destination is flagged if its packet count exceeds the mean packet count
    per destination by the given multiplier.

    Returns:
        List of findings, 1 per suspicious destination IP.
    """
    counts: dict[str, int] = defaultdict(int)
    for p in packets:
        counts[p.dst_ip] += 1
    
    if not counts:
        return []
    
    mean = sum(counts.values()) / len(counts)
    threshold = mean * multiplier

    findings = []
    for dst_ip, count in counts.items():
        if count > threshold:
            findings.append({
                "type": "traffic_spike",
                "dst_ip": dst_ip,
                "packet_count": count,
                "threshold": round(threshold, 1),
            })
    return sorted(findings, key=lambda f: -f["packet_count"])

def detect_all(packets: list[PacketInfo]) -> list[dict]:
    """
    Run all anomaly detectors & combine their findings.
    """
    return detect_port_scans(packets) + detect_traffic_spikes(packets)
    