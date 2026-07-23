from collections import Counter

from netscope.models import PacketInfo


def protocol_distribution(packets: list[PacketInfo]) -> dict[str, int]:
    """
    Count packets per protocol.
    """
    return dict(Counter(p.protocol for p in packets))

def top_talkers(packets: list[PacketInfo], n: int=5) -> list[tuple[str, int]]:
    """
    Top source IPs by total bytes sent.

    Returns:
        List of (ip, total_bytes), highest first.
    """
    byte_counts: Counter = Counter()
    for p in packets:
        byte_counts[p.src_ip] += p.size
    return byte_counts.most_common(n)

def top_ports(packets: list[PacketInfo], n: int=5) -> list[tuple[int, int]]:
    """
    Most common destination ports.

    Returns:
        List of (port, packet_count), highest first.
    """
    port_counts = Counter(
        p.dst_port for p in packets if p.dst_port is not None
    )
    return port_counts.most_common(n)

def traffic_over_time(packets: list[PacketInfo], bucket_seconds: float=1.0) -> dict[float, int]:
    """
    Total bytes per time bucket.

    Args:
        packets: Parsed packets.
        bucket_seconds: Width of each time bucket in seconds.
    
    Returns:
        Dict mapping bucket start time -> total bytes in that bucket.
    """
    if not packets:
        return {}
    
    start = min(p.timestamp for p in packets)
    buckets: dict[float, int] = {}

    for p in packets:
        bucket = start + ((p.timestamp - start) // bucket_seconds)*bucket_seconds
        buckets[bucket] = buckets.get(bucket, 0) + p.size
    
    return dict(sorted(buckets.items()))
    