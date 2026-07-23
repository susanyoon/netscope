from scapy.all import IP, TCP, UDP, rdpcap

from netscope.models import PacketInfo


def parse_pcap(file_path: str) -> list[PacketInfo]:
    """
    Parse a PCAP file & extract metadata from IP packets.

    Args:
        file_path (str): Path to the PCAP file.

    Returns:
        A list of PacketInfo objects, 1 per IP packet.
    """

    packets = rdpcap(file_path)

    results = []

    for packet in packets:
        if IP not in packet:
            continue

        src_port = None
        dst_port = None

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        results.append(
            PacketInfo(
                timestamp=float(packet.time),
                src_ip=packet[IP].src,
                dst_ip=packet[IP].dst,
                src_port=src_port,
                dst_port=dst_port,
                protocol=packet[IP].payload.name,
                size=len(packet),
            )
        )
    return results