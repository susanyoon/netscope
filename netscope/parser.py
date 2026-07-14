from scapy.all import rdpcap, IP

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
        if IP in packet:
            results.append(
                PacketInfo(
                    src_ip=packet[IP].src,
                    dst_ip=packet[IP].dst,
                    protocol=packet[IP].payload.name,
                    size=len(packet),
                )
            )
    return results