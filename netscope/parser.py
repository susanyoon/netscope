from scapy.all import rdpcap, IP


def parse_pcap(file_path):
    """
    Parse a PCAP file & extract metadata from IP packets.

    Args:
        file_path (str): Path to the PCAP file.

    Returns:
        list[dict]: List of packet metadata dictionaries.
    """

    packets = rdpcap(file_path)

    results = []

    for packet in packets:
        if IP in packet:
            protocol = packet[IP].payload.name

            results.append(
                {
                    "src_ip": packet[IP].src,
                    "dst_ip": packet[IP].dst,
                    "protocol": protocol,
                    "size": len(packet),
                }
            )
    return results