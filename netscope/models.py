from dataclasses import dataclass


@dataclass
class PacketInfo:
    """
    Metadata extracted from a single IP packet.
    """

    src_ip: str
    dst_ip: str
    protocol: str
    size: int