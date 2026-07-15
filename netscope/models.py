from dataclasses import dataclass


@dataclass
class PacketInfo:
    """
    Metadata extracted from a single IP packet.
    """

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    size: int