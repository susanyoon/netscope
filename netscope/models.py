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

@dataclass
class Flow:
    """
    A network conversation: packets sharing the same 5-tuple.
    """

    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    packet_count: int
    total_bytes: int
    start_time: float
    end_time: float

    @property
    def duration(self) -> float:
        """
        Duration of the flow in seconds.
        """
        return self.end_time - self.start_time
