from netscope.models import Flow, PacketInfo


def aggregate_flows(packets: list[PacketInfo]) -> list[Flow]:
    """
    Group packets into flows by their 5-tuple.
    Args:
        packets: Parsed packets from parse_pcap.
    Returns:
        A list of Flow objects, 1 per unique 5-tuple.
    """
    flows: dict[tuple, Flow] = {}

    for pkt in packets:
        key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)

        if key not in flows:
            flows[key] = Flow(
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                src_port=pkt.src_port,
                dst_port=pkt.dst_port,
                protocol=pkt.protocol,
                packet_count=1,
                total_bytes=pkt.size,
                start_time=pkt.timestamp,
                end_time=pkt.timestamp,
            )
        else:
            flow = flows[key]
            flow.packet_count += 1
            flow.total_bytes += pkt.size
            flow.start_time = min(flow.start_time, pkt.timestamp)
            flow.end_time = max(flow.end_time, pkt.timestamp)
    
    return list(flows.values())