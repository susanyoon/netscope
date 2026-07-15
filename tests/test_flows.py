from netscope.flows import aggregate_flows
from netscope.models import PacketInfo


def make_packet(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000, dst_port=80, protocol="TCP", size=100, timestamp=1.0):
    return PacketInfo(
        timestamp=timestamp, src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port, protocol=protocol, size=size,
    )


def test_single_packet_creates_one_flow():
    flows = aggregate_flows([make_packet()])
    assert len(flows) == 1
    assert flows[0].packet_count == 1
    assert flows[0].total_bytes == 100

def test_same_tuple_packets_merge_into_one_flow():
    packets = [
        make_packet(size=100, timestamp=1.0),
        make_packet(size=200, timestamp=2.0),
        make_packet(size=300, timestamp=3.0),
    ]
    flows = aggregate_flows(packets)
    assert len(flows) == 1
    assert flows[0].packet_count == 3
    assert flows[0].total_bytes == 600
    assert flows[0].duration == 2.0


def test_different_tuples_create_separate_flows():
    packets = [
        make_packet(dst_port=80),
        make_packet(dst_port=443),
    ]
    flows = aggregate_flows(packets)
    assert len(flows) == 2


def test_out_of_order_timestamps():
    packets = [
        make_packet(timestamp=5.0),
        make_packet(timestamp=1.0),
    ]
    flows = aggregate_flows(packets)
    assert flows[0].start_time == 1.0
    assert flows[0].end_time == 5.0


def test_empty_input_returns_empty_list():
    assert aggregate_flows([]) == []