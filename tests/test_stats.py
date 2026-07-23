from netscope.models import PacketInfo
from netscope.stats import (
    protocol_distribution,
    top_ports,
    top_talkers,
    traffic_over_time,
)


def make_packet(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000, dst_port=80, protocol="TCP", size=100, timestamp=1.0):
    return PacketInfo(
        timestamp=timestamp, src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port, protocol=protocol, size=size,
    )

def test_protocol_distribution():
    packets = [
        make_packet(protocol="TCP"),
        make_packet(protocol="TCP"),
        make_packet(protocol="UDP"),
    ]
    assert protocol_distribution(packets) == {"TCP": 2, "UDP": 1}

def test_top_talkers_sorted_by_bytes():
    packets = [
        make_packet(src_ip="10.0.0.1", size=100),
        make_packet(src_ip="10.0.0.2", size=500),
        make_packet(src_ip="10.0.0.1", size=100),
    ]
    result = top_talkers(packets)
    assert result[0] == ("10.0.0.2", 500)
    assert result[1] == ("10.0.0.1", 200)

def test_top_talkers_respects_n():
    packets = [make_packet(src_ip=f"10.0.0.{i}") for i in range(10)]
    assert len(top_talkers(packets, n=3)) == 3

def test_top_ports_ignores_none():
    packets = [
        make_packet(dst_port=80),
        make_packet(dst_port=80),
        make_packet(dst_port=443),
        make_packet(dst_port=None, protocol="ICMP"),
    ]
    result = top_ports(packets)
    assert result[0] == (80, 2)
    assert (None, 1) not in result

def test_traffic_over_time_buckets():
    packets = [
        make_packet(timestamp=0.0, size=100),
        make_packet(timestamp=0.5, size=100),
        make_packet(timestamp=2.1, size=300),
    ]
    result = traffic_over_time(packets, bucket_seconds=1.0)
    assert result[0.0] == 200      # both early packets in 1st bucket
    assert result[2.0] == 300      # late packet 2 buckets later

def test_traffic_over_time_empty():
    assert traffic_over_time([]) == {}