from netscope.anomalies import detect_port_scans, detect_traffic_spikes
from netscope.models import PacketInfo


def make_packet(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000, dst_port=80, protocol="TCP", size=100, timestamp=1.0):
    return PacketInfo(timestamp=timestamp, src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port, protocol=protocol, size=size,)

def test_port_scan_detected():
    # 1 source hitting 15 different ports
    packets = [make_packet(src_ip="10.0.0.99", dst_port=p) for p in range(15)]
    findings = detect_port_scans(packets, port_threshold=10)
    assert len(findings) == 1
    assert findings[0]["src_ip"] == "10.0.0.99"
    assert findings[0]["distinct_ports"] == 15

def test_no_port_scan_below_threshold():
    packets = [make_packet(src_ip="10.0.0.1", dst_port=p) for p in range(5)]
    assert detect_port_scans(packets, port_threshold=10) == []

def test_port_scan_ignores_none_ports():
    packets = [make_packet(src_ip="10.0.0.1", dst_port=None, protocol="ICMP") for _ in range(20)]
    assert detect_port_scans(packets, port_threshold=10) == []

def test_traffic_spike_detected():
    # 1 dst gets 100 packets, 3 others get 1 each
    packets = [make_packet(dst_ip="10.0.0.5") for _ in range(100)]
    packets += [make_packet(dst_ip=f"10.0.0.{i}") for i in range(1, 4)]
    findings = detect_traffic_spikes(packets, multiplier=3.0)
    assert any(f["dst_ip"] == "10.0.0.5" for f in findings)

def test_no_spike_when_uniform():
    # every dst gets the same amount, nothing stands out
    packets = [make_packet(dst_ip=f"10.0.0.{i}") for i in range(10)]
    assert detect_traffic_spikes(packets, multiplier=3.0) == []

def test_empty_input():
    assert detect_port_scans([]) == []
    assert detect_traffic_spikes([]) == []