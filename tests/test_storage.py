from netscope.flows import aggregate_flows
from netscope.models import PacketInfo
from netscope.storage import Storage


def make_packet(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000, dst_port=80, protocol="TCP", size=100, timestamp=1.0):
    return PacketInfo(timestamp=timestamp, src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port, protocol=protocol, size=size,)

def make_storage(tmp_path):
    return Storage(str(tmp_path / "test.db"))

def test_save_returns_analysis_id(tmp_path):
    storage = make_storage(tmp_path)
    packets = [make_packet()]
    flows = aggregate_flows(packets)
    analysis_id = storage.save_analysis("capture.pcap", packets, flows)
    assert isinstance(analysis_id, int)
    storage.close()

def test_list_analyses(tmp_path):
    storage = make_storage(tmp_path)
    packets = [make_packet()]
    storage.save_analysis("first.pcap", packets, aggregate_flows(packets))
    storage.save_analysis("second.pcap", packets, aggregate_flows(packets))

    analyses = storage.list_analyses()
    assert len(analyses) == 2
    assert analyses[0]["packet_count"] == 1
    storage.close()

def test_flows_round_trip(tmp_path):
    """What we save is exactly what we get back."""
    storage = make_storage(tmp_path)
    packets = [
        make_packet(size=100, timestamp=1.0),
        make_packet(size=200, timestamp=3.0),
        make_packet(dst_port=443, size=50),
    ]
    flows = aggregate_flows(packets)
    analysis_id = storage.save_analysis("capture.pcap", packets, flows)

    loaded = storage.get_flows(analysis_id)
    assert sorted(loaded, key=lambda f: f.total_bytes) == \
           sorted(flows, key=lambda f: f.total_bytes)
    storage.close()
    
def test_packets_round_trip(tmp_path):
    storage = make_storage(tmp_path)
    packets = [make_packet(timestamp=1.0), make_packet(timestamp=2.0, size=300)]
    analysis_id = storage.save_analysis("capture.pcap", packets, aggregate_flows(packets))

    loaded = storage.get_packets(analysis_id)
    assert loaded == packets
    storage.close()

def test_analyses_are_isolated(tmp_path):
    """Flows from one analysis don't leak into another."""
    storage = make_storage(tmp_path)
    p1 = [make_packet(src_ip="10.0.0.1")]
    p2 = [make_packet(src_ip="99.0.0.1"), make_packet(src_ip="99.0.0.2", dst_port=443)]
    id1 = storage.save_analysis("one.pcap", p1, aggregate_flows(p1))
    id2 = storage.save_analysis("two.pcap", p2, aggregate_flows(p2))

    assert len(storage.get_flows(id1)) == 1 
    assert len(storage.get_flows(id2)) == 2
    storage.close()   