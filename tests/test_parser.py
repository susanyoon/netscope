from netscope.models import PacketInfo
from netscope.parser import parse_pcap


def test_parse_pcap_returns_all_ip_packets():
    packets = parse_pcap("tests/sample.pcap")
    assert len(packets) == 3


def test_returns_packet_info_objects():
    packets = parse_pcap("tests/sample.pcap")
    for pkt in packets:
        assert isinstance(pkt, PacketInfo)


def test_known_values():
    packets = parse_pcap("tests/sample.pcap")
    assert packets[0].src_ip == "192.168.1.10"
    assert packets[0].protocol == "TCP"
    assert packets[1].protocol == "UDP"


def test_sizes_are_positive_integers():
    packets = parse_pcap("tests/sample.pcap")
    for pkt in packets:
        assert isinstance(pkt.size, int)
        assert pkt.size > 0
