from netscope.parser import parse_pcap


def test_parse_pscap_returns_list():
    packets = parse_pcap("tests/sample.pcap")
    assert len(packets) == 3


def test_packet_fields_present():
    packets = parse_pcap("tests/sample.pcap")
    for pkt in packets:
        assert set(pkt.keys()) == {"src_ip", "dst_ip", "protocol", "size"}


def test_known_values():
    packets = parse_pcap("tests/sample.pcap")
    assert packets[0]["src_ip"] == "192.168.1.10"
    assert packets[0]["protocol"] == "TCP"
    assert packets[1]["protocol"] == "UDP"


def test_sizes_are_positive_integers():
    packets = parse_pcap("tests/sample.pcap")
    for pkt in packets:
        assert isinstance(pkt["size"], int)
        assert pkt["size"] > 0