from netscope.charts import(
    chart_protocol_distribution,
    chart_top_talkers,
    chart_traffic_over_time,
)
from netscope.parser import parse_pcap


def test_charts_create_png_files(tmp_path):
    packets = parse_pcap("tests/sample.pcap")

    for func, name in [
        (chart_protocol_distribution, "protocols.png"),
        (chart_top_talkers, "talkers.png"),
        (chart_traffic_over_time, "traffic.png"),
    ]:
        out = tmp_path / name
        func(packets, str(out))
        assert out.exists()
        assert out.stat().st_size > 0