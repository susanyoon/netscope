import matplotlib

matplotlib.use("Agg")    # render w/o a display window
import matplotlib.pyplot as plt

from netscope.models import PacketInfo
from netscope.stats import protocol_distribution, top_talkers, traffic_over_time

def chart_protocol_distribution(packets: list[PacketInfo], output_path: str) -> None:
    """
    Save a bar chart of packets per protocol.
    """
    dist = protocol_distribution(packets)
    protocols = list(dist.keys())
    counts = list(dist.values())

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar(protocols, counts)
    ax.set_title("Protocol Distribution")
    ax.set_xlabel("Protocol")
    ax.set_ylabel("Packets")
    fig.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)


def chart_top_talkers(packets: list[PacketInfo], output_path: str, n: int=5) -> None:
    """
    Save a horizontal bar chart of top source IPs by bytes.
    """
    talkers = top_talkers(packets, n=n)
    ips = [ip for ip, _ in talkers][::-1]    # reversed = biggest on top
    byte_counts = [b for _, b in talkers][::-1]

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.barh(ips, byte_counts)
    ax.set_title(f"Top {len(ips)} Talkers by Bytes Sent")
    ax.set_xlabel("Bytes")
    fig.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)


def chart_traffic_over_time(packets: list[PacketInfo], output_path: str, bucket_seconds: float=1.0) -> None:
    """
    Save a line chart of traffic volume over time.
    """
    buckets = traffic_over_time(packets, bucket_seconds=bucket_seconds)
    if not buckets:
        raise ValueError("No packets to chart.")
    
    start = min(buckets.keys())
    times = [t - start for t in buckets.keys()]  # seconds since capture start
    volumes = list(buckets.values())

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.plot(times, volumes, marker="o")
    ax.set_title("Traffic Over Time")
    ax.set_xlabel("Seconds since capture start")
    ax.set_ylabel("Bytes per bucket")
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)
