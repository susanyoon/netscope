import typer
from rich.console import Console
from rich.table import Table

from netscope.flows import aggregate_flows
from netscope.parser import parse_pcap

app = typer.Typer(help="NetScope: network traffic analyzer for PCAP files.")
console = Console()

@app.command()
def summary(pcap_file: str):
    """
    Show a high-level summary of a PCAP file
    """
    packets = parse_pcap(pcap_file)
    flows = aggregate_flows(packets)

    if not packets:
        console.print("[yellow]No IP packets found in this capture.[/yellow]")
        raise typer.Exit()
    
    total_bytes = sum(p.size for p in packets)
    duration = max(p.timestamp for p in packets) - min(p.timestamp for p in packets)

    protocols: dict[str, int] = {}
    for p in packets:
        protocols[p.protocol] = protocols.get(p.protocol, 0) + 1
    
    console.print(f"\n[bold]Summary for[/bold] {pcap_file}\n")
    console.print(f"  Packets:  {len(packets)}")
    console.print(f"  Flows:  {len(flows)}")
    console.print(f"  Bytes:  {total_bytes:,}")
    console.print(f"  Duration:  {duration:.2f}s")

    table = Table(title="Protocol Breakdown")
    table.add_column("Protocol")
    table.add_column("Packets", justify="right")
    for proto, count in sorted(protocols.items(), key=lambda x: -x[1]):
        table.add_row(proto, str(count))
    console.print(table)


@app.command()
def flows(pcap_file: str, sort_by: str="bytes"):
    """
    List flows in a PCAP file, sorted by bytes or packets.
    """
    packets = parse_pcap(pcap_file)
    flow_list = aggregate_flows(packets)

    if sort_by == "packets":
        flow_list.sort(key=lambda f: f.packet_count, reverse=True)
    else:
        flow_list.sort(key=lambda f: f.total_bytes, reverse=True)
    
    table = Table(title=f"Flows  ({len(flow_list)})")
    table.add_column("Source")
    table.add_column("Destination")
    table.add_column("Proto")
    table.add_column("Packets", justify="right")
    table.add_column("Bytes", justify="right")

    for f in flow_list:
        src = f"{f.src_ip}:{f.src_port}" if f.src_port else f.src_ip
        dst = f"{f.dst_ip}:{f.dst_port}" if f.dst_port else f.dst_ip
        table.add_row(src, dst, f.protocol, str(f.packet_count), f"{f.total_bytes:,}")
    
    console.print(table)


if __name__ == "__main__":
    app()