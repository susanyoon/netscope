from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from netscope.anomalies import detect_all
from netscope.charts import (
    chart_protocol_distribution,
    chart_top_talkers,
    chart_traffic_over_time,
)
from netscope.flows import aggregate_flows
from netscope.parser import parse_pcap
from netscope.stats import protocol_distribution, top_talkers
from netscope.storage import Storage

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

    protocols = protocol_distribution(packets)
    
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

    talkers = top_talkers(packets)
    talker_table = Table(title="Top Talkers")
    talker_table.add_column("Source IP")
    talker_table.add_column("Bytes", justify="right")
    for ip, byte_count in talkers:
        talker_table.add_row(ip, f"{byte_count:,}")
    console.print(talker_table)


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

@app.command()
def chart(pcap_file: str, output_dir: str="charts"):
    """
    Generate PNG charts from a PCAP file.
    """
    packets = parse_pcap(pcap_file)
    if not packets:
        console.print("[yellow]No IP packets found in this capture.[/yellow]")
        raise typer.Exist(code=1)
    
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    chart_protocol_distribution(packets, str(out / "protocols.png"))
    chart_top_talkers(packets, str(out / "top_talkers.png"))
    chart_traffic_over_time(packets, str(out / "traffic_over_time.png"))

    console.print(f"[green]Charts written to {out}/[/green]")

@app.command()
def analyze(pcap_file: str, db: str = "netscope.db"):
    """Parse a PCAP file & save the analysis to the database."""
    packets = parse_pcap(pcap_file)
    if not packets:
        console.print("[yellow]No IP packets found in this capture.[/yellow]")
        raise typer.Exit(code=1)
    
    flow_list = aggregate_flows(packets)
    storage = Storage(db)
    analysis_id = storage.save_analysis(pcap_file, packets, flow_list)
    storage.close()

    console.print(
        f"[green]Saved analysis #{analysis_id}[/green] "
        f"({len(packets)} packets, {len(flow_list)} flows) to {db}"
    )

@app.command()
def history(db: str = "netscope.db"):
    """List saved analyses."""
    storage = Storage(db)
    analyses = storage.list_analyses()
    storage.close()

    if not analyses:
        console.print("No saved analyses yet. Run [bold]netscope analyze[/bold] first.")
        raise typer.Exit()
    
    table = Table(title="Saved Analyses")
    table.add_column("ID", justify="right")
    table.add_column("File")
    table.add_column("Analyzed At")
    table.add_column("Packets", justify="right")
    table.add_column("Flows", justify="right")
    for a in analyses:
        table.add_row(str(a["id"]), a["pcap_file"], a["analyzed_at"][:19], str(a["packet_count"]), str(a["flow_count"]))
    console.print(table)

@app.command()
def anomalies(pcap_file: str):
    """
    Detect suspicious patterns in a PCAP file.
    """
    packets = parse_pcap(pcap_file)
    findings = detect_all(packets)

    if not findings:
        console.print("[green]No anomalies detected.[/green]")
        raise typer.Exit()
    
    table = Table(title="Anomalies")
    table.add_column("Type")
    table.add_column("Details")
    for f in findings:
        details = ", ".join(f"{k}={v}" for k, v in f.items() if k != "type")
        table.add_row(f["type"], details)
    console.print(table)


if __name__ == "__main__":
    app()