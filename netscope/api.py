import shutil
import tempfile
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile

from netscope.flows import aggregate_flows
from netscope.parser import parse_pcap
from netscope.stats import protocol_distribution, top_talkers
from netscope.storage import Storage

DB_PATH = os.environ.get("NETSCOPE_DB", "netscope.db")

app = FastAPI(
    title="NetScope API",
    description="Network traffic analysis for PCAP files.",
    version="0.1.0",
)


def get_storage() -> Storage:
    return Storage(DB_PATH)

@app.get("/")
def root():
    return {"name": "NetScope API", "docs": "/docs"}

@app.post("/analyses")
async def create_analysis(file: UploadFile):
    """Upload a PCAP file & analyze it."""
    if not file.filename or not file.filename.endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="File mnust be a PCAP capture.")
    
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name
    
    try:
        packets = parse_pcap(tmp_path)
    except Exception:
        raise HTTPException(status_code=400, detail="Could not parse file as DCAP.")
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    
    if not packets:
        raise HTTPException(status_code=400, detail="No IP packets found in capture.")
    
    flows = aggregate_flows(packets)
    storage = get_storage()
    analysis_id = storage.save_analysis(file.filename, packets, flows)
    storage.close()

    return {
        "id": analysis_id,
        "pcap_file": file.filename,
        "packet_count": len(packets),
        "flow_count": len(flows),
    }

@app.get("/analyses")
def list_analyses():
    """List all saved analyses."""
    storage = get_storage()
    analyses = storage.list_analyses()
    storage.close()
    return analyses

@app.get("/analyses/{analysis_id}/flows")
def get_flows(analysis_id: int):
    """Flows for 1 analysis, sorted by bytes."""
    storage = get_storage()
    flows = storage.get_flows(analysis_id)
    storage.close()
    if not flows:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return flows

@app.get("/analyses/{analysis_id}/stats")
def get_stats(analysis_id: int):
    """Summary stats for 1 analysis."""
    storage = get_storage()
    packets = storage.get_packets(analysis_id)
    storage.close()
    if not packets:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return {
        "packet_count": len(packets),
        "total_bytes": sum(p.size for p in packets),
        "protocols": protocol_distribution(packets),
        "top_talkers": [
            {"ip": ip, "bytes": b} for ip, b in top_talkers(packets)
        ],
    }