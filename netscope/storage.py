import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from netscope.models import Flow, PacketInfo

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pcap_file TEXT NOT NULL,
    analyzed_at TEXT NOT NULL,
    packet_count INTEGER NOT NULL,
    flow_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER NOT NULL REFERENCES analyses(id),
    timestamp REAL NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT NOT NULL,
    size INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER NOT NULL REFERENCES analyses(id),
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT NOT NULL,
    packet_count INTEGER NOT NULL,
    total_bytes INTEGER NOT NULL,
    start_time REAL NOT NULL,
    end_time REAL NOT NULL
);
"""

class Storage:
    """SQLite persistence for NetScope analyses."""

    def __init__(self, db_path: str = "netscope.db"):
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
    
    def close(self) -> None:
        self.conn.close()
    
    def save_analysis(
        self, pcap_file: str, packets: list[PacketInfo], flows:list[Flow]) -> int:
        """Save a full analysis. Returns the new analysis id. """
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO analyses (pcap_file, analyzed_at, packet_count,flow_count) "
            "VALUES (?, ?, ?, ?)",
            (
                Path(pcap_file).name,
                datetime.now(timezone.utc).isoformat(),
                len(packets),
                len(flows),
            ),
        )
        analysis_id = cur.lastrowid

        cur.executemany(
            "INSERT INTO packets "
            "(analysis_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, size) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (analysis_id, p.timestamp, p.src_ip, p.dst_ip, p.src_port, p.dst_port, p.protocol, p.size)
                for p in packets
            ],
        )

        cur.executemany(
            "INSERT INTO flows "
            "(analysis_id, src_ip, dst_ip, src_port, dst_port, protocol, "
            "packet_count, total_bytes, start_time, end_time) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (analysis_id, f.src_ip, f.dst_ip, f.src_port, f.dst_port,
                 f.protocol, f.packet_count, f.total_bytes, f.start_time, f.end_time)
                for f in flows
            ],
        )

        self.conn.commit()
        return analysis_id
    
    def list_analyses(self) -> list[dict]:
        """All saved analyses, newest first."""
        rows = self.conn.execute(
            "SELECT * FROM analyses ORDER BY analyzed_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    
    def get_flows(self, analysis_id: int) -> list[Flow]:
        """Reload the flows for one analysis."""
        rows = self.conn.execute(
            "SELECT src_ip, dst_ip, src_port, dst_port, protocol, "
            "packet_count, total_bytes, start_time, end_time "
            "FROM flows WHERE analysis_id = ? ORDER BY total_bytes DESC",
            (analysis_id,),
        ).fetchall()
        return [Flow(**dict(r)) for r in rows]
    
    def get_packets(self, analysis_id: int) -> list[PacketInfo]:
        """Reload the packets for one analysis."""
        rows = self.conn.execute(
            "SELECT timestamp, src_ip, dst_ip, src_port, dst_port, protocol, size "
            "FROM packets WHERE analysis_id = ? ORDER BY timestamp",
            (analysis_id,),
        ).fetchall()
        return [PacketInfo(**dict(r)) for r in rows]
