# NetScope

![CI](https://github.com/susanyoon/netscope/actions/workflows/ci.yml/badge.svg)

NetScope is a Python-based network traffic analysis platform that processes PCAP files and extracts actionable insights about network activity (packet metadata, flow aggregation, and traffic summaries from the command line).

## Features

- [x] Parse PCAP files (IP, TCP, UDP w/ ports & timestamps)
- [x] Aggregate network flows by 5-tuple
- [x] Traffic summaries and protocol breakdown (CLI)
- [x] Protocol statistics and visualizations
- [x] SQLite storage
- [x] REST API
- [x] Docker support
- [ ] Basic anomaly detection

## Installation

```bash
git clone https://github.com/susanyoon/netscope.git
cd netscope
pip install -e ".[dev]"
```

## Usage

```bash
netscope summary capture.pcap    # high-level traffic summary
netscope flows capture.pcap      # flow table, sorted by bytes
netscope flows capture.pcap --sort-by packets
```
<img width="488" height="172" alt="image" src="https://github.com/user-attachments/assets/29d08eba-d9fd-4a2b-9df2-b621e6460687" />

## Charts

`netscope chart capture.pcap` generates visualizations:

![Traffic over time](docs/traffic_over_time.png)
![Protocol distribution](docs/protocols.png)
![Top talkers](docs/top_talkers.png)

## Running Tests

```bash
pytest
```

## Tech Stack
- Python
- Scapy
- Typer
- Rich
- FastAPI 
- SQLite 

## API

Run the API server:

```bash
fastapi dev netscope/api.py
```

![API overview](docs/netscope_api_overall.png)
![API response](docs/netscope_api_postcall.png)

Interactive docs at `http://127.0.0.1:8000/docs`

## Running with Docker

```bash
docker compose up --build
```

Then open http://localhost:8000/docs


## Project Status
Under active devlopment.
See [Issues](https://github.com/susanyoon/netscope/issues) for the roadmap.

