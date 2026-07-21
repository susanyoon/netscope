import pytest
from fastapi.testclient import TestClient

import netscope.api
from netscope.api import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(netscope.api, "DB_PATH", str(tmp_path / "test.db"))
    return TestClient(app)

def _upload_sample(client):
    with open("tests/sample.pcap", "rb") as f:
        return client.post(
            "/analyses", files={"file": ("sample.pcap", f, "application/octet-stream")}
        )

def test_root(client):
    assert client.get("/").status_code == 200

def test_upload_and_analyze(client):
    response = _upload_sample(client)
    assert response.status_code == 200
    body = response.json()
    assert body["packet_count"] == 3
    assert body["flow_count"] == 3

def test_list_analyses(client):
    _upload_sample(client)
    response = client.get("/analyses")
    assert response.status_code == 200
    assert len(response.json()) == 1

def test_get_flows(client):
    analysis_id = _upload_sample(client).json()["id"]
    response = client.get(f"/analyses/{analysis_id}/flows")
    assert response.status_code == 200
    assert len(response.json()) == 3

def test_stats(client):
    analysis_id = _upload_sample(client).json()["id"]
    stats = client.get(f"/analyses/{analysis_id}/stats").json()
    assert stats["packet_count"] == 3
    assert "UDP" in stats["protocols"]

def test_missing_analysis_404(client):
    assert client.get("/analyses/9999/flows").status_code == 404

def test_rejects_non_pcap_filename(client):
    response = client.post(
        "/analyses", files={"file": ("notes.txt", b"hello", "text/plain")}
    )
    assert response.status_code == 400

