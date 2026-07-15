from typer.testing import CliRunner

from netscope.cli import app

runner = CliRunner()


def test_summary_runs():
    result = runner.invoke(app, ["summary", "tests/sample.pcap"])
    assert result.exit_code == 0
    assert "Packets" in result.output

def test_flows_runs():
    result = runner.invoke(app, ["flows", "tests/sample.pcap"])
    assert result.exit_code == 0

def test_missing_file_fails():
    result = runner.invoke(app, ["summary", "does_not_exist.pcap"])
    assert result.exit_code != 0