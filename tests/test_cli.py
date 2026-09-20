import json
import os
import sys

import pytest

from logsentinel import cli
from logsentinel.analyzer import aggregate_by_ip, build_recommendations, build_summary
from logsentinel.parser import parse_log_file

SAMPLE_LOG = os.path.join(
    os.path.dirname(__file__), "..", "sample_logs", "auth.log.sample"
)


def _sample_report(threshold=10):
    events = parse_log_file(SAMPLE_LOG)
    stats = aggregate_by_ip(events)
    summary = build_summary(events, stats, threshold)
    recommendations = build_recommendations(summary, stats)
    return summary, stats, recommendations


def test_export_json(tmp_path):
    summary, stats, recommendations = _sample_report()

    path = cli.export_json(summary, stats, recommendations, str(tmp_path))
    assert os.path.isfile(path)

    with open(path, encoding="utf-8") as f:
        report = json.load(f)

    assert report["summary"]["total_events"] == 27
    assert report["summary"]["suspicious_ips"] == ["185.220.101.45"]
    assert report["ip_details"]["185.220.101.45"]["failed"] == 7
    assert "root" in report["ip_details"]["185.220.101.45"]["users_tried"]
    assert report["recommendations"] == recommendations


def test_export_markdown(tmp_path):
    summary, stats, recommendations = _sample_report()

    path = cli.export_markdown(summary, stats, recommendations, str(tmp_path))
    assert os.path.isfile(path)

    content = open(path, encoding="utf-8").read()
    assert "# LogSentinel" in content
    assert "185.220.101.45" in content
    assert "SUSPECT" in content


def test_main_generates_json_report(tmp_path, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["logsentinel", SAMPLE_LOG, "--json", "--output-dir", str(tmp_path)],
    )

    cli.main()

    report_path = tmp_path / "report.json"
    assert report_path.is_file()
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["summary"]["unique_ips"] == 4


def test_main_missing_logfile_exits(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["logsentinel", "/tmp/does-not-exist.log"])

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    assert exc_info.value.code == 1
    assert "introuvable" in capsys.readouterr().err
