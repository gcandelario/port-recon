"""Unit tests for scanner.reporter."""

import json
import csv
from pathlib import Path

import pytest

from scanner.core import ScanResult, ScanSummary
from scanner.reporter import Reporter


def _make_summary(open_ports=(80, 443), closed_ports=(22,), filtered_ports=(8080,)):
    results = (
        [ScanResult(port=p, state="open", service="HTTP", latency_ms=5.2) for p in open_ports]
        + [ScanResult(port=p, state="closed", service="SSH") for p in closed_ports]
        + [ScanResult(port=p, state="filtered", service="HTTP-ALT") for p in filtered_ports]
    )
    total = len(results)
    s = ScanSummary(
        target_host="example.com",
        target_ip="93.184.216.34",
        total_ports=total,
        scan_duration_s=1.23,
    )
    s.results = results
    return s


class TestReporterExportJSON:
    def test_json_file_created(self, tmp_path):
        out = tmp_path / "results.json"
        reporter = Reporter(_make_summary(), output_path=out, output_format="json")
        reporter.export()
        assert out.exists()

    def test_json_structure(self, tmp_path):
        out = tmp_path / "results.json"
        summary = _make_summary()
        Reporter(summary, output_path=out, output_format="json").export()
        data = json.loads(out.read_text())
        assert "meta" in data
        assert "results" in data
        assert data["meta"]["target_host"] == "example.com"
        assert data["meta"]["open"] == summary.open_count

    def test_json_results_count(self, tmp_path):
        out = tmp_path / "results.json"
        summary = _make_summary()
        Reporter(summary, output_path=out, output_format="json").export()
        data = json.loads(out.read_text())
        assert len(data["results"]) == len(summary.results)

    def test_json_result_fields(self, tmp_path):
        out = tmp_path / "results.json"
        Reporter(_make_summary(), output_path=out, output_format="json").export()
        data = json.loads(out.read_text())
        required = {"port", "state", "service", "banner", "latency_ms"}
        for row in data["results"]:
            assert required.issubset(row.keys())


class TestReporterExportCSV:
    def test_csv_file_created(self, tmp_path):
        out = tmp_path / "results.csv"
        Reporter(_make_summary(), output_path=out, output_format="csv").export()
        assert out.exists()

    def test_csv_headers(self, tmp_path):
        out = tmp_path / "results.csv"
        Reporter(_make_summary(), output_path=out, output_format="csv").export()
        with out.open() as fh:
            reader = csv.DictReader(fh)
            assert set(reader.fieldnames) == {"port", "state", "service", "latency_ms", "banner"}

    def test_csv_row_count(self, tmp_path):
        out = tmp_path / "results.csv"
        summary = _make_summary()
        Reporter(summary, output_path=out, output_format="csv").export()
        with out.open() as fh:
            rows = list(csv.DictReader(fh))
        assert len(rows) == len(summary.results)

    def test_no_export_when_no_path(self, tmp_path):
        # Should not raise and should not write any file
        Reporter(_make_summary(), output_path=None).export()


class TestReporterSummaryCounts:
    def test_open_count(self):
        s = _make_summary(open_ports=(80, 443, 8080), closed_ports=(), filtered_ports=())
        assert s.open_count == 3

    def test_closed_count(self):
        s = _make_summary(open_ports=(), closed_ports=(22, 25), filtered_ports=())
        assert s.closed_count == 2

    def test_filtered_count(self):
        s = _make_summary(open_ports=(), closed_ports=(), filtered_ports=(135, 139, 445))
        assert s.filtered_count == 3
