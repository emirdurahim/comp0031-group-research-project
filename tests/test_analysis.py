"""Tests for the analysis module (stats and plots)."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from src.analysis.stats import compare_algorithms, load_summary_csv


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SUMMARY_ROWS = [
    {
        "algorithm": "BIKE-Level-1",
        "parameter_set": "Level-1",
        "num_trials": "10",
        "keygen_time_s_mean": "0.001",
        "keygen_time_s_stdev": "0.0001",
        "encap_time_s_mean": "0.002",
        "decap_time_s_mean": "0.003",
        "public_key_size_bytes": "1541",
        "secret_key_size_bytes": "3110",
        "ciphertext_size_bytes": "1573",
        "shared_secret_size_bytes": "32",
        "keygen_memory_bytes_mean": "1024",
        "encap_memory_bytes_mean": "2048",
        "decap_memory_bytes_mean": "512",
    },
    {
        "algorithm": "HQC-HQC-128",
        "parameter_set": "HQC-128",
        "num_trials": "10",
        "keygen_time_s_mean": "0.0005",
        "keygen_time_s_stdev": "0.00005",
        "encap_time_s_mean": "0.001",
        "decap_time_s_mean": "0.0015",
        "public_key_size_bytes": "2249",
        "secret_key_size_bytes": "2289",
        "ciphertext_size_bytes": "4481",
        "shared_secret_size_bytes": "64",
        "keygen_memory_bytes_mean": "512",
        "encap_memory_bytes_mean": "1024",
        "decap_memory_bytes_mean": "256",
    },
]


def _write_summary_csv(tmp_path: Path) -> Path:
    p = tmp_path / "summary.csv"
    with p.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(_SUMMARY_ROWS[0].keys()))
        writer.writeheader()
        writer.writerows(_SUMMARY_ROWS)
    return p


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class TestLoadSummaryCSV:
    def test_returns_list_of_dicts(self, tmp_path):
        p = _write_summary_csv(tmp_path)
        rows = load_summary_csv(p)
        assert isinstance(rows, list)
        assert len(rows) == 2
        assert rows[0]["algorithm"] == "BIKE-Level-1"

    def test_all_columns_present(self, tmp_path):
        p = _write_summary_csv(tmp_path)
        rows = load_summary_csv(p)
        for col in _SUMMARY_ROWS[0]:
            assert col in rows[0]


class TestCompareAlgorithms:
    def test_sorted_ascending(self):
        ranked = compare_algorithms(_SUMMARY_ROWS, metric="keygen_time_s_mean")
        assert ranked[0]["algorithm"] == "HQC-HQC-128"  # 0.0005 < 0.001

    def test_returns_correct_columns(self):
        ranked = compare_algorithms(_SUMMARY_ROWS, metric="keygen_time_s_mean")
        for r in ranked:
            assert "algorithm" in r
            assert "parameter_set" in r
            assert "keygen_time_s_mean" in r

    def test_unknown_metric_raises(self):
        with pytest.raises(KeyError):
            compare_algorithms(_SUMMARY_ROWS, metric="nonexistent_metric")


# ---------------------------------------------------------------------------
# Plots (require matplotlib)
# ---------------------------------------------------------------------------

class TestPlots:
    def _skip_if_no_mpl(self):
        pytest.importorskip("matplotlib")

    def test_plot_timing_comparison(self, tmp_path):
        self._skip_if_no_mpl()
        from src.analysis.plots import plot_timing_comparison
        out = plot_timing_comparison(_SUMMARY_ROWS, output_dir=tmp_path)
        assert out.exists()
        assert out.suffix == ".png"

    def test_plot_key_sizes(self, tmp_path):
        self._skip_if_no_mpl()
        from src.analysis.plots import plot_key_sizes
        out = plot_key_sizes(_SUMMARY_ROWS, output_dir=tmp_path)
        assert out.exists()

    def test_plot_memory_usage(self, tmp_path):
        self._skip_if_no_mpl()
        from src.analysis.plots import plot_memory_usage
        out = plot_memory_usage(_SUMMARY_ROWS, output_dir=tmp_path)
        assert out.exists()

    def test_plot_raises_without_mpl(self, tmp_path, monkeypatch):
        import src.analysis.plots as plots_module
        monkeypatch.setattr(plots_module, "_MPL_AVAILABLE", False)
        with pytest.raises(ImportError, match="matplotlib"):
            plots_module.plot_timing_comparison(_SUMMARY_ROWS, output_dir=tmp_path)
