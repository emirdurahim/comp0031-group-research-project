"""Tests for the benchmarking framework."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from src.algorithms import BIKE, HQC
from src.benchmarks.metrics import (
    BenchmarkResult,
    AggregatedResult,
    aggregate_results,
    CSV_FIELDS,
)
from src.benchmarks.runner import BenchmarkRunner


# ---------------------------------------------------------------------------
# BenchmarkResult
# ---------------------------------------------------------------------------

class TestBenchmarkResult:
    def _make_result(self, trial: int = 0) -> BenchmarkResult:
        return BenchmarkResult(
            algorithm="BIKE-Level-1",
            parameter_set="Level-1",
            trial=trial,
            keygen_time_s=0.001,
            encap_time_s=0.002,
            decap_time_s=0.003,
            keygen_memory_bytes=1024,
            encap_memory_bytes=2048,
            decap_memory_bytes=512,
            public_key_size_bytes=1541,
            secret_key_size_bytes=3110,
            ciphertext_size_bytes=1573,
            shared_secret_size_bytes=32,
        )

    def test_to_dict_has_all_csv_fields(self):
        result = self._make_result()
        d = result.to_dict()
        for field in CSV_FIELDS:
            assert field in d, f"Missing field: {field}"

    def test_to_dict_values(self):
        result = self._make_result(trial=3)
        d = result.to_dict()
        assert d["algorithm"] == "BIKE-Level-1"
        assert d["trial"] == 3
        assert d["public_key_size_bytes"] == 1541


# ---------------------------------------------------------------------------
# aggregate_results
# ---------------------------------------------------------------------------

class TestAggregateResults:
    def _make_results(self, n: int = 5) -> list[BenchmarkResult]:
        return [
            BenchmarkResult(
                algorithm="HQC-HQC-128",
                parameter_set="HQC-128",
                trial=i,
                keygen_time_s=0.001 * (i + 1),
                encap_time_s=0.002,
                decap_time_s=0.003,
                keygen_memory_bytes=1000 * (i + 1),
                encap_memory_bytes=2000,
                decap_memory_bytes=500,
                public_key_size_bytes=2249,
                secret_key_size_bytes=2289,
                ciphertext_size_bytes=4481,
                shared_secret_size_bytes=64,
            )
            for i in range(n)
        ]

    def test_basic_aggregation(self):
        results = self._make_results(5)
        agg = aggregate_results(results)
        assert isinstance(agg, AggregatedResult)
        assert agg.algorithm == "HQC-HQC-128"
        assert agg.num_trials == 5

    def test_stat_keys(self):
        agg = aggregate_results(self._make_results(3))
        for key in ("mean", "median", "stdev", "min", "max"):
            assert key in agg.keygen_time_s

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            aggregate_results([])

    def test_mixed_algorithms_raises(self):
        results = self._make_results(2)
        results[1] = BenchmarkResult(
            algorithm="BIKE-Level-1",
            parameter_set="Level-1",
            trial=1,
            keygen_time_s=0.001,
            encap_time_s=0.002,
            decap_time_s=0.003,
            keygen_memory_bytes=1024,
            encap_memory_bytes=2048,
            decap_memory_bytes=512,
            public_key_size_bytes=1541,
            secret_key_size_bytes=3110,
            ciphertext_size_bytes=1573,
            shared_secret_size_bytes=32,
        )
        with pytest.raises(ValueError, match="single algorithm"):
            aggregate_results(results)

    def test_to_dict(self):
        agg = aggregate_results(self._make_results(3))
        d = agg.to_dict()
        assert "keygen_time_s_mean" in d
        assert "encap_time_s_stdev" in d


# ---------------------------------------------------------------------------
# BenchmarkRunner
# ---------------------------------------------------------------------------

class TestBenchmarkRunner:
    def test_run_returns_correct_count(self, tmp_path):
        kem = BIKE("Level-1")
        runner = BenchmarkRunner(kem, num_trials=3, output_dir=tmp_path)
        results = runner.run()
        assert len(results) == 3

    def test_run_returns_benchmark_results(self, tmp_path):
        kem = BIKE("Level-1")
        runner = BenchmarkRunner(kem, num_trials=2, output_dir=tmp_path)
        results = runner.run()
        for r in results:
            assert isinstance(r, BenchmarkResult)
            assert r.algorithm == kem.full_name()
            assert r.keygen_time_s >= 0
            assert r.public_key_size_bytes == 1541

    def test_run_and_save_writes_csv(self, tmp_path):
        kem = BIKE("Level-1")
        runner = BenchmarkRunner(kem, num_trials=2, output_dir=tmp_path)
        runner.run_and_save()
        csv_files = list(tmp_path.glob("*.csv"))
        assert len(csv_files) == 1
        with csv_files[0].open() as fh:
            reader = csv.DictReader(fh)
            rows = list(reader)
        assert len(rows) == 2
        assert "keygen_time_s" in rows[0]

    def test_run_and_save_returns_aggregated(self, tmp_path):
        kem = HQC("HQC-128")
        runner = BenchmarkRunner(kem, num_trials=3, output_dir=tmp_path)
        agg = runner.run_and_save()
        assert isinstance(agg, AggregatedResult)
        assert agg.num_trials == 3

    def test_default_output_dir_exists(self):
        """BenchmarkRunner creates output_dir if it doesn't exist."""
        import tempfile, os
        with tempfile.TemporaryDirectory() as td:
            new_dir = Path(td) / "nonexistent"
            kem = BIKE("Level-1")
            runner = BenchmarkRunner(kem, num_trials=1, output_dir=new_dir)
            assert new_dir.exists()
