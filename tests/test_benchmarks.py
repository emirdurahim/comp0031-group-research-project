"""Tests for the benchmarking framework."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from src.algorithms import ML_DSA, ML_KEM
from src.benchmarks.metrics import (
    BenchmarkResult,
    SignatureBenchmarkResult,
    AggregatedResult,
    AggregatedSignatureResult,
    aggregate_results,
    aggregate_signature_results,
    CSV_FIELDS,
    SIGNATURE_CSV_FIELDS,
)
from src.benchmarks.runner import BenchmarkRunner, SignatureBenchmarkRunner


# ---------------------------------------------------------------------------
# BenchmarkResult (KEM)
# ---------------------------------------------------------------------------

class TestBenchmarkResult:
    def _make_result(self, trial: int = 0) -> BenchmarkResult:
        return BenchmarkResult(
            algorithm="FIPS-203-ML-KEM-512",
            parameter_set="ML-KEM-512",
            trial=trial,
            keygen_time_s=0.001,
            encap_time_s=0.002,
            decap_time_s=0.003,
            keygen_memory_bytes=1024,
            encap_memory_bytes=2048,
            decap_memory_bytes=512,
            public_key_size_bytes=800,
            secret_key_size_bytes=1632,
            ciphertext_size_bytes=768,
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
        assert d["algorithm"] == "FIPS-203-ML-KEM-512"
        assert d["trial"] == 3
        assert d["public_key_size_bytes"] == 800


# ---------------------------------------------------------------------------
# SignatureBenchmarkResult
# ---------------------------------------------------------------------------

class TestSignatureBenchmarkResult:
    def _make_result(self, trial: int = 0) -> SignatureBenchmarkResult:
        return SignatureBenchmarkResult(
            algorithm="Dilithium-ML-DSA-44",
            parameter_set="ML-DSA-44",
            trial=trial,
            keygen_time_s=0.005,
            sign_time_s=0.010,
            verify_time_s=0.003,
            keygen_memory_bytes=4096,
            sign_memory_bytes=8192,
            verify_memory_bytes=2048,
            public_key_size_bytes=1312,
            secret_key_size_bytes=2560,
            signature_size_bytes=2420,
        )

    def test_to_dict_has_all_csv_fields(self):
        result = self._make_result()
        d = result.to_dict()
        for field in SIGNATURE_CSV_FIELDS:
            assert field in d, f"Missing field: {field}"

    def test_to_dict_values(self):
        result = self._make_result(trial=2)
        d = result.to_dict()
        assert d["algorithm"] == "Dilithium-ML-DSA-44"
        assert d["trial"] == 2
        assert d["signature_size_bytes"] == 2420


# ---------------------------------------------------------------------------
# aggregate_results (KEM)
# ---------------------------------------------------------------------------

class TestAggregateResults:
    def _make_results(self, n: int = 5) -> list[BenchmarkResult]:
        return [
            BenchmarkResult(
                algorithm="FIPS-203-ML-KEM-768",
                parameter_set="ML-KEM-768",
                trial=i,
                keygen_time_s=0.001 * (i + 1),
                encap_time_s=0.002,
                decap_time_s=0.003,
                keygen_memory_bytes=1000 * (i + 1),
                encap_memory_bytes=2000,
                decap_memory_bytes=500,
                public_key_size_bytes=1184,
                secret_key_size_bytes=2400,
                ciphertext_size_bytes=1088,
                shared_secret_size_bytes=32,
            )
            for i in range(n)
        ]

    def test_basic_aggregation(self):
        results = self._make_results(5)
        agg = aggregate_results(results)
        assert isinstance(agg, AggregatedResult)
        assert agg.algorithm == "FIPS-203-ML-KEM-768"
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
            algorithm="FIPS-203-ML-KEM-512",
            parameter_set="ML-KEM-512",
            trial=1,
            keygen_time_s=0.001,
            encap_time_s=0.002,
            decap_time_s=0.003,
            keygen_memory_bytes=1024,
            encap_memory_bytes=2048,
            decap_memory_bytes=512,
            public_key_size_bytes=800,
            secret_key_size_bytes=1632,
            ciphertext_size_bytes=768,
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
# aggregate_signature_results
# ---------------------------------------------------------------------------

class TestAggregateSignatureResults:
    def _make_results(self, n: int = 5) -> list[SignatureBenchmarkResult]:
        return [
            SignatureBenchmarkResult(
                algorithm="Dilithium-ML-DSA-65",
                parameter_set="ML-DSA-65",
                trial=i,
                keygen_time_s=0.005 * (i + 1),
                sign_time_s=0.010,
                verify_time_s=0.003,
                keygen_memory_bytes=4000 * (i + 1),
                sign_memory_bytes=8000,
                verify_memory_bytes=2000,
                public_key_size_bytes=1952,
                secret_key_size_bytes=4032,
                signature_size_bytes=3309,
            )
            for i in range(n)
        ]

    def test_basic_aggregation(self):
        results = self._make_results(5)
        agg = aggregate_signature_results(results)
        assert isinstance(agg, AggregatedSignatureResult)
        assert agg.algorithm == "Dilithium-ML-DSA-65"
        assert agg.num_trials == 5

    def test_stat_keys(self):
        agg = aggregate_signature_results(self._make_results(3))
        for key in ("mean", "median", "stdev", "min", "max"):
            assert key in agg.keygen_time_s
            assert key in agg.sign_time_s

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            aggregate_signature_results([])

    def test_to_dict(self):
        agg = aggregate_signature_results(self._make_results(3))
        d = agg.to_dict()
        assert "keygen_time_s_mean" in d
        assert "sign_time_s_stdev" in d


# ---------------------------------------------------------------------------
# SignatureBenchmarkRunner
# ---------------------------------------------------------------------------

class TestSignatureBenchmarkRunner:
    def test_run_returns_correct_count(self, tmp_path):
        sig_alg = ML_DSA("ML-DSA-44")
        runner = SignatureBenchmarkRunner(sig_alg, num_trials=3, output_dir=tmp_path)
        results = runner.run()
        assert len(results) == 3

    def test_run_returns_signature_results(self, tmp_path):
        sig_alg = ML_DSA("ML-DSA-44")
        runner = SignatureBenchmarkRunner(sig_alg, num_trials=2, output_dir=tmp_path)
        results = runner.run()
        for r in results:
            assert isinstance(r, SignatureBenchmarkResult)
            assert r.algorithm == sig_alg.full_name()
            assert r.keygen_time_s >= 0
            assert r.sign_time_s >= 0
            assert r.signature_size_bytes == 2420

    def test_run_and_save_writes_csv(self, tmp_path):
        sig_alg = ML_DSA("ML-DSA-44")
        runner = SignatureBenchmarkRunner(sig_alg, num_trials=2, output_dir=tmp_path)
        runner.run_and_save()
        csv_files = list(tmp_path.glob("*.csv"))
        assert len(csv_files) == 1
        with csv_files[0].open() as fh:
            reader = csv.DictReader(fh)
            rows = list(reader)
        assert len(rows) == 2
        assert "sign_time_s" in rows[0]

    def test_run_and_save_returns_aggregated(self, tmp_path):
        sig_alg = ML_DSA("ML-DSA-65")
        runner = SignatureBenchmarkRunner(sig_alg, num_trials=3, output_dir=tmp_path)
        agg = runner.run_and_save()
        assert isinstance(agg, AggregatedSignatureResult)
        assert agg.num_trials == 3

    def test_default_output_dir_exists(self):
        """SignatureBenchmarkRunner creates output_dir if it doesn't exist."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            new_dir = Path(td) / "nonexistent"
            sig_alg = ML_DSA("ML-DSA-44")
            runner = SignatureBenchmarkRunner(sig_alg, num_trials=1, output_dir=new_dir)
            assert new_dir.exists()
