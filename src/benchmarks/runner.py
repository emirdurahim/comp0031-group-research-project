"""Benchmarking runner for KEM algorithms.

:class:`BenchmarkRunner` orchestrates repeated timing and memory
measurements for any :class:`~src.algorithms.base.KEMAlgorithm`
implementation and writes results to CSV.
"""

from __future__ import annotations

import csv
import os
import time
import tracemalloc
from pathlib import Path
from typing import List, Optional

from src.algorithms.base import KEMAlgorithm

from .metrics import BenchmarkResult, CSV_FIELDS, aggregate_results, AggregatedResult


class BenchmarkRunner:
    """Run repeated benchmark trials for a KEM algorithm.

    Parameters
    ----------
    algorithm:
        An instantiated :class:`~src.algorithms.base.KEMAlgorithm`.
    num_trials:
        Number of independent trials to run (default: ``10``).
    output_dir:
        Directory in which to write CSV result files.
        Defaults to ``data/`` relative to the repository root.
    """

    def __init__(
        self,
        algorithm: KEMAlgorithm,
        num_trials: int = 10,
        output_dir: Optional[Path] = None,
    ) -> None:
        self.algorithm = algorithm
        self.num_trials = num_trials
        if output_dir is None:
            output_dir = Path(__file__).resolve().parents[2] / "data"
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> List[BenchmarkResult]:
        """Execute all trials and return a list of :class:`BenchmarkResult`.

        Each trial performs keygen → encapsulate → decapsulate and records
        wall-clock time and peak heap allocation for each step.
        """
        results: List[BenchmarkResult] = []
        for trial in range(self.num_trials):
            result = self._run_trial(trial)
            results.append(result)
        return results

    def run_and_save(self) -> AggregatedResult:
        """Run all trials, save per-trial CSV, and return aggregated stats."""
        results = self.run()
        self._save_csv(results)
        return aggregate_results(results)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_trial(self, trial: int) -> BenchmarkResult:
        """Run a single keygen/encap/decap trial and return metrics."""
        algo = self.algorithm

        # --- Key generation ---
        tracemalloc.start()
        t0 = time.perf_counter()
        kp = algo.keygen()
        keygen_time = time.perf_counter() - t0
        _, keygen_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # --- Encapsulation ---
        tracemalloc.start()
        t0 = time.perf_counter()
        enc = algo.encapsulate(kp.public_key)
        encap_time = time.perf_counter() - t0
        _, encap_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # --- Decapsulation ---
        tracemalloc.start()
        t0 = time.perf_counter()
        algo.decapsulate(enc.ciphertext, kp.secret_key)
        decap_time = time.perf_counter() - t0
        _, decap_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        return BenchmarkResult(
            algorithm=algo.full_name(),
            parameter_set=algo.parameter_set,
            trial=trial,
            keygen_time_s=keygen_time,
            encap_time_s=encap_time,
            decap_time_s=decap_time,
            keygen_memory_bytes=keygen_peak,
            encap_memory_bytes=encap_peak,
            decap_memory_bytes=decap_peak,
            public_key_size_bytes=len(kp.public_key),
            secret_key_size_bytes=len(kp.secret_key),
            ciphertext_size_bytes=len(enc.ciphertext),
            shared_secret_size_bytes=len(enc.shared_secret),
        )

    def _save_csv(self, results: List[BenchmarkResult]) -> Path:
        """Serialise per-trial results to a CSV file and return its path."""
        safe_name = self.algorithm.full_name().replace(" ", "_")
        csv_path = self.output_dir / f"{safe_name}_trials.csv"
        with csv_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
            writer.writeheader()
            for result in results:
                writer.writerow(result.to_dict())
        return csv_path
