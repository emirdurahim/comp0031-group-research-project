"""Metrics collection for KEM benchmarking.

:class:`BenchmarkResult` captures a single benchmark trial's measurements.
:func:`aggregate_results` computes summary statistics over repeated trials.
"""

from __future__ import annotations

import numpy as np
from dataclasses import dataclass
from typing import Dict, List, Sequence


@dataclass
class BenchmarkResult:
    """Measurements from a single KEM benchmark trial.

    Attributes
    ----------
    algorithm:
        Human-readable algorithm name (e.g. ``"BIKE-Level-1"``).
    parameter_set:
        The parameter set used (e.g. ``"Level-1"``).
    trial:
        Zero-based trial index.
    keygen_time_s:
        Wall-clock time for key generation, in seconds.
    encap_time_s:
        Wall-clock time for encapsulation, in seconds.
    decap_time_s:
        Wall-clock time for decapsulation, in seconds.
    keygen_memory_bytes:
        Peak memory usage during key generation, in bytes.
    encap_memory_bytes:
        Peak memory usage during encapsulation, in bytes.
    decap_memory_bytes:
        Peak memory usage during decapsulation, in bytes.
    public_key_size_bytes:
        Byte length of the generated public key.
    secret_key_size_bytes:
        Byte length of the generated secret key.
    ciphertext_size_bytes:
        Byte length of the ciphertext produced by encapsulation.
    shared_secret_size_bytes:
        Byte length of the shared secret.
    """

    algorithm: str
    parameter_set: str
    trial: int
    keygen_time_s: float
    encap_time_s: float
    decap_time_s: float
    keygen_memory_bytes: int
    encap_memory_bytes: int
    decap_memory_bytes: int
    public_key_size_bytes: int
    secret_key_size_bytes: int
    ciphertext_size_bytes: int
    shared_secret_size_bytes: int

    def to_dict(self) -> Dict[str, object]:
        """Return a flat dictionary suitable for CSV serialisation."""
        return {
            "algorithm": self.algorithm,
            "parameter_set": self.parameter_set,
            "trial": self.trial,
            "keygen_time_s": self.keygen_time_s,
            "encap_time_s": self.encap_time_s,
            "decap_time_s": self.decap_time_s,
            "keygen_memory_bytes": self.keygen_memory_bytes,
            "encap_memory_bytes": self.encap_memory_bytes,
            "decap_memory_bytes": self.decap_memory_bytes,
            "public_key_size_bytes": self.public_key_size_bytes,
            "secret_key_size_bytes": self.secret_key_size_bytes,
            "ciphertext_size_bytes": self.ciphertext_size_bytes,
            "shared_secret_size_bytes": self.shared_secret_size_bytes,
        }


# Canonical CSV column order (all fields of BenchmarkResult)
CSV_FIELDS: List[str] = [
    "algorithm",
    "parameter_set",
    "trial",
    "keygen_time_s",
    "encap_time_s",
    "decap_time_s",
    "keygen_memory_bytes",
    "encap_memory_bytes",
    "decap_memory_bytes",
    "public_key_size_bytes",
    "secret_key_size_bytes",
    "ciphertext_size_bytes",
    "shared_secret_size_bytes",
]


@dataclass
class AggregatedResult:
    """Summary statistics over repeated benchmark trials for one algorithm.

    Each timing/memory field stores a dict with keys
    ``mean``, ``median``, ``stdev``, ``min``, and ``max``.
    """

    algorithm: str
    parameter_set: str
    num_trials: int
    keygen_time_s: Dict[str, float]
    encap_time_s: Dict[str, float]
    decap_time_s: Dict[str, float]
    keygen_memory_bytes: Dict[str, float]
    encap_memory_bytes: Dict[str, float]
    decap_memory_bytes: Dict[str, float]
    public_key_size_bytes: int
    secret_key_size_bytes: int
    ciphertext_size_bytes: int
    shared_secret_size_bytes: int

    def to_dict(self) -> Dict[str, object]:
        """Return a flat dictionary (one row per stat) for reporting."""
        row: Dict[str, object] = {
            "algorithm": self.algorithm,
            "parameter_set": self.parameter_set,
            "num_trials": self.num_trials,
            "public_key_size_bytes": self.public_key_size_bytes,
            "secret_key_size_bytes": self.secret_key_size_bytes,
            "ciphertext_size_bytes": self.ciphertext_size_bytes,
            "shared_secret_size_bytes": self.shared_secret_size_bytes,
        }
        for metric in (
            "keygen_time_s",
            "encap_time_s",
            "decap_time_s",
            "keygen_memory_bytes",
            "encap_memory_bytes",
            "decap_memory_bytes",
        ):
            stats = getattr(self, metric)
            for stat_name, value in stats.items():
                row[f"{metric}_{stat_name}"] = value
        return row


def _stat_summary(values: Sequence[float]) -> Dict[str, float]:
    """Compute basic descriptive statistics over *values*."""
    if not values:
        return {"mean": 0.0, "median": 0.0, "stdev": 0.0, "min": 0.0, "max": 0.0}
    arr = np.array(values, dtype=float)
    return {
        "mean": float(np.mean(arr)),
        "median": float(np.median(arr)),
        "stdev": float(np.std(arr, ddof=1)) if len(arr) > 1 else 0.0,
        "min": float(np.min(arr)),
        "max": float(np.max(arr)),
    }


def aggregate_results(results: List[BenchmarkResult]) -> AggregatedResult:
    """Aggregate a list of per-trial :class:`BenchmarkResult` objects.

    Parameters
    ----------
    results:
        All trials for a **single** algorithm/parameter-set combination.

    Returns
    -------
    AggregatedResult
        Summary statistics across all trials.

    Raises
    ------
    ValueError
        If *results* is empty or contains data from multiple algorithms.
    """
    if not results:
        raise ValueError("Cannot aggregate an empty list of results.")
    algorithms = {r.algorithm for r in results}
    if len(algorithms) > 1:
        raise ValueError(
            f"aggregate_results expects a single algorithm; got {algorithms}"
        )
    param_sets = {r.parameter_set for r in results}
    if len(param_sets) > 1:
        raise ValueError(
            f"aggregate_results expects a single parameter set; got {param_sets}"
        )

    first = results[0]
    return AggregatedResult(
        algorithm=first.algorithm,
        parameter_set=first.parameter_set,
        num_trials=len(results),
        keygen_time_s=_stat_summary([r.keygen_time_s for r in results]),
        encap_time_s=_stat_summary([r.encap_time_s for r in results]),
        decap_time_s=_stat_summary([r.decap_time_s for r in results]),
        keygen_memory_bytes=_stat_summary([float(r.keygen_memory_bytes) for r in results]),
        encap_memory_bytes=_stat_summary([float(r.encap_memory_bytes) for r in results]),
        decap_memory_bytes=_stat_summary([float(r.decap_memory_bytes) for r in results]),
        public_key_size_bytes=first.public_key_size_bytes,
        secret_key_size_bytes=first.secret_key_size_bytes,
        ciphertext_size_bytes=first.ciphertext_size_bytes,
        shared_secret_size_bytes=first.shared_secret_size_bytes,
    )
