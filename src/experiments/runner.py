"""Experiment runner – orchestrates benchmarks across multiple algorithms.

Usage example::

    from src.experiments.runner import ExperimentRunner

    runner = ExperimentRunner("src/experiments/configs/default.json")
    summary = runner.run()
    runner.save_summary(summary)
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Dict, List, Optional, Union

from src.algorithms import (
    BIKE,
    HQC,
    ClassicMcEliece,
    Dilithium,
    NTRULPRime,
    StreamlinedNTRUPrime,
)
from src.algorithms.base import KEMAlgorithm, SignatureAlgorithm
from src.benchmarks.metrics import AggregatedResult, AggregatedSignatureResult
from src.benchmarks.runner import BenchmarkRunner, SignatureBenchmarkRunner

from .config import ExperimentConfig, ExperimentEntry, load_config

# ---------------------------------------------------------------------------
# Registry mapping algorithm name → constructor
# ---------------------------------------------------------------------------

_ALGORITHM_REGISTRY: Dict[str, type] = {
    "BIKE": BIKE,
    "HQC": HQC,
    "Classic McEliece": ClassicMcEliece,
    "ClassicMcEliece": ClassicMcEliece,
    "Streamlined NTRU Prime": StreamlinedNTRUPrime,
    "StreamlinedNTRUPrime": StreamlinedNTRUPrime,
    "NTRU LPRime": NTRULPRime,
    "NTRULPRime": NTRULPRime,
    "Dilithium": Dilithium,
    "ML-DSA": Dilithium,
    "FIPS204": Dilithium,
}


def _build_algorithm(
    name: str, parameter_set: str
) -> Union[KEMAlgorithm, SignatureAlgorithm]:
    """Instantiate an algorithm by name and parameter set.

    Raises
    ------
    ValueError
        If *name* is not found in the registry.
    """
    cls = _ALGORITHM_REGISTRY.get(name)
    if cls is None:
        raise ValueError(
            f"Unknown algorithm {name!r}. "
            f"Available: {sorted(_ALGORITHM_REGISTRY.keys())}"
        )
    return cls(parameter_set=parameter_set)  # type: ignore[call-arg]


class ExperimentRunner:
    """Run all experiments defined in a configuration file.

    Parameters
    ----------
    config:
        Either a path to a JSON/YAML config file or an already-parsed
        :class:`~src.experiments.config.ExperimentConfig`.
    output_dir:
        Override for the output directory specified in the config.
    """

    def __init__(
        self,
        config: str | Path | ExperimentConfig,
        output_dir: Optional[Path] = None,
    ) -> None:
        if isinstance(config, ExperimentConfig):
            self.config = config
        else:
            self.config = load_config(config)

        repo_root = Path(__file__).resolve().parents[2]
        self.output_dir = Path(output_dir) if output_dir else repo_root / self.config.output_dir

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> List[Union[AggregatedResult, AggregatedSignatureResult]]:
        """Execute all experiments and return aggregated results."""
        all_results: List[Union[AggregatedResult, AggregatedSignatureResult]] = []
        for entry in self.config.experiments:
            for param_set in entry.parameter_sets:
                result = self._run_entry(entry, param_set)
                all_results.append(result)
        return all_results

    def save_summary(
        self,
        results: List[Union[AggregatedResult, AggregatedSignatureResult]],
        filename: str = "summary.csv",
    ) -> Path:
        """Write a summary CSV of aggregated results to *output_dir*.

        KEM and signature results are saved to separate files so that
        column layouts remain consistent within each file.

        Returns the path of the KEM summary (or *filename* if no KEMs).
        """
        kem_results = [r for r in results if isinstance(r, AggregatedResult)]
        sig_results = [r for r in results if isinstance(r, AggregatedSignatureResult)]

        self.output_dir.mkdir(parents=True, exist_ok=True)
        kem_path = self.output_dir / filename

        if kem_results:
            fieldnames = list(kem_results[0].to_dict().keys())
            with kem_path.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=fieldnames)
                writer.writeheader()
                for result in kem_results:
                    writer.writerow(result.to_dict())

        if sig_results:
            sig_path = self.output_dir / filename.replace(".csv", "_signatures.csv")
            fieldnames = list(sig_results[0].to_dict().keys())
            with sig_path.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=fieldnames)
                writer.writeheader()
                for result in sig_results:
                    writer.writerow(result.to_dict())

        return kem_path

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_entry(
        self, entry: ExperimentEntry, parameter_set: str
    ) -> Union[AggregatedResult, AggregatedSignatureResult]:
        algo = _build_algorithm(entry.algorithm, parameter_set)

        if isinstance(algo, SignatureAlgorithm):
            bench_runner = SignatureBenchmarkRunner(
                algorithm=algo,
                num_trials=entry.num_trials,
                output_dir=self.output_dir,
            )
        else:
            bench_runner = BenchmarkRunner(
                algorithm=algo,
                num_trials=entry.num_trials,
                output_dir=self.output_dir,
            )
        return bench_runner.run_and_save()
