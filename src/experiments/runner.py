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
from typing import Dict, List, Optional

from src.algorithms import (
    BIKE,
    HQC,
    ClassicMcEliece,
    NTRULPRime,
    StreamlinedNTRUPrime,
)
from src.algorithms.base import KEMAlgorithm
from src.benchmarks.metrics import AggregatedResult
from src.benchmarks.runner import BenchmarkRunner

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
}


def _build_algorithm(name: str, parameter_set: str) -> KEMAlgorithm:
    """Instantiate a KEM algorithm by name and parameter set.

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

    def run(self) -> List[AggregatedResult]:
        """Execute all experiments and return aggregated results."""
        all_results: List[AggregatedResult] = []
        for entry in self.config.experiments:
            for param_set in entry.parameter_sets:
                result = self._run_entry(entry, param_set)
                all_results.append(result)
        return all_results

    def save_summary(
        self,
        results: List[AggregatedResult],
        filename: str = "summary.csv",
    ) -> Path:
        """Write a summary CSV of aggregated results to *output_dir*.

        Returns the path of the written file.
        """
        if not results:
            return self.output_dir / filename

        self.output_dir.mkdir(parents=True, exist_ok=True)
        csv_path = self.output_dir / filename
        fieldnames = list(results[0].to_dict().keys())
        with csv_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for result in results:
                writer.writerow(result.to_dict())
        return csv_path

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_entry(
        self, entry: ExperimentEntry, parameter_set: str
    ) -> AggregatedResult:
        algo = _build_algorithm(entry.algorithm, parameter_set)
        bench_runner = BenchmarkRunner(
            algorithm=algo,
            num_trials=entry.num_trials,
            output_dir=self.output_dir,
        )
        return bench_runner.run_and_save()
