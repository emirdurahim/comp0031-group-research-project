"""Statistical analysis helpers for benchmark results.

Functions in this module operate on lists of
:class:`~src.benchmarks.metrics.AggregatedResult` objects (or raw CSVs)
and compute higher-level summaries.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Dict, List


def load_summary_csv(path: str | Path) -> List[Dict[str, str]]:
    """Load a summary CSV produced by :meth:`ExperimentRunner.save_summary`.

    Parameters
    ----------
    path:
        Path to the CSV file.

    Returns
    -------
    list of dict
        One dict per row, with all values as strings (as returned by
        :mod:`csv.DictReader`).
    """
    path = Path(path)
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        return list(reader)


def load_trials_csv(path: str | Path) -> List[Dict[str, str]]:
    """Load a per-trial CSV produced by :class:`~src.benchmarks.runner.BenchmarkRunner`.

    Parameters
    ----------
    path:
        Path to the CSV file.

    Returns
    -------
    list of dict
        One dict per trial row.
    """
    return load_summary_csv(path)  # same format, re-use loader


def compare_algorithms(
    summary_rows: List[Dict[str, str]],
    metric: str = "keygen_time_s_mean",
) -> List[Dict[str, object]]:
    """Rank algorithms by a given metric.

    Parameters
    ----------
    summary_rows:
        Rows loaded from a summary CSV (see :func:`load_summary_csv`).
    metric:
        The column name to rank by (default: ``"keygen_time_s_mean"``).

    Returns
    -------
    list of dict
        Rows sorted ascending by *metric*, each containing at least
        ``algorithm``, ``parameter_set``, and the requested *metric*.
    """
    subset = []
    for row in summary_rows:
        if metric not in row:
            raise KeyError(f"Metric {metric!r} not found in CSV columns.")
        subset.append(
            {
                "algorithm": row["algorithm"],
                "parameter_set": row["parameter_set"],
                metric: float(row[metric]),
            }
        )
    subset.sort(key=lambda r: r[metric])  # type: ignore[arg-type]
    return subset
