"""Analysis package for PQC benchmark results."""

from .plots import (
    plot_key_sizes,
    plot_memory_usage,
    plot_signature_memory,
    plot_signature_sizes,
    plot_signature_timing,
    plot_timing_comparison,
)
from .stats import compare_algorithms, load_summary_csv, load_trials_csv

__all__ = [
    "load_summary_csv",
    "load_trials_csv",
    "compare_algorithms",
    "plot_timing_comparison",
    "plot_key_sizes",
    "plot_memory_usage",
    "plot_signature_timing",
    "plot_signature_sizes",
    "plot_signature_memory",
]
