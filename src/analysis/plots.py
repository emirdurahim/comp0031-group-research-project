"""Plotting utilities for PQC benchmark results.

All public functions accept data in the form returned by
:func:`~src.analysis.stats.load_summary_csv` and produce matplotlib
figures that are saved to the ``results/`` directory.

Matplotlib is an optional dependency; an :class:`ImportError` is raised
with a helpful message if it is not installed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

try:
    import matplotlib
    matplotlib.use("Agg")  # non-interactive backend for scripts/CI
    import matplotlib.pyplot as plt

    _MPL_AVAILABLE = True
except ImportError:  # pragma: no cover
    _MPL_AVAILABLE = False


def _require_mpl() -> None:
    if not _MPL_AVAILABLE:
        raise ImportError(
            "matplotlib is required for plotting. "
            "Install it with: pip install matplotlib"
        )


def plot_timing_comparison(
    summary_rows: List[Dict[str, str]],
    output_dir: Optional[Path] = None,
    filename: str = "timing_comparison.png",
) -> Path:
    """Bar chart comparing mean keygen/encap/decap times across algorithms.

    Parameters
    ----------
    summary_rows:
        Rows loaded from a summary CSV.
    output_dir:
        Directory to save the figure (default: ``results/``).
    filename:
        Output filename (default: ``"timing_comparison.png"``).

    Returns
    -------
    Path
        Path of the saved figure.
    """
    _require_mpl()

    output_dir = _default_results_dir(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    labels = [f"{r['algorithm']}\n{r['parameter_set']}" for r in summary_rows]
    keygen = [float(r.get("keygen_time_s_mean", 0)) for r in summary_rows]
    encap = [float(r.get("encap_time_s_mean", 0)) for r in summary_rows]
    decap = [float(r.get("decap_time_s_mean", 0)) for r in summary_rows]

    x = range(len(labels))
    width = 0.25

    fig, ax = plt.subplots(figsize=(max(10, len(labels) * 0.8), 6))
    ax.bar([i - width for i in x], keygen, width, label="KeyGen")
    ax.bar(list(x), encap, width, label="Encapsulate")
    ax.bar([i + width for i in x], decap, width, label="Decapsulate")

    ax.set_xlabel("Algorithm / Parameter Set")
    ax.set_ylabel("Time (seconds)")
    ax.set_title("KEM Timing Comparison")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
    ax.legend()
    fig.tight_layout()

    out_path = output_dir / filename
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def plot_key_sizes(
    summary_rows: List[Dict[str, str]],
    output_dir: Optional[Path] = None,
    filename: str = "key_sizes.png",
) -> Path:
    """Bar chart comparing public key, secret key, and ciphertext sizes.

    Parameters
    ----------
    summary_rows:
        Rows loaded from a summary CSV.
    output_dir:
        Directory to save the figure (default: ``results/``).
    filename:
        Output filename (default: ``"key_sizes.png"``).

    Returns
    -------
    Path
        Path of the saved figure.
    """
    _require_mpl()

    output_dir = _default_results_dir(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    labels = [f"{r['algorithm']}\n{r['parameter_set']}" for r in summary_rows]
    pk_sizes = [int(r.get("public_key_size_bytes", 0)) for r in summary_rows]
    sk_sizes = [int(r.get("secret_key_size_bytes", 0)) for r in summary_rows]
    ct_sizes = [int(r.get("ciphertext_size_bytes", 0)) for r in summary_rows]

    x = range(len(labels))
    width = 0.25

    fig, ax = plt.subplots(figsize=(max(10, len(labels) * 0.8), 6))
    ax.bar([i - width for i in x], pk_sizes, width, label="Public Key")
    ax.bar(list(x), sk_sizes, width, label="Secret Key")
    ax.bar([i + width for i in x], ct_sizes, width, label="Ciphertext")

    ax.set_xlabel("Algorithm / Parameter Set")
    ax.set_ylabel("Size (bytes)")
    ax.set_title("KEM Key and Ciphertext Sizes")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
    ax.legend()
    fig.tight_layout()

    out_path = output_dir / filename
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def plot_memory_usage(
    summary_rows: List[Dict[str, str]],
    output_dir: Optional[Path] = None,
    filename: str = "memory_usage.png",
) -> Path:
    """Bar chart comparing peak memory usage across operations.

    Parameters
    ----------
    summary_rows:
        Rows loaded from a summary CSV.
    output_dir:
        Directory to save the figure (default: ``results/``).
    filename:
        Output filename (default: ``"memory_usage.png"``).

    Returns
    -------
    Path
        Path of the saved figure.
    """
    _require_mpl()

    output_dir = _default_results_dir(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    labels = [f"{r['algorithm']}\n{r['parameter_set']}" for r in summary_rows]
    keygen_mem = [float(r.get("keygen_memory_bytes_mean", 0)) for r in summary_rows]
    encap_mem = [float(r.get("encap_memory_bytes_mean", 0)) for r in summary_rows]
    decap_mem = [float(r.get("decap_memory_bytes_mean", 0)) for r in summary_rows]

    x = range(len(labels))
    width = 0.25

    fig, ax = plt.subplots(figsize=(max(10, len(labels) * 0.8), 6))
    ax.bar([i - width for i in x], keygen_mem, width, label="KeyGen")
    ax.bar(list(x), encap_mem, width, label="Encapsulate")
    ax.bar([i + width for i in x], decap_mem, width, label="Decapsulate")

    ax.set_xlabel("Algorithm / Parameter Set")
    ax.set_ylabel("Peak memory (bytes)")
    ax.set_title("KEM Memory Usage Comparison")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
    ax.legend()
    fig.tight_layout()

    out_path = output_dir / filename
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _default_results_dir(override: Optional[Path]) -> Path:
    if override is not None:
        return Path(override)
    return Path(__file__).resolve().parents[2] / "results"


# ======================================================================
# Digital-signature plots
# ======================================================================


def plot_signature_timing(
    summary_rows: List[Dict[str, str]],
    output_dir: Optional[Path] = None,
    filename: str = "signature_timing_comparison.png",
) -> Path:
    """Bar chart comparing mean keygen/sign/verify times for signature algorithms.

    Parameters
    ----------
    summary_rows:
        Rows loaded from a signature summary CSV.
    output_dir:
        Directory to save the figure (default: ``results/``).
    filename:
        Output filename.

    Returns
    -------
    Path
        Path of the saved figure.
    """
    _require_mpl()

    output_dir = _default_results_dir(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    labels = [f"{r['algorithm']}\n{r['parameter_set']}" for r in summary_rows]
    keygen = [float(r.get("keygen_time_s_mean", 0)) for r in summary_rows]
    sign = [float(r.get("sign_time_s_mean", 0)) for r in summary_rows]
    verify = [float(r.get("verify_time_s_mean", 0)) for r in summary_rows]

    x = range(len(labels))
    width = 0.25

    fig, ax = plt.subplots(figsize=(max(10, len(labels) * 0.8), 6))
    ax.bar([i - width for i in x], keygen, width, label="KeyGen")
    ax.bar(list(x), sign, width, label="Sign")
    ax.bar([i + width for i in x], verify, width, label="Verify")

    ax.set_xlabel("Algorithm / Parameter Set")
    ax.set_ylabel("Time (seconds)")
    ax.set_title("Signature Timing Comparison")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
    ax.legend()
    fig.tight_layout()

    out_path = output_dir / filename
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def plot_signature_sizes(
    summary_rows: List[Dict[str, str]],
    output_dir: Optional[Path] = None,
    filename: str = "signature_sizes.png",
) -> Path:
    """Bar chart comparing public key, secret key, and signature sizes.

    Parameters
    ----------
    summary_rows:
        Rows loaded from a signature summary CSV.
    output_dir:
        Directory to save the figure (default: ``results/``).
    filename:
        Output filename.

    Returns
    -------
    Path
        Path of the saved figure.
    """
    _require_mpl()

    output_dir = _default_results_dir(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    labels = [f"{r['algorithm']}\n{r['parameter_set']}" for r in summary_rows]
    pk_sizes = [int(r.get("public_key_size_bytes", 0)) for r in summary_rows]
    sk_sizes = [int(r.get("secret_key_size_bytes", 0)) for r in summary_rows]
    sig_sizes = [int(r.get("signature_size_bytes", 0)) for r in summary_rows]

    x = range(len(labels))
    width = 0.25

    fig, ax = plt.subplots(figsize=(max(10, len(labels) * 0.8), 6))
    ax.bar([i - width for i in x], pk_sizes, width, label="Public Key")
    ax.bar(list(x), sk_sizes, width, label="Secret Key")
    ax.bar([i + width for i in x], sig_sizes, width, label="Signature")

    ax.set_xlabel("Algorithm / Parameter Set")
    ax.set_ylabel("Size (bytes)")
    ax.set_title("Signature Key and Signature Sizes")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
    ax.legend()
    fig.tight_layout()

    out_path = output_dir / filename
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def plot_signature_memory(
    summary_rows: List[Dict[str, str]],
    output_dir: Optional[Path] = None,
    filename: str = "signature_memory_usage.png",
) -> Path:
    """Bar chart comparing peak memory usage for signature operations.

    Parameters
    ----------
    summary_rows:
        Rows loaded from a signature summary CSV.
    output_dir:
        Directory to save the figure (default: ``results/``).
    filename:
        Output filename.

    Returns
    -------
    Path
        Path of the saved figure.
    """
    _require_mpl()

    output_dir = _default_results_dir(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    labels = [f"{r['algorithm']}\n{r['parameter_set']}" for r in summary_rows]
    keygen_mem = [float(r.get("keygen_memory_bytes_mean", 0)) for r in summary_rows]
    sign_mem = [float(r.get("sign_memory_bytes_mean", 0)) for r in summary_rows]
    verify_mem = [float(r.get("verify_memory_bytes_mean", 0)) for r in summary_rows]

    x = range(len(labels))
    width = 0.25

    fig, ax = plt.subplots(figsize=(max(10, len(labels) * 0.8), 6))
    ax.bar([i - width for i in x], keygen_mem, width, label="KeyGen")
    ax.bar(list(x), sign_mem, width, label="Sign")
    ax.bar([i + width for i in x], verify_mem, width, label="Verify")

    ax.set_xlabel("Algorithm / Parameter Set")
    ax.set_ylabel("Peak memory (bytes)")
    ax.set_title("Signature Memory Usage Comparison")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
    ax.legend()
    fig.tight_layout()

    out_path = output_dir / filename
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path
