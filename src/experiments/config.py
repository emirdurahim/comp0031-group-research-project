"""Experiment configuration loading.

Supports JSON and YAML configuration files.  Each config file describes
one or more experiment entries, each specifying an algorithm, a list of
parameter sets, and the number of benchmark trials.

Schema (JSON / YAML)
--------------------
.. code-block:: json

    {
      "experiments": [
        {
          "algorithm": "BIKE",
          "parameter_sets": ["Level-1", "Level-3"],
          "num_trials": 20
        }
      ],
      "output_dir": "data"
    }
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml  # type: ignore[import]

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


@dataclass
class ExperimentEntry:
    """A single experiment specification."""

    algorithm: str
    parameter_sets: List[str]
    num_trials: int = 10


@dataclass
class ExperimentConfig:
    """Top-level experiment configuration.

    Attributes
    ----------
    experiments:
        List of :class:`ExperimentEntry` objects to run.
    output_dir:
        Where benchmark CSVs should be written (default: ``"data"``).
    """

    experiments: List[ExperimentEntry] = field(default_factory=list)
    output_dir: str = "data"


def load_config(path: str | Path) -> ExperimentConfig:
    """Load an experiment config from a JSON or YAML file.

    Parameters
    ----------
    path:
        Path to the configuration file.  The file extension determines
        the parser: ``.json`` uses the stdlib JSON parser; ``.yaml`` /
        ``.yml`` use PyYAML (must be installed).

    Returns
    -------
    ExperimentConfig

    Raises
    ------
    ValueError
        If the file extension is not recognised or if PyYAML is needed
        but not installed.
    FileNotFoundError
        If *path* does not exist.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    suffix = path.suffix.lower()
    if suffix == ".json":
        with path.open("r", encoding="utf-8") as fh:
            raw: Dict[str, Any] = json.load(fh)
    elif suffix in {".yaml", ".yml"}:
        if not _YAML_AVAILABLE:
            raise ValueError(
                "PyYAML is required to load YAML configs. "
                "Install it with: pip install pyyaml"
            )
        with path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    else:
        raise ValueError(
            f"Unsupported config file format {suffix!r}. Use .json or .yaml/.yml"
        )

    return _parse_config(raw)


def _parse_config(raw: Dict[str, Any]) -> ExperimentConfig:
    """Convert a raw dict (from JSON/YAML) into an :class:`ExperimentConfig`."""
    entries: List[ExperimentEntry] = []
    for entry_data in raw.get("experiments", []):
        entries.append(
            ExperimentEntry(
                algorithm=entry_data["algorithm"],
                parameter_sets=list(entry_data.get("parameter_sets", [])),
                num_trials=int(entry_data.get("num_trials", 10)),
            )
        )
    return ExperimentConfig(
        experiments=entries,
        output_dir=raw.get("output_dir", "data"),
    )
