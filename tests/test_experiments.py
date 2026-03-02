"""Tests for the experiment runner and config loader."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.experiments.config import ExperimentConfig, ExperimentEntry, load_config
from src.experiments.runner import ExperimentRunner


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

class TestLoadConfig:
    def test_load_json(self, tmp_path):
        cfg = {
            "experiments": [
                {
                    "algorithm": "BIKE",
                    "parameter_sets": ["Level-1"],
                    "num_trials": 3,
                }
            ],
            "output_dir": "data",
        }
        p = tmp_path / "cfg.json"
        p.write_text(json.dumps(cfg))

        config = load_config(p)
        assert isinstance(config, ExperimentConfig)
        assert len(config.experiments) == 1
        assert config.experiments[0].algorithm == "BIKE"
        assert config.experiments[0].num_trials == 3

    def test_load_yaml(self, tmp_path):
        pytest.importorskip("yaml")
        content = (
            "experiments:\n"
            "  - algorithm: HQC\n"
            "    parameter_sets:\n"
            "      - HQC-128\n"
            "    num_trials: 5\n"
            "output_dir: data\n"
        )
        p = tmp_path / "cfg.yaml"
        p.write_text(content)

        config = load_config(p)
        assert config.experiments[0].algorithm == "HQC"
        assert config.experiments[0].num_trials == 5

    def test_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "nonexistent.json")

    def test_unsupported_extension(self, tmp_path):
        p = tmp_path / "cfg.toml"
        p.write_text("[experiments]")
        with pytest.raises(ValueError, match="Unsupported"):
            load_config(p)

    def test_default_num_trials(self, tmp_path):
        cfg = {
            "experiments": [
                {"algorithm": "BIKE", "parameter_sets": ["Level-1"]}
            ]
        }
        p = tmp_path / "cfg.json"
        p.write_text(json.dumps(cfg))
        config = load_config(p)
        assert config.experiments[0].num_trials == 10

    def test_default_output_dir(self, tmp_path):
        cfg = {"experiments": []}
        p = tmp_path / "cfg.json"
        p.write_text(json.dumps(cfg))
        config = load_config(p)
        assert config.output_dir == "data"


# ---------------------------------------------------------------------------
# ExperimentEntry dataclass
# ---------------------------------------------------------------------------

class TestExperimentEntry:
    def test_defaults(self):
        entry = ExperimentEntry(algorithm="BIKE", parameter_sets=["Level-1"])
        assert entry.num_trials == 10

    def test_custom_trials(self):
        entry = ExperimentEntry(
            algorithm="HQC", parameter_sets=["HQC-128"], num_trials=25
        )
        assert entry.num_trials == 25


# ---------------------------------------------------------------------------
# ExperimentRunner
# ---------------------------------------------------------------------------

class TestExperimentRunner:
    def _small_config(self) -> ExperimentConfig:
        return ExperimentConfig(
            experiments=[
                ExperimentEntry(
                    algorithm="BIKE",
                    parameter_sets=["Level-1"],
                    num_trials=2,
                )
            ],
            output_dir="data",
        )

    def test_run_returns_results(self, tmp_path):
        runner = ExperimentRunner(self._small_config(), output_dir=tmp_path)
        results = runner.run()
        assert len(results) == 1

    def test_run_multiple_param_sets(self, tmp_path):
        config = ExperimentConfig(
            experiments=[
                ExperimentEntry(
                    algorithm="HQC",
                    parameter_sets=["HQC-128", "HQC-192"],
                    num_trials=2,
                )
            ],
            output_dir="data",
        )
        runner = ExperimentRunner(config, output_dir=tmp_path)
        results = runner.run()
        assert len(results) == 2

    def test_save_summary_writes_csv(self, tmp_path):
        runner = ExperimentRunner(self._small_config(), output_dir=tmp_path)
        results = runner.run()
        csv_path = runner.save_summary(results)
        assert csv_path.exists()
        text = csv_path.read_text()
        assert "algorithm" in text

    def test_save_summary_empty_returns_path(self, tmp_path):
        runner = ExperimentRunner(self._small_config(), output_dir=tmp_path)
        path = runner.save_summary([])
        assert isinstance(path, Path)

    def test_unknown_algorithm_raises(self, tmp_path):
        config = ExperimentConfig(
            experiments=[
                ExperimentEntry(
                    algorithm="FakeKEM",
                    parameter_sets=["Level-1"],
                    num_trials=1,
                )
            ],
            output_dir="data",
        )
        runner = ExperimentRunner(config, output_dir=tmp_path)
        with pytest.raises(ValueError, match="Unknown algorithm"):
            runner.run()

    def test_load_from_json_file(self, tmp_path):
        cfg = {
            "experiments": [
                {"algorithm": "BIKE", "parameter_sets": ["Level-1"], "num_trials": 1}
            ],
            "output_dir": "data",
        }
        p = tmp_path / "cfg.json"
        p.write_text(json.dumps(cfg))
        runner = ExperimentRunner(p, output_dir=tmp_path)
        results = runner.run()
        assert len(results) == 1

    def test_default_config_file_is_valid(self):
        """Ensure the bundled default.json config loads without error."""
        default_cfg = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "experiments"
            / "configs"
            / "default.json"
        )
        config = load_config(default_cfg)
        assert len(config.experiments) == 5
