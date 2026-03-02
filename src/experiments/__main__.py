"""Allow ``python -m src.experiments.runner`` to execute the default experiment."""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run PQC KEM benchmarking experiments."
    )
    parser.add_argument(
        "--config",
        default=str(
            Path(__file__).resolve().parent / "configs" / "default.json"
        ),
        help="Path to a JSON or YAML experiment config file.",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Override the output directory for benchmark CSVs.",
    )
    parser.add_argument(
        "--summary",
        default="summary.csv",
        help="Filename for the aggregated summary CSV (default: summary.csv).",
    )
    args = parser.parse_args()

    from src.experiments.runner import ExperimentRunner

    output_dir = Path(args.output_dir) if args.output_dir else None
    runner = ExperimentRunner(args.config, output_dir=output_dir)

    print(f"Loading config: {args.config}")
    results = runner.run()
    summary_path = runner.save_summary(results, filename=args.summary)
    print(f"Done. {len(results)} experiment(s) completed.")
    print(f"Summary written to: {summary_path}")


if __name__ == "__main__":
    main()
