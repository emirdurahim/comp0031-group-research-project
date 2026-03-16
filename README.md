# comp0031-group-research-project

**Group Research Project – Hybrid Information Security towards the Age of Quantum Computation**

This repository contains a Python research framework for implementing and
benchmarking post-quantum cryptographic (PQC) Key Encapsulation Mechanisms
(KEMs) from the [NIST Fourth Round PQC Standardisation](https://csrc.nist.gov/publications/detail/nistir/8413/final).

---

## Algorithms

| Algorithm                                                                     | Family               | NIST Security Levels                  | Implementation Status |
| ----------------------------------------------------------------------------- | -------------------- | ------------------------------------- | --------------------- |
| [BIKE](https://bikesuite.org/)                                                | Code-based           | 1, 3, 5                               | Not Implemented       |
| [HQC](https://pqc-hqc.org/)                                                   | Code-based           | 1 (HQC-128), 3 (HQC-192), 5 (HQC-256) | Not Implemented       |
| [Classic McEliece](https://classic.mceliece.org/)                             | Code-based           | 1–5 (5 parameter sets)                | Not Implemented       |
| [Streamlined NTRU Prime](https://ntruprime.cr.yp.to/)                         | NTRU-based           | sntrup653–sntrup1277                  | Not Implemented       |
| [NTRU LPRime](https://ntruprime.cr.yp.to/)                                    | NTRU-based           | ntrulpr653–ntrulpr1277                | Not Implemented       |
| [FIPS-203 (ML-KEM)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) | Module Lattice-based | ML-KEM-512, ML-KEM-768, ML-KEM-1024   | **Implemented**       |

> **Note:** The cryptographic algorithm bodies are **placeholder stubs** that
> return random bytes of the correct sizes. They exercise the full benchmarking
> pipeline but do not provide real security. Implement the cryptographic
> operations inside each `src/algorithms/*.py` module to replace the stubs.

---

## Repository layout

```
src/
    algorithms/          # KEM algorithm modules + abstract base class
        base.py
        bike.py
        hqc.py
        mceliece.py
        ntru_prime.py
        ntru_lprime.py
    benchmarks/          # Timing & memory measurement framework
        metrics.py
        runner.py
    experiments/         # Config-driven experiment orchestration
        config.py
        runner.py
        configs/
            default.json
            default.yaml
    analysis/            # Plotting and statistical helpers
        plots.py
        stats.py
tests/                   # pytest test suite
data/                    # Benchmark CSV output (git-ignored)
results/                 # Generated figures (git-ignored)
requirements.txt
```

---

## Quick start

### 1 – Create and activate a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate        # Linux / macOS
.venv\Scripts\activate           # Windows
```

### 2 – Install dependencies

```bash
pip install -r requirements.txt
```

### 3 – Run the test suite

```bash
pytest tests/ -v
```

### 4 – Run the default experiment

```bash
python -m src.experiments.runner
```

Or from a Python script:

```python
from src.experiments.runner import ExperimentRunner

runner = ExperimentRunner("src/experiments/configs/default.json")
results = runner.run()
runner.save_summary(results)          # writes data/summary.csv
```

### 5 – Generate plots

```python
from src.analysis.stats import load_summary_csv
from src.analysis.plots import plot_timing_comparison, plot_key_sizes

rows = load_summary_csv("data/summary.csv")
plot_timing_comparison(rows)   # saves results/timing_comparison.png
plot_key_sizes(rows)           # saves results/key_sizes.png
```

---

## Configuration files

Experiments are described in JSON or YAML files (see
`src/experiments/configs/default.json`):

```json
{
  "experiments": [
    {
      "algorithm": "BIKE",
      "parameter_sets": ["Level-1", "Level-3", "Level-5"],
      "num_trials": 10
    }
  ],
  "output_dir": "data"
}
```

Supported algorithm names: `"BIKE"`, `"HQC"`, `"Classic McEliece"`,
`"Streamlined NTRU Prime"`, `"NTRU LPRime"`.

---

## Extending the project

1. **Implement a real algorithm** – replace the stub body in the relevant
   `src/algorithms/*.py` module. The `keygen`, `encapsulate`, and `decapsulate`
   methods must satisfy the interface defined in `src/algorithms/base.py`.

2. **Add a new algorithm** – subclass `KEMAlgorithm`, register it in
   `src/experiments/runner._ALGORITHM_REGISTRY`, and export it from
   `src/algorithms/__init__.py`.

3. **Custom experiments** – create a new JSON/YAML config file and pass its
   path to `ExperimentRunner`.

---

## Reproducibility

- Pin exact versions with `pip freeze > requirements-lock.txt`.
- The benchmarks use `time.perf_counter` (wall-clock) and `tracemalloc`
  (heap) for measurements. For more deterministic results, disable
  background processes and use CPU affinity tools (e.g. `taskset` on Linux).
- Random keys are generated with `os.urandom`; the stubs are inherently
  non-deterministic (as real KEMs would be).

---

## Licence

See [LICENSE](LICENSE).
