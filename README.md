# comp0031-group-research-project

### Group Research Project – Hybrid Information Security towards the Age of Quantum Computation\*\*

This repository contains a Python research framework for implementing and
benchmarking post-quantum cryptographic (PQC) Key Encapsulation Mechanisms
(KEMs) from the [NIST PQC Standards](https://csrc.nist.gov/projects/post-quantum-cryptography) published in August 2024.

---

## Algorithms

| Algorithm                                                                      | Family               | NIST Security Levels                                                                                                                       | Implementation Status |
| ------------------------------------------------------------------------------ | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | --------------------- |
| [FIPS-203 (ML-KEM)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)  | Module Lattice-based | ML-KEM-512, ML-KEM-768, ML-KEM-1024                                                                                                        | **Implemented**       |
| [FIPS-204 (ML-DSA)](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf)  | Module Lattice-based | ML-DSA-44, ML-DSA-65, ML-DSA-87                                                                                                            | **Implemented**       |
| [FIPS-205 (SLH-DSA)](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf) | Hash-based           | SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-256s, SLH-DSA-SHAKE-256f | **Implemented**       |

---

## Repository layout

```
src/
    algorithms/          # KEM algorithm modules + abstract base class
        base.py
        fips203.py
        fips204/         # FIPS 204 related codes
        fips205/         # FIPS 205 related codes
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
    qkd_simulation/
        bb84.py          # Simulation of QKD(BB84) using QISKIT
    hybrid/
        hybrid.py        # Hybrid simulation with PQC(FIPS-203) and QKD(BB84)
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
      "algorithm": "FIPS-203",
      "parameter_sets": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
      "num_trials": 100
    }
  ],
  "output_dir": "data"
}
```

Supported algorithm names: `"FIPS-203"`, `"Dilithium"`, `"SLH-DSA"`

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
