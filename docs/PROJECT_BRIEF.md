# COMP0031 Project Brief: Hybrid Information Security towards the Age of Quantum Computation

## 1. Project Overview
**Objective:** Build a reproducible, research-grade Python benchmarking framework to evaluate five Post-Quantum Cryptographic (PQC) Key Encapsulation Mechanisms (KEMs) based on the NIST Fourth Round evaluation criteria.
**Target Algorithms:** BIKE, HQC, Classic McEliece, Streamlined NTRU Prime, NTRU LPRime.
**Target Output:** A 9-page IEEE Transactions-style research paper analyzing the speed, memory, and size trade-offs of these algorithms.

## 2. Current Codebase State
* **Architecture:** Modular, config-driven, and structurally sound. The `KEMAlgorithm` base interface is strictly enforced.
* **Benchmarking Engine:** Fully functional. Measures wall-clock time (`time.perf_counter`) and peak heap allocation (`tracemalloc`) for Keygen, Encapsulation, and Decapsulation.
* **Analysis & Plotting:** CSV aggregation and Matplotlib bar charts (timing, memory, sizes) are operational.
* **CRITICAL GAP:** The algorithms (`src/algorithms/*.py`) are currently **placeholder stubs** returning `os.urandom` bytes. They do not execute real cryptographic mathematics.

---

## 3. Phased Execution Plan

### Phase 1: Cryptographic Integration (High Priority)
The immediate next step is to replace the placeholder stubs with real cryptographic math.
* **Step 1.1:** Identify and install Python bindings for the target PQC algorithms (e.g., `liboqs-python` via the Open Quantum Safe project, or CFFI wrappers).
* **Step 1.2:** Update `requirements.txt` with the new cryptographic dependencies.
* **Step 1.3:** Rewrite the `keygen()`, `encapsulate()`, and `decapsulate()` methods in `bike.py`, `hqc.py`, `mceliece.py`, `ntru_prime.py`, and `ntru_lprime.py` to call the real cryptographic libraries instead of `os.urandom`.
* **Step 1.4:** Implement Known Answer Tests (KATs) in `tests/test_algorithms.py` to ensure the outputs exactly match NIST-provided test vectors.

### Phase 2: Rigorous Benchmarking & Data Collection
Once the cryptography is real, transition to formal data collection.
* **Step 2.1:** Modify the experiment configurations (`src/experiments/configs/default.json` and `default.yaml`). Increase the `num_trials` from `10` to a statistically significant number (e.g., 1,000 or 10,000) for the final run.
* **Step 2.2:** Isolate the testing environment. Disable background processes and consider CPU affinity tools (e.g., `taskset` on Linux) to ensure deterministic timing measurements.
* **Step 2.3:** Execute the main experiment runner: `python -m src.experiments.runner`.
* **Step 2.4:** Verify that raw trial data and aggregated summaries are correctly populated in the `data/` directory.

### Phase 3: Statistical Analysis & Visualization
Process the raw data for inclusion in the final research paper.
* **Step 3.1:** Extend `src/analysis/stats.py` to calculate advanced statistics, such as confidence intervals and p-values, to compare algorithm performance rigorously.
* **Step 3.2:** Run the plotting utilities (`plot_timing_comparison`, `plot_key_sizes`, `plot_memory_usage`) to generate figures in the `results/` folder.
* **Step 3.3:** Refine Matplotlib styling (labels, fonts, error bars from standard deviations) to meet IEEE academic publishing standards.

### Phase 4: Constructing the Research Paper
Use the generated data and plots to write the COMP0031 Group Report.
* **Step 4.1:** Format the document to the IEEE Transactions style with a strict 9-page limit (excluding references).
* **Step 4.2:** Draft the sections according to the COMP0031 syllabus structure:
  * **Abstract & Introduction:** Define the PQC landscape and the NIST context.
  * **Related Work:** Discuss NIST IR 8413/8545 and other benchmarking studies.
  * **Research Hypothesis & Experiment Design:** Detail the benchmarking framework, metrics tracked (speed, size, memory), and environmental controls.
  * **Analysis of Results:** Embed the generated charts from Phase 3 and present the statistical findings.
  * **Discussion & Limitations:** Address anomalies (e.g., McEliece's massive key generation time) and limitations of the testing environment.
  * **Conclusion & Future Work:** Final verdict on the algorithms based on the data.
* **Step 4.3:** Complete the Individual Peer Assessment of Contribution (IPAC) on Moodle.

---

## 4. Repository & Development Rules
To maintain the integrity of the research framework:
1. **Virtual Environment Isolation:** All package installations must be done within the active `.venv` using `python -m pip install`.
2. **Clean Git History:** Use the **Squash and Merge** strategy on GitHub to keep the main branch history linear, clean, and professional.
3. **Never Commit Data/Artifacts:** Ensure `.venv/`, `__pycache__/`, raw `data/*.csv`, and generated `results/*.png` remain ignored via `.gitignore`.