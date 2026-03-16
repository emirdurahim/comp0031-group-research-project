# COMP0031 Project Stages

A sequential breakdown of the project into digestible sub-tasks.
Each stage lists clear **pre-conditions** (what must be true before starting) and **post-conditions** (what must be true when finished).

---

## Stage 1 — Dependency Setup & Library Selection

**Goal:** Identify, install, and validate the Python bindings needed to execute real PQC algorithms.

| # | Task | Details |
|---|------|---------|
| 1.1 | Research PQC library options | Evaluate `liboqs-python` (Open Quantum Safe) and any CFFI/ctypes wrappers for BIKE, HQC, Classic McEliece, NTRU Prime, and NTRU LPRime. |
| 1.2 | Install chosen libraries inside `.venv` | `python -m pip install <package>` and verify imports succeed. |
| 1.3 | Update `requirements.txt` | Pin exact versions of all new cryptographic dependencies. |

**Pre-conditions:**
- Python virtual environment (`.venv`) is created and activated.
- Current codebase builds and runs with the existing placeholder stubs.

**Post-conditions:**
- All selected PQC libraries import successfully inside the `.venv`.
- `requirements.txt` reflects every new dependency with pinned versions.
- A brief note in the PR/commit message records *why* each library was chosen.

---

## Stage 2 — Cryptographic Integration: BIKE

**Goal:** Replace the placeholder stub in `src/algorithms/bike.py` with calls to the real cryptographic library.

| # | Task | Details |
|---|------|---------|
| 2.1 | Implement `bike.py` | Rewrite `keygen()`, `encapsulate()`, `decapsulate()` to use the real BIKE KEM. |

**Pre-conditions:**
- Stage 1 is complete; all PQC libraries are installed and importable.
- The `KEMAlgorithm` base interface in `src/algorithms/base.py` is understood and unchanged.

**Post-conditions:**
- The BIKE algorithm file calls the real cryptographic library (no `os.urandom` stubs remain).
- `keygen()` returns a valid key-pair; `encapsulate()` / `decapsulate()` produce matching shared secrets.
- BIKE implementation conforms to the `KEMAlgorithm` interface.

---

## Stage 3 — Cryptographic Integration: HQC

**Goal:** Replace the placeholder stub in `src/algorithms/hqc.py` with calls to the real cryptographic library.

| # | Task | Details |
|---|------|---------|
| 3.1 | Implement `hqc.py` | Rewrite `keygen()`, `encapsulate()`, `decapsulate()` to use the real HQC KEM. |

**Pre-conditions:**
- Stage 2 is complete.

**Post-conditions:**
- The HQC algorithm file calls the real cryptographic library.
- HQC implementation conforms to the `KEMAlgorithm` interface.

---

## Stage 4 — Cryptographic Integration: Classic McEliece

**Goal:** Replace the placeholder stub in `src/algorithms/mceliece.py` with calls to the real cryptographic library.

| # | Task | Details |
|---|------|---------|
| 4.1 | Implement `mceliece.py` | Rewrite `keygen()`, `encapsulate()`, `decapsulate()` to use the real Classic McEliece KEM. |

**Pre-conditions:**
- Stage 3 is complete.

**Post-conditions:**
- The Classic McEliece algorithm file calls the real cryptographic library.
- McEliece implementation conforms to the `KEMAlgorithm` interface.

---

## Stage 5 — Cryptographic Integration: Streamlined NTRU Prime

**Goal:** Replace the placeholder stub in `src/algorithms/ntru_prime.py` with calls to the real cryptographic library.

| # | Task | Details |
|---|------|---------|
| 5.1 | Implement `ntru_prime.py` | Rewrite `keygen()`, `encapsulate()`, `decapsulate()` to use the real Streamlined NTRU Prime KEM. |

**Pre-conditions:**
- Stage 4 is complete.

**Post-conditions:**
- The Streamlined NTRU Prime algorithm file calls the real cryptographic library.
- Streamlined NTRU Prime implementation conforms to the `KEMAlgorithm` interface.

---

## Stage 6 — Cryptographic Integration: NTRU LPRime

**Goal:** Replace the placeholder stub in `src/algorithms/ntru_lprime.py` with calls to the real cryptographic library.

| # | Task | Details |
|---|------|---------|
| 6.1 | Implement `ntru_lprime.py` | Rewrite `keygen()`, `encapsulate()`, `decapsulate()` to use the real NTRU LPRime KEM. |

**Pre-conditions:**
- Stage 5 is complete.

**Post-conditions:**
- The NTRU LPRime algorithm file calls the real cryptographic library.
- NTRU LPRime implementation conforms to the `KEMAlgorithm` interface.

---

## Stage 7 — Known Answer Tests (KATs) & Correctness Validation

**Goal:** Prove cryptographic correctness by verifying outputs against NIST-provided test vectors.

| # | Task | Details |
|---|------|---------|
| 7.1 | Obtain NIST KAT vectors | Download or embed the official Known Answer Test files for each algorithm. |
| 7.2 | Write KAT tests | Add tests in `tests/test_algorithms.py` that compare the framework's output against the NIST vectors. |
| 7.3 | Run & pass all tests | Execute `pytest tests/` and ensure zero failures. |

**Pre-conditions:**
- Stage 6 is complete; all five algorithm files are implemented with real crypto.

**Post-conditions:**
- `pytest tests/` passes with 100 % success.
- Each algorithm has at least one KAT test confirming output matches the NIST reference vector.

---

## Stage 8 — Experiment Configuration & Environment Isolation

**Goal:** Prepare the benchmarking environment for statistically significant, reproducible results.

| # | Task | Details |
|---|------|---------|
| 8.1 | Update experiment configs | In `src/experiments/configs/`, increase `num_trials` to ≥ 1 000 (or 10 000 for the final run). |
| 8.2 | Document environment controls | Record OS, CPU model, RAM, Python version. Disable non-essential background processes. Consider CPU affinity (`taskset`). |
| 8.3 | Dry-run with low trial count | Run `python -m src.experiments.runner` with ~50 trials to verify the pipeline end-to-end. |

**Pre-conditions:**
- Stage 7 is complete; all algorithms pass KAT tests.
- Benchmarking engine (`time.perf_counter`, `tracemalloc`) is functional (already confirmed).

**Post-conditions:**
- Config files reflect the agreed trial counts.
- A short dry-run completes without errors, and raw CSV data appears in `data/`.
- Environment specification document exists (hardware, OS, Python version, background process policy).

---

## Stage 9 — Full Benchmark Execution & Data Collection

**Goal:** Execute the final, high-trial-count experiment and collect raw data.

| # | Task | Details |
|---|------|---------|
| 9.1 | Run full experiment | `python -m src.experiments.runner` with the production config. |
| 9.2 | Validate output data | Confirm `data/` contains raw trial CSVs and aggregated summaries for all five algorithms × three operations. |
| 9.3 | Back up raw data | Copy/archive the raw CSV files outside the repo (they are `.gitignore`-d). |

**Pre-conditions:**
- Stage 8 is complete; dry-run succeeded and environment is isolated.

**Post-conditions:**
- Raw per-trial data and aggregated summaries exist in `data/`.
- No missing algorithm/operation combinations.
- Data files are backed up in a separate location.

---

## Stage 10 — Statistical Analysis

**Goal:** Derive rigorous statistics from the raw benchmark data.

| # | Task | Details |
|---|------|---------|
| 10.1 | Extend `src/analysis/stats.py` | Add confidence interval computation (e.g., 95 % CI), standard deviation, and p-value calculations for pair-wise algorithm comparisons. |
| 10.2 | Run analysis on collected data | Execute the analysis module and review the output for correctness. |
| 10.3 | Export summary tables | Generate a clean summary table (CSV or LaTeX) suitable for the paper. |

**Pre-conditions:**
- Stage 9 is complete; raw data is available in `data/`.

**Post-conditions:**
- Statistical summary (means, std devs, CIs, p-values) is computed and stored.
- Summary tables are ready for inclusion in the paper.

---

## Stage 11 — Visualization & Plot Generation

**Goal:** Produce publication-quality figures for the IEEE paper.

| # | Task | Details |
|---|------|---------|
| 11.1 | Generate comparison charts | Run `plot_timing_comparison`, `plot_key_sizes`, `plot_memory_usage`. |
| 11.2 | Add error bars | Incorporate standard-deviation or CI error bars into timing/memory plots. |
| 11.3 | Apply IEEE styling | Adjust fonts, labels, axis formatting, and legend placement to IEEE Transactions standards. |
| 11.4 | Export to `results/` | Save final figures as high-resolution PNGs/PDFs. |

**Pre-conditions:**
- Stage 10 is complete; statistical summaries and raw data are available.

**Post-conditions:**
- All required plots (timing, memory, key sizes) exist in `results/`.
- Plots include error bars and follow IEEE styling guidelines.
- Figures are referenced by filename for easy inclusion in the paper.

---

## Stage 12 — Research Paper Drafting

**Goal:** Write the 9-page IEEE Transactions-style group report.

| # | Task | Details |
|---|------|---------|
| 12.1 | Set up IEEE template | Create or obtain the LaTeX/Word IEEE Transactions template and enforce the 9-page limit (excl. references). |
| 12.2 | Draft Abstract & Introduction | Define the PQC landscape, NIST context, and research motivation. |
| 12.3 | Draft Related Work | Discuss NIST IR 8413/8545 and prior benchmarking studies. |
| 12.4 | Draft Hypothesis & Experiment Design | Detail the benchmarking framework, tracked metrics (speed, size, memory), and environmental controls. |
| 12.5 | Draft Analysis of Results | Embed Phase 11 charts and present statistical findings. |
| 12.6 | Draft Discussion & Limitations | Address anomalies (e.g., McEliece key-gen time) and environment limitations. |
| 12.7 | Draft Conclusion & Future Work | Provide a final verdict and outline next research directions. |
| 12.8 | Peer review & final edit | Internal group review for clarity, consistency, and page-limit compliance. |

**Pre-conditions:**
- Stages 10 and 11 are complete; statistical summaries and publication-quality plots are ready.

**Post-conditions:**
- A complete 9-page IEEE-formatted paper is ready for submission.
- All figures and tables are embedded and correctly referenced.
- References section is complete.

---

## Stage 13 — Submission & IPAC

**Goal:** Submit all deliverables and complete the peer assessment.

| # | Task | Details |
|---|------|---------|
| 13.1 | Final paper review | One last read-through by all group members. |
| 13.2 | Submit research paper | Upload the final PDF per COMP0031 submission guidelines. |
| 13.3 | Complete IPAC | Each member fills in the Individual Peer Assessment of Contribution on Moodle. |

**Pre-conditions:**
- Stage 12 is complete; the paper is finalized and approved by all members.

**Post-conditions:**
- Paper is submitted on time.
- All IPAC forms are completed on Moodle.

---

## Dependency Graph (Summary)

```
Stage 1 → Stage 2 → Stage 3 → Stage 4 → Stage 5 → Stage 6 → Stage 7 → Stage 8 → Stage 9 → Stage 10 → Stage 11 → Stage 12 → Stage 13
```

Every stage is strictly sequential; each depends on the successful completion of the one before it.
