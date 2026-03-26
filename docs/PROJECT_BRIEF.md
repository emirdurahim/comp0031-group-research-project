# COMP0031 Project Brief: Benchmarking FIPS-Standardized Post-Quantum Cryptography

## 1. Project Overview
[cite_start]**Objective:** Build a reproducible, research-grade Python benchmarking framework to evaluate the finalized National Institute of Standards and Technology (NIST) Post-Quantum Cryptography (PQC) standards: FIPS 203, FIPS 204, and FIPS 205[cite: 6342]. 
[cite_start]**Target Output:** A 9-page IEEE Transactions-style research paper analyzing the performance, memory, and size trade-offs of these standardized algorithms for the COMP0031 Group Research Project[cite: 855, 894].

## 2. Target Algorithms (The FIPS Standards)
The project focus has explicitly shifted away from the Round 4 candidates to the officially approved standards. The framework must implement and benchmark:

* [cite_start]**FIPS 203 (ML-KEM):** The Module-Lattice-Based Key-Encapsulation Mechanism[cite: 1096]. 
    * [cite_start]*Approved Parameter Sets:* ML-KEM-512, ML-KEM-768, and ML-KEM-1024[cite: 1122].
* [cite_start]**FIPS 204 (ML-DSA):** The Module-Lattice-Based Digital Signature Algorithm[cite: 2596]. 
    * [cite_start]*Approved Parameter Sets:* ML-DSA-44, ML-DSA-65, and ML-DSA-87[cite: 2909].
* [cite_start]**FIPS 205 (SLH-DSA):** The Stateless Hash-Based Digital Signature Algorithm[cite: 4358].
    * [cite_start]*Approved Parameter Sets:* SHA2 and SHAKE variants across varying security categories, including fast ('f') and small ('s') variants (e.g., SLH-DSA-SHA2-128s, SLH-DSA-SHAKE-256f)[cite: 5902].

## 3. Current Codebase State & Necessary Architectural Changes
* **Current State:** The repository is modular and config-driven, but currently houses placeholder stubs for old Round 4 candidates (BIKE, HQC, Classic McEliece, NTRU Prime) that return `os.urandom` bytes. Furthermore, the `base.py` interface is strictly designed for KEMs (`keygen`, `encapsulate`, `decapsulate`).
* [cite_start]**Required Architectural Shift:** Because FIPS 204 and FIPS 205 are digital signature algorithms[cite: 2596, 4358], the base interface must be expanded or split. [cite_start]Digital signatures require signature generation using a private key and signature verification using a public key, which differs from KEM encapsulation/decapsulation[cite: 2638, 2639, 4399, 4400].

---

## 4. Phased Execution Plan

### Phase 1: Cryptographic Integration (Standardization Shift)
* **Step 1.1:** Deprecate and remove the legacy Round 4 algorithms from `src/algorithms/` and the algorithm registry in `runner.py`.
* **Step 1.2:** Update `base.py` to support two distinct abstract base classes: one for KEMs (FIPS 203) and one for Digital Signatures (FIPS 204, 205).
* **Step 1.3:** Install reliable Python bindings (e.g., `liboqs-python`) that support the finalized FIPS standards, updating `requirements.txt`.
* **Step 1.4:** Implement wrapper classes for ML-KEM, ML-DSA, and SLH-DSA, ensuring they return mathematically correct cryptographic operations rather than placeholder bytes. 
* **Step 1.5:** Write Known Answer Tests (KATs) in `tests/test_algorithms.py` to ensure outputs match NIST-provided test vectors exactly.

### Phase 2: Rigorous Benchmarking & Data Collection
* **Step 2.1:** Overhaul the experiment configurations (`src/experiments/configs/default.json` and `default.yaml`) to map to the new FIPS parameter sets.
* **Step 2.2:** Adjust `metrics.py` to track public key sizes, private key sizes, and ciphertext sizes for ML-KEM, as well as signature sizes for ML-DSA and SLH-DSA.
* **Step 2.3:** Execute `python -m src.experiments.runner` using a statistically significant number of trials (e.g., `num_trials: 1000`).
* **Step 2.4:** Collect wall-clock time (`time.perf_counter`) and peak memory usage (`tracemalloc`) data, saving to CSV in the `data/` directory.

### Phase 3: Statistical Analysis & Visualization
* **Step 3.1:** Run `src/analysis/stats.py` to aggregate the CSV trial data into mean, standard deviation, min, and max metrics.
* **Step 3.2:** Generate Matplotlib charts using `src/analysis/plots.py` to visually compare timing, key sizes, and memory usage between the three FIPS standards.

### Phase 4: Constructing the Research Paper
* [cite_start]**Step 4.1:** Format the report to a strict maximum of 9 pages (excluding references) using the IEEE Transactions style[cite: 894].
* **Step 4.2:** Draft the report following the required structure:
    * **1. [cite_start]Introduction:** Discuss the threat of quantum computing to RSA/ECC and the 2024 NIST FIPS standardizations[cite: 6121, 6342].
    * **2. Related Work:** Review other benchmarking literature.
    * **3. [cite_start]Research Hypothesis:** Define the specific questions regarding the performance trade-offs between lattice-based (FIPS 203/204) and hash-based (FIPS 205) cryptography[cite: 863, 6138].
    * **4. [cite_start]Experiment Design:** Detail the methodology, dataset collection, metrics, and benchmarks [cite: 882-886].
    * **5. [cite_start]Analysis of Results:** Embed the generated charts and discuss the statistical data[cite: 887].
    * **6. [cite_start]Discussion and Limitations:** Interpret the findings and state any constraints of the experimental setup[cite: 888].
    * **7. [cite_start]Conclusion and Future Work:** Summarize the operational implications for migrating to PQC[cite: 889, 6250].
* **Step 4.3:** Ensure all text is original; use of generative AI tools must adhere to UCL policy[cite: 1050, 1053]. 
* [cite_start]**Step 4.4:** Complete the Individual Peer Assessment of Contribution (IPAC) via Moodle before the deadline (Monday 30 March 2026 at 16:00 UK time)[cite: 873, 1065].