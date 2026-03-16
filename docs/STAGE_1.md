# Stage 1 Detailed Implementation: Dependency Setup & Library Selection

This document expands upon Stage 1 from the master `STAGES.md` roadmap. It provides concrete instructions, evaluation metrics for libraries, and a rigorous, test-driven validation plan for the chosen Post-Quantum Cryptography (PQC) libraries.

## 1. Objectives

The primary objective of Stage 1 is to locate, install, and validate Python bindings capable of securely and efficiently executing the following NIST Round 4 PQC Key Encapsulation Mechanisms (KEMs):
1.  **BIKE**
2.  **HQC**
3.  **Classic McEliece**
4.  **Streamlined NTRU Prime**
5.  **NTRU LPRime**

## 2. Implementation Steps

### 2.1 Research and Evaluate Libraries
Not all PQC libraries in Python are production-ready or offer coverage for all five algorithms.

**Primary Candidate:** `liboqs-python` (Open Quantum Safe)
-   **Pros:** Backed by the robust C-based `liboqs`, actively maintained, tracks NIST rounds closely.
-   **Cons:** Requires the underlying C library to be built or available on the host system.

**Secondary Candidates:** Standalone CFFI/ctypes wrappers for specific algorithms (if `liboqs` lacks support or fails to compile on the target benchmarking hardware).

**Action Required:**
-   Verify if `liboqs-python` explicitly supports the exact parameter sets (e.g., `Kyber512`, `Classic-McEliece-348864`) needed for the benchmark.
-   Document the findings in a brief architectural decision record (ADR) appended to this repository (e.g., in a PR description).

### 2.2 Installation within the Virtual Environment
To ensure benchmark reproducibility, the environment must be strictly isolated.

**Action Required:**
1.  Ensure `.venv` is active: `source .venv/bin/activate` (Mac/Linux) or `.venv\Scripts\activate` (Windows).
2.  Install the chosen package(s). Example:
    ```bash
    python -m pip install liboqs-python
    ```
3.  If building from source is required (often true for `liboqs`), document the *exact* build string (e.g., `cmake .. -DOQS_USE_OPENSSL=ON`).

### 2.3 Dependency Pinning
The exact state of the environment must be captured so the 9-page IEEE paper is fundamentally reproducible by external researchers.

**Action Required:**
1.  Run `python -m pip freeze > requirements_temp.txt`.
2.  Identify the installed PQC libraries (and their direct dependencies) from `requirements_temp.txt`.
3.  Append these to the project's official `requirements.txt` using exact version pinning (e.g., `liboqs-python==0.8.0`).

---

## 3. Comprehensive Unit Testing Plan

The successful completion of Stage 1 is **not** determined simply by a successful `pip install`. The environment must empirically prove that the libraries are accessible and functional. 

The following tests must be implemented (e.g., in `tests/test_stage1_env.py`) and must pass 100%.

### 3.1 Test Suite: `TestLibraryAvailability`

1.  **`test_liboqs_import_successful()`**
    *   **Description:** Asserts that `import oqs` does not throw an `ImportError` or `ModuleNotFoundError`.
    *   **Purpose:** Verifies the C-bindings are correctly linked to the active Python interpreter.

2.  **`test_target_kems_enabled()`**
    *   **Description:** Inspects the library's registry (e.g., `oqs.get_enabled_KEM_mechanisms()`) and asserts that *all five* target algorithm strings (BIKE, HQC, McEliece, NTRU Prime, NTRU LPRime) are present in the list.
    *   **Purpose:** Ensures the underlying C-library was compiled with support for the specific algorithms we are benchmarking.

### 3.2 Test Suite: `TestBasicAPIExecution`

These tests verify that the library can perform a dry-run without segfaulting, validating the interface before we integrate it into our `src/algorithms/` stubs in Stage 2.

1.  **`test_bike_instantiation()`**
    *   **Description:** Attempts to instantiate the BIKE KEM object (e.g., `with oqs.KeyEncapsulation('BIKE1-L1-CPA') as kem:`).
    *   **Purpose:** Validates the constructor and memory allocation for the algorithm.

2.  **`test_hqc_instantiation()`**
    *   **Description:** Attempts to instantiate the HQC KEM object.

3.  **`test_mceliece_instantiation()`**
    *   **Description:** Attempts to instantiate the Classic McEliece KEM object.

4.  **`test_ntru_prime_instantiation()`**
    *   **Description:** Attempts to instantiate the Streamlined NTRU Prime KEM object.

5.  **`test_ntru_lprime_instantiation()`**
    *   **Description:** Attempts to instantiate the NTRU LPRime KEM object.

### 3.3 Test Suite: `TestMemorySafeguards` (Optional but Recommended)

Because PQC wrappers often use CFFI to allocate C-level memory, improper teardown can cause memory leaks—ruining our `tracemalloc` memory benchmarking later.

1.  **`test_context_manager_cleanup()`**
    *   **Description:** Instantiates a KEM object, forces garbage collection or exits the `with` block, and asserts that the object's pointer is safely freed/nullified.
    *   **Purpose:** Prevents C-level memory leaks from invalidating Stage 5 benchmarks.

---

## 4. Stage 1 Acceptance Criteria

Before moving to **Stage 2** (where we rewrite `bike.py`, `hqc.py`, etc.), the following must be true:
- [ ] `import oqs` (or chosen alternative) works locally and on any CI pipeline.
- [ ] `pytest tests/test_stage1_env.py` passes completely.
- [ ] `requirements.txt` contains pinned versions for the cryptographic libraries.
