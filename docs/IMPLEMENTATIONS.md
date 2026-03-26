# PQC Algorithms: Implementation Details

This document provides a comprehensive overview of the cryptographic implementations currently integrated into the repository for the COMP0031 Group Research Project. It serves as a technical orientation for team members to understand the architecture, module relationships, and status of the finalized NIST Post-Quantum Cryptography (PQC) standards.

---

## 1. Architectural Paradigm Shift

Previously, the framework relied on placeholder implementations for NIST Round 4 KEM candidates (BIKE, HQC, Classic McEliece, NTRU Prime). To align with the finalized FIPS standardizations, the architecture has been rewritten.

### `src/algorithms/base.py`
The base interface formerly assumed all algorithms were Key-Encapsulation Mechanisms (KEMs). Because FIPS 204 and FIPS 205 are digital signature algorithms, the base interface has been cleanly split into two abstract base classes:
*   `KEMAlgorithm`: Contains `keygen()`, `encapsulate()`, and `decapsulate()` methods.
*   `SignatureAlgorithm`: Contains `keygen()`, `sign()`, and `verify()` methods.

---

## 2. FIPS 205: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
**Status:** ✅ Fully Implemented and Verified (Pure Python)
**Location:** `src/algorithms/fips205/`

SLH-DSA is a highly complex, purely hash-based signature algorithm completely abstracted from mathematical trapdoors (no lattices). It has been built from scratch internally, mapping exactly to the FIPS 205 guidelines.

### Internal Module Structure:
To ensure testability and isolation, SLH-DSA has been separated into strictly bounded components:
1.  **`parameters.py`**: Defines the approved configurations (e.g., `SLH-DSA-SHAKE-128f`, `SLH-DSA-SHAKE-256s`). Note: Only the purely SHAKE-based parameters are currently configured for evaluation (`f` represents fast signing, `s` represents small signatures).
2.  **`address.py`**: Implements the `ADRS` 32-byte address structure used to provide cryptographic domain separation for every single hash call within the algorithm.
3.  **`hash_functions.py`**: Configures the tweakable hash functions (`H_msg`, `PRF`, `PRF_msg`, `F`, `H`, `T_len`) built on top of `hashlib.shake_256`. 
4.  **`wots.py`**: The Winternitz One-Time Signature (WOTS+) scheme, used to sign the roots of the sub-trees.
5.  **`fors.py`**: The Forest of Random Subsets (FORS), a few-time signature scheme used to sign the actual message digest at the bottom-most layer.
6.  **`xmss.py`**: The extended Merkle Signature Scheme (eXtended Merkle Signature Scheme). It constructs the Trees and the overarching Hypertree.
7.  **`core.py`**: Binds the modules together for the public algorithms: `slh_keygen()`, `slh_sign()`, and `slh_verify()`.

**Interactive Demo:** You can run a purely interactive demonstration of SLH-DSA by running:
```bash
python src/algorithms/fips205/demo.py
```

---

## 3. FIPS 204: ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
**Status:** ✅ Implemented and Validated 
**Location:** `src/algorithms/dilithium/` 

Formerly known as CRYSTALS-Dilithium. It is registered within our system as a `SignatureAlgorithm`.

*   **Parameters:** `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`
*   **Key Behavior:** Uses Module Learning with Errors (MLWE) across polynomial rings. Validation tests are currently active and passing inside `tests/test_algorithms.py::TestDilithium`.

---

## 4. FIPS 203: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
**Status:** 🚧 Implemented (Needs Debugging)
**Location:** `src/algorithms/fips203.py`

Formerly known as CRYSTALS-Kyber. ML-KEM is the only finalized key exchange standard in the suite. Registered to the `KEMAlgorithm` interface.

*   **Parameters:** `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024`
*   **Current State:** The algorithm logic is populated, but currently throws a `ValueError: Invalid parameters` during the `test_interface` tests due to a mathematical discrepancy in the re-encoding phase (`re_encoded_t_hat != t_hat_bytes`) during encapsulation. **This is the primary pending task.**

---

## 5. Testing & Benchmarking 

### Comprehensive Pytest Suite
We test all algorithm parameters individually against the established `base.py` interfaces. 
To verify all algorithms, run:
```bash
export PYTHONPATH=. 
pytest tests/test_algorithms.py -v
```
To test SLH-DSA modularly:
```bash
export PYTHONPATH=. 
pytest tests/test_fips205_*.py -v
```

### Benchmarking Framework
The benchmarking configuration has been overhauled from the default boilerplate to exclusively test the FIPS algorithms.
**Configuration:** `src/experiments/configs/default.json` and `default.yaml`

To run data collection to extract timing and memory metrics over hundreds of iterations (Output dumps to `data/`):
```bash
export PYTHONPATH=. 
python -m src.experiments.runner
```
*Note: Ensure `ML-KEM` bugs are patched before attempting large-scale data collection!*
