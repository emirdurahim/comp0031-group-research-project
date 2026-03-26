from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
from qiskit_aer.noise import NoiseModel, depolarizing_error
from typing import Literal
import random


class BB84:

    def __init__(self):
        error_rate = 0
        depol_error = depolarizing_error(error_rate, 1)
        noise_model = NoiseModel()
        noise_model.add_all_qubit_quantum_error(
            depol_error, ["h", "x", "u1", "u2", "u3"]
        )

        self._simulator = AerSimulator(noise_model=noise_model)

    def _encodes(self, bits: list[int], bases: list[int]) -> list[QuantumCircuit]:
        qubits = []
        for bit, basis in zip(bits, bases):
            qc = QuantumCircuit(1, 1)
            if bit == 1:
                qc.x(0)  # Flip qubit to become 1
            if basis == 0:
                qc.h(0)  # Change to X-basis
            qubits.append(qc)
        return qubits

    def _measure(self, qubits: list[QuantumCircuit], bases: list[int]) -> list[int]:
        bits = []
        for qubit, basis in zip(qubits, bases):
            if basis == 0:
                qubit.h(0)
            qubit.measure(0, 0)

            result = self._simulator.run(qubit, shots=1, memory=True).result()
            measured_bit = int(result.get_memory()[0])
            bits.append(measured_bit)
        return bits

    def generate_qubits(
        self, n: int
    ) -> tuple[list[int], list[int], list[QuantumCircuit]]:
        bits = [random.randint(0, 1) for _ in range(n)]
        bases = [random.randint(0, 1) for _ in range(n)]
        return bits, bases, self._encodes(bits, bases)

    def measure_qubits(
        self, qubits: list[QuantumCircuit]
    ) -> tuple[list[int], list[int]]:
        bases = [random.randint(0, 1) for _ in range(len(qubits))]
        return bases, self._measure(qubits, bases)

    def sifting(
        self, self_bases: list[int], other_bases: list[int], bits: list[int]
    ) -> list[int]:
        sifted_bits = []
        for self_basis, other_basis, bit in zip(self_bases, other_bases, bits):
            if self_basis == other_basis:
                sifted_bits.append(bit)

        return sifted_bits

    def initiate_qber(self, bits: list[int]) -> tuple[list[int], list[int]]:
        sample_size = int(len(bits) * 0.2)  # Use 20% of bits to perform QNER
        indices = random.sample(range(len(bits)), sample_size)
        qner_bits = []
        for index in sorted(indices, reverse=True):
            qner_bits.append(bits.pop(index))
        return indices, qner_bits

    def check_qber(
        self,
        bits: list[int],
        other_bits: list[int],
        indices: list[int],
        threshold: float = 0.11,
    ) -> bool:
        incorrect = 0
        for index, other_bit in zip(sorted(indices, reverse=True), other_bits):
            if other_bit != bits.pop(index):
                incorrect += 1
        return incorrect / len(indices) < threshold
