"""Base interfaces for PQC algorithm implementations.

KEM algorithms derive from :class:`KEMAlgorithm` and must provide:

* :meth:`keygen`      – generate a public/secret key pair
* :meth:`encapsulate` – produce a ciphertext and a shared secret
* :meth:`decapsulate` – recover the shared secret from the ciphertext

Digital-signature algorithms derive from :class:`SignatureAlgorithm` and must
provide:

* :meth:`keygen` – generate a public/secret key pair
* :meth:`sign`   – produce a signature over a message
* :meth:`verify` – verify a signature against a message
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class KeyPair:
    """Container for a public/secret key pair."""

    public_key: bytes
    secret_key: bytes


@dataclass(frozen=True)
class EncapsulationResult:
    """Container for an encapsulation output."""

    ciphertext: bytes
    shared_secret: bytes


class KEMAlgorithm(ABC):
    """Abstract base class for KEM algorithms.

    Subclasses must implement :meth:`keygen`, :meth:`encapsulate`,
    :meth:`decapsulate`, :attr:`name`, and :attr:`parameter_set`.
    """

    # ------------------------------------------------------------------
    # Core KEM interface
    # ------------------------------------------------------------------

    @abstractmethod
    def keygen(self) -> KeyPair:
        """Generate a fresh public/secret key pair.

        Returns
        -------
        KeyPair
            A :class:`KeyPair` containing the serialised public key and
            secret key as :class:`bytes` objects.
        """

    @abstractmethod
    def encapsulate(self, public_key: bytes) -> EncapsulationResult:
        """Encapsulate a shared secret under *public_key*.

        Parameters
        ----------
        public_key:
            The recipient's public key, as returned by :meth:`keygen`.

        Returns
        -------
        EncapsulationResult
            A :class:`EncapsulationResult` containing the ciphertext and
            the shared secret.
        """

    @abstractmethod
    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """Recover the shared secret from *ciphertext* using *secret_key*.

        Parameters
        ----------
        ciphertext:
            The ciphertext produced by :meth:`encapsulate`.
        secret_key:
            The secret key produced by :meth:`keygen`.

        Returns
        -------
        bytes
            The recovered shared secret.
        """

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable algorithm name (e.g. ``"BIKE"``)."""

    @property
    @abstractmethod
    def parameter_set(self) -> str:
        """Name of the active parameter set (e.g. ``"Level-1"``)."""

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(parameter_set={self.parameter_set!r})"

    def full_name(self) -> str:
        """Return ``"<name>-<parameter_set>"``, e.g. ``"BIKE-Level-1"``."""
        return f"{self.name}-{self.parameter_set}"

    def public_key_size(self, public_key: bytes) -> int:
        """Return the byte length of *public_key*."""
        return len(public_key)

    def ciphertext_size(self, ciphertext: bytes) -> int:
        """Return the byte length of *ciphertext*."""
        return len(ciphertext)

    def shared_secret_size(self, shared_secret: bytes) -> int:
        """Return the byte length of *shared_secret*."""
        return len(shared_secret)


class SignatureAlgorithm(ABC):
    """Abstract base class for digital-signature algorithms.

    Subclasses must implement :meth:`keygen`, :meth:`sign`,
    :meth:`verify`, :attr:`name`, and :attr:`parameter_set`.
    """

    # ------------------------------------------------------------------
    # Core signature interface
    # ------------------------------------------------------------------

    @abstractmethod
    def keygen(self) -> KeyPair:
        """Generate a fresh public/secret key pair.

        Returns
        -------
        KeyPair
            A :class:`KeyPair` containing the serialised public key and
            secret key as :class:`bytes` objects.
        """

    @abstractmethod
    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """Sign *message* using *secret_key*.

        Parameters
        ----------
        secret_key:
            The signer's secret key, as returned by :meth:`keygen`.
        message:
            The message to sign.

        Returns
        -------
        bytes
            The signature.
        """

    @abstractmethod
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify *signature* over *message* using *public_key*.

        Parameters
        ----------
        public_key:
            The signer's public key, as returned by :meth:`keygen`.
        message:
            The message that was signed.
        signature:
            The signature to verify.

        Returns
        -------
        bool
            ``True`` if the signature is valid, ``False`` otherwise.
        """

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable algorithm name (e.g. ``"Dilithium"``)."""

    @property
    @abstractmethod
    def parameter_set(self) -> str:
        """Name of the active parameter set (e.g. ``"ML-DSA-44"``)."""

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(parameter_set={self.parameter_set!r})"

    def full_name(self) -> str:
        """Return ``"<name>-<parameter_set>"``, e.g. ``"Dilithium-ML-DSA-44"``."""
        return f"{self.name}-{self.parameter_set}"

    def public_key_size(self, public_key: bytes) -> int:
        """Return the byte length of *public_key*."""
        return len(public_key)

    def signature_size(self, signature: bytes) -> int:
        """Return the byte length of *signature*."""
        return len(signature)
