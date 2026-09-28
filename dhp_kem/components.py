"""
dhp_kem.components
==================

Thin wrappers around the two component KEMs of DHP-KEM:

  * The CLASSICAL component — X25519 Diffie-Hellman, supplied by the
    well-vetted `cryptography` library (which itself uses OpenSSL).
    We treat it as a "key-encapsulation mechanism" by:
        Encap: generate ephemeral (a, A=a·G); ss = a · pk_ec
        Decap: ss = sk_ec · A
    i.e. the standard ephemeral-static ECDH-DH-KEM construction.

  * The POST-QUANTUM component — ML-KEM (FIPS 203), supplied by the
    `kyber_py` library, a pure-Python reference implementation.  We
    call the FIPS-203-standard KeyGen / Encaps / Decaps directly.

These wrappers exist purely to give DHP-KEM a uniform (KeyGen, Encap, Decap)
interface independent of which Python library is used for each primitive.
Replacing an underlying library (e.g. swapping kyber_py for liboqs-python)
requires touching only this file.

WARNING
-------
kyber_py is a clear, well-tested reference implementation, but it is NOT
side-channel hardened and NOT performance optimised.  For production use,
replace it with a constant-time implementation such as the one bundled
with liboqs.  See §9.2 of the report for the verification methodology
(CT-Verif, ctgrind, Binsec/Rel) that must be applied before any
production deployment.
"""
from __future__ import annotations
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)

from kyber_py.ml_kem import ML_KEM_768, ML_KEM_1024

from .params import ParameterSet, MLKEMVariant


# =============================================================================
# Classical component:  X25519 ECDH-KEM
# =============================================================================

@dataclass(frozen=True)
class ECDHKeyPair:
    """Long-term ECDH key pair for the recipient.

    The private key is stored as the `cryptography` `X25519PrivateKey`
    object (which keeps it in OpenSSL's secure memory).  The public key
    is its 32-byte raw serialisation.
    """
    sk: X25519PrivateKey
    pk: bytes   # 32-byte raw X25519 public point


def ecdh_keygen() -> ECDHKeyPair:
    """Generate a long-term X25519 key pair."""
    sk = X25519PrivateKey.generate()
    pk_bytes = sk.public_key().public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw,
    )
    return ECDHKeyPair(sk=sk, pk=pk_bytes)


def ecdh_encap(pk_ec: bytes) -> tuple[bytes, bytes]:
    """Run the ECDH "encapsulation" half.

    Generates an ephemeral (a, A=a·G), computes ss = a · pk_ec, returns
    (A, ss) so that the receiver, who knows sk_ec, can recompute ss.

    Returns
    -------
    A : bytes
        Ephemeral public point (32 bytes for X25519).
    ss : bytes
        Shared secret ss_ec (32 bytes for X25519).
    """
    if len(pk_ec) != 32:
        raise ValueError(f"X25519 pk must be 32 bytes, got {len(pk_ec)}")
    a_sk = X25519PrivateKey.generate()
    A = a_sk.public_key().public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw,
    )
    peer_pk = X25519PublicKey.from_public_bytes(pk_ec)
    ss = a_sk.exchange(peer_pk)
    return A, ss


def ecdh_decap(sk_ec: X25519PrivateKey, A: bytes) -> bytes:
    """Run the ECDH "decapsulation" half: ss = sk_ec · A."""
    if len(A) != 32:
        raise ValueError(f"X25519 ephemeral A must be 32 bytes, got {len(A)}")
    return sk_ec.exchange(X25519PublicKey.from_public_bytes(A))


# =============================================================================
# Post-quantum component:  ML-KEM (FIPS 203)
# =============================================================================

@dataclass(frozen=True)
class MLKEMKeyPair:
    """Long-term ML-KEM key pair.  Both halves are byte strings per FIPS 203."""
    ek: bytes   # encapsulation key
    dk: bytes   # decapsulation key
    variant: MLKEMVariant


def _mlkem_module(variant: MLKEMVariant):
    """Map our enum to the kyber_py module-level instance."""
    return {
        MLKEMVariant.ML_KEM_768:  ML_KEM_768,
        MLKEMVariant.ML_KEM_1024: ML_KEM_1024,
    }[variant]


def mlkem_keygen(variant: MLKEMVariant) -> MLKEMKeyPair:
    """Generate a long-term ML-KEM key pair of the requested variant."""
    kem = _mlkem_module(variant)
    ek, dk = kem.keygen()
    return MLKEMKeyPair(ek=ek, dk=dk, variant=variant)


def mlkem_encap(variant: MLKEMVariant, ek: bytes) -> tuple[bytes, bytes]:
    """Encapsulate against an ML-KEM encapsulation key.

    Returns
    -------
    c_lwe : bytes
        Ciphertext (1088 bytes for ML-KEM-768; 1568 bytes for ML-KEM-1024).
    ss : bytes
        Shared secret ss_lwe (32 bytes).
    """
    kem = _mlkem_module(variant)
    # kyber_py.encaps returns (K, c) per its API signature
    K, c = kem.encaps(ek)
    return c, K


def mlkem_decap(variant: MLKEMVariant, dk: bytes, c_lwe: bytes) -> bytes:
    """Decapsulate an ML-KEM ciphertext."""
    kem = _mlkem_module(variant)
    return kem.decaps(dk, c_lwe)


# =============================================================================
# Parameter-set dispatch
# =============================================================================

def get_mlkem_variant(ps: ParameterSet) -> MLKEMVariant:
    """Return the MLKEMVariant required by a parameter set."""
    return ps.mlkem_variant
