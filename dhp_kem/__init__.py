"""
dhp_kem — reference implementation of the DHP-KEM hybrid KEM.

DHP-KEM (Dual Hard-Problem KEM) combines:

    * ECDH on Curve25519 (classical, hard under ECDLP)
    * ML-KEM-768 / ML-KEM-1024 (post-quantum, hard under Module-LWE)

through a transcript-bound HKDF Extract-then-Expand combiner.

The encapsulated session key K remains pseudorandom as long as AT LEAST
ONE of ECDLP and Module-LWE remains computationally hard (disjunctive
dual-hardness; Proposition 2 of the accompanying report).

Quick start
-----------
    >>> from dhp_kem import DHP_KEM_128, keygen, encap, decap
    >>> kp = keygen(DHP_KEM_128)
    >>> ct, K = encap(DHP_KEM_128, kp.pk)
    >>> K_prime = decap(DHP_KEM_128, kp.sk, ct)
    >>> K == K_prime
    True

This is the reference, NOT a production implementation.  See README.md
for the (substantial) list of side-channel and operational hardening
steps required before any deployment.
"""
from .params import (
    ParameterSet,
    MLKEMVariant,
    DHP_KEM_128,
    DHP_KEM_256,
    DHP_KEM_LT,
    PARAMETER_SETS,
    get,
)
from .kem import (
    keygen, encap, decap,
    DHPKeyPair, DHPPublicKey, DHPSecretKey, DHPCiphertext,
)
from . import combiner, transcript, components

__version__ = "1.0.0"

__all__ = [
    # parameters
    "ParameterSet", "MLKEMVariant",
    "DHP_KEM_128", "DHP_KEM_256", "DHP_KEM_LT",
    "PARAMETER_SETS", "get",
    # API
    "keygen", "encap", "decap",
    "DHPKeyPair", "DHPPublicKey", "DHPSecretKey", "DHPCiphertext",
    # sub-modules (for fine-grained testing)
    "combiner", "transcript", "components",
]
