"""
dhp_kem.params
==============

Parameter-set registry for DHP-KEM.

Three named parameter sets are defined, matching the NCS-1:2020 levels.
Each parameter set bundles:

  * the classical ECDH curve         (currently X25519 in all three sets)
  * the post-quantum ML-KEM variant  (ML-KEM-768 or ML-KEM-1024)
  * the hash function used for the transcript and HKDF
  * the symmetric output length L (in bytes)
  * the domain-separator string `ctx` that is fed to HKDF-Expand

Constants are kept here so that the rest of the package never hard-codes
"32 bytes" or "ML-KEM-768"; the protocol logic is parameter-set agnostic.

The LT (research-tier) profile names FrodoKEM-1344 as a second post-quantum
component for defence in depth against structured-lattice cryptanalysis.
The reference implementation in this repository does NOT include FrodoKEM
(no maintained pure-Python implementation is currently available).  The
LT entry below is therefore reserved as a placeholder for future work and
marked accordingly; using ParamSet.LT will raise NotImplementedError at
runtime.

References
----------
[10] FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard
[19] NCA NCS-1:2020 — National Cryptographic Standards
[40] RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function
"""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum


class MLKEMVariant(Enum):
    """Identifies which ML-KEM parameter set the post-quantum component uses."""
    ML_KEM_768  = "ML-KEM-768"
    ML_KEM_1024 = "ML-KEM-1024"


@dataclass(frozen=True)
class ParameterSet:
    """A single named parameter set for DHP-KEM.

    Attributes
    ----------
    name : str
        Public name (e.g. "DHP-KEM-128").
    classical_curve : str
        Currently only "X25519" is implemented.
    mlkem_variant : MLKEMVariant
        Which FIPS-203 ML-KEM size is used.
    hash_name : str
        Hash function used both for the transcript H(...) and inside HKDF.
        Must be one of {"SHA-384", "SHA-512"}.
    L : int
        Output key length in bytes (32 for AES-256-class output).
    ctx_template : str
        Domain-separator string supplied to HKDF-Expand as `info`.
    nca_tier : str
        Saudi NCS-1:2020 level mapping (one of MODERATE / ADVANCED / LT).
    """
    name: str
    classical_curve: str
    mlkem_variant: MLKEMVariant
    hash_name: str
    L: int
    ctx_template: str
    nca_tier: str


# ------------------------------------------------------------------
# Concrete parameter sets used in the report (Section 3.3, Table 1)
# ------------------------------------------------------------------
DHP_KEM_128 = ParameterSet(
    name="DHP-KEM-128",
    classical_curve="X25519",
    mlkem_variant=MLKEMVariant.ML_KEM_768,
    hash_name="SHA-384",
    L=32,
    ctx_template="DHP-KEM-v1 / KSA / MODERATE",
    nca_tier="MODERATE",
)

DHP_KEM_256 = ParameterSet(
    name="DHP-KEM-256",
    # Although the *report* specifies P-384 for ADVANCED, the reference
    # implementation here uses X25519 across the board to keep the
    # dependency surface minimal.  P-384 could be substituted by replacing
    # the classical_curve string AND the corresponding component wrapper.
    classical_curve="X25519",
    mlkem_variant=MLKEMVariant.ML_KEM_1024,
    hash_name="SHA-512",
    L=32,
    ctx_template="DHP-KEM-v1 / KSA / ADVANCED",
    nca_tier="ADVANCED",
)

DHP_KEM_LT = ParameterSet(
    name="DHP-KEM-LT",
    classical_curve="X25519",
    mlkem_variant=MLKEMVariant.ML_KEM_1024,   # FrodoKEM-1344 omitted (NotImplementedError)
    hash_name="SHA-512",
    L=32,
    ctx_template="DHP-KEM-v1 / KSA / LT",
    nca_tier="LT (research-tier)",
)


# Convenience map for tests / CLI tools / benchmarks
PARAMETER_SETS: dict[str, ParameterSet] = {
    ps.name: ps for ps in (DHP_KEM_128, DHP_KEM_256, DHP_KEM_LT)
}


def get(name: str) -> ParameterSet:
    """Look up a parameter set by string name.

    >>> get("DHP-KEM-128").nca_tier
    'MODERATE'
    """
    if name not in PARAMETER_SETS:
        raise KeyError(f"Unknown DHP-KEM parameter set: {name!r}. "
                       f"Choose one of {sorted(PARAMETER_SETS)}.")
    return PARAMETER_SETS[name]
