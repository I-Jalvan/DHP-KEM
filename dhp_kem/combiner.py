"""
dhp_kem.combiner
================

The DHP-KEM combiner.

This is the heart of the proposed protocol (Section 3.6 and Section 4.3 of
the report).  Given the two component shared secrets ss_ec (ECDH) and
ss_lwe (ML-KEM), and the transcript hash T, the combiner produces the
final symmetric session key K:

                    salt = T
    ┌──────────────────────────────────────────┐
    │   PRK = HKDF-Extract(salt, ss_ec || ss_lwe)   │   stage 1
    └──────────────────────────────────────────┘
                    info = ctx
    ┌──────────────────────────────────────────┐
    │   K   = HKDF-Expand(PRK, info, L)             │   stage 2
    └──────────────────────────────────────────┘

The two-stage Extract-then-Expand structure is required (rather than the
flat HKDF(salt || ikm || info) that some early hybrid schemes used) for
two reasons (Proposition 2 of the report):

  1. Extract guarantees that K is uniform when EITHER input has high
     entropy (the dual-PRF / hybrid-PRG assumption of [12, §3]).
  2. Expand allows L > hash_len and supports clean info-binding.

Security
--------
Proposition 2 (Combiner Security, restated for DHP-KEM from
Giacon-Heuer-Poettering [11]) states:

    If HKDF satisfies the dual-PRF assumption [12], and either KEM_ec or
    KEM_lwe is IND-CCA2 secure, then DHP-KEM is IND-CCA2 secure.

References
----------
[11] Giacon, Heuer, and Poettering    — "KEM combiners" (PKC 2018)
[12] Bindel et al.                    — "Hybrid KEM/AKE" (PQCrypto 2019)
[40] RFC 5869                         — HKDF
"""
from __future__ import annotations

from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512, HashAlgorithm
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.hmac import HMAC

from .params import ParameterSet


_HASH_OBJECTS: dict[str, type[HashAlgorithm]] = {
    "SHA-256": SHA256,
    "SHA-384": SHA384,
    "SHA-512": SHA512,
}


def _hash_obj(name: str) -> HashAlgorithm:
    """Return a `cryptography` hash-algorithm instance for `name`."""
    try:
        return _HASH_OBJECTS[name]()
    except KeyError as exc:
        raise ValueError(
            f"Unsupported hash for HKDF: {name!r}. "
            f"Supported: {sorted(_HASH_OBJECTS)}."
        ) from exc


def hkdf_extract(salt: bytes, ikm: bytes, hash_name: str) -> bytes:
    """RFC 5869 §2.2 — Extract step.

    PRK = HMAC-H(salt, IKM)

    Implemented explicitly (rather than via `cryptography.HKDF` in
    extract-and-expand mode) so that the two stages can be inspected
    separately for KAT generation and for the unit tests in
    test_combiner.py.

    Parameters
    ----------
    salt : bytes
        The transcript hash T.  Length determined by the hash function
        (48 or 64 bytes); any non-empty length is accepted.
    ikm : bytes
        Input keying material: the concatenation ss_ec || ss_lwe.
    hash_name : str
        One of "SHA-256", "SHA-384", "SHA-512".

    Returns
    -------
    bytes
        The pseudorandom key PRK (hash_output_len bytes).
    """
    h = _hash_obj(hash_name)
    hmac = HMAC(salt, h)
    hmac.update(ikm)
    return hmac.finalize()


def hkdf_expand(prk: bytes, info: bytes, length: int, hash_name: str) -> bytes:
    """RFC 5869 §2.3 — Expand step.

    K = HKDF-Expand(PRK, info, L) using HMAC-H as the PRF.

    Parameters
    ----------
    prk : bytes
        Pseudorandom key from Extract.
    info : bytes
        Application-supplied context-and-application-specific information.
        For DHP-KEM this is the ctx domain-separator string.
    length : int
        Desired output length in bytes.  RFC 5869 limits this to
        255 * hash_output_len, which is far more than DHP-KEM needs.
    hash_name : str
        One of "SHA-256", "SHA-384", "SHA-512".

    Returns
    -------
    bytes
        Output keying material of `length` bytes.
    """
    kdf = HKDFExpand(algorithm=_hash_obj(hash_name), length=length, info=info)
    return kdf.derive(prk)


def combine(
    ps: ParameterSet,
    ss_ec: bytes,
    ss_lwe: bytes,
    transcript: bytes,
    ctx: bytes | None = None,
) -> bytes:
    """Combine two shared secrets into the DHP-KEM session key K.

    Implements Section 3.6 of the report:

        PRK = HKDF-Extract(salt = transcript, IKM = ss_ec || ss_lwe)
        K   = HKDF-Expand(PRK, info = ctx, L = ps.L)

    Parameters
    ----------
    ps : ParameterSet
        Active parameter set (determines hash and output length).
    ss_ec : bytes
        Shared secret from the ECDH component.  Exactly 32 bytes for
        X25519; longer for NIST P-curves.
    ss_lwe : bytes
        Shared secret from the ML-KEM component.  32 bytes for all
        ML-KEM variants per FIPS 203.
    transcript : bytes
        Output of `dhp_kem.transcript.compute_transcript(...)`.
        Used as the HKDF-Extract `salt` parameter.
    ctx : bytes, optional
        Domain-separator string fed to HKDF-Expand as `info`.  Defaults
        to `ps.ctx_template.encode('utf-8')`.

    Returns
    -------
    bytes
        The final session key K (ps.L bytes).
    """
    if not isinstance(ss_ec, (bytes, bytearray)) or len(ss_ec) == 0:
        raise ValueError("ss_ec must be non-empty bytes")
    if not isinstance(ss_lwe, (bytes, bytearray)) or len(ss_lwe) == 0:
        raise ValueError("ss_lwe must be non-empty bytes")
    if not isinstance(transcript, (bytes, bytearray)) or len(transcript) == 0:
        raise ValueError("transcript must be non-empty bytes")

    if ctx is None:
        ctx = ps.ctx_template.encode("utf-8")
    elif isinstance(ctx, str):
        ctx = ctx.encode("utf-8")

    ikm = bytes(ss_ec) + bytes(ss_lwe)
    prk = hkdf_extract(salt=bytes(transcript), ikm=ikm,
                       hash_name=ps.hash_name)
    return hkdf_expand(prk=prk, info=ctx, length=ps.L,
                       hash_name=ps.hash_name)
