"""
dhp_kem.kem
===========

High-level DHP-KEM API.

Three functions, matching the standard KEM interface:

    keygen(ps)              → DHPKeyPair                long-term keypair
    encap(ps, public_key)   → (ciphertext, K)           encapsulate
    decap(ps, secret_key,
          ciphertext)       → K                         decapsulate

A DHPKeyPair carries BOTH component keypairs (ECDH + ML-KEM) plus the
parameter set under which it was generated; a DHPCiphertext bundles the
ephemeral ECDH point A and the ML-KEM ciphertext c_lwe.

This file implements Algorithms 1, 2, and 3 of the report (§3.4–§3.7).

Forward secrecy note
--------------------
DHP-KEM as specified uses a LONG-TERM recipient key pair (Goal G3 of §3.1
in its base form).  Session-level forward secrecy is obtained by running
keygen() afresh on the recipient side per session — the ephemeral-
ephemeral usage pattern.  The AKE wrapper in §10.5 of the report
specifies exactly this composition.

Testing
-------
See tests/test_correctness.py for randomised round-trip tests across all
three parameter sets, tests/test_negative.py for tampered-input rejection,
and tests/test_kat.py for deterministic Known-Answer Tests using fixed
seeds (vectors stored in kat_vectors/).
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from . import components as cmp
from . import transcript as tr
from . import combiner as cb
from .params import ParameterSet, MLKEMVariant


# =============================================================================
# Public-key bundles
# =============================================================================

@dataclass(frozen=True)
class DHPPublicKey:
    """Recipient's long-term public key bundle: (pk_ec, pk_lwe)."""
    pk_ec: bytes
    pk_lwe: bytes
    paramset_name: str


@dataclass(frozen=True)
class DHPSecretKey:
    """Recipient's long-term secret key bundle: (sk_ec, sk_lwe).

    sk_ec is a `cryptography.X25519PrivateKey` object (kept inside
    OpenSSL's protected key store); sk_lwe is the FIPS-203 decapsulation
    key as a byte string.
    """
    sk_ec: X25519PrivateKey
    sk_lwe: bytes
    paramset_name: str

    # Also retained for transcript re-computation during Decap:
    pk_ec: bytes
    pk_lwe: bytes


@dataclass(frozen=True)
class DHPKeyPair:
    """Long-term keypair: bundles a public and a secret key."""
    pk: DHPPublicKey
    sk: DHPSecretKey


@dataclass(frozen=True)
class DHPCiphertext:
    """The wire-format ciphertext: (A, c_lwe).

    Total size for DHP-KEM-128 (X25519 + ML-KEM-768): 32 + 1088 = 1120 bytes.
    For DHP-KEM-256 (X25519 + ML-KEM-1024):           32 + 1568 = 1600 bytes.
    """
    A: bytes
    c_lwe: bytes
    paramset_name: str


# =============================================================================
# The three KEM operations
# =============================================================================

def keygen(ps: ParameterSet) -> DHPKeyPair:
    """Generate a long-term DHP-KEM key pair.

    Generates (sk_ec, pk_ec) ← ECDH.KeyGen() and (dk, ek) ← ML-KEM.KeyGen()
    independently, then bundles them together.

    The two halves can in principle be generated on different machines
    (HSMs); the construction does not require correlation between them.

    Parameters
    ----------
    ps : ParameterSet
        e.g. dhp_kem.params.DHP_KEM_128.

    Returns
    -------
    DHPKeyPair
    """
    if ps.nca_tier == "LT (research-tier)":
        raise NotImplementedError(
            "DHP-KEM-LT requires FrodoKEM-1344 in addition to ML-KEM-1024, "
            "which is not implemented in this reference package.  "
            "See params.py docstring for context."
        )

    # ECDH half
    ec_kp = cmp.ecdh_keygen()
    # ML-KEM half
    mlkem_kp = cmp.mlkem_keygen(ps.mlkem_variant)

    pk = DHPPublicKey(pk_ec=ec_kp.pk, pk_lwe=mlkem_kp.ek,
                      paramset_name=ps.name)
    sk = DHPSecretKey(sk_ec=ec_kp.sk, sk_lwe=mlkem_kp.dk,
                      pk_ec=ec_kp.pk, pk_lwe=mlkem_kp.ek,
                      paramset_name=ps.name)
    return DHPKeyPair(pk=pk, sk=sk)


def encap(ps: ParameterSet, pk: DHPPublicKey,
          ctx: Optional[bytes] = None) -> tuple[DHPCiphertext, bytes]:
    """Encapsulate a fresh session key K against the recipient's public key.

    Implements Algorithm 2 of the report (§3.6):

        (a, A)            ← ECDH.KeyGen()
        ss_ec             ← a · pk_ec
        (c_lwe, ss_lwe)   ← ML-KEM.Encap(pk_lwe)
        T                 ← H(A || c_lwe || pk_ec || pk_lwe)
        K                 ← HKDF-Expand(HKDF-Extract(T, ss_ec || ss_lwe), ctx)
        ct                ← (A, c_lwe)

    Parameters
    ----------
    ps : ParameterSet
    pk : DHPPublicKey
        Recipient's long-term public key.
    ctx : bytes, optional
        Optional override for the domain-separator string; defaults to
        ps.ctx_template.

    Returns
    -------
    (DHPCiphertext, bytes)
        The wire ciphertext and the freshly-derived session key K.
    """
    if pk.paramset_name != ps.name:
        raise ValueError(
            f"Public key was generated for {pk.paramset_name!r} but "
            f"encap is being called with {ps.name!r}."
        )

    # 1.  Classical ECDH half — produces (A, ss_ec)
    A, ss_ec = cmp.ecdh_encap(pk.pk_ec)

    # 2.  Post-quantum half — produces (c_lwe, ss_lwe)
    c_lwe, ss_lwe = cmp.mlkem_encap(ps.mlkem_variant, pk.pk_lwe)

    # 3.  Transcript binding
    T = tr.compute_transcript(ps, A=A, c_lwe=c_lwe,
                              pk_ec=pk.pk_ec, pk_lwe=pk.pk_lwe)

    # 4.  Combiner — produces K
    K = cb.combine(ps, ss_ec=ss_ec, ss_lwe=ss_lwe, transcript=T, ctx=ctx)

    ct = DHPCiphertext(A=A, c_lwe=c_lwe, paramset_name=ps.name)
    return ct, K


def decap(ps: ParameterSet, sk: DHPSecretKey, ct: DHPCiphertext,
          ctx: Optional[bytes] = None) -> bytes:
    """Decapsulate a DHP-KEM ciphertext.

    Implements Algorithm 3 of the report (§3.7):

        ss_ec'   ← sk_ec · A
        ss_lwe'  ← ML-KEM.Decap(sk_lwe, c_lwe)
        T'       ← H(A || c_lwe || pk_ec || pk_lwe)
        K'       ← HKDF-Expand(HKDF-Extract(T', ss_ec' || ss_lwe'), ctx)

    If the ciphertext is genuine, K' == K (Proposition 1, §3.8).

    Parameters
    ----------
    ps : ParameterSet
    sk : DHPSecretKey
    ct : DHPCiphertext
    ctx : bytes, optional

    Returns
    -------
    bytes
        The recovered session key K'.

    Notes
    -----
    Note that FIPS-203 ML-KEM's decapsulation is itself an implicit-
    rejection KEM: on a tampered ciphertext it returns a deterministic
    pseudorandom value derived from the decapsulation key, NOT an error.
    This means decap() always returns a 32-byte K' — testing whether
    K' equals the encapsulator's K is the only check that distinguishes
    a genuine from a tampered ciphertext.  See test_negative.py.
    """
    if sk.paramset_name != ps.name:
        raise ValueError(
            f"Secret key was generated for {sk.paramset_name!r} but "
            f"decap is being called with {ps.name!r}."
        )
    if ct.paramset_name != ps.name:
        raise ValueError(
            f"Ciphertext was produced under {ct.paramset_name!r} but "
            f"decap is being called with {ps.name!r}."
        )

    # 1.  Recover ss_ec' = sk_ec · A
    ss_ec = cmp.ecdh_decap(sk.sk_ec, ct.A)

    # 2.  Recover ss_lwe' = ML-KEM.Decap(sk_lwe, c_lwe)
    ss_lwe = cmp.mlkem_decap(ps.mlkem_variant, sk.sk_lwe, ct.c_lwe)

    # 3.  Recompute transcript using Bob's known long-term public keys
    T = tr.compute_transcript(ps, A=ct.A, c_lwe=ct.c_lwe,
                              pk_ec=sk.pk_ec, pk_lwe=sk.pk_lwe)

    # 4.  Combiner
    return cb.combine(ps, ss_ec=ss_ec, ss_lwe=ss_lwe, transcript=T, ctx=ctx)
