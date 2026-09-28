"""
dhp_kem.transcript
==================

Transcript-hash computation for DHP-KEM.

The transcript hash T binds every cryptographic operation in a session to
the exact sequence of public values exchanged.  It is fed to HKDF-Extract
as the `salt` parameter, which is the mechanism that gives DHP-KEM its
standalone-CCA security property (Section 5.3 of the report, "Standalone
security via explicit transcript binding").

The construction is:

    T = H( A || c_lwe || pk_ec || pk_lwe )

where:
    A       — the encapsulator's freshly-generated ECDH public element
              (32 bytes for X25519)
    c_lwe   — the ML-KEM ciphertext
              (1088 bytes for ML-KEM-768; 1568 bytes for ML-KEM-1024)
    pk_ec   — Bob's long-term ECDH public key
    pk_lwe  — Bob's long-term ML-KEM encapsulation key

Length-prefixing is NOT used because every field has a fixed length determined
by the parameter set, and field-order is fixed by the protocol specification
(Section 3.6).  Reviewers from the IETF tradition may prefer explicit
length-prefixes; the present convention matches what is universal in
hash-then-sign and KEM combiner literature (e.g. RFC 9180 HPKE §5.2).

References
----------
[11] Giacon, Heuer, Poettering — KEM combiners (PKC 2018)
[12] Bindel et al.            — Hybrid KEM/AKE (PQCrypto 2019)
"""
from __future__ import annotations
import hashlib

from .params import ParameterSet


_HASH_FACTORIES = {
    "SHA-256": hashlib.sha256,
    "SHA-384": hashlib.sha384,
    "SHA-512": hashlib.sha512,
}


def _hash_factory(name: str):
    """Return a hashlib factory for `name`, e.g. _hash_factory('SHA-384')."""
    try:
        return _HASH_FACTORIES[name]
    except KeyError as exc:
        raise ValueError(
            f"Unknown hash function {name!r}. "
            f"Supported: {sorted(_HASH_FACTORIES)}."
        ) from exc


def compute_transcript(
    ps: ParameterSet,
    A: bytes,
    c_lwe: bytes,
    pk_ec: bytes,
    pk_lwe: bytes,
) -> bytes:
    """Compute the transcript hash T = H(A || c_lwe || pk_ec || pk_lwe).

    Parameters
    ----------
    ps : ParameterSet
        Determines the hash function used.
    A : bytes
        The encapsulator's ECDH public element for this session.
    c_lwe : bytes
        The ML-KEM ciphertext.
    pk_ec, pk_lwe : bytes
        Bob's two long-term public keys.

    Returns
    -------
    bytes
        Hash output (48 bytes for SHA-384, 64 bytes for SHA-512).

    Raises
    ------
    TypeError
        If any input is not exactly `bytes`.

    Notes
    -----
    This function is order-sensitive.  Swapping `pk_ec` and `pk_lwe` (or any
    other ordering change) yields a different transcript hash, which is the
    intended behaviour: a tampered transcript MUST produce a different
    derived key.  Test `test_combiner.test_transcript_is_order_sensitive`
    locks this guarantee.
    """
    for label, value in (("A", A), ("c_lwe", c_lwe),
                         ("pk_ec", pk_ec), ("pk_lwe", pk_lwe)):
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError(f"transcript field {label!r} must be bytes, "
                            f"got {type(value).__name__}")
    h = _hash_factory(ps.hash_name)()
    h.update(bytes(A))
    h.update(bytes(c_lwe))
    h.update(bytes(pk_ec))
    h.update(bytes(pk_lwe))
    return h.digest()
