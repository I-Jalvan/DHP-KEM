"""
generate_worked_example.py
==========================

Regenerates the exact hex-byte trace that appears as §2c (Worked Example)
in the report.  Uses deterministic seeds so that every byte is exactly
reproducible across machines.

Usage:
    cd code/
    python -m examples.generate_worked_example          # human-readable trace
    python -m examples.generate_worked_example --json   # JSON output

The report quotes:
    - first 32 bytes and last 32 bytes of ek (1184 bytes total) and c_lwe
      (1088 bytes total)
    - full hex of pk_ec, A, ss_ec, ss_lwe, T, K (all <= 64 bytes)
    - SHA-256 of the long fields (ek, dk, c_lwe) for verification

This file is a *demonstration*, not part of the dhp_kem core library.
"""
from __future__ import annotations
import argparse
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from kyber_py.ml_kem import ML_KEM_768

from dhp_kem.params import DHP_KEM_128
from dhp_kem.transcript import compute_transcript
from dhp_kem.combiner import combine


def _derive(label: str, n: int) -> bytes:
    """Deterministic seed bytes for the example."""
    return hashlib.shake_128(label.encode()).digest(n)


def generate_trace() -> dict:
    """Run a complete DHP-KEM-128 encap/decap cycle with seeded inputs."""

    # ---- Bob: long-term key pair ------------------------------------------
    sk_ec_seed = _derive("WorkedExample/Bob/X25519/priv", 32)
    bob_sk_ec  = X25519PrivateKey.from_private_bytes(sk_ec_seed)
    bob_pk_ec  = bob_sk_ec.public_key().public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw)

    d_seed = _derive("WorkedExample/Bob/MLKEM/d", 32)
    z_seed = _derive("WorkedExample/Bob/MLKEM/z", 32)
    bob_ek, bob_dk = ML_KEM_768._keygen_internal(d_seed, z_seed)

    # ---- Alice: ephemeral ECDH and ML-KEM encapsulation -------------------
    alice_seed = _derive("WorkedExample/Alice/X25519/priv", 32)
    alice_sk   = X25519PrivateKey.from_private_bytes(alice_seed)
    A          = alice_sk.public_key().public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw)
    ss_ec      = alice_sk.exchange(X25519PublicKey.from_public_bytes(bob_pk_ec))

    m_seed = _derive("WorkedExample/Alice/MLKEM/m", 32)
    ss_lwe, c_lwe = ML_KEM_768._encaps_internal(bob_ek, m_seed)

    # ---- The DHP-KEM combiner --------------------------------------------
    T = compute_transcript(DHP_KEM_128, A=A, c_lwe=c_lwe,
                           pk_ec=bob_pk_ec, pk_lwe=bob_ek)
    K = combine(DHP_KEM_128, ss_ec=ss_ec, ss_lwe=ss_lwe, transcript=T)

    # ---- Bob's side: verify the receiver computes the same K -------------
    ss_ec_recv  = bob_sk_ec.exchange(X25519PublicKey.from_public_bytes(A))
    ss_lwe_recv = ML_KEM_768.decaps(bob_dk, c_lwe)
    T_recv      = compute_transcript(DHP_KEM_128, A=A, c_lwe=c_lwe,
                                     pk_ec=bob_pk_ec, pk_lwe=bob_ek)
    K_recv      = combine(DHP_KEM_128, ss_ec=ss_ec_recv,
                          ss_lwe=ss_lwe_recv, transcript=T_recv)
    assert K == K_recv, "Worked-example round-trip failed"

    return {
        "bob": {
            "sk_ec_seed":   sk_ec_seed.hex(),
            "pk_ec":        bob_pk_ec.hex(),
            "mlkem_d_seed": d_seed.hex(),
            "mlkem_z_seed": z_seed.hex(),
            "ek_first32":   bob_ek[:32].hex(),
            "ek_last32":    bob_ek[-32:].hex(),
            "ek_len":       len(bob_ek),
            "ek_sha256":    hashlib.sha256(bob_ek).hexdigest(),
            "dk_len":       len(bob_dk),
            "dk_sha256":    hashlib.sha256(bob_dk).hexdigest(),
        },
        "alice": {
            "sk_ec_seed":   alice_seed.hex(),
            "A":            A.hex(),
            "mlkem_m_seed": m_seed.hex(),
            "c_lwe_first32":c_lwe[:32].hex(),
            "c_lwe_last32": c_lwe[-32:].hex(),
            "c_lwe_len":    len(c_lwe),
            "c_lwe_sha256": hashlib.sha256(c_lwe).hexdigest(),
            "ss_ec":        ss_ec.hex(),
            "ss_lwe":       ss_lwe.hex(),
        },
        "combiner": {
            "transcript_T":   T.hex(),
            "transcript_len": len(T),
            "K":              K.hex(),
        },
    }


def print_human(trace: dict) -> None:
    print("=" * 72)
    print("  DHP-KEM-128 WORKED EXAMPLE  (X25519 + ML-KEM-768 + HKDF-SHA-384)")
    print("=" * 72)
    print(f"\n-- Bob's long-term key material --")
    print(f"  sk_ec (X25519 seed):  {trace['bob']['sk_ec_seed']}")
    print(f"  pk_ec (32 bytes):     {trace['bob']['pk_ec']}")
    print(f"  ek    (1184 bytes):   {trace['bob']['ek_first32']} ... "
          f"{trace['bob']['ek_last32']}")
    print(f"        sha256(ek)   =  {trace['bob']['ek_sha256']}")
    print(f"        sha256(dk)   =  {trace['bob']['dk_sha256']}")
    print(f"\n-- Alice's encapsulation --")
    print(f"  A     (32 bytes):     {trace['alice']['A']}")
    print(f"  c_lwe (1088 bytes):   {trace['alice']['c_lwe_first32']} ... "
          f"{trace['alice']['c_lwe_last32']}")
    print(f"        sha256(c_lwe)=  {trace['alice']['c_lwe_sha256']}")
    print(f"  ss_ec  (32 bytes):    {trace['alice']['ss_ec']}")
    print(f"  ss_lwe (32 bytes):    {trace['alice']['ss_lwe']}")
    print(f"\n-- Combiner --")
    print(f"  T = SHA-384(...) :    {trace['combiner']['transcript_T'][:64]}")
    print(f"                        {trace['combiner']['transcript_T'][64:]}")
    print(f"  K (output, 32B)  :    {trace['combiner']['K']}")
    print("=" * 72)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="emit JSON instead")
    args = ap.parse_args()
    trace = generate_trace()
    if args.json:
        print(json.dumps(trace, indent=2))
    else:
        print_human(trace)
