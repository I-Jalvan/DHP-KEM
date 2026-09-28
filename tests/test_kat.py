"""
test_kat.py
===========

Known-Answer Tests (KATs) for DHP-KEM.

KATs are deterministic test vectors generated under a fixed RNG seed and
stored as JSON in ../kat_vectors/.  They serve two purposes:

  1. Regression detection — if a later code change subtly alters the
     output of combine(), keygen, encap, or decap, the KAT file no
     longer matches and the test fails.

  2. Interoperability — a second implementation (e.g. one in Go, Rust,
     or constant-time C) can replay the same RNG seeds and check that
     its outputs agree.

KATs cover only the deterministic parts of the protocol — specifically
the combiner (combine()) and the transcript hash (compute_transcript()).
The full encap/decap roundtrip is NOT KAT-able in this reference
implementation because:

  * X25519 key generation uses OpenSSL's CSPRNG (not seedable from
    Python in this library); and
  * kyber-py's keygen / encaps also draw fresh randomness internally.

A future version of this code could use a deterministic-randomness mode
to make those KAT-able too; for now we KAT the parts we can.

USAGE
-----
Regenerate the KAT file (e.g. after legitimate spec changes):
    python -m tests.test_kat --generate

Verify against the stored KAT (default):
    python -m tests.test_kat
    pytest tests/test_kat.py
"""
import argparse
import hashlib
import json
import os
import sys
import unittest

import dhp_kem
from dhp_kem.combiner import combine
from dhp_kem.transcript import compute_transcript

KAT_DIR  = os.path.join(os.path.dirname(__file__), "..", "kat_vectors")
KAT_FILE = os.path.join(KAT_DIR, "dhp_kem_kat_v1.json")


# Deterministic byte stream from a SHAKE-128-like construction (we use
# hashlib.shake_128 for portability across Python versions and OSes).
def _det_bytes(seed: bytes, label: str, n: int) -> bytes:
    """Derive `n` bytes deterministically from (seed, label)."""
    return hashlib.shake_128(seed + b"|" + label.encode()).digest(n)


def generate_kats() -> dict:
    """Build a dict of KAT vectors keyed by parameter-set name.

    For each parameter set we generate:
        ss_ec, ss_lwe, A, c_lwe, pk_ec, pk_lwe   — synthetic deterministic
        T  = compute_transcript(...)
        K  = combine(ps, ss_ec, ss_lwe, T, ctx)
    """
    seed = b"DHP-KEM-KAT-v1-seed"
    out = {
        "format_version": 1,
        "scheme": "DHP-KEM",
        "rng_construction": "shake_128(seed + b'|' + label)",
        "seed": seed.hex(),
        "vectors": {},
    }
    for name in ("DHP-KEM-128", "DHP-KEM-256"):
        ps = dhp_kem.get(name)
        # Lengths for synthetic inputs:
        #   ss_ec  : 32 (X25519)
        #   ss_lwe : 32 (ML-KEM standard)
        #   A      : 32 (X25519)
        #   pk_ec  : 32 (X25519)
        #   pk_lwe : 1184 (ML-KEM-768) or 1568 (ML-KEM-1024)
        #   c_lwe  : 1088 (ML-KEM-768) or 1568 (ML-KEM-1024)
        if name == "DHP-KEM-128":
            pk_lwe_len, c_lwe_len = 1184, 1088
        else:
            pk_lwe_len, c_lwe_len = 1568, 1568
        label = name
        ss_ec  = _det_bytes(seed, f"{label}/ss_ec",  32)
        ss_lwe = _det_bytes(seed, f"{label}/ss_lwe", 32)
        A      = _det_bytes(seed, f"{label}/A",      32)
        c_lwe  = _det_bytes(seed, f"{label}/c_lwe",  c_lwe_len)
        pk_ec  = _det_bytes(seed, f"{label}/pk_ec",  32)
        pk_lwe = _det_bytes(seed, f"{label}/pk_lwe", pk_lwe_len)

        T = compute_transcript(ps, A=A, c_lwe=c_lwe, pk_ec=pk_ec, pk_lwe=pk_lwe)
        K = combine(ps, ss_ec=ss_ec, ss_lwe=ss_lwe, transcript=T)
        out["vectors"][name] = {
            "ss_ec":  ss_ec.hex(),
            "ss_lwe": ss_lwe.hex(),
            "A":      A.hex(),
            "c_lwe_sha256": hashlib.sha256(c_lwe).hexdigest(),  # too long inline
            "pk_ec":  pk_ec.hex(),
            "pk_lwe_sha256": hashlib.sha256(pk_lwe).hexdigest(),
            "T":      T.hex(),
            "K":      K.hex(),
            "ctx":    ps.ctx_template,
        }
    return out


def _regenerate_inputs_from_seed(seed: bytes, ps):
    """Re-derive the inputs given the same seed (used by verifier)."""
    name = ps.name
    if name == "DHP-KEM-128":
        pk_lwe_len, c_lwe_len = 1184, 1088
    else:
        pk_lwe_len, c_lwe_len = 1568, 1568
    label = name
    return dict(
        ss_ec  = _det_bytes(seed, f"{label}/ss_ec",  32),
        ss_lwe = _det_bytes(seed, f"{label}/ss_lwe", 32),
        A      = _det_bytes(seed, f"{label}/A",      32),
        c_lwe  = _det_bytes(seed, f"{label}/c_lwe",  c_lwe_len),
        pk_ec  = _det_bytes(seed, f"{label}/pk_ec",  32),
        pk_lwe = _det_bytes(seed, f"{label}/pk_lwe", pk_lwe_len),
    )


def write_kat_file(path: str = KAT_FILE) -> None:
    """Generate fresh KATs and write them to disk."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    kats = generate_kats()
    with open(path, "w") as f:
        json.dump(kats, f, indent=2, sort_keys=True)
    print(f"Wrote KATs to {path}")


def load_kat_file(path: str = KAT_FILE) -> dict:
    """Load KAT vectors from disk."""
    with open(path) as f:
        return json.load(f)


class KATVerificationTests(unittest.TestCase):
    """Re-run combine() and compute_transcript() and check against stored KATs."""

    def setUp(self):
        if not os.path.isfile(KAT_FILE):
            self.skipTest(f"KAT file not present at {KAT_FILE!r}.  "
                          f"Generate with:  python -m tests.test_kat --generate")
        self.kats = load_kat_file(KAT_FILE)

    def test_format_version_known(self):
        self.assertEqual(self.kats["format_version"], 1)
        self.assertEqual(self.kats["scheme"], "DHP-KEM")

    def test_each_vector_replays_correctly(self):
        seed = bytes.fromhex(self.kats["seed"])
        for ps_name, vec in self.kats["vectors"].items():
            ps = dhp_kem.get(ps_name)
            inputs = _regenerate_inputs_from_seed(seed, ps)

            # Verify the inputs match what the KAT says
            self.assertEqual(inputs["ss_ec"].hex(),  vec["ss_ec"],
                f"{ps_name}: ss_ec mismatch — seed-regeneration broken")
            self.assertEqual(inputs["ss_lwe"].hex(), vec["ss_lwe"])
            self.assertEqual(inputs["A"].hex(),      vec["A"])
            self.assertEqual(inputs["pk_ec"].hex(),  vec["pk_ec"])
            self.assertEqual(
                hashlib.sha256(inputs["c_lwe"]).hexdigest(),
                vec["c_lwe_sha256"], f"{ps_name}: c_lwe checksum mismatch")
            self.assertEqual(
                hashlib.sha256(inputs["pk_lwe"]).hexdigest(),
                vec["pk_lwe_sha256"])

            # Replay compute_transcript and combine
            T = compute_transcript(ps, A=inputs["A"], c_lwe=inputs["c_lwe"],
                                   pk_ec=inputs["pk_ec"], pk_lwe=inputs["pk_lwe"])
            self.assertEqual(T.hex(), vec["T"],
                f"{ps_name}: transcript hash diverges from KAT")
            K = combine(ps, ss_ec=inputs["ss_ec"],
                            ss_lwe=inputs["ss_lwe"],
                            transcript=T)
            self.assertEqual(K.hex(), vec["K"],
                f"{ps_name}: combined K diverges from KAT")


# ---------------------------------------------------------------------------
# CLI / pytest dual driver
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--generate", action="store_true",
                    help="Re-generate the KAT file and exit.")
    args, rest = ap.parse_known_args()
    if args.generate:
        write_kat_file()
    else:
        sys.argv[1:] = rest
        unittest.main(verbosity=2)
