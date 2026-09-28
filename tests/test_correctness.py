"""
test_correctness.py
===================

Randomised roundtrip tests:

  For each parameter set, for `N_ITERATIONS` random instances:
     1. Generate a long-term keypair (sk, pk)
     2. Run (ct, K)  = Encap(pk)
     3. Run K'      = Decap(sk, ct)
     4. Assert K == K'

This is the operational form of Proposition 1 (Correctness) from §3.8
of the report.

Per FIPS 203, ML-KEM-768/1024 has correctness error bounded by 2^{-164}
or smaller.  Across N_ITERATIONS ≤ 1000 the probability of even one
genuine correctness failure is on the order of 10^{-46}, so any failure
here indicates a bug.

Usage:
    python -m tests.test_correctness          # full run (default)
    pytest tests/test_correctness.py          # also works under pytest
"""
import sys
import unittest

import dhp_kem
from dhp_kem.params import PARAMETER_SETS


# Iterations are intentionally modest because Encap+Decap involves a full
# Kyber operation which is ~10ms per round in pure Python; 50 iterations
# per parameter set is plenty for a smoke test.
N_ITERATIONS = 50


class CorrectnessTests(unittest.TestCase):

    def _roundtrip(self, ps_name: str, n: int):
        ps = dhp_kem.get(ps_name)
        if ps.nca_tier.startswith("LT"):
            self.skipTest(f"{ps_name} requires FrodoKEM (not in reference impl)")
        failures = 0
        for i in range(n):
            kp = dhp_kem.keygen(ps)
            ct, K = dhp_kem.encap(ps, kp.pk)
            K_prime = dhp_kem.decap(ps, kp.sk, ct)
            if K != K_prime:
                failures += 1
        self.assertEqual(failures, 0,
            f"{ps_name}: {failures}/{n} correctness failures (expected 0).")

    def test_dhp_kem_128_correctness(self):
        self._roundtrip("DHP-KEM-128", N_ITERATIONS)

    def test_dhp_kem_256_correctness(self):
        self._roundtrip("DHP-KEM-256", N_ITERATIONS)

    def test_dhp_kem_lt_refuses(self):
        ps = dhp_kem.get("DHP-KEM-LT")
        with self.assertRaises(NotImplementedError):
            dhp_kem.keygen(ps)

    def test_key_K_is_correct_length(self):
        for name in ("DHP-KEM-128", "DHP-KEM-256"):
            ps = dhp_kem.get(name)
            kp = dhp_kem.keygen(ps)
            ct, K = dhp_kem.encap(ps, kp.pk)
            self.assertEqual(len(K), ps.L,
                f"{name}: key length {len(K)} != ps.L={ps.L}")

    def test_ciphertext_components_are_correct_length(self):
        # A is always 32 bytes (X25519).
        # c_lwe is 1088 bytes for ML-KEM-768 and 1568 bytes for ML-KEM-1024.
        expected_c_lwe = {"DHP-KEM-128": 1088, "DHP-KEM-256": 1568}
        for name, c_len in expected_c_lwe.items():
            ps = dhp_kem.get(name)
            kp = dhp_kem.keygen(ps)
            ct, _ = dhp_kem.encap(ps, kp.pk)
            self.assertEqual(len(ct.A), 32, f"{name}: |A| should be 32")
            self.assertEqual(len(ct.c_lwe), c_len,
                f"{name}: |c_lwe| should be {c_len}, got {len(ct.c_lwe)}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
