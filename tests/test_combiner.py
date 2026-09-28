"""
test_combiner.py
================

Unit tests for the HKDF Extract-then-Expand combiner in dhp_kem.combiner.

These tests are deliberately decoupled from ECDH and ML-KEM: they feed
synthetic shared secrets into combine() and check structural / algebraic
properties.

Covered properties
------------------
  1. Output length matches ps.L.
  2. Determinism — same inputs ⇒ same output.
  3. Sensitivity to ss_ec  (flip one bit ⇒ different K).
  4. Sensitivity to ss_lwe (flip one bit ⇒ different K).
  5. Sensitivity to T      (flip one bit ⇒ different K).
  6. Sensitivity to ctx    (different ctx ⇒ different K).
  7. RFC 5869 §2.2 conformance — our hkdf_extract matches a known test
     vector from RFC 5869 Appendix A.1 (SHA-256).
  8. Extract+Expand together match a separate canonical HKDF call from
     cryptography.hazmat.primitives.kdf.hkdf.HKDF.
"""
import sys
import unittest

from dhp_kem import params, combiner
from dhp_kem.combiner import hkdf_extract, hkdf_expand, combine

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256


class CombinerStructuralTests(unittest.TestCase):

    PS = params.DHP_KEM_128

    SS_EC  = b"\x11" * 32
    SS_LWE = b"\x22" * 32
    T      = b"\xAA" * 48     # SHA-384 sized
    CTX    = b"unit-test"

    def test_output_length(self):
        K = combine(self.PS, self.SS_EC, self.SS_LWE, self.T, self.CTX)
        self.assertEqual(len(K), self.PS.L)

    def test_determinism(self):
        K1 = combine(self.PS, self.SS_EC, self.SS_LWE, self.T, self.CTX)
        K2 = combine(self.PS, self.SS_EC, self.SS_LWE, self.T, self.CTX)
        self.assertEqual(K1, K2)

    def test_sensitive_to_ss_ec(self):
        K1 = combine(self.PS, self.SS_EC,       self.SS_LWE, self.T, self.CTX)
        flipped = bytearray(self.SS_EC); flipped[0] ^= 1
        K2 = combine(self.PS, bytes(flipped),   self.SS_LWE, self.T, self.CTX)
        self.assertNotEqual(K1, K2)

    def test_sensitive_to_ss_lwe(self):
        K1 = combine(self.PS, self.SS_EC, self.SS_LWE,       self.T, self.CTX)
        flipped = bytearray(self.SS_LWE); flipped[0] ^= 1
        K2 = combine(self.PS, self.SS_EC, bytes(flipped),    self.T, self.CTX)
        self.assertNotEqual(K1, K2)

    def test_sensitive_to_transcript(self):
        K1 = combine(self.PS, self.SS_EC, self.SS_LWE, self.T,            self.CTX)
        flipped = bytearray(self.T); flipped[0] ^= 1
        K2 = combine(self.PS, self.SS_EC, self.SS_LWE, bytes(flipped),    self.CTX)
        self.assertNotEqual(K1, K2)

    def test_sensitive_to_ctx(self):
        K1 = combine(self.PS, self.SS_EC, self.SS_LWE, self.T, b"ctx-A")
        K2 = combine(self.PS, self.SS_EC, self.SS_LWE, self.T, b"ctx-B")
        self.assertNotEqual(K1, K2)

    def test_rejects_empty_inputs(self):
        with self.assertRaises(ValueError):
            combine(self.PS, b"", self.SS_LWE, self.T, self.CTX)
        with self.assertRaises(ValueError):
            combine(self.PS, self.SS_EC, b"", self.T, self.CTX)
        with self.assertRaises(ValueError):
            combine(self.PS, self.SS_EC, self.SS_LWE, b"", self.CTX)


class HKDFConformanceTests(unittest.TestCase):
    """RFC 5869 §A.1 (Test Case 1, SHA-256) — known answer."""

    # Test Case 1: SHA-256, IKM=22 bytes, salt=13 bytes, info=10 bytes, L=42
    IKM    = bytes.fromhex("0b" * 22)
    SALT   = bytes.fromhex("000102030405060708090a0b0c")
    INFO   = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    L      = 42
    EXP_PRK = bytes.fromhex(
        "077709362c2e32df0ddc3f0dc47bba63"
        "90b6c73bb50f9c3122ec844ad7c2b3e5")
    EXP_OKM = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865")

    def test_extract_matches_rfc5869(self):
        prk = hkdf_extract(salt=self.SALT, ikm=self.IKM, hash_name="SHA-256")
        self.assertEqual(prk, self.EXP_PRK,
            "hkdf_extract output diverges from RFC 5869 §A.1 Test Case 1")

    def test_expand_matches_rfc5869(self):
        okm = hkdf_expand(prk=self.EXP_PRK, info=self.INFO,
                          length=self.L, hash_name="SHA-256")
        self.assertEqual(okm, self.EXP_OKM,
            "hkdf_expand output diverges from RFC 5869 §A.1 Test Case 1")

    def test_extract_then_expand_matches_canonical_HKDF(self):
        """Our two-stage call must equal a single HKDF() from `cryptography`."""
        prk = hkdf_extract(self.SALT, self.IKM, "SHA-256")
        okm_two_stage = hkdf_expand(prk, self.INFO, self.L, "SHA-256")
        okm_canonical = HKDF(
            algorithm=SHA256(), length=self.L,
            salt=self.SALT, info=self.INFO,
        ).derive(self.IKM)
        self.assertEqual(okm_two_stage, okm_canonical)


if __name__ == "__main__":
    unittest.main(verbosity=2)
