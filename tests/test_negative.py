"""
test_negative.py
================

Negative tests — every kind of input tampering must produce a session
key different from the encapsulator's K.

Note on the FIPS-203 implicit-rejection design:  ML-KEM does NOT raise an
error on a tampered ciphertext.  Instead it deterministically derives a
"rejection" shared secret from the decapsulation key, so that Decap
always returns 32 bytes.  This is by design (it avoids decryption-error-
oracle side channels).  At the DHP-KEM level the resulting K' will then
differ from K with probability ~ 1 - 2^{-256}, and the receiving
application is expected to detect this by verifying a downstream MAC
or AEAD tag.  In these tests we assert K' != K.

Each test runs only once because the assertion is "K' != K" and the
probability of a collision is ~ 2^{-256}.

Test taxonomy
-------------
  flip_byte_in_A           — corrupt one byte of the ephemeral ECDH point
  flip_byte_in_c_lwe       — corrupt one byte of the Kyber ciphertext
  wrong_secret_key         — decap with a freshly-generated unrelated sk
  swap_paramsets           — encap under one parameter set, decap under
                             another (should raise)
  transcript_order_swap    — verify that transcript binding is field-order
                             sensitive (tests/test_combiner.py also covers
                             this for the lower-level combine() function)
"""
import sys
import unittest

import dhp_kem


PARAMS_TO_TEST = ("DHP-KEM-128", "DHP-KEM-256")


class NegativeTests(unittest.TestCase):

    def setUp(self):
        # Pre-generate one keypair per parameter set; reused for speed.
        self.kp = {}
        self.ct = {}
        self.K  = {}
        for name in PARAMS_TO_TEST:
            ps = dhp_kem.get(name)
            kp = dhp_kem.keygen(ps)
            ct, K = dhp_kem.encap(ps, kp.pk)
            self.kp[name] = kp
            self.ct[name] = ct
            self.K[name]  = K

    def test_flip_byte_in_A(self):
        """Corrupting the ephemeral ECDH point must change K."""
        for name in PARAMS_TO_TEST:
            ps = dhp_kem.get(name)
            ct = self.ct[name]
            tampered_A = bytearray(ct.A)
            tampered_A[0] ^= 0x01           # flip the lowest bit of byte 0
            ct_bad = dhp_kem.DHPCiphertext(
                A=bytes(tampered_A), c_lwe=ct.c_lwe,
                paramset_name=ct.paramset_name)
            K_bad = dhp_kem.decap(ps, self.kp[name].sk, ct_bad)
            self.assertNotEqual(K_bad, self.K[name],
                f"{name}: flipping a byte in A did NOT change K")

    def test_flip_byte_in_c_lwe(self):
        """Corrupting the Kyber ciphertext must change K (implicit reject)."""
        for name in PARAMS_TO_TEST:
            ps = dhp_kem.get(name)
            ct = self.ct[name]
            tampered_c = bytearray(ct.c_lwe)
            tampered_c[0] ^= 0x01
            ct_bad = dhp_kem.DHPCiphertext(
                A=ct.A, c_lwe=bytes(tampered_c),
                paramset_name=ct.paramset_name)
            K_bad = dhp_kem.decap(ps, self.kp[name].sk, ct_bad)
            self.assertNotEqual(K_bad, self.K[name],
                f"{name}: flipping a byte in c_lwe did NOT change K")

    def test_wrong_secret_key(self):
        """Decap with an unrelated keypair must NOT recover K."""
        for name in PARAMS_TO_TEST:
            ps = dhp_kem.get(name)
            wrong_kp = dhp_kem.keygen(ps)   # fresh, unrelated keypair
            K_bad = dhp_kem.decap(ps, wrong_kp.sk, self.ct[name])
            self.assertNotEqual(K_bad, self.K[name],
                f"{name}: decap with wrong sk DID recover K")

    def test_swap_paramsets_rejected(self):
        """Encap'ing under one paramset and Decap'ing under another fails."""
        ps128 = dhp_kem.get("DHP-KEM-128")
        ps256 = dhp_kem.get("DHP-KEM-256")
        kp128 = dhp_kem.keygen(ps128)
        kp256 = dhp_kem.keygen(ps256)
        ct128, _ = dhp_kem.encap(ps128, kp128.pk)
        # Try to Decap a 128-tier ciphertext under 256-tier parameters
        with self.assertRaises(ValueError):
            dhp_kem.decap(ps256, kp256.sk, ct128)
        # Also: passing the wrong pk to encap
        with self.assertRaises(ValueError):
            dhp_kem.encap(ps256, kp128.pk)


class TranscriptOrderTests(unittest.TestCase):
    """Verify transcript binding is field-order sensitive (Section 3.6)."""

    def test_transcript_changes_when_fields_reordered(self):
        ps = dhp_kem.get("DHP-KEM-128")
        from dhp_kem.transcript import compute_transcript
        A     = b"\x01" * 32
        c_lwe = b"\x02" * 1088
        pk_ec = b"\x03" * 32
        pk_lwe= b"\x04" * 1184
        T_correct = compute_transcript(ps, A, c_lwe, pk_ec, pk_lwe)
        # Swap any two fields ⇒ different T
        T_swap1   = compute_transcript(ps, c_lwe, A, pk_ec, pk_lwe)
        T_swap2   = compute_transcript(ps, A, c_lwe, pk_lwe, pk_ec)
        self.assertNotEqual(T_correct, T_swap1)
        self.assertNotEqual(T_correct, T_swap2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
