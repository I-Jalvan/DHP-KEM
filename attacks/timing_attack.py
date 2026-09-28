"""
timing_attack.py — Timing-leak demonstration on byte-string comparison.

Two implementations of "is this MAC tag correct?" are tested:

  1. naive_compare(a, b):   returns False at the first mismatching byte.
     This is the C-style early-exit comparison still used in some
     application code.  An attacker who can measure response time can
     recover the correct tag byte-by-byte.

  2. constant_time_compare(a, b): runs the same number of operations
     regardless of where the strings differ.  This is what `hmac.compare_digest`
     does in the Python standard library.

We time both functions across many trials with two test inputs:
  * `EARLY`:   mismatches at byte 0
  * `LATE`:    mismatches at byte 31 (last byte of a 32-byte tag)

For the naive version, LATE takes ~32x longer than EARLY (visible as a
significant median-time gap).  For the constant-time version, the two
medians overlap within timing noise.

This kind of leak is what FIPS 140-3 §IG D.G and SP 800-185 require
implementations to defend against; it is also what Lucky-13 (Al-Fardan-
Paterson, S&P 2013) exploited against TLS's MAC-then-encrypt.

Reference: report §6b Side-Channel Attacks, "Timing attacks".
"""
from __future__ import annotations
import statistics
import time


TAG_LEN = 32


def naive_compare(a: bytes, b: bytes) -> bool:
    """INSECURE: exits at the first mismatching byte."""
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:
            return False
    return True


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """SECURE: runs to completion regardless of where (or whether) a, b differ.

    The trick is to XOR every byte pair, OR-fold them into a single
    accumulator, and only inspect the final accumulator.  The CPU still
    sees one branch (the final == 0) but the branch's predicate is
    independent of which byte first differed.
    """
    if len(a) != len(b):
        return False
    accumulator = 0
    for x, y in zip(a, b):
        accumulator |= x ^ y
    return accumulator == 0


def _timed(fn, a, b, n_trials: int) -> list[float]:
    samples = []
    for _ in range(20):                      # warmup
        fn(a, b)
    for _ in range(n_trials):
        t0 = time.perf_counter()
        fn(a, b)
        samples.append((time.perf_counter() - t0) * 1e6)   # microseconds
    return samples


def main():
    n = 4000
    correct = b"\x00" * TAG_LEN
    early   = b"\xFF" + b"\x00" * (TAG_LEN - 1)
    late    = b"\x00" * (TAG_LEN - 1) + b"\xFF"

    print(f"Comparing {TAG_LEN}-byte tags, {n} timing trials each")
    print("=" * 70)

    for fn_label, fn in [("naive_compare           (INSECURE)", naive_compare),
                          ("constant_time_compare    (SECURE)", constant_time_compare)]:
        t_early = _timed(fn, correct, early, n)
        t_late  = _timed(fn, correct, late,  n)
        med_e = statistics.median(t_early)
        med_l = statistics.median(t_late)
        ratio = med_l / med_e if med_e > 0 else float("inf")
        print(f"\n  {fn_label}")
        print(f"    median time, mismatch at byte 0   : {med_e:8.3f} µs")
        print(f"    median time, mismatch at byte 31  : {med_l:8.3f} µs")
        print(f"    ratio (late / early)              : {ratio:6.3f}")
        if ratio > 1.5:
            print(f"    >>> LEAK detected: timing exposes mismatch position.")
        else:
            print(f"    -> No exploitable timing difference.")

    print()
    print("In Python, this is what `hmac.compare_digest` does at the C layer.")
    print("In ML-KEM the analogous risk is comparing the re-encrypted ciphertext")
    print("during decapsulation; the FIPS-203 reference implementation uses a")
    print("constant-time compare for exactly this reason (see RFC 9794 §3.4).")


if __name__ == "__main__":
    main()
